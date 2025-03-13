#pragma once

#include <cryptonote_config.h>
#include <oxenmq/oxenmq.h>

#include <chrono>
#include <ethyl/provider.hpp>
#include <forward_list>
#include <iterator>
#include <ranges>
#include <shared_mutex>
#include <unordered_set>

#include "crypto/crypto.h"
#include "crypto/eth.h"
#include "events.h"
#include "recent_events.h"
#include "rewards_contract.h"

namespace cryptonote {
class core;
}

namespace crypto {
struct public_key;
};

namespace eth {

struct L2State {
    static constexpr uint8_t MIN_VERSION = 1;
    static constexpr uint8_t MAX_VERSION = 1;
    uint8_t version = MAX_VERSION;
    uint64_t chain_id;
    std::string rewards_contract;

    uint64_t latest_height = 0;
    uint64_t synced_height = 0;

    // l2_height => recent events at that height
    RecentEvents<event::NewServiceNodeV2> recent_regs;
    RecentEvents<event::ServiceNodeExitRequest> recent_unlocks;
    RecentEvents<event::ServiceNodeExit> recent_exits;
    RecentEvents<event::StakingRequirementUpdated> recent_req_changes;

    std::map<uint64_t, uint64_t> reward_rate;
};

struct L2PurgeState {
    static constexpr uint8_t MIN_VERSION = 1;
    static constexpr uint8_t MAX_VERSION = 1;
    uint8_t version = MAX_VERSION;
    uint64_t chain_id;
    std::string rewards_contract;
    uint64_t latest_height = 0;
    std::unordered_set<eth::bls_public_key> in_contract;
};

class L2Proxy;

class L2Tracker {
  private:
    cryptonote::core& core;
    oxenmq::TaggedThreadID update_thread_id;

    template <class Archive>
    friend void serialize_object(Archive&, L2Tracker&);

  public:
    // We have to hold this in a shared_ptr because it requires shared_from_this.  This will be
    // nullptr when our L2 state comes from an oxend proxy.
    const std::shared_ptr<ethyl::Provider> provider;

  private:
    std::optional<RewardsContract> rewards_contract;  // nullopt in oxend-proxy mode
    mutable std::shared_mutex mutex;

    L2State state{};
    L2PurgeState purge_state{};

    uint64_t latest_blockchain_l2_height = 0;
    bool initial = true;
    bool update_in_progress = false;
    std::chrono::steady_clock::time_point next_provider_check = std::chrono::steady_clock::now();
    std::optional<std::chrono::steady_clock::time_point> primary_down;
    std::chrono::steady_clock::time_point primary_last_warned;
    std::optional<std::chrono::steady_clock::time_point> latest_height_ts;

    // Proxy object for handing proxy requests to us, i.e. we are the proxy:
    std::unique_ptr<L2Proxy> l2_proxy;

    // Connection info that we proxy to, i.e. we use a proxy for L2 info:
    struct l2_oxend_proxy {
        oxenmq::address address;
        std::string id;  // Descriptive string identifying this remote for logs
        oxenmq::ConnectionID connid;
        bool pending_connect;
        l2_oxend_proxy(oxenmq::address a, std::string id) :
                address{std::move(a)}, id{std::move(id)}, connid{}, pending_connect{false} {}
    };
    std::vector<l2_oxend_proxy> l2_oxend_proxies;

    // Provider state updating: `update_state()` starts a chain of updates, each one triggering the
    // next step in the chain when its response is received.  While such an update is in progress
    // any call to `update_state()` will do nothing.
    //
    // This is called periodically automatically.
    //
    // We request:
    // 1. if we have multiple provider and we haven't checked the height of all of them in a while
    //    (PROVIDERS_CHECK_INTERVAL) then fetch the height from all of them and use to decide
    //    whether we need to switch our active provider (i.e. if the primary provider is too far
    //    behind, or we're on a backup but the primary looks good again).  Whatever node we end
    //    deciding to use defines our new current height, and we proceed to step 3.
    // 2. otherwise (no multiple providers, or we aren't due to rechecked them) fetch the updated
    //    height from our current active provider.  Proceed to 3.
    // 3. If we are missing reward info for a recent reward height block (i.e. those divisible by
    //    L2_REWARD_POOL_UPDATE_BLOCKS), fetch the updated reward data.  We generally keep the most
    //    recent and second-most recent on hand, and so this step will repeat if we need both.  Once
    //    we've done any reward updates (or if none were needed) proceed to 4.
    // 4. Log updating.  We fetch logs, starting at the next block height after the most recent log
    //    fetch (or HIST_SIZE ago, if that is later), giving us ethereum events for node actions.
    //    We fetch at most 100 (by default, but confirable) at a time, and as each set of logs comes
    //    back repeat this step until we have fetched all logs up to the current height.  Any such
    //    witnessed events are added to the mempool for inclusion in new blocks and are used for
    //    confirm (or deny) L2 events that are still awaiting confirmation.
    // 5. If the height passed a new L2_NODE_LIST_PURGE_BLOCKS height interval since the last purge
    //    check we performed then we fetch the full set of current nodes from the contract; any
    //    nodes present in the oxend service node list that are neither present in the contract nor
    //    present in the list of recent removal/liquidation events becauses a node to be purged.
    //    This follows the same confirmation voting process as events from step 4 for removing the
    //    node from the network.  If this request fails because the height is quite old then we
    //    retry the request for the current height (but don't load Purge txes if using that
    //    fallback).
    //
    void update_state();
    void set_height(uint64_t new_height, bool take_lock = true);
    void update_height();
    void update_rewards(std::optional<std::forward_list<uint64_t>> more = std::nullopt);
    void update_logs();
    void update_purge_list(bool curr_height_fallback = false);
    void update_done(bool changes = true);

    void generate_purge_transactions();

    // oxend proxy updates works entirely differently from the above: we subscribe for l2 updates
    // with the remote oxend every 30s (to ensure we remain subscribed), and then it pushes
    // notifications to us when its L2 state changes, at which point we initiate a state update and
    // then, when that comes back, apply it in one shot.
    //
    // (Definitions of the proxy-related functions in l2_tracker_proxy.cpp, alongside the server
    // proxy code).

    // Interval for re-subscribing with the proxy.  Unlike the L2 provider interval, this is fixed
    // because it doesn't have any effect on how fast we get updates: the proxy pushes update
    // notifications to us as soon as they arrive; the 30s interval is just how often we send
    // (re-)subscribe requests to keep us subscribed to those push updates.
    static constexpr std::chrono::milliseconds PROXY_RESUB_INTERVAL = 30s;

    void proxy_connect_and_subscribe();
    void proxy_send_subscribe(const l2_oxend_proxy& oxend);
    void proxy_disconnect(oxenmq::ConnectionID conn, bool clear_only = false);
    // Handler for reverse command l2_notify.(purge_)state:
    void l2_notify_state(oxenmq::Message& msg, bool purge);
    void proxy_request_generic(
            oxenmq::ConnectionID to,
            std::string_view endpoint,
            std::optional<std::string_view> body,
            std::string_view descr,
            std::string_view id,
            std::function<
                    void(bool& success,
                         bool& log_error,
                         std::vector<std::string>& data,
                         const oxenmq::ConnectionID& conn,
                         std::string_view id)>);
    void proxy_request_if_newer(
            oxenmq::ConnectionID conn,
            std::optional<uint64_t> state_height,
            std::optional<uint64_t> purge_state_height);
    void proxy_request_state(oxenmq::ConnectionID conn, bool purge_state);
    uint64_t l2_state_requested = 0, l2_purge_state_requested = 0;
    void proxy_update_state(L2State&& new_state, std::string_view from);
    void proxy_update_state(L2PurgeState&& new_state, std::string_view from);

    void add_to_mempool(const event::StateChangeVariant& state_change);

    // Base constructor
    L2Tracker(
            cryptonote::core& core,
            std::shared_ptr<ethyl::Provider>,
            std::function<void()> on_startup);

  public:
    // Constructs an L2Tracker in regular, fetch-from-L2-provider-rpc mode.  The optional
    // `update_frequency` determines how frequently we poll for updated chain state and logs: This
    // defines how many requests we make to the L2 provider: each (this period) we need to make one
    // request to get the current block height, and then at least one more to fetch any logs since
    // the previous block height we knew about.
    explicit L2Tracker(cryptonote::core& core, std::chrono::milliseconds update_frequency = 10s);

    // Constructs an L2Tracker in L2 proxy mode, where we rely on one or more external oxends to
    // provide us with L2 state data.
    explicit L2Tracker(
            cryptonote::core& core,
            std::span<const std::pair<oxenmq::address, crypto::ed25519_public_key>> oxend_proxies);

    // Returns true if this L2Tracker is in oxend-proxied mode, in which case L2 state from events
    // is dictated by the configured proxy, and active requests (get_all_service_node_ids() and
    // get_non_signers()) are not available.
    bool proxied() const { return static_cast<bool>(provider); }

    // Numbers of states we track behind the current L2 height before discarding them.  The default
    // is enough to have the last hour of history (for an L2 such as Arbitrum with its 0.25s block
    // time), plus a buffer so that pulse quorum nodes can properly recognize L2 events from the
    // past hour (for achieving pulse consensus).
    //
    // Ignored when in oxend-proxy mode (in proxy mode the entire L2 state gets replaced on each
    // update, and so we drop states when the proxied-from node drops states).
    uint64_t HIST_SIZE = 70min / 250ms;

    // The "safe" number of blocks ago within which we expect to be able to issue recent historic
    // contract calls.  On arbitrum most provider nodes have only 30min of contract state history
    // available, and so we use 10min of typical 250ms blocks as a safe buffer (partly because
    // Arbitrum blocks sometimes go slower, particularly on testnet).
    uint64_t SAFE_HISTORY_BLOCKS = 10min / 250ms;

    // How many blocks worth of logs we fetch at once.  Various providers impose various limits on
    // this based on the free/paid tier, and so there is no perfect default.  1000 blocks at once
    // seems to be accepted by most free tier L2 provider plans, but the limits vary widely from one
    // provider to the next, and so this option may need to be updated (via oxend's l2-max-logs=
    // config file setting or command-line parameter).
    //
    // Note that this interacts in normal operation with the UPDATE_FREQUENCY: you generally want
    // this value to be at least a little higher than the number of blocks the L2 produces during an
    // UPDATE_FREQUENCY period (for Arbitrum: 4 blocks per second) otherwise you just end up having
    // to make multiple logs requests every UPDATE_FREQUENCY seconds and you are better off either
    // lowering the update frequency, or increasing the number (but there is no "best" choice here
    // as it depends on the limits/rates imposed by the provider).
    //
    // This also affects startup, when we need to fetch `HIST_SIZE` logs, and so need to make
    // HIST_SIZE / (this value) requests to fill the initial event state.
    //
    // Ignored when in oxend-proxy mode.
    uint64_t GETLOGS_MAX_BLOCKS = cryptonote::ETH_L2_DEFAULT_MAX_LOGS;

    // These two parameters control how we re-check all the configured L2 providers to reprioritize,
    // when multiple providers are configured.  When checking, we consider each provider to be in
    // good standing if its height is within `CHECK_THRESHOLD` blocks of the maximum height we
    // retrieve from any L2.  We always prioritize "good" providers in the order they were provided
    // to use (so that if you have primary and two backups, the primary will always be first as long
    // as it isn't too far behind), followed by non-good providers sorted by how far behind they
    // were.
    //
    // Ignored when in oxend-proxy mode.
    std::chrono::milliseconds PROVIDERS_CHECK_INTERVAL = cryptonote::ETH_L2_DEFAULT_CHECK_INTERVAL;
    uint64_t PROVIDERS_CHECK_THRESHOLD = cryptonote::ETH_L2_DEFAULT_CHECK_THRESHOLD;

    // Does a *synchronous* test of the chainId of all providers; this is intended to be called once
    // during oxen-core construction, and to abort startup if the provider(s) are providing the
    // wrong chain.  Logs errors and returns false if any return a chainId that doesn't match the
    // required L2 chain Id.  Returns true if all providers match.  Any providers that time out
    // produce a warning, but do not cause a false return value.
    //
    // This method does nothing when using l2 oxend proxies.
    bool check_chain_id() const;

    // Returns the reward rate for the given L2 height.  Returns nullopt if we don't know/haven't
    // retrieved it yet (and so this should generally be called with a safe height, not the current
    // L2 height).  (Note that L2 reward rates only change on L2 block heights divisible by
    // L2_REWARD_POOL_UPDATE_BLOCKS, not on every block).
    std::optional<uint64_t> get_reward_rate(uint64_t height) const;

    // Returns the latest L2 height we know about, i.e. from previous provider updates.
    uint64_t get_latest_height() const;

    // Returns the latest L2 height that we have known about for at least 70s
    // (L2_TRACKER_SAFE_BLOCKS); when building a block we use this slight lag so that service nodes
    // that are up to a minute out of sync with the L2 tracker (e.g. because they update once a
    // minute) won't have trouble accepting our block.
    uint64_t get_safe_height() const;

    // Returns the age of the last successful height response we got from an L2 RPC provider.
    std::optional<std::chrono::nanoseconds> latest_height_age() const;

    // Performs an asynchronous request to the current L2 contract to retrieve the current list of
    // BLS pubkeys, and returns a NonSigners struct containing the numeric contract
    // IDs of any contract pubkeys that are not in the `[begin..end)` input range, and any rejected
    // pubkeys that are not in the contract and should be remove before submission to the contract.
    //
    // This method returns immediately: when the data is returned from the contract the given
    // callback is invoked with the result.
    //
    // Invokes with nullopt on failure.
    void get_non_signers(
            std::unordered_set<bls_public_key> bls_public_keys,
            std::function<void(std::optional<NonSigners>)> callback);

    // Versions of the above that take a pubkey range and construct the unordered_set on the fly
    template <std::ranges::input_range R>
        requires std::same_as<const std::ranges::range_reference_t<R>, const bls_public_key&>
    void get_non_signers(R&& r, std::function<void(std::optional<NonSigners>)> callback) {
        return get_non_signers(
                std::unordered_set<bls_public_key>{r.begin(), r.end()}, std::move(callback));
    }

    // Initiates an asynchronous request for all current L2 contract numeric IDs and pubkeys of
    // contract service nodes at the given height (current height if nullopt).  This method returns
    // immediately, with a followup call passing the result to given lambda (likely from a different
    // thread) when the request completes, or a call to the lambda with `std::nullopt` if the
    // request fails or times out.
    void get_all_service_node_ids(
            std::optional<uint64_t> height,
            std::function<void(std::optional<ServiceNodeIDs>)> callback);

    // Returns true if the given pubkey is in the L2 contract, as of the last contract list update,
    // false if not in the list.  (This method does not make a new L2 provider request).  Returns
    // nullopt if the current cache is empty (i.e. indicating that we have not successfully synced
    // the pubkey purge list recently).  Note that this value is cached and typically somewhat
    // stale: it is only updated every netconf.L2_NODE_LIST_PURGE_BLOCKS L2 blocks.
    std::optional<bool> is_in_contract(const eth::bls_public_key& pubkey) const;

    // Returns all contract node BLS pubkeys, as of the last purge list update.  Note that if the
    // purge list has not been recently successfully updated, this set will be empty (and so an
    // empty set should be treated specially, but *not* as a contract-has-no-nodes indicator).
    std::unordered_set<eth::bls_public_key> all_contract_pubkeys() const;

    // Returns true/false for whether we have recently observed the given event from the L2 tracker
    // logs.  This is used for pulse confirmation voting.
    bool get_vote_for(const event::NewServiceNodeV2& reg) const;
    bool get_vote_for(const event::ServiceNodeExit& exit) const;
    bool get_vote_for(const event::ServiceNodeExitRequest& unlock) const;
    bool get_vote_for(const event::StakingRequirementUpdated& req_change) const;
    bool get_vote_for(const event::ServiceNodePurge& purge) const;
    bool get_vote_for(const std::monostate&) const { return false; }

    // Returns a copy of the current full L2 tracking state (excluding in-contract nodes for
    // purging).
    L2State get_state() const;

    // Returns the current L2 purge state tracking, containing all the known service nodes in the
    // contract.  This is updated infrequently (once/hour by default) and is huge, and so is kept
    // separate from the rest of the L2State, above.
    L2PurgeState get_purge_state() const;

    // Enables L2 proxy support.  This allows whitelisted remotes to obtain our L2 state via OMQ
    // (instead of using their own L2 provider), with subscription that notifications them upon
    // completion of L2 state updates.
    void enable_proxy(oxenmq::OxenMQ& omq, std::filesystem::path whitelist);

    // Allow public shared locking of current state.  Note that exclusive locking is *not* publicly
    // exposed, and is used internally when updating the data (holding the shared lock is sufficient
    // to prevent any updates).
    void lock_shared() { mutex.lock_shared(); }
    bool try_lock_shared() { return mutex.try_lock_shared(); }
    void unlock_shared() { mutex.unlock_shared(); }

    ~L2Tracker();

  private:
    // Must hold mutex (in exclusive mode) while calling!
    void prune_old_states();

    // Must hold shared lock (or stronger) on the l2 tracker *and* the blockchain while calling!
    // This is the meat of get_vote_for ServiceNodePurge, but is also used internally when deciding
    // whether to put things in the mempool.
    bool is_node_purgeable(const bls_public_key& bls_pubkey) const;
};

}  // namespace eth
