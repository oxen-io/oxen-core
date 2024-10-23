#pragma once

#include <cryptonote_config.h>
#include <oxenmq/oxenmq.h>

#include <chrono>
#include <ethyl/provider.hpp>
#include <forward_list>
#include <iterator>
#include <shared_mutex>
#include <unordered_set>

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

class L2Tracker {
  private:
    cryptonote::core& core;
    oxenmq::TimerID updater;
    // We have to hold this in a shared_ptr because it requires shared_from_this
    const std::shared_ptr<ethyl::Provider> provider_ptr = ethyl::Provider::make_provider();

  public:
    ethyl::Provider& provider{*provider_ptr};

  private:
    RewardsContract rewards_contract;
    mutable std::shared_mutex mutex;

    const uint64_t chain_id;

    // l2_height => recent events at that height
    RecentEvents<event::NewServiceNodeV2> recent_regs_v2;
    RecentEvents<event::ServiceNodeExitRequest> recent_unlocks;
    RecentEvents<event::ServiceNodeExit> recent_exits;
    RecentEvents<event::StakingRequirementUpdated> recent_req_changes;
    std::unordered_set<eth::bls_public_key> in_contract;
    std::map<uint64_t, uint64_t> reward_rate;
    uint64_t latest_height = 0, synced_height = 0, latest_blockchain_l2_height = 0,
             latest_purge_check = 0;
    bool initial = true;
    bool update_in_progress = false;
    std::chrono::steady_clock::time_point next_provider_check = std::chrono::steady_clock::now();
    std::optional<std::chrono::steady_clock::time_point> primary_down;
    std::chrono::steady_clock::time_point primary_last_warned;
    std::optional<std::chrono::steady_clock::time_point> latest_height_ts;

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
    void add_to_mempool(const event::StateChangeVariant& state_change);

  public:
    // Constructs an L2Tracker.  The optional `update_frequency` determines how frequently we poll
    // for updated chain state and logs: This defines how many requests we make to the L2 provider:
    // each (this period) we need to make one request to get the current block height, and then at
    // least one more to fetch any logs since the previous block height we knew about.
    explicit L2Tracker(cryptonote::core& core, std::chrono::milliseconds update_frequency = 10s);

    // Numbers of states we track behind the current L2 height before discarding them.  The default
    // is enough to have the last hour of history (for an L2 such as Arbitrum with its 0.25s block
    // time), plus a buffer so that pulse quorum nodes can properly recognize L2 events from the
    // past hour (for achieving pulse consensus).
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
    uint64_t GETLOGS_MAX_BLOCKS = cryptonote::ETH_L2_DEFAULT_MAX_LOGS;

    // These two parameters control how we re-check all the configured L2 providers to reprioritize,
    // when multiple providers are configured.  When checking, we consider each provider to be in
    // good standing if its height is within `CHECK_THRESHOLD` blocks of the maximum height we
    // retrieve from any L2.  We always prioritize "good" providers in the order they were provided
    // to use (so that if you have primary and two backups, the primary will always be first as long
    // as it isn't too far behind), followed by non-good providers sorted by how far behind they
    // were.
    std::chrono::milliseconds PROVIDERS_CHECK_INTERVAL = cryptonote::ETH_L2_DEFAULT_CHECK_INTERVAL;
    uint64_t PROVIDERS_CHECK_THRESHOLD = cryptonote::ETH_L2_DEFAULT_CHECK_THRESHOLD;

    // Does a *synchronous* test of the chainId of all providers; this is intended to be called once
    // during oxen-core construction, and to abort startup if the provider(s) are providing the
    // wrong chain.  Logs errors and returns false if any return a chainId that doesn't match the
    // required L2 chain Id.  Returns true if all providers match.  Any providers that time out
    // produce a warning, but do not cause a false return value.
    bool check_chain_id() const;

    // Returns the reward rate for the given L2 height.  Returns nullopt if we don't know/haven't
    // retrieved it yet (and so this should generally be called with a safe height, not the current
    // L2 height).  (Note that L2 reward rates only change on L2 block heights divisible by
    // L2_REWARD_POOL_UPDATE_BLOCKS, not on every block).
    std::optional<uint64_t> get_reward_rate(uint64_t height) const;

    // Returns the latest L2 height we know about, i.e. from previous provider updates.
    uint64_t get_latest_height() const;

    // Returns the latest L2 height that we have known about for at least 30s (SAFE_BLOCKS); when
    // building a block we use this slight lag so that service nodes that are a few seconds out of
    // sync won't have trouble accepting our block.
    uint64_t get_safe_height() const;

    // Returns the age of the last successful height response we got from an L2 RPC provider.
    std::optional<std::chrono::nanoseconds> latest_height_age() const;

    std::vector<uint64_t> get_non_signers(
            const std::unordered_set<bls_public_key>& bls_public_keys);
    template <std::input_iterator It, std::sentinel_for<It> End>
    std::vector<uint64_t> get_non_signers(It begin, End end) {
        return get_non_signers(std::unordered_set<bls_public_key>{begin, end});
    }
    std::vector<bls_public_key> get_all_bls_public_keys(uint64_t blockNumber);

    RewardsContract::ServiceNodeIDs get_all_service_node_ids(std::optional<uint64_t> height);

    // Returns true/false for whether we have recently observed the given event from the L2 tracker
    // logs.  This is used for pulse confirmation voting.
    bool get_vote_for(const event::NewServiceNodeV2& reg) const;
    bool get_vote_for(const event::ServiceNodeExit& exit) const;
    bool get_vote_for(const event::ServiceNodeExitRequest& unlock) const;
    bool get_vote_for(const event::StakingRequirementUpdated& req_change) const;
    bool get_vote_for(const event::ServiceNodePurge& purge) const;
    bool get_vote_for(const std::monostate&) const { return false; }

    // Allow public shared locking of current state.  Note that exclusive locking is *not* publicly
    // exposed, and is used internally when updating the data (holding the shared lock is sufficient
    // to prevent any updates).
    void lock_shared() { mutex.lock_shared(); }
    bool try_lock_shared() { return mutex.try_lock_shared(); }
    void unlock_shared() { mutex.unlock_shared(); }

  private:
    // Must hold mutex (in exclusive mode) while calling!
    void prune_old_states();

    // Must hold shared lock (or stronger) on the l2 tracker *and* the blockchain while calling!
    // This is the meat of get_vote_for ServiceNodePurge, but is also used internally when deciding
    // whether to put things in the mempool.
    bool is_node_purgeable(const bls_public_key& bls_pubkey) const;
};
}  // namespace eth
