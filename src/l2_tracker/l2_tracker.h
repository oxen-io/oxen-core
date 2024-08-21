#pragma once

#include <oxenmq/oxenmq.h>

#include <concepts>
#include <forward_list>
#include <iterator>
#include <shared_mutex>
#include <unordered_set>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "l2_tracker/events.h"
#include "recent_events.h"
#include "rewards_contract.h"

namespace oxenmq {
class OxenMQ;
}

namespace cryptonote {
class core;
}

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
    RecentEvents<event::NewServiceNode> recent_regs;
    RecentEvents<event::ServiceNodeRemovalRequest> recent_unlocks;
    RecentEvents<event::ServiceNodeRemoval> recent_removals;
    std::map<uint64_t, uint64_t> reward_rate;
    uint64_t latest_height = 0, synced_height = 0;
    bool initial = true;
    bool update_in_progress = false;
    std::chrono::steady_clock::time_point next_provider_check = std::chrono::steady_clock::now();
    std::optional<std::chrono::steady_clock::time_point> primary_down;
    std::chrono::steady_clock::time_point primary_last_warned;

    // Provider state updating: `update_state()` starts a chain of updates, each one triggering the
    // next step in the chain when its response is received.  While such an update is in progress
    // any call to `update_state()` will do nothing.
    //
    // This is called periodically automatically.
    //
    // We request:
    // - current height of all providers (only if we are using multiple providers and it has been a
    //   while since we last checked).  Once we get this response, we choose a best provider and set
    //   up the provider to prioritize that one.  Then we call `update_state()` again to continue.
    // - current height
    // - the most recent reward rate (for the most recent divisible-by-L2_REWARD_POOL_UPDATE_BLOCKS
    //   L2 height).  We may need to repeat this, depending on HIST_SIZE and what info we already
    //   have.
    // - logs for up to 1000 blocks since our last updated height
    // - repeated log requests for up to 100 blocks at a time until we get everything up to the
    //   height we got in the first stage.
    //
    // As log entries come in we translate them into oxen state change transactions that we insert
    // into the mempool, to be included if this node is called upon to produce a new block.
    void update_state();
    void update_height();
    void update_rewards(std::optional<std::forward_list<uint64_t>> more = std::nullopt);
    void update_logs();
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
    size_t HIST_SIZE = 70min / 250ms;

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
    bool get_vote_for(const event::NewServiceNode& reg) const;
    bool get_vote_for(const event::ServiceNodeRemoval& removal) const;
    bool get_vote_for(const event::ServiceNodeRemovalRequest& unlock) const;
    bool get_vote_for(const std::monostate&) const { return false; }

    // TODO FIXME: the entire L2Tracker shouldn't be here if there are no clients
    bool provider_has_clients() const { return provider.numClients(); }

    // Allow public shared locking of current state.  Note that exclusive locking is *not* publicly
    // exposed, and is used internally when updating the data (holding the shared lock is sufficient
    // to prevent any updates).
    void lock_shared() { mutex.lock_shared(); }
    bool try_lock_shared() { return mutex.try_lock_shared(); }
    void unlock_shared() { mutex.unlock_shared(); }

  private:
    // Must hold mutex (in exclusive mode) while calling!
    void prune_old_states();
};

}  // namespace eth
