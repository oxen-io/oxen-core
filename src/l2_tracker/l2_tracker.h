#pragma once

#include <oxenmq/oxenmq.h>

#include <atomic>
#include <forward_list>
#include <iterator>
#include <list>
#include <shared_mutex>
#include <unordered_set>

#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "rewards_contract.h"

namespace oxenmq {
class OxenMQ;
}

namespace cryptonote {
class core;
}

namespace eth {

struct TransactionReviewSession {
  private:
    // True if this is an active review session; false if we didn't have sufficient information to
    // properly create a review (in which case validation is skipped).
    bool active = false;

    std::list<NewServiceNodeTx> new_service_nodes;
    std::list<ServiceNodeRemovalRequestTx> removal_requests;
    std::list<ServiceNodeLiquidatedTx> liquidations;
    std::list<ServiceNodeRemovalTx> removals;

    friend class L2Tracker;

  public:
    // Default constructor; this constructs an inactive TransactionReviewSession, which just blindly
    // approves anything.  For an actually validating review, construct one via
    // L2Tracker::initialize_review().
    TransactionReviewSession() {}

    TransactionReviewSession(TransactionReviewSession&&) = default;
    TransactionReviewSession(const TransactionReviewSession&) = default;
    TransactionReviewSession& operator=(TransactionReviewSession&&) = default;
    TransactionReviewSession& operator=(const TransactionReviewSession&) = default;

    /// This object converts to `true` if this is an active review session, `false` if it is in
    /// "accept anything" mode (i.e. due to insufficient L2 provider data).
    explicit operator bool() const { return active; }

    /// The following process... methods take the details of an L2 state change transaction and, if
    /// it matches one in the review (so as to prohibit duplicates), removes it from the review and
    /// returns true.
    ///
    /// If the given transaction does not match an L2 state change, returns false and sets
    /// `fail_reason` to the reason the transaction should be rejected.
    ///
    /// If the object is not active, this always returns true.
    bool processNewServiceNodeTx(
            const bls_public_key& bls_pubkey,
            const eth::address& eth_address,
            const crypto::public_key& service_node_pubkey,
            std::string& fail_reason);
    bool processServiceNodeRemovalRequestTx(
            const bls_public_key& bls_pubkey, std::string& fail_reason);
    bool processServiceNodeRemovalTx(
            const eth::address& eth_address,
            const uint64_t amount,
            const bls_public_key& bls_pubkey,
            std::string& fail_reason);
    bool processServiceNodeLiquidatedTx(const bls_public_key& bls_pubkey, std::string& fail_reason);

    /// Called to check that all L2 state changes were found via the process... methods.  Returns
    /// true if there are no leftover expected L2 state changes left, false if there are still L2
    /// state changes that were not processed.
    ///
    /// Always returns true for an inactive review.
    bool finalize();
};

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
    std::map<uint64_t, std::vector<TransactionStateChangeVariant>> state_history;
    std::map<uint64_t, uint64_t> reward_rate;
    uint64_t latest_height = 0, synced_height = 0, confirmed_height = 0, earliest_height = 0;
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
    // - logs for up to 100 blocks since our last updated height
    // - repeated log requests for up to 100 blocks at a time until we get everything up to the
    //   height we got in the first stage.
    //
    // As log entries come in we translate them into oxen state change transactions that we insert
    // into the mempool.
    void update_state();
    void update_height();
    void update_rewards(std::optional<std::forward_list<uint64_t>> more = std::nullopt);
    void update_logs();
    void add_to_mempool(uint64_t l2_height, const TransactionStateChangeVariant& state_change);

  public:
    // Constructs an L2Tracker.  The optional `update_frequency` determines how frequently we poll
    // for updated chain state and logs: This defines how many requests we make to the L2 provider:
    // each (this period) we need to make one request to get the current block height, and then at
    // least one more to fetch any logs since the previous block height we knew about.
    explicit L2Tracker(cryptonote::core& core, std::chrono::milliseconds update_frequency = 10s);

    // Numbers of states we keep before the current height before discarding them.  The default is
    // enough to have the last hour of history (for an L2 such as Arbitrum with its 0.25s block
    // time).
    size_t HIST_SIZE = 1h / 250ms;

    // This is similar to HIST_SIZE, but defines how much history we request from the L2 provider at
    // once.  This matters at startup, where this defines how much initial history to fetch, and can
    // also apply after an extended downtime or L2 provider unavailability.  If we ever find that we
    // are *more* than this number of blocks behind (or at startup) then we throw away older history
    // and sync up by fetching just this amount of recent history.
    //
    // A default, non-archive Arbitrum node keeps only 30min of block state, so this ought to be
    // shorter than that.
    size_t MAX_HIST_FETCH = 10min / 250ms;

    // How many blocks worth of logs we fetch at once.  Various providers impose various limits on
    // this based on the free/pair tier, but 100 at once seems to be accepted by most free tiers and
    // so that is our default.  Note that this interacts with the UPDATE_FREQUENCY: you generally
    // want this value to be at least a little higher than the number of blocks the L2 produces
    // during an UPDATE_FREQUENCY period (for Arbitrum: 4 blocks per second) otherwise you just end
    // up having to make multiple logs requests every UPDATE_FREQUENCY seconds and you are better
    // off either lowering the update frequency, or increasing the number (but there is no "best"
    // choice here as it depends on the limits/rates imposed by the provider).
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

    // How many blocks behind the last known head we use for the "safe" height, i.e. the cutoff
    // height for state change inclusions when building pulse blocks (so that we don't send things
    // that are too new that other nodes might not know about yet).  The default is 30s behind.
    static constexpr uint64_t SAFE_BLOCKS = 30s / 250ms;

    // Returns the reward rate for the given L2 height.  Returns nullopt if we don't know/haven't
    // retrieved it yet (and so this should generally be called with a safe height, not the current
    // L2 height).  (Note that L2 reward rates only change on L2 block heights divisible by
    // L2_REWARD_POOL_UPDATE_BLOCKS, not on every block).
    std::optional<uint64_t> get_reward_rate(uint64_t height) const;

    // This function checks whether transactions on the oxen chain should be there.  It is called
    // when deciding whether to accept a block (and, for a pulse quorum validator, whether to sign
    // one).
    //
    // This works by calling `initialize_review` with the l2 block height as included in the block
    // itself; it then populates a "review session" containing all blocks that should be present
    // from the l2_height just after that of the previous block (as given to us by
    // set_confirmed_height()), up to and including the new provided height.
    //
    // The review session should have one of the `process...` methods called for each state change
    // transaction in the block; this will mark it as included, or fail if it should not have been
    // included.
    //
    // Finally a call to `finalize()` will check that the review session is empty, i.e. there were
    // no omitted L2 transactions in the L2 range implied by the block.
    //
    // Note that this TransactionReviewSession will be inactive (thus allowing everything) if there
    // is not enough stored L2 state to fully validate.
    //
    // TODO FIXME: this approach has some problems because it assumes a node's L2 provider is always
    // reliable; in practice an L2 outage or brief stall of a major provider could cause Oxen nodes
    // to desync from each other, and various edge cases in provider logs retrieval (such as missing
    // a log statement due to provider request load balancing) could cause longer desyncs for
    // individual nodes.
    //
    // There are likely also issues with Oxen reorgs because of the complexities of how state
    // changes enter the transaction pool via L2 Logs and, for popped blocks, from the blocks
    // themselves.
    //
    // There's a further problem in the event of an Oxen chain stall for whatever reason: because we
    // only have limited storage of state changes (see HIST_SIZE) if the last block was too long
    // ago, we can't do a transaction review at all if the previous block time was too long ago (and
    // so this blind acceptance could be use to push through non-consensus state changes).
    //
    // This will be revisited with a similar but more resilient approach that uses the L2 network
    // for data information, but without requiring exact confirmation and instead relying on
    // multiple Oxen pulse quorum confirmations (rather than individual node L2 provider data) for
    // achieving Oxen state change consensus.
    TransactionReviewSession initialize_review(uint64_t ethereum_height) const;

    // Called to set the confirmed L2 height from an Oxen block when the head of the Oxen chain is
    // updated.
    void set_confirmed_height(uint64_t l2_block_height);

    // Returns the latest L2 height we know about, i.e. from previous provider updates.
    uint64_t get_latest_height() const;
    // Returns the latest L2 height that we have known about for at least 30s (SAFE_BLOCKS); when
    // building a block we use this slight lag so that service nodes that are a few seconds out of
    // sync won't have trouble accepting our block.
    uint64_t get_safe_height() const;
    // Returns the latest L2 height that has been written into an Oxen block we've accepted (as per
    // the last call to `set_confirmed_height()`).
    uint64_t get_confirmed_height() const;

    std::vector<uint64_t> get_non_signers(
            const std::unordered_set<bls_public_key>& bls_public_keys);
    template <std::input_iterator It, std::sentinel_for<It> End>
    std::vector<uint64_t> get_non_signers(It begin, End end) {
        return get_non_signers(std::unordered_set<bls_public_key>{begin, end});
    }
    std::vector<bls_public_key> get_all_bls_public_keys(uint64_t blockNumber);

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
    void prune_old_states(bool to_fetch_limit = false);

    void get_review_transactions();
    // END
};

}  // namespace eth
