#pragma once

#include <array>

#include "../cryptonote_config.h"

namespace cryptonote {

struct network_config final {
    // The network type of this config.
    const network_type NETWORK_TYPE;

    // If non-empty, the default path subdir we use for this chain, e.g. ~/.oxen/SUBDIR.  Mainnet
    // has no subdir, all other networks use a distinct subdirectory.
    std::string_view DEFAULT_CONFIG_SUBDIR;

    // Used to estimate the blockchain height from a timestamp, with some grace time.  This can
    // drift slightly over time (because average block time is not typically *exactly*
    // DIFFICULTY_TARGET_V2).
    const uint64_t HEIGHT_ESTIMATE_HEIGHT;
    const time_t HEIGHT_ESTIMATE_TIMESTAMP;

    const uint64_t PUBLIC_ADDRESS_BASE58_PREFIX;
    const uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
    const uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX;
    const uint16_t P2P_DEFAULT_PORT;
    const uint16_t RPC_DEFAULT_PORT;
    const uint16_t QNET_DEFAULT_PORT;
    const std::array<unsigned char, 16> NETWORK_ID;
    const std::string_view GENESIS_TX;
    const uint32_t GENESIS_NONCE;
    const std::chrono::seconds GOVERNANCE_REWARD_INTERVAL;
    // Two addresses for the governance wallet: [0] is used for hardfork v7-v10, [1] is used from
    // hardfork v11-v20.
    const std::array<std::string_view, 2> GOVERNANCE_WALLET_ADDRESS;

    // How much an uptime proof timestamp can deviate from our timestamp before we refuse it:
    const std::chrono::seconds UPTIME_PROOF_TOLERANCE;
    // How long to wait after startup before broadcasting a proof
    const std::chrono::seconds UPTIME_PROOF_STARTUP_DELAY;
    // How frequently to check whether we need to broadcast a proof
    const std::chrono::seconds UPTIME_PROOF_CHECK_INTERVAL;
    // How often to send proofs out to the network since the last proof we successfully sent.
    // (Approximately; this can be up to CHECK_INTERFACE/2 off in either direction).  The minimum
    // accepted time between proofs is half of this.
    const std::chrono::seconds UPTIME_PROOF_FREQUENCY;
    // The maximum time that we consider an uptime proof to be valid (i.e. after this time since the
    // last proof we consider the SN to be down)
    const std::chrono::seconds UPTIME_PROOF_VALIDITY;

    // True if this network requires storage server and lokinet.
    const bool HAVE_STORAGE_AND_LOKINET;

    // The ideal block time.  Before the pulse hardfork, the actual block time compared to this
    // determines the difficulty of subsequent blocks; with pulse this determines when each pulse
    // quorum begins block construction.
    const std::chrono::seconds TARGET_BLOCK_TIME;

    // Takes a duration and returns the number of blocks in that duration.
    constexpr int64_t BLOCKS_IN(std::chrono::seconds interval) const {
        return interval / TARGET_BLOCK_TIME;
    }
    constexpr int64_t BLOCKS_PER_DAY() const { return BLOCKS_IN(24h); }
    constexpr int64_t BLOCKS_PER_HOUR() const { return BLOCKS_IN(1h); }

    // Pulse parameters:
    //
    // Maximum amount of time the pulse leader will wait at each stage of the pulse construction for
    // a response from all validators.  If a validator times out then that validator is excluded
    // from future rounds of the pulse construction.
    const std::chrono::seconds PULSE_STAGE_TIMEOUT;
    // Maximum of time the network will wait for a pulse block before assuming it has failed and
    // starting a backup quorum.
    const std::chrono::seconds PULSE_ROUND_TIMEOUT;
    // Normally blocks are TARGET_BLOCK_TIME (2min) apart, but in the case of previous blocks being
    // too slow or too fast the pulse quorum block construction gets accelerated or delayed by up to
    // this amount to get back to the TARGET_BLOCK_TIME average.
    const std::chrono::seconds PULSE_MAX_START_ADJUSTMENT;
    // How many active service nodes we require to make pulse work.  This must be >=
    // PULSE_QUORUM_SIZE.  The network will stall (and require manual mining to resume) if this
    // threshold is reached.  This is intentionally designed to trigger (and stall the network) if
    // active nodes numbers drop to absurdly low levels.
    const size_t PULSE_MIN_SERVICE_NODES;

    constexpr std::chrono::seconds PULSE_MIN_TARGET_BLOCK_TIME() const {
        return TARGET_BLOCK_TIME - PULSE_MAX_START_ADJUSTMENT;
    }
    constexpr std::chrono::seconds PULSE_MAX_TARGET_BLOCK_TIME() const {
        return TARGET_BLOCK_TIME + PULSE_MAX_START_ADJUSTMENT;
    }

    // Batching SN Rewards
    //
    // Number of blocks between payouts to an individual wallet.  Each wallet uses a pseudo-random
    // offset from this to still receive every BATCHING_INTERVAL, but different wallets receive at
    // different offsets within the block cycle.
    const uint64_t BATCHING_INTERVAL;
    // The minimum payout (in atomic OXEN) required for the batch rewards to issue a payment
    const uint64_t MIN_BATCH_PAYMENT_AMOUNT;
    // Maximum number of batch payments in a single block:
    const uint64_t LIMIT_BATCH_OUTPUTS;
    // Number of blocks that a SN must be active before they start earning a share of the block
    // reward.
    const uint64_t SERVICE_NODE_PAYABLE_AFTER_BLOCKS;

    // Amount of time a stake remains locked after a deregistration:
    const std::chrono::seconds DEREGISTRATION_LOCK_DURATION;

    // Amount of time after initiating a SN unlock before the node expires (during which it must
    // stay registered or else will face the DEREGISTRATION_LOCK_DURATION penalty).
    const std::chrono::seconds UNLOCK_DURATION;

    // After a hardfork we will decommission sns but won't dereg, allowing time to update
    const uint64_t HARDFORK_DEREGISTRATION_GRACE_PERIOD;

    // batching and SNL will save the state every STORE_LONG_TERM_STATE_INTERVAL blocks; this helps
    // recovering the state faster (without having to go to the very beginning of the chain) in the
    // event of too many popped or reorged blocks.
    const uint64_t STORE_LONG_TERM_STATE_INTERVAL;

    // batching rewards stores reward balances for this many recent blocks (in addition to the
    // long-term interval blocks controlled by the above).  This is used to allow lookups of reward
    // balances at recent heights.
    const uint64_t STORE_RECENT_REWARDS;

    /// (HF21+) Number of blocks after a registration expires (i.e. regular requested removals,
    /// *not* deregs) during which the node is protected from liquidation-with-penalty.  Regular
    /// removals can still be submitted to remove it from the ETH pubkey list, but *not* penalizing
    /// liquidation (which also remove it but award a penalty reward to the liquidator) during this
    /// buffer period.
    const uint64_t ETH_EXIT_BUFFER;

    // Details of the ethereum smart contract managing rewards and chain its kept on:
    const uint32_t ETHEREUM_CHAIN_ID;
    const std::string_view ETHEREUM_REWARDS_CONTRACT;
    const std::string_view ETHEREUM_POOL_CONTRACT;

    // How frequently the reward rate gets recomputed for inclusion into Oxen blocks.  An Oxen block
    // that has a l2_height of x must include the reward computed at the highest block height <= x
    // that is divisible by this number.  For instance, if this is 1000, an Oxen block with
    // l2_height=12345678 uses the reward value computed at L2 height 12345000.
    const uint64_t L2_REWARD_POOL_UPDATE_BLOCKS;

    // How many blocks behind the last known head we use for the "safe" height, i.e. the cutoff
    // height for state change inclusions when building pulse blocks (so that we don't send things
    // that are too new that other nodes might not know about yet).
    const uint64_t L2_TRACKER_SAFE_BLOCKS;

    constexpr std::string_view governance_wallet_address(hf hard_fork_version) const {
        const auto wallet_switch =
                (NETWORK_TYPE == network_type::MAINNET || NETWORK_TYPE == network_type::FAKECHAIN)
                        ? hf::hf11_infinite_staking
                        : hf::hf10_bulletproofs;
        return GOVERNANCE_WALLET_ADDRESS[hard_fork_version >= wallet_switch ? 1 : 0];
    }
};

}  // namespace cryptonote
