#pragma once

#include "mainnet.h"
#include "testnet.h"

namespace cryptonote::config::fakechain {

// Fakechain uptime proofs are 60x faster than mainnet, because this really only runs on a
// hand-crafted, typically local temporary network.
inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 5s;
inline constexpr auto UPTIME_PROOF_CHECK_INTERVAL = 5s;
inline constexpr auto UPTIME_PROOF_FREQUENCY = 1min;
inline constexpr auto UPTIME_PROOF_VALIDITY = 2min + 5s;

inline constexpr auto GOVERNANCE_REWARD_INTERVAL = 200min;

inline constexpr network_config config{
        network_type::FAKECHAIN,
        mainnet::HEIGHT_ESTIMATE_HEIGHT,
        mainnet::HEIGHT_ESTIMATE_TIMESTAMP,
        mainnet::PUBLIC_ADDRESS_BASE58_PREFIX,
        mainnet::PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        mainnet::PUBLIC_SUBADDRESS_BASE58_PREFIX,
        mainnet::P2P_DEFAULT_PORT,
        mainnet::RPC_DEFAULT_PORT,
        mainnet::QNET_DEFAULT_PORT,
        mainnet::NETWORK_ID,
        mainnet::GENESIS_TX,
        mainnet::GENESIS_NONCE,
        GOVERNANCE_REWARD_INTERVAL,
        mainnet::GOVERNANCE_WALLET_ADDRESS,
        mainnet::UPTIME_PROOF_TOLERANCE,
        UPTIME_PROOF_STARTUP_DELAY,
        UPTIME_PROOF_CHECK_INTERVAL,
        UPTIME_PROOF_FREQUENCY,
        UPTIME_PROOF_VALIDITY,
        false, // storage & lokinet
        mainnet::TARGET_BLOCK_TIME,
        mainnet::PULSE_STAGE_TIMEOUT,
        mainnet::PULSE_ROUND_TIMEOUT,
        mainnet::PULSE_MAX_START_ADJUSTMENT,
        mainnet::PULSE_MIN_SERVICE_NODES,
        testnet::BATCHING_INTERVAL,
        mainnet::MIN_BATCH_PAYMENT_AMOUNT,
        mainnet::LIMIT_BATCH_OUTPUTS,
        testnet::SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
        mainnet::HARDFORK_DEREGISTRATION_GRACE_PERIOD,
        mainnet::STORE_LONG_TERM_STATE_INTERVAL,
        testnet::ETH_REMOVAL_BUFFER,
        mainnet::ETHEREUM_CHAIN_ID,
        mainnet::ETHEREUM_REWARDS_CONTRACT,
        mainnet::ETHEREUM_POOL_CONTRACT,
        mainnet::L2_REWARD_POOL_UPDATE_BLOCKS,
};


}  // namespace cryptonote::config::fakechain
