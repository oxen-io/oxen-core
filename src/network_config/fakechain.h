#pragma once

#include "mainnet.h"
#include "testnet.h"

namespace cryptonote::config::fakechain {
inline constexpr network_config config{
        .NETWORK_TYPE = network_type::FAKECHAIN,
        .DEFAULT_CONFIG_SUBDIR = "regtest"sv,
        .HEIGHT_ESTIMATE_HEIGHT = mainnet::config.HEIGHT_ESTIMATE_HEIGHT,
        .HEIGHT_ESTIMATE_TIMESTAMP = mainnet::config.HEIGHT_ESTIMATE_TIMESTAMP,
        .PUBLIC_ADDRESS_BASE58_PREFIX = mainnet::config.PUBLIC_ADDRESS_BASE58_PREFIX,
        .PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX =
                mainnet::config.PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        .PUBLIC_SUBADDRESS_BASE58_PREFIX = mainnet::config.PUBLIC_SUBADDRESS_BASE58_PREFIX,
        .P2P_DEFAULT_PORT = mainnet::config.P2P_DEFAULT_PORT,
        .RPC_DEFAULT_PORT = mainnet::config.RPC_DEFAULT_PORT,
        .QNET_DEFAULT_PORT = mainnet::config.QNET_DEFAULT_PORT,
        .NETWORK_ID = mainnet::config.NETWORK_ID,
        .GENESIS_TX = mainnet::config.GENESIS_TX,
        .GENESIS_NONCE = mainnet::config.GENESIS_NONCE,
        .GOVERNANCE_REWARD_INTERVAL = 200min,
        .GOVERNANCE_WALLET_ADDRESS = mainnet::config.GOVERNANCE_WALLET_ADDRESS,
        .UPTIME_PROOF_TOLERANCE = mainnet::config.UPTIME_PROOF_TOLERANCE,
        // Fakechain uptime proofs are 60x faster than mainnet, because this
        // really only runs on a hand-crafted, typically local temporary
        // network.
        .UPTIME_PROOF_STARTUP_DELAY = 5s,
        .UPTIME_PROOF_CHECK_INTERVAL = 5s,
        .UPTIME_PROOF_FREQUENCY = 1min,
        .UPTIME_PROOF_VALIDITY = 2min + 5s,
        .HAVE_STORAGE_AND_LOKINET = false,
        .TARGET_BLOCK_TIME = mainnet::config.TARGET_BLOCK_TIME,
        .PULSE_STAGE_TIMEOUT = mainnet::config.PULSE_STAGE_TIMEOUT,
        .PULSE_ROUND_TIMEOUT = mainnet::config.PULSE_ROUND_TIMEOUT,
        .PULSE_MAX_START_ADJUSTMENT = mainnet::config.PULSE_MAX_START_ADJUSTMENT,
        .PULSE_MIN_SERVICE_NODES = mainnet::config.PULSE_MIN_SERVICE_NODES,
        .BATCHING_INTERVAL = testnet::config.BATCHING_INTERVAL,
        .MIN_BATCH_PAYMENT_AMOUNT = mainnet::config.MIN_BATCH_PAYMENT_AMOUNT,
        .LIMIT_BATCH_OUTPUTS = mainnet::config.LIMIT_BATCH_OUTPUTS,
        .SERVICE_NODE_PAYABLE_AFTER_BLOCKS = testnet::config.SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
        .DEREGISTRATION_LOCK_DURATION = 1h,
        .UNLOCK_DURATION = 30min,
        .HARDFORK_DEREGISTRATION_GRACE_PERIOD =
                mainnet::config.HARDFORK_DEREGISTRATION_GRACE_PERIOD,
        .STORE_LONG_TERM_STATE_INTERVAL = mainnet::config.STORE_LONG_TERM_STATE_INTERVAL,
        .STORE_RECENT_REWARDS = mainnet::config.STORE_RECENT_REWARDS,
        .ETH_REMOVAL_BUFFER = testnet::config.ETH_REMOVAL_BUFFER,
        .ETHEREUM_CHAIN_ID = mainnet::config.ETHEREUM_CHAIN_ID,
        .ETHEREUM_REWARDS_CONTRACT = mainnet::config.ETHEREUM_REWARDS_CONTRACT,
        .ETHEREUM_POOL_CONTRACT = mainnet::config.ETHEREUM_POOL_CONTRACT,
        .L2_REWARD_POOL_UPDATE_BLOCKS = mainnet::config.L2_REWARD_POOL_UPDATE_BLOCKS,
        .L2_TRACKER_SAFE_BLOCKS = mainnet::config.L2_TRACKER_SAFE_BLOCKS,
};
}  // namespace cryptonote::config::fakechain
