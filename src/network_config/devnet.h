#pragma once

#include "mainnet.h"
#include "testnet.h"

namespace cryptonote::config::devnet {
inline constexpr network_config config{
        .NETWORK_TYPE = network_type::DEVNET,
        .DEFAULT_CONFIG_SUBDIR = "devnet3"sv,
        .HEIGHT_ESTIMATE_HEIGHT = 0,
        .HEIGHT_ESTIMATE_TIMESTAMP = 1597170000,
        .PUBLIC_ADDRESS_BASE58_PREFIX = 3930,             // ~ dV1 .. dV3
        .PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 4442,  // ~ dVA .. dVC
        .PUBLIC_SUBADDRESS_BASE58_PREFIX = 5850,          // ~ dVa .. dVc
        .P2P_DEFAULT_PORT = 38856,
        .RPC_DEFAULT_PORT = 38857,
        .QNET_DEFAULT_PORT = 38859,
        .NETWORK_ID =
                {{0x03,
                  0xf7,
                  0x5c,
                  0x7d,
                  0x5d,
                  0x17,
                  0xcb,
                  0x6b,
                  0x1b,
                  0xf4,
                  0x63,
                  0x79,
                  0x7a,
                  0x57,
                  0xab,
                  0xd5}},
        .GENESIS_TX =
                "04011e1e01ff00018080c9db97f4fb2702fa27e905f604faa4eb084ee675faca77b0cfea9adec152"
                "6da33cae5e286f31624201dae05bf3fa1662b7fd373c92426763d921cf3745e10ee43edb510f690c"
                "656f247200000000000000000000000000000000000000000000000000000000000000000000"sv,
        .GENESIS_NONCE = 12345,
        .GOVERNANCE_REWARD_INTERVAL = mainnet::config.GOVERNANCE_REWARD_INTERVAL,
        .GOVERNANCE_WALLET_ADDRESS =
                {
                        "dV3EhSE1xXgSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYd"
                        "gzZhDLMTo9uEv82M4A7Uimp",  // HF7-9
                        "dV3EhSE1xXgSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYd"
                        "gzZhDLMTo9uEv82M4A7Uimp",  // HF10
                },
        .UPTIME_PROOF_TOLERANCE = mainnet::config.UPTIME_PROOF_TOLERANCE,
        .UPTIME_PROOF_STARTUP_DELAY = 5s,
        .UPTIME_PROOF_CHECK_INTERVAL = mainnet::config.UPTIME_PROOF_CHECK_INTERVAL,
        .UPTIME_PROOF_FREQUENCY = testnet::config.UPTIME_PROOF_FREQUENCY,
        .UPTIME_PROOF_VALIDITY = testnet::config.UPTIME_PROOF_VALIDITY,
        .HAVE_STORAGE_AND_LOKINET = false,  // storage & lokinet
        .TARGET_BLOCK_TIME = mainnet::TARGET_BLOCK_TIME,
        .PULSE_STAGE_TIMEOUT = mainnet::config.PULSE_STAGE_TIMEOUT,
        .PULSE_ROUND_TIMEOUT = mainnet::config.PULSE_ROUND_TIMEOUT,
        .PULSE_MAX_START_ADJUSTMENT = mainnet::config.PULSE_MAX_START_ADJUSTMENT,
        .PULSE_MIN_SERVICE_NODES = testnet::config.PULSE_MIN_SERVICE_NODES,
        .BATCHING_INTERVAL = testnet::config.BATCHING_INTERVAL,
        .MIN_BATCH_PAYMENT_AMOUNT = mainnet::config.MIN_BATCH_PAYMENT_AMOUNT,
        .LIMIT_BATCH_OUTPUTS = mainnet::config.LIMIT_BATCH_OUTPUTS,
        .SERVICE_NODE_PAYABLE_AFTER_BLOCKS = testnet::config.SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
        .DEREGISTRATION_LOCK_DURATION = testnet::config.DEREGISTRATION_LOCK_DURATION,
        .UNLOCK_DURATION = testnet::config.UNLOCK_DURATION,
        .HARDFORK_DEREGISTRATION_GRACE_PERIOD =
                mainnet::config.HARDFORK_DEREGISTRATION_GRACE_PERIOD,
        .STORE_LONG_TERM_STATE_INTERVAL = mainnet::config.STORE_LONG_TERM_STATE_INTERVAL,
        .STORE_RECENT_REWARDS = mainnet::config.STORE_RECENT_REWARDS,
        .ETH_EXIT_BUFFER = testnet::config.ETH_EXIT_BUFFER,
        .ETHEREUM_CHAIN_ID = 421614,  // Arbitrum Sepolia
        .ETHEREUM_REWARDS_CONTRACT = "0x75Dc11700b2D03902FCb5Ca7aFd6A859a1Fa25Cb",
        .ETHEREUM_POOL_CONTRACT = "0xb515C61DE12f28eE908a905b930aFb80B9bAd7cf",
        .L2_REWARD_POOL_UPDATE_BLOCKS = testnet::config.L2_REWARD_POOL_UPDATE_BLOCKS,
        .L2_TRACKER_SAFE_BLOCKS = mainnet::config.L2_TRACKER_SAFE_BLOCKS,
        .L2_NODE_LIST_PURGE_BLOCKS = 10min / L2_BLOCK_TIME,
        .L2_NODE_LIST_PURGE_MIN_OXEN_AGE = mainnet::config.L2_NODE_LIST_PURGE_MIN_OXEN_AGE,
};
}  // namespace cryptonote::config::devnet
