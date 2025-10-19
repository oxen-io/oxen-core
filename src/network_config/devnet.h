#pragma once

#include "mainnet.h"
#include "testnet.h"

namespace cryptonote::config::devnet {

inline constexpr std::array seeds = {
        "37.27.236.229:34602"sv,  // public.session.foundation
        "104.243.40.38:34619"sv,  // angus.oxen.io
};

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
                  0xd7}},
        .P2P_SEED_NODES = seeds,
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
        .MAX_DEACTIVATE_PER_BLOCK = testnet::config.MAX_DEACTIVATE_PER_BLOCK,
        .HAVE_STORAGE_SERVER = false,
        .HAVE_SESSION_ROUTER = false,
        .HAVE_LOKINET = false,
        .TARGET_BLOCK_TIME = 30s,
        .PULSE_STAGE_TIMEOUT = 10s,
        .PULSE_ROUND_TIMEOUT = 30s,
        .PULSE_MAX_START_ADJUSTMENT = 10s,
        .PULSE_MIN_SERVICE_NODES = testnet::config.PULSE_MIN_SERVICE_NODES,
        .BATCHING_INTERVAL = testnet::config.BATCHING_INTERVAL,
        .MIN_BATCH_PAYMENT_AMOUNT = mainnet::config.MIN_BATCH_PAYMENT_AMOUNT,
        .LIMIT_BATCH_OUTPUTS = mainnet::config.LIMIT_BATCH_OUTPUTS,
        .SERVICE_NODE_PAYABLE_AFTER_BLOCKS = testnet::config.SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
        .DEREGISTRATION_LOCK_DURATION = testnet::config.DEREGISTRATION_LOCK_DURATION,
        .UNLOCK_DURATION = testnet::config.UNLOCK_DURATION,
        .HARDFORK_DEREGISTRATION_GRACE_PERIOD = 100,
        .HISTORY_ARCHIVE_INTERVAL = mainnet::config.HISTORY_ARCHIVE_INTERVAL,
        .HISTORY_ARCHIVE_KEEP_WINDOW = mainnet::config.HISTORY_ARCHIVE_KEEP_WINDOW,
        .HISTORY_RECENT_KEEP_WINDOW = mainnet::config.HISTORY_RECENT_KEEP_WINDOW,
        .ETH_EXIT_BUFFER = testnet::config.ETH_EXIT_BUFFER,
        .ETH_DEREG_BUFFER = testnet::config.ETH_DEREG_BUFFER,
        .ETHEREUM_CHAIN_ID = 42161,  // Arbitrum Mainnet
        .ETHEREUM_REWARDS_CONTRACT = "0xDa11D8E9EDE9c5A1a40A5D1cF3A5278bAd139f07",
        .ETHEREUM_POOL_CONTRACT = "0x35FD198cAEa28457AA0C47b2777F944c634810CF",
        .L2_REWARD_POOL_UPDATE_BLOCKS = testnet::config.L2_REWARD_POOL_UPDATE_BLOCKS,
        .L2_TRACKER_SAFE_BLOCKS = mainnet::config.L2_TRACKER_SAFE_BLOCKS,
        .L2_NODE_LIST_PURGE_BLOCKS = 10min / L2_BLOCK_TIME,
        .L2_NODE_LIST_PURGE_MIN_OXEN_AGE = mainnet::config.L2_NODE_LIST_PURGE_MIN_OXEN_AGE,
        .DEFAULT_STAKING_URL = "https://stake-dev.getsession.org"sv,
};
}  // namespace cryptonote::config::devnet
