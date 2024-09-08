#pragma once

#include "mainnet.h"

namespace cryptonote::config::testnet {
inline constexpr network_config config{
        .NETWORK_TYPE = network_type::TESTNET,
        .DEFAULT_CONFIG_SUBDIR = "testnet"sv,
        .HEIGHT_ESTIMATE_HEIGHT = 339767,
        .HEIGHT_ESTIMATE_TIMESTAMP = 1595360006,
        .PUBLIC_ADDRESS_BASE58_PREFIX = 156,
        .PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 157,
        .PUBLIC_SUBADDRESS_BASE58_PREFIX = 158,
        .P2P_DEFAULT_PORT = 38156,
        .RPC_DEFAULT_PORT = 38157,
        .QNET_DEFAULT_PORT = 38159,
        .NETWORK_ID = {{
                0x22,
                0x3a,
                0x78,
                0x65,
                0xe1,
                0x6f,
                0xca,
                0xb8,
                0x02,
                0xa1,
                0xdc,
                0x17,
                0x61,
                0x64,
                0x15,
                0xbe,
        }},
        .GENESIS_TX =
                "04011e1e01ff00018080c9db97f4fb2702fa27e905f604faa4eb084ee675faca77b0cfea9adec152"
                "6da33cae5e286f31624201dae05bf3fa1662b7fd373c92426763d921cf3745e10ee43edb510f690c"
                "656f247200000000000000000000000000000000000000000000000000000000000000000000"sv,
        .GENESIS_NONCE = 12345,
        .GOVERNANCE_REWARD_INTERVAL = 2000min,
        .GOVERNANCE_WALLET_ADDRESS =
                {
                        "T6Tnu9YUgVcSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M482ypm7"sv,  // HF7-9
                        "T6Tnu9YUgVcSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M482ypm7"sv,  // HF10
                },
        .UPTIME_PROOF_TOLERANCE = mainnet::config.UPTIME_PROOF_TOLERANCE,
        .UPTIME_PROOF_STARTUP_DELAY = mainnet::config.UPTIME_PROOF_STARTUP_DELAY,
        .UPTIME_PROOF_CHECK_INTERVAL = mainnet::config.UPTIME_PROOF_CHECK_INTERVAL,
        // Testnet uptime proofs are 6x faster than mainnet (devnet config also uses these)
        .UPTIME_PROOF_FREQUENCY = 10min,
        .UPTIME_PROOF_VALIDITY = 21min,
        .HAVE_STORAGE_AND_LOKINET = true,  // storage & lokinet
        .TARGET_BLOCK_TIME = mainnet::config.TARGET_BLOCK_TIME,
        .PULSE_STAGE_TIMEOUT = mainnet::config.PULSE_STAGE_TIMEOUT,
        .PULSE_ROUND_TIMEOUT = mainnet::config.PULSE_ROUND_TIMEOUT,
        .PULSE_MAX_START_ADJUSTMENT = mainnet::config.PULSE_MAX_START_ADJUSTMENT,
        .PULSE_MIN_SERVICE_NODES = 12,  // == pulse quorum size
        .BATCHING_INTERVAL = 20,
        .MIN_BATCH_PAYMENT_AMOUNT = mainnet::config.MIN_BATCH_PAYMENT_AMOUNT,
        .LIMIT_BATCH_OUTPUTS = mainnet::config.LIMIT_BATCH_OUTPUTS,
        .SERVICE_NODE_PAYABLE_AFTER_BLOCKS = 4,
        .DEREGISTRATION_LOCK_DURATION = 48h,
        .UNLOCK_DURATION = 24h,
        .HARDFORK_DEREGISTRATION_GRACE_PERIOD =
                mainnet::config.HARDFORK_DEREGISTRATION_GRACE_PERIOD,
        .STORE_LONG_TERM_STATE_INTERVAL = mainnet::config.STORE_LONG_TERM_STATE_INTERVAL,
        .STORE_RECENT_REWARDS = mainnet::config.STORE_RECENT_REWARDS,
        // Much shorter than mainnet so that you can test this more easily.
        .ETH_REMOVAL_BUFFER = 1h / mainnet::config.TARGET_BLOCK_TIME,
        // FIXME!
        .ETHEREUM_CHAIN_ID = static_cast<uint32_t>(-1),
        .ETHEREUM_REWARDS_CONTRACT = "0x0000000000000000000000000000000000000000",
        .ETHEREUM_POOL_CONTRACT = "0x0000000000000000000000000000000000000000",
        // Sepolia arbitrum sometimes slows down below the typical 250ms seen on mainnet, so for
        // testnet/devnet we shorten this by half compared to mainnet:
        .L2_REWARD_POOL_UPDATE_BLOCKS = mainnet::config.L2_REWARD_POOL_UPDATE_BLOCKS / 4,
        .L2_TRACKER_SAFE_BLOCKS = mainnet::config.L2_TRACKER_SAFE_BLOCKS,
};
}  // namespace cryptonote::config::testnet
