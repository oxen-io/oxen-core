#pragma once

#include "mainnet.h"
#include "testnet.h"

namespace cryptonote::config::stagenet {
inline constexpr network_config config{
        .NETWORK_TYPE = network_type::STAGENET,
        .DEFAULT_CONFIG_SUBDIR = "stagenet2"sv,
        .HEIGHT_ESTIMATE_HEIGHT = 0,
        .HEIGHT_ESTIMATE_TIMESTAMP = 1720140000,
        .PUBLIC_ADDRESS_BASE58_PREFIX = 4888,             // ~ ST2 .. ST4
        .PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 5272,  // ~ ST9 .. STB
        .PUBLIC_SUBADDRESS_BASE58_PREFIX = 5656,          // ~ STF .. STJ
        .P2P_DEFAULT_PORT = 11022,
        .RPC_DEFAULT_PORT = 11023,
        .QNET_DEFAULT_PORT = 11025,
        .NETWORK_ID =
                {{0x41,
                  0x6c,
                  0x6c,
                  0x79,
                  0x6f,
                  0x75,
                  0x72,
                  0x53,
                  0x45,
                  0x4e,
                  0x54,
                  0x61,
                  0x72,
                  0x65,
                  0x62,
                  0x65}},
        .GENESIS_TX =
                "04011e1e01ff00018080c9db97f4fb2702fa27e905f604faa4eb084ee675faca77b0cfea9adec1526d"
                "a33cae5e286f31624201dae05bf3fa1662b7fd373c92426763d921cf3745e10ee43edb510f690c656f"
                "247200000000000000000000000000000000000000000000000000000000000000000000"sv,
        .GENESIS_NONCE = 12345,
        .GOVERNANCE_REWARD_INTERVAL = mainnet::config.GOVERNANCE_REWARD_INTERVAL,
        .GOVERNANCE_WALLET_ADDRESS =
                {
                        "ST4BqQJpS2t8otav3yWwwX4eM4xTE1isFPNsGYyPVkDQeUPjmw4kJsW8NHWYq2FZcGMsVuqrBw"
                        "GTfZydWyvzXoG22r2BJuPRf",  // HF7-9
                        "ST4BqQJpS2t8otav3yWwwX4eM4xTE1isFPNsGYyPVkDQeUPjmw4kJsW8NHWYq2FZcGMsVuqrBw"
                        "GTfZydWyvzXoG22r2BJuPRf",  // HF10
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
        // Much shorter than mainnet so that you can test this more easily.
        .ETH_EXIT_BUFFER = 2h / mainnet::config.TARGET_BLOCK_TIME,
        .ETHEREUM_CHAIN_ID = 421614,
        .ETHEREUM_REWARDS_CONTRACT = "0xb691e7C159369475D0a3d4694639ae0144c7bAB2"sv,
        .ETHEREUM_POOL_CONTRACT = "0x84a648F74Eaf037dD9558987F6179E692d5F2566"sv,
        .L2_REWARD_POOL_UPDATE_BLOCKS = testnet::config.L2_REWARD_POOL_UPDATE_BLOCKS,
        .L2_TRACKER_SAFE_BLOCKS = mainnet::config.L2_TRACKER_SAFE_BLOCKS,
};
}  // namespace cryptonote::config::stagenet
