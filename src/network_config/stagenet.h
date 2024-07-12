#pragma once

#include "devnet.h"
#include "mainnet.h"

namespace cryptonote::config::stagenet {

inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 0;
inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1720140000;
inline constexpr uint64_t PUBLIC_ADDRESS_BASE58_PREFIX = 4888;             // ~ ST2 .. ST4
inline constexpr uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 5272;  // ~ ST9 .. STB
inline constexpr uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX = 5656;          // ~ STF .. STJ
inline constexpr uint16_t P2P_DEFAULT_PORT = 11022;
inline constexpr uint16_t RPC_DEFAULT_PORT = 11023;
inline constexpr uint16_t QNET_DEFAULT_PORT = 11025;
inline constexpr boost::uuids::uuid const NETWORK_ID = {
        {0x61,
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
         0x65}};
inline constexpr std::string_view GENESIS_TX =
        "04011e1e01ff00018080c9db97f4fb2702fa27e905f604faa4eb084ee675faca77b0cfea9adec152"
        "6da33cae5e286f31624201dae05bf3fa1662b7fd373c92426763d921cf3745e10ee43edb510f690c"
        "656f247200000000000000000000000000000000000000000000000000000000000000000000"sv;
inline constexpr uint32_t GENESIS_NONCE = 12345;

inline constexpr std::array GOVERNANCE_WALLET_ADDRESS = {
        // hardfork v7-9
        "ST4BqQJpS2t8otav3yWwwX4eM4xTE1isFPNsGYyPVkDQeUPjmw4kJsW8NHWYq2FZcGMsVuqrBwGTfZydWyvzXoG22r2BJuPRf"sv,
        // hardfork v10
        "ST4BqQJpS2t8otav3yWwwX4eM4xTE1isFPNsGYyPVkDQeUPjmw4kJsW8NHWYq2FZcGMsVuqrBwGTfZydWyvzXoG22r2BJuPRf"sv,
};

inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 5s;

// Much shorter than mainnet so that you can test this more easily.
inline constexpr uint64_t ETH_REMOVAL_BUFFER = 2h / mainnet::TARGET_BLOCK_TIME;

inline constexpr uint32_t ETHEREUM_CHAIN_ID = 421614;
inline constexpr auto ETHEREUM_REWARDS_CONTRACT = "0xEF43cd64528eA89966E251d4FE17c660222D2c9d"sv;
inline constexpr auto ETHEREUM_POOL_CONTRACT = "0x408bCc6C9b942ECc4F289C080d2A1a2a3617Aff8"sv;

inline constexpr network_config config{
        network_type::STAGENET,
        HEIGHT_ESTIMATE_HEIGHT,
        HEIGHT_ESTIMATE_TIMESTAMP,
        PUBLIC_ADDRESS_BASE58_PREFIX,
        PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        PUBLIC_SUBADDRESS_BASE58_PREFIX,
        P2P_DEFAULT_PORT,
        RPC_DEFAULT_PORT,
        QNET_DEFAULT_PORT,
        NETWORK_ID,
        GENESIS_TX,
        GENESIS_NONCE,
        mainnet::GOVERNANCE_REWARD_INTERVAL,
        GOVERNANCE_WALLET_ADDRESS,
        mainnet::UPTIME_PROOF_TOLERANCE,
        mainnet::UPTIME_PROOF_STARTUP_DELAY,
        mainnet::UPTIME_PROOF_CHECK_INTERVAL,
        testnet::UPTIME_PROOF_FREQUENCY,
        testnet::UPTIME_PROOF_VALIDITY,
        false,  // storage & lokinet
        mainnet::TARGET_BLOCK_TIME,
        mainnet::PULSE_STAGE_TIMEOUT,
        mainnet::PULSE_ROUND_TIMEOUT,
        mainnet::PULSE_MAX_START_ADJUSTMENT,
        testnet::PULSE_MIN_SERVICE_NODES,
        testnet::BATCHING_INTERVAL,
        mainnet::MIN_BATCH_PAYMENT_AMOUNT,
        mainnet::LIMIT_BATCH_OUTPUTS,
        testnet::SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
        mainnet::HARDFORK_DEREGISTRATION_GRACE_PERIOD,
        mainnet::STORE_LONG_TERM_STATE_INTERVAL,
        ETH_REMOVAL_BUFFER,
        ETHEREUM_CHAIN_ID,
        ETHEREUM_REWARDS_CONTRACT,
        ETHEREUM_POOL_CONTRACT,
        mainnet::L2_REWARD_POOL_UPDATE_BLOCKS,
};

}  // namespace cryptonote::config::stagenet
