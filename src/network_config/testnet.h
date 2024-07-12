#pragma once

#include "mainnet.h"

namespace cryptonote::config::testnet {

inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 339767;
inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1595360006;
inline constexpr uint64_t PUBLIC_ADDRESS_BASE58_PREFIX = 156;
inline constexpr uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 157;
inline constexpr uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX = 158;
inline constexpr uint16_t P2P_DEFAULT_PORT = 38156;
inline constexpr uint16_t RPC_DEFAULT_PORT = 38157;
inline constexpr uint16_t QNET_DEFAULT_PORT = 38159;
inline constexpr boost::uuids::uuid const NETWORK_ID = {{
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
}};
inline constexpr std::string_view GENESIS_TX =
        "04011e1e01ff00018080c9db97f4fb2702fa27e905f604faa4eb084ee675faca77b0cfea9adec152"
        "6da33cae5e286f31624201dae05bf3fa1662b7fd373c92426763d921cf3745e10ee43edb510f690c"
        "656f247200000000000000000000000000000000000000000000000000000000000000000000"sv;
inline constexpr uint32_t GENESIS_NONCE = 12345;

inline constexpr auto GOVERNANCE_REWARD_INTERVAL = 2000min;
inline constexpr std::array GOVERNANCE_WALLET_ADDRESS = {
        // hardfork v7-9
        "T6Tnu9YUgVcSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M482ypm7"sv,
        // hardfork v10
        "T6Tnu9YUgVcSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M482ypm7"sv,
};

// Testnet uptime proofs are 6x faster than mainnet (devnet config also uses these)
inline constexpr auto UPTIME_PROOF_FREQUENCY = 10min;
inline constexpr auto UPTIME_PROOF_VALIDITY = 21min;
inline constexpr uint64_t BATCHING_INTERVAL = 20;
inline constexpr uint64_t SERVICE_NODE_PAYABLE_AFTER_BLOCKS = 4;

inline constexpr size_t PULSE_MIN_SERVICE_NODES = 12;  // == pulse quorum size

// Much shorter than mainnet so that you can test this more easily.
inline constexpr uint64_t ETH_REMOVAL_BUFFER = 1h / mainnet::TARGET_BLOCK_TIME;

// FIXME!
inline constexpr uint32_t ETHEREUM_CHAIN_ID = -1;
inline constexpr auto ETHEREUM_REWARDS_CONTRACT = "0x0000000000000000000000000000000000000000"sv;
inline constexpr auto ETHEREUM_POOL_CONTRACT = "0x0000000000000000000000000000000000000000"sv;

inline constexpr network_config config{
        network_type::TESTNET,
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
        GOVERNANCE_REWARD_INTERVAL,
        GOVERNANCE_WALLET_ADDRESS,
        mainnet::UPTIME_PROOF_TOLERANCE,
        mainnet::UPTIME_PROOF_STARTUP_DELAY,
        mainnet::UPTIME_PROOF_CHECK_INTERVAL,
        UPTIME_PROOF_FREQUENCY,
        UPTIME_PROOF_VALIDITY,
        true, // storage & lokinet
        mainnet::TARGET_BLOCK_TIME,
        mainnet::PULSE_STAGE_TIMEOUT,
        mainnet::PULSE_ROUND_TIMEOUT,
        mainnet::PULSE_MAX_START_ADJUSTMENT,
        PULSE_MIN_SERVICE_NODES,
        BATCHING_INTERVAL,
        mainnet::MIN_BATCH_PAYMENT_AMOUNT,
        mainnet::LIMIT_BATCH_OUTPUTS,
        SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
        mainnet::HARDFORK_DEREGISTRATION_GRACE_PERIOD,
        mainnet::STORE_LONG_TERM_STATE_INTERVAL,
        ETH_REMOVAL_BUFFER,
        ETHEREUM_CHAIN_ID,
        ETHEREUM_REWARDS_CONTRACT,
        ETHEREUM_POOL_CONTRACT,
        mainnet::L2_REWARD_POOL_UPDATE_BLOCKS,
};

}  // namespace cryptonote::config::testnet
