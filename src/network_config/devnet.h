#pragma once

#include "mainnet.h"
#include "testnet.h"

namespace cryptonote::config::devnet {

inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 0;
inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1597170000;
inline constexpr uint64_t PUBLIC_ADDRESS_BASE58_PREFIX = 3930;             // ~ dV1 .. dV3
inline constexpr uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 4442;  // ~ dVA .. dVC
inline constexpr uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX = 5850;          // ~dVa .. dVc
inline constexpr uint16_t P2P_DEFAULT_PORT = 38856;
inline constexpr uint16_t RPC_DEFAULT_PORT = 38857;
inline constexpr uint16_t QNET_DEFAULT_PORT = 38859;
inline constexpr boost::uuids::uuid const NETWORK_ID = {
        {0xa9,
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
         0xd5}};
inline constexpr std::string_view GENESIS_TX =
        "04011e1e01ff00018080c9db97f4fb2702fa27e905f604faa4eb084ee675faca77b0cfea9adec152"
        "6da33cae5e286f31624201dae05bf3fa1662b7fd373c92426763d921cf3745e10ee43edb510f690c"
        "656f247200000000000000000000000000000000000000000000000000000000000000000000"sv;
inline constexpr uint32_t GENESIS_NONCE = 12345;

inline constexpr std::array GOVERNANCE_WALLET_ADDRESS = {
        // hardfork v7-9
        "dV3EhSE1xXgSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M4A7Uimp"sv,
        // hardfork v10
        "dV3EhSE1xXgSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M4A7Uimp"sv,
};

inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 5s;

inline constexpr uint32_t ETHEREUM_CHAIN_ID = 421614;
inline constexpr auto ETHEREUM_REWARDS_CONTRACT = "0xB333811db68888800a23E79b38E401451d97aEdD"sv;
inline constexpr auto ETHEREUM_POOL_CONTRACT = "0x8B11c5777EE7BFC1F1195A9ef0506Ae7846CC5b8"sv;

inline constexpr network_config config{
        network_type::DEVNET,
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
        false, // storage & lokinet
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
        testnet::ETH_REMOVAL_BUFFER,
        ETHEREUM_CHAIN_ID,
        ETHEREUM_REWARDS_CONTRACT,
        ETHEREUM_POOL_CONTRACT,
        mainnet::L2_REWARD_POOL_UPDATE_BLOCKS,
};

}  // namespace cryptonote::config::devnet
