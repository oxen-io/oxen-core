#pragma once

#include "devnet.h"

// NOTE: A local-devnet involves launching typically a local Ethereum
// blockchain via Hardhat, Ganache or Foundry's Anvil for example.
// These use local-developer wallets which deploy our rewards contract
// to a deterministic address different from those deployed on a
// live-devnet (because the wallets may be live-wallets that produce
// different contract addresses).
//
// These addresses below are the current up-to-date contract addresses
// that would be used if deployed on a local-devnet and can be enabled
// by defining the macro accordingly.
//
// A local-devnet can be deployed by running
// `utils/local-devnet/service_node_network.py`

namespace cryptonote::config::localdev {

inline constexpr uint32_t ETHEREUM_CHAIN_ID = 31337;
inline constexpr auto ETHEREUM_REWARDS_CONTRACT = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"sv;
inline constexpr auto ETHEREUM_POOL_CONTRACT = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"sv;

inline constexpr uint64_t L2_REWARD_POOL_UPDATE_BLOCKS = 4;

inline constexpr auto TARGET_BLOCK_TIME = 6s;
inline constexpr auto PULSE_STAGE_TIMEOUT = 1s;
inline constexpr auto PULSE_ROUND_TIMEOUT = 3s;
inline constexpr auto PULSE_MAX_START_ADJUSTMENT = 3s;

inline constexpr network_config config{
        network_type::LOCALDEV,
        devnet::HEIGHT_ESTIMATE_HEIGHT,
        devnet::HEIGHT_ESTIMATE_TIMESTAMP,
        devnet::PUBLIC_ADDRESS_BASE58_PREFIX,
        devnet::PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        devnet::PUBLIC_SUBADDRESS_BASE58_PREFIX,
        devnet::P2P_DEFAULT_PORT,
        devnet::RPC_DEFAULT_PORT,
        devnet::QNET_DEFAULT_PORT,
        devnet::NETWORK_ID,
        devnet::GENESIS_TX,
        devnet::GENESIS_NONCE,
        mainnet::GOVERNANCE_REWARD_INTERVAL,
        devnet::GOVERNANCE_WALLET_ADDRESS,
        mainnet::UPTIME_PROOF_TOLERANCE,
        mainnet::UPTIME_PROOF_STARTUP_DELAY,
        mainnet::UPTIME_PROOF_CHECK_INTERVAL,
        testnet::UPTIME_PROOF_FREQUENCY,
        testnet::UPTIME_PROOF_VALIDITY,
        false, // storage & lokinet
        TARGET_BLOCK_TIME,
        PULSE_STAGE_TIMEOUT,
        PULSE_ROUND_TIMEOUT,
        PULSE_MAX_START_ADJUSTMENT,
        testnet::PULSE_MIN_SERVICE_NODES,
        testnet::BATCHING_INTERVAL,
        mainnet::MIN_BATCH_PAYMENT_AMOUNT,
        mainnet::LIMIT_BATCH_OUTPUTS,
        testnet::SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
        mainnet::HARDFORK_DEREGISTRATION_GRACE_PERIOD,
        mainnet::STORE_LONG_TERM_STATE_INTERVAL,
        testnet::ETH_REMOVAL_BUFFER,
        devnet::ETHEREUM_CHAIN_ID,
        devnet::ETHEREUM_REWARDS_CONTRACT,
        devnet::ETHEREUM_POOL_CONTRACT,
        L2_REWARD_POOL_UPDATE_BLOCKS,
};

}  // namespace cryptonote::config::localdev
