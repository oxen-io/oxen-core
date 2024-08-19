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
inline constexpr network_config config{
        .NETWORK_TYPE = network_type::LOCALDEV,
        .DEFAULT_CONFIG_SUBDIR = "localdev"sv,
        .HEIGHT_ESTIMATE_HEIGHT = devnet::config.HEIGHT_ESTIMATE_HEIGHT,
        .HEIGHT_ESTIMATE_TIMESTAMP = devnet::config.HEIGHT_ESTIMATE_TIMESTAMP,
        .PUBLIC_ADDRESS_BASE58_PREFIX = devnet::config.PUBLIC_ADDRESS_BASE58_PREFIX,
        .PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX =
                devnet::config.PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        .PUBLIC_SUBADDRESS_BASE58_PREFIX = devnet::config.PUBLIC_SUBADDRESS_BASE58_PREFIX,
        .P2P_DEFAULT_PORT = devnet::config.P2P_DEFAULT_PORT,
        .RPC_DEFAULT_PORT = devnet::config.RPC_DEFAULT_PORT,
        .QNET_DEFAULT_PORT = devnet::config.QNET_DEFAULT_PORT,
        .NETWORK_ID = devnet::config.NETWORK_ID,
        .GENESIS_TX = devnet::config.GENESIS_TX,
        .GENESIS_NONCE = devnet::config.GENESIS_NONCE,
        .GOVERNANCE_REWARD_INTERVAL = mainnet::config.GOVERNANCE_REWARD_INTERVAL,
        .GOVERNANCE_WALLET_ADDRESS = devnet::config.GOVERNANCE_WALLET_ADDRESS,
        .UPTIME_PROOF_TOLERANCE = mainnet::config.UPTIME_PROOF_TOLERANCE,
        .UPTIME_PROOF_STARTUP_DELAY = mainnet::config.UPTIME_PROOF_STARTUP_DELAY,
        .UPTIME_PROOF_CHECK_INTERVAL = mainnet::config.UPTIME_PROOF_CHECK_INTERVAL,
        .UPTIME_PROOF_FREQUENCY = testnet::config.UPTIME_PROOF_FREQUENCY,
        .UPTIME_PROOF_VALIDITY = testnet::config.UPTIME_PROOF_VALIDITY,
        .HAVE_STORAGE_AND_LOKINET = false,
        .TARGET_BLOCK_TIME = 5s,
        .PULSE_STAGE_TIMEOUT = 3s,
        .PULSE_ROUND_TIMEOUT = 4s,
        .PULSE_MAX_START_ADJUSTMENT = 4s,
        .PULSE_MIN_SERVICE_NODES = testnet::config.PULSE_MIN_SERVICE_NODES,
        .BATCHING_INTERVAL = testnet::config.BATCHING_INTERVAL,
        .MIN_BATCH_PAYMENT_AMOUNT = mainnet::config.MIN_BATCH_PAYMENT_AMOUNT,
        .LIMIT_BATCH_OUTPUTS = mainnet::config.LIMIT_BATCH_OUTPUTS,
        .SERVICE_NODE_PAYABLE_AFTER_BLOCKS = 1,
        .HARDFORK_DEREGISTRATION_GRACE_PERIOD =
                mainnet::config.HARDFORK_DEREGISTRATION_GRACE_PERIOD,
        .STORE_LONG_TERM_STATE_INTERVAL = mainnet::config.STORE_LONG_TERM_STATE_INTERVAL,
        .ETH_REMOVAL_BUFFER = testnet::config.ETH_REMOVAL_BUFFER,
        .ETHEREUM_CHAIN_ID = 31337,
        .ETHEREUM_REWARDS_CONTRACT = "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"sv,
        .ETHEREUM_POOL_CONTRACT = "0x9fE46736679d2D9a65F0992F2272dE9f3c7fa6e0"sv,
        // Set the reward rate, polled from the smart contract to be sampled
        // very frequently because everything is running locally.
        // This is needed for tests because we are running Pulse nodes
        // which means block producing is slowed down due to round
        // timings and IPC. The L2 similarly is updating in lock-step with
        // the Oxen workchain.
        .L2_REWARD_POOL_UPDATE_BLOCKS = 4,
        // All Session nodes are connected to the same RPC provider (e.g.
        // Foundry's Anvil) which is also running locally hence we have a very
        // low threshold for the number of blocks to trail the tip by.
        .L2_TRACKER_SAFE_BLOCKS = 1,
};
}  // namespace cryptonote::config::localdev
