#pragma once

#include <crypto/hash.h>
#include <networks.h>

#include <chrono>

// Namespace for storing the ethereum contract, events, and function call signatures.
namespace eth::contract {

namespace event {

    extern const crypto::hash NewServiceNode;
    extern const crypto::hash ServiceNodeExitRequest;
    extern const crypto::hash ServiceNodeExit;
    extern const crypto::hash StakingRequirementUpdated;

}  // namespace event

namespace call {

    extern const crypto::hash4 Pool_rewardRate;
    extern const crypto::hash4 ServiceNodeRewards_serviceNodes;
    extern const crypto::hash4 ServiceNodeRewards_allServiceNodeIDs;

}  // namespace call

// NOTE: ServiceNodeRewards.sol Constants/Functionality
// Constants and functionality ported from `eth-sn-contracts/contracts/ServiceNodeRewards.sol`. This
// should be kept in sync with the contract. These declarations are all prefixed with `rewards` or
// `REWARDS` to indicate so.

// TODO: In debug mode we could do a one-off request on startup to verify that the constants are
// valid OR make sure we witness the logs from the contract that are emitted if these values change
// dynamically and assert in development builds.

// How long a BLS aggregated signature is valid for before it's rejected by the smart contract for
// being too old. This is used to invalidate old exits and liquidation requests (and also stop
// replay of signatures).
constexpr inline std::chrono::seconds REWARDS_EXIT_SIGNATURE_EXPIRY = 10min;

// How many non-signers are permitted given the node count.
constexpr inline uint64_t rewards_bls_non_signer_threshold(uint64_t total_nodes) {
    constexpr uint64_t bls_non_signer_threshold_max = 300;
    uint64_t one_third_of_nodes = total_nodes / 3;
    return std::min(bls_non_signer_threshold_max, one_third_of_nodes);
}

}  // namespace eth::contract
