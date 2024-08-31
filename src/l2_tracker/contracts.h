#pragma once

#include "crypto/hash.h"
#include "networks.h"

// Namespace for storing the ethereum contract, events, and function call signatures.
namespace eth::contract {

inline constexpr std::string_view rewards_address(const cryptonote::network_type nettype) {
    return get_config(nettype).ETHEREUM_REWARDS_CONTRACT;
}
inline constexpr std::string_view pool_address(const cryptonote::network_type nettype) {
    return get_config(nettype).ETHEREUM_POOL_CONTRACT;
}

namespace event {

    extern const crypto::hash NewServiceNode;
    extern const crypto::hash ServiceNodeRemovalRequest;
    extern const crypto::hash ServiceNodeRemoval;
    extern const crypto::hash StakingRequirementUpdated;

}  // namespace event

namespace call {

    extern const crypto::hash4 Pool_rewardRate;
    extern const crypto::hash4 ServiceNodeRewards_serviceNodes;
    extern const crypto::hash4 ServiceNodeRewards_allServiceNodeIDs;

}  // namespace call

}  // namespace eth::contract
