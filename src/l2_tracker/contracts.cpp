#include "contracts.h"

namespace eth::contract {

namespace event {

    const crypto::hash NewServiceNodeV2 = crypto::keccak(
            "NewServiceNodeV2(uint64,address,(uint256,uint256),(uint256,uint256,uint256,"
            "uint16),((address,address),uint256)[])"sv);

    // TODO: Rename the contract event from Removal to Exit as this follows the terminology we've
    // been using to refer to it
    const crypto::hash ServiceNodeExitRequest =
            crypto::keccak("ServiceNodeRemovalRequest(uint64,address,(uint256,uint256))"sv);

    const crypto::hash ServiceNodeExit =
            crypto::keccak("ServiceNodeRemoval(uint64,address,uint256,(uint256,uint256))"sv);

    const crypto::hash StakingRequirementUpdated =
            crypto::keccak("StakingRequirementUpdated(uint256)"sv);

}  // namespace event

namespace call {

    const crypto::hash4 Pool_rewardRate =
            crypto::keccak_prefix<crypto::hash4>("rewardRate()"sv);  // 0x7b0a47ee

    const crypto::hash4 ServiceNodeRewards_serviceNodes =
            crypto::keccak_prefix<crypto::hash4>("serviceNodes(uint64)"sv);  // 0x040f9853

    const crypto::hash4 ServiceNodeRewards_allServiceNodeIDs =
            crypto::keccak_prefix<crypto::hash4>("allServiceNodeIDs()"sv);  // 0xabf2c503

}  // namespace call

}  // namespace eth::contract
