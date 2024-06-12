#include "pool_contract.h"
#include <ethyl/utils.hpp>
#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("l2_tracker");

PoolContract::PoolContract(std::string _contractAddress, ethyl::Provider& _provider) :
        contractAddress(std::move(_contractAddress)), provider(_provider) {}

RewardRateResponse PoolContract::RewardRate(uint64_t timestamp, uint64_t ethereum_block_height) {
    oxen::log::trace(
            logcat,
            "Querying reward rate from pool contract {} at ts {}, Ethereum height {}",
            contractAddress,
            timestamp,
            ethereum_block_height);

    ethyl::ReadCallData callData;
    callData.contractAddress = contractAddress;
    std::string timestampStr = ethyl::utils::padTo32Bytes(
            ethyl::utils::decimalToHex(timestamp), ethyl::utils::PaddingDirection::LEFT);

    // keccak256("rewardRate(uint256)")
    std::string functionABI = "0xcea01962";
    callData.data = functionABI + timestampStr;

    // NOTE: Parse the reward value (returned in a hex string, e.g. "0x")
    std::string reward_rate_str     = provider.callReadFunction(callData, ethereum_block_height);
    std::string_view reward_rate_sv = reward_rate_str;
    if (reward_rate_sv.starts_with("0x") || reward_rate_sv.starts_with("0X"))
        reward_rate_sv.remove_prefix(2);

    RewardRateResponse result = {
        .timestamp = timestamp,
        .reward = reward_rate_sv.size() ? ethyl::utils::hexStringToU64(reward_rate_sv) : 0,
    };

    oxen::log::trace(
            logcat,
            "Retrieved pool reward {} (reward string was {})",
            result.reward,
            reward_rate_str);
    return result;
}
