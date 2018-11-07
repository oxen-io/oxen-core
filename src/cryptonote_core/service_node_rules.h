#pragma once

namespace service_nodes {


inline uint64_t get_staking_requirement_lock_blocks(cryptonote::network_type nettype)
{
constexpr static uint32_t STAKING_REQUIREMENT_LOCK_BLOCKS         = 30*24*30;
constexpr static uint32_t STAKING_REQUIREMENT_LOCK_BLOCKS_TESTNET = 30*24*2;
constexpr static uint32_t STAKING_REQUIREMENT_LOCK_BLOCKS_FAKENET = 30;

switch(nettype) {
    case cryptonote::TESTNET: return STAKING_REQUIREMENT_LOCK_BLOCKS_TESTNET;
    case cryptonote::FAKECHAIN: return STAKING_REQUIREMENT_LOCK_BLOCKS_FAKENET;
    default: return STAKING_REQUIREMENT_LOCK_BLOCKS;
}
}

inline uint64_t get_min_node_contribution(uint64_t staking_requirement, uint64_t total_reserved)
{
  return std::min(staking_requirement - total_reserved, staking_requirement / MAX_NUMBER_OF_CONTRIBUTORS);
}
}