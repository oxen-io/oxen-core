#include "cryptonote_config.h"
#include "common/exp2.h"
#include "common/int-util.h"
#include <vector>

#include "service_node_rules.h"

namespace service_nodes {


uint64_t get_staking_requirement(cryptonote::network_type m_nettype, uint64_t height)
{
    if (m_nettype == cryptonote::TESTNET || m_nettype == cryptonote::FAKECHAIN)
        return COIN * 100;

    uint64_t hardfork_height = m_nettype == cryptonote::MAINNET ? 101250 : 96210 /* stagenet */;
    if (height < hardfork_height) height = hardfork_height;

    uint64_t height_adjusted = height - hardfork_height;
    uint64_t base = 10000 * COIN;
    uint64_t variable = (35000.0 * COIN) / loki_exp2(height_adjusted/129600.0);
    uint64_t linear_up = (uint64_t)(5 * COIN * height / 2592) + 8000 * COIN;
    uint64_t flat = 15000 * COIN;
    return std::max(base + variable, height < 3628800 ? linear_up : flat);
}

uint64_t portions_to_amount(uint64_t portions, uint64_t staking_requirement)
{
    uint64_t hi, lo, resulthi, resultlo;
    lo = mul128(staking_requirement, portions, &hi);
    div128_64(hi, lo, STAKING_PORTIONS, &resulthi, &resultlo);
    return resultlo;
}

bool check_service_node_portions(uint8_t hf_version, const std::vector<uint64_t>& portions)
{
    if (portions.size() > MAX_NUMBER_OF_CONTRIBUTORS) return false;

    uint64_t reserved = 0;
    for (auto i = 0u; i < portions.size(); ++i) {
        const uint64_t min_portions = get_min_node_contribution(hf_version, STAKING_PORTIONS, reserved, i);
        if (portions[i] < min_portions) return false;
        reserved += portions[i];
    }

    return reserved <= STAKING_PORTIONS;
}


static uint64_t get_min_node_contribution_pre_v11(uint64_t staking_requirement, uint64_t total_reserved)
{
    return std::min(staking_requirement - total_reserved, staking_requirement / MAX_NUMBER_OF_CONTRIBUTORS);
}

uint64_t get_min_node_contribution(uint8_t version, uint64_t staking_requirement, uint64_t total_reserved, size_t contrib_count)
{
    if (version < cryptonote::network_version_11_swarms) {
        return get_min_node_contribution_pre_v11(staking_requirement, total_reserved);
    }

    const uint64_t needed = staking_requirement - total_reserved;
    const size_t vacant = MAX_NUMBER_OF_CONTRIBUTORS - contrib_count;

    /// This function is not called when the node is full, but if
    /// it does in the future, at least we don't cause undefined behaviour
    if (vacant == 0) return 0;
    assert(vacant > 0); /// sanity, should never happen

    return std::min(needed, needed / vacant);
}

}