#include "service_node_rules.h"

#include <oxenc/endian.h>

#include <boost/lexical_cast.hpp>
#include <cfenv>
#include <limits>
#include <vector>

#include "common/oxen.h"
#include "common/string_util.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_config.h"
#include "epee/int-util.h"
#include "oxen_economy.h"

using cryptonote::hf;

namespace service_nodes {

using namespace cryptonote;
using namespace oxen;

static auto logcat = log::Cat("service_nodes");

uint64_t get_staking_requirement(cryptonote::network_type nettype, hf hardfork) {
    assert(hardfork >= hf::hf16_pulse);
    if (nettype == network_type::MAINNET)
        return hardfork >= hf::hf20 ? SENT_STAKING_REQUIREMENT : OXEN_STAKING_REQUIREMENT;
    return hardfork >= hf::hf20 ? SENT_STAKING_REQUIREMENT_TESTNET
                                : OXEN_STAKING_REQUIREMENT_TESTNET;
}

// TODO(oxen): Move to oxen_economy, this will also need access to oxen::exp2
uint64_t get_staking_requirement(cryptonote::network_type nettype, uint64_t height) {
    if (is_hard_fork_at_least(nettype, hf::hf20, height))
        return nettype == network_type::MAINNET ? SENT_STAKING_REQUIREMENT
                                                : SENT_STAKING_REQUIREMENT_TESTNET;
    else if (nettype != cryptonote::network_type::MAINNET)
        return OXEN_STAKING_REQUIREMENT_TESTNET;
    else if (is_hard_fork_at_least(nettype, hf::hf16_pulse, height))
        return OXEN_STAKING_REQUIREMENT;

    if (is_hard_fork_at_least(nettype, hf::hf13_enforce_checkpoints, height)) {
        constexpr int64_t heights[] = {
                385824,
                429024,
                472224,
                515424,
                558624,
                601824,
                645024,
        };

        constexpr int64_t lsr[] = {
                20458'380815527,
                19332'319724305,
                18438'564443912,
                17729'190407764,
                17166'159862153,
                16719'282221956,
                16364'595203882,
        };

        assert(static_cast<int64_t>(height) >= heights[0]);
        constexpr uint64_t LAST_HEIGHT = heights[oxen::array_count(heights) - 1];
        constexpr uint64_t LAST_REQUIREMENT = lsr[oxen::array_count(lsr) - 1];
        if (height >= LAST_HEIGHT)
            return LAST_REQUIREMENT;

        size_t i = 0;
        for (size_t index = 1; index < oxen::array_count(heights); index++) {
            if (heights[index] > static_cast<int64_t>(height)) {
                i = (index - 1);
                break;
            }
        }

        int64_t H = height;
        int64_t result =
                lsr[i] + (H - heights[i]) * ((lsr[i + 1] - lsr[i]) / (heights[i + 1] - heights[i]));
        return static_cast<uint64_t>(result);
    }

    uint64_t hardfork_height = 101250;
    if (height < hardfork_height)
        height = hardfork_height;

    uint64_t height_adjusted = height - hardfork_height;
    uint64_t base = 0, variable = 0;
    std::fesetround(FE_TONEAREST);
    if (is_hard_fork_at_least(nettype, hf::hf11_infinite_staking, height)) {
        base = 15000 * oxen::COIN;
        variable = (25007.0 * oxen::COIN) / oxen::exp2(height_adjusted / 129600.0);
    } else {
        base = 10000 * oxen::COIN;
        variable = (35000.0 * oxen::COIN) / oxen::exp2(height_adjusted / 129600.0);
    }

    uint64_t result = base + variable;
    return result;
}

uint64_t portions_to_amount(uint64_t portions, uint64_t staking_requirement) {
    return mul128_div64(staking_requirement, portions, cryptonote::old::STAKING_PORTIONS);
}

bool check_service_node_portions(
        hf hf_version,
        const std::vector<std::pair<cryptonote::account_public_address, uint64_t>>& portions) {
    // When checking portion we always use HF18 rules, even on HF19, because a registration actually
    // generated under HF19+ won't get here.
    if (hf_version == hf::hf19_reward_batching)
        hf_version = hf::hf18;
    else if (hf_version > hf::hf19_reward_batching) {
        log::info(
                logcat,
                "Registration tx rejected: portions-based registrations not permitted after HF19");
        return false;
    }
    if (portions.size() > oxen::MAX_CONTRIBUTORS_V1) {
        log::info(
                logcat,
                "Registration tx rejected: too many contributors ({} > {})",
                portions.size(),
                oxen::MAX_CONTRIBUTORS_V1);
        return false;
    }

    uint64_t reserved = 0;
    uint64_t remaining = cryptonote::old::STAKING_PORTIONS;
    for (size_t i = 0; i < portions.size(); ++i) {

        const uint64_t min_portions = get_min_node_contribution(
                hf_version, cryptonote::old::STAKING_PORTIONS, reserved, i);
        if (portions[i].second < min_portions) {
            log::info(
                    logcat,
                    "Registration tx rejected: portion {} too small ({} < {})",
                    i,
                    portions[i].second,
                    min_portions);
            return false;
        }
        if (portions[i].second > remaining) {
            log::info(logcat, "Registration tx rejected: portion {} exceeds available portions", i);
            return false;
        }

        reserved += portions[i].second;
        remaining -= portions[i].second;
    }

    return true;
}

bool check_service_node_stakes(
        hf hf_version, uint64_t staking_requirement, const std::vector<uint64_t>& stakes) {
    if (hf_version < hf::hf19_reward_batching) {
        log::info(
                logcat,
                "Registration tx rejected: amount-based registrations not accepted before HF19");
        return false;  // OXEN-based registrations not accepted before HF19
    }
    if (stakes.size() > oxen::MAX_CONTRIBUTORS_HF19) {
        log::info(
                logcat,
                "Registration tx rejected: too many contributors ({} > {})",
                stakes.size(),
                oxen::MAX_CONTRIBUTORS_HF19);
        return false;
    }

    const auto operator_requirement = MINIMUM_OPERATOR_CONTRIBUTION(staking_requirement);

    uint64_t reserved = 0;
    uint64_t remaining = staking_requirement;
    for (size_t i = 0; i < stakes.size(); i++) {
        const uint64_t min_stake =
                i == 0 ? operator_requirement
                       : get_min_node_contribution(hf_version, staking_requirement, reserved, i);

        if (stakes[i] < min_stake) {
            log::info(
                    logcat,
                    "Registration tx rejected: stake {} too small ({} < {})",
                    i,
                    stakes[i],
                    min_stake);
            return false;
        }
        if (stakes[i] > remaining) {
            log::info(
                    logcat,
                    "Registration tx rejected: stake {} ({}) exceeds available remaining stake "
                    "({})",
                    i,
                    stakes[i],
                    remaining);
            return false;
        }

        reserved += stakes[i];
        remaining -= stakes[i];
    }

    return true;
}

crypto::hash generate_request_stake_unlock_hash(uint32_t nonce) {
    static_assert(
            sizeof(crypto::hash) == 8 * sizeof(uint32_t) &&
            alignof(crypto::hash) >= alignof(uint32_t));
    crypto::hash result;
    oxenc::host_to_little_inplace(nonce);
    for (size_t i = 0; i < 8; i++)
        reinterpret_cast<uint32_t*>(result.data())[i] = nonce;
    return result;
}

uint64_t get_locked_key_image_unlock_height(
        cryptonote::network_type nettype, uint64_t node_register_height, uint64_t curr_height) {
    uint64_t blocks_to_lock = staking_num_lock_blocks(nettype);
    uint64_t result = curr_height + (blocks_to_lock / 2);
    return result;
}

static uint64_t get_min_node_contribution_pre_v11(
        uint64_t staking_requirement, uint64_t total_reserved) {
    return std::min(
            staking_requirement - total_reserved, staking_requirement / oxen::MAX_CONTRIBUTORS_V1);
}

uint64_t get_max_node_contribution(
        hf version, uint64_t staking_requirement, uint64_t total_reserved) {
    if (version >= hf::hf16_pulse)
        return (staking_requirement - total_reserved) * cryptonote::MAXIMUM_ACCEPTABLE_STAKE::num /
               cryptonote::MAXIMUM_ACCEPTABLE_STAKE::den;
    return std::numeric_limits<uint64_t>::max();
}

uint64_t get_min_node_contribution(
        hf version,
        uint64_t staking_requirement,
        uint64_t total_reserved,
        size_t num_contributions) {
    if (version < hf::hf11_infinite_staking)
        return get_min_node_contribution_pre_v11(staking_requirement, total_reserved);

    const uint64_t needed = staking_requirement - total_reserved;

    const size_t max_contributors = version >= hf::hf19_reward_batching
                                          ? oxen::MAX_CONTRIBUTORS_HF19
                                          : oxen::MAX_CONTRIBUTORS_V1;
    if (max_contributors <= num_contributions)
        return UINT64_MAX;

    const size_t num_contributions_remaining_avail = max_contributors - num_contributions;
    return needed / num_contributions_remaining_avail;
}

uint64_t get_min_node_contribution_in_portions(
        hf version,
        uint64_t staking_requirement,
        uint64_t total_reserved,
        size_t num_contributions) {
    uint64_t atomic_amount = get_min_node_contribution(
            version, staking_requirement, total_reserved, num_contributions);
    uint64_t result = (atomic_amount == UINT64_MAX)
                            ? UINT64_MAX
                            : (get_portions_to_make_amount(staking_requirement, atomic_amount));
    return result;
}

uint64_t get_portions_to_make_amount(
        uint64_t staking_requirement, uint64_t amount, uint64_t max_portions) {
    uint64_t lo, hi, resulthi, resultlo;
    lo = mul128(amount, max_portions, &hi);
    if (lo > UINT64_MAX - (staking_requirement - 1))
        hi++;
    lo += staking_requirement - 1;
    div128_64(hi, lo, staking_requirement, &resulthi, &resultlo);
    return resultlo;
}

std::optional<double> parse_fee_percent(std::string_view fee) {
    if (fee.ends_with("%"))
        fee.remove_suffix(1);

    double percent;
    try {
        percent = boost::lexical_cast<double>(fee);
    } catch (...) {
        return std::nullopt;
    }

    if (percent < 0 || percent > 100)
        return std::nullopt;

    return percent;
}

uint16_t percent_to_basis_points(std::string percent_string) {
    const auto percent = parse_fee_percent(percent_string);
    if (!percent)
        throw invalid_registration{"could not parse fee percent"};

    if (*percent < 0.0 || *percent > 100.0)
        throw invalid_registration{"fee percent out of bounds"};

    auto basis_points =
            static_cast<uint16_t>(std::lround(*percent / 100.0 * cryptonote::STAKING_FEE_BASIS));
    if (*percent == 100.0)
        basis_points = cryptonote::STAKING_FEE_BASIS;

    return basis_points;
}
}  // namespace service_nodes
