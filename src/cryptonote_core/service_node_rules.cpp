#include "service_node_rules.h"

#include <oxenc/endian.h>

#include <boost/lexical_cast.hpp>
#include <cfenv>
#include <limits>
#include <utility>
#include <vector>

#include "common/oxen.h"
#include "common/string_util.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_config.h"
#include "epee/int-util.h"
#include "networks.h"
#include "oxen_economy.h"

using cryptonote::hf;

namespace service_nodes {

using namespace cryptonote;
using namespace oxen;

static auto logcat = log::Cat("service_nodes");

template <cryptonote::network_type Net>
static constexpr bool has_valid_parameters() {
    constexpr auto& conf = get_config(Net);

    static_assert(conf.PULSE_MIN_SERVICE_NODES >= PULSE_QUORUM_SIZE);

    // Some sanity checks on the recommission credit value:
    static_assert(
            RECOMMISSION_CREDIT(conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT), 0) <=
                    conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT),
            "Max recommission credit should not be higher than DECOMMISSION_MAX_CREDIT");

    // These are by no means exhaustive, but will at least catch simple mistakes
    static_assert(
            RECOMMISSION_CREDIT(
                    conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT),
                    conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT)) <=
                            RECOMMISSION_CREDIT(
                                    conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT),
                                    conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT) / 2) &&
                    RECOMMISSION_CREDIT(
                            conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT),
                            conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT) / 2) <=
                            RECOMMISSION_CREDIT(conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT), 0) &&
                    RECOMMISSION_CREDIT(
                            conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT) / 2,
                            conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT) / 2) <=
                            RECOMMISSION_CREDIT(conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT) / 2, 0),
            "Recommission credit should be (weakly) decreasing in the length of decommissioning");
    static_assert(
            RECOMMISSION_CREDIT(conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT) / 2, 1) <=
                            RECOMMISSION_CREDIT(conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT), 1) &&
                    RECOMMISSION_CREDIT(0, 1) <=
                            RECOMMISSION_CREDIT(conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT) / 2, 1),
            "Recommission credit should be (weakly) increasing in initial credit blocks");

    // This one actually could be supported (i.e. you can have negative credit and have to crawl out
    // of that hole), but the current code is entirely untested as to whether or not that actually
    // works.
    static_assert(
            RECOMMISSION_CREDIT(conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT), 0) >= 0 &&
                    RECOMMISSION_CREDIT(
                            conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT),
                            conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT)) >= 0 &&
                    RECOMMISSION_CREDIT(
                            conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT),
                            2 * conf.BLOCKS_IN(DECOMMISSION_MAX_CREDIT)) >=
                            0,  // delayed recommission that overhangs your time
            "Recommission credit should not be negative");

    return true;
}

static_assert([]<size_t... I>(std::index_sequence<I...>) {
    return (has_valid_parameters<ALL_NETWORKS[I]>() && ...);
}(std::make_index_sequence<ALL_NETWORKS.size()>{}));

uint64_t get_default_staking_requirement(cryptonote::network_type nettype, hf hardfork) {
    assert(hardfork >= hf::hf16_pulse);
    if (hardfork >= feature::ETH_BLS)
        return nettype == network_type::MAINNET ? SENT_STAKING_REQUIREMENT
                                                : SENT_STAKING_REQUIREMENT_TESTNET;

    return nettype == network_type::MAINNET ? OXEN_STAKING_REQUIREMENT
                                            : OXEN_STAKING_REQUIREMENT_TESTNET;
}

uint64_t get_default_staking_requirement(cryptonote::network_type nettype, uint64_t height) {

    auto hf_version = get_network_version(nettype, height);
    if (hf_version >= hf::hf16_pulse)
        return get_default_staking_requirement(nettype, hf_version);

    if (nettype != cryptonote::network_type::MAINNET)
        return OXEN_STAKING_REQUIREMENT_TESTNET;

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
        log::warning(
                logcat,
                "Registration tx rejected: amount-based registrations not accepted before HF19");
        return false;  // OXEN-based registrations not accepted before HF19
    }
    if (stakes.size() > oxen::MAX_CONTRIBUTORS_HF19) {
        log::warning(
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
            log::warning(
                    logcat,
                    "Registration tx rejected: stake {} too small ({} < {})",
                    i,
                    stakes[i],
                    min_stake);
            return false;
        }
        if (stakes[i] > remaining) {
            log::warning(
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

    if (hf_version >= feature::ETH_BLS) {
        if (remaining != 0) {
            log::warning(
                    logcat,
                    "Registration tx rejected: Eth registrations must contribute the full service "
                    "node staking requirement ({} contributed of {} required)",
                    reserved,
                    staking_requirement);
            return false;
        }
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

// pre-HF11
uint64_t staking_num_lock_blocks(cryptonote::network_type nettype) {
    switch (nettype) {
        case cryptonote::network_type::FAKECHAIN: return 30;
        case cryptonote::network_type::TESTNET: return get_config(nettype).BLOCKS_IN(48h);
        default: return get_config(nettype).BLOCKS_IN(30 * 24h);
    }
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

    if (version >= feature::ETH_BLS)
        // With Eth registrations the minimum contribution is enforced in the multi-contributor
        // contract side, and not checkable at all in Oxen because Eth registrations are always full
        // registrations, and *any* set of (non-operator) contributions that make up a full stake
        // sorted from highest to lowest will always satisfy the contributor staking requirements.
        // (The proof is pretty easy to see: given N contributions that fill the remaining required
        // stake, the largest of the contributions will be at least as big as the average
        // contribution, remaining / N, and thus contribution >= remaining / N >= remaining / M,
        // where where M >= N is the maximum spots remaining, and remaining / M is the required
        // contribution rule.
        return 1;

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
        throw oxen::traced<invalid_registration>{"could not parse fee percent"};

    if (*percent < 0.0 || *percent > 100.0)
        throw oxen::traced<invalid_registration>{"fee percent out of bounds"};

    auto basis_points =
            static_cast<uint16_t>(std::lround(*percent / 100.0 * cryptonote::STAKING_FEE_BASIS));
    if (*percent == 100.0)
        basis_points = cryptonote::STAKING_FEE_BASIS;

    return basis_points;
}
}  // namespace service_nodes
