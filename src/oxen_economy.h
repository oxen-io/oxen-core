#pragma once
#include "cryptonote_config.h"

namespace oxen {

inline constexpr uint64_t COIN = 1000000000;  // 1 LOKI = pow(10, 9)
inline constexpr size_t DISPLAY_DECIMAL_POINT = 9;

// Pre-HF15 money supply parameters:

// total number coins to be generated (old curve)
inline constexpr uint64_t MONEY_SUPPLY = ((uint64_t)(-1));
inline constexpr uint64_t EMISSION_LINEAR_BASE = ((uint64_t)(1) << 58);
inline constexpr uint64_t EMISSION_SUPPLY_MULTIPLIER = 19;
inline constexpr uint64_t EMISSION_SUPPLY_DIVISOR = 10;
inline constexpr uint64_t EMISSION_DIVISOR = 2000000;

// HF15 money supply parameters:
inline constexpr uint64_t BLOCK_REWARD_HF15 = 25 * COIN;
inline constexpr uint64_t MINER_REWARD_HF15 = BLOCK_REWARD_HF15 * 24 / 100;  // Only until HF16
inline constexpr uint64_t SN_REWARD_HF15 = BLOCK_REWARD_HF15 * 66 / 100;
inline constexpr uint64_t FOUNDATION_REWARD_HF15 = BLOCK_REWARD_HF15 * 10 / 100;

// HF16+ money supply parameters: same as HF15 except the miner fee goes away and is redirected to
// LF to be used exclusively for Loki Chainflip liquidity seeding and incentives.  See
// https://github.com/oxen-project/oxen-improvement-proposals/issues/24 for more details.  This ends
// after 6 months.
inline constexpr uint64_t BLOCK_REWARD_HF16 = BLOCK_REWARD_HF15;
inline constexpr uint64_t CHAINFLIP_LIQUIDITY_HF16 = BLOCK_REWARD_HF15 * 24 / 100;

// HF17: at most 6 months after HF16.  This is tentative and will likely be replaced before the
// actual HF with a new reward schedule including Chainflip rewards, but as per the LRC linked
// above, the liquidity funds end after 6 months.  That means that until HF17 is finalized, this is
// the fallback if we hit the 6-months-after-HF16 point:
inline constexpr uint64_t BLOCK_REWARD_HF17 = 18'333'333'333;
inline constexpr uint64_t FOUNDATION_REWARD_HF17 = 1'833'333'333;

static_assert(MINER_REWARD_HF15 + SN_REWARD_HF15 + FOUNDATION_REWARD_HF15 == BLOCK_REWARD_HF15);
static_assert(
        CHAINFLIP_LIQUIDITY_HF16 + SN_REWARD_HF15 + FOUNDATION_REWARD_HF15 == BLOCK_REWARD_HF16);
static_assert(SN_REWARD_HF15 + FOUNDATION_REWARD_HF17 == BLOCK_REWARD_HF17);

// -------------------------------------------------------------------------------------------------
//
// Service Nodes
//
// -------------------------------------------------------------------------------------------------

// Fixed (pre-SENT) OXEN staking requirement since HF16 (before that it was height dependent, see
// service_node_rules.cpp):
inline constexpr uint64_t OXEN_STAKING_REQUIREMENT = 15'000 * COIN;
// testnet/devnet/fakenet have always had a fixed 100 OXEN staking requirement:
inline constexpr uint64_t OXEN_STAKING_REQUIREMENT_TESTNET = 100 * COIN;
// Max contributors since HF19:
inline constexpr size_t MAX_CONTRIBUTORS_HF19 = 10;
// Max contributors before HF19:
inline constexpr size_t MAX_CONTRIBUTORS_V1 = 4;

// SENT staking requirement starting at HF20
inline constexpr uint64_t SENT_STAKING_REQUIREMENT = 25'000 * COIN;
inline constexpr uint64_t SENT_STAKING_REQUIREMENT_TESTNET = 120 * COIN;

// Initial SENT reward for the first few blocks of HF21 (before there are L2_REWARD_CONSENSUS_BLOCKS
// blocks to achieve reward consensus).  This value is based on a 40M initial reward pool with 15.1%
// annual simple payout rate (= 14% compounding rate).
inline constexpr uint64_t ETH_BLS_INITIAL_REWARD = 40000000'000000000 * 151 / 1000 / 365 / 720;

constexpr uint64_t MINIMUM_OPERATOR_CONTRIBUTION(uint64_t staking_requirement) {
    return staking_requirement / 4;
}

// -------------------------------------------------------------------------------------------------
//
// Blink
//
// -------------------------------------------------------------------------------------------------
// Blink fees: in total the sender must pay (MINER_TX_FEE_PERCENT + BURN_TX_FEE_PERCENT) * [minimum
// tx fee] + BLINK_BURN_FIXED, and the miner including the tx includes MINER_TX_FEE_PERCENT *
// [minimum tx fee]; the rest must be left unclaimed.

// The blink miner tx fee (as a percentage of the minimum tx fee)
constexpr uint64_t BLINK_MINER_TX_FEE_PERCENT = 100;
// A fixed amount (in atomic currency units) that the sender must burn
constexpr uint64_t BLINK_BURN_FIXED = 0;
// A percentage of the minimum miner tx fee that the sender must burn.  (Adds to
// BLINK_BURN_FIXED)
constexpr uint64_t BLINK_BURN_TX_FEE_PERCENT_V15 = 150;
// A percentage of the minimum miner tx fee that the sender must burn.  (Adds to
// BLINK_BURN_FIXED)
constexpr uint64_t BLINK_BURN_TX_FEE_PERCENT_V18 = 200;

static_assert(
        BLINK_MINER_TX_FEE_PERCENT >= 100,
        "blink miner fee cannot be smaller than the base tx fee");
static_assert(BLINK_BURN_FIXED >= 0, "fixed blink burn amount cannot be negative");
static_assert(BLINK_BURN_TX_FEE_PERCENT_V18 >= 0, "blink burn tx percent cannot be negative");

}  // namespace oxen

// -------------------------------------------------------------------------------------------------
//
// ONS
//
// -------------------------------------------------------------------------------------------------
namespace ons {
enum struct mapping_type : uint16_t {
    session = 0,
    wallet = 1,
    lokinet = 2,  // the type value stored in the database; counts as 1-year when used in a buy tx.
    lokinet_2years,
    lokinet_5years,
    lokinet_10years,
    _count,
    update_record_internal,
};

constexpr bool is_lokinet_type(mapping_type t) {
    return t >= mapping_type::lokinet && t <= mapping_type::lokinet_10years;
}

// How many days we add per "year" of ONS lokinet registration.  We slightly extend this to the 368
// days per registration "year" to allow for some blockchain time drift + leap years.
constexpr uint64_t REGISTRATION_YEAR_DAYS = 368;

constexpr uint64_t burn_needed(cryptonote::hf hf_version, mapping_type type) {
    uint64_t result = 0;

    // The base amount for session/wallet/lokinet-1year:
    const uint64_t basic_fee =
            (hf_version >= cryptonote::hf::hf18         ? 7 * oxen::COIN
             : hf_version >= cryptonote::hf::hf16_pulse ? 15 * oxen::COIN
                                                        : 20 * oxen::COIN);
    switch (type) {
        case mapping_type::update_record_internal: result = 0; break;

        case mapping_type::lokinet: /* FALLTHRU */
        case mapping_type::session: /* FALLTHRU */
        case mapping_type::wallet:  /* FALLTHRU */
        default: result = basic_fee; break;

        case mapping_type::lokinet_2years: result = 2 * basic_fee; break;
        case mapping_type::lokinet_5years: result = 4 * basic_fee; break;
        case mapping_type::lokinet_10years: result = 6 * basic_fee; break;
    }
    return result;
}
};  // namespace ons
