#pragma once
#include <cstdint>

constexpr uint64_t COIN                       = (uint64_t)1000000000; // 1 LOKI = pow(10, 9)
constexpr uint64_t MONEY_SUPPLY               = ((uint64_t)(-1)); // MONEY_SUPPLY - total number coins to be generated
constexpr uint64_t EMISSION_LINEAR_BASE       = ((uint64_t)(1) << 58);
constexpr uint64_t EMISSION_SUPPLY_MULTIPLIER = 19;
constexpr uint64_t EMISSION_SUPPLY_DIVISOR    = 10;
constexpr uint64_t EMISSION_DIVISOR           = 2000000;

// Transition (HF15) money supply parameters
constexpr uint64_t BLOCK_REWARD_HF15      = 25 * COIN;
constexpr uint64_t MINER_REWARD_HF15      = BLOCK_REWARD_HF15 * 24 / 100;
constexpr uint64_t SN_REWARD_HF15         = BLOCK_REWARD_HF15 * 66 / 100;
constexpr uint64_t FOUNDATION_REWARD_HF15 = BLOCK_REWARD_HF15 * 10 / 100;

// New (HF16+) money supply parameters (tentative - HF16 not yet scheduled)
constexpr uint64_t BLOCK_REWARD_HF16      = 21 * COIN /* TODO - see below */;
constexpr uint64_t SN_REWARD_HF16         = BLOCK_REWARD_HF16 * 90 / 100;
constexpr uint64_t FOUNDATION_REWARD_HF16 = BLOCK_REWARD_HF16 * 10 / 100;

// TODO: For now we add 1 extra atomic loki to the HF16 block reward, above; ultimately with pulse
// we want to just drop the miner reward output entirely when a tx has no transactions, but we don't
// support that yet in the current code and if we put an output of 0 it currently breaks the test
// suite (which assumes an output of 0 means ringct, which this is not).  Thus this +1 hack for now,
// to keep the current test suite happy until we actually implement this for HF16.
// constexpr uint64_t MINER_REWARD_HF16 = 0;

static_assert(MINER_REWARD_HF15 + SN_REWARD_HF15 + FOUNDATION_REWARD_HF15 == BLOCK_REWARD_HF15);
static_assert(                    SN_REWARD_HF16 + FOUNDATION_REWARD_HF16 == BLOCK_REWARD_HF16);

// -------------------------------------------------------------------------------------------------
//
// Blink
//
// -------------------------------------------------------------------------------------------------
// Blink fees: in total the sender must pay (MINER_TX_FEE_PERCENT + BURN_TX_FEE_PERCENT) * [minimum tx fee] + BLINK_BURN_FIXED,
// and the miner including the tx includes MINER_TX_FEE_PERCENT * [minimum tx fee]; the rest must be left unclaimed.
constexpr uint64_t BLINK_MINER_TX_FEE_PERCENT = 100; // The blink miner tx fee (as a percentage of the minimum tx fee)
constexpr uint64_t BLINK_BURN_FIXED           = 0;  // A fixed amount (in atomic currency units) that the sender must burn
constexpr uint64_t BLINK_BURN_TX_FEE_PERCENT  = 150; // A percentage of the minimum miner tx fee that the sender must burn.  (Adds to BLINK_BURN_FIXED)

// FIXME: can remove this post-fork 15; the burned amount only matters for mempool acceptance and
// blink quorum signing, but isn't part of the blockchain concensus rules (so we don't actually have
// to keep it around in the code for syncing the chain).
constexpr uint64_t BLINK_BURN_TX_FEE_PERCENT_OLD = 400; // A percentage of the minimum miner tx fee that the sender must burn.  (Adds to BLINK_BURN_FIXED)

static_assert(BLINK_MINER_TX_FEE_PERCENT >= 100, "blink miner fee cannot be smaller than the base tx fee");
static_assert(BLINK_BURN_FIXED >= 0, "fixed blink burn amount cannot be negative");
static_assert(BLINK_BURN_TX_FEE_PERCENT >= 0, "blink burn tx percent cannot be negative");

// -------------------------------------------------------------------------------------------------
//
// LNS
//
// -------------------------------------------------------------------------------------------------
namespace lns
{
enum struct mapping_type : uint16_t
{
  session,
  wallet,
  lokinet_1year,
  lokinet_2years,
  lokinet_5years,
  lokinet_10years,
  _count,
  update_record_internal,
};

constexpr uint64_t burn_needed(uint8_t /*hf_version*/, mapping_type type)
{
  uint64_t result = 0;
  switch (type)
  {
    case mapping_type::update_record_internal:
      result = 0;
      break;

    case mapping_type::lokinet_1year: /* FALLTHRU */
    case mapping_type::session: /* FALLTHRU */
    case mapping_type::wallet: /* FALLTHRU */
    default:
      result = 20 * COIN;
      break;

    case mapping_type::lokinet_2years: result = 40 * COIN; break;
    case mapping_type::lokinet_5years: result = 80 * COIN; break;
    case mapping_type::lokinet_10years: result = 120 * COIN; break;
  }
  return result;
}
}; // namespace lns

