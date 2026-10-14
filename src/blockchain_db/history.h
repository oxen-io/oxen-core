#pragma once

#include <cryptonote_config.h>

#include <cstdint>
#include <optional>
#include <string_view>

namespace cryptonote {

// The smallest history a node can be set to keep: one day of 2-minute blocks.  It covers every
// lookback of block processing from HF15 on (none goes back more than 65 blocks; see
// history_minimum), and leaves room for the service node and rewards restore points a rewind
// needs: those are stored every 60 blocks, each with the quorums of the 65 heights before it, so
// the newest restorable one can be up to ~185 blocks back.
inline constexpr uint64_t HISTORY_MIN_BLOCKS = 720;

// Kept beyond the staking lock period before HF15, so that small rewinds there never need a block
// that has already been dropped.
inline constexpr uint64_t HISTORY_LOCK_MARGIN = 360;

/// Returns the fewest of the most recent blocks whose bodies and transactions block processing
/// needs while the chain has `height` blocks (that is, while adding the block at `height`): the
/// blocks at heights [height - result, height).
///
/// Before HF15 (mainnet height 496,969) that is the staking lock period plus HISTORY_LOCK_MARGIN,
/// and from HF15 on it is HISTORY_MIN_BLOCKS.  Together these cover every read that adding a
/// block makes of an older block body or transaction:
///
/// - HF9 (mainnet 101,250-161,848): service node expiry re-reads the registration txs in the
///   block one staking lock period back (`staking_num_lock_blocks`, 21,600 blocks on mainnet).
///   That cannot be computed from service node state (a node can have more than one
///   registration tx, and expires on the anniversary of the one in that block).  For the first
///   lock period of HF9 the block it reads is from before HF9, which is why the longer minimum
///   starts at genesis rather than at HF9.
/// - HF10-HF14: batched governance payouts, at multiples of the governance interval, sum the
///   governance share of every block of the previous interval, which takes those blocks' miner
///   txs: the 5,040 blocks before the payout on mainnet.
/// - Every other read is within 65 blocks: pulse quorum entropy (up to 36 blocks back, HF16+),
///   L2 event confirmations (the tx and its block, up to 30 back, HF21+), the L2 reward
///   consensus (15 back, HF21+), quorums (65 back, from stored service node state rather than
///   blocks) and the immutable checkpoint (the older of the two newest service node
///   checkpoints).
///
/// Difficulty, timestamp, weight and emission checks, and the pulse round timings (which go back
/// to the block before HF16), read only `blocks` index columns, which are kept for all heights, so
/// they place no bound on the history.
uint64_t history_minimum(network_type nettype, uint64_t height);

/// Returns how many of the most recent blocks' bodies and transactions a node set to keep
/// `history` blocks keeps while the chain has `height` blocks: the larger of `history` and
/// history_minimum.  A `history` of 0 means all of them (a full node), for which this returns 0.
uint64_t history_window(network_type nettype, uint64_t history, uint64_t height);

/// Parses a --history value: "full" (returned as 0), a number of blocks, or a duration given as a
/// number followed by w, d or h (weeks, days or hours), which is converted to blocks at the
/// network's target block time.
///
/// @throw std::invalid_argument if the value is not one of those, or is less than
/// HISTORY_MIN_BLOCKS blocks.
uint64_t parse_history(std::string_view value, network_type nettype);

/// For a database keeping `history` blocks whose oldest kept block body is at `start`, with
/// `height` blocks in the chain: the height the chain has to reach before the database holds that
/// whole history, if it doesn't yet (because the history was made larger than what had been kept
/// until then).
std::optional<uint64_t> history_complete_at(uint64_t history, uint64_t start, uint64_t height);

}  // namespace cryptonote
