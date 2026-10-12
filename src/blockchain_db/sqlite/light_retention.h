#pragma once

#include <cryptonote_config.h>

#include <cstdint>

namespace cryptonote {

// The fewest recent blocks a light node keeps the bodies and transactions of: one week of
// 2-minute blocks, which covers every lookback of block processing from HF15 on (see
// light_retention_blocks).  Peers may rely on any light node serving at least this many blocks
// below its top height.
inline constexpr uint64_t LIGHT_RETENTION_BLOCKS = 5040;

// Kept beyond the staking lock period before HF15, so that small rewinds there never need a block
// that has already been dropped.
inline constexpr uint64_t LIGHT_RETENTION_LOCK_MARGIN = 360;

/// Returns how many of the most recent blocks a light node must keep the bodies and transactions
/// of while the chain has `height` blocks (that is, while adding the block at `height`): the
/// blocks at heights [height - window, height) are needed, and anything older can be dropped.
///
/// Before HF15 (mainnet height 496,969) that is the staking lock period plus
/// LIGHT_RETENTION_LOCK_MARGIN, and from HF15 on it is LIGHT_RETENTION_BLOCKS.  Together these
/// cover every read that adding a block makes of an older block body or transaction:
///
/// - HF9 (mainnet 101,250-161,848): service node expiry re-reads the registration txs in the
///   block one staking lock period back (`staking_num_lock_blocks`, 21,600 blocks on mainnet).
///   That cannot be computed from service node state (a node can have more than one
///   registration tx, and expires on the anniversary of the one in that block).  For the first
///   lock period of HF9 the block it reads is from before HF9, which is why the longer window
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
/// to the block before HF16), read only `blocks` index columns, which a light node keeps for all
/// heights, so they place no bound on the window.
uint64_t light_retention_blocks(network_type nettype, uint64_t height);

}  // namespace cryptonote
