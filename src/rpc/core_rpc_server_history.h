#pragma once

#include <fmt/format.h>

#include <cstdint>

#include "rpc/common/rpc_command.h"
#include "rpc/core_rpc_server_error_codes.h"

// What a node keeping a limited history (see --history) answers when asked for something it no
// longer has: the bodies and transactions of the blocks before its `history_start`, and the
// service node states, checkpoints and rewards history of those heights.  (What it keeps of every
// block, such as its hash, timestamp and weights, the outputs and key images, and the hashes of the
// transactions without inputs, is answered as on any other node.)
namespace cryptonote::rpc {

// The error for a request that needs something from before `history_start`.
inline rpc_error history_not_kept(uint64_t history_start) {
    return rpc_error{
            ERROR_HISTORY_NOT_KEPT,
            fmt::format(
                    "Not available on this node: it keeps block history from height {} "
                    "(--history)",
                    history_start)};
}

// Whether something covering blocks from `first` on needs any from before `history_start`.  A
// request reaching back before it is refused as a whole, rather than answered for just the part
// that is kept, which would look like a complete answer.
constexpr bool before_history(uint64_t first, uint64_t history_start) {
    return first < history_start;
}

}  // namespace cryptonote::rpc
