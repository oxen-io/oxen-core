#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <oxen/quic/address.hpp>
#include <utility>

#include "common/format.h"

// What peers can serve a syncing node, going by the history they advertise (see
// CORE_SYNC_DATA::history: 0 if a peer keeps every block, otherwise how many of its most recent
// blocks it keeps; nullopt if it hasn't said, as peers from before the field don't).
namespace cryptonote {

// A peer's history moves up as its chain grows, and what we know of its chain height can be a
// little behind, so we don't count on it still having a block within this many of the oldest one
// it advertises.
inline constexpr uint64_t PEER_HISTORY_MARGIN = 100;

// Whether a peer at chain height `peer_height` keeping `history` blocks still keeps block
// `height` (and so every block from there up).  This doesn't check that the peer has reached
// `height` at all: it is also what a peerlist entry, whose height we don't know, is judged by
// against the height of the chain.  A peer that hasn't said what it keeps is taken to keep every
// block, as every peer from before the field does.
constexpr bool history_covers(
        uint64_t height, uint64_t peer_height, std::optional<uint64_t> history) {
    return !history || *history == 0 || height + *history >= peer_height + PEER_HISTORY_MARGIN;
}

// Describes a peer's history for a log or listing: "archive", "N blocks" or "???".
inline std::string describe_history(std::optional<uint64_t> history) {
    if (!history)
        return "???";
    if (*history == 0)
        return "archive";
    return "{} blocks"_format(*history);
}

// Whether a connected peer at chain height `peer_height` keeping `history` blocks can give us
// block `height`.
constexpr bool peer_can_serve(
        uint64_t height, uint64_t peer_height, std::optional<uint64_t> history) {
    return height < peer_height && history_covers(height, peer_height, history);
}

// Whether a connected peer at chain height `peer_height` keeping `history` blocks has had block
// `height` but no longer keeps it (unlike a peer that just hasn't got it yet).
constexpr bool peer_no_longer_keeps(
        uint64_t height, uint64_t peer_height, std::optional<uint64_t> history) {
    return height < peer_height && !history_covers(height, peer_height, history);
}

// What a syncing node still needs.
struct sync_need {
    // The lowest block not yet downloaded or queued for download: what a peer must be able to
    // serve to be of any use to the sync.
    uint64_t height;
    // The chain height we are syncing to.
    uint64_t target;
};

// The peers connected to while syncing that turned out unable to serve what the sync needed, so
// that picking peers to connect to passes them over even though their peerlist entries say they
// could (the entries don't say how far a peer's own chain has got).
class unhelpful_peers {
  public:
    // Records a peer, with the chain height and history it had, as unable to serve the sync.
    void add(const oxen::quic::Address& addr, uint64_t height, std::optional<uint64_t> history);

    bool contains(const oxen::quic::Address& addr) const;

    // Forgets the peers that, as they were when recorded, could serve block `need`: as the sync
    // gets on, its needs move up into what they keep.  (A peer recorded as not yet having the
    // block is never forgotten this way, as what the sync needs only moves up: only by clear().)
    void forget_servable(uint64_t need);

    // Forgets every peer, once syncing is done.
    void clear() { m_peers.clear(); }

    bool empty() const { return m_peers.empty(); }
    size_t size() const { return m_peers.size(); }

  private:
    // address -> {chain height, history}
    std::map<oxen::quic::Address, std::pair<uint64_t, std::optional<uint64_t>>> m_peers;
};

}  // namespace cryptonote
