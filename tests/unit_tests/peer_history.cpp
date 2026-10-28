#include <gtest/gtest.h>

#include <sstream>

#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "cryptonote_protocol/peer_history.h"
#include "epee/serialization/keyvalue_serialization.h"
#include "epee/storages/portable_storage_template_helper.h"
#include "net/address.h"
#include "p2p/net_peerlist.h"
#include "p2p/p2p_protocol_defs.h"

using cryptonote::history_covers;
using cryptonote::peer_can_serve;
using cryptonote::PEER_HISTORY_MARGIN;

namespace {

oxen::quic::Address addr(uint32_t ip, uint16_t port = 22022) {
    return oxen::quic::Address{oxen::quic::ipv4{ip}, port};
}

// CORE_SYNC_DATA and peerlist_entry as peers that predate the history field have them.
struct old_core_sync_data {
    uint64_t current_height;
    uint64_t cumulative_difficulty;
    crypto::hash top_id;
    cryptonote::hf top_version;
    std::vector<uint64_t> blink_blocks;
    std::vector<crypto::hash> blink_hash;

    BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(current_height)
    KV_SERIALIZE(cumulative_difficulty)
    KV_SERIALIZE_VAL_POD_AS_BLOB(top_id)
    KV_SERIALIZE_ENUM(top_version)
    KV_SERIALIZE(blink_blocks)
    KV_SERIALIZE_CONTAINER_POD_AS_BLOB(blink_hash)
    END_KV_SERIALIZE_MAP()
};

struct old_peerlist_entry {
    oxen::quic::Address adr{};
    nodetool::peerid_type id;
    int64_t last_seen;

    BEGIN_KV_SERIALIZE_MAP()
    KV_SERIALIZE(adr)
    KV_SERIALIZE(id)
    KV_SERIALIZE_OPT(last_seen, (int64_t)0)
    uint16_t rpc_port = 0;
    KV_SERIALIZE_VALUE(rpc_port);
    END_KV_SERIALIZE_MAP()
};

}  // namespace

TEST(peer_history, archive_peers_serve_everything_they_have) {
    EXPECT_TRUE(peer_can_serve(0, 1'000'000, 0));
    EXPECT_TRUE(peer_can_serve(999'999, 1'000'000, 0));
    // ... but not what they haven't got yet
    EXPECT_FALSE(peer_can_serve(1'000'000, 1'000'000, 0));
    EXPECT_FALSE(peer_can_serve(2'000'000, 1'000'000, 0));
}

TEST(peer_history, windowed_peers_serve_their_window_less_the_margin) {
    constexpr uint64_t top = 1'000'000, history = 20'000;
    // The oldest block it keeps is at top - history, but within the margin of that doesn't count
    const uint64_t first = top - history + PEER_HISTORY_MARGIN;
    EXPECT_TRUE(peer_can_serve(first, top, history));
    EXPECT_FALSE(peer_can_serve(first - 1, top, history));
    EXPECT_FALSE(peer_can_serve(top - history, top, history));
    EXPECT_FALSE(peer_can_serve(0, top, history));
    EXPECT_TRUE(peer_can_serve(top - 1, top, history));
    EXPECT_FALSE(peer_can_serve(top, top, history));

    // A window shorter than the margin can't serve anything at all
    EXPECT_FALSE(peer_can_serve(top - 1, top, PEER_HISTORY_MARGIN));
    EXPECT_FALSE(peer_can_serve(top - 1, top, 50));

    // Windows near the bottom of the chain don't underflow
    EXPECT_TRUE(peer_can_serve(0, 500, 600));
    EXPECT_FALSE(peer_can_serve(0, 600, 600));
}

TEST(peer_history, peers_that_no_longer_keep_a_block) {
    using cryptonote::peer_no_longer_keeps;
    constexpr uint64_t top = 1'000'000, history = 20'000;
    const uint64_t first = top - history + PEER_HISTORY_MARGIN;
    // A windowed peer past the block that has dropped it is waited on...
    EXPECT_TRUE(peer_no_longer_keeps(first - 1, top, history));
    EXPECT_TRUE(peer_no_longer_keeps(0, top, history));
    // ... but not one that still keeps it,
    EXPECT_FALSE(peer_no_longer_keeps(first, top, history));
    // nor one that hasn't got that far (which we get the chain from as usual),
    EXPECT_FALSE(peer_no_longer_keeps(top, top, history));
    EXPECT_FALSE(peer_no_longer_keeps(top + 5, top, history));
    // nor an archive peer
    EXPECT_FALSE(peer_no_longer_keeps(0, top, 0));
}

TEST(peer_history, peerlist_entries_are_selected_by_history_against_the_target) {
    // A peerlist entry's height is unknown (or long stale), so selection asks only whether the
    // history it advertises would reach back to what we need from the height we are syncing to.
    constexpr uint64_t target = 2'000'000;
    // archive entries always qualify
    EXPECT_TRUE(history_covers(0, target, 0));
    EXPECT_TRUE(history_covers(target + 1000, target, 0));
    // windowed entries covering the need qualify, up to the margin
    EXPECT_TRUE(history_covers(target - 10'000, target, 20'000));
    EXPECT_TRUE(history_covers(target - 20'000 + PEER_HISTORY_MARGIN, target, 20'000));
    // ... and those not covering it don't
    EXPECT_FALSE(history_covers(target - 20'000 + PEER_HISTORY_MARGIN - 1, target, 20'000));
    EXPECT_FALSE(history_covers(0, target, 20'000));
    EXPECT_FALSE(history_covers(1'000'000, target, 720));
}

TEST(peer_history, missing_field_means_archive) {
    // Sync data from a peer that predates the field reads as a peer of unknown history, which is
    // treated as an archive peer
    old_core_sync_data old{};
    old.current_height = 1234;
    old.top_version = cryptonote::hf::hf21_eth;
    std::string blob = epee::serialization::store_t_to_binary(old);
    cryptonote::CORE_SYNC_DATA sync{};
    sync.history = 99;
    ASSERT_TRUE(epee::serialization::load_t_from_binary(sync, blob));
    EXPECT_EQ(sync.current_height, 1234);
    EXPECT_EQ(sync.history, std::nullopt);
    EXPECT_TRUE(history_covers(0, 1'000'000, sync.history));
    EXPECT_TRUE(peer_can_serve(0, 1'000'000, sync.history));
    EXPECT_FALSE(cryptonote::peer_no_longer_keeps(0, 1'000'000, sync.history));
    EXPECT_EQ(cryptonote::describe_history(sync.history), "???");
    EXPECT_EQ(cryptonote::describe_history(0), "archive");
    EXPECT_EQ(cryptonote::describe_history(720), "720 blocks");

    // and so do its peerlist entries
    old_peerlist_entry old_pe{addr(0x01020304), 42, 1000};
    blob = epee::serialization::store_t_to_binary(old_pe);
    nodetool::peerlist_entry pe{};
    pe.history = 99;
    ASSERT_TRUE(epee::serialization::load_t_from_binary(pe, blob));
    EXPECT_EQ(pe.id, 42);
    EXPECT_EQ(pe.history, std::nullopt);
}

TEST(peer_history, history_is_sent_and_old_peers_accept_it) {
    cryptonote::CORE_SYNC_DATA sync{};
    sync.current_height = 1234;
    sync.top_version = cryptonote::hf::hf21_eth;
    sync.history = 20'160;
    std::string blob = epee::serialization::store_t_to_binary(sync);

    cryptonote::CORE_SYNC_DATA sync2{};
    ASSERT_TRUE(epee::serialization::load_t_from_binary(sync2, blob));
    EXPECT_EQ(sync2.history, 20'160);

    old_core_sync_data old{};
    ASSERT_TRUE(epee::serialization::load_t_from_binary(old, blob));
    EXPECT_EQ(old.current_height, 1234);

    // An archive node says so (a 0), so that it can be told from a node that never said
    sync.history = 0;
    blob = epee::serialization::store_t_to_binary(sync);
    ASSERT_TRUE(epee::serialization::load_t_from_binary(sync2, blob));
    EXPECT_EQ(sync2.history, 0);
    ASSERT_TRUE(epee::serialization::load_t_from_binary(old, blob));
    EXPECT_EQ(old.current_height, 1234);
    // while an unknown history is left out, as the nodes that never say leave it
    sync.history = std::nullopt;
    EXPECT_EQ(
            epee::serialization::store_t_to_binary(sync),
            epee::serialization::store_t_to_binary(old));

    nodetool::peerlist_entry pe{addr(0x01020304), 42, 1000, 720};
    blob = epee::serialization::store_t_to_binary(pe);
    nodetool::peerlist_entry pe2{};
    ASSERT_TRUE(epee::serialization::load_t_from_binary(pe2, blob));
    EXPECT_EQ(pe2.history, 720);
    old_peerlist_entry old_pe{};
    ASSERT_TRUE(epee::serialization::load_t_from_binary(old_pe, blob));
    EXPECT_EQ(old_pe.id, 42);
}

TEST(peer_history, unhelpful_peers) {
    cryptonote::unhelpful_peers unhelpful;
    // a windowed peer at 1,000,000 keeping 20,000 blocks, when we need block 500,000
    unhelpful.add(addr(1), 1'000'000, 20'000);
    // a peer behind us
    unhelpful.add(addr(2), 400'000, 0);
    EXPECT_TRUE(unhelpful.contains(addr(1)));
    EXPECT_TRUE(unhelpful.contains(addr(2)));
    EXPECT_FALSE(unhelpful.contains(addr(3)));
    EXPECT_EQ(unhelpful.size(), 2);

    // Re-adding updates rather than duplicates
    unhelpful.add(addr(1), 1'000'000, 20'000);
    EXPECT_EQ(unhelpful.size(), 2);

    // Nothing is forgotten while what we need is still out of their reach
    unhelpful.forget_servable(500'000);
    unhelpful.forget_servable(1'000'000 - 20'000 + PEER_HISTORY_MARGIN - 1);
    EXPECT_EQ(unhelpful.size(), 2);

    // The windowed one is forgotten once what we need moves up into its window
    unhelpful.forget_servable(1'000'000 - 20'000 + PEER_HISTORY_MARGIN);
    EXPECT_FALSE(unhelpful.contains(addr(1)));
    // but the one that was behind stays, as we only need ever higher blocks
    EXPECT_TRUE(unhelpful.contains(addr(2)));
    unhelpful.forget_servable(1'500'000);
    EXPECT_TRUE(unhelpful.contains(addr(2)));

    // ... until syncing is done
    unhelpful.clear();
    EXPECT_TRUE(unhelpful.empty());
}

TEST(peer_history, gossip_does_not_lose_a_known_history) {
    nodetool::peerlist_manager plm;
    plm.init(nodetool::peerlist_types{}, false);
    const auto a = addr(0x05060708);

    // Learned from gossip with a history
    plm.append_with_peer_gray({a, 7, 100, 720});
    // then gossiped again by a peer that predates the field
    plm.append_with_peer_gray({a, 7, 200, std::nullopt});
    nodetool::peerlist_entry pe;
    ASSERT_TRUE(plm.get_gray_peer_by_index(pe, 0));
    EXPECT_EQ(pe.history, 720);

    // but what the peer says itself always goes
    plm.set_peer_just_seen(7, a, 0);
    ASSERT_EQ(plm.get_white_peers_count(), 1);
    ASSERT_TRUE(plm.get_white_peer_by_index(pe, 0));
    EXPECT_EQ(pe.history, 0);
    plm.set_peer_just_seen(7, a, 1440);
    ASSERT_TRUE(plm.get_white_peer_by_index(pe, 0));
    EXPECT_EQ(pe.history, 1440);
    EXPECT_GT(pe.last_seen, 200);

    // ... as does a history relayed for it, archive included,
    plm.append_with_peer_white({a, 7, 300, 0});
    ASSERT_TRUE(plm.get_white_peer_by_index(pe, 0));
    EXPECT_EQ(pe.history, 0);
    // but not an entry relayed without one
    plm.append_with_peer_white({a, 7, 300, std::nullopt});
    ASSERT_TRUE(plm.get_white_peer_by_index(pe, 0));
    EXPECT_EQ(pe.history, 0);
}

TEST(peer_history, stored_in_the_peerlist_file) {
    nodetool::peerlist_types types{};
    types.white.push_back({addr(1000, 10), 44, 55, 20'160});
    types.white.push_back({addr(1001, 11), 45, 56, std::nullopt});
    types.gray.push_back({addr(2000, 20), 84, 45, 0});
    types.gray.push_back({addr(3000, 30), 85, 46, 720});

    nodetool::peerlist_storage peers{};
    std::ostringstream out{};
    ASSERT_TRUE(peers.store(out, types));

    std::istringstream in{out.str()};
    auto read = nodetool::peerlist_storage::open(in, true);
    ASSERT_TRUE(read);
    auto public_ = read->take();
    ASSERT_EQ(public_.white.size(), 2);
    EXPECT_EQ(public_.white[0].history, 20'160);
    EXPECT_EQ(public_.white[1].history, std::nullopt);
    ASSERT_EQ(public_.gray.size(), 2);
    EXPECT_EQ(public_.gray[0].history, 0);
    EXPECT_EQ(public_.gray[1].history, 720);
}
