#include <gtest/gtest.h>

#include <sstream>

#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "epee/serialization/keyvalue_serialization.h"
#include "epee/storages/portable_storage_template_helper.h"
#include "p2p/net_peerlist.h"
#include "p2p/p2p_protocol_defs.h"

namespace {

epee::net_utils::network_address addr(uint32_t ip, uint16_t port = 22022) {
    return epee::net_utils::ipv4_network_address{ip, port};
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
    epee::net_utils::network_address adr;
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

TEST(peer_history, missing_field_means_archive) {
    // Sync data from a peer that predates the field reads as an archive peer
    old_core_sync_data old{};
    old.current_height = 1234;
    old.top_version = cryptonote::hf::hf21_eth;
    std::string blob = epee::serialization::store_t_to_binary(old);
    cryptonote::CORE_SYNC_DATA sync{};
    sync.history = 99;
    ASSERT_TRUE(epee::serialization::load_t_from_binary(sync, blob));
    EXPECT_EQ(sync.current_height, 1234);
    EXPECT_EQ(sync.history, 0);

    // and its peerlist entries are entries for archive peers
    old_peerlist_entry old_pe{addr(0x01020304), 42, 1000};
    blob = epee::serialization::store_t_to_binary(old_pe);
    nodetool::peerlist_entry pe{};
    pe.history = 99;
    ASSERT_TRUE(epee::serialization::load_t_from_binary(pe, blob));
    EXPECT_EQ(pe.id, 42);
    EXPECT_EQ(pe.history, 0);
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

    // An archive node's sync data has no history in it at all: just what old peers send
    sync.history = 0;
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

TEST(peer_history, gossip_does_not_lose_a_known_history) {
    nodetool::peerlist_manager plm;
    plm.init(nodetool::peerlist_types{}, false);
    const auto a = addr(0x05060708);

    // Learned from gossip with a history
    plm.append_with_peer_gray({a, 7, 100, 720});
    // then gossiped again by a peer that predates the field
    plm.append_with_peer_gray({a, 7, 200, 0});
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

    // ... while a 0 relayed for it doesn't
    plm.append_with_peer_white({a, 7, 300, 0});
    ASSERT_TRUE(plm.get_white_peer_by_index(pe, 0));
    EXPECT_EQ(pe.history, 1440);
}

TEST(peer_history, stored_in_the_peerlist_file) {
    nodetool::peerlist_types types{};
    types.white.push_back({addr(1000, 10), 44, 55, 20'160});
    types.gray.push_back({addr(2000, 20), 84, 45, 0});
    types.gray.push_back({addr(3000, 30), 85, 46, 720});

    nodetool::peerlist_storage peers{};
    std::ostringstream out{};
    ASSERT_TRUE(peers.store(out, types));

    std::istringstream in{out.str()};
    auto read = nodetool::peerlist_storage::open(in, true);
    ASSERT_TRUE(read);
    auto public_ = read->take_zone(epee::net_utils::zone::public_);
    ASSERT_EQ(public_.white.size(), 1);
    EXPECT_EQ(public_.white[0].history, 20'160);
    ASSERT_EQ(public_.gray.size(), 2);
    EXPECT_EQ(public_.gray[0].history, 0);
    EXPECT_EQ(public_.gray[1].history, 720);
}
