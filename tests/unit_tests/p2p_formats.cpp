// Pins the exact bytes that peer addresses serialize to, both on the p2p wire (KV portable storage)
// and in the p2pstate file (boost portable binary archive): existing nodes and existing files
// depend on them, so they must not change.

#include <gtest/gtest.h>
#include <oxenc/hex.h>

#include <sstream>

#include "boost/archive/portable_binary_iarchive.hpp"
#include "boost/archive/portable_binary_oarchive.hpp"
#include "common/format.h"
#include "epee/storages/portable_storage_template_helper.h"
#include "p2p/net_peerlist_boost_serialization.h"
#include "p2p/p2p_protocol_defs.h"

using namespace std::literals;

namespace {

nodetool::peerlist_entry ipv4_entry() {
    nodetool::peerlist_entry e{};
    e.adr = net::ipv4_address{oxen::quic::ipv4{51, 0, 18, 255}, 65535};
    e.id = 0x0102030405060708;
    e.last_seen = 1700000000;
    e.history = 1000;
    return e;
}

nodetool::peerlist_entry ipv6_entry() {
    nodetool::peerlist_entry e{};
    e.adr = epee::net_utils::ipv6_network_address{
            boost::asio::ip::make_address_v6("2001:db8::1"), 22022};
    e.id = 0x0102030405060708;
    e.last_seen = 1700000000;
    return e;
}

// clang-format off
constexpr auto kv_header = "011101010101020101"sv;
// adr: {addr: {m_ip: u32 (the legacy, byte-reversed int), m_port: u16}, type: u8 1}
constexpr auto kv_ipv4_adr =
        "08"
            "0461646472" "0c" "08"
                "046d5f6970" "06" "330012ff"
                "066d5f706f7274" "07" "ffff"
            "0474797065" "08" "01"sv;
// adr: {addr: {addr: 16-byte string, m_port: u16}, type: u8 2}
constexpr auto kv_ipv6_adr =
        "08"
            "0461646472" "0c" "08"
                "0461646472" "0a" "40" "20010db8000000000000000000000001"
                "066d5f706f7274" "07" "0656"
            "0474797065" "08" "02"sv;
constexpr auto kv_id = "026964" "05" "0807060504030201"sv;
constexpr auto kv_last_seen = "096c6173745f7365656e" "01" "00f1536500000000"sv;
constexpr auto kv_rpc_port = "087270635f706f7274" "07" "0000"sv;
// clang-format on

std::string kv_hex(const nodetool::peerlist_entry& e) {
    std::string bin;
    EXPECT_TRUE(epee::serialization::store_t_to_binary(e, bin));
    return oxenc::to_hex(bin);
}

std::string boost_hex(const nodetool::peerlist_entry& e) {
    std::ostringstream out;
    {
        boost::archive::portable_binary_oarchive a{out};
        a << e;
    }
    return oxenc::to_hex(out.str());
}

nodetool::peerlist_entry boost_load(std::string_view hex) {
    std::istringstream in{oxenc::from_hex(hex)};
    boost::archive::portable_binary_iarchive a{in};
    nodetool::peerlist_entry e{};
    a >> e;
    return e;
}

}  // namespace

TEST(p2p_formats, kv_ipv4_peer) {
    auto expected = "{}14" "03616472" "0c" "{}" "07686973746f7279" "05" "e803000000000000" "{}{}{}"_format(
            kv_header, kv_ipv4_adr, kv_id, kv_last_seen, kv_rpc_port);
    EXPECT_EQ(kv_hex(ipv4_entry()), expected);

    nodetool::peerlist_entry loaded{};
    ASSERT_TRUE(epee::serialization::load_t_from_binary(loaded, oxenc::from_hex(expected)));
    EXPECT_EQ(loaded.adr, ipv4_entry().adr);
    EXPECT_EQ(loaded.adr.str(), "51.0.18.255:65535");
    EXPECT_EQ(loaded.id, ipv4_entry().id);
    EXPECT_EQ(loaded.last_seen, ipv4_entry().last_seen);
    EXPECT_EQ(loaded.history, ipv4_entry().history);
}

TEST(p2p_formats, kv_ipv6_peer) {
    auto expected = "{}10" "03616472" "0c" "{}{}{}{}"_format(
            kv_header, kv_ipv6_adr, kv_id, kv_last_seen, kv_rpc_port);
    EXPECT_EQ(kv_hex(ipv6_entry()), expected);

    nodetool::peerlist_entry loaded{};
    ASSERT_TRUE(epee::serialization::load_t_from_binary(loaded, oxenc::from_hex(expected)));
    EXPECT_EQ(loaded.adr, ipv6_entry().adr);
    EXPECT_EQ(loaded.adr.str(), "[2001:db8::1]:22022");
    EXPECT_FALSE(loaded.history);
}

// clang-format off
// The archive header, then peerlist_entry's class info (version 6).  Each class (other than the
// archive's primitives) gets its class info (tracking and version) on its first appearance, so
// what follows depends on the address being serialized as nested objects exactly as it is.
constexpr auto boost_header =
        "01" "16" "73657269616c697a6174696f6e3a3a61726368697665" "0080" "00" "0106"sv;
// clang-format on

TEST(p2p_formats, boost_ipv4_peer) {
    // clang-format off
    auto expected = "{}"
            "0000" "01"         // network_address class info; type 1
            "0000"              // ipv4 address class info
            "04" "330012ff"     // ip (the legacy, byte-reversed int)
            "02" "ffff"         // port
            "08" "0807060504030201" // id
            "04" "00f15365"     // last_seen
            "01" "01"           // has history
            "02" "e803"_format( // history
            boost_header);
    // clang-format on
    EXPECT_EQ(boost_hex(ipv4_entry()), expected);
    auto loaded = boost_load(boost_hex(ipv4_entry()));
    EXPECT_EQ(loaded.adr, ipv4_entry().adr);
    EXPECT_EQ(loaded.id, ipv4_entry().id);
    EXPECT_EQ(loaded.last_seen, ipv4_entry().last_seen);
    EXPECT_EQ(loaded.history, ipv4_entry().history);
}

TEST(p2p_formats, boost_ipv6_peer) {
    // clang-format off
    auto expected = "{}"
            "0000" "02"         // network_address class info; type 2
            "0000"              // ipv6 address class info
            "0000"              // boost::asio::ip::address_v6 class info
            "20010db8000000000000000000000001" // the 16 address bytes
            "02" "0656"         // port
            "08" "0807060504030201" // id
            "04" "00f15365"     // last_seen
            "00"_format(        // no history
            boost_header);
    // clang-format on
    EXPECT_EQ(boost_hex(ipv6_entry()), expected);
    auto loaded = boost_load(boost_hex(ipv6_entry()));
    EXPECT_EQ(loaded.adr, ipv6_entry().adr);
    EXPECT_FALSE(loaded.history);
}
