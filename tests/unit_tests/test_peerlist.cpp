// Copyright (c) 2014-2018, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "gtest/gtest.h"

#include "common/util.h"
#include "p2p/net_peerlist.h"
#include "epee/net/net_utils_base.h"

TEST(peer_list, peer_list_general)
{
  nodetool::peerlist_manager plm;
  plm.init(nodetool::peerlist_types{}, false);
#define MAKE_IPV4_ADDRESS(a,b,c,d,e) oxen::quic::Address{oxen::quic::ipv4(a,b,c,d),e}
#define ADD_GRAY_NODE(addr_, id_, last_seen_) {  nodetool::peerlist_entry ple; ple.last_seen=last_seen_;ple.adr = addr_; ple.id = id_;plm.append_with_peer_gray(ple);}
#define ADD_WHITE_NODE(addr_, id_, last_seen_) {  nodetool::peerlist_entry ple;ple.last_seen=last_seen_; ple.adr = addr_; ple.id = id_;plm.append_with_peer_white(ple);}

#define PRINT_HEAD(step) {std::vector<nodetool::peerlist_entry> bs_head; bool r = plm.get_peerlist_head(bs_head, 100);std::cout << "step " << step << ": " << bs_head.size() << std::endl;}

  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,1, 8080), 121241, 34345);
  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,2, 8080), 121241, 34345);
  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,3, 8080), 121241, 34345);
  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,4, 8080), 121241, 34345);
  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,5, 8080), 121241, 34345);

  ADD_WHITE_NODE(MAKE_IPV4_ADDRESS(123,43,12,1, 8080), 121241, 34345);
  ADD_WHITE_NODE(MAKE_IPV4_ADDRESS(123,43,12,2, 8080), 121241, 34345);
  ADD_WHITE_NODE(MAKE_IPV4_ADDRESS(123,43,12,3, 8080), 121241, 34345);
  ADD_WHITE_NODE(MAKE_IPV4_ADDRESS(123,43,12,4, 8080), 121241, 34345);

  size_t gray_list_size = plm.get_gray_peers_count();
  ASSERT_EQ(gray_list_size, 1);

  std::vector<nodetool::peerlist_entry> bs_head;
  bool r = plm.get_peerlist_head(bs_head, 100);
  std::cout << bs_head.size() << std::endl;
  ASSERT_TRUE(r);

  ASSERT_EQ(bs_head.size(), 4);


  ADD_GRAY_NODE(MAKE_IPV4_ADDRESS(123,43,12,5, 8080), 121241, 34345);
  ASSERT_EQ(plm.get_gray_peers_count(), 1);
  ASSERT_EQ(plm.get_white_peers_count(), 4);
}

namespace
{
  bool check_empty(nodetool::peerlist_storage& peers)
  {
    const nodetool::peerlist_types types{peers.take()};
    EXPECT_TRUE(types.white.empty());
    EXPECT_TRUE(types.gray.empty());
    EXPECT_TRUE(types.anchor.empty());
    return types.white.empty() && types.gray.empty() && types.anchor.empty();
  }

  void check_public_peers(const nodetool::peerlist_types& types)
  {
    ASSERT_EQ(1u, types.white.size());
    ASSERT_TRUE(types.white[0].adr.is_ipv4());
    EXPECT_EQ(oxen::quic::ipv4{1000}, types.white[0].adr.to_ipv4());
    EXPECT_EQ(10u, types.white[0].adr.port());
    EXPECT_EQ(44u, types.white[0].id);
    EXPECT_EQ(55u, types.white[0].last_seen);

    ASSERT_EQ(1u, types.gray.size());
    ASSERT_TRUE(types.gray[0].adr.is_ipv4());
    EXPECT_EQ(oxen::quic::ipv4{2000}, types.gray[0].adr.to_ipv4());
    EXPECT_EQ(20u, types.gray[0].adr.port());
    EXPECT_EQ(84u, types.gray[0].id);
    EXPECT_EQ(45u, types.gray[0].last_seen);

    ASSERT_EQ(1u, types.anchor.size());
    ASSERT_TRUE(types.anchor[0].adr.is_ipv4());
    EXPECT_EQ(oxen::quic::ipv4{999}, types.anchor[0].adr.to_ipv4());
    EXPECT_EQ(654u, types.anchor[0].adr.port());
    EXPECT_EQ(444u, types.anchor[0].id);
    EXPECT_EQ(555u, types.anchor[0].first_seen);
  }
}

TEST(peerlist_storage, store)
{
  nodetool::peerlist_storage peers{};
  EXPECT_TRUE(check_empty(peers));

  std::string buffer{};
  {
    nodetool::peerlist_types types{};
    types.white.push_back({oxen::quic::Address{oxen::quic::ipv4{1000}, 10}, 44, 55});
    types.gray.push_back({oxen::quic::Address{oxen::quic::ipv4{2000}, 20}, 84, 45});
    types.anchor.push_back({oxen::quic::Address{oxen::quic::ipv4{999}, 654}, 444, 555});

    std::ostringstream stream{};
    EXPECT_TRUE(peers.store(stream, types));
    buffer = stream.str();
  }
  EXPECT_TRUE(check_empty(peers));
  {
    std::istringstream stream{buffer};
    std::optional<nodetool::peerlist_storage> read_peers =
      nodetool::peerlist_storage::open(stream, true);
    ASSERT_TRUE(bool(read_peers));
    peers = std::move(*read_peers);
  }

  nodetool::peerlist_types types = peers.take();
  EXPECT_TRUE(check_empty(peers));
  check_public_peers(types);

  // Storing what was taken and reading it back gives the same peers again
  {
    std::ostringstream stream{};
    EXPECT_TRUE(peers.store(stream, types));
    buffer = stream.str();
  }
  {
    std::istringstream stream{buffer};
    std::optional<nodetool::peerlist_storage> read_peers =
      nodetool::peerlist_storage::open(stream, true);
    ASSERT_TRUE(bool(read_peers));
    peers = std::move(*read_peers);
  }
  types = peers.take();
  EXPECT_TRUE(check_empty(peers));
  check_public_peers(types);
}
