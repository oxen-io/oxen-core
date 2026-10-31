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
#include "cryptonote_core/cryptonote_core.h"
#include "p2p/net_node.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"

#define MAKE_IPV4_ADDRESS(a,b,c,d) oxen::quic::Address{oxen::quic::ipv4(a,b,c,d),0}
#define MAKE_IPV4_ADDRESS_PORT(a,b,c,d,e) oxen::quic::Address{oxen::quic::ipv4(a,b,c,d),e}
#define MAKE_IPV4_SUBNET(a,b,c,d,e) (oxen::quic::ipv4(a,b,c,d) / e)

// These only use the p2p server's own state, so the core under its protocol handler is never
// initialized.
using Server = nodetool::node_server;

static bool is_blocked(Server &server, const oxen::quic::Address &address, time_t *t = NULL)
{
  std::map<std::string, time_t> hosts = server.get_blocked_hosts();
  for (auto rec: hosts)
  {
    if (rec.first == address.host())
    {
      if (t)
        *t = rec.second;
      return true;
    }
  }
  return false;
}

TEST(ban, add)
{
  cryptonote::core pr_core;
  cryptonote::protocol_handler cprotocol(pr_core);
  Server server(cprotocol);
  cprotocol.set_p2p_endpoint(&server);

  // starts empty
  ASSERT_TRUE(server.get_blocked_hosts().empty());
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));

  // add an IP
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 1);
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));

  // add the same, should not change
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 1);
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));

  // remove an unblocked IP, should not change
  ASSERT_FALSE(server.unblock_host(MAKE_IPV4_ADDRESS(1,2,3,5)));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 1);
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));

  // remove the IP, ends up empty
  ASSERT_TRUE(server.unblock_host(MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 0);
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));

  // remove the IP from an empty list, still empty
  ASSERT_FALSE(server.unblock_host(MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 0);
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));

  // add two for known amounts of time, they're both blocked
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4), 1));
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,5), 3));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 2);
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));
  ASSERT_TRUE(server.unblock_host(MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(server.unblock_host(MAKE_IPV4_ADDRESS(1,2,3,5)));

  // these tests would need to call is_remote_ip_allowed, which is private
#if 0
  // after two seconds, the first IP is unblocked, but not the second yet
  sleep(2);
  ASSERT_TRUE(server.get_blocked_hosts().size() == 1);
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));

  // after two more seconds, the second IP is also unblocked
  sleep(2);
  ASSERT_TRUE(server.get_blocked_hosts().size() == 0);
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));
#endif

  // add an IP again, then re-ban for longer, then shorter
  time_t t;
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4), 2));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 1);
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4), &t));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));
  ASSERT_TRUE(t >= 1);
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4), 9));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 1);
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4), &t));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));
  ASSERT_TRUE(t >= 8);
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4), 5));
  ASSERT_TRUE(server.get_blocked_hosts().size() == 1);
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4), &t));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,5)));
  ASSERT_TRUE(t >= 4);
}

namespace {
// Records the connections a protocol handler drops, in place of a p2p node dropping them
struct drop_recorder : nodetool::p2p_endpoint_stub {
  std::vector<cryptonote::connection_id_t> dropped;
  bool drop_connection(const cryptonote::cryptonote_connection_context& context) override
  {
    dropped.push_back(context.m_connection_id);
    return true;
  }
};
}

TEST(protocol_handler, oversized_chain_entry_drops_peer)
{
  cryptonote::core pr_core;
  cryptonote::protocol_handler cprotocol(pr_core);
  drop_recorder p2p;
  cprotocol.set_p2p_endpoint(&p2p);

  cryptonote::NOTIFY_RESPONSE_CHAIN_ENTRY::request entry{};
  entry.m_block_ids.resize(cryptonote::BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT + 1);
  entry.start_height = 0;
  entry.total_height = entry.m_block_ids.size();
  const auto body = nodetool::levin::encode(entry);

  cryptonote::cryptonote_connection_context context{
      cryptonote::connection_id_t::random(), MAKE_IPV4_ADDRESS(1,2,3,4), false};
  cprotocol.notify(
      cryptonote::NOTIFY_RESPONSE_CHAIN_ENTRY::ID,
      oxen::quic::reinterpret_span<const uint8_t>(std::span{body}),
      context);
  ASSERT_EQ(p2p.dropped.size(), 1);
  EXPECT_EQ(p2p.dropped[0], context.m_connection_id);
}

TEST(protocol_handler, oversized_chain_request_drops_peer)
{
  cryptonote::core pr_core;
  cryptonote::protocol_handler cprotocol(pr_core);
  drop_recorder p2p;
  cprotocol.set_p2p_endpoint(&p2p);

  cryptonote::NOTIFY_REQUEST_CHAIN::request request{};
  request.block_ids.resize(cryptonote::SHORT_CHAIN_HISTORY_MAX_COUNT + 1);
  const auto body = nodetool::levin::encode(request);

  cryptonote::cryptonote_connection_context context{
      cryptonote::connection_id_t::random(), MAKE_IPV4_ADDRESS(1,2,3,4), false};
  cprotocol.notify(
      cryptonote::NOTIFY_REQUEST_CHAIN::ID,
      oxen::quic::reinterpret_span<const uint8_t>(std::span{body}),
      context);
  ASSERT_EQ(p2p.dropped.size(), 1);
  EXPECT_EQ(p2p.dropped[0], context.m_connection_id);
}

TEST(sync_need, heights)
{
  using cryptonote::sync_need_for;
  // At the network's height
  EXPECT_FALSE(sync_need_for(1, 1, 1));

  auto need = sync_need_for(1, 1, 1000);
  ASSERT_TRUE(need);
  EXPECT_EQ(need->height, 1);
  EXPECT_EQ(need->target, 1000);

  // What is needed next is the lowest block not yet downloaded, which can be well past the chain
  need = sync_need_for(1, 500, 1000);
  ASSERT_TRUE(need);
  EXPECT_EQ(need->height, 500);

  // Within the margin of the target only a peer's height, not its history, could keep it from
  // serving, so there is nothing for the peer policy to do
  EXPECT_FALSE(sync_need_for(1, 1, 1 + cryptonote::PEER_HISTORY_MARGIN));
  EXPECT_TRUE(sync_need_for(1, 1, 2 + cryptonote::PEER_HISTORY_MARGIN));
  EXPECT_FALSE(sync_need_for(1, 900, 1000));
}

TEST(sync_need, only_until_first_synchronized)
{
  // Once synchronized, a target ahead of us is just a new block arriving, not a sync
  cryptonote::core pr_core;
  cryptonote::protocol_handler synced(pr_core, /*offline=*/true);
  ASSERT_TRUE(synced.is_synchronized());
  EXPECT_FALSE(synced.get_sync_need());
}

TEST(ban, limit)
{
  cryptonote::core pr_core;
  cryptonote::protocol_handler cprotocol(pr_core);
  Server server(cprotocol);
  cprotocol.set_p2p_endpoint(&server);

  // starts empty
  ASSERT_TRUE(server.get_blocked_hosts().empty());
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4), std::numeric_limits<time_t>::max() - 1));
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS(1,2,3,4), 1));
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS(1,2,3,4)));
}

TEST(ban, subnet)
{
  time_t seconds;
  cryptonote::core pr_core;
  cryptonote::protocol_handler cprotocol(pr_core);
  Server server(cprotocol);
  cprotocol.set_p2p_endpoint(&server);

  ASSERT_TRUE(server.block_subnet(MAKE_IPV4_SUBNET(1,2,3,4,24), 10));
  ASSERT_TRUE(server.get_blocked_subnets().size() == 1);
  ASSERT_TRUE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,2,3,4), &seconds));
  ASSERT_TRUE(seconds >= 9);
  ASSERT_TRUE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,2,3,255), &seconds));
  ASSERT_TRUE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,2,3,0), &seconds));
  ASSERT_FALSE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,2,4,0), &seconds));
  ASSERT_FALSE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,2,2,0), &seconds));
  ASSERT_TRUE(server.unblock_subnet(MAKE_IPV4_SUBNET(1,2,3,8,24)));
  ASSERT_TRUE(server.get_blocked_subnets().size() == 0);
  ASSERT_FALSE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,2,3,255), &seconds));
  ASSERT_FALSE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,2,3,0), &seconds));
  ASSERT_TRUE(server.block_subnet(MAKE_IPV4_SUBNET(1,2,3,4,8), 10));
  ASSERT_TRUE(server.get_blocked_subnets().size() == 1);
  ASSERT_TRUE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,255,3,255), &seconds));
  ASSERT_TRUE(server.is_host_blocked(MAKE_IPV4_ADDRESS(1,0,3,255), &seconds));
  ASSERT_FALSE(server.unblock_subnet(MAKE_IPV4_SUBNET(1,2,3,8,24)));
  ASSERT_TRUE(server.get_blocked_subnets().size() == 1);
  ASSERT_TRUE(server.block_subnet(MAKE_IPV4_SUBNET(1,2,3,4,8), 10));
  ASSERT_TRUE(server.get_blocked_subnets().size() == 1);
  ASSERT_TRUE(server.unblock_subnet(MAKE_IPV4_SUBNET(1,255,0,0,8)));
  ASSERT_TRUE(server.get_blocked_subnets().size() == 0);
}

TEST(ban, ignores_port)
{
  time_t seconds;
  cryptonote::core pr_core;
  cryptonote::protocol_handler cprotocol(pr_core);
  Server server(cprotocol);
  cprotocol.set_p2p_endpoint(&server);

  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS_PORT(1,2,3,4,5)));
  ASSERT_TRUE(server.block_host(MAKE_IPV4_ADDRESS_PORT(1,2,3,4,5), std::numeric_limits<time_t>::max() - 1));
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS_PORT(1,2,3,4,5)));
  ASSERT_TRUE(is_blocked(server,MAKE_IPV4_ADDRESS_PORT(1,2,3,4,6)));
  ASSERT_TRUE(server.unblock_host(MAKE_IPV4_ADDRESS_PORT(1,2,3,4,5)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS_PORT(1,2,3,4,5)));
  ASSERT_FALSE(is_blocked(server,MAKE_IPV4_ADDRESS_PORT(1,2,3,4,6)));
}

TEST(node_server, bind_same_p2p_port)
{
  struct test_data_t
  {
    cryptonote::core pr_core;
    cryptonote::protocol_handler cprotocol;
    std::unique_ptr<Server> server;

    test_data_t(): cprotocol(pr_core)
    {
      server.reset(new Server(cprotocol));
      cprotocol.set_p2p_endpoint(server.get());
    }
  };

  const auto new_node = []() -> std::unique_ptr<test_data_t> {
    test_data_t *d = new test_data_t;
    return std::unique_ptr<test_data_t>(d);
  };

  const auto init = [](const std::unique_ptr<test_data_t>& server, uint16_t port) -> bool {
    boost::program_options::options_description desc_options("Command line options");
    boost::program_options::options_description hidden("Hidden options");
    cryptonote::core::init_options(desc_options);
    Server::init_options(desc_options, hidden);

    const char *argv[2] = {nullptr, nullptr};
    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(1, argv, desc_options), vm);

    vm.find(nodetool::arg_p2p_bind_port.name)->second = boost::program_options::variable_value(port, false);

    boost::program_options::notify(vm);

    return server->server->init(vm);
  };

  constexpr uint16_t port = 48080;
  constexpr uint16_t port_another = 58080;

  const auto node = new_node();
  EXPECT_TRUE(init(node, port));

  EXPECT_FALSE(init(new_node(), port));
  EXPECT_TRUE(init(new_node(), port_another));
}
