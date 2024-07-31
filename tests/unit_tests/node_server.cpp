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
#include "p2p/net_node.inl"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.inl"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/cryptonote_tx_utils.h"

#define MAKE_IPV4_ADDRESS(a,b,c,d) epee::net_utils::ipv4_network_address{MAKE_IP(a,b,c,d),0}
#define MAKE_IPV4_ADDRESS_PORT(a,b,c,d,e) epee::net_utils::ipv4_network_address{MAKE_IP(a,b,c,d),e}
#define MAKE_IPV4_SUBNET(a,b,c,d,e) epee::net_utils::ipv4_network_subnet{MAKE_IP(a,b,c,d),e}

namespace cryptonote {
  class blockchain_storage;
}

struct fake_lockable {
  void lock() {}
  void unlock() {}
  bool try_lock() { return true; }
  void lock_shared() {}
  void unlock_shared() {}
  bool try_lock_shared() { return true; }
};

class test_core
{
public:
  void on_synchronized(){}
  void safesyncmode(const bool){}
  void set_target_blockchain_height(uint64_t) {}
  bool init(const boost::program_options::variables_map& vm) {return true ;}
  bool deinit(){return true;}
  std::vector<cryptonote::tx_verification_batch_info> parse_incoming_txs(const std::vector<std::string>& tx_blobs, const cryptonote::tx_pool_options &opts) { return {}; }
  bool handle_parsed_txs(std::vector<cryptonote::tx_verification_batch_info> &parsed_txs, const cryptonote::tx_pool_options &opts, uint64_t *blink_rollback_height = nullptr) { if (blink_rollback_height) *blink_rollback_height = 0; return true; }
  std::vector<cryptonote::tx_verification_batch_info> handle_incoming_txs(const std::vector<std::string>& tx_blobs, const cryptonote::tx_pool_options &opts) { return {}; }
  bool handle_incoming_tx(const std::string& tx_blob, cryptonote::tx_verification_context& tvc, const cryptonote::tx_pool_options &opts) { return true; }
  std::pair<std::vector<std::shared_ptr<cryptonote::blink_tx>>, std::unordered_set<crypto::hash>> parse_incoming_blinks(const std::vector<cryptonote::serializable_blink_metadata> &blinks) { return {}; }
  int add_blinks(const std::vector<std::shared_ptr<cryptonote::blink_tx>> &blinks) { return 0; }
  bool handle_incoming_block(const std::string& block_blob, const cryptonote::block *block, cryptonote::block_verification_context& bvc, cryptonote::checkpoint_t const *checkpoint, bool update_miner_blocktemplate = true) { return true; }
  bool handle_uptime_proof(const cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request &proof, bool &my_uptime_proof_confirmation) { return false; }
  struct faker_miner {
      void pause() {}
      void resume() {}
  } miner;
  bool on_idle(){return true;}
  struct fake_blockchain : fake_lockable {
    bool find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, cryptonote::NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp){return true;}
    uint64_t get_current_blockchain_height() const {return 1;}
    uint64_t get_immutable_height() const {return 1;}
    std::pair<uint64_t, crypto::hash> get_tail_id() const { return {0, crypto::null<crypto::hash>};}
    bool have_block(const crypto::hash& id) const {return true;}
    bool get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<std::string, cryptonote::block>>& blocks, std::vector<std::string>& txs) const { return false; }
    bool get_transactions(const std::vector<crypto::hash>& txs_ids, std::vector<cryptonote::transaction>& txs, std::unordered_set<crypto::hash>* missed_txs) const { return false; }
    bool get_block_by_hash(const crypto::hash &h, cryptonote::block &blk, bool *orphan = NULL) const { return false; }
    bool handle_get_blocks(cryptonote::NOTIFY_REQUEST_GET_BLOCKS::request& arg, cryptonote::NOTIFY_RESPONSE_GET_BLOCKS::request& rsp){return true;}
    bool handle_get_txs(cryptonote::NOTIFY_REQUEST_GET_TXS::request&, cryptonote::NOTIFY_NEW_TRANSACTIONS::request&) { return true; }
    cryptonote::difficulty_type get_block_cumulative_difficulty(uint64_t height) const { return 0; }
    uint64_t prevalidate_block_hashes(uint64_t height, const std::vector<crypto::hash> &hashes) { return 0; }
    bool blink_rollback(uint64_t rollback_height) { return false; }
    bool get_short_chain_history(std::list<crypto::hash>& ids) const { return true; }
    bool is_within_compiled_block_hash_area(uint64_t height) const { return false; }
    uint32_t get_blockchain_pruning_seed() const { return 0; }

    struct fake_db {
        cryptonote::difficulty_type get_block_cumulative_difficulty(uint64_t height) const { return 0; }
    } db_;
    fake_db& db() { return db_; }
  } blockchain;
  bool get_test_drop_download() const {return true;}
  bool get_test_drop_download_height() const {return true;}
  bool prepare_handle_incoming_blocks(const std::vector<cryptonote::block_complete_entry>  &blocks_entry, std::vector<cryptonote::block> &blocks) { return true; }
  bool cleanup_handle_incoming_blocks(bool force_sync = false) { return true; }
  uint64_t get_target_blockchain_height() const { return 1; }
  size_t get_block_sync_size(uint64_t height) const { return cryptonote::BLOCKS_SYNCHRONIZING_DEFAULT_COUNT; }
  virtual crypto::hash on_transaction_relayed(const std::string& tx) { return crypto::null<crypto::hash>; }
  cryptonote::network_type get_nettype() const { return cryptonote::network_type::MAINNET; }
  const cryptonote::network_config& get_net_config() const { return get_config(get_nettype()); }
  bool pad_transactions() { return false; }
  bool prune_blockchain(uint32_t pruning_seed = 0) { return true; }
  void stop() {}

  // TODO(oxen): Write tests
  bool add_service_node_vote(const service_nodes::quorum_vote_t& vote, cryptonote::vote_verification_context &vvc) { return false; }
  void set_service_node_votes_relayed(const std::vector<service_nodes::quorum_vote_t> &votes) {}

  bool handle_incoming_blinks(const std::vector<cryptonote::serializable_blink_metadata> &blinks, std::vector<crypto::hash> *bad_blinks = nullptr, std::vector<crypto::hash> *missing_txs = nullptr) { return true; }

  struct fake_lock { ~fake_lock() { /* avoid unused variable warning by having a destructor */ } };
  fake_lock incoming_tx_lock() { return {}; }

  struct fake_pool : fake_lockable {
      void add_missing_blink_hashes(const std::map<uint64_t, std::vector<crypto::hash>> &potential) {}
      template <typename... Args>
      int blink_shared_lock(Args &&...args) { return 42; }
      std::shared_ptr<cryptonote::blink_tx> get_blink(crypto::hash &) { return nullptr; }
      bool get_transaction(const crypto::hash& id, std::string& tx_blob) const { return false; }
      bool have_tx(const crypto::hash &txid) const { return false; }
      std::map<uint64_t, crypto::hash> get_blink_checksums() const { return {}; }
      std::vector<crypto::hash> get_mined_blinks(const std::set<uint64_t> &) const { return {}; }
      void keep_missing_blinks(std::vector<crypto::hash> &tx_hashes) const {}
  } mempool;

private:
  fake_pool m_pool;
};

typedef nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<test_core>> Server;

static bool is_blocked(Server &server, const epee::net_utils::network_address &address, time_t *t = NULL)
{
  std::map<std::string, time_t> hosts = server.get_blocked_hosts();
  for (auto rec: hosts)
  {
    if (rec.first == address.host_str())
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
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core);
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

TEST(ban, limit)
{
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core);
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
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core);
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
  test_core pr_core;
  cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol(pr_core);
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
    test_core pr_core;
    cryptonote::t_cryptonote_protocol_handler<test_core> cprotocol;
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

  const auto init = [](const std::unique_ptr<test_data_t>& server, const char* port) -> bool {
    boost::program_options::options_description desc_options("Command line options");
    boost::program_options::options_description hidden("Hidden options");
    cryptonote::core::init_options(desc_options);
    Server::init_options(desc_options, hidden);

    const char *argv[2] = {nullptr, nullptr};
    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(1, argv, desc_options), vm);

    vm.find(nodetool::arg_p2p_bind_port.name)->second = boost::program_options::variable_value(std::string(port), false);

    boost::program_options::notify(vm);

    return server->server->init(vm);
  };

  constexpr char port[] = "48080";
  constexpr char port_another[] = "58080";

  const auto node = new_node();
  EXPECT_TRUE(init(node, port));

  EXPECT_FALSE(init(new_node(), port));
  EXPECT_TRUE(init(new_node(), port_another));
}

namespace nodetool { template class node_server<cryptonote::t_cryptonote_protocol_handler<test_core>>; }
namespace cryptonote { template class t_cryptonote_protocol_handler<test_core>; }
