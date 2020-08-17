// Copyright (c) 2018-2020, The Loki Project
// Copyright (c) 2014-2019, The Monero Project
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

#pragma once

#include <optional>

#include "common/common_fwd.h"
#include "common/scoped_message_writer.h"
#include "rpc/http_client.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "rpc/core_rpc_server.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize {

class rpc_command_executor final {
private:
  std::optional<cryptonote::rpc::http_client> m_rpc_client;
  cryptonote::rpc::core_rpc_server* m_rpc_server = nullptr;
  const cryptonote::rpc::rpc_context m_server_context{true};

public:
  /// Executor for remote connection RPC
  rpc_command_executor(
      std::string remote_url,
      const std::optional<tools::login>& user
    );
  /// Executor for local daemon RPC
  rpc_command_executor(cryptonote::rpc::core_rpc_server& rpc_server)
    : m_rpc_server{&rpc_server} {}

  /// Runs some RPC command either via json_rpc or a direct core rpc call.
  ///
  /// @param req the request object (rvalue reference)
  /// @param res the response object (lvalue reference)
  /// @param error print this (and, on exception, the exception message) on failure.  If empty then
  /// nothing is printed on failure.
  /// @param check_status_ok whether we require res.status == STATUS_OK to consider the request
  /// successful
  template <typename RPC>
  bool invoke(typename RPC::request&& req, typename RPC::response& res, const std::string& error, bool check_status_ok = true)
  {
    try {
      if (m_rpc_client) {
        res = m_rpc_client->json_rpc<RPC>(RPC::names()[0], req);
      } else {
        res = m_rpc_server->invoke(std::move(req), m_server_context);
      }
      if (!check_status_ok || res.status == cryptonote::rpc::STATUS_OK)
        return true;
    } catch (const std::exception& e) {
      if (!error.empty())
        tools::fail_msg_writer() << error << ": " << e.what();
      return false;
    } catch (...) {}
    if (!error.empty())
      tools::fail_msg_writer() << error;
    return false;
  }

  bool print_checkpoints(uint64_t start_height, uint64_t end_height, bool print_json);

  bool print_sn_state_changes(uint64_t start_height, uint64_t end_height);

  bool print_peer_list(bool white = true, bool gray = true, size_t limit = 0, bool pruned_only = false, bool publicrpc_only = false);

  bool print_peer_list_stats();

  bool save_blockchain();

  bool show_hash_rate();

  bool hide_hash_rate();

  bool show_difficulty();

  bool show_status();

  bool print_connections();

  bool print_blockchain_info(int64_t start_block_index, uint64_t end_block_index);

  bool print_quorum_state(uint64_t start_height, uint64_t end_height);

  bool set_log_level(int8_t level);

  bool set_log_categories(std::string categories);

  bool print_height();

private:
  bool print_block(cryptonote::rpc::GET_BLOCK::request&& req, bool include_hdex);

public:
  bool print_block_by_hash(const crypto::hash& block_hash, bool include_hex);

  bool print_block_by_height(uint64_t height, bool include_hex);

  bool print_transaction(const crypto::hash& transaction_hash, bool include_metadata, bool include_hex, bool include_json);

  bool is_key_image_spent(const crypto::key_image &ki);

  bool print_transaction_pool_long();

  bool print_transaction_pool_short();

  bool print_transaction_pool_stats();

  bool start_mining(const cryptonote::account_public_address& address, uint64_t num_threads, uint32_t num_blocks, cryptonote::network_type nettype);

  bool stop_mining();

  bool mining_status();

  bool stop_daemon();

  bool print_status();

  bool get_limit(bool up = true, bool down = true);

  bool set_limit(int64_t limit_down, int64_t limit_up);

  bool out_peers(bool set, uint32_t limit);

  bool in_peers(bool set, uint32_t limit);

  bool hard_fork_info(uint8_t version);

  bool print_bans();

  bool ban(const std::string &address, time_t seconds, bool clear_ban = false);

  bool unban(const std::string &address);

  bool banned(const std::string &address);

  bool flush_txpool(std::string txid);

  bool output_histogram(const std::vector<uint64_t> &amounts, uint64_t min_count, uint64_t max_count);

  bool print_coinbase_tx_sum(uint64_t height, uint64_t count);

  bool alt_chain_info(const std::string &tip, size_t above, uint64_t last_blocks);

  bool print_blockchain_dynamic_stats(uint64_t nblocks);

  bool relay_tx(const std::string &txid);

  bool sync_info();

  bool pop_blocks(uint64_t num_blocks);

  bool print_sn_key();

  bool print_sn_status(std::vector<std::string> args);

  bool print_sr(uint64_t height);

  bool prepare_registration();

  bool print_sn(const std::vector<std::string> &args);

  bool prune_blockchain();

  bool check_blockchain_pruning();

  bool print_net_stats();

  bool set_bootstrap_daemon(
    const std::string &address,
    const std::string &username,
    const std::string &password);

  bool flush_cache(bool bad_txs, bool invalid_blocks);

  bool version();

  bool test_trigger_uptime_proof();
};

} // namespace daemonize
