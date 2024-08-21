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

#include <concepts>
#include <exception>
#include <optional>

#include "common/common_fwd.h"
#include "common/exception.h"
#include "common/scoped_message_writer.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "rpc/common/command_decorators.h"
#include "rpc/core_rpc_server.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "rpc/http_client.h"

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize {

class rpc_command_executor final {
  private:
    std::variant<cryptonote::rpc::http_client, oxenmq::ConnectionID> m_rpc;
    oxenmq::OxenMQ* m_omq = nullptr;

  public:
    /// Executor for HTTP remote connection RPC
    rpc_command_executor(std::string http_url, const std::optional<tools::login>& user);

    /// Executor for OMQ RPC, either local (inproc) or remote.
    rpc_command_executor(oxenmq::OxenMQ& omq, oxenmq::ConnectionID conn);

    /// FIXME: remove this!
    ///
    /// Runs some RPC command either via json_rpc or a direct core rpc call.
    ///
    /// @param req the request object (rvalue reference)
    /// @param error print this (and, on exception, the exception message) on failure.  If empty
    /// then nothing is printed on failure.
    /// @param check_status_ok whether we require res.status == STATUS_OK to consider the request
    /// successful
    template <std::derived_from<cryptonote::rpc::RPC_COMMAND> RPC>
        requires cryptonote::rpc::FIXME_has_nested_response_v<RPC>
    bool invoke(
            typename RPC::request&& req,
            typename RPC::response& res,
            const std::string& error,
            bool check_status_ok = true) {
        try {
            if (auto* rpc_client = std::get_if<cryptonote::rpc::http_client>(&m_rpc)) {
                res = rpc_client->json_rpc<RPC>(RPC::names()[0], req);
            } else {
                throw oxen::traced<std::runtime_error>{"fixme"};
            }
            if (!check_status_ok || res.status == cryptonote::rpc::STATUS_OK)
                return true;
        } catch (const std::exception& e) {
            if (!error.empty())
                tools::fail_msg_writer("{}: {}", error, e.what());
            return false;
        } catch (...) {
        }
        if (!error.empty())
            tools::fail_msg_writer("{}", error);
        return false;
    }

    /// Runs some RPC command either via json_rpc or an internal rpc call.  Returns nlohmann::json
    /// results on success, throws on failure.
    ///
    /// Note that for a json_rpc request this is the "result" value inside the json_rpc wrapper, not
    /// the wrapper itself.
    ///
    /// This is the low-level implementing method for `invoke<SOMERPC>(...)`.
    ///
    /// @param method the method name, typically `SOMERPC::names()[0]`
    /// @param public_method true if this is a public rpc request; this is used, in particular, to
    /// decide whether "rpc." or "admin." should be prefixed if this goes through OMQ RPC.
    /// @param params the "params" field for the request.  Can be nullopt to pass no "params".
    /// @param check_status_ok whether we require the result to have a "status" key set to STATUS_OK
    /// to consider the request successful.  Note that this defaults to *false* if this is called
    /// directly, unlike the RPC-type-templated version, below.
    nlohmann::json invoke(
            std::string_view method,
            bool public_method,
            std::optional<nlohmann::json> params,
            bool check_status_ok = false);

    /// Runs some RPC command either via json_rpc or an internal rpc call.  Returns nlohmann::json
    /// results on success, throws on failure.
    ///
    /// @tparam RPC the rpc type class
    /// @param params the "params" value to pass to json_rpc, or std::nullopt to omit it
    /// @param check_status_ok whether we require the result to have a "status" key set to STATUS_OK
    /// to consider the request successful
    template <std::derived_from<cryptonote::rpc::RPC_COMMAND> RPC>
        requires(!cryptonote::rpc::FIXME_has_nested_response_v<RPC>)
    nlohmann::json invoke(
            std::optional<nlohmann::json> params = std::nullopt, bool check_status_ok = true) {
        return invoke(
                RPC::names()[0],
                std::is_base_of_v<cryptonote::rpc::PUBLIC, RPC>,
                std::move(params),
                check_status_ok);
    }

    // Invokes a simple RPC method that doesn't take any arguments and for which we don't care about
    // the return value beyond the "status": "OK" field.  Returns true (and prints a success
    // message) on success, false (with a failure message printed) on failure.
    template <std::derived_from<cryptonote::rpc::RPC_COMMAND> RPC>
        requires(!cryptonote::rpc::FIXME_has_nested_response_v<RPC>)
    bool invoke_simple(std::string_view error_prefix, std::string_view success_msg) {
        if (!try_running([this] { return invoke<RPC>(); }, error_prefix))
            return false;

        tools::success_msg_writer() + success_msg;
        return true;
    }

    template <typename Response>
    nlohmann::json make_request(nlohmann::json params) {
        return invoke<Response>(params)["response"];
    }

    bool print_checkpoints(
            std::optional<uint64_t> start_height,
            std::optional<uint64_t> end_height,
            bool print_json);

    bool print_sn_state_changes(uint64_t start_height, std::optional<uint64_t> end_height);

    bool print_peer_list(
            bool white = true, bool gray = true, size_t limit = 0, bool pruned_only = false);

    bool print_peer_list_stats();

    bool save_blockchain();

    bool show_difficulty();

    bool show_status();

    bool print_connections();

    bool print_blockchain_info(int64_t start_block_index, uint64_t end_block_index);

    bool print_quorum_state(
            std::optional<uint64_t> start_height, std::optional<uint64_t> end_height);

    bool set_log_level(std::string categories);

    bool print_height();

  public:
    bool print_block_by_hash(const crypto::hash& block_hash, bool include_hex);

    bool print_block_by_height(uint64_t height, bool include_hex);

    bool print_transaction(
            const crypto::hash& transaction_hash,
            bool include_metadata,
            bool include_hex,
            bool include_json);

    bool is_key_image_spent(const std::vector<crypto::key_image>& ki);

    bool print_transaction_pool(bool long_format);

    bool print_transaction_pool_stats();

    bool start_mining(std::string address, int num_threads, int num_blocks);

    bool stop_mining();

    bool mining_status();

    bool stop_daemon();

    bool get_limit();

    bool set_limit(int64_t limit_down, int64_t limit_up);

    bool out_peers(bool set, uint32_t limit);

    bool in_peers(bool set, uint32_t limit);

    bool print_bans();

    bool ban(const std::string& address, time_t seconds, bool clear_ban = false);

    bool unban(const std::string& address);

    bool banned(const std::string& address);

    bool flush_txpool(std::string txid);

    bool output_histogram(
            const std::vector<uint64_t>& amounts, uint64_t min_count, uint64_t max_count);

    bool print_coinbase_tx_sum(uint64_t height, uint64_t count);

    bool alt_chain_info(const std::string& tip, size_t above, uint64_t last_blocks);

    bool print_blockchain_dynamic_stats(uint64_t nblocks);

    bool relay_tx(const std::string& txid);

    bool sync_info();

    bool pop_blocks(uint64_t num_blocks);

    bool print_sn_key();

    bool print_sn_status(std::vector<std::string> args);

    bool print_sr(uint64_t height);

    bool prepare_registration(bool force_registration = false);

    bool prepare_eth_registration(
            std::string_view operator_address,
            std::string_view contract_address,
            bool print = false);

    bool print_sn(const std::vector<std::string>& args, bool self = false);

    bool prune_blockchain();

    bool check_blockchain_pruning();

    bool print_net_stats();

    bool flush_cache(bool bad_txs, bool invalid_blocks);

    bool claim_rewards(const std::string& address);

    bool version();

    bool test_trigger_uptime_proof();
};

}  // namespace daemonize
