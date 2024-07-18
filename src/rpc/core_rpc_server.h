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

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <memory>
#include <variant>

#include "core_rpc_server_binary_commands.h"
#include "core_rpc_server_commands_defs.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "p2p/net_node.h"
#include "rpc/common/rpc_command.h"

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "daemon.rpc"

namespace boost::program_options {
class options_description;
class variables_map;
}  // namespace boost::program_options

namespace cryptonote::rpc {

// FIXME: temporary shim for converting RPC methods
template <typename T, typename = void>
struct FIXME_has_nested_response : std::false_type {};
template <typename RPC>
struct FIXME_has_nested_response<RPC, std::void_t<typename RPC::response>> : std::true_type {};
template <typename T>
constexpr bool FIXME_has_nested_response_v = FIXME_has_nested_response<T>::value;

class core_rpc_server;

/// Stores an RPC command callback.  These are set up in core_rpc_server.cpp.
struct rpc_command {
    using result_type = std::variant<oxenc::bt_value, nlohmann::json, std::string>;
    // Called with the incoming command data; returns the response body if all goes well,
    // otherwise throws an exception.
    result_type (*invoke)(rpc_request&&, core_rpc_server&);
    bool is_public;  // callable via restricted RPC
    bool is_binary;  // only callable at /name (for HTTP RPC), and binary data, not JSON.
    bool is_legacy;  // callable at /name (for HTTP RPC), even though it is JSON (for backwards
                     // compat).
};

/// RPC command registration; to add a new command, define it in core_rpc_server_commands_defs.h
/// and then actually do the registration in core_rpc_server.cpp.
extern const std::unordered_map<std::string, std::shared_ptr<const rpc_command>> rpc_commands;

// Function used for getting an output distribution; this is non-static because we need to get at
// it from the test suite, but should be considered internal.
namespace detail {
    std::optional<output_distribution_data> get_output_distribution(
            const std::function<bool(
                    uint64_t, uint64_t, uint64_t, uint64_t&, std::vector<uint64_t>&, uint64_t&)>& f,
            uint64_t amount,
            uint64_t from_height,
            uint64_t to_height,
            const std::function<crypto::hash(uint64_t)>& get_hash,
            bool cumulative,
            uint64_t blockchain_height);
}

/**
 * Core RPC server.
 *
 * This class handles all internal core RPC requests, but does not itself listen for anything
 * external.  It is meant to be used by other RPC server bridge classes (such as rpc::http_server)
 * to map incoming HTTP requests into internal core RPC requests through this class, and then send
 * them back to the requester.
 *
 * In order to add a new RPC request object you must:
 *
 * - add the appropriate NEWTYPE struct with request/response substructs to
 *   core_rpc_server_commands_defs.h; the base types it inherits from determine the permissions
 *   and data type, and a static `names()` method determined the rpc name (and any older aliases).
 * - add an invoke() method overload declaration here which takes a NEWTYPE::request and
 * rpc_context, and returns a NEWTYPE::response.
 * - add the invoke() definition in core_rpc_server.cpp, and add NEWTYPE to the list of command
 *   types near the top of core_rpc_server.cpp.
 */
class core_rpc_server {
  public:
    core_rpc_server(
            core& cr,
            nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>>&
                    p2p);

    static void init_options(
            boost::program_options::options_description& desc,
            boost::program_options::options_description& hidden);

    /// Returns a reference to the owning cryptonote core object
    core& get_core() { return m_core; }
    const core& get_core() const { return m_core; }

    network_type nettype() const { return m_core.get_nettype(); }

    // JSON & bt-encoded RPC endpoints
    void invoke(ONS_RESOLVE& resolve, rpc_context context);
    void invoke(GET_HEIGHT& req, rpc_context context);
    void invoke(GET_INFO& info, rpc_context context);
    void invoke(GET_NET_STATS& get_net_stats, rpc_context context);
    void invoke(GET_OUTPUTS& get_outputs, rpc_context context);
    void invoke(HARD_FORK_INFO& hfinfo, rpc_context context);
    void invoke(START_MINING& start_mining, rpc_context context);
    void invoke(STOP_MINING& stop_mining, rpc_context context);
    void invoke(SAVE_BC& save_bc, rpc_context context);
    void invoke(STOP_DAEMON& stop_daemon, rpc_context context);
    void invoke(GET_BLOCK_COUNT& getblockcount, rpc_context context);
    void invoke(MINING_STATUS& mining_status, rpc_context context);
    void invoke(GET_TRANSACTION_POOL_HASHES& get_transaction_pool_hashes, rpc_context context);
    void invoke(GET_TRANSACTION_POOL_STATS& get_transaction_pool_stats, rpc_context context);
    void invoke(GET_TRANSACTIONS& req, rpc_context context);
    void invoke(GET_CONNECTIONS& get_connections, rpc_context context);
    void invoke(SYNC_INFO& sync, rpc_context context);
    void invoke(GET_SERVICE_NODE_STATUS& sns, rpc_context context);
    void invoke(GET_SERVICE_NODES& sns, rpc_context context);
    void invoke(GET_LIMIT& limit, rpc_context context);
    void invoke(SET_LIMIT& limit, rpc_context context);
    void invoke(IS_KEY_IMAGE_SPENT& spent, rpc_context context);
    void invoke(SUBMIT_TRANSACTION& tx, rpc_context context);
    void invoke(GET_BLOCK_HASH& req, rpc_context context);
    void invoke(GET_PEER_LIST& pl, rpc_context context);
    void invoke(SET_LOG_LEVEL& set_log_level, rpc_context context);
    void invoke(BANNED& banned, rpc_context context);
    void invoke(FLUSH_TRANSACTION_POOL& flush_transaction_pool, rpc_context context);
    void invoke(GET_VERSION& version, rpc_context context);
    void invoke(GET_COINBASE_TX_SUM& get_coinbase_tx_sum, rpc_context context);
    void invoke(GET_FEE_ESTIMATE& get_fee_estimate, rpc_context context);
    void invoke(OUT_PEERS& out_peers, rpc_context context);
    void invoke(IN_PEERS& in_peers, rpc_context context);
    void invoke(POP_BLOCKS& pop_blocks, rpc_context context);
    void invoke(LOKINET_PING& lokinet_ping, rpc_context context);
    void invoke(STORAGE_SERVER_PING& storage_server_ping, rpc_context context);
    void invoke(PRUNE_BLOCKCHAIN& prune_blockchain, rpc_context context);
    void invoke(GET_SN_STATE_CHANGES& get_sn_state_changes, rpc_context context);
    void invoke(TEST_TRIGGER_P2P_RESYNC& test_trigger_p2p_resync, rpc_context context);
    void invoke(TEST_TRIGGER_UPTIME_PROOF& test_trigger_uptime_proof, rpc_context context);
    void invoke(REPORT_PEER_STATUS& report_peer_status, rpc_context context);
    void invoke(FLUSH_CACHE& flush_cache, rpc_context context);
    void invoke(GET_LAST_BLOCK_HEADER& get_last_block_header, rpc_context context);
    void invoke(GET_BLOCK_HEADER_BY_HASH& get_block_header_by_hash, rpc_context context);
    void invoke(GET_BANS& get_bans, rpc_context context);
    void invoke(SET_BANS& set_bans, rpc_context context);
    void invoke(GET_CHECKPOINTS& get_checkpoints, rpc_context context);
    void invoke(GET_STAKING_REQUIREMENT& get_staking_requirement, rpc_context context);
    void invoke(GET_SERVICE_KEYS& get_service_keys, rpc_context context);
    void invoke(GET_SERVICE_PRIVKEYS& get_service_privkeys, rpc_context context);
    void invoke(
            GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES& get_service_node_blacklisted_key_images,
            rpc_context context);
    void invoke(BLS_REWARDS_REQUEST& bls_rewards_request, rpc_context context);
    void invoke(BLS_EXIT_REQUEST& bls_withdrawal_request, rpc_context context);
    void invoke(BLS_LIQUIDATION_REQUEST& bls_withdrawal_request, rpc_context context);
    void invoke(BLS_REGISTRATION& bls_registration_request, rpc_context context);
    void invoke(RELAY_TX& relay_tx, rpc_context context);
    void invoke(GET_BLOCK_HEADERS_RANGE& get_block_headers_range, rpc_context context);
    void invoke(GET_BLOCK_HEADER_BY_HEIGHT& get_block_header_by_height, rpc_context context);
    void invoke(GET_BLOCK& get_block, rpc_context context);
    void invoke(
            GET_SERVICE_NODE_REGISTRATION_CMD& get_service_node_registration_cmd,
            rpc_context context);
    void invoke(
            GET_SERVICE_NODE_REGISTRATION_CMD_RAW& get_service_node_registration_cmd_raw,
            rpc_context context);
    void invoke(GET_QUORUM_STATE& get_quorum_state, rpc_context context);
    void invoke(GET_ALTERNATE_CHAINS& get_alternate_chains, rpc_context context);
    void invoke(GET_OUTPUT_HISTOGRAM& get_output_histogram, rpc_context context);
    void invoke(ONS_OWNERS_TO_NAMES& ons_owners_to_names, rpc_context context);
    void invoke(GET_ACCRUED_REWARDS& rpc, rpc_context context);
    void invoke(ONS_NAMES_TO_OWNERS& ons_names_to_owners, rpc_context context);

    // Deprecated Monero NIH binary endpoints:
    GET_ALT_BLOCKS_HASHES_BIN::response invoke(
            GET_ALT_BLOCKS_HASHES_BIN::request&& req, rpc_context context);
    GET_BLOCKS_BIN::response invoke(GET_BLOCKS_BIN::request&& req, rpc_context context);
    GET_BLOCKS_BY_HEIGHT_BIN::response invoke(
            GET_BLOCKS_BY_HEIGHT_BIN::request&& req, rpc_context context);
    GET_HASHES_BIN::response invoke(GET_HASHES_BIN::request&& req, rpc_context context);
    GET_OUTPUT_BLACKLIST_BIN::response invoke(
            GET_OUTPUT_BLACKLIST_BIN::request&& req, rpc_context context);
    GET_OUTPUT_DISTRIBUTION_BIN::response invoke(
            GET_OUTPUT_DISTRIBUTION_BIN::request&& req, rpc_context context);
    GET_OUTPUTS_BIN::response invoke(GET_OUTPUTS_BIN::request&& req, rpc_context context);
    GET_TRANSACTION_POOL_HASHES_BIN::response invoke(
            GET_TRANSACTION_POOL_HASHES_BIN::request&& req, rpc_context context);
    GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN::response invoke(
            GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN::request&& req, rpc_context context);
    GET_OUTPUT_DISTRIBUTION::response invoke(
            GET_OUTPUT_DISTRIBUTION::request&& req, rpc_context context, bool binary = false);

  private:
    bool check_core_ready();

    void fill_sn_response_entry(
            nlohmann::json& entry,
            bool is_bt,
            const std::unordered_set<std::string>& requested,
            const service_nodes::service_node_pubkey_info& sn_info,
            uint64_t top_height);

    // utils
    uint64_t get_block_reward(const block& blk);
    void fill_block_header_response(
            const block& blk,
            bool orphan_status,
            uint64_t height,
            const crypto::hash& hash,
            block_header_response& response,
            bool fill_pow_hash,
            bool get_tx_hashes);

    core& m_core;
    nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>>& m_p2p;
};

}  // namespace cryptonote::rpc

BOOST_CLASS_VERSION(
        nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>>, 1);
