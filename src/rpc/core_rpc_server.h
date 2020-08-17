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

#include <variant>
#include <memory>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>

#include "bootstrap_daemon.h"
#include "core_rpc_server_commands_defs.h"
#include "cryptonote_core/cryptonote_core.h"
#include "p2p/net_node.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"

#if defined(LOKI_ENABLE_INTEGRATION_TEST_HOOKS)
#include "common/loki_integration_test_hooks.h"
#endif

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "daemon.rpc"

namespace boost { namespace program_options {
class options_description;
class variables_map;
}}

namespace cryptonote { namespace rpc {

  /// Exception when trying to invoke an RPC command that indicate a parameter parse failure (will
  /// give an invalid params error for JSON-RPC, for example).
  struct parse_error : std::runtime_error { using std::runtime_error::runtime_error; };

  /// Exception used to signal various types of errors with a request back to the caller.  This
  /// exception indicates that the caller did something wrong: bad data, invalid value, etc., but
  /// don't indicate a local problem (and so we'll log them only at debug).  For more serious,
  /// internal errors a command should throw some other stl error (e.g. std::runtime_error or
  /// perhaps std::logic_error), which will result in a local daemon warning (and a generic internal
  /// error response to the user).
  ///
  /// For JSON RPC these become an error response with the code as the error.code value and the
  /// string as the error.message.
  /// For HTTP JSON these become a 500 Internal Server Error response with the message as the body.
  /// For LokiMQ the code becomes the first part of the response and the message becomes the
  /// second part of the response.
  struct rpc_error : std::runtime_error {
    /// \param code - a signed, 16-bit numeric code.  0 must not be used (as it is used for a
    /// success code in LokiMQ), and values in the -32xxx range are reserved by JSON-RPC.
    ///
    /// \param message - a message to send along with the error code (see general description above).
    rpc_error(int16_t code, std::string message)
      : std::runtime_error{"RPC error " + std::to_string(code) + ": " + message},
        code{code}, message{std::move(message)} {}

    int16_t code;
    std::string message;
  };

  /// Junk that epee makes us deal with to pass in a generically parsed json value
  using jsonrpc_params = std::pair<epee::serialization::portable_storage, epee::serialization::storage_entry>;

  enum struct rpc_source : uint8_t { internal, http, lmq };

  /// Contains the context of the invocation, which must be filled out by the glue code (e.g. HTTP
  /// RPC server) with requester-specific context details.
  struct rpc_context {
    // Specifies that the requestor has admin permissions (e.g. is on an unrestricted RPC port, or
    // is a local internal request).  This can be used to provide different results for an admin
    // versus non-admin when invoking a public RPC command.  (Note that non-public RPC commands do
    // not need to check this field for authentication: a non-public invoke() is not called in the
    // first place if attempted by a public requestor).
    bool admin = false;

    // The RPC engine source of the request, i.e. internal, HTTP, LMQ
    rpc_source source = rpc_source::internal;

    // A free-form identifier (meant for humans) identifiying the remote address of the request;
    // this might be IP:PORT, or could contain a pubkey, or ...
    std::string remote;
  };

  struct rpc_request {
    // The request body; for a non-HTTP-JSON-RPC request the string or string_view will be populated
    // with the unparsed request body (though may be empty, e.g. for GET requests).  For HTTP
    // JSON-RPC request, if the request has a "params" value then the epee storage pair will be set
    // to the portable_storage entry and the storage entry containing "params".  If "params" is
    // omitted entirely (or, for LMQ, there is no data part) then the string will be set in the
    // variant (and empty).
    //
    // The returned value in either case is the serialized value to return.
    //
    // If sometimes goes wrong, throw.
    std::variant<std::string_view, std::string, jsonrpc_params> body;

    // Returns a string_view of the body, if the body is a string or string_view.  Returns
    // std::nullopt if the body is a jsonrpc_params.
    std::optional<std::string_view> body_view() const;

    // Values to pass through to the invoke() call
    rpc_context context;
  };

  class core_rpc_server;

  /// Stores an RPC command callback.  These are set up in core_rpc_server.cpp.
  struct rpc_command {
    // Called with the incoming command data; returns the response body if all goes well,
    // otherwise throws an exception.
    std::string(*invoke)(rpc_request&&, core_rpc_server&);
    bool is_public; // callable via restricted RPC
    bool is_binary; // only callable at /name (for HTTP RPC), and binary data, not JSON.
    bool is_legacy; // callable at /name (for HTTP RPC), even though it is JSON (for backwards compat).
  };

  /// RPC command registration; to add a new command, define it in core_rpc_server_commands_defs.h
  /// and then actually do the registration in core_rpc_server.cpp.
  extern const std::unordered_map<std::string, std::shared_ptr<const rpc_command>> rpc_commands;


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
   * - add an invoke() method overload declaration here which takes a NEWTYPE::request and rpc_context,
   *   and returns a NEWTYPE::response.
   * - add the invoke() definition in core_rpc_server.cpp, and add NEWTYPE to the list of command
   *   types near the top of core_rpc_server.cpp.
   */
  class core_rpc_server
  {
  public:
    static const command_line::arg_descriptor<std::string> arg_bootstrap_daemon_address;
    static const command_line::arg_descriptor<std::string> arg_bootstrap_daemon_login;

    core_rpc_server(
        core& cr
      , nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& p2p
      );

    static void init_options(boost::program_options::options_description& desc, boost::program_options::options_description& hidden);
    void init(const boost::program_options::variables_map& vm);

    /// Returns a reference to the owning cryptonote core object
    core& get_core() { return m_core; }
    const core& get_core() const { return m_core; }

    network_type nettype() const { return m_core.get_nettype(); }

    GET_HEIGHT::response                                invoke(GET_HEIGHT::request&& req, rpc_context context);
    GET_BLOCKS_FAST::response                           invoke(GET_BLOCKS_FAST::request&& req, rpc_context context);
    GET_ALT_BLOCKS_HASHES::response                     invoke(GET_ALT_BLOCKS_HASHES::request&& req, rpc_context context);
    GET_BLOCKS_BY_HEIGHT::response                      invoke(GET_BLOCKS_BY_HEIGHT::request&& req, rpc_context context);
    GET_HASHES_FAST::response                           invoke(GET_HASHES_FAST::request&& req, rpc_context context);
    GET_TRANSACTIONS::response                          invoke(GET_TRANSACTIONS::request&& req, rpc_context context);
    IS_KEY_IMAGE_SPENT::response                        invoke(IS_KEY_IMAGE_SPENT::request&& req, rpc_context context);
    GET_TX_GLOBAL_OUTPUTS_INDEXES::response             invoke(GET_TX_GLOBAL_OUTPUTS_INDEXES::request&& req, rpc_context context);
    SEND_RAW_TX::response                               invoke(SEND_RAW_TX::request&& req, rpc_context context);
    START_MINING::response                              invoke(START_MINING::request&& req, rpc_context context);
    STOP_MINING::response                               invoke(STOP_MINING::request&& req, rpc_context context);
    MINING_STATUS::response                             invoke(MINING_STATUS::request&& req, rpc_context context);
    GET_OUTPUTS_BIN::response                           invoke(GET_OUTPUTS_BIN::request&& req, rpc_context context);
    GET_OUTPUTS::response                               invoke(GET_OUTPUTS::request&& req, rpc_context context);
    GET_INFO::response                                  invoke(GET_INFO::request&& req, rpc_context context);
    GET_NET_STATS::response                             invoke(GET_NET_STATS::request&& req, rpc_context context);
    SAVE_BC::response                                   invoke(SAVE_BC::request&& req, rpc_context context);
    GET_PEER_LIST::response                             invoke(GET_PEER_LIST::request&& req, rpc_context context);
    GET_PUBLIC_NODES::response                          invoke(GET_PUBLIC_NODES::request&& req, rpc_context context);
    SET_LOG_HASH_RATE::response                         invoke(SET_LOG_HASH_RATE::request&& req, rpc_context context);
    SET_LOG_LEVEL::response                             invoke(SET_LOG_LEVEL::request&& req, rpc_context context);
    SET_LOG_CATEGORIES::response                        invoke(SET_LOG_CATEGORIES::request&& req, rpc_context context);
    GET_TRANSACTION_POOL::response                      invoke(GET_TRANSACTION_POOL::request&& req, rpc_context context);
    GET_TRANSACTION_POOL_HASHES_BIN::response           invoke(GET_TRANSACTION_POOL_HASHES_BIN::request&& req, rpc_context context);
    GET_TRANSACTION_POOL_HASHES::response               invoke(GET_TRANSACTION_POOL_HASHES::request&& req, rpc_context context);
    GET_TRANSACTION_POOL_STATS::response                invoke(GET_TRANSACTION_POOL_STATS::request&& req, rpc_context context);
    SET_BOOTSTRAP_DAEMON::response                      invoke(SET_BOOTSTRAP_DAEMON::request&& req, rpc_context context);
    STOP_DAEMON::response                               invoke(STOP_DAEMON::request&& req, rpc_context context);
    GET_LIMIT::response                                 invoke(GET_LIMIT::request&& req, rpc_context context);
    SET_LIMIT::response                                 invoke(SET_LIMIT::request&& req, rpc_context context);
    OUT_PEERS::response                                 invoke(OUT_PEERS::request&& req, rpc_context context);
    IN_PEERS::response                                  invoke(IN_PEERS::request&& req, rpc_context context);
    GET_OUTPUT_DISTRIBUTION::response                   invoke(GET_OUTPUT_DISTRIBUTION::request&& req, rpc_context context, bool binary = false);
    GET_OUTPUT_DISTRIBUTION_BIN::response               invoke(GET_OUTPUT_DISTRIBUTION_BIN::request&& req, rpc_context context);
    POP_BLOCKS::response                                invoke(POP_BLOCKS::request&& req, rpc_context context);
    GETBLOCKCOUNT::response                             invoke(GETBLOCKCOUNT::request&& req, rpc_context context);
    GETBLOCKHASH::response                              invoke(GETBLOCKHASH::request&& req, rpc_context context);
    GETBLOCKTEMPLATE::response                          invoke(GETBLOCKTEMPLATE::request&& req, rpc_context context);
    SUBMITBLOCK::response                               invoke(SUBMITBLOCK::request&& req, rpc_context context);
    GENERATEBLOCKS::response                            invoke(GENERATEBLOCKS::request&& req, rpc_context context);
    GET_LAST_BLOCK_HEADER::response                     invoke(GET_LAST_BLOCK_HEADER::request&& req, rpc_context context);
    GET_BLOCK_HEADER_BY_HASH::response                  invoke(GET_BLOCK_HEADER_BY_HASH::request&& req, rpc_context context);
    GET_BLOCK_HEADER_BY_HEIGHT::response                invoke(GET_BLOCK_HEADER_BY_HEIGHT::request&& req, rpc_context context);
    GET_BLOCK_HEADERS_RANGE::response                   invoke(GET_BLOCK_HEADERS_RANGE::request&& req, rpc_context context);
    GET_BLOCK::response                                 invoke(GET_BLOCK::request&& req, rpc_context context);
    GET_CONNECTIONS::response                           invoke(GET_CONNECTIONS::request&& req, rpc_context context);
    HARD_FORK_INFO::response                            invoke(HARD_FORK_INFO::request&& req, rpc_context context);
    SETBANS::response                                   invoke(SETBANS::request&& req, rpc_context context);
    GETBANS::response                                   invoke(GETBANS::request&& req, rpc_context context);
    BANNED::response                                    invoke(BANNED::request&& req, rpc_context context);
    FLUSH_TRANSACTION_POOL::response                    invoke(FLUSH_TRANSACTION_POOL::request&& req, rpc_context context);
    GET_OUTPUT_HISTOGRAM::response                      invoke(GET_OUTPUT_HISTOGRAM::request&& req, rpc_context context);
    GET_VERSION::response                               invoke(GET_VERSION::request&& req, rpc_context context);
    GET_COINBASE_TX_SUM::response                       invoke(GET_COINBASE_TX_SUM::request&& req, rpc_context context);
    GET_BASE_FEE_ESTIMATE::response                     invoke(GET_BASE_FEE_ESTIMATE::request&& req, rpc_context context);
    GET_ALTERNATE_CHAINS::response                      invoke(GET_ALTERNATE_CHAINS::request&& req, rpc_context context);
    RELAY_TX::response                                  invoke(RELAY_TX::request&& req, rpc_context context);
    SYNC_INFO::response                                 invoke(SYNC_INFO::request&& req, rpc_context context);
    GET_TRANSACTION_POOL_BACKLOG::response              invoke(GET_TRANSACTION_POOL_BACKLOG::request&& req, rpc_context context);
    PRUNE_BLOCKCHAIN::response                          invoke(PRUNE_BLOCKCHAIN::request&& req, rpc_context context);
    GET_OUTPUT_BLACKLIST::response                      invoke(GET_OUTPUT_BLACKLIST::request&& req, rpc_context context);
    GET_QUORUM_STATE::response                          invoke(GET_QUORUM_STATE::request&& req, rpc_context context);
    GET_SERVICE_NODE_REGISTRATION_CMD_RAW::response     invoke(GET_SERVICE_NODE_REGISTRATION_CMD_RAW::request&& req, rpc_context context);
    GET_SERVICE_NODE_REGISTRATION_CMD::response         invoke(GET_SERVICE_NODE_REGISTRATION_CMD::request&& req, rpc_context context);
    GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES::response   invoke(GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES::request&& req, rpc_context context);
    GET_SERVICE_KEYS::response                          invoke(GET_SERVICE_KEYS::request&& req, rpc_context context);
    GET_SERVICE_PRIVKEYS::response                      invoke(GET_SERVICE_PRIVKEYS::request&& req, rpc_context context);
    GET_SERVICE_NODE_STATUS::response                   invoke(GET_SERVICE_NODE_STATUS::request&& req, rpc_context context);
    GET_SERVICE_NODES::response                         invoke(GET_SERVICE_NODES::request&& req, rpc_context context);
    GET_STAKING_REQUIREMENT::response                   invoke(GET_STAKING_REQUIREMENT::request&& req, rpc_context context);
    PERFORM_BLOCKCHAIN_TEST::response                   invoke(PERFORM_BLOCKCHAIN_TEST::request&& req, rpc_context context);
    STORAGE_SERVER_PING::response                       invoke(STORAGE_SERVER_PING::request&& req, rpc_context context);
    LOKINET_PING::response                              invoke(LOKINET_PING::request&& req, rpc_context context);
    GET_CHECKPOINTS::response                           invoke(GET_CHECKPOINTS::request&& req, rpc_context context);
    GET_SN_STATE_CHANGES::response                      invoke(GET_SN_STATE_CHANGES::request&& req, rpc_context context);
    REPORT_PEER_SS_STATUS::response                     invoke(REPORT_PEER_SS_STATUS::request&& req, rpc_context context);
    TEST_TRIGGER_P2P_RESYNC::response                   invoke(TEST_TRIGGER_P2P_RESYNC::request&& req, rpc_context context);
    TEST_TRIGGER_UPTIME_PROOF::response                 invoke(TEST_TRIGGER_UPTIME_PROOF::request&& req, rpc_context context);
    LNS_NAMES_TO_OWNERS::response                       invoke(LNS_NAMES_TO_OWNERS::request&& req, rpc_context context);
    LNS_OWNERS_TO_NAMES::response                       invoke(LNS_OWNERS_TO_NAMES::request&& req, rpc_context context);
    FLUSH_CACHE::response                               invoke(FLUSH_CACHE::request&& req, rpc_context);

#if defined(LOKI_ENABLE_INTEGRATION_TEST_HOOKS)
    void on_relay_uptime_and_votes()
    {
      m_core.submit_uptime_proof();
      m_core.relay_service_node_votes();
      std::cout << "Votes and uptime relayed";
      integration_test::write_buffered_stdout();
    }

    void on_debug_mine_n_blocks(std::string const &address, uint64_t num_blocks)
    {
      cryptonote::miner &miner = m_core.get_miner();
      if (miner.is_mining())
      {
        std::cout << "Already mining";
        return;
      }

      cryptonote::address_parse_info info;
      if(!get_account_address_from_str(info, m_core.get_nettype(), address))
      {
        std::cout << "Failed, wrong address";
        return;
      }

      uint64_t height = m_core.get_current_blockchain_height();
      if (!miner.start(info.address, 1, num_blocks))
      {
        std::cout << "Failed, mining not started";
        return;
      }

      while (m_core.get_current_blockchain_height() != (height + num_blocks))
        std::this_thread::sleep_for(500ms);
      std::cout << "Mining stopped in daemon";
    }
#endif

private:
    bool check_core_ready();

    void fill_sn_response_entry(GET_SERVICE_NODES::response::entry& entry, const service_nodes::service_node_pubkey_info &sn_info, uint64_t current_height);

    //utils
    uint64_t get_block_reward(const block& blk);
    std::optional<std::string> get_random_public_node();
    bool set_bootstrap_daemon(const std::string &address, std::string_view username_password);
    bool set_bootstrap_daemon(const std::string &address, std::string_view username, std::string_view password);
    void fill_block_header_response(const block& blk, bool orphan_status, uint64_t height, const crypto::hash& hash, block_header_response& response, bool fill_pow_hash, bool get_tx_hashes);
    std::unique_lock<std::shared_mutex> should_bootstrap_lock();

    template <typename COMMAND_TYPE>
    bool use_bootstrap_daemon_if_necessary(const typename COMMAND_TYPE::request& req, typename COMMAND_TYPE::response& res);
    
    core& m_core;
    nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >& m_p2p;
    std::shared_mutex m_bootstrap_daemon_mutex;
    std::atomic<bool> m_should_use_bootstrap_daemon;
    std::unique_ptr<bootstrap_daemon> m_bootstrap_daemon;
    std::chrono::system_clock::time_point m_bootstrap_height_check_time;
    bool m_was_bootstrap_ever_used;
  };

}} // namespace cryptonote::rpc

BOOST_CLASS_VERSION(nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core> >, 1);
