// Copyright (c) 2017-2019, The Monero Project
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

#pragma once

#include <chrono>
#include <string>
#include <mutex>
#include <type_traits>
#include "include_base_utils.h"
#include "rpc/http_client.h"
#include "rpc/core_rpc_server_commands_defs.h"

namespace tools
{

class NodeRPCProxy
{
public:
  explicit NodeRPCProxy(cryptonote::rpc::http_client& http_client);

  void invalidate();
  void set_offline(bool offline) { m_offline = offline; }

  bool get_rpc_version(cryptonote::rpc::version_t &version) const;
  bool get_height(uint64_t &height) const;
  void set_height(uint64_t h);
  bool get_target_height(uint64_t &height) const;
  bool get_immutable_height(uint64_t &height) const;
  bool get_block_weight_limit(uint64_t &block_weight_limit) const;
  bool get_earliest_height(uint8_t version, uint64_t &earliest_height) const;
  bool get_dynamic_base_fee_estimate(uint64_t grace_blocks, cryptonote::byte_and_output_fees &fees) const;
  bool get_fee_quantization_mask(uint64_t &fee_quantization_mask) const;
  std::optional<uint8_t> get_hardfork_version() const;

  std::pair<bool, std::vector<cryptonote::rpc::GET_SERVICE_NODES::response::entry>>             get_service_nodes(std::vector<std::string> pubkeys) const;
  std::pair<bool, std::vector<cryptonote::rpc::GET_SERVICE_NODES::response::entry>>             get_all_service_nodes() const;
  std::pair<bool, std::vector<cryptonote::rpc::GET_SERVICE_NODES::response::entry>>             get_contributed_service_nodes(const std::string& contributor) const;
  std::pair<bool, std::vector<cryptonote::rpc::GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES::entry>> get_service_node_blacklisted_key_images() const;
  std::pair<bool, std::vector<cryptonote::rpc::LNS_OWNERS_TO_NAMES::response_entry>>            lns_owners_to_names(cryptonote::rpc::LNS_OWNERS_TO_NAMES::request const &request) const;
  std::pair<bool, std::vector<cryptonote::rpc::LNS_NAMES_TO_OWNERS::response_entry>>            lns_names_to_owners(cryptonote::rpc::LNS_NAMES_TO_OWNERS::request const &request) const;

private:
  bool get_info() const;

  // Invokes an JSON RPC request and checks it for errors, include a check that the response
  // `.status` value is equal to rpc::STATUS_OK.  Returns the response on success, logs and throws
  // on error.
  template <typename RPC>
  typename RPC::response invoke_json_rpc(const typename RPC::request& req) const
  {
    typename RPC::response result;
    try {
      result = m_http_client.json_rpc<RPC>(RPC::names().front(), req);
    } catch (const std::exception& e) {
      MERROR(e.what());
      throw;
    }
    if (result.status != cryptonote::rpc::STATUS_OK) {
      std::string error = "Request for " + std::string{RPC::names().front()} + " failed: " + (result.status == cryptonote::rpc::STATUS_BUSY ? "daemon is busy" : result.status);
      MERROR(error);
      throw std::runtime_error{error};
    }

    return result;
  }

  // Makes a json rpc request with the given request value and (if successful) returns a
  // std::pair<bool, Value>.  Takes two arguments: the request, and a lambda that takes an rvalue
  // response and returns an value (typically moved via something like `return
  // std::move(response.whatever)`).
  template <typename RPC, typename GetValue,
           typename Value = decltype(std::declval<GetValue>()(typename RPC::response{}))>
  std::pair<bool, Value> get_result_pair(const typename RPC::request& req, GetValue get_value, uint64_t* check_height = nullptr) const
  {
    std::pair<bool, Value> result;
    auto& [success, value] = result;
    success = false;

    if (m_offline)
      return result;

    try {
      value = get_value(invoke_json_rpc<RPC>(req));
      success = true;
    } catch (...) {}

    return result;
  }

  cryptonote::rpc::http_client& m_http_client;
  bool m_offline;

  mutable uint64_t m_service_node_blacklisted_key_images_cached_height;
  mutable std::vector<cryptonote::rpc::GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES::entry> m_service_node_blacklisted_key_images;

  bool update_all_service_nodes_cache(uint64_t height) const;

  mutable std::mutex m_sn_cache_mutex;
  mutable uint64_t m_all_service_nodes_cached_height;
  mutable std::vector<cryptonote::rpc::GET_SERVICE_NODES::response::entry> m_all_service_nodes;

  mutable uint64_t m_contributed_service_nodes_cached_height;
  mutable std::string m_contributed_service_nodes_cached_address;
  mutable std::vector<cryptonote::rpc::GET_SERVICE_NODES::response::entry> m_contributed_service_nodes;

  mutable uint64_t m_height;
  mutable uint64_t m_immutable_height;
  mutable std::array<uint64_t, 256> m_earliest_height;
  mutable cryptonote::byte_and_output_fees m_dynamic_base_fee_estimate;
  mutable uint64_t m_dynamic_base_fee_estimate_cached_height;
  mutable uint64_t m_dynamic_base_fee_estimate_grace_blocks;
  mutable uint64_t m_fee_quantization_mask;
  bool refresh_dynamic_base_fee_cache(uint64_t grace_blocks) const;
  mutable cryptonote::rpc::version_t m_rpc_version;
  mutable uint64_t m_target_height;
  mutable uint64_t m_block_weight_limit;
  mutable std::chrono::steady_clock::time_point m_get_info_time;
  mutable std::chrono::steady_clock::time_point m_height_time;
};

}
