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

#include "node_rpc_proxy.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include <chrono>
#include <cpr/cpr.h>

namespace rpc = cryptonote::rpc;

using namespace std::literals;

namespace tools
{

static constexpr std::chrono::seconds rpc_timeout{30};

NodeRPCProxy::NodeRPCProxy(rpc::http_client& http_client)
  : m_http_client{http_client}
  , m_offline(false)
{
  invalidate();
}

void NodeRPCProxy::invalidate()
{
  m_service_node_blacklisted_key_images_cached_height = 0;
  m_service_node_blacklisted_key_images.clear();

  m_all_service_nodes_cached_height = 0;
  m_all_service_nodes.clear();

  m_contributed_service_nodes_cached_height = 0;
  m_contributed_service_nodes_cached_address.clear();
  m_contributed_service_nodes.clear();

  m_height = 0;
  m_immutable_height = 0;
  for (size_t n = 0; n < 256; ++n)
    m_earliest_height[n] = 0;
  m_dynamic_base_fee_estimate = {0, 0};
  m_dynamic_base_fee_estimate_cached_height = 0;
  m_dynamic_base_fee_estimate_grace_blocks = 0;
  m_fee_quantization_mask = 1;
  m_rpc_version = {0, 0};
  m_target_height = 0;
  m_block_weight_limit = 0;
  m_get_info_time = std::chrono::steady_clock::time_point::min();
  m_height_time = std::chrono::steady_clock::time_point::min();
}

bool NodeRPCProxy::get_rpc_version(rpc::version_t &rpc_version) const
{
  if (m_offline) return false;
  if (m_rpc_version == rpc::version_t{0, 0})
  {
    try {
      auto res = invoke_json_rpc<rpc::GET_VERSION>({});
      m_rpc_version = rpc::make_version(res.version);
    } catch (...) { return false; }
  }
  rpc_version = m_rpc_version;
  return true;
}

void NodeRPCProxy::set_height(uint64_t h)
{
  m_height = h;
  if (h < m_immutable_height)
      m_immutable_height = 0;
  m_height_time = std::chrono::steady_clock::now();
}

bool NodeRPCProxy::get_info() const
{
  if (m_offline) return false;
  auto now = std::chrono::steady_clock::now();
  if (now >= m_get_info_time + 30s) // re-cache every 30 seconds
  {
    try {
      auto resp_t = invoke_json_rpc<rpc::GET_INFO>({});

      m_height = resp_t.height;
      m_target_height = resp_t.target_height;
      m_block_weight_limit = resp_t.block_weight_limit ? resp_t.block_weight_limit : resp_t.block_size_limit;
      m_immutable_height = resp_t.immutable_height;
      m_get_info_time = now;
      m_height_time = now;
    } catch (...) { return false; }
  }
  return true;
}

bool NodeRPCProxy::get_height(uint64_t &height) const
{
  auto now = std::chrono::steady_clock::now();
  if (now >= m_height_time + 30s) // re-cache every 30 seconds
    if (!get_info())
      return false;

  height = m_height;
  return true;
}

bool NodeRPCProxy::get_target_height(uint64_t &height) const
{
  if (!get_info())
    return false;
  height = m_target_height;
  return true;
}

bool NodeRPCProxy::get_immutable_height(uint64_t &height) const
{
  if (!get_info())
    return false;
  height = m_immutable_height;
  return false;
}

bool NodeRPCProxy::get_block_weight_limit(uint64_t &block_weight_limit) const
{
  if (!get_info())
    return false;
  block_weight_limit = m_block_weight_limit;
  return true;
}

bool NodeRPCProxy::get_earliest_height(uint8_t version, uint64_t &earliest_height) const
{
  if (m_offline)
    return false;
  if (m_earliest_height[version] == 0)
  {
    rpc::HARD_FORK_INFO::request req_t{};
    req_t.version = version;
    try {
      auto resp_t = invoke_json_rpc<rpc::HARD_FORK_INFO>(req_t);
      m_earliest_height[version] = resp_t.earliest_height;
    } catch (...) { return false; }
  }

  earliest_height = m_earliest_height[version];
  return true;
}

std::optional<uint8_t> NodeRPCProxy::get_hardfork_version() const
{
  if (m_offline)
    return std::nullopt;

  try {
    return invoke_json_rpc<rpc::HARD_FORK_INFO>({}).version;
  } catch (...) {}

  return std::nullopt;
}

bool NodeRPCProxy::refresh_dynamic_base_fee_cache(uint64_t grace_blocks) const
{
  uint64_t height;
  if (m_offline || !get_height(height))
    return false;

  if (m_dynamic_base_fee_estimate_cached_height != height || m_dynamic_base_fee_estimate_grace_blocks != grace_blocks)
  {
    rpc::GET_BASE_FEE_ESTIMATE::request req_t{};
    req_t.grace_blocks = grace_blocks;
    try {
      auto resp_t = invoke_json_rpc<rpc::GET_BASE_FEE_ESTIMATE>(req_t);
      m_dynamic_base_fee_estimate = {resp_t.fee_per_byte, resp_t.fee_per_output};
      m_dynamic_base_fee_estimate_cached_height = height;
      m_dynamic_base_fee_estimate_grace_blocks = grace_blocks;
      m_fee_quantization_mask = resp_t.quantization_mask;
    } catch (...) { return false; }
  }
  return true;
}

bool NodeRPCProxy::get_dynamic_base_fee_estimate(uint64_t grace_blocks, cryptonote::byte_and_output_fees &fees) const
{
  if (!refresh_dynamic_base_fee_cache(grace_blocks))
    return false;
  fees = m_dynamic_base_fee_estimate;
  return true;
}

bool NodeRPCProxy::get_fee_quantization_mask(uint64_t &fee_quantization_mask) const
{
  if (!refresh_dynamic_base_fee_cache(m_dynamic_base_fee_estimate_grace_blocks))
    return false;

  fee_quantization_mask = m_fee_quantization_mask;
  if (fee_quantization_mask == 0)
  {
    MERROR("Fee quantization mask is 0, forcing to 1");
    fee_quantization_mask = 1;
  }
  return true;
}

std::pair<bool, std::vector<cryptonote::rpc::GET_SERVICE_NODES::response::entry>> NodeRPCProxy::get_service_nodes(std::vector<std::string> pubkeys) const
{
  rpc::GET_SERVICE_NODES::request req{};
  req.service_node_pubkeys = std::move(pubkeys);
  return get_result_pair<rpc::GET_SERVICE_NODES>(req, [](auto&& res) { return std::move(res.service_node_states); });
}

// Updates the cache of all service nodes; the mutex lock must be already held
bool NodeRPCProxy::update_all_service_nodes_cache(uint64_t height) const {
  if (m_offline)
    return false;

  try {
    auto res = invoke_json_rpc<rpc::GET_SERVICE_NODES>({});
    m_all_service_nodes_cached_height = height;
    m_all_service_nodes = std::move(res.service_node_states);
  } catch (...) { return false; }

  return true;
}


std::pair<bool, std::vector<cryptonote::rpc::GET_SERVICE_NODES::response::entry>> NodeRPCProxy::get_all_service_nodes() const
{
  std::pair<bool, std::vector<cryptonote::rpc::GET_SERVICE_NODES::response::entry>> result;
  auto& [success, sns] = result;
  success = false;

  uint64_t height{0};
  if (!get_height(height))
    return result;

  {
    std::lock_guard lock{m_sn_cache_mutex};
    if (m_all_service_nodes_cached_height != height && !update_all_service_nodes_cache(height))
      return result;

    sns = m_all_service_nodes;
  }

  success = true;
  return result;
}

// Filtered version of the above that caches the filtered result as long as used on the same
// contributor at the same height (which is very common, for example, for wallet balance lookups).
std::pair<bool, std::vector<cryptonote::rpc::GET_SERVICE_NODES::response::entry>> NodeRPCProxy::get_contributed_service_nodes(const std::string &contributor) const
{
  std::pair<bool, std::vector<cryptonote::rpc::GET_SERVICE_NODES::response::entry>> result;
  auto& [success, sns] = result;
  success = false;

  uint64_t height;
  if (m_offline || !get_height(height))
    return result;

  {
    std::lock_guard lock{m_sn_cache_mutex};
    if (m_contributed_service_nodes_cached_height != height || m_contributed_service_nodes_cached_address != contributor) {
      if (m_all_service_nodes_cached_height != height && !update_all_service_nodes_cache(height))
        return result;

      m_contributed_service_nodes.clear();
      std::copy_if(m_all_service_nodes.begin(), m_all_service_nodes.end(), std::back_inserter(m_contributed_service_nodes),
          [&contributor](const auto& sn)
          {
            return std::any_of(sn.contributors.begin(), sn.contributors.end(),
                [&contributor](const auto& c) { return contributor == c.address; });
          }
      );
      m_contributed_service_nodes_cached_height = height;
      m_contributed_service_nodes_cached_address = contributor;
    }

    sns = m_contributed_service_nodes;
  }

  success = true;
  return result;
}

std::pair<bool, std::vector<cryptonote::rpc::GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES::entry>> NodeRPCProxy::get_service_node_blacklisted_key_images() const
{
  std::pair<bool, std::vector<cryptonote::rpc::GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES::entry>> result;
  auto& [success, sns] = result;
  success = false;

  uint64_t height;
  if (m_offline || !get_height(height))
    return result;

  {
    std::lock_guard lock{m_sn_cache_mutex};
    if (m_service_node_blacklisted_key_images_cached_height != height)
    {
      try {
        auto res = invoke_json_rpc<rpc::GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES>({});
        m_service_node_blacklisted_key_images_cached_height = height;
        m_service_node_blacklisted_key_images               = std::move(res.blacklist);
      } catch (...) {
        return result;
      }
    }

    sns = m_service_node_blacklisted_key_images;
  }

  success = true;
  return result;
}

std::pair<bool, std::vector<cryptonote::rpc::LNS_OWNERS_TO_NAMES::response_entry>> NodeRPCProxy::lns_owners_to_names(cryptonote::rpc::LNS_OWNERS_TO_NAMES::request const &request) const
{
  return get_result_pair<rpc::LNS_OWNERS_TO_NAMES>(request, [](auto&& res) { return std::move(res.entries); });
}

std::pair<bool, std::vector<cryptonote::rpc::LNS_NAMES_TO_OWNERS::response_entry>> NodeRPCProxy::lns_names_to_owners(cryptonote::rpc::LNS_NAMES_TO_OWNERS::request const &request) const
{
  return get_result_pair<rpc::LNS_NAMES_TO_OWNERS>(request, [](auto&& res) { return std::move(res.entries); });
}

}
