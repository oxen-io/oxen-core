// Copyright (c) 2020, The Loki Project
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

#pragma once

#include "core_rpc_server.h"
#include "cryptonote_core/blockchain.h"
#include "oxenmq/connections.h"

namespace oxenmq { class OxenMQ; }

namespace cryptonote { namespace rpc {

void init_lmq_options(boost::program_options::options_description& desc);

/**
 * LMQ RPC server class.  This doesn't actually hold the OxenMQ instance--that's in
 * cryptonote_core--but it works with it to add RPC endpoints, make it listen on RPC ports, and
 * handles RPC requests.
 */
class lmq_rpc final : public cryptonote::BlockAddedHook {

  enum class mempool_sub_type { all, blink };
  struct mempool_sub {
    std::chrono::steady_clock::time_point expiry;
    mempool_sub_type type;
  };

  struct block_sub {
    std::chrono::steady_clock::time_point expiry;
  };

  cryptonote::core& core_;
  core_rpc_server& rpc_;
  std::shared_timed_mutex subs_mutex_;
  std::unordered_map<oxenmq::ConnectionID, mempool_sub> mempool_subs_;
  std::unordered_map<oxenmq::ConnectionID, block_sub> block_subs_;

public:
  lmq_rpc(cryptonote::core& core, core_rpc_server& rpc, const boost::program_options::variables_map& vm);

  bool block_added(const block& block, const std::vector<transaction>& txs, const checkpoint_t *) override;

  void send_mempool_notifications(const crypto::hash& id, const transaction& tx, const std::string& blob, const tx_pool_options& opts);
};

}} // namespace cryptonote::rpc
