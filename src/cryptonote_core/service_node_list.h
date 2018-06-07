// Copyright (c)      2018, The Loki Project
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

#include "blockchain.h"

namespace service_nodes
{
  class service_node_list
    : public cryptonote::Blockchain::BlockAddedHook,
      public cryptonote::Blockchain::BlockchainDetachedHook,
      public cryptonote::Blockchain::InitHook
  {
  public:
    service_node_list(cryptonote::Blockchain& blockchain);
    void block_added(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs);
    void blockchain_detached(uint64_t height);
    void init();

    std::vector<crypto::public_key> get_expired_nodes(uint64_t block_height);

  private:
    bool process_registration_tx(const cryptonote::transaction& tx, uint64_t block_height, crypto::public_key& pub_spendkey_out);
    template<typename T>
    void block_added_generic(const cryptonote::block& block, const T& txs);

    bool reg_tx_has_correct_unlock_time(const cryptonote::transaction& tx, uint64_t block_height);
    bool reg_tx_extract_fields(const cryptonote::transaction& tx, crypto::secret_key& viewkey, crypto::public_key& pub_viewkey, crypto::public_key& pub_spendkey, crypto::public_key& tx_pub_key);
    void reg_tx_calculate_subaddresses(const crypto::secret_key& viewkey, const crypto::public_key& pub_viewkey, const crypto::public_key& pub_spendkey, std::vector<crypto::public_key>& subaddresses, hw::device& hwdev);
    bool is_reg_tx_staking_output(const cryptonote::transaction& tx, int i, uint64_t block_height, crypto::key_derivation derivation, std::vector<crypto::public_key> subaddresses, hw::device& hwdev);

    std::unordered_map<crypto::public_key, uint64_t> m_service_nodes_last_reward;
    cryptonote::Blockchain& m_blockchain;
  };
}
