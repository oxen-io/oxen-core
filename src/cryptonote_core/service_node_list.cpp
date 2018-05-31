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

#include <functional>

#include "service_node_list.h"

namespace service_nodes
{
  service_node_list::service_node_list(cryptonote::Blockchain& blockchain)
  {
    blockchain.hook_new_block([&](const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs) {
      this->add_block(block, txs);
    });
  }

  void service_node_list::add_block(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs)
  {
    for (const cryptonote::transaction& tx : txs) {
      if(tx.unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER)
      {
        uint64_t lock_time = tx.unlock_time - cryptonote::get_block_height(block);
        LOG_PRINT_L0("Found tx with lock time " << lock_time << " = " << tx.unlock_time << " - " << cryptonote::get_block_height(block));
        if (lock_time >= STAKING_REQUIREMENT_LOCK_BLOCKS) {
          LOG_PRINT_L0("Identified staking transaction");
        }
      }
    }
  }

  void service_node_list::remove_block(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs)
  {
    LOG_PRINT_L0("Remove Tx hook called");
  }
}
