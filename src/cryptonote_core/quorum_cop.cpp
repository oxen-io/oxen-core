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

#include "cryptonote_config.h"

#include "quorum_cop.h"

// TODO: rebase on top of doyle's changes and use the other constant.
const uint64_t VOTE_LIFETIME_BY_HEIGHT = (60 * 60 * 2) / DIFFICULTY_TARGET_V2;

namespace service_nodes
{
  quorum_cop::quorum_cop(cryptonote::Blockchain& blockchain, service_nodes::service_node_list& service_node_list)
    : m_service_node_list(service_node_list), m_last_height(0)
  {
    blockchain.hook_block_added(*this);
    blockchain.hook_blockchain_detached(*this);
  }

  void quorum_cop::blockchain_detached(uint64_t height)
  {
    // TODO: check for big reorg and if too big panic.
  }

  void quorum_cop::block_added(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs)
  {
    uint64_t height = cryptonote::get_block_height(block);

    if (height < REORG_SAFETY_BUFFER_IN_BLOCKS)
      return;

    if (height >= VOTE_LIFETIME_BY_HEIGHT)
      m_last_height = std::max(m_last_height, height - VOTE_LIFETIME_BY_HEIGHT);

    while (m_last_height < height - REORG_SAFETY_BUFFER_IN_BLOCKS)
    {
      std::cout << "Processing quorum cop stuff for height = " << m_last_height << std::endl;
      // XXX IN HERE, go through the quorum for m_last_height and for each of
      // the pubkeys, check if the uptime proof was seen in the last hour and
      // five minutes. If not, submit a vote to the vote pool.

      m_last_height++;
    }
  }

  bool quorum_cop::handle_uptime_proof(uint64_t timestamp, const crypto::public_key& pubkey, const crypto::signature& sig)
  {
    uint64_t now = time(nullptr);

    if (timestamp < now - SECONDS_UPTIME_PROOF_BUFFER || timestamp > now + SECONDS_UPTIME_PROOF_BUFFER)
      return false;

    if (!m_service_node_list.is_service_node(pubkey))
      return false; // this pubkey is not a service node

    if (m_uptime_proof_seen[pubkey] > now - SECONDS_UPTIME_PROOF_FREQUENCY + 2 * SECONDS_UPTIME_PROOF_BUFFER)
    {
      return false; // already received one uptime proof for this node recently.
    }

    char buf[44] = "SUP"; // Meaningless magic bytes
    crypto::hash hash;
    memcpy(buf + 4, reinterpret_cast<const void *>(&pubkey), 32);
    memcpy(buf + 4 + 32, reinterpret_cast<const void *>(&timestamp), 8);
    crypto::cn_fast_hash(buf, 40, hash);

    if (!crypto::check_signature(hash, pubkey, sig))
      return false;

    // TODO: remove old/expired nodes (memleak)
    // TODO: make thread safe

    m_uptime_proof_seen[pubkey] = timestamp;

    return true;
  }

  void quorum_cop::generate_uptime_proof_request(const crypto::public_key& pubkey, const crypto::secret_key& seckey, cryptonote::NOTIFY_UPTIME_PROOF::request& req) const
  {
    uint64_t timestamp = time(nullptr);

    char buf[44] = "SUP"; // Meaningless magic bytes
    crypto::hash hash;
    memcpy(buf + 4, reinterpret_cast<const void *>(&pubkey), 32);
    memcpy(buf + 4 + 32, reinterpret_cast<const void *>(&timestamp), 8);
    crypto::cn_fast_hash(buf, 40, hash);

    req.timestamp = timestamp;
    req.pubkey = pubkey;
    crypto::generate_signature(hash, pubkey, seckey, req.sig);
  }
}
