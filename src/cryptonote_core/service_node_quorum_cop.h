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

#include "serialization/serialization.h"
#include "cryptonote_protocol/cryptonote_protocol_handler_common.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_core/service_node_voting.h"
#include <cassert>
#include <mutex>

namespace cryptonote
{
  class core;
  struct vote_verification_context;
  struct checkpoint_t;
};

namespace service_nodes
{
  struct service_node_info;

  struct quorum
  {
    std::vector<crypto::public_key> validators; // Array of public keys identifying service nodes who validate and sign.
    std::vector<crypto::public_key> workers;    // Array of public keys of tested service nodes (if applicable).

    BEGIN_SERIALIZE()
      FIELD(validators)
      FIELD(workers)
    END_SERIALIZE()
  };

  inline std::ostream &operator<<(std::ostream &os, quorum const &q)
  {
    for (size_t i = 0; i < q.validators.size(); i++) os << "V[" << i << "] " << q.validators[i] << "\n";
    for (size_t i = 0; i < q.workers.size(); i++) os    << "W[" << i << "] " << q.workers[i] << "\n";
    return os;
  }

  struct quorum_manager
  {
    std::shared_ptr<const quorum> obligations;
    // TODO(doyle): Workers aren't used, but I kept this as a quorum
    // to avoid drastic changes for now to a lot of the service node API
    std::shared_ptr<const quorum> checkpointing;
    std::shared_ptr<const quorum> blink;
    std::shared_ptr<const quorum> pulse;

    std::shared_ptr<const quorum> get(quorum_type type) const
    {
      if (type == quorum_type::obligations) return obligations;
      else if (type == quorum_type::checkpointing) return checkpointing;
      else if (type == quorum_type::blink) return blink;
      else if (type == quorum_type::pulse) return pulse;
      MERROR("Developer error: Unhandled quorum enum with value: " << (size_t)type);
      assert(!"Developer error: Unhandled quorum enum with value: ");
      return nullptr;
    }
  };

  struct service_node_test_results {
    bool uptime_proved            = true;
    bool single_ip                = true;
    bool checkpoint_participation = true;
    bool pulse_participation      = true;
    bool timestamp_participation  = true;
    bool timesync_status          = true;
    bool storage_server_reachable = true;

    char const *why() const;
    bool passed() const { return uptime_proved && checkpoint_participation && pulse_participation && storage_server_reachable && timestamp_participation && timesync_status; }
  };

  class quorum_cop
    : public cryptonote::BlockAddedHook,
      public cryptonote::BlockchainDetachedHook,
      public cryptonote::InitHook
  {
  public:
    explicit quorum_cop(cryptonote::core& core);

    void init() override;
    bool block_added(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs, cryptonote::checkpoint_t const * /*checkpoint*/) override;
    void blockchain_detached(uint64_t height, bool by_pop_blocks) override;

    void                       set_votes_relayed  (std::vector<quorum_vote_t> const &relayed_votes);
    std::vector<quorum_vote_t> get_relayable_votes(uint64_t current_height, uint8_t hf_version, bool quorum_relay);
    bool                       handle_vote        (quorum_vote_t const &vote, cryptonote::vote_verification_context &vvc);

    static int64_t calculate_decommission_credit(const service_node_info &info, uint64_t current_height);

  private:
    void process_quorums(cryptonote::block const &block);
    service_node_test_results check_service_node(uint8_t hf_version, const crypto::public_key &pubkey, const service_node_info &info) const;

    cryptonote::core& m_core;
    voting_pool       m_vote_pool;
    uint64_t          m_obligations_height;
    uint64_t          m_last_checkpointed_height;
    mutable std::recursive_mutex m_lock;
  };

  int find_index_in_quorum_group(std::vector<crypto::public_key> const &group, const crypto::public_key &my_pubkey);

  /** Calculates a checksum value from the (ordered!) set of pubkeys to casually test whether two
   * quorums are the same.  (Not meant to be cryptographically secure).
   *
   * offset is used to add multiple lists together without having to construct a separate vector,
   * that is:
   *
   *     checksum([a,b,c,d,e])
   *
   * and
   *
   *     checksum([a,b,c]) + checksum([d,e], 3)
   *
   * yield the same result.  Public keys may be null; pubkeys that are skipped via the offset are
   * equivalent to a null pubkey for skipped entries, and the checksum of [a,b,ZERO] is equal to the
   * checksum of [a,b] but not equal to [a,ZERO,b].
   */
  uint64_t quorum_checksum(const std::vector<crypto::public_key> &pubkeys, size_t offset = 0);
}
