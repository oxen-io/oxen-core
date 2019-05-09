// Copyright (c) 2018, The Loki Project
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

#include <vector>
#include <unordered_map>
#include <utility>

#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/blobdatatype.h"

#include "math_helper.h"
#include "syncobj.h"

namespace cryptonote
{
  struct vote_verification_context;
  struct tx_extra_service_node_deregister;
};

namespace service_nodes
{
  struct testing_quorum;

  struct voter_to_signature
  {
    uint16_t          validator_index;
    crypto::signature signature;
  };

  struct checkpoint_vote
  {
    crypto::hash block_hash;
  };

  struct deregister_vote
  {
    static const uint64_t VOTE_LIFETIME_BY_HEIGHT       = BLOCKS_EXPECTED_IN_HOURS(2);
    static const uint64_t DEREGISTER_LIFETIME_BY_HEIGHT = VOTE_LIFETIME_BY_HEIGHT;
    uint32_t service_node_index;

    static bool verify(cryptonote::network_type nettype, const cryptonote::tx_extra_service_node_deregister& deregister,
                       cryptonote::vote_verification_context& vvc,
                       const service_nodes::testing_quorum &quorum);

  };

  enum struct quorum_type
  {
    uptime_deregister = 0,
    checkpointing,
    count,
  };

  struct quorum_vote_t
  {
    size_t            version = 0;
    quorum_type       type;
    uint64_t          block_height;
    uint32_t          validator_index;
    crypto::signature signature;

    union
    {
      deregister_vote deregister;
      checkpoint_vote checkpoint;
    };
  };

  bool              verify_vote(cryptonote::network_type nettype, const quorum_vote_t& vote, cryptonote::vote_verification_context &vvc, const service_nodes::testing_quorum &quorum);
  crypto::signature sign_vote  (quorum_vote_t const &vote, const crypto::public_key& pub, const crypto::secret_key& sec);

  // NOTE: This preserves the deregister vote format pre-checkpointing so that
  // up to the hardfork, we can still deserialize and serialize until we switch
  // over to the new format
  struct legacy_deregister_vote
  {
    uint64_t          block_height;
    uint32_t          service_node_index;
    uint32_t          voters_quorum_index;
    crypto::signature signature;
  };

  bool           convert_deregister_vote_to_legacy(quorum_vote_t const &vote, legacy_deregister_vote &legacy);
  quorum_vote_t  convert_legacy_deregister_vote   (legacy_deregister_vote const &vote);

  struct pool_vote_entry
  {
    quorum_vote_t vote;
    uint64_t      time_last_sent_p2p;
  };

  struct voting_pool
  {
    cryptonote::network_type m_nettype = cryptonote::UNDEFINED;

    struct voting_result
    {
      std::vector<pool_vote_entry> const *votes; // The vector the vote was added to, nullptr if vote_valid is FALSE
      bool vote_valid;
      bool vote_unique;
    };

    /**
     *  @return True if vote was valid and in the pool already or just added (check vote verfication for specific case).
     */
    voting_result add_pool_vote(uint64_t latest_height,
                                const quorum_vote_t& vote,
                                cryptonote::vote_verification_context& vvc,
                                const service_nodes::testing_quorum &quorum);

    // TODO(loki): Review relay behaviour and all the cases when it should be triggered
    void                         set_relayed         (const std::vector<quorum_vote_t>& votes);
    void                         remove_expired_votes(uint64_t height);
    void                         remove_used_votes   (std::vector<cryptonote::transaction> const &txs);
    std::vector<quorum_vote_t>   get_relayable_votes () const;

  private:
    struct deregister_pool_entry
    {
      uint64_t                     block_height;
      uint32_t                     service_node_index;
      std::vector<pool_vote_entry> votes;
    };
    std::vector<deregister_pool_entry> m_deregister_pool;

    struct checkpoint_pool_entry
    {
      uint64_t                     height;
      crypto::hash                 hash;
      std::vector<pool_vote_entry> votes;
    };
    std::vector<checkpoint_pool_entry> m_checkpoint_pool;

    mutable epee::critical_section m_lock;
  };
}; // namespace service_nodes

