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

#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"

#include "math_helper.h"
#include "syncobj.h"

namespace cryptonote
{
  struct vote_verification_context;
  class Blockchain;
};

namespace loki
{
  // TODO(doyle): Complexity analysis for managing votes, determine the upper
  // and lower bounds of what numbers we expect.

  // std::vector<Block Height Entries> partial_deregisters
  // My assumption is that the block heights we keep votes around for
  // is going to be very small and short lived < 10 entries ~ 20mins worth of
  // blocks, avg block time 120s. So linearly scanning for a block height is
  // effective with low code complexity/computation and memory usage.

  // std::unordered_map<Node Index, std::Vector<Votes>> service_node_votes
  // In each block height we have our quorum 10 SNodes querying 1% of the
  // network. Assuming a very generous 50,000 node network, 1% of nodes is 500,
  // with each needing 10 votes to kick off the network, so 500 entries in the
  // map with 10 votes each.
  // As opposed to (500 nodes * 10 votes) = 5000 votes to sort and search if in
  // a vector per block height.

  namespace xx__service_node
  {
    extern const char *secret_spend_keys_str[100];
    extern const char *secret_view_keys_str[100];
    extern const char *public_spend_keys_str[100];
    extern const char *public_view_keys_str[100];
    extern std::vector<crypto::secret_key> secret_view_keys;
    extern std::vector<crypto::public_key> public_view_keys;
    extern std::vector<crypto::secret_key> secret_spend_keys;
    extern std::vector<crypto::public_key> public_spend_keys;
    void init();
  };

  namespace service_node_deregister
  {
    struct vote
    {
      uint64_t          block_height;
      uint32_t          service_node_index;
      uint32_t          voters_quorum_index;
      crypto::signature signature;
    };

    crypto::hash make_unsigned_vote_hash(const cryptonote::tx_extra_service_node_deregister& deregister);
    crypto::hash make_unsigned_vote_hash(const vote& v);

    bool verify(const cryptonote::tx_extra_service_node_deregister& deregister,
                cryptonote::vote_verification_context& vvc,
                const std::vector<crypto::public_key> &quorum);

    bool verify(const vote& v, cryptonote::vote_verification_context &vvc,
                const std::vector<crypto::public_key> &quorum);
  };

  // TODO(doyle): We need to a scheme to remove dead votes, see tx_memory_pool::on_idle
  class deregister_vote_pool
  {
    public:
      class pool_entry
      {
        public:
          pool_entry(uint64_t time_last_sent_p2p, service_node_deregister::vote vote)
            : m_time_last_sent_p2p(time_last_sent_p2p), m_vote(vote) {}

          uint64_t m_time_last_sent_p2p;
          service_node_deregister::vote m_vote;
      };

      struct pool_group
      {
        using service_node_index = uint32_t;
        uint64_t block_height;
        time_t   time_group_created;
        std::unordered_map<service_node_index, std::vector<pool_entry>> service_node;
      };

      /**
       *  @return True if vote was valid and in the pool already or just added (check vote verfication for specific case).
       */
      bool add_vote(const service_node_deregister::vote& new_vote, cryptonote::vote_verification_context& vvc,
                    const std::vector<crypto::public_key>& quorum, cryptonote::transaction &tx);

      // TODO(doyle): Review relay behaviour and all the cases when it should be triggered
      void xx__print_service_node() const;
      void set_relayed           (const std::vector<service_node_deregister::vote>& votes);
      void remove_expired_votes  (uint64_t height);
      std::vector<service_node_deregister::vote> get_relayable_votes() const;

    private:
      std::vector<pool_group> m_deregisters;
      mutable epee::critical_section m_lock;
  };

}; // namespace loki
