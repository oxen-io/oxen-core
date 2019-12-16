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
#include "cryptonote_basic/tx_extra.h"

#include "string_tools.h"
#include "math_helper.h"
#include "syncobj.h"

#include <boost/serialization/base_object.hpp>

namespace cryptonote
{
  struct tx_verification_context;
  struct vote_verification_context;
  struct checkpoint_t;
};

namespace service_nodes
{
  struct quorum;

  struct checkpoint_vote { crypto::hash block_hash; };
  struct state_change_vote { uint16_t worker_index; new_state state; };

  enum struct quorum_type : uint8_t
  {
    obligations = 0,
    checkpointing,
    blink,
    _count
  };

  inline std::ostream &operator<<(std::ostream &os, quorum_type v) {
    switch(v)
    {
      case quorum_type::obligations:   return os << "obligation";
      case quorum_type::checkpointing: return os << "checkpointing";
      case quorum_type::blink:         return os << "blink";
      default: assert(false);          return os << "xx_unhandled_type";
    }
  }

  enum struct quorum_group : uint8_t { invalid, validator, worker, _count };
  struct quorum_vote_t
  {
    // Note: This type has various padding and alignment and was mistakingly serialized as a blob
    // (padding and all, and not portable).  To remain compatible, we have to reproduce the blob
    // data byte-for-byte as expected in the loki 5.x struct memory layout on AMD64, via the
    // vote_to_blob functions below.

    uint8_t           version = 0;
    quorum_type       type;
    uint64_t          block_height;
    quorum_group      group;
    uint16_t          index_in_group;
    crypto::signature signature;

    union
    {
      state_change_vote state_change;
      checkpoint_vote   checkpoint;
    };

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(version)
      KV_SERIALIZE_ENUM(type)
      KV_SERIALIZE(block_height)
      KV_SERIALIZE_ENUM(group)
      KV_SERIALIZE(index_in_group)
      KV_SERIALIZE_VAL_POD_AS_BLOB(signature)
      if (this_ref.type == quorum_type::checkpointing)
      {
        KV_SERIALIZE_VAL_POD_AS_BLOB_N(checkpoint.block_hash, "checkpoint")
      }
      else
      {
        KV_SERIALIZE(state_change.worker_index)
        KV_SERIALIZE_ENUM(state_change.state)
      }
    END_KV_SERIALIZE_MAP()

   // TODO(loki): idk exactly if I want to implement this, but need for core tests to compile. Not sure I care about serializing for core tests at all.
   private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive &ar, const unsigned int /*version*/) { }
  };

  void vote_to_blob(const quorum_vote_t& vote, unsigned char blob[]);
  void blob_to_vote(const unsigned char blob[], quorum_vote_t& vote);

  struct voter_to_signature
  {
    voter_to_signature() = default;
    voter_to_signature(quorum_vote_t const &vote) : voter_index(vote.index_in_group), signature(vote.signature) { }
    uint16_t          voter_index;
    crypto::signature signature;

    BEGIN_SERIALIZE()
      FIELD(voter_index)
      FIELD(signature)
    END_SERIALIZE()
  };

  struct service_node_keys;

  quorum_vote_t            make_state_change_vote(uint64_t block_height, uint16_t index_in_group, uint16_t worker_index, new_state state, const service_node_keys &keys);
  quorum_vote_t            make_checkpointing_vote(uint8_t hf_version, crypto::hash const &block_hash, uint64_t block_height, uint16_t index_in_quorum, const service_node_keys &keys);
  cryptonote::checkpoint_t make_empty_service_node_checkpoint(crypto::hash const &block_hash, uint64_t height);

  bool               verify_checkpoint                  (uint8_t hf_version, cryptonote::checkpoint_t const &checkpoint, service_nodes::quorum const &quorum);
  bool               verify_tx_state_change             (const cryptonote::tx_extra_service_node_state_change& state_change, uint64_t latest_height, cryptonote::tx_verification_context& vvc, const service_nodes::quorum &quorum, uint8_t hf_version);
  bool               verify_vote_age                    (const quorum_vote_t& vote, uint64_t latest_height, cryptonote::vote_verification_context &vvc);
  bool               verify_vote_signature              (uint8_t hf_version, const quorum_vote_t& vote, cryptonote::vote_verification_context &vvc, const service_nodes::quorum &quorum);
  crypto::signature  make_signature_from_vote           (quorum_vote_t const &vote, const service_node_keys &keys);
  crypto::signature  make_signature_from_tx_state_change(cryptonote::tx_extra_service_node_state_change const &state_change, const service_node_keys &keys);

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

  struct pool_vote_entry
  {
    quorum_vote_t vote;
    uint64_t      time_last_sent_p2p;
  };

  struct voting_pool
  {
    // return: The vector of votes if the vote is valid (and even if it is not unique) otherwise nullptr
    std::vector<pool_vote_entry> add_pool_vote_if_unique(const quorum_vote_t &vote, cryptonote::vote_verification_context &vvc);

    // TODO(loki): Review relay behaviour and all the cases when it should be triggered
    void                         set_relayed         (const std::vector<quorum_vote_t>& votes);
    void                         remove_expired_votes(uint64_t height);
    void                         remove_used_votes   (std::vector<cryptonote::transaction> const &txs, uint8_t hard_fork_version);

    /// Returns relayable votes for either p2p (quorum_relay=false) or quorumnet
    /// (quorum_relay=true).  Before HF14 everything goes via p2p; starting in HF14 obligation votes
    /// go via quorumnet, checkpoints go via p2p.
    std::vector<quorum_vote_t>   get_relayable_votes (uint64_t height, uint8_t hf_version, bool quorum_relay) const;
    bool                         received_checkpoint_vote(uint64_t height, size_t index_in_quorum) const;

  private:
    std::vector<pool_vote_entry> *find_vote_pool(const quorum_vote_t &vote, bool create_if_not_found = false);

    struct obligations_pool_entry
    {
      explicit obligations_pool_entry(const quorum_vote_t &vote)
          : height{vote.block_height}, worker_index{vote.state_change.worker_index}, state{vote.state_change.state} {}
      obligations_pool_entry(const cryptonote::tx_extra_service_node_state_change &sc)
          : height{sc.block_height}, worker_index{sc.service_node_index}, state{sc.state} {}

      uint64_t                     height;
      uint32_t                     worker_index;
      new_state                    state;
      std::vector<pool_vote_entry> votes;

      bool operator==(const obligations_pool_entry &e) const { return height == e.height && worker_index == e.worker_index && state == e.state; }
    };
    std::vector<obligations_pool_entry> m_obligations_pool;

    struct checkpoint_pool_entry
    {
      explicit checkpoint_pool_entry(const quorum_vote_t &vote) : height{vote.block_height}, hash{vote.checkpoint.block_hash} {}
      checkpoint_pool_entry(uint64_t height, crypto::hash const &hash): height(height), hash(hash) {}
      uint64_t                     height;
      crypto::hash                 hash;
      std::vector<pool_vote_entry> votes;

      bool operator==(const checkpoint_pool_entry &e) const { return height == e.height && hash == e.hash; }
    };
    std::vector<checkpoint_pool_entry> m_checkpoint_pool;

    mutable epee::critical_section m_lock;
  };
}; // namespace service_nodes

