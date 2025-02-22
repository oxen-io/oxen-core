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

#include <boost/serialization/base_object.hpp>
#include <cassert>
#include <mutex>
#include <utility>
#include <vector>

#include "common/periodic_task.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/tx_extra.h"

namespace cryptonote {
struct tx_verification_context;
struct vote_verification_context;
struct checkpoint_t;
};  // namespace cryptonote

namespace service_nodes {
struct quorum;

struct checkpoint_vote {
    crypto::hash block_hash;
};
struct state_change_vote {
    uint16_t worker_index;
    new_state state;
    uint16_t reason;
};

enum struct quorum_type : uint8_t { obligations = 0, checkpointing, blink, pulse, _count };

inline constexpr std::string_view to_string(const quorum_type& q) {
    switch (q) {
        case quorum_type::obligations: return "obligation";
        case quorum_type::checkpointing: return "checkpointing";
        case quorum_type::blink: return "blink";
        case quorum_type::pulse: return "pulse";
        default: assert(false); return "xx_unhandled_type";
    }
};

enum struct quorum_group : uint8_t { invalid, validator, worker, _count };
struct quorum_vote_t {
    uint8_t version = 0;
    quorum_type type;
    uint64_t block_height;
    quorum_group group;
    uint16_t index_in_group;
    crypto::signature signature;

    union {
        state_change_vote state_change;
        checkpoint_vote checkpoint;
    };

    KV_MAP_SERIALIZABLE

    // TODO(oxen): idk exactly if I want to implement this, but need for core tests to compile. Not
    // sure I care about serializing for core tests at all.
  private:
    friend class boost::serialization::access;
    template <class Archive>
    void serialize(Archive& ar, const unsigned int /*version*/) {}
};

struct service_node_keys;

quorum_vote_t make_state_change_vote(
        uint64_t block_height,
        uint16_t index_in_group,
        uint16_t worker_index,
        new_state state,
        uint16_t reason,
        const service_node_keys& keys);
quorum_vote_t make_checkpointing_vote(
        cryptonote::hf hf_version,
        crypto::hash const& block_hash,
        uint64_t block_height,
        uint16_t index_in_quorum,
        const service_node_keys& keys);
cryptonote::checkpoint_t make_empty_service_node_checkpoint(
        crypto::hash const& block_hash, uint64_t height);

bool verify_checkpoint(
        cryptonote::hf hf_version,
        cryptonote::checkpoint_t const& checkpoint,
        service_nodes::quorum const& quorum);
bool verify_tx_state_change(
        const cryptonote::tx_extra_service_node_state_change& state_change,
        uint64_t latest_height,
        cryptonote::tx_verification_context& vvc,
        const service_nodes::quorum& quorum,
        cryptonote::hf hf_version);
bool verify_vote_age(
        const quorum_vote_t& vote,
        uint64_t latest_height,
        cryptonote::vote_verification_context& vvc);
bool verify_vote_signature(
        cryptonote::hf hf_version,
        const quorum_vote_t& vote,
        cryptonote::vote_verification_context& vvc,
        const service_nodes::quorum& quorum);
bool verify_quorum_signatures(
        service_nodes::quorum const& quorum,
        service_nodes::quorum_type type,
        cryptonote::hf hf_version,
        uint64_t height,
        crypto::hash const& hash,
        std::vector<quorum_signature> const& signatures,
        const cryptonote::block* block = nullptr);
bool verify_pulse_quorum_sizes(service_nodes::quorum const& quorum);
crypto::signature make_signature_from_vote(
        quorum_vote_t const& vote, const service_node_keys& keys);
crypto::signature make_signature_from_tx_state_change(
        cryptonote::tx_extra_service_node_state_change const& state_change,
        const service_node_keys& keys);

struct pool_vote_entry {
    quorum_vote_t vote;
    uint64_t time_last_sent_p2p;
};

struct voting_pool {
    // return: The vector of votes if the vote is valid (and even if it is not unique) otherwise
    // nullptr
    std::vector<pool_vote_entry> add_pool_vote_if_unique(
            const quorum_vote_t& vote, cryptonote::vote_verification_context& vvc);

    // TODO(oxen): Review relay behaviour and all the cases when it should be triggered
    void set_relayed(const std::vector<quorum_vote_t>& votes);
    void remove_expired_votes(uint64_t height);
    void remove_used_votes(std::vector<cryptonote::transaction> const& txs, cryptonote::hf version);

    /// Returns relayable votes for either p2p (quorum_relay=false) or quorumnet
    /// (quorum_relay=true).  Before HF14 everything goes via p2p; starting in HF14 obligation votes
    /// go via quorumnet, checkpoints go via p2p.
    std::vector<quorum_vote_t> get_relayable_votes(
            uint64_t height, cryptonote::hf hf_version, bool quorum_relay) const;
    bool received_checkpoint_vote(uint64_t height, size_t index_in_quorum) const;

  private:
    std::vector<pool_vote_entry>* find_vote_pool(
            const quorum_vote_t& vote, bool create_if_not_found = false);

    struct obligations_pool_entry {
        explicit obligations_pool_entry(const quorum_vote_t& vote) :
                height{vote.block_height},
                worker_index{vote.state_change.worker_index},
                state{vote.state_change.state} {}
        obligations_pool_entry(const cryptonote::tx_extra_service_node_state_change& sc) :
                height{sc.block_height}, worker_index{sc.service_node_index}, state{sc.state} {}

        uint64_t height;
        uint32_t worker_index;
        new_state state;
        std::vector<pool_vote_entry> votes;

        bool operator==(const obligations_pool_entry& e) const {
            return height == e.height && worker_index == e.worker_index && state == e.state;
        }
    };
    std::vector<obligations_pool_entry> m_obligations_pool;

    struct checkpoint_pool_entry {
        explicit checkpoint_pool_entry(const quorum_vote_t& vote) :
                height{vote.block_height}, hash{vote.checkpoint.block_hash} {}
        checkpoint_pool_entry(uint64_t height, crypto::hash const& hash) :
                height(height), hash(hash) {}
        uint64_t height;
        crypto::hash hash;
        std::vector<pool_vote_entry> votes;

        bool operator==(const checkpoint_pool_entry& e) const {
            return height == e.height && hash == e.hash;
        }
    };
    std::vector<checkpoint_pool_entry> m_checkpoint_pool;

    mutable std::recursive_mutex m_lock;
};
};  // namespace service_nodes

template <>
inline constexpr bool formattable::via_to_string<service_nodes::quorum_type> = true;
