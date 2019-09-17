// Copyright (c) 2019, The Loki Project
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

#include "quorumnet.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/service_node_voting.h"
#include "cryptonote_core/service_node_rules.h"
#include "quorumnet/sn_network.h"
#include "quorumnet/conn_matrix.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "qnet"

namespace quorumnet {

using namespace service_nodes;

struct SNNWrapper {
    SNNetwork snn;
    cryptonote::core &core; // FIXME - may not be needed?
    service_node_list &sn_list;

    template <typename... Args>
    SNNWrapper(cryptonote::core &core, service_node_list &sn_list, Args &&...args) :
        snn{std::forward<Args>(args)...}, core{core}, sn_list{sn_list} {}
};

template <typename T>
std::string key_data_as_string(const T &key) {
    return {reinterpret_cast<const char *>(key.data), sizeof(key.data)};
}

static crypto::x25519_public_key x25519_from_string(const std::string &pubkey) {
    crypto::x25519_public_key x25519_pub = crypto::x25519_public_key::null();
    if (pubkey.size() == sizeof(crypto::x25519_public_key))
        std::memcpy(x25519_pub.data, pubkey.data(), pubkey.size());
    return x25519_pub;
}

static std::string get_connect_string(const service_node_list &sn_list, crypto::x25519_public_key x25519_pub) {
    if (!x25519_pub) {
        MDEBUG("no connection available: pubkey is empty");
        return "";
    }
    auto pubkey = sn_list.get_pubkey_from_x25519(x25519_pub);
    if (!pubkey) {
        MDEBUG("no connection available: could not find primary pubkey from x25519 pubkey " << x25519_pub);
        return "";
    }
    auto states = sn_list.get_service_node_list_state({{pubkey}});
    if (states.empty()) {
        MDEBUG("no connection available: primary pubkey " << pubkey << " is not registered");
        return "";
    }
    const auto &proof = *states[0].info->proof;
    if (!proof.public_ip || !proof.quorumnet_port) {
        MDEBUG("no connection available: primary pubkey " << pubkey << " has no associated ip and/or port");
        return "";
    }
    return "tcp://" + epee::string_tools::get_ip_string_from_int32(proof.public_ip) + ":" + std::to_string(proof.quorumnet_port);
}

static constexpr el::Level easylogging_level(LogLevel level) {
    switch (level) {
        case LogLevel::fatal: return el::Level::Fatal;
        case LogLevel::error: return el::Level::Error;
        case LogLevel::warn:  return el::Level::Warning;
        case LogLevel::info:  return el::Level::Info;
        case LogLevel::debug: return el::Level::Debug;
        case LogLevel::trace: return el::Level::Trace;
    };
    return el::Level::Unknown;
};
static bool snn_want_log(LogLevel level) {
    return ELPP->vRegistry()->allowed(easylogging_level(level), LOKI_DEFAULT_LOG_CATEGORY);
}
static void snn_write_log(LogLevel level, const char *file, int line, std::string msg) {
    el::base::Writer(easylogging_level(level), file, line, ELPP_FUNC, el::base::DispatchAction::NormalLog).construct(LOKI_DEFAULT_LOG_CATEGORY) << msg;
}

static void *new_snnwrapper(cryptonote::core &core, service_node_list &sn_list, const std::string &bind) {
    auto keys = core.get_service_node_keys();
    assert((bool) keys);
    MINFO("Starting quorumnet listener on " << bind << " with x25519 pubkey " << keys->pub_x25519);
    auto *obj = new SNNWrapper(core, sn_list,
            key_data_as_string(keys->pub_x25519),
            key_data_as_string(keys->key_x25519),
            std::vector<std::string>{{bind}},
            [&sn_list](const std::string &x25519_pub) { return get_connect_string(sn_list, x25519_from_string(x25519_pub)); },
            [&sn_list](const std::string &ip, const std::string &x25519_pubkey_str) {
                // TODO: this function could also check to see whether the given pubkey *should* be
                // contacting us (i.e. either will soon be or was recently in a shared quorum).
                return true;
                return (bool) sn_list.get_pubkey_from_x25519(x25519_from_string(x25519_pubkey_str));
            },
            snn_want_log, snn_write_log);

    obj->snn.data = obj; // Provide pointer to the instance for callbacks

    return obj;
}

static void delete_snnwrapper(void *obj) { 
    auto *snn = reinterpret_cast<SNNWrapper *>(obj);
    MINFO("Shutting down quorumnet listener");
    delete snn;
}


template <typename E>
static E get_enum(const bt_dict &d, const std::string &key, E sup) {
    E result = static_cast<E>(get_int<std::underlying_type_t<E>>(d.at(key)));
    if (result < sup)
        return result;
    throw std::invalid_argument("invalid enum value for field " + key);
}



static bt_dict serialize_vote(const quorum_vote_t &vote) {
    bt_dict result{
        {"v", vote.version},
        {"t", static_cast<uint8_t>(vote.type)},
        {"h", vote.block_height},
        {"g", static_cast<uint8_t>(vote.group)},
        {"i", vote.index_in_group},
        {"s", std::string{reinterpret_cast<const char *>(&vote.signature), sizeof(vote.signature)}},
    };
    if (vote.type == quorum_type::checkpointing)
        result["bh"] = std::string{vote.checkpoint.block_hash.data, sizeof(crypto::hash)};
    else {
        result["wi"] = vote.state_change.worker_index;
        result["sc"] = static_cast<std::underlying_type_t<new_state>>(vote.state_change.state);
    }
    return result;
}

static quorum_vote_t deserialize_vote(const bt_dict &d) {
    quorum_vote_t vote;
    vote.version = get_int<uint8_t>(d.at("v"));
    vote.type = get_enum(d, "t", quorum_type::count);
    vote.block_height = get_int<uint64_t>(d.at("h"));
    vote.group = get_enum(d, "g", quorum_group::count);
    if (vote.group == quorum_group::invalid) throw std::invalid_argument("invalid vote group");
    vote.index_in_group = get_int<uint16_t>(d.at("i"));
    auto &sig = boost::get<std::string>(d.at("s"));
    if (sig.size() != sizeof(vote.signature)) throw std::invalid_argument("invalid vote signature size");
    std::memcpy(&vote.signature, sig.data(), sizeof(vote.signature));
    if (vote.type == quorum_type::checkpointing) {
        auto &bh = boost::get<std::string>(d.at("bh"));
        if (bh.size() != sizeof(vote.checkpoint.block_hash.data)) throw std::invalid_argument("invalid vote checkpoint block hash");
        std::memcpy(vote.checkpoint.block_hash.data, bh.data(), sizeof(vote.checkpoint.block_hash.data));
    } else {
        vote.state_change.worker_index = get_int<uint16_t>(d.at("wi"));
        get_enum(d, "sc", new_state::_count);
    }

    return vote;
}

static const std::vector<crypto::public_key> &quorum_voter_list(quorum_type t, const service_nodes::testing_quorum &q) {
    return t == quorum_type::checkpointing ? q.workers : q.validators;
}

static void relay_votes(void *obj, const std::vector<service_nodes::quorum_vote_t> &votes) {
    auto &snw = *reinterpret_cast<SNNWrapper *>(obj);

        MDEBUG("hi");
    auto my_keys_ptr = snw.core.get_service_node_keys();
    assert(my_keys_ptr);
    const auto &my_keys = *my_keys_ptr;

        MDEBUG("hi");
    // Loop twice: the first time we build up the set of remotes we need for all votes; then we look
    // up their proofs -- which requires a potentially expensive lock -- to get the x25519 pubkey
    // and port from the proof; then we do the sending in the second loop.
    std::unordered_set<crypto::public_key> need_remotes;
    std::vector<std::tuple<int, const service_nodes::quorum_vote_t *, const std::vector<crypto::public_key> *>> valid_votes;
    valid_votes.reserve(votes.size());
    for (auto &v : votes) {
        auto quorum = snw.sn_list.get_testing_quorum(v.type, v.block_height);

        if (!quorum) {
            MWARNING("Unable to relay vote: no testing quorum vote for type " << v.type << " @ height " << v.block_height);
            continue;
        }

        MDEBUG("hi");
        auto &quorum_voters = quorum_voter_list(v.type, *quorum);
        MDEBUG("hi");
        if (quorum_voters.size() < service_nodes::min_votes_for_quorum_type(v.type)) {
            MWARNING("Invalid vote relay: " << v.type << " quorum @ height " << v.block_height <<
                    " does not have enough validators (" << quorum_voters.size() << ") to reach the minimum required votes ("
                    << service_nodes::min_votes_for_quorum_type(v.type) << ")");
        }
        MDEBUG("hi");

        int my_pos = service_nodes::find_index_in_quorum_group(quorum_voters, my_keys);
        MDEBUG("hi");
        if (my_pos < 0) {
            MWARNING("Invalid vote relay: vote to relay does not include this service node");
            MTRACE("me: " << my_keys.pub);
            for (const auto &v : quorum->validators)
                MTRACE("validator: " << v);
            for (const auto &v : quorum->workers)
                MTRACE("worker: " << v);
            continue;
        }
        MDEBUG("hi");

        for (int i : quorumnet::quorum_outgoing_conns(my_pos, quorum_voters.size()))
            need_remotes.insert(quorum_voters[i]);

        MDEBUG("hi z");
        valid_votes.emplace_back(my_pos, &v, &quorum_voters);
        MDEBUG("hi zz");
    }

    MDEBUG("Relaying " << valid_votes.size() << " votes");
    if (valid_votes.empty())
        return;

    // pubkey => {x25519_pubkey, connect_string}
    std::unordered_map<crypto::public_key, std::pair<crypto::x25519_public_key, std::string>> remotes;
    snw.sn_list.for_each_service_node_info(need_remotes.begin(), need_remotes.end(),
        [&remotes](const crypto::public_key &pubkey, const service_nodes::service_node_info &info) {
            if (!info.is_active()) return;
            auto &proof = *info.proof;
            if (!proof.pubkey_x25519 || !proof.quorumnet_port || !proof.public_ip) return;
            remotes.emplace(pubkey,
                std::make_pair(proof.pubkey_x25519, "tcp://" + epee::string_tools::get_ip_string_from_int32(proof.public_ip) + ":" + std::to_string(proof.quorumnet_port)));
        });

    for (auto &vote_data : valid_votes) {
        int my_pos = std::get<0>(vote_data);
        auto &vote = *std::get<1>(vote_data);
        auto &quorum_voters = *std::get<2>(vote_data);

        bt_dict vote_to_send = serialize_vote(vote);

        for (int i : quorumnet::quorum_outgoing_conns(my_pos, quorum_voters.size())) {
            auto it = remotes.find(quorum_voters[i]);
            if (it == remotes.end()) {
                MINFO("Unable to relay vote to peer " << quorum_voters[i] << ": peer is inactive or we are missing a x25519 pubkey and/or quorumnet port");
                continue;
            }

            auto &remote_info = it->second;
            std::string x25519_pubkey{reinterpret_cast<const char *>(remote_info.first.data), sizeof(crypto::x25519_public_key)};
            MDEBUG("Relaying vote to peer " << remote_info.first << " @ " << remote_info.second);
            snw.snn.send_hint(x25519_pubkey, remote_info.second, "vote", vote_to_send);
        }
    }
}

void handle_vote(SNNetwork::message &m, void *self) {
    auto &snw = *reinterpret_cast<SNNWrapper *>(self);

    MDEBUG("Received a relayed vote from " << as_hex(m.pubkey));

    try {
        quorum_vote_t vote = deserialize_vote(m.data);

        if (vote.block_height > snw.core.get_current_blockchain_height()) {
            MDEBUG("Ignoring vote: block height " << vote.block_height << " is too high");
            return;
        }

        cryptonote::vote_verification_context vvc = {};
        snw.core.add_service_node_vote(vote, vvc);
        if (vvc.m_verification_failed)
        {
            MWARNING("Vote verification failed; ignoring vote");
            return;
        }

        if (vvc.m_added_to_pool)
            relay_votes(self, {{vote}});
    }
    catch (const std::exception &e) {
        MWARNING("Deserialization of vote from " << as_hex(m.pubkey) << " failed: " << e.what());
    }
}

/// Sets the cryptonote::quorumnet_* function pointers (allowing core to avoid linking to
/// cryptonote_protocol).  Called from daemon/daemon.cpp.  Also registers quorum command callbacks.
void init_core_callbacks() {
    cryptonote::quorumnet_new = new_snnwrapper;
    cryptonote::quorumnet_delete = delete_snnwrapper;
    cryptonote::quorumnet_relay_votes = relay_votes;

    SNNetwork::register_quorum_command("vote", handle_vote);
}

}

