// Copyright (c) 2019-2020, The Loki Project
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
#include "cryptonote_core/tx_blink.h"
#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/pulse.h"
#include "quorumnet_conn_matrix.h"
#include "cryptonote_config.h"
#include "common/random.h"

#include <lokimq/lokimq.h>
#include <lokimq/hex.h>
#include <shared_mutex>
#include <iterator>
#include <time.h>

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "qnet"

namespace quorumnet {

namespace {

using namespace service_nodes;
using namespace lokimq;

using blink_tx = cryptonote::blink_tx;

constexpr auto NUM_BLINK_QUORUMS = tools::enum_count<blink_tx::subquorum>;
static_assert(std::is_same<const uint8_t, decltype(NUM_BLINK_QUORUMS)>(), "unexpected underlying blink quorum count type");

using quorum_array = std::array<std::shared_ptr<const service_nodes::quorum>, NUM_BLINK_QUORUMS>;

using pending_signature = std::tuple<bool, uint8_t, int, crypto::signature>; // approval, subquorum, subquorum position, signature

struct pending_signature_hash {
    size_t operator()(const pending_signature &s) const { return std::get<uint8_t>(s) + std::hash<crypto::signature>{}(std::get<crypto::signature>(s)); }
};

using pending_signature_set = std::unordered_set<pending_signature, pending_signature_hash>;

struct QnetState {
    cryptonote::core &core;
    LokiMQ &lmq{core.get_lmq()};

    // Track submitted blink txes here; unlike the blinks stored in the mempool we store these ones
    // more liberally to track submitted blinks, even if unsigned/unacceptable, while the mempool
    // only stores approved blinks.
    std::shared_mutex mutex;

    struct blink_metadata {
        std::shared_ptr<blink_tx> btxptr;
        pending_signature_set pending_sigs;
        ConnectionID reply_conn;
        uint64_t reply_tag = 0;
    };
    // { height => { txhash => {blink_tx,conn,reply}, ... }, ... }
    std::map<uint64_t, std::unordered_map<crypto::hash, blink_metadata>> blinks;

    // FIXME:
    //std::chrono::steady_clock::time_point last_blink_cleanup = std::chrono::steady_clock::now();

    std::mutex pulse_message_queue_mutex;
    std::condition_variable pulse_message_queue_cv;
    std::queue<pulse::message> pulse_message_queue;

    QnetState(cryptonote::core &core) : core{core} {}

    static QnetState &from(void* obj) {
        assert(obj);
        return *reinterpret_cast<QnetState*>(obj);
    }
};

template <typename T>
std::string get_data_as_string(const T &key) {
    static_assert(std::is_trivial<T>(), "cannot safely copy non-trivial class to string");
    return {reinterpret_cast<const char *>(&key), sizeof(key)};
}

crypto::x25519_public_key x25519_from_string(std::string_view pubkey) {
    crypto::x25519_public_key x25519_pub = crypto::x25519_public_key::null();
    if (pubkey.size() == sizeof(crypto::x25519_public_key))
        std::memcpy(x25519_pub.data, pubkey.data(), pubkey.size());
    return x25519_pub;
}

void setup_endpoints(cryptonote::core& core, void* obj);

void *new_qnetstate(cryptonote::core& core) {
    return new QnetState(core);
}

void delete_qnetstate(void *&obj) {
    auto* qnet = static_cast<QnetState*>(obj);
    delete qnet;
    obj = nullptr;
}


template <typename E>
#ifdef __GNUG__
[[gnu::warn_unused_result]]
#endif
E get_enum(const bt_dict &d, const std::string &key) {
    E result = static_cast<E>(get_int<std::underlying_type_t<E>>(d.at(key)));
    if (result < E::_count)
        return result;
    throw std::invalid_argument("invalid enum value for field " + key);
}

struct prepared_relay_destinations
{
  std::string x25519_string;
  std::string connect_string;
};

// Relay data to a random subset of the quorum up to num_peers. If the sender is
// a validator in the quorum, prefer peer_info to get a fully connected relay
// with redundancy.
// Returns the number of peers it actually prepared relay destinations.
template <typename It>
std::vector<prepared_relay_destinations>
peer_prepare_relay_to_quorum_subset(cryptonote::core &core, It quorum_begin, It quorum_end, size_t num_peers) {
    // Lookup the x25519 and ZMQ connection string for all possible blink recipients so that we
    // know where to send it to, and so that we can immediately exclude SNs that aren't active
    // anymore.
    std::unordered_set<crypto::public_key> candidates;
    for (auto it = quorum_begin; it != quorum_end; it++)
      candidates.insert((*it)->validators.begin(), (*it)->validators.end());

    MDEBUG("Have " << candidates.size() << " SN candidates");

    std::vector<std::tuple<std::string, std::string, decltype(proof_info{}.version)>> remotes; // {x25519 pubkey, connect string, version}
    remotes.reserve(candidates.size());
    core.get_service_node_list().for_each_service_node_info_and_proof(candidates.begin(), candidates.end(),
        [&remotes](const auto &pubkey, const auto &info, const auto &proof) {
            if (!info.is_active()) {
                MTRACE("Not include inactive node " << pubkey);
                return;
            }
            if (!proof.pubkey_x25519 || !proof.quorumnet_port || !proof.public_ip) {
                MTRACE("Not including node " << pubkey << ": missing x25519(" << to_hex(get_data_as_string(proof.pubkey_x25519)) << "), "
                        "public_ip(" << epee::string_tools::get_ip_string_from_int32(proof.public_ip) << "), or qnet port(" << proof.quorumnet_port << ")");
                return;
            }
            remotes.emplace_back(get_data_as_string(proof.pubkey_x25519),
                    "tcp://" + epee::string_tools::get_ip_string_from_int32(proof.public_ip) + ":" + std::to_string(proof.quorumnet_port),
                    proof.version);
        });

    // Select 4 random SNs to send the data to, but prefer SNs with newer versions because they may have network fixes.
    MDEBUG("Have " << remotes.size() << " candidates after checking active status and connection details");
    std::vector<size_t> indices(remotes.size());
    std::iota(indices.begin(), indices.end(), 0);
    std::shuffle(indices.begin(), indices.end(), tools::rng);

    // Stable sort by version so that we keep the shuffled order within a version
    using std::get;
    std::stable_sort(indices.begin(), indices.end(), [&remotes](size_t a, size_t b) {
        return get<2>(remotes[a]) > get<2>(remotes[b]); });

    if (indices.size() > num_peers)
        indices.resize(num_peers);

    std::vector<prepared_relay_destinations> result;
    result.reserve(indices.size());

    for (size_t i : indices)
      result.push_back({std::move(get<0>(remotes[i])), std::move(get<1>(remotes[i]))});
    return result;
}

void peer_relay_to_prepared_destinations(cryptonote::core &core, std::vector<prepared_relay_destinations> const &destinations, std::string_view command, std::string &&data)
{
    for (auto const &[x25519_string, connect_string]: destinations) {
        MINFO("Relaying data to " << to_hex(x25519_string) << " @ " << connect_string);
        core.get_lmq().send(x25519_string, command, std::move(data), send_option::hint{connect_string});
    }
}


/// Helper class to calculate and relay to peers of quorums.
///
/// TODO: add a wrapper that caches this so that looking up the same quorum peers within a certain
/// amount of time doesn't need to recalculate.
class peer_info {
public:
    using exclude_set = std::unordered_set<crypto::public_key>;

    /// Maps pubkeys to x25519 pubkeys and zmq connection strings
    std::unordered_map<crypto::public_key, std::pair<crypto::x25519_public_key, std::string>> remotes;
    /// Stores the x25519 string pubkeys to either zmq connection strings (for a "strong"
    /// connection) or empty strings (for an opportunistic "weak" connection).
    std::unordered_map<std::string /*x25519 pubkey*/, std::string /*conn location*/> peers;
    /// The number of strong peers, that is, the count of `peers` that has a non-empty second value.
    /// Will be the same as `peers.count()` if opportunistic connections are disabled.
    int strong_peers;
    /// The caller's positions in the given quorum(s), -1 if not found
    std::vector<int> my_position;
    /// The number of actual positions found in my_position (i.e. the number of elements of
    /// `my_position` not equal to -1).
    int my_position_count;

    /// Singleton wrapper around peer_info
    peer_info(
            QnetState& qnet,
            quorum_type q_type,
            const quorum *quorum,
            bool opportunistic = true,
            exclude_set exclude = {},
            bool include_workers = false
            )
        : peer_info(qnet, q_type, &quorum, &quorum + 1, opportunistic, std::move(exclude), include_workers) {}

    /// Constructs peer information for the given quorums and quorum position of the caller.
    /// \param qnet - the QnetState reference
    /// \param q_type - the type of quorum
    /// \param qbegin, qend - the iterators to a set of pointers (or other deferenceable type) to quorums
    /// \param opportunistic - if true then the peers to relay will also attempt to relay to any
    ///     incoming peers *if* those peers are already connected when the message is relayed.
    /// \param exclude - can be specified as a set of peers that should be excluded from the peer
    ///     list.  Typically for peers that we already know have the relayed information.  This SN's
    ///     pubkey is always added to this exclude list.
    template <typename QuorumIt>
    peer_info(
            QnetState& qnet,
            quorum_type q_type,
            QuorumIt qbegin, QuorumIt qend,
            bool opportunistic = true,
            std::unordered_set<crypto::public_key> exclude = {},
            bool include_workers = false
            )
    : lmq{qnet.lmq} {

        const auto& keys = qnet.core.get_service_keys();
        assert(qnet.core.service_node());
        const auto &my_pubkey = keys.pub;
        exclude.insert(keys.pub);

        // - Find my position(s) in the quorum(s)
        // - Build a list of all other quorum members so we can look them all up at once (i.e. to
        //   lock the required lookup mutex only once).
        my_position_count = 0;
        std::unordered_set<crypto::public_key> need_remotes;
        for (auto qit = qbegin; qit != qend; ++qit) {
            auto &v = (*qit)->validators;
            int my_pos = -1;
            for (size_t i = 0; i < v.size(); i++) {
                if (v[i] == my_pubkey) my_pos = static_cast<int>(i);
                else if (!exclude.count(v[i]))
                    need_remotes.insert(v[i]);
            }
            my_position.push_back(my_pos);
            if (my_pos >= 0) my_position_count++;

            if (include_workers) {
                auto &w = (*qit)->workers;
                for (size_t i = 0; i < w.size(); i++) {
                    if (!exclude.count(w[i])) need_remotes.insert(w[i]);
                }
            }
        }

        // Lookup the x25519 and ZMQ connection string for all peers
        qnet.core.get_service_node_list().for_each_service_node_info_and_proof(need_remotes.begin(), need_remotes.end(),
            [this](const auto &pubkey, const auto &info, const auto &proof) {
              if (info.is_active() && proof.pubkey_x25519 && proof.quorumnet_port && proof.public_ip)
                remotes.emplace(pubkey, std::make_pair(proof.pubkey_x25519,
                    "tcp://" + epee::string_tools::get_ip_string_from_int32(proof.public_ip) + ":" + std::to_string(proof.quorumnet_port)));
            });

        compute_validator_peers(qbegin, qend, opportunistic);

        if (include_workers) {
            for (auto qit = qbegin; qit != qend; ++qit) {
                auto &w = (*qit)->workers;
                for (size_t i = 0; i < w.size(); i++)
                    add_peer(w[i]);
            }
        }
    }

    /// Relays a command and any number of serialized data to everyone we're supposed to relay to
    template <typename... T>
    void relay_to_peers(const std::string_view &cmd, const T &...data) {
        relay_to_peers_impl(cmd, std::array<std::string, sizeof...(T)>{bt_serialize(data)...},
                std::make_index_sequence<sizeof...(T)>{});
    }

private:
    LokiMQ &lmq;

    /// Looks up a pubkey in known remotes and adds it to `peers`.  If strong, it is added with an
    /// address, otherwise it is added with an empty address.  If the element already exists, it
    /// will be updated *if* it the existing entry is weak and `strong` is true, otherwise it will
    /// be left as is.  Returns true if a new entry was created or a weak entry was upgraded.
    bool add_peer(const crypto::public_key &pubkey, bool strong = true) {
        auto it = remotes.find(pubkey);
        if (it != remotes.end()) {
            std::string remote_addr = strong ? it->second.second : ""s;
            auto ins = peers.emplace(get_data_as_string(it->second.first), std::move(remote_addr));
            if (strong && !ins.second && ins.first->second.empty()) {
                ins.first->second = it->second.second;
                strong_peers++;
                return true; // Upgraded weak to strong
            }
            if (strong && ins.second)
                strong_peers++;

            return ins.second;
        }
        return false;
    }

    // Build a map of x25519 keys -> connection strings of all our quorum peers we talk to; the
    // connection string is non-empty only for *strong* peer (i.e. one we should connect to if not
    // already connected) and empty if it's an opportunistic peer (i.e. only send along if we already
    // have a connection).
    template <typename QuorumIt>
    void compute_validator_peers(QuorumIt qbegin, QuorumIt qend, bool opportunistic) {

        // TODO: when we receive a new block, if our quorum starts soon we can tell SNNetwork to
        // pre-connect (to save the time in handshaking when we get an actual blink tx).

        strong_peers = 0;

        size_t i = 0;
        for (QuorumIt qit = qbegin; qit != qend; ++i, ++qit) {
            if (my_position[i] < 0) {
                MTRACE("Not in subquorum " << (i == 0 ? "Q" : "Q'"));
                continue;
            } else {
                MTRACE("I am in subquorum " << (i == 0 ? "Q" : "Q'") << " position " << my_position[i]);
            }

            auto &validators = (*qit)->validators;

            // Relay to all my outgoing targets within the quorum (connecting if not already connected)
            for (int j : quorum_outgoing_conns(my_position[i], validators.size())) {
                if (add_peer(validators[j]))
                    MTRACE("Relaying within subquorum " << (i == 0 ? "Q" : "Q'") << "[" << my_position[i] << "] to [" << j << "] " << validators[j]);
            }

            // Opportunistically relay to all my *incoming* sources within the quorum *if* I already
            // have a connection open with them, but don't open a new connection if I don't.
            for (int j : quorum_incoming_conns(my_position[i], validators.size())) {
                if (add_peer(validators[j], false /*!strong*/))
                    MTRACE("Optional opportunistic relay within quorum " << (i == 0 ? "Q" : "Q'") << "[" << my_position[i] << "] to [" << j << "] " << validators[j]);
            }

            // Now establish strong interconnections between quorums, if we have multiple subquorums
            // (i.e.  blink quorums).
            //
            // If I'm in the last half* of the first quorum then I relay to the first half (roughly) of
            // the next quorum.  i.e. nodes 5-9 in Q send to nodes 0-4 in Q'.  For odd numbers the last
            // position gets left out (e.g. for 9 members total we would have 0-3 talk to 4-7 and no one
            // talks to 8).
            //
            // (* - half here means half the size of the smaller quorum)
            //
            // We also skip this entirely if this SN is in both quorums since then we're already
            // relaying to nodes in the next quorum.  (Ideally we'd do the same if the recipient is in
            // both quorums, but that's harder to figure out and so the special case isn't worth
            // worrying about).
            QuorumIt qnext = std::next(qit);
            if (qnext != qend && my_position[i + 1] < 0) {
                auto &next_validators = (*qnext)->validators;
                int half = std::min<int>(validators.size(), next_validators.size()) / 2;
                if (my_position[i] >= half && my_position[i] < half*2) {
                    int next_pos = my_position[i] - half;
                    bool added = add_peer(next_validators[next_pos]);
                    MTRACE("Inter-quorum relay from Q[" << my_position[i] << "] (me) to Q'[" << next_pos << "] = " << next_validators[next_pos]
                            << (added ? "" : " (skipping; already relaying to that SN)"));
                } else {
                    MTRACE("Q[" << my_position[i] << "] is not a Q -> Q' inter-quorum relay position");
                }
            } else if (qnext != qend) {
                MTRACE("Not doing inter-quorum relaying because I am in both quorums (Q[" << my_position[i] << "], Q'[" << my_position[i+1] << "])");
            }

            // Exactly the same connections as above, but in reverse: the first half of Q' sends to
            // the second half of Q.  Typically this will end up reusing an already open connection,
            // but if there isn't such an open connection then we establish a new one.
            if (qit != qbegin && my_position[i - 1] < 0) {
                auto &prev_validators = (*std::prev(qit))->validators;
                int half = std::min<int>(validators.size(), prev_validators.size()) / 2;
                if (my_position[i] < half) {
                    int prev_pos = half + my_position[i];
                    bool added = add_peer(prev_validators[prev_pos]);
                    MTRACE("Inter-quorum relay from Q'[" << my_position[i] << "] (me) to Q[" << prev_pos << "] = " << prev_validators[prev_pos]
                            << (added ? "" : " (already relaying to that SN)"));
                } else {
                    MTRACE("Q'[" << my_position[i] << "] is not a Q' -> Q inter-quorum relay position");
                }
            } else if (qit != qbegin) {
                MTRACE("Not doing inter-quorum relaying because I am in both quorums (Q[" << my_position[i-1] << "], Q'[" << my_position[i] << "])");
            }
        }
    }

    /// Relays a command and pre-serialized data to everyone we're supposed to relay to
    template<size_t N, size_t... I>
    void relay_to_peers_impl(const std::string_view &cmd, std::array<std::string, N> relay_data, std::index_sequence<I...>) {
        for (auto &peer : peers) {
            MTRACE("Relaying " << cmd << " to peer " << to_hex(peer.first) << (peer.second.empty() ? " (if connected)"s : " @ " + peer.second));
            if (peer.second.empty())
                lmq.send(peer.first, cmd, relay_data[I]..., send_option::optional{});
            else
                lmq.send(peer.first, cmd, relay_data[I]..., send_option::hint{peer.second});
        }
    }

};


bt_dict serialize_vote(const quorum_vote_t &vote) {
    bt_dict result{
        {"v", vote.version},
        {"t", static_cast<uint8_t>(vote.type)},
        {"h", vote.block_height},
        {"g", static_cast<uint8_t>(vote.group)},
        {"i", vote.index_in_group},
        {"s", get_data_as_string(vote.signature)},
    };
    if (vote.type == quorum_type::checkpointing)
        result["bh"] = std::string{vote.checkpoint.block_hash.data, sizeof(crypto::hash)};
    else {
        result["wi"] = vote.state_change.worker_index;
        result["sc"] = static_cast<std::underlying_type_t<new_state>>(vote.state_change.state);
    }
    return result;
}

quorum_vote_t deserialize_vote(std::string_view v) {
    const auto &d = bt_deserialize<bt_dict>(v); // throws if not a bt_dict
    quorum_vote_t vote;
    vote.version = get_int<uint8_t>(d.at("v"));
    vote.type = get_enum<quorum_type>(d, "t");
    vote.block_height = get_int<uint64_t>(d.at("h"));
    vote.group = get_enum<quorum_group>(d, "g");
    if (vote.group == quorum_group::invalid) throw std::invalid_argument("invalid vote group");
    vote.index_in_group = get_int<uint16_t>(d.at("i"));
    auto &sig = var::get<std::string>(d.at("s"));
    if (sig.size() != sizeof(vote.signature)) throw std::invalid_argument("invalid vote signature size");
    std::memcpy(&vote.signature, sig.data(), sizeof(vote.signature));
    if (vote.type == quorum_type::checkpointing) {
        auto &bh = var::get<std::string>(d.at("bh"));
        if (bh.size() != sizeof(vote.checkpoint.block_hash.data)) throw std::invalid_argument("invalid vote checkpoint block hash");
        std::memcpy(vote.checkpoint.block_hash.data, bh.data(), sizeof(vote.checkpoint.block_hash.data));
    } else {
        vote.state_change.worker_index = get_int<uint16_t>(d.at("wi"));
        vote.state_change.state = get_enum<new_state>(d, "sc");
    }

    return vote;
}

void relay_obligation_votes(void *obj, const std::vector<service_nodes::quorum_vote_t> &votes) {
    auto &qnet = QnetState::from(obj);

    const auto& my_keys = qnet.core.get_service_keys();
    assert(qnet.core.service_node());

    MDEBUG("Starting relay of " << votes.size() << " votes");
    std::vector<service_nodes::quorum_vote_t> relayed_votes;
    relayed_votes.reserve(votes.size());
    for (auto &vote : votes) {
        if (vote.type != quorum_type::obligations) {
            MERROR("Internal logic error: quorumnet asked to relay a " << vote.type << " vote, but should only be called with obligations votes");
            continue;
        }

        auto quorum = qnet.core.get_service_node_list().get_quorum(vote.type, vote.block_height);
        if (!quorum) {
            MWARNING("Unable to relay vote: no " << vote.type << " quorum available for height " << vote.block_height);
            continue;
        }

        auto &quorum_voters = quorum->validators;
        if (quorum_voters.size() < service_nodes::min_votes_for_quorum_type(vote.type)) {
            MWARNING("Invalid vote relay: " << vote.type << " quorum @ height " << vote.block_height <<
                    " does not have enough validators (" << quorum_voters.size() << ") to reach the minimum required votes ("
                    << service_nodes::min_votes_for_quorum_type(vote.type) << ")");
            continue;
        }

        peer_info pinfo{qnet, vote.type, quorum.get()};
        if (!pinfo.my_position_count) {
            MWARNING("Invalid vote relay: vote to relay does not include this service node");
            continue;
        }

        pinfo.relay_to_peers("quorum.vote_ob", serialize_vote(vote));
        relayed_votes.push_back(vote);
    }
    MDEBUG("Relayed " << relayed_votes.size() << " votes");
    qnet.core.set_service_node_votes_relayed(relayed_votes);
}

void handle_obligation_vote(Message& m, QnetState& qnet) {
    MDEBUG("Received a relayed obligation vote from " << to_hex(m.conn.pubkey()));

    if (m.data.size() != 1) {
        MINFO("Ignoring vote: expected 1 data part, not " << m.data.size());
        return;
    }

    try {
        std::vector<quorum_vote_t> vvote;
        vvote.push_back(deserialize_vote(m.data[0]));
        auto& vote = vvote.back();

        if (vote.type != quorum_type::obligations) {
            MWARNING("Received invalid non-obligations vote via quorumnet; ignoring");
            return;
        }
        if (vote.block_height > qnet.core.get_current_blockchain_height()) {
            MDEBUG("Ignoring vote: block height " << vote.block_height << " is too high");
            return;
        }

        cryptonote::vote_verification_context vvc{};
        qnet.core.add_service_node_vote(vote, vvc);
        if (vvc.m_verification_failed)
        {
            MWARNING("Vote verification failed; ignoring vote");
            return;
        }

        if (vvc.m_added_to_pool)
            relay_obligation_votes(&qnet, std::move(vvote));
    }
    catch (const std::exception &e) {
        MWARNING("Deserialization of vote from " << to_hex(m.conn.pubkey()) << " failed: " << e.what());
    }
}

void handle_timestamp(Message& m) {
    MDEBUG("Received a timestamp request from " << to_hex(m.conn.pubkey()));
    const time_t seconds = time(nullptr);
    m.send_reply(std::to_string(seconds));
}

/// Gets an integer value out of a bt_dict, if present and fits (i.e. get_int<> succeeds); if not
/// present or conversion falls, returns `fallback`.
template <typename I>
std::enable_if_t<std::is_integral<I>::value, I> get_or(bt_dict &d, const std::string &key, I fallback) {
    auto it = d.find(key);
    if (it != d.end()) {
        try { return get_int<I>(it->second); }
        catch (...) {}
    }
    return fallback;
}

// Obtains the blink quorums, verifies that they are of an acceptable size, and verifies the given
// input quorum checksum matches the computed checksum for the quorums (if provided), otherwise sets
// the given output checksum (if provided) to the calculated value.  Throws std::runtime_error on
// failure.
quorum_array get_blink_quorums(uint64_t blink_height, const service_node_list &snl, const uint64_t *input_checksum, uint64_t *output_checksum = nullptr) {
    // We currently just use two quorums, Q and Q' in the whitepaper, but this code is designed to
    // work fine with more quorums (but don't use a single subquorum; that could only be secure or
    // reliable but not both).
    quorum_array result;

    uint64_t local_checksum = 0;
    for (uint8_t qi = 0; qi < NUM_BLINK_QUORUMS; qi++) {
        auto height = blink_tx::quorum_height(blink_height, static_cast<blink_tx::subquorum>(qi));
        if (!height)
            throw std::runtime_error("too early in blockchain to create a quorum");
        result[qi] = snl.get_quorum(quorum_type::blink, height);
        if (!result[qi])
            throw std::runtime_error("failed to obtain a blink quorum");
        auto &v = result[qi]->validators;
        if (v.size() < BLINK_MIN_VOTES || v.size() > BLINK_SUBQUORUM_SIZE)
            throw std::runtime_error("not enough blink nodes to form a quorum");
        local_checksum += quorum_checksum(v, qi * BLINK_SUBQUORUM_SIZE);
    }
    MTRACE("Verified enough active blink nodes for a quorum; quorum checksum: " << local_checksum);

    if (input_checksum) {
        if (*input_checksum != local_checksum)
            throw std::runtime_error("wrong quorum checksum: expected " + std::to_string(local_checksum) + ", received " + std::to_string(*input_checksum));

        MTRACE("Blink quorum checksum matched");
    }
    if (output_checksum)
        *output_checksum = local_checksum;

    return result;
}

// Used when debugging is enabled to print known signatures.
// Prints [x x x ...] [x x x ...] for the quorums where each "x" is either "A" for an approval
// signature, "R" for a rejection signature, or "-" for no signature.
std::string debug_known_signatures(blink_tx &btx, quorum_array &blink_quorums) {
    std::ostringstream os;
    bool first = true;
    for (uint8_t qi = 0; qi < blink_quorums.size(); qi++) {
        if (qi > 0) os << ' ';
        os << '[';
        const auto q = static_cast<blink_tx::subquorum>(qi);
        const int slots = blink_quorums[qi]->validators.size();
        for (int i = 0; i < slots; i++) {
            if (i > 0) os << ' ';
            auto st = btx.get_signature_status(q, i);
            os << (st == blink_tx::signature_status::approved ? 'A' : st == blink_tx::signature_status::rejected ? 'R' : '-');
        }
        os << ']';
    }
    return os.str();
}


/// Processes blink signatures; called immediately upon receiving a signature if we know about the
/// tx; otherwise signatures are stored until we learn about the tx and then processed.
void process_blink_signatures(QnetState &qnet, const std::shared_ptr<blink_tx> &btxptr, quorum_array &blink_quorums, uint64_t quorum_checksum, std::list<pending_signature> &&signatures,
        uint64_t reply_tag, // > 0 if we are expected to send a status update if it becomes accepted/rejected
        ConnectionID reply_conn, // who we are supposed to send the status update to
        const std::string &received_from = ""s /* x25519 of the peer that sent this, if available (to avoid trying to pointlessly relay back to them) */) {

    auto &btx = *btxptr;

    // First check values and discard any signatures for positions we already have.
    {
        auto lock = btx.shared_lock(); // Don't take out a heavier unique lock until later when we are sure we need
        for (auto it = signatures.begin(); it != signatures.end(); ) {
            auto &pending = *it;
            auto &qi = std::get<uint8_t>(pending);
            auto &position = std::get<int>(pending);

            auto subquorum = static_cast<blink_tx::subquorum>(qi);
            auto &validators = blink_quorums[qi]->validators;

            if (position < 0 || position >= (int) validators.size()) {
                MWARNING("Invalid blink signature: subquorum position is invalid");
                it = signatures.erase(it);
            } else if (btx.get_signature_status(subquorum, position) != blink_tx::signature_status::none) {
                it = signatures.erase(it);
            } else {
                ++it;
            }
        }
    }
    if (signatures.empty())
        return;

    // Now check and discard any invalid signatures (we can do this without holding a lock)
    for (auto it = signatures.begin(); it != signatures.end(); ) {
        auto &pending = *it;
        auto &approval = std::get<bool>(pending);
        auto &qi = std::get<uint8_t>(pending);
        auto &position = std::get<int>(pending);
        auto &signature = std::get<crypto::signature>(pending);

        auto subquorum = static_cast<blink_tx::subquorum>(qi);
        auto &validators = blink_quorums[qi]->validators;

        if (!crypto::check_signature(btx.hash(approval), validators[position], signature)) {
            MWARNING("Invalid blink signature: signature verification failed");
            it = signatures.erase(it);
            continue;
        }
        ++it;
    }

    if (signatures.empty())
        return;

    bool became_approved = false, became_rejected = false;
    {
        auto lock = btx.unique_lock();

        bool already_approved = btx.approved(),
             already_rejected = !already_approved && btx.rejected();

        MTRACE("Before recording new signatures I have existing signatures: " << debug_known_signatures(btx, blink_quorums));

        // Now actually add them (and do one last check on them)
        for (auto it = signatures.begin(); it != signatures.end(); ) {
            auto &pending = *it;
            auto &approval = std::get<bool>(pending);
            auto &qi = std::get<uint8_t>(pending);
            auto &position = std::get<int>(pending);
            auto &signature = std::get<crypto::signature>(pending);

            auto subquorum = static_cast<blink_tx::subquorum>(qi);
            auto &validators = blink_quorums[qi]->validators;

            if (btx.add_prechecked_signature(subquorum, position, approval, signature)) {
                MDEBUG("Validated and stored " << (approval ? "approval" : "rejection") << " signature for tx " << btx.get_txhash() << ", subquorum " << int{qi} << ", position " << position);
                ++it;
            }
            else {
                // Signature already present, which means it got added between the check above and now
                // by another thread.
                it = signatures.erase(it);
            }
        }

        if (!signatures.empty()) {
            MDEBUG("Updated signatures; now have signatures: " << debug_known_signatures(btx, blink_quorums));

            if (!already_approved && !already_rejected) {
                if (btx.approved()) {
                    became_approved = true;
                } else if (btx.rejected()) {
                    became_rejected = true;
                }
            }
        }
    }

    if (became_approved) {
        MINFO("Accumulated enough signatures for blink tx: enabling tx relay");
        auto &pool = qnet.core.get_pool();
        {
            auto lock = pool.blink_unique_lock();
            pool.add_existing_blink(btxptr);
        }
        pool.set_relayable({{btx.get_txhash()}});
        qnet.core.relay_txpool_transactions();
    }

    if (signatures.empty())
        return;

    peer_info::exclude_set relay_exclude;
    if (!received_from.empty()) {
        auto pubkey = qnet.core.get_service_node_list().get_pubkey_from_x25519(x25519_from_string(received_from));
        if (pubkey)
            relay_exclude.insert(std::move(pubkey));
    }

    // We added new signatures that we didn't have before, so relay those signatures to blink peers
    peer_info pinfo{qnet, quorum_type::blink, blink_quorums.begin(), blink_quorums.end(), true /*opportunistic*/,
        std::move(relay_exclude)};

    MDEBUG("Relaying " << signatures.size() << " blink signatures to " << pinfo.strong_peers << " (strong) + " <<
            (pinfo.peers.size() - pinfo.strong_peers) << " (opportunistic) blink peers");

    bt_list i_list, p_list, r_list, s_list;
    for (auto &s : signatures) {
        i_list.emplace_back(std::get<uint8_t>(s));
        p_list.emplace_back(std::get<int>(s));
        r_list.emplace_back(std::get<bool>(s));
        s_list.emplace_back(get_data_as_string(std::get<crypto::signature>(s)));
    }

    bt_dict blink_sign_data{
        {"h", btx.height},
        {"#", get_data_as_string(btx.get_txhash())},
        {"q", quorum_checksum},
        {"i", std::move(i_list)},
        {"p", std::move(p_list)},
        {"r", std::move(r_list)},
        {"s", std::move(s_list)},
    };

    pinfo.relay_to_peers("quorum.blink_sign", blink_sign_data);

    MTRACE("Done blink signature relay");

    if (reply_tag && reply_conn) {
        if (became_approved) {
            MINFO("Blink tx became approved; sending result back to originating node");
            qnet.lmq.send(reply_conn, "bl.good", bt_serialize(bt_dict{{"!", reply_tag}}), send_option::optional{});
        } else if (became_rejected) {
            MINFO("Blink tx became rejected; sending result back to originating node");
            qnet.lmq.send(reply_conn, "bl.bad", bt_serialize(bt_dict{{"!", reply_tag}}), send_option::optional{});
        }
    }
}



/// A "blink" message is used to submit a blink tx from a node to members of the blink quorum and
/// also used to relay the blink tx between quorum members.  Fields are:
///
///     "!" - Non-zero positive integer value for a connecting node; we include the tag in any
///           response if present so that the initiator can associate the response to the request.
///           If there is no tag then there will be no success/error response.  Only included in
///           node-to-SN submission but not SN-to-SN relaying (which doesn't return a response
///           message).
///
///     "h" - Blink authorization height for the transaction.  Must be within 2 of the current
///           height for the tx to be accepted.  Mandatory.
///
///     "q" - checksum of blink quorum members.  Mandatory, and must match the receiving SN's
///           locally computed checksum of blink quorum members.
///
///     "t" - the serialized transaction data.
///
///     "#" - precomputed tx hash.  This much match the actual hash of the transaction (the blink
///           submission will fail immediately if it does not).
///
void handle_blink(lokimq::Message& m, QnetState& qnet) {
    // TODO: if someone sends an invalid tx (i.e. one that doesn't get to the distribution stage)
    // then put a timeout on that IP during which new submissions from them are dropped for a short
    // time.
    // If an incoming connection:
    // - We can refuse new connections from that IP in the ZAP handler
    // - We can (somewhat hackily) disconnect by getting the raw fd via the SRCFD property of the
    //   message and close it.
    // If an outgoing connection - refuse reconnections via ZAP and just close it.

    MDEBUG("Received a blink tx from " << (m.conn.sn() ? "SN " : "non-SN ") << to_hex(m.conn.pubkey()));

    assert(qnet.core.service_node());
    if (!qnet.core.service_node())
        return;
    const auto& keys = qnet.core.get_service_keys();

    if (m.data.size() != 1) {
        MINFO("Rejecting blink message: expected one data entry not " << m.data.size());
        // No valid data and so no reply tag; we can't send a response
        return;
    }
    auto data = bt_deserialize<bt_dict>(m.data[0]);

    auto tag = get_or<uint64_t>(data, "!", 0);

    auto hf_version = qnet.core.get_blockchain_storage().get_current_hard_fork_version();
    if (hf_version < HF_VERSION_BLINK) {
        MWARNING("Rejecting blink message: blink is not available for hardfork " << (int) hf_version);
        if (tag)
            m.send_back("bl.nostart", bt_serialize(bt_dict{{"!", tag}, {"e", "Invalid blink authorization height"sv}}));
        return;
    }

    // verify that height is within-2 of current height
    auto blink_height = get_int<uint64_t>(data.at("h"));
    auto local_height = qnet.core.get_current_blockchain_height();

    if (blink_height < local_height - 2) {
        MINFO("Rejecting blink tx because blink auth height is too low (" << blink_height << " vs. " << local_height << ")");
        if (tag)
            m.send_back("bl.nostart", bt_serialize(bt_dict{{"!", tag}, {"e", "Invalid blink authorization height"sv}}));
        return;
    } else if (blink_height > local_height + 2) {
        // TODO: if within some threshold (maybe 5-10?) we could hold it and process it once we are
        // within 2.
        MINFO("Rejecting blink tx because blink auth height is too high (" << blink_height << " vs. " << local_height << ")");
        if (tag)
            m.send_back("bl.nostart", bt_serialize(bt_dict{{"!", tag}, {"e", "Invalid blink authorization height"sv}}));
        return;
    }
    MTRACE("Blink tx auth height " << blink_height << " is valid (local height is " << local_height << ")");

    auto t_it = data.find("t");
    if (t_it == data.end()) {
        MINFO("Rejecting blink tx: no tx data included in request");
        if (tag)
            m.send_back("bl.nostart", bt_serialize(bt_dict{{"!", tag}, {"e", "No transaction included in blink request"sv}}));
        return;
    }
    const std::string &tx_data = var::get<std::string>(t_it->second);
    MTRACE("Blink tx data is " << tx_data.size() << " bytes");

    // "hash" is optional -- it lets us short-circuit processing the tx if we've already seen it,
    // and is added internally by SN-to-SN forwards but not the original submitter.  We don't trust
    // the hash if we haven't seen it before -- this is only used to skip propagation and
    // validation.
    crypto::hash tx_hash;
    auto &tx_hash_str = var::get<std::string>(data.at("#"));
    bool already_approved = false, already_rejected = false;
    if (tx_hash_str.size() == sizeof(crypto::hash)) {
        std::memcpy(tx_hash.data, tx_hash_str.data(), sizeof(crypto::hash));
        std::shared_lock lock{qnet.mutex};
        auto bit = qnet.blinks.find(blink_height);
        if (bit != qnet.blinks.end()) {
            auto &umap = bit->second;
            auto it = umap.find(tx_hash);
            if (it != umap.end() && it->second.btxptr) {
                if (tag) {
                    // This is a direct blink submission, not a quorum-relayed submission
                    already_approved = it->second.btxptr->approved();
                    already_rejected = !already_approved && it->second.btxptr->rejected();
                    if (already_approved || already_rejected) {
                        // Quorum approved/rejected the tx before we received the submitted blink,
                        // reply with a bl.good/bl.bad immediately (done below, outside the lock).
                        MINFO("Submitted blink tx already " << (already_approved ? "approved" : "rejected") <<
                                "; sending result back to originating node");
                    } else {
                        // We've already seen it but are still waiting on more signatures to
                        // determine the result, so stash the tag & pubkey in the metadata to delay
                        // the reply until a signature comes in that flips it to approved/rejected
                        // status.
                        it->second.reply_tag = tag;
                        it->second.reply_conn = m.conn;
                        return;
                    }
                } else {
                    MDEBUG("Already seen and forwarded this blink tx, ignoring it.");
                    return;
                }
            }
        }
        MTRACE("Blink tx hash: " << to_hex(tx_hash.data));
    } else {
        MINFO("Rejecting blink tx: invalid tx hash included in request");
        if (tag)
            m.send_back("bl.nostart", bt_serialize(bt_dict{{"!", tag}, {"e", "Invalid transaction hash"s}}));
        return;
    }

    if (already_approved || already_rejected) {
        m.send_back(already_approved ? "bl.good" : "bl.bad", bt_serialize(bt_dict{{"!", tag}}), send_option::optional{});
        return;
    }

    quorum_array blink_quorums;
    uint64_t checksum = get_int<uint64_t>(data.at("q"));
    try {
        blink_quorums = get_blink_quorums(blink_height, qnet.core.get_service_node_list(), &checksum);
    } catch (const std::runtime_error &e) {
        MINFO("Rejecting blink tx: " << e.what());
        if (tag)
            m.send_back("bl.nostart", bt_serialize(bt_dict{{"!", tag}, {"e", "Unable to retrieve blink quorum: "s + e.what()}}));
        return;
    }

    peer_info pinfo{qnet, quorum_type::blink, blink_quorums.begin(), blink_quorums.end(), true /*opportunistic*/,
        {qnet.core.get_service_node_list().get_pubkey_from_x25519(x25519_from_string(m.conn.pubkey()))} // exclude the peer that just sent it to us
        };

    if (pinfo.my_position_count > 0)
        MTRACE("Found this SN in " << pinfo.my_position_count << " subquorums");
    else {
        MINFO("Rejecting blink tx: this service node is not a member of the blink quorum!");
        if (tag)
            m.send_back("bl.nostart", bt_serialize(bt_dict{{"!", tag}, {"e", "Blink tx relayed to non-blink quorum member"sv}}));
        return;
    }

    auto btxptr = std::make_shared<blink_tx>(blink_height);
    auto &btx = *btxptr;
    auto &tx = var::get<cryptonote::transaction>(btx.tx);
    // If any quorums are too small set the extra spaces to rejected (this also checks that no
    // quorums are too big).
    for (size_t qi = 0; qi < blink_quorums.size(); qi++)
        btx.limit_signatures(static_cast<blink_tx::subquorum>(qi), blink_quorums[qi]->validators.size());

    {
        crypto::hash tx_hash_actual;
        if (!cryptonote::parse_and_validate_tx_from_blob(tx_data, tx, tx_hash_actual)) {
            MINFO("Rejecting blink tx: failed to parse transaction data");
            if (tag)
                m.send_back("bl.nostart", bt_serialize(bt_dict{{"!", tag}, {"e", "Failed to parse transaction data"sv}}));
            return;
        }
        MTRACE("Successfully parsed transaction data");

        if (tx_hash != tx_hash_actual) {
            MINFO("Rejecting blink tx: submitted tx hash " << tx_hash << " did not match actual tx hash " << tx_hash_actual);
            if (tag)
                m.send_back("bl.nostart", bt_serialize(bt_dict{{"!", tag}, {"e", "Invalid transaction hash"sv}}));
            return;
        } else {
            MTRACE("Pre-computed tx hash matches actual tx hash");
        }
    }

    // Abort if we don't have at least one strong peer to send it to.  This can only happen if it's
    // a brand new SN (not just restarted!) that hasn't received uptime proofs before.
    if (!pinfo.strong_peers) {
        MWARNING("Could not find connection info for any blink quorum peers.  Aborting blink tx");
        if (tag)
            m.send_back("bl.nostart", bt_serialize(bt_dict{{"!", tag}, {"e", "No quorum peers are currently reachable"sv}}));
        return;
    }

    // See if we've already handled this blink tx, and if not, store it.  Also check for any pending
    // signatures for this blink tx that we received or processed before we got here with this tx.
    std::list<pending_signature> signatures;
    {
        std::unique_lock lock{qnet.mutex};
        auto &bl_info = qnet.blinks[blink_height][tx_hash];
        if (bl_info.btxptr) {
            MDEBUG("Already seen and forwarded this blink tx, ignoring it.");
            return;
        }
        bl_info.btxptr = btxptr;
        for (auto &sig : bl_info.pending_sigs)
            signatures.push_back(std::move(sig));
        bl_info.pending_sigs.clear();
        if (tag > 0) {
            bl_info.reply_tag = tag;
            bl_info.reply_conn = m.conn;
        }
    }
    MTRACE("Accepted new blink tx for verification");

    // The submission looks good.  We distribute it first, *before* we start verifying the actual tx
    // details, for two reasons: we want other quorum members to start verifying ASAP, and we want
    // to propagate to peers even if the things below fail on this node (because our peers might
    // succeed).  We test the bits *above*, however, because if they fail we won't agree on the
    // right quorum to send it to.
    //
    // FIXME - am I 100% sure I want to do the above?  Verifying the TX would cut off being able to
    // induce a node to broadcast a junk TX to other quorum members.


    {
        bt_dict blink_data{
            {"h", blink_height},
            {"q", checksum},
            {"t", tx_data},
            {"#", tx_hash_str},
        };
        MDEBUG("Relaying blink tx to " << pinfo.strong_peers << " strong and " << (pinfo.peers.size() - pinfo.strong_peers) << " opportunistic blink peers");
        pinfo.relay_to_peers("blink.submit", blink_data);
    }

    // Anything past this point always results in a success or failure signature getting sent to peers

    // Check tx for validity
    bool approved;
    auto min = tx.get_min_version_for_hf(hf_version),
         max = tx.get_max_version_for_hf(hf_version);
    if (tx.version < min || tx.version > max) {
        approved = false;
        MINFO("Blink TX " << tx_hash << " rejected because TX version " << tx.version << " invalid: TX version not between " << min << " and " << max);
    } else {
        bool already_in_mempool;
        cryptonote::tx_verification_context tvc = {};
        approved = qnet.core.get_pool().add_new_blink(btxptr, tvc, already_in_mempool);

        MINFO("Blink TX " << tx_hash << (approved ? " approved and added to mempool" : " rejected"));
        if (!approved)
            MDEBUG("TX rejected because: " << print_tx_verification_context(tvc));
    }

    auto hash_to_sign = btx.hash(approved);
    crypto::signature sig;
    generate_signature(hash_to_sign, keys.pub, keys.key, sig);

    // Now that we have the blink tx stored we can add our signature *and* any other pending
    // signatures we are holding onto, then blast the entire thing to our peers.
    for (uint8_t qi = 0; qi < NUM_BLINK_QUORUMS; qi++)
        if (pinfo.my_position[qi] >= 0)
            signatures.emplace_back(approved, qi, pinfo.my_position[qi], sig);

    process_blink_signatures(qnet, btxptr, blink_quorums, checksum, std::move(signatures), tag, m.conn.pubkey());
}

template <typename Consume>
void extract_signature_values(bt_dict_consumer& data, std::string_view key, std::list<pending_signature>& signatures, Consume consume) {
    if (!data.skip_until(key)) throw std::invalid_argument("Invalid blink signature data: missing required field '" + std::string{key} + "'");
    auto list = data.consume_list_consumer();
    auto it = signatures.begin();
    for (; !list.is_finished(); ++it) {
        if (it == signatures.end()) throw std::invalid_argument("Invalid blink signature data: " + std::string{key} + " size > i size");
        std::get<decltype(consume(list))>(*it) = consume(list);
    }
    if (it != signatures.end()) throw std::invalid_argument("Invalid blink signature data: " + std::string{key} + " size < i size");
}

crypto::signature convert_string_view_bytes_to_signature(std::string_view sig_str)
{
  if (sig_str.size() != sizeof(crypto::signature))
      throw std::invalid_argument("Invalid signature data size: " + std::to_string(sig_str.size()));

  crypto::signature result;
  std::memcpy(&result, sig_str.data(), sizeof(crypto::signature));
  if (!result) throw std::invalid_argument("Invalid signature data: null signature given");

  return result;
}

/// A "blink_sign" message is used to relay signatures from one quorum member to other members.
/// Fields are:
///
///     "h" - Blink authorization height of the signature.
///
///     "#" - tx hash of the transaction.
///
///     "q" - checksum of blink quorum members.  Mandatory, and must match the receiving SN's
///           locally computed checksum of blink quorum members.
///
///     "i" - list of quorum indices, i.e. 0 for the base quorum, 1 for the future quorum
///
///     "p" - list of quorum positions
///
///     "r" - list of blink signature results (0 if rejected, 1 if approved)
///
///     "s" - list of blink signatures
///
/// Each of "i", "p", "r", and "s" must be exactly the same length; each element at a position in
/// each list corresponds to the values at the same position of the other lists.
///
/// Signatures will be forwarded if new; known signatures will be ignored.
void handle_blink_signature(Message& m, QnetState& qnet) {
    MDEBUG("Received a blink tx signature from SN " << to_hex(m.conn.pubkey()));

    if (m.data.size() != 1)
        throw std::runtime_error("Rejecting blink signature: expected one data entry not " + std::to_string(m.data.size()));

    // Note: this dict_consumer processes in ASCII-order.  Also worth noting is that we skip over
    // unknown values here (which could be helpful if we want to add fields in the future).
    bt_dict_consumer data{m.data[0]};

    // # - hash (32 bytes)
    if (!data.skip_until("#")) throw std::invalid_argument("Invalid blink signature data: missing required field '#'");
    auto hash_str = data.consume_string_view();
    if (hash_str.size() != sizeof(crypto::hash))
        throw std::invalid_argument("Invalid blink signature data: invalid tx hash");
    crypto::hash tx_hash;
    std::memcpy(tx_hash.data, hash_str.data(), sizeof(crypto::hash));

    // h - height
    if (!data.skip_until("h")) throw std::invalid_argument("Invalid blink signature data: missing required field 'h'");
    uint64_t blink_height = data.consume_integer<uint64_t>();
    if (!blink_height) throw std::invalid_argument("Invalid blink signature data: height cannot be 0");


    std::list<pending_signature> signatures;

    // i - list of quorum indices
    if (!data.skip_until("i")) throw std::invalid_argument("Invalid blink signature data: missing required field 'i'");
    auto quorum_indices = data.consume_list_consumer();
    while (!quorum_indices.is_finished()) {
        uint8_t q = quorum_indices.consume_integer<uint8_t>();
        if (q >= NUM_BLINK_QUORUMS)
            throw std::invalid_argument("Invalid blink signature data: invalid quorum index " + std::to_string(q));
        signatures.emplace_back();
        std::get<uint8_t>(signatures.back()) = q;
    }

    // p - list of quorum positions
    extract_signature_values(data, "p", signatures, [](bt_list_consumer& l) {
        int pos = l.consume_integer<int>();
        if (pos < 0 || pos >= BLINK_SUBQUORUM_SIZE) // This is only input validation: it might actually have to be smaller depending on the actual quorum (we check later)
            throw std::invalid_argument("Invalid blink signature data: invalid quorum position " + std::to_string(pos));
        return pos;
    });

    // q - quorum membership checksum
    if (!data.skip_until("q")) throw std::invalid_argument("Invalid blink signature data: missing required field 'q'");
    // Before 7.1.8 we get a int64_t on the wire, using 2s-complement representation when the value
    // is a uint64_t that exceeds the max of an int64_t so, if negative, pull it off and static cast
    // it back (the static_cast assumes a 2s-complement architecture which isn't technically
    // guaranteed until C++20, but is pretty much universal).
    static_assert(sizeof(int64_t) == sizeof(uint64_t) && static_cast<uint64_t>(int64_t{-1}) == ~uint64_t{0},
            "Non 2s-complement architecture not supported"); // Just in case
    uint64_t checksum = data.is_negative_integer()
        ? static_cast<uint64_t>(data.consume_integer<int64_t>())
        : data.consume_integer<uint64_t>(); // If not negative, read as uint64_t (so that we allow large positive uint64_t's on the wire)

    // r - list of 1/0 results (1 = approved, 0 = rejected)
    extract_signature_values(data, "r", signatures, [](bt_list_consumer& l) { return l.consume_integer<bool>(); });

    // s - list of 64-byte signatures
    extract_signature_values(data, "s", signatures, [](bt_list_consumer& l) {
        return convert_string_view_bytes_to_signature(l.consume_string_view());
    });

    auto blink_quorums = get_blink_quorums(blink_height, qnet.core.get_service_node_list(), &checksum); // throws if bad quorum or checksum mismatch

    uint64_t reply_tag = 0;
    ConnectionID reply_conn;
    std::shared_ptr<blink_tx> btxptr;
    auto find_blink = [&]() {
        auto height_it = qnet.blinks.find(blink_height);
        if (height_it == qnet.blinks.end())
            return;
        auto &blinks_at_height = height_it->second;
        auto it = blinks_at_height.find(tx_hash);
        if (it == blinks_at_height.end())
            return;
        auto &b_meta = it->second;
        btxptr = b_meta.btxptr;
        reply_tag = b_meta.reply_tag;
        reply_conn = b_meta.reply_conn;
    };

    {
        // Most of the time we'll already know about the blink and don't need a unique lock to
        // extract info we need.  If we fail, we'll stash the signature to be processed when we get
        // the blink tx itself.
        std::shared_lock lock{qnet.mutex};
        find_blink();
    }

    if (!btxptr) {
        std::unique_lock lock{qnet.mutex};
        // We probably don't have it, so want to stash the signature until we received it.  There's
        // a chance, however, that another thread processed it while we were waiting for this
        // exclusive mutex, so check it again before we stash a delayed signature.
        find_blink();
        if (!btxptr) {
            MINFO("Blink tx not found in local blink cache; delaying signature verification");
            auto &delayed = qnet.blinks[blink_height][tx_hash].pending_sigs;
            for (auto &sig : signatures)
                delayed.insert(std::move(sig));
            return;
        }
    }

    MINFO("Found blink tx in local blink cache");

    process_blink_signatures(qnet, btxptr, blink_quorums, checksum, std::move(signatures), reply_tag, reply_conn, m.conn.pubkey());
}


using blink_response = std::pair<cryptonote::blink_result, std::string>;
struct blink_result_data {
    crypto::hash hash;
    std::promise<blink_response> promise;
    std::chrono::high_resolution_clock::time_point expiry;
    int remote_count;
    std::atomic<int> nostart_count{0};
};
std::unordered_map<uint64_t, blink_result_data> pending_blink_results;
std::shared_mutex pending_blink_result_mutex;

// Sanity check against runaway active pending blink submissions
constexpr size_t MAX_ACTIVE_PROMISES = 1000;

std::future<std::pair<cryptonote::blink_result, std::string>> send_blink(cryptonote::core& core, const std::string &tx_blob) {
    std::promise<std::pair<cryptonote::blink_result, std::string>> promise;
    auto future = promise.get_future();
    cryptonote::transaction tx;
    crypto::hash tx_hash;

    uint64_t blink_tag = 0;
    blink_result_data *brd = nullptr;

    if (!cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash)) {
        promise.set_value(std::make_pair(cryptonote::blink_result::rejected, "Could not parse transaction data"));
    } else {
        auto now = std::chrono::high_resolution_clock::now();
        bool found = false;
        std::unique_lock lock{pending_blink_result_mutex};
        for (auto it = pending_blink_results.begin(); it != pending_blink_results.end(); ) {
            auto &b_results = it->second;
            if (b_results.expiry < now) {
                try { b_results.promise.set_value(std::make_pair(cryptonote::blink_result::timeout, "Blink quorum timeout")); }
                catch (const std::future_error &) { /* ignore */ }
                it = pending_blink_results.erase(it);
            } else {
                if (!found && b_results.hash == tx_hash)
                    found = true;
                ++it;
            }
        }
        if (found) {
            promise.set_value(std::make_pair(cryptonote::blink_result::rejected, "Transaction was already submitted"));
        } else if (pending_blink_results.size() >= MAX_ACTIVE_PROMISES) {
            promise.set_value(std::make_pair(cryptonote::blink_result::rejected, "Node is busy, try again later"));
        } else {
            while (!brd) {
                // Choose an unused tag randomly so that the blink tag value doesn't give anything away
                blink_tag = tools::rng();
                if (blink_tag == 0 || pending_blink_results.count(blink_tag) > 0) continue;
                brd = &pending_blink_results[blink_tag];
                brd->hash = tx_hash;
                brd->promise = std::move(promise);
                brd->expiry = std::chrono::high_resolution_clock::now() + 30s;
            }
        }
    }

    if (!blink_tag) return future;

    try {
        uint64_t height = core.get_current_blockchain_height();
        uint64_t checksum;
        auto quorums = get_blink_quorums(height, core.get_service_node_list(), nullptr, &checksum);

        std::string data = bt_serialize<bt_dict>({
            {"!", blink_tag},
            {"#", get_data_as_string(tx_hash)},
            {"h", height},
            {"q", checksum},
            {"t", tx_blob}
        });

        auto destinations = peer_prepare_relay_to_quorum_subset(core, quorums.begin(), quorums.end(), 4 /*num_peers*/);
        brd->remote_count = destinations.size();
        peer_relay_to_prepared_destinations(core, destinations, "blink.submit"sv, std::move(data));

    } catch (...) {
        std::unique_lock lock{pending_blink_result_mutex};
        auto it = pending_blink_results.find(blink_tag); // Look up again because `brd` might have been deleted
        if (it != pending_blink_results.end()) {
            try {
                it->second.promise.set_exception(std::current_exception());
            } catch (const std::future_error &) { /* ignore */ }
        }
    }

    return future;
}

void common_blink_response(uint64_t tag, cryptonote::blink_result res, std::string msg, bool nostart = false) {
    bool promise_set = false;
    {
        std::shared_lock lock{pending_blink_result_mutex};
        auto it = pending_blink_results.find(tag);
        if (it == pending_blink_results.end())
            return; // Already handled, or obsolete

        auto &pbr = it->second;
        bool forward_response;
        if (nostart) {
            // On a bl.nostart response wait until we have confirmation from a majority of the nodes
            // we sent to because it could be a local blink quorum node error.
            int count = ++pbr.nostart_count;
            forward_response = count > pbr.remote_count / 2;
        } else {
            // Otherwise on bl.good or bl.bad response we immediately send it back.  In theory a
            // service node could lie about this, but there's nothing actually at risk other than a
            // false confirmation message returned to the sender which will get resolved at the next
            // refresh (the recipient verifies blink signatures and isn't affected).
            forward_response = true;
        }
        if (forward_response) {
            try {
                pbr.promise.set_value(std::make_pair(res, msg));
                promise_set = true;
            }
            catch (const std::future_error &) { /* ignore */ }
        }
    }
    if (promise_set) {
        std::unique_lock lock{pending_blink_result_mutex};
        pending_blink_results.erase(tag);
    }
}

/// bl.nostart is sent back to the submitter when the tx doesn't get far enough to be distributed
/// among the quorum because of some failure (bad height, parse failure, etc.)  It includes:
///
///     ! - the tag as included in the submission
///     e - an error message
///
/// It's possible for some nodes to accept and others to refuse, so we don't actually set the
/// promise unless we get a nostart response from a majority of the remotes.
void handle_blink_not_started(Message& m) {
    if (m.data.size() != 1) {
        MERROR("Bad blink not started response: expected one data entry not " << m.data.size());
        return;
    }
    auto data = bt_deserialize<bt_dict>(m.data[0]);
    auto tag = get_int<uint64_t>(data.at("!"));
    auto& error = var::get<std::string>(data.at("e"));

    MINFO("Received no-start blink response: " << error);

    common_blink_response(tag, cryptonote::blink_result::rejected, std::move(error), true /*nostart*/);
}
/// bl.bad gets returned once we know enough of the blink quorum has rejected the result to make it
/// unequivocal that it has been rejected.  We require a failure response from a majority of the
/// remotes before setting the promise.
///
///     ! - the tag as included in the submission
///
void handle_blink_failure(Message &m) {
    if (m.data.size() != 1) {
        MERROR("Blink failure message not understood: expected one data entry not " << m.data.size());
        return;
    }
    auto data = bt_deserialize<bt_dict>(m.data[0]);
    auto tag = get_int<uint64_t>(data.at("!"));

    // TODO - we ought to be able to signal an error message *sometimes*, e.g. if one of the remotes
    // we sent it to rejected it then that remote can reply with a message.  That gets a bit
    // complicated, though, in terms of maintaining internal state (since the bl.bad is sent on
    // signature receipt, not at rejection time), so for now we don't include it.
    //auto &error = var::get<std::string>(data.at("e"));

    MINFO("Received blink failure response");

    common_blink_response(tag, cryptonote::blink_result::rejected, "Transaction rejected by quorum"s);
}

/// bl.good gets returned once we know enough of the blink quorum has accepted the result to make it
/// valid.  We require a good response from a majority of the remotes before setting the promise.
///
///     ! - the tag as included in the submission
///
void handle_blink_success(Message& m) {
    if (m.data.size() != 1) {
        MERROR("Blink success message not understood: expected one data entry not " << m.data.size());
        return;
    }
    auto data = bt_deserialize<bt_dict>(m.data[0]);
    auto tag = get_int<uint64_t>(data.at("!"));

    MINFO("Received blink success response");

    common_blink_response(tag, cryptonote::blink_result::accepted, ""s);
}

//
// Pulse
//

// NOTE: Common header fields in pulse::message (quorum position, round,
// signature) are tagged lexicographically sorted with the header to allow
// sequentially parsing out the header data in one shot.

const std::string PULSE_TAG_QUORUM_POSITION   = "q";
const std::string PULSE_TAG_BLOCK_ROUND       = "r";
const std::string PULSE_TAG_SIGNATURE         = "s";

// Extra fields are intentionally given tags after the common header fields.
const std::string PULSE_TAG_BLOCK_TEMPLATE        = "t";
const std::string PULSE_TAG_VALIDATOR_BITSET      = "u";
const std::string PULSE_TAG_RANDOM_VALUE          = "v";
const std::string PULSE_TAG_RANDOM_VALUE_HASH     = "x";
const std::string PULSE_TAG_FINAL_BLOCK_SIGNATURE = "z";

const std::string PULSE_CMD_CATEGORY               = "pulse";
const std::string PULSE_CMD_VALIDATOR_BITSET       = "validator_bitset";
const std::string PULSE_CMD_VALIDATOR_BIT          = "validator_bit";
const std::string PULSE_CMD_BLOCK_TEMPLATE         = "block_template";
const std::string PULSE_CMD_RANDOM_VALUE_HASH      = "random_value_hash";
const std::string PULSE_CMD_RANDOM_VALUE           = "random_value";
const std::string PULSE_CMD_SIGNED_BLOCK           = "signed_block";
const std::string PULSE_CMD_SEND_VALIDATOR_BITSET  = PULSE_CMD_CATEGORY + "." + PULSE_CMD_VALIDATOR_BITSET;
const std::string PULSE_CMD_SEND_VALIDATOR_BIT     = PULSE_CMD_CATEGORY + "." + PULSE_CMD_VALIDATOR_BIT;
const std::string PULSE_CMD_SEND_BLOCK_TEMPLATE    = PULSE_CMD_CATEGORY + "." + PULSE_CMD_BLOCK_TEMPLATE;
const std::string PULSE_CMD_SEND_RANDOM_VALUE_HASH = PULSE_CMD_CATEGORY + "." + PULSE_CMD_RANDOM_VALUE_HASH;
const std::string PULSE_CMD_SEND_RANDOM_VALUE      = PULSE_CMD_CATEGORY + "." + PULSE_CMD_RANDOM_VALUE;
const std::string PULSE_CMD_SEND_SIGNED_BLOCK      = PULSE_CMD_CATEGORY + "." + PULSE_CMD_SIGNED_BLOCK;

void pulse_relay_message_to_quorum(void *self, pulse::message const &msg, service_nodes::quorum const &quorum, bool block_producer)
{
  peer_info::exclude_set relay_exclude;

  bool include_block_producer = false;
  std::string_view command    = {};

  bt_dict data                = {};
  data[PULSE_TAG_SIGNATURE]   = tools::view_guts(msg.signature);
  data[PULSE_TAG_BLOCK_ROUND] = msg.round;

  if (msg.type == pulse::message_type::block_template)
  {
    command                        = PULSE_CMD_SEND_BLOCK_TEMPLATE;
    data[PULSE_TAG_BLOCK_TEMPLATE] = msg.block_template.blob;
  }
  else
  {
    data[PULSE_TAG_QUORUM_POSITION] = msg.quorum_position;

    switch(msg.type)
    {
      case pulse::message_type::invalid:
        assert("Invalid Code Path" == nullptr);
        break;

      case pulse::message_type::signed_block:
      {
        command = PULSE_CMD_SEND_SIGNED_BLOCK;
        data[PULSE_TAG_FINAL_BLOCK_SIGNATURE] = tools::view_guts(msg.signed_block.signature_of_final_block_hash);
      }
      break;

      case pulse::message_type::block_template: break;

      case pulse::message_type::handshake: /* FALLTHRU */
      case pulse::message_type::handshake_bitset:
      {
        assert(msg.quorum_position < quorum.validators.size());

        include_block_producer = msg.type == pulse::message_type::handshake_bitset;
        relay_exclude.insert(quorum.validators[msg.quorum_position]);

        if (msg.type == pulse::message_type::handshake)
        {
          command = PULSE_CMD_SEND_VALIDATOR_BIT;
        }
        else
        {
          assert(msg.type == pulse::message_type::handshake_bitset);
          command = PULSE_CMD_SEND_VALIDATOR_BITSET;
          data[PULSE_TAG_VALIDATOR_BITSET] = msg.handshakes.validator_bitset;
        }
      }
      break;

      case pulse::message_type::random_value_hash:
      {
        command = PULSE_CMD_SEND_RANDOM_VALUE_HASH;
        data[PULSE_TAG_RANDOM_VALUE_HASH] = tools::view_guts(msg.random_value_hash.hash);
      }
      break;

      case pulse::message_type::random_value:
      {
        command = PULSE_CMD_SEND_RANDOM_VALUE;
        data[PULSE_TAG_RANDOM_VALUE] = tools::view_guts(msg.random_value.value);
      }
      break;
    }
  }


  auto &qnet = QnetState::from(self);
  if (block_producer)
  {
    service_nodes::quorum const *quorum_ptr = &quorum;
    auto destinations = peer_prepare_relay_to_quorum_subset(qnet.core, &quorum_ptr, &quorum_ptr + 1, 4 /*num_peers*/);
    peer_relay_to_prepared_destinations(qnet.core, destinations, command, bt_serialize(data));
  }
  else
  {
    peer_info peer_list{qnet,
                        quorum_type::pulse,
                        &quorum,
                        true /*opportunistic*/,
                        std::move(relay_exclude),
                        include_block_producer /*include_workers*/};
    peer_list.relay_to_peers(command, data);
  }
}

pulse::message pulse_parse_msg_header_fields(pulse::message_type type, bt_dict_consumer &data, std::string_view error_prefix)
{
  pulse::message result = {};
  result.type           = type;

  if (type != pulse::message_type::block_template)
  {
    if (auto const &tag = PULSE_TAG_QUORUM_POSITION; data.skip_until(tag))
      result.quorum_position = data.consume_integer<int>();
    else
      throw std::invalid_argument(std::string(error_prefix) + tag + "'");
  }

  if (auto const &tag = PULSE_TAG_BLOCK_ROUND; data.skip_until(tag))
    result.round = data.consume_integer<uint8_t>();
  else
    throw std::invalid_argument(std::string(error_prefix) + tag + "'");

  if (auto const &tag = PULSE_TAG_SIGNATURE; data.skip_until(tag)) {
    auto sig_str     = data.consume_string_view();
    result.signature = convert_string_view_bytes_to_signature(sig_str);
  } else {
    throw std::invalid_argument(std::string(error_prefix) + tag + "'");
  }

  return result;
}

// Invoked when daemon has received a participation handshake message via
// QuorumNet from another validator, either forwarded or originating from that
// node. The message is added to the Pulse message queue and validating the
// contents of the message is left to the caller.
void handle_pulse_participation_bit_or_bitset(Message &m, QnetState& qnet, bool bitset)
{
  if (m.data.size() != 1)
      throw std::runtime_error("Rejecting pulse participation "s + (bitset ? "bitset" : "handshake") + ": expected one data entry not " + std::to_string(m.data.size()));

  std::string_view const INVALID_ARG_PREFIX = bitset ? "Invalid pulse validator bitset: missing required field '"sv
                                                     : "Invalid pulse validator bit: missing required field '"sv;
  bt_dict_consumer data{m.data[0]};
  auto type          = (bitset) ? pulse::message_type::handshake_bitset : pulse::message_type::handshake;
  pulse::message msg = pulse_parse_msg_header_fields(type, data, INVALID_ARG_PREFIX);

  if (bitset)
  {
    if (auto const &tag = PULSE_TAG_VALIDATOR_BITSET; data.skip_until(tag))
      msg.handshakes.validator_bitset = data.consume_integer<uint16_t>();
    else
      throw std::invalid_argument(std::string(INVALID_ARG_PREFIX) + tag + "'");
  }

  qnet.lmq.job([&qnet, data = std::move(msg)]() { pulse::handle_message(&qnet, data); }, qnet.core.pulse_thread_id());
}

void handle_pulse_block_template(Message &m, QnetState &qnet)
{
  if (m.data.size() != 1)
      throw std::runtime_error("Rejecting pulse block template expected one data entry not "s + std::to_string(m.data.size()));

  bt_dict_consumer data{m.data[0]};
  std::string_view constexpr INVALID_ARG_PREFIX = "Invalid pulse block template: missing required field '"sv;
  pulse::message msg = pulse_parse_msg_header_fields(pulse::message_type::block_template, data, INVALID_ARG_PREFIX);

  if (auto const &tag = PULSE_TAG_BLOCK_TEMPLATE; data.skip_until(tag))
    msg.block_template.blob = data.consume_string_view();
  else
    throw std::invalid_argument(std::string(INVALID_ARG_PREFIX) + tag + "'");

  qnet.lmq.job([&qnet, data = std::move(msg)]() { pulse::handle_message(&qnet, data); }, qnet.core.pulse_thread_id());
}

void handle_pulse_random_value_hash(Message &m, QnetState &qnet)
{
  if (m.data.size() != 1)
      throw std::runtime_error("Rejecting pulse random value hash expected one data entry not "s + std::to_string(m.data.size()));

  bt_dict_consumer data{m.data[0]};

  std::string_view constexpr INVALID_ARG_PREFIX = "Invalid pulse random value hash: missing required field '"sv;
  pulse::message msg = pulse_parse_msg_header_fields(pulse::message_type::random_value_hash, data, INVALID_ARG_PREFIX);

  if (auto const &tag = PULSE_TAG_RANDOM_VALUE_HASH; data.skip_until(tag)) {
    auto str = data.consume_string_view();
    if (str.size() != sizeof(msg.random_value_hash.hash))
      throw std::invalid_argument("Invalid hash data size: " + std::to_string(str.size()));

    std::memcpy(msg.random_value_hash.hash.data, str.data(), str.size());
  } else {
    throw std::invalid_argument(std::string(INVALID_ARG_PREFIX) + tag + "'");
  }

  qnet.lmq.job([&qnet, data = std::move(msg)]() { pulse::handle_message(&qnet, data); }, qnet.core.pulse_thread_id());
}

void handle_pulse_random_value(Message &m, QnetState &qnet)
{
  if (m.data.size() != 1)
      throw std::runtime_error("Rejecting pulse random value expected one data entry not "s + std::to_string(m.data.size()));

  std::string_view constexpr INVALID_ARG_PREFIX = "Invalid pulse random value: missing required field '"sv;
  bt_dict_consumer data{m.data[0]};

  pulse::message msg = pulse_parse_msg_header_fields(pulse::message_type::random_value, data, INVALID_ARG_PREFIX);
  if (auto const &tag = PULSE_TAG_RANDOM_VALUE; data.skip_until(tag)) {
    auto str = data.consume_string_view();
    if (str.size() != sizeof(msg.random_value.value.data))
      throw std::invalid_argument("Invalid data size: " + std::to_string(str.size()));
    std::memcpy(msg.random_value.value.data, str.data(), str.size());
  } else {
    throw std::invalid_argument(std::string(INVALID_ARG_PREFIX) + tag + "'");
  }

  qnet.lmq.job([&qnet, data = std::move(msg)]() { pulse::handle_message(&qnet, data); }, qnet.core.pulse_thread_id());
}

void handle_pulse_signed_block(Message &m, QnetState &qnet)
{
  if (m.data.size() != 1)
      throw std::runtime_error("Rejecting pulse signed block expected one data entry not "s + std::to_string(m.data.size()));

  std::string_view constexpr INVALID_ARG_PREFIX = "Invalid pulse signed block: missing required field '"sv;
  bt_dict_consumer data{m.data[0]};
  pulse::message msg = pulse_parse_msg_header_fields(pulse::message_type::signed_block, data, INVALID_ARG_PREFIX);

  if (auto const &tag = PULSE_TAG_FINAL_BLOCK_SIGNATURE; data.skip_until(tag)) {
    auto sig_str                                   = data.consume_string_view();
    msg.signed_block.signature_of_final_block_hash = convert_string_view_bytes_to_signature(sig_str);
  } else {
    throw std::invalid_argument("Invalid pulse signed block: missing required field '"s + tag + "'");
  }

  qnet.lmq.job([&qnet, data = std::move(msg)]() { pulse::handle_message(&qnet, data); }, qnet.core.pulse_thread_id());
}

} // end empty namespace


/// Sets the cryptonote::quorumnet_* function pointers (allowing core to avoid linking to
/// cryptonote_protocol).  Called from daemon/daemon.cpp.  Also registers quorum command callbacks.
void init_core_callbacks() {
    cryptonote::quorumnet_new = new_qnetstate;
    cryptonote::quorumnet_init = setup_endpoints;
    cryptonote::quorumnet_delete = delete_qnetstate;
    cryptonote::quorumnet_relay_obligation_votes = relay_obligation_votes;
    cryptonote::quorumnet_send_blink = send_blink;
    cryptonote::quorumnet_pulse_relay_message_to_quorum = pulse_relay_message_to_quorum;
}

namespace {
void setup_endpoints(cryptonote::core& core, void* obj) {
    auto& lmq = core.get_lmq();

    if (core.service_node()) {
        if (!obj)
            throw std::logic_error{"qnet initialization failure: quorumnet_new must be called for service node operation"};
        auto& qnet = QnetState::from(obj);
        // quorum.*: commands between quorum members, requires that both side of the connection is a SN
        lmq.add_category("quorum", Access{AuthLevel::none, true /*remote sn*/, true /*local sn*/}, 2 /*reserved threads*/)
            // Receives an obligation vote
            .add_command("vote_ob", [&qnet](Message& m) { handle_obligation_vote(m, qnet); })
            // Receives blink tx signatures or rejections between quorum members (either original or
            // forwarded).  These are propagated by the receiver if new
            .add_command("blink_sign", [&qnet](Message& m) { handle_blink_signature(m, qnet); })
            // Receives a request for the timestamp
            .add_request_command("timestamp", [](Message& m) { handle_timestamp(m); })
            ;

        // blink.*: commands sent to blink quorum members from anyone (e.g. blink submission)
        lmq.add_category("blink", Access{AuthLevel::none, false /*remote sn*/, true /*local sn*/}, 1 /*reserved thread*/)
            // Receives a new blink tx submission from an external node, or forward from other quorum
            // members who received it from an external node.
            .add_command("submit", [&qnet](Message& m) { handle_blink(m, qnet); })
            ;

        lmq.add_category(PULSE_CMD_CATEGORY, Access{AuthLevel::none, true /*remote sn*/, true /*local sn*/}, 1 /*reserved thread*/)
            .add_command(PULSE_CMD_VALIDATOR_BIT, [&qnet](Message& m) { handle_pulse_participation_bit_or_bitset(m, qnet, false /*bitset*/); })
            .add_command(PULSE_CMD_VALIDATOR_BITSET, [&qnet](Message& m) { handle_pulse_participation_bit_or_bitset(m, qnet, true /*bitset*/); })
            .add_command(PULSE_CMD_BLOCK_TEMPLATE, [&qnet](Message& m) { handle_pulse_block_template(m, qnet); })
            .add_command(PULSE_CMD_RANDOM_VALUE_HASH, [&qnet](Message& m) { handle_pulse_random_value_hash(m, qnet); })
            .add_command(PULSE_CMD_RANDOM_VALUE, [&qnet](Message& m) { handle_pulse_random_value(m, qnet); })
            .add_command(PULSE_CMD_SIGNED_BLOCK, [&qnet](Message& m) { handle_pulse_signed_block(m, qnet); })
            ;
    }

    // bl.*: responses to blinks sent from quorum members back to the node who submitted the blink
    lmq.add_category("bl", Access{AuthLevel::none, true /*remote sn*/, false /*local sn*/})
        // Message sent back to the blink initiator that the transaction was NOT relayed, either
        // because the height was invalid or the quorum checksum failed.  This is only sent by the
        // entry point service nodes into the quorum to let it know the tx verification has not
        // started from that node.  It does not necessarily indicate a failure unless all entry
        // point attempts return the same.
        .add_command("nostart", handle_blink_not_started)
        // Message send back from the entry SNs back to the initiator that the Blink tx has been
        // rejected: that is, enough signed rejections have occured that the Blink tx cannot be
        // accepted.
        .add_command("bad", handle_blink_failure)
        // Sends a message from the entry SNs back to the initiator that the Blink tx has been
        // accepted and validated and is being broadcast to the network.
        .add_command("good", handle_blink_success)
        ;

    // Compatibility aliases.  No longer used since 7.1.4, but can still be received from previous
    // 7.1.x nodes.
    // Transition plan:
    // 8.1.0: keep the aliases (so the 7.1.x nodes still using them can talk to 8.x), but don't use
    // them anymore.
    // 8.x.1 (i.e. the first post-hard-fork release): remove the aliases since no 7.1.x nodes will
    // be left.

    lmq.add_command_alias("vote_ob", "quorum.vote_ob");
    lmq.add_command_alias("blink_sign", "quorum.blink_sign");
    lmq.add_command_alias("timestamp", "quorum.timestamp");
    lmq.add_command_alias("blink", "blink.submit");
    lmq.add_command_alias("bl_nostart", "bl.nostart");
    lmq.add_command_alias("bl_bad", "bl.bad");
    lmq.add_command_alias("bl_good", "bl.good");
}
}

}
