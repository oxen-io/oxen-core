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

#include <chrono>
#include <iterator>
#include <limits>
#include <mutex>
#include <shared_mutex>
#include <string_view>

#include "common/util.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_config.h"
#include "cryptonote_core/service_node_quorum_cop.h"
#include "cryptonote_core/service_node_rules.h"
#include "cryptonote_core/service_node_voting.h"
#include "l2_tracker/events.h"
#include "networks.h"
#include "serialization/crypto.h"
#include "serialization/map.h"
#include "serialization/serialization.h"
#include "serialization/vector_bool.h"
#include "uptime_proof.h"

namespace cryptonote {
class Blockchain;
class BlockchainDB;
struct checkpoint_t;
};  // namespace cryptonote

namespace service_nodes {
inline constexpr uint64_t INVALID_HEIGHT = static_cast<uint64_t>(-1);

struct checkpoint_participation_entry {
    uint64_t height = INVALID_HEIGHT;
    bool voted = true;

    bool pass() const { return voted; };
};
struct pulse_participation_entry {
    uint64_t height = INVALID_HEIGHT;
    uint8_t round = 0;
    bool voted = true;

    bool pass() const { return voted; }
};
struct timestamp_participation_entry {
    bool participated = true;
    bool pass() const { return participated; };
};
struct timesync_entry {
    bool in_sync = true;
    bool pass() const { return in_sync; }
};

template <typename ValueType, size_t Count = QUORUM_VOTE_CHECK_COUNT>
struct participation_history {
    std::array<ValueType, Count> history;
    size_t write_index = 0;

    void reset() { write_index = 0; }

    void add(const ValueType& entry) { history[write_index++ % history.size()] = entry; }
    void add(ValueType&& entry) { history[write_index++ % history.size()] = std::move(entry); }

    // Returns the number of failures we have stored (of the last Count records).
    size_t failures() const {
        return std::count_if(begin(), end(), [](auto& e) { return !e.pass(); });
    }
    size_t passes() const { return size() - failures(); }

    bool empty() const { return write_index == 0; }
    size_t size() const { return std::min(history.size(), write_index); }
    constexpr size_t max_size() const noexcept { return Count; }

    ValueType* begin() { return history.data(); }
    ValueType* end() { return history.data() + size(); }
    const ValueType* begin() const { return history.data(); }
    const ValueType* end() const { return history.data() + size(); }
};

inline constexpr auto NEVER = std::chrono::steady_clock::time_point::min();

struct proof_info {
    proof_info();

    participation_history<pulse_participation_entry> pulse_participation;
    participation_history<checkpoint_participation_entry> checkpoint_participation;
    participation_history<timestamp_participation_entry> timestamp_participation;
    participation_history<timesync_entry> timesync_status;

    uint64_t timestamp = 0;  // The actual time we last received an uptime proof (serialized)
    uint64_t effective_timestamp =
            0;  // Typically the same, but on recommissions it is set to the recommission block time
                // to fend off instant obligation checks
    std::array<std::pair<uint32_t, uint64_t>, 2> public_ips = {};  // (not serialized)

    // See set_storage_server_peer_reachable(...) and set_lokinet_peer_reachable(...)
    struct reachable_stats {
        std::chrono::steady_clock::time_point last_reachable = NEVER, first_unreachable = NEVER,
                                              last_unreachable = NEVER;

        // Returns whether or not this stats indicates a node that is currently (probably)
        // reachable:
        // - true if the last test was a pass (regardless of how long ago)
        // - false if the last test was a recent fail (i.e. less than REACHABLE_MAX_FAILURE_VALIDITY
        // ago)
        // - nullopt if the last test was a failure, but is considered stale.
        // Both true and nullopt are considered a pass for service node testing.
        std::optional<bool> reachable(
                const std::chrono::steady_clock::time_point& now =
                        std::chrono::steady_clock::now()) const;

        // Returns true if this stats indicates a node that has recently failed reachability (see
        // above) *and* has been unreachable for at least the given grace time (that is: there is
        // both a recent failure and a failure more than `grace` ago, with no intervening
        // reachability pass reports).
        bool unreachable_for(
                std::chrono::seconds threshold,
                const std::chrono::steady_clock::time_point& now =
                        std::chrono::steady_clock::now()) const;
    };
    reachable_stats ss_reachable{};
    reachable_stats lokinet_reachable{};

    // Unlike all of the above (except for timestamp), these values *do* get serialized
    std::unique_ptr<uptime_proof::Proof> proof{};

    // Derived from pubkey_ed25519, not serialized
    crypto::x25519_public_key pubkey_x25519 = crypto::null<crypto::x25519_public_key>;

    // Updates pubkey_ed25519 to the given key, re-deriving the x25519 key if it actually changes
    // (does nothing if the key is the same as the current value).  If x25519 derivation fails then
    // both pubkeys are set to null.
    void update_pubkey(const crypto::ed25519_public_key& pk);

    // Called to update data received from a proof is received, updating values in the local object.
    // Returns true if serializable data is changed (in which case `store()` should be called).
    // Note that this does not update the m_x25519_to_pub map if the x25519 key changes (that's the
    // caller's responsibility).
    bool update(
            uint64_t ts,
            std::unique_ptr<uptime_proof::Proof> new_proof,
            const crypto::x25519_public_key& pk_x2);

    // Stores this record in the database.
    void store(const crypto::public_key& pubkey, cryptonote::Blockchain& blockchain);
};

struct pulse_sort_key {
    uint64_t last_height_validating_in_quorum = 0;
    uint8_t quorum_index = 0;

    bool operator==(pulse_sort_key const& other) const {
        return last_height_validating_in_quorum == other.last_height_validating_in_quorum &&
               quorum_index == other.quorum_index;
    }
    bool operator<(pulse_sort_key const& other) const {
        bool result = std::make_pair(last_height_validating_in_quorum, quorum_index) <
                      std::make_pair(other.last_height_validating_in_quorum, other.quorum_index);
        return result;
    }

    BEGIN_SERIALIZE_OBJECT()
    VARINT_FIELD(last_height_validating_in_quorum)
    FIELD(quorum_index)
    END_SERIALIZE()
};

struct service_node_info  // registration information
{
    enum class version_t : uint8_t {
        v0_checkpointing,  // versioning reset in 4.0.0 (data structure storage changed)
        v1_add_registration_hf_version,
        v2_ed25519,
        v3_quorumnet,
        v4_noproofs,
        v5_pulse_recomm_credit,
        v6_reassign_sort_keys,
        v7_decommission_reason,
        v8_ethereum_address,
        _count
    };

    struct contribution_t {
        enum class version_t : uint8_t {
            v0,

            _count
        };

        version_t version{version_t::v0};
        crypto::public_key key_image_pub_key{};
        crypto::key_image key_image{};
        uint64_t amount = 0;

        contribution_t() = default;
        contribution_t(
                version_t version,
                const crypto::public_key& pubkey,
                const crypto::key_image& key_image,
                uint64_t amount) :
                version{version}, key_image_pub_key{pubkey}, key_image{key_image}, amount{amount} {}

        BEGIN_SERIALIZE_OBJECT()
        ENUM_FIELD(version, version < version_t::_count)
        FIELD(key_image_pub_key)
        FIELD(key_image)
        VARINT_FIELD(amount)
        END_SERIALIZE()
    };

    struct contributor_t {
        uint8_t version = 1;
        uint64_t amount = 0;
        uint64_t reserved = 0;
        cryptonote::account_public_address address{};
        eth::address ethereum_address{};
        std::vector<contribution_t> locked_contributions;

        contributor_t() = default;
        contributor_t(uint64_t reserved_, const cryptonote::account_public_address& address_) :
                reserved(reserved_), address(address_) {
            *this = {};
            reserved = reserved_;
            address = address_;
        }

        BEGIN_SERIALIZE_OBJECT()
        VARINT_FIELD(version)
        VARINT_FIELD(amount)
        VARINT_FIELD(reserved)
        FIELD(address)
        FIELD(locked_contributions)
        if (version >= 1)
            FIELD(ethereum_address);
        END_SERIALIZE()
    };

    uint64_t registration_height = 0;
    uint64_t requested_unlock_height = 0;
    // block_height and transaction_index are to record when the service node last received a
    // reward.
    uint64_t last_reward_block_height = 0;
    uint32_t last_reward_transaction_index = 0;
    uint32_t decommission_count = 0;  // How many times this service node has been decommissioned
    int64_t active_since_height = 0;  // if decommissioned: equal to the *negative* height at which
                                      // you became active before the decommission
    uint64_t last_decommission_height = 0;  // The height at which the last (or current!)
                                            // decommissioning started, or 0 if never decommissioned
    uint16_t last_decommission_reason_consensus_all =
            0;  // The reason which the last (or current!) decommissioning occurred as voted by all
                // SNs, or 0 if never decommissioned
    uint16_t last_decommission_reason_consensus_any =
            0;  // The reason which the last (or current!) decommissioning occurred as voted by any
                // of the SNs, or 0 if never decommissioned
    int64_t recommission_credit = 0;  // The number of blocks of credit you started with or kept
                                      // when you were last activated (i.e. as of
                                      // `active_since_height`)
    std::vector<contributor_t> contributors;
    uint64_t total_contributed = 0;
    uint64_t total_reserved = 0;
    uint64_t staking_requirement = 0;
    uint64_t portions_for_operator = 0;
    swarm_id_t swarm_id = 0;
    cryptonote::account_public_address operator_address{};
    eth::address operator_ethereum_address{};
    eth::bls_public_key bls_public_key{};
    uint64_t last_ip_change_height = 0;  // The height of the last quorum penalty for changing IPs
    version_t version = tools::enum_top<version_t>;
    cryptonote::hf registration_hf_version = cryptonote::hf::none;
    pulse_sort_key pulse_sorter;

    service_node_info() = default;
    bool is_fully_funded() const { return total_contributed >= staking_requirement; }
    bool is_decommissioned() const { return active_since_height < 0; }
    bool is_active() const { return is_fully_funded() && !is_decommissioned(); }
    bool is_payable(uint64_t at_height, cryptonote::network_type nettype) const {
        auto& netconf = get_config(nettype);
        return is_active() &&
               at_height >= active_since_height + netconf.SERVICE_NODE_PAYABLE_AFTER_BLOCKS;
    }

    bool can_transition_to_state(
            cryptonote::hf hf_version, uint64_t block_height, new_state proposed_state) const;
    bool can_be_voted_on(uint64_t block_height) const;
    size_t total_num_locked_contributions() const;

    BEGIN_SERIALIZE_OBJECT()
    ENUM_FIELD(version, version < version_t::_count)
    VARINT_FIELD(registration_height)
    VARINT_FIELD(requested_unlock_height)
    VARINT_FIELD(last_reward_block_height)
    VARINT_FIELD(last_reward_transaction_index)
    VARINT_FIELD(decommission_count)
    VARINT_FIELD(active_since_height)
    VARINT_FIELD(last_decommission_height)
    FIELD(contributors)
    VARINT_FIELD(total_contributed)
    VARINT_FIELD(total_reserved)
    VARINT_FIELD(staking_requirement)
    VARINT_FIELD(portions_for_operator)
    FIELD(operator_address)
    VARINT_FIELD(swarm_id)
    if (version < version_t::v4_noproofs) {
        uint32_t fake_ip = 0;
        uint16_t fake_port = 0;
        VARINT_FIELD_N("public_ip", fake_ip)
        VARINT_FIELD_N("storage_port", fake_port)
    }
    VARINT_FIELD(last_ip_change_height)
    if (version >= version_t::v1_add_registration_hf_version)
        VARINT_FIELD(registration_hf_version);
    if (version >= version_t::v2_ed25519 && version < version_t::v4_noproofs) {
        crypto::ed25519_public_key fake_pk = crypto::null<crypto::ed25519_public_key>;
        FIELD_N("pubkey_ed25519", fake_pk)
        if (version >= version_t::v3_quorumnet) {
            uint16_t fake_port = 0;
            VARINT_FIELD_N("quorumnet_port", fake_port)
        }
    }
    if (version >= version_t::v5_pulse_recomm_credit) {
        VARINT_FIELD(recommission_credit)
        FIELD(pulse_sorter)
    }
    if (version >= version_t::v7_decommission_reason) {
        VARINT_FIELD(last_decommission_reason_consensus_all)
        VARINT_FIELD(last_decommission_reason_consensus_any)
    }
    if (version >= version_t::v8_ethereum_address) {
        FIELD(bls_public_key)
        FIELD(operator_ethereum_address)
    }
    END_SERIALIZE()
};

struct service_node_address {
    crypto::public_key sn_pubkey;
    eth::bls_public_key bls_pubkey;
    crypto::x25519_public_key x_pubkey;
    uint32_t ip;
    uint16_t port;
};

using pubkey_and_sninfo = std::pair<crypto::public_key, std::shared_ptr<const service_node_info>>;
using service_nodes_infos_t =
        std::unordered_map<crypto::public_key, std::shared_ptr<const service_node_info>>;

struct service_node_pubkey_info {
    crypto::public_key pubkey;
    std::shared_ptr<const service_node_info> info;

    service_node_pubkey_info() = default;
    service_node_pubkey_info(const pubkey_and_sninfo& pair) :
            pubkey{pair.first}, info{pair.second} {}

    BEGIN_SERIALIZE_OBJECT()
    FIELD(pubkey)
    if (Archive::is_deserializer)
        info = std::make_shared<service_node_info>();
    FIELD_N("info", const_cast<service_node_info&>(*info))
    END_SERIALIZE()
};

struct key_image_blacklist_entry {
    enum struct version_t : uint8_t {
        version_0,
        version_1_serialize_amount,
        count,
    };
    version_t version{version_t::version_1_serialize_amount};
    crypto::key_image key_image;
    uint64_t unlock_height = 0;
    uint64_t amount = 0;

    key_image_blacklist_entry() = default;
    key_image_blacklist_entry(
            version_t version,
            const crypto::key_image& key_image,
            uint64_t unlock_height,
            uint64_t amount) :
            version{version}, key_image{key_image}, unlock_height{unlock_height}, amount(amount) {}

    bool operator==(const key_image_blacklist_entry& other) const {
        return key_image == other.key_image;
    }
    bool operator==(const crypto::key_image& image) const { return key_image == image; }

    BEGIN_SERIALIZE()
    ENUM_FIELD(version, version < version_t::count)
    FIELD(key_image)
    VARINT_FIELD(unlock_height)
    if (version >= version_t::version_1_serialize_amount)
        VARINT_FIELD(amount)
    END_SERIALIZE()
};

struct payout_entry {
    cryptonote::account_public_address address;
    uint64_t portions;

    constexpr bool operator==(const payout_entry& x) const {
        return portions == x.portions && address == x.address;
    }
};

struct payout {
    crypto::public_key key;
    std::vector<payout_entry> payouts;
};

crypto::x25519_public_key snpk_to_xpk(const crypto::public_key& snpk);

/// Collection of keys used by a service node
struct service_node_keys {
    /// The service node key pair used for registration-related data on the chain; is
    /// curve25519-based but with Monero-specific changes that make it useless for external tools
    /// supporting standard ed25519 or x25519 keys.
    /// TODO(oxen) - eventually drop this key and just do everything with the ed25519 key.
    crypto::secret_key key;
    crypto::public_key pub;

    /// A secondary SN key pair used for ancillary operations by tools (e.g. libsodium) that rely
    /// on standard cryptography keypair signatures.
    crypto::ed25519_secret_key key_ed25519;
    crypto::ed25519_public_key pub_ed25519;

    /// A x25519 key computed from the ed25519 key, above, that is used for SN-to-SN encryption.
    /// (Unlike this above two keys this is not stored to disk; it is generated on the fly from the
    /// ed25519 key).
    crypto::x25519_secret_key key_x25519;
    crypto::x25519_public_key pub_x25519;

    /// BLS keypair of this service node, used for SENT registrations and interacting with the SENT
    /// staking contract.
    eth::bls_secret_key key_bls;
    eth::bls_public_key pub_bls;
};

class service_node_list {
  public:
    explicit service_node_list(cryptonote::Blockchain& blockchain);
    // non-copyable:
    service_node_list(const service_node_list&) = delete;
    service_node_list& operator=(const service_node_list&) = delete;

    void block_add(
            const cryptonote::block& block,
            const std::vector<cryptonote::transaction>& txs,
            const cryptonote::checkpoint_t* checkpoint);
    bool state_history_exists(uint64_t height);
    bool process_batching_rewards(const cryptonote::block& block);
    bool pop_batching_rewards_block(const cryptonote::block& block);
    void blockchain_detached(uint64_t height);
    void init();
    void validate_miner_tx(const cryptonote::miner_tx_info& info) const;
    void alt_block_add(const cryptonote::block_add_info& info);
    payout get_next_block_leader() const {
        std::lock_guard lock{m_sn_mutex};
        return m_state.get_next_block_leader();
    }
    bool is_service_node(const crypto::public_key& pubkey, bool require_active = true) const;
    bool is_key_image_locked(
            crypto::key_image const& check_image,
            uint64_t* unlock_height = nullptr,
            service_node_info::contribution_t* the_locked_contribution = nullptr) const;
    uint64_t height() const { return m_state.height; }

    /// Note(maxim): this should not affect thread-safety as the returned object is const
    ///
    /// For checkpointing, quorums are only generated when height % CHECKPOINT_INTERVAL == 0 (and
    /// the actual internal quorum used is for `height - REORG_SAFETY_BUFFER_BLOCKS_POST_HF12`, i.e.
    /// do no subtract off the buffer in advance).
    /// Similarly for blink (but on BLINK_QUORUM_INTERVAL, but without any buffer offset applied
    /// here). return: nullptr if the quorum is not cached in memory (pruned from memory).
    std::shared_ptr<const quorum> get_quorum(
            quorum_type type,
            uint64_t height,
            bool include_old = false,
            std::vector<std::shared_ptr<const quorum>>* alt_states = nullptr) const;
    bool get_quorum_pubkey(
            quorum_type type,
            quorum_group group,
            uint64_t height,
            size_t quorum_index,
            crypto::public_key& key) const;

    size_t get_service_node_count() const;
    std::vector<service_node_pubkey_info> get_service_node_list_state(
            const std::vector<crypto::public_key>& service_node_pubkeys = {}) const;
    const std::vector<key_image_blacklist_entry>& get_blacklisted_key_images() const {
        return m_state.key_image_blacklist;
    }

    /// Accesses a proof with the required lock held; used to extract needed proof values.  Func
    /// should be callable with a single `const proof_info &` argument.  If there is no proof info
    /// at all for the given pubkey then Func will not be called.
    template <typename Func>
    void access_proof(const crypto::public_key& pubkey, Func f) const {
        std::unique_lock lock{m_sn_mutex};
        auto it = proofs.find(pubkey);
        if (it != proofs.end())
            f(it->second);
    }

    /// Returns the (monero curve) pubkey associated with a x25519 pubkey.  Returns a null public
    /// key if not found.  (Note: this is just looking up the association, not derivation).
    ///
    /// As of feature::SN_PK_IS_ED25519 this is looked up in the state and will always be present
    /// (if the given pubkey actually belongs to an active service node).  Before that HF, the
    /// pubkey will only be available if a recent proof has been received from the SN.
    crypto::public_key get_pubkey_from_x25519(const crypto::x25519_public_key& x25519) const;

    // Returns a pubkey of a random service node in the service node list
    crypto::public_key get_random_pubkey();

    /// Initializes the x25519 map from current pubkey state; called during initialization.
    ///
    /// TODO Deprecated: Can be removed after HF21 (replaced with a map in the state_t object).
    void initialize_x25519_map();

    /// Remote SN lookup address function for OxenMQ: given a string_view of a x25519 pubkey, this
    /// returns that service node's quorumnet contact information, if we have it, else empty string.
    std::string remote_lookup(std::string_view x25519_pk);

    /// Does something read-only for each registered service node in the range of pubkeys.  The SN
    /// lock is held while iterating, so the "something" should be quick.
    ///
    /// Unknown public keys are skipped.
    template <
            std::input_iterator It,
            std::sentinel_for<It> End,
            std::invocable<const crypto::public_key&, const service_node_info&, const proof_info&>
                    Func>
    void for_each_service_node_info_and_proof(It begin, End end, Func f) const {
        static const proof_info empty_proof{};
        std::lock_guard lock{m_sn_mutex};
        for (auto sni_end = m_state.service_nodes_infos.end(); begin != end; ++begin) {
            auto it = m_state.service_nodes_infos.find(*begin);
            if (it != sni_end) {
                auto pit = proofs.find(it->first);
                f(it->first, *it->second, (pit != proofs.end() ? pit->second : empty_proof));
            }
        }
    }

    /// Copies x25519 pubkeys (as strings) of all currently registered SNs into the given output
    /// iterator.  (Before the feature::SN_PK_IS_ED25519 hardfork this only includes SNs with known
    /// proofs.)
    template <std::output_iterator<std::string> OutputIt>
    void copy_x25519_pubkeys(OutputIt out, cryptonote::network_type nettype) const {
        std::lock_guard lock{m_sn_mutex};
        if (cryptonote::is_hard_fork_at_least(
                    nettype, cryptonote::feature::SN_PK_IS_ED25519, m_state.height)) {
            for (const auto& [xpk, _ignore] : m_state.x25519_map)
                *out++ = std::string{reinterpret_cast<const char*>(&xpk), sizeof(xpk)};
        } else {
            for (const auto& pk_info : m_state.service_nodes_infos) {
                auto it = proofs.find(pk_info.first);
                if (it == proofs.end())
                    continue;
                if (const auto& x2_pk = it->second.pubkey_x25519)
                    *out++ = std::string{reinterpret_cast<const char*>(&x2_pk), sizeof(x2_pk)};
            }
        }
    }

    /// Copies `service_node_address`es (pubkeys, ip, port) of all currently active SNs with
    /// potentially reachable, known addresses (via a recently received valid proof) into the given
    /// output iterator.  Service nodes that are active but for which we have not yet
    /// received/accepted a proof containing IP info are not included.
    template <std::output_iterator<service_node_address> OutputIt>
    void copy_reachable_active_service_node_addresses(OutputIt out, cryptonote::network_type nettype) const {
        std::lock_guard lock{m_sn_mutex};
        bool sn_pk_is_ed25519_hf = cryptonote::is_hard_fork_at_least(
                nettype, cryptonote::feature::SN_PK_IS_ED25519, m_state.height);

        for (const auto& pk_info : m_state.service_nodes_infos) {
            if (!pk_info.second->is_active())
                continue;
            auto it = proofs.find(pk_info.first);
            if (it == proofs.end())
                continue;
            // If we don't have a proof then we won't know the IP/port, and so this node isn't
            // considered reachable and shouldn't be returned.
            if (!it->second.proof)
                continue;
            auto& proof = *it->second.proof;

            crypto::x25519_public_key pubkey_x25519;
            if (sn_pk_is_ed25519_hf) {
                pubkey_x25519 = snpk_to_xpk(pk_info.first);
            } else {
                assert(it->second.pubkey_x25519);  // Should always be set to non-null if we have a
                                                   // proof
                pubkey_x25519 = it->second.pubkey_x25519;
            }
            *out++ = service_node_address{
                    pk_info.first,
                    pk_info.second->bls_public_key,
                    sn_pk_is_ed25519_hf ? snpk_to_xpk(pk_info.first) : it->second.pubkey_x25519,
                    proof.public_ip,
                    proof.qnet_port};
        }
    }

    std::vector<pubkey_and_sninfo> active_service_nodes_infos() const {
        return m_state.active_service_nodes_infos();
    }

    void set_my_service_node_keys(const service_node_keys* keys);
    void set_quorum_history_storage(
            uint64_t hist_size);  // 0 = none (default), 1 = unlimited, N = # of blocks
    bool store();

    uptime_proof::Proof generate_uptime_proof(
            cryptonote::hf hardfork,
            uint32_t public_ip,
            uint16_t storage_port,
            uint16_t storage_omq_port,
            std::array<uint16_t, 3> ss_version,
            uint16_t quorumnet_port,
            std::array<uint16_t, 3> lokinet_version,
            const eth::BLSSigner& signer) const;

    bool handle_uptime_proof(
            std::unique_ptr<uptime_proof::Proof> proof,
            bool& my_uptime_proof_confirmation,
            crypto::x25519_public_key& x25519_pkey);

    crypto::public_key public_key_lookup(const eth::bls_public_key& bls_pubkey) const;

    void record_checkpoint_participation(
            crypto::public_key const& pubkey, uint64_t height, bool participated);

    // Called every hour to remove proofs for expired SNs from memory and the database.
    void cleanup_proofs();

    // Called via RPC from storage server/lokinet to report a ping test result for a remote storage
    // server/lokinet.
    //
    // How this works:
    // - SS randomly picks probably-good nodes to test every 10s (with fuzz), and pings
    //   known-failing nodes to re-test them.
    // - SS re-tests nodes with a linear backoff: 10s+fuzz after the first failure, then 20s+fuzz,
    //   then 30s+fuzz, etc. (up to ~2min retest intervals)
    // - Whenever SS gets *any* ping result at all it notifies us via RPC (which lands here), and it
    //   is (as of 9.x) our responsibility to decide when too many bad pings should be penalized.
    //
    // Our rules are as follows:
    // - if we have received only failures for more than 1h5min *and* we have at least one failure
    //   in the last 10min then we consider SS reachability to be failing.
    // - otherwise we consider it good.  (Which means either it passed a reachability test at least
    //   once in the last 1h5min *or* SS stopped pinging it, perhaps because it restarted).
    //
    // Lokinet works essentially the same, except that its concept of a "ping" is being able to
    // successfully establish a session with the given remote lokinet snode.
    //
    // We do all this by tracking three values:
    // - last_reachable
    // - first_unreachable
    // - last_unreachable
    //
    // On a good ping, we set last_reachable to the current time and clear first_unreachable.  On a
    // bad ping we set last_unreachable to the current time and, if first_unreachable is empty, set
    // it to current time as well.
    //
    // This then lets us figure out:
    // - current status can be good (first_unreachable == 0), passable (last_unreachable < 10min
    // ago), or failing.
    // - current *failing* status (current status == failing && first_unreachable more than 1h5min
    // ago)
    // - last test time (max(last_reachable, last_unreachable), "not yet" if this is 0)
    // - last test result (last_reachable >= last_unreachable)
    // - how long it has been unreachable (now - first_unreachable, if first_unreachable is set)
    //
    // (Also note that the actual times references here are for convenience, 10min is actually
    // REACHABLE_MAX_FAILURE_VALIDITY, and 1h5min is actually
    // UPTIME_PROOF_VALIDITY-UPTIME_PROOF_FREQUENCY (which is actually 11min on testnet rather than
    // 1h5min)).
    bool set_storage_server_peer_reachable(crypto::public_key const& pubkey, bool value);
    bool set_lokinet_peer_reachable(crypto::public_key const& pubkey, bool value);

  private:
    bool set_peer_reachable(bool storage_server, crypto::public_key const& pubkey, bool value);

  public:
    struct quorum_for_serialization {
        uint8_t version;
        uint64_t height;
        quorum quorums[tools::enum_count<quorum_type>];

        BEGIN_SERIALIZE()
        FIELD(version)
        FIELD(height)
        FIELD_N("obligations_quorum", quorums[static_cast<uint8_t>(quorum_type::obligations)])
        FIELD_N("checkpointing_quorum", quorums[static_cast<uint8_t>(quorum_type::checkpointing)])
        END_SERIALIZE()
    };

    struct unconfirmed_l2_tx {
        // Height of the block in which this tx was mined/pulsed
        uint64_t height_added;
        // Number of confirmation or denial points.
        uint32_t confirmations;
        uint32_t denials;

        // Basis for confirmation points.  A initial inclusion or follow-up confirmation or denial
        // gets this value divided by (R+1), where R is the round number (e.g. R=0 is the initial
        // quorum; R=3 is the third backup quorum).
        //
        // The specific value here is the smallest number divisible by all integers from 1 to 10 so
        // that there is no integer precision loss of scores up to the first 10 quorum rounds.  (It
        // could go higher -- 219060189739591200 is divisible by all integers up to 42 without
        // leading to overflow --  but doing so increases serialized size and having some small
        // precision loss in backup quorum votes (especially beyond the first few rounds) really
        // doesn't matter that much.
        static constexpr uint32_t FULL_SCORE = 2 * 3 * 2 * 5 * 7 * 2 * 3;

        // Resolution rules:
        //
        // - we require at least 5 more (full) votes for the winning side than the losing side
        // - we require that the winning side votes is at least double the losing side (i.e. >= 2/3
        //   majority of votes)
        // - we require that it be resolved within 30 blocks, otherwise it loses (regarldess of the
        //   votes).
        static constexpr uint32_t MIN_FINALIZED_DIFFERENCE = FULL_SCORE * 5;
        static constexpr uint32_t MIN_FINALIZED_RATIO = 2;
        static constexpr uint64_t MAX_VOTING_BLOCKS = 30;

        // Returns true if the confirmation/denial votes determine that this transaction should be
        // confirmed as accepted.
        constexpr bool is_accepted() const {
            return confirmations >= denials + MIN_FINALIZED_DIFFERENCE &&
                   confirmations >= denials * MIN_FINALIZED_RATIO;
        }

        // Returns true if the confirmation/denial votes determine that this transaction should be
        // confirmed as denied.
        constexpr bool is_denied() const {
            return denials >= confirmations + MIN_FINALIZED_DIFFERENCE &&
                   denials >= confirmations * MIN_FINALIZED_RATIO;
        }

        // Returns true if this transaction should be denied due to taking too many blocks to reach
        // consensus.  (Note that it is possible for a tx to become properly confirmed/denied at the
        // same time it expires, in which case the proper confirmation/denial takes effect).
        constexpr bool is_expired(uint64_t curr_height) const {
            return curr_height >= height_added + MAX_VOTING_BLOCKS;
        }

        // Returns an optional bool indicating the confirmation status:
        // - std::nullopt -- not yet confirmed, denied, nor expired
        // - true -- confirmed accepted
        // - false -- confirmed denied or denied by expiry
        constexpr std::optional<bool> confirmed(uint64_t curr_height) const {
            if (is_accepted())
                return true;
            if (is_denied() || is_expired(curr_height))
                return false;
            return std::nullopt;
        }

        explicit unconfirmed_l2_tx(
                uint64_t height = 0, uint32_t confirmations = 0, uint32_t denials = 0) :
                height_added{height}, confirmations{confirmations}, denials{denials} {}
        unconfirmed_l2_tx(uint64_t height, const cryptonote::pulse_header& pulse) :
                unconfirmed_l2_tx{height, FULL_SCORE / (static_cast<uint32_t>(pulse.round) + 1)} {}

        template <class Archive>
        void serialize_value(Archive& ar) {
            // We don't include a version here becuse state_serialized is already versioned.  If we
            // end up needing versioning on this specific value then we can use a class tag
            // extension to determine which serialization path to follow in state_serialized's
            // serialization.
            field_varint(ar, "height", height_added);
            field_varint(ar, "confirmations", confirmations);
            field_varint(ar, "denials", denials);
        }
    };

    struct state_serialized {
        enum struct version_t : uint8_t {
            version_0,
            version_1_serialize_hash,
            version_2_l2_confirmations,
            count,
        };
        static version_t get_version(cryptonote::hf /*hf_version*/) {
            return version_t::version_2_l2_confirmations;
        }

        version_t version;
        uint64_t height;
        std::vector<service_node_pubkey_info> infos;
        std::vector<key_image_blacklist_entry> key_image_blacklist;
        quorum_for_serialization quorums;
        bool only_stored_quorums;
        crypto::hash block_hash;
        std::map<crypto::hash, unconfirmed_l2_tx> unconfirmed_l2_txes;
        crypto::public_key block_leader;

        template <class Archive>
        void serialize_value(Archive& ar) {
            field_varint(ar, "version", version, [](auto v) { return v < version_t::count; });
            field_varint(ar, "height", height);
            field(ar, "infos", infos);
            field(ar, "key_image_blacklist", key_image_blacklist);
            field(ar, "quorums", quorums);
            field(ar, "only_stored_quorums", only_stored_quorums);

            if (version >= version_t::version_1_serialize_hash)
                field(ar, "block_hash", block_hash);

            if (version >= version_t::version_2_l2_confirmations) {
                field(ar, "unconfirmed_l2", unconfirmed_l2_txes);
                field(ar, "block_leader", block_leader);
            }
        }
    };

    struct data_for_serialization {
        enum struct version_t : uint8_t {
            version_0,
            count,
        };
        static version_t get_version(cryptonote::hf /*hf_version*/) { return version_t::version_0; }

        version_t version;
        std::vector<quorum_for_serialization> quorum_states;
        std::vector<state_serialized> states;
        void clear() {
            quorum_states.clear();
            states.clear();
            version = {};
        }

        BEGIN_SERIALIZE()
        ENUM_FIELD(version, version < version_t::count)
        FIELD(quorum_states)
        FIELD(states)
        END_SERIALIZE()
    };

    struct state_t;
    using state_set = std::set<state_t, std::less<>>;
    using block_height = uint64_t;
    struct state_t {
        crypto::hash block_hash{};
        bool only_loaded_quorums{false};
        service_nodes_infos_t service_nodes_infos;
        std::vector<key_image_blacklist_entry> key_image_blacklist;
        std::unordered_map<crypto::x25519_public_key, crypto::public_key> x25519_map;
        block_height height{0};
        // Mutable because we are allowed to (and need to) change it via std::set iterator:
        mutable quorum_manager quorums;

        // The block leader of the block this state_t belongs to.  Only stored for HF20+ blocks
        // (before HF20 the winner is in the block's miner tx).  See `get_block_leader()` for a
        // method that works both before and after HF20.
        crypto::public_key block_leader;

        // blockchaindb-global-transaction-index => confirmation metadata of unconfirmed L2 state
        // changes.  This is an *ordered* map because confirmation votes in a pulse block depend on
        // the order of txes in here.
        std::map<crypto::hash, unconfirmed_l2_tx> unconfirmed_l2_txes;

        service_node_list* sn_list;

        state_t(service_node_list* snl) : sn_list{snl} {}
        state_t(service_node_list* snl, state_serialized&& state);

        friend bool operator<(const state_t& a, const state_t& b) { return a.height < b.height; }
        friend bool operator<(const state_t& s, block_height h) { return s.height < h; }
        friend bool operator<(block_height h, const state_t& s) { return h < s.height; }

        // Inserts/erase a service node_node_info from service_nodes_infos, with proper updating of
        // dependent fields (such as x25519_map).
        void insert_info(
                const crypto::public_key& pubkey, std::shared_ptr<service_node_info>&& info_ptr);
        service_nodes_infos_t::iterator erase_info(const service_nodes_infos_t::iterator& it);

        std::vector<pubkey_and_sninfo> active_service_nodes_infos() const;
        std::vector<pubkey_and_sninfo> decommissioned_service_nodes_infos()
                const;  // return: All nodes that are fully funded *and* decommissioned.
        std::vector<pubkey_and_sninfo> payable_service_nodes_infos(
                uint64_t height, cryptonote::network_type nettype)
                const;  // return: All nodes that are active and have been online for a period
                        // greater than SERVICE_NODE_PAYABLE_AFTER_BLOCKS

        std::vector<crypto::public_key> get_expired_nodes(
                cryptonote::BlockchainDB const& db,
                cryptonote::network_type nettype,
                cryptonote::hf hf_version,
                uint64_t block_height) const;
        void update_from_block(
                cryptonote::BlockchainDB const& db,
                cryptonote::network_type nettype,
                state_set const& state_history,
                state_set const& state_archive,
                std::unordered_map<crypto::hash, state_t> const& alt_states,
                const cryptonote::block& block,
                const std::vector<cryptonote::transaction>& txs,
                const service_node_keys* my_keys);

        // Returns true if there was a registration:
        bool process_registration_tx(
                cryptonote::network_type nettype,
                cryptonote::block const& block,
                const cryptonote::transaction& tx,
                uint32_t index,
                const service_node_keys* my_keys);
        // Returns true if there was a successful contribution that fully funded a service node:
        bool process_contribution_tx(
                cryptonote::network_type nettype,
                cryptonote::block const& block,
                const cryptonote::transaction& tx,
                uint32_t index);
        // Returns true if a service node changed state (deregistered, decommissioned, or
        // recommissioned)
        bool process_state_change_tx(
                state_set const& state_history,
                state_set const& state_archive,
                std::unordered_map<crypto::hash, state_t> const& alt_states,
                cryptonote::network_type nettype,
                const cryptonote::block& block,
                const cryptonote::transaction& tx,
                const service_node_keys* my_keys);
        bool process_key_image_unlock_tx(
                cryptonote::network_type nettype,
                cryptonote::hf hf_version,
                uint64_t block_height,
                const cryptonote::transaction& tx);
        // TODO oxen delete this function after HF20
        bool is_premature_unlock(
                cryptonote::network_type nettype,
                cryptonote::hf hf_version,
                uint64_t block_height,
                const cryptonote::transaction& tx) const;
        // Processes a newly observed ETH transaction, starting the confirmation process.  This does
        // not validate it; that happens once confirmed by the network.
        void process_new_ethereum_tx(
                cryptonote::block const& block,
                const cryptonote::transaction& tx,
                const service_node_keys* my_keys);

        // Applies a pulse-quorums-confirmed L2 event to the service node list state.  Returns true
        // if processing the event affects swarms, false if it does not.
        bool process_confirmed_event(
                const eth::event::NewServiceNode& new_sn,
                cryptonote::network_type nettype,
                cryptonote::hf hf_version,
                uint64_t height,
                uint32_t index,
                const service_node_keys* my_keys);
        bool process_confirmed_event(
                const eth::event::ServiceNodeRemovalRequest& rem_req,
                cryptonote::network_type nettype,
                cryptonote::hf hf_version,
                uint64_t height,
                uint32_t index,
                const service_node_keys* my_keys);
        bool process_confirmed_event(
                const eth::event::ServiceNodeRemoval& removal,
                cryptonote::network_type nettype,
                cryptonote::hf hf_version,
                uint64_t height,
                uint32_t index,
                const service_node_keys* my_keys);
        bool process_confirmed_event(
                const std::monostate&,  // do-nothing fallback for "not an event" variant
                cryptonote::network_type,
                cryptonote::hf,
                uint64_t,
                uint32_t,
                const service_node_keys*) {
            return false;
        }

        // Returns the block leader of the next block: that is, the round 0 pulse quorum leader, and
        // (before HF19) the service node that earns the service node reward for the next block.
        // Returns a payout with a null key if the next block cannot be a pulse block.
        payout get_next_block_leader() const;
        // Returns the pubkey of the block leader of *this* block: that is, the round 0 pulse quorum
        // leader, and (before HF19) the service node that earned the service node reward for this
        // block.  Returns a null public key if this block was not a pulse block.
        //
        // A pointer to the block can be passed as `b` if precomputed as an optimization; if omitted
        // the block will be looked up from the database when needed (i.e. for HF19 and earlier).
        crypto::public_key get_block_leader(const cryptonote::block* b = nullptr) const;

        // Returns the pulse quorum for round `round` of the next expected block.  E.g. `round=0`
        // returns the primary quorum, `round=17` returns the 17th backup quorum.  Returns nullopt
        // if the next block cannot be a pulse block (e.g. because of insufficient active nodes to
        // form a full pulse quorum).
        std::optional<quorum> get_next_pulse_quorum(cryptonote::hf hf_version, uint8_t round) const;

        // Returns the pulse quorum that actually produced this block.  In contrast to
        // `get_block_leader()`, this returns the leader of the actual pulse quorum, which could be
        // a backup round (for blocks that failed to produce a block in round 0 and fell back to a
        // backup round).  Up to the end of OXEN rewards (i.e. up until HF21), this is the service
        // node that earns any (OXEN) tx fees in the processed block.
        //
        // Returns nullopt if this was not a pulse block (i.e. a mined block).
        std::optional<quorum> get_pulse_quorum() const;
        // Wrapper around `get_pulse_quorum`, above, that returns just the SN pubkey of the pulse
        // quorum leader, or a null key if there was no pulse quorum for this state_t/block.
        crypto::public_key get_block_producer() const;

      private:
        // Rebuilds the x25519_map from the list of service nodes.  Does nothing if the
        // feature::SN_PK_IS_ED25519 fork hasn't happened for this state height.
        void initialize_xpk_map();

        mutable std::optional<service_nodes::payout> next_block_leader_cache;
    };

    // Can be set to true (via --dev-allow-local-ips) for debugging a new testnet on a local private
    // network.
    bool debug_allow_local_ips = false;
    void record_timestamp_participation(crypto::public_key const& pubkey, bool participated);
    void record_timesync_status(crypto::public_key const& pubkey, bool synced);

    // TODO oxen delete this function after HF20 (it is only used for mempool selection, not
    // consensus).
    bool is_premature_unlock(
            cryptonote::network_type nettype,
            cryptonote::hf hf_version,
            uint64_t block_height,
            const cryptonote::transaction& tx) const {
        return m_state.is_premature_unlock(nettype, hf_version, block_height, tx);
    }

    bool is_recently_expired(const eth::bls_public_key& node_bls_pubkey) const;

    /**
     * @brief gets the L2 votes (confirm or deny) for all current pending unconfirmed L2 state
     * changes.
     *
     * This is used by pulse block producers and miners, and verified by pulse quorum signers, and
     * is a pulse quorum consensus value but *not* a chain consensus value.
     *
     * @returns vector of votes
     */
    std::vector<bool> l2_pending_state_votes() const;

    cryptonote::Blockchain& blockchain;

  private:
    bool m_rescanning = false; /* set to true when doing a rescan so we know not to reset proofs */
    void process_block(
            const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs);
    void record_pulse_participation(
            crypto::public_key const& pubkey, uint64_t height, uint8_t round, bool participated);

    // Verify block against Service Node state that has just been called with
    // 'state.update_from_block(block)'.
    void verify_block(
            const cryptonote::block& block,
            bool alt_block,
            cryptonote::checkpoint_t const* checkpoint);

    void reset(bool delete_db_entry = false);
    bool load(uint64_t current_height);

    mutable std::recursive_mutex m_sn_mutex;
    const service_node_keys* m_service_node_keys;
    uint64_t m_store_quorum_history = 0;
    mutable std::shared_mutex m_x25519_map_mutex;

    /// Maps x25519 pubkeys to registration pubkeys + last block seen value (used for expiry)
    std::unordered_map<crypto::x25519_public_key, std::pair<crypto::public_key, time_t>>
            x25519_to_pub;
    std::chrono::system_clock::time_point x25519_map_last_pruned =
            std::chrono::system_clock::from_time_t(0);
    std::unordered_map<crypto::public_key, proof_info> proofs;

    struct quorums_by_height {
        quorums_by_height() = default;
        quorums_by_height(uint64_t height, quorum_manager quorums) :
                height(height), quorums(std::move(quorums)) {}
        uint64_t height;
        quorum_manager quorums;
    };

    struct {
        std::deque<quorums_by_height> old_quorum_states;  // Store all old quorum history only if
                                                          // run with --store-full-quorum-history
        state_set state_history;  // Store state_t's from MIN(2nd oldest checkpoint | height -
                                  // DEFAULT_SHORT_TERM_STATE_HISTORY) up to the block height
        state_set state_archive;  // Store state_t's where ((height < m_state_history.first()) &&
                                  // (height % STORE_LONG_TERM_STATE_INTERVAL))
        std::unordered_map<crypto::hash, state_t> alt_state;
        bool state_added_to_archive;
        data_for_serialization cache_long_term_data;
        data_for_serialization cache_short_term_data;
        std::string cache_data_blob;
    } m_transient = {};

    state_t m_state;  // NOTE: Not in m_transient due to the non-trivial constructor. We can't
                      // blanket initialise using = {}; needs to be reset in ::reset(...) manually

    // nodes that can't yet be liquidated; the .second value is the expiry block height at which we
    // remove them (and thus allow liquidation):
    std::unordered_map<eth::bls_public_key, uint64_t> recently_expired_nodes;
};

struct staking_components {
    crypto::public_key service_node_pubkey;
    cryptonote::account_public_address address;
    uint64_t transferred;
    crypto::secret_key tx_key;
    std::vector<service_node_info::contribution_t> locked_contributions;
};
bool tx_get_staking_components(
        cryptonote::transaction_prefix const& tx_prefix,
        staking_components* contribution,
        crypto::hash const& txid);
bool tx_get_staking_components(cryptonote::transaction const& tx, staking_components* contribution);
bool tx_get_staking_components_and_amounts(
        cryptonote::network_type nettype,
        cryptonote::hf hf_version,
        cryptonote::transaction const& tx,
        uint64_t block_height,
        staking_components* contribution);

using contribution = std::pair<cryptonote::account_public_address, uint64_t>;
using eth_contribution = std::pair<eth::address, uint64_t>;
struct registration_details {
    crypto::public_key service_node_pubkey;
    std::vector<contribution> reserved;
    uint64_t fee;
    uint64_t hf;         // expiration timestamp before HF19
    bool uses_portions;  // if true then `hf` is a timestamp
    union {
        // Up to HF20 we use a Monero-type signature (which is the same crypto, but incompatible
        // with standard Ed25519 signatures); starting at HF21 all registration signatures must be
        // proper Ed25519.
        crypto::signature signature;
        crypto::ed25519_signature ed_signature;
    };
    std::vector<eth_contribution> eth_contributions;
    eth::bls_public_key bls_pubkey;
};

bool is_registration_tx(
        cryptonote::network_type nettype,
        cryptonote::hf hf_version,
        const cryptonote::transaction& tx,
        uint64_t block_timestamp,
        uint64_t block_height,
        uint32_t index,
        crypto::public_key& key,
        service_node_info& info);

std::optional<registration_details> reg_tx_extract_fields(const cryptonote::transaction& tx);

uint64_t offset_testing_quorum_height(quorum_type type, uint64_t height);

// Converts string input values into a partially filled `registration_details`; pubkey and
// signature will be defaulted.  Throws invalid_registration on any invalid input.
registration_details convert_registration_args(
        cryptonote::network_type nettype,
        cryptonote::hf hf_version,
        const std::vector<std::string>& args,
        uint64_t staking_requirement);

void validate_registration(
        cryptonote::hf hf_version,
        cryptonote::network_type nettype,
        uint64_t staking_requirement,
        uint64_t block_timestamp,
        const registration_details& registration);
void validate_registration_signature(const registration_details& registration);
crypto::hash get_registration_hash(const registration_details& registration);

std::basic_string<unsigned char> get_eth_registration_message_for_signing(
        const registration_details& registration);

bool make_registration_cmd(
        cryptonote::network_type nettype,
        cryptonote::hf hf_version,
        uint64_t staking_requirement,
        const std::vector<std::string>& args,
        const service_node_keys& keys,
        std::string& cmd,
        bool make_friendly);

service_nodes::quorum generate_pulse_quorum(
        cryptonote::network_type nettype,
        crypto::public_key const& leader,
        cryptonote::hf hf_version,
        std::vector<pubkey_and_sninfo> const& active_snode_list,
        std::vector<crypto::hash> const& pulse_entropy,
        uint8_t pulse_round);

// The pulse entropy is generated for the next block after the top_block passed in.
std::vector<crypto::hash> get_pulse_entropy_for_next_block(
        cryptonote::BlockchainDB const& db,
        cryptonote::block const& top_block,
        uint8_t pulse_round);
std::vector<crypto::hash> get_pulse_entropy_for_next_block(
        cryptonote::BlockchainDB const& db, crypto::hash const& top_hash, uint8_t pulse_round);
// Same as above, but uses the current blockchain top block and defaults to round 0 if not
// specified.
std::vector<crypto::hash> get_pulse_entropy_for_next_block(
        cryptonote::BlockchainDB const& db, uint8_t pulse_round = 0);

payout service_node_payout_portions(const crypto::public_key& key, const service_node_info& info);

const static payout_entry null_payout_entry = {
        cryptonote::null_address, cryptonote::old::STAKING_PORTIONS};
const static payout null_payout = {crypto::null<crypto::public_key>, {null_payout_entry}};
}  // namespace service_nodes
