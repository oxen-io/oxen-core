#pragma once

#include "crypto/crypto.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"

namespace service_nodes {
struct service_node_keys;
}

namespace uptime_proof {

// Class containing uptime proof details and serialization code.
//
// Note that members of this class are publicly exposed and non-const for convenience, but generally
// should be treated as read-only (as changes will not propagate to the proof's hash and
// serialization).
class Proof {

  public:
    std::array<uint16_t, 3> version{};
    std::array<uint16_t, 3> storage_server_version{};
    std::array<uint16_t, 3> session_router_version{};
    std::array<uint16_t, 3> lokinet_version{};

    uint64_t timestamp{};
    crypto::ed25519_public_key pubkey_ed25519{};
    crypto::ed25519_signature sig_ed25519{};
    eth::bls_public_key pubkey_bls{};
    uint64_t l2_height{};

    // Copies the pubkey_ed25519 into a crypto::public_key for convenience.
    crypto::public_key pubkey() const;

    // Our proof of possession here is the BLS signature of H(pubkey_bls || service_node_pubkey); we
    // can't use the same PoP that we use for the smart contract because for transitioning nodes in
    // HF20 (where we need/use this) there isn't an operator or contributor contract ETH address
    // associated with the SN.
    eth::bls_signature pop_bls{};

    uint32_t public_ip{};
    uint16_t storage_https_port{};
    uint16_t storage_omq_port{};
    uint16_t qnet_port{};

    // Returns true if this Proof and the given Proof value have different contact-dependent fields:
    // that is, if oxend/lokinet/SS version, the ed/X pubkeys, IP, or ports of various services are
    // different across the two proofs.
    bool contact_info_changed(const Proof& other) const;

    // Non-consensus field: stores the current git version or release tag to assist debugging.
    std::string version_tag;

    // The hash of the proof data, computed during construction as either the hash of the incoming
    // proof data, or the hash of the outgoing serialized proof data.  This is only available for a
    // freshly created proof (incoming or outgoing) but will not be available across restarts (i.e.
    // this is not persisted in the blockchain db).
    crypto::hash proof_hash = crypto::null<crypto::hash>;

    // For a proof we construct locally from fields, this contains the serialized proof info.  We
    // *don't* populate this for incoming proofs, or persist this to the db.
    std::string serialized_proof;

    Proof() = default;
    Proof(cryptonote::hf hardfork,
          cryptonote::network_type nettype,
          uint32_t sn_public_ip,
          uint16_t sn_storage_https_port,
          uint16_t sn_storage_omq_port,
          std::array<uint16_t, 3> ss_version,
          uint16_t quorumnet_port,
          uint64_t l2_height,
          std::array<uint16_t, 3> sr_version,
          std::array<uint16_t, 3> lokinet_version,
          const service_nodes::service_node_keys& keys);

    Proof(cryptonote::hf hardfork,
          cryptonote::network_type nettype,
          std::string_view serialized_proof);
    std::string bt_encode_uptime_proof(
            cryptonote::hf hardfork, cryptonote::network_type nettype) const;

    cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request generate_request(
            cryptonote::hf hardfork) const;

    bool operator==(const Proof& other) const;
};

}  // namespace uptime_proof
