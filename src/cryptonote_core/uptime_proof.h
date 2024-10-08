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
    std::array<uint16_t, 3> lokinet_version{};

    // TODO: after HF21 we can drop `pubkey`, `sig` (just keeping the _ed25519 versions),
    // `pubkey_bls`, and `bls_pop`: the data these carry will be directly stored in the registration
    // (either copied in at the HF21 block transition for transitioning nodes, or in the
    // registration itself for new HF21+ registrations).

    uint64_t timestamp{};
    crypto::public_key pubkey{};
    crypto::signature sig{};
    crypto::ed25519_public_key pubkey_ed25519{};
    crypto::ed25519_signature sig_ed25519{};
    eth::bls_public_key pubkey_bls{};

    // Our proof of possession here is the BLS signature of H(pubkey_bls || service_node_pubkey); we
    // can't use the same PoP that we use for the smart contract because for transitioning nodes in
    // HF20 (where we need/use this) there isn't an operator or contributor contract ETH address
    // associated with the SN.
    eth::bls_signature pop_bls{};

    uint32_t public_ip{};
    uint16_t storage_https_port{};
    uint16_t storage_omq_port{};
    uint16_t qnet_port{};

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
          std::array<uint16_t, 3> lokinet_version,
          const service_nodes::service_node_keys& keys);

    Proof(cryptonote::hf hardfork, std::string_view serialized_proof);
    std::string bt_encode_uptime_proof(cryptonote::hf hardfork) const;

    cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request generate_request(
            cryptonote::hf hardfork) const;

    bool operator==(const Proof& other) const;
};

}  // namespace uptime_proof
