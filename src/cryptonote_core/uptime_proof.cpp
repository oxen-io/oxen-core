#include "uptime_proof.h"
#include "service_node_list.h"


#include <common/guts.h>
#include <common/exception.h>
#include <crypto/crypto.h>
#include <cryptonote_config.h>
#include <epee/string_tools.h>
#include <logging/oxen_logger.h>
#include <version.h>
#include <bls/bls_signer.h>

#include <oxenc/bt_producer.h>

extern "C" {
#include <sodium/crypto_sign.h>
}

namespace uptime_proof {

static auto logcat = oxen::log::Cat("uptime_proof");

using cryptonote::hf;
namespace feature = cryptonote::feature;

// Constructor for the uptime proof, will take the service node keys as a param and sign
Proof::Proof(
        hf hardfork,
        uint32_t sn_public_ip,
        uint16_t sn_storage_https_port,
        uint16_t sn_storage_omq_port,
        const std::array<uint16_t, 3> ss_version,
        uint16_t quorumnet_port,
        const std::array<uint16_t, 3> lokinet_version,
        const service_nodes::service_node_keys& keys,
        const BLSSigner& bls_signer) :
        version{OXEN_VERSION},
        storage_server_version{ss_version},
        lokinet_version{lokinet_version},
        timestamp{static_cast<uint64_t>(time(nullptr))},
        pubkey{keys.pub},
        pubkey_ed25519{keys.pub_ed25519},
        pubkey_bls{keys.pub_bls},
        public_ip{sn_public_ip},
        storage_https_port{sn_storage_https_port},
        storage_omq_port{sn_storage_omq_port},
        qnet_port{quorumnet_port} {

    if (hardfork == feature::ETH_TRANSITION) {
        assert(keys.pub_bls);
        pop_bls = bls_signer.signMsg(crypto::keccak(keys.pub_bls, keys.pub));
    }

    serialized_proof = bt_encode_uptime_proof(hardfork);
    proof_hash = crypto::keccak(serialized_proof);

    if (hardfork < feature::ETH_BLS)
        // Starting from HF21 we have guaranteed unified pubkey/ed25519 pubkey, so don't need to
        // send the old primary SN signature anymore: the single ed25519 signature does it all.
        crypto::generate_signature(proof_hash, keys.pub, keys.key, sig);

    crypto_sign_detached(
            sig_ed25519.data(),
            nullptr,
            proof_hash.data(),
            proof_hash.size(),
            keys.key_ed25519.data());
}

// Deserialize from a btencoded string into our Proof instance
Proof::Proof(cryptonote::hf hardfork, std::string_view serialized_proof) {

    proof_hash = crypto::keccak(serialized_proof);

    using namespace oxenc;

    auto proof = oxenc::bt_dict_consumer{serialized_proof};
    // NB: we must consume in sorted key order

    if (hardfork == feature::ETH_TRANSITION) {
        pubkey_bls = tools::make_from_guts<crypto::bls_public_key>(
                proof.require<std::string_view>("bk"sv));
        pop_bls = tools::make_from_guts<crypto::bls_signature>(
                proof.require<std::string_view>("bp"sv));
    }


    if (auto ip = proof.require<std::string>("ip");
        !epee::string_tools::get_ip_int32_from_string(public_ip, ip) || public_ip == 0)
        throw oxen::runtime_error{"Invalid IP address in proof"};

    lokinet_version = proof.require<std::array<uint16_t, 3>>("lv");

    bool found_pk = false;
    if (proof.skip_until("pk")) {
        found_pk = true;
        pubkey = tools::make_from_guts<crypto::public_key>(proof.consume_string_view());
    }

    pubkey_ed25519 = tools::make_from_guts<crypto::ed25519_public_key>(
            proof.require<std::string_view>("pke"sv));

    qnet_port = proof.require<uint16_t>("q");
    if (qnet_port == 0)
        throw oxen::runtime_error{"Invalid omq port in proof"};

    // Unlike qnet_port, these *can* be zero (on devnet); but this is checked elsewhere.
    storage_https_port = proof.require<uint16_t>("shp");
    storage_omq_port = proof.require<uint16_t>("sop");

    storage_server_version = proof.require<std::array<uint16_t, 3>>("sv");

    timestamp = proof.require<uint64_t>("t");

    version = proof.require<std::array<uint16_t, 3>>("v");

    if (!found_pk) {
        // If there is no primary pubkey then copy the ed25519 into primary (we don't send both
        // when they are the same).
        std::memcpy(pubkey.data(), pubkey_ed25519.data(), 32);
    }
}

std::string Proof::bt_encode_uptime_proof(hf hardfork) const {
    // NB: must append in ascii order
    oxenc::bt_dict_producer proof;

    if (hardfork == cryptonote::feature::ETH_TRANSITION) {
        proof.append("bk", tools::view_guts(pubkey_bls));
        proof.append("bp", tools::view_guts(pop_bls));
    }
    proof.append("ip", epee::string_tools::get_ip_string_from_int32(public_ip));
    proof.append("lv", lokinet_version);
    if (auto main_pk = tools::view_guts(pubkey); main_pk != tools::view_guts(pubkey_ed25519))
        proof.append("pk", main_pk);
    proof.append("pke", tools::view_guts(pubkey_ed25519));
    proof.append("q", qnet_port);
    proof.append("shp", storage_https_port);
    proof.append("sop", storage_omq_port);
    proof.append("sv", storage_server_version);
    proof.append("t", timestamp);
    proof.append("v", version);
    return std::move(proof).str();
}

cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request Proof::generate_request(hf hardfork) const {
    cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request request;
    assert(!serialized_proof.empty());
    request.proof = serialized_proof;
    if (hardfork < feature::ETH_BLS) {
        // Starting at the full ETH hardfork we only send the ed25519 sig (because ed and primary
        // pubkeys are guaranteed unified starting at HF21).
        request.sig = tools::view_guts(sig);
    }
    request.ed_sig = tools::view_guts(sig_ed25519);

    return request;
}

inline constexpr static auto proof_tuple(const Proof& p) {
    return std::tie(
            p.timestamp,
            p.pubkey,
            p.sig,
            p.pubkey_ed25519,
            p.sig_ed25519,
            p.pubkey_bls,
            p.pop_bls,
            p.public_ip,
            p.storage_https_port,
            p.storage_omq_port,
            p.qnet_port,
            p.version,
            p.storage_server_version,
            p.lokinet_version);
}

bool Proof::operator==(const Proof& o) const {
    return proof_tuple(*this) == proof_tuple(o);
}

}  // namespace uptime_proof
