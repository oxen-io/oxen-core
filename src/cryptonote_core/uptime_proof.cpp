#include "uptime_proof.h"

#include <common/exception.h>
#include <common/guts.h>
#include <crypto/crypto.h>
#include <cryptonote_config.h>
#include <epee/string_tools.h>
#include <logging/oxen_logger.h>
#include <oxenc/bt_producer.h>
#include <version.h>

#include "bls/bls_crypto.h"
#include "service_node_list.h"

extern "C" {
#include <sodium/crypto_sign.h>
}

namespace uptime_proof {

using cryptonote::hf;
namespace feature = cryptonote::feature;

// Constructor for the uptime proof, will take the service node keys as a param and sign
Proof::Proof(
        hf hardfork,
        cryptonote::network_type nettype,
        uint32_t sn_public_ip,
        uint16_t sn_storage_https_port,
        uint16_t sn_storage_omq_port,
        const std::array<uint16_t, 3> ss_version,
        uint16_t quorumnet_port,
        uint64_t l2_height,
        const std::array<uint16_t, 3> sr_version,
        const std::array<uint16_t, 3> lokinet_version,
        const service_nodes::service_node_keys& keys) :
        version{OXEN_VERSION},
        storage_server_version{ss_version},
        session_router_version{sr_version},
        lokinet_version{lokinet_version},
        timestamp{static_cast<uint64_t>(time(nullptr))},
        pubkey_ed25519{keys.pub_ed25519},
        pubkey_bls{keys.pub_bls},
        l2_height{l2_height},
        public_ip{sn_public_ip},
        storage_https_port{sn_storage_https_port},
        storage_omq_port{sn_storage_omq_port},
        qnet_port{quorumnet_port},
        version_tag(OXEN_VERSION_TAG) {

    if (hardfork == feature::ETH_TRANSITION || nettype == cryptonote::network_type::LOCALDEV ||
        hardfork >= hf::hf22_eth_fixup) {

        assert(keys.pub_bls);
        pop_bls = eth::sign(
                nettype,
                keys.key_bls,
                tools::concat_guts<uint8_t>(keys.pub_bls, keys.pub),
                &crypto::null<eth::address>);
    }

    serialized_proof = bt_encode_uptime_proof(hardfork, nettype);
    proof_hash = crypto::keccak(serialized_proof);

    crypto_sign_detached(
            sig_ed25519.data(),
            nullptr,
            proof_hash.data(),
            proof_hash.size(),
            keys.key_ed25519.data());
}

// Deserialize from a btencoded string into our Proof instance
Proof::Proof(
        cryptonote::hf hardfork,
        cryptonote::network_type nettype,
        std::string_view serialized_proof) {

    proof_hash = crypto::keccak(serialized_proof);

    using namespace oxenc;

    auto proof = oxenc::bt_dict_consumer{serialized_proof};
    // NB: we must consume in sorted key order

    pubkey_bls =
            tools::make_from_guts<eth::bls_public_key>(proof.require<std::string_view>("bk"sv));
    pop_bls = tools::make_from_guts<eth::bls_signature>(proof.require<std::string_view>("bp"sv));

    if (nettype != cryptonote::network_type::MAINNET) {
        if (proof.skip_until("gh")) {
            version_tag = proof.consume_string();
        }
        if (version_tag.size() > 100)
            throw oxen::traced<std::runtime_error>{"version tag too long"};
    }

    if (auto ip = proof.require<std::string>("ip");
        !epee::string_tools::get_ip_int32_from_string(public_ip, ip) || public_ip == 0)
        throw oxen::traced<std::runtime_error>{"Invalid IP address in proof"};

    l2_height = proof.require<uint64_t>("l2");
    if (l2_height == 0)
        throw oxen::traced<std::runtime_error>{"Invalid L2 height in proof"};

    lokinet_version =
            proof.maybe<std::array<uint16_t, 3>>("lv").value_or(std::array<uint16_t, 3>{0, 0, 0});

    pubkey_ed25519 = tools::make_from_guts<crypto::ed25519_public_key>(
            proof.require<std::string_view>("pke"sv));

    qnet_port = proof.require<uint16_t>("q");
    if (qnet_port == 0)
        throw oxen::traced<std::runtime_error>{"Invalid omq port in proof"};

    // Unlike qnet_port, these *can* be zero (on devnet); but this is checked elsewhere.
    storage_https_port = proof.require<uint16_t>("shp");
    storage_omq_port = proof.require<uint16_t>("sop");

    // TODO: we can .require instead of .maybe this after HF23 has happened:
    session_router_version =
            proof.maybe<std::array<uint16_t, 3>>("srv").value_or(std::array<uint16_t, 3>{0, 0, 0});

    storage_server_version = proof.require<std::array<uint16_t, 3>>("sv");

    timestamp = proof.require<uint64_t>("t");

    version = proof.require<std::array<uint16_t, 3>>("v");
}

crypto::public_key Proof::pubkey() const {
    crypto::public_key pk;
    std::memcpy(pk.data(), pubkey_ed25519.data(), sizeof(crypto::public_key));
    return pk;
}

bool Proof::contact_info_changed(const Proof& other) const {
    auto fields = [](const Proof& p) {
        return std::tie(
                p.version,
                p.storage_server_version,
                p.session_router_version,
                p.lokinet_version,
                p.pubkey_ed25519,
                p.public_ip,
                p.storage_https_port,
                p.storage_omq_port,
                p.qnet_port);
    };
    return fields(*this) != fields(other);
}

std::string Proof::bt_encode_uptime_proof(hf hardfork, cryptonote::network_type nettype) const {
    // NOTE: New fields can be added to the encoded proof without breaking older clients (i.e. no
    // need to hardfork-gate additions): the signature applies over the entire encoded proof, not
    // just known fields in that proof.  Older clients simply ignore extra fields that they don't
    // understand.

    // NB: must append in ascii order
    oxenc::bt_dict_producer proof;

    proof.append("bk", tools::view_guts(pubkey_bls));
    proof.append("bp", tools::view_guts(pop_bls));
    if (nettype != cryptonote::network_type::MAINNET)
        proof.append("gh", version_tag);
    proof.append("ip", epee::string_tools::get_ip_string_from_int32(public_ip));
    proof.append("l2", l2_height);
    proof.append("lv", lokinet_version);
    proof.append("pke", tools::view_guts(pubkey_ed25519));
    proof.append("q", qnet_port);
    proof.append("shp", storage_https_port);
    proof.append("sop", storage_omq_port);
    proof.append("srv", session_router_version);
    proof.append("sv", storage_server_version);
    proof.append("t", timestamp);
    proof.append("v", version);
    return std::move(proof).str();
}

cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request Proof::generate_request(hf hardfork) const {
    cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request request;
    assert(!serialized_proof.empty());
    request.proof = serialized_proof;
    request.ed_sig = tools::view_guts(sig_ed25519);

    return request;
}

inline constexpr static auto proof_tuple(const Proof& p) {
    return std::tie(
            p.timestamp,
            p.pubkey_ed25519,
            p.sig_ed25519,
            p.pubkey_bls,
            p.pop_bls,
            p.public_ip,
            p.storage_https_port,
            p.storage_omq_port,
            p.qnet_port,
            p.l2_height,
            p.version,
            p.storage_server_version,
            p.session_router_version,
            p.lokinet_version);
}

bool Proof::operator==(const Proof& o) const {
    return proof_tuple(*this) == proof_tuple(o);
}

}  // namespace uptime_proof
