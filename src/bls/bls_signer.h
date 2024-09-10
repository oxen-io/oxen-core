#pragma once

#include <crypto/crypto.h>
#include <cryptonote_config.h>

#define BLS_ETH
#define MCLBN_FP_UNIT_SIZE 4
#define MCLBN_FR_UNIT_SIZE 4

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <bls/bls.hpp>
#include <mcl/bn.hpp>
#undef MCLBN_NO_AUTOLINK
#pragma GCC diagnostic pop

#include "crypto/crypto.h"
#include "crypto/eth.h"
#include "cryptonote_config.h"

namespace eth {

class BLSSigner {
  private:
    bls::SecretKey secretKey;
    cryptonote::network_type nettype;

  public:
    // Constructs a BLSSigner; if the `key` is nullptr, a key is generated; otherwise the key is
    // loaded from the given bls_secret_key data.
    explicit BLSSigner(const cryptonote::network_type nettype, const bls_secret_key* key = nullptr);

    // See -standing `signMsg` except the `msg` is signed by this class's key and network type.
    bls_signature signMsg(std::span<const uint8_t> msg) const;

    // See free-standing `verifyMsg` except the `msg` is verified by this class's network type.
    bool verifyMsg(const bls_signature& signature, const bls_public_key &pubkey, std::span<const uint8_t> msg) const;

    // Sign an arbitrary length message `msg` with the given BLS `key`. The message has a domain
    // separation tag that is disambiguated with the `nettype`.
    static bls_signature signMsg(cryptonote::network_type nettype, const bls::SecretKey& key, std::span<const uint8_t> msg);

    // Verify an arbitrary length message `msg` was signed by the secret key component of the given
    // public BLS `pubkey`.
    static bool verifyMsg(cryptonote::network_type nettype, const bls_signature& signature, const bls_public_key &pubkey, std::span<const uint8_t> msg);

    // Create a proof signing over the `sender` and `serviceNodePubkey` that this class is in
    // possession of the secret component of the associated public key.
    bls_signature proofOfPossession(
            const eth::address& sender, const crypto::public_key& serviceNodePubkey) const;

    // Gets the public key in hex representation
    std::string getPubkeyHex() const;

    // Gets the public key in herumi/bls representation
    bls::PublicKey getPubkey() const;

    // Gets the public key as our crypto::bls_public_key type
    bls_public_key getCryptoPubkey() const;

    // Gets the secret key as our crypto::bls_secret_key type
    bls_secret_key getCryptoSeckey() const;

    // Construct the domain separation tag used to disambiguate signatures with the same contents
    // across in different network types.
    static crypto::hash buildTagHash(std::string_view baseTag, cryptonote::network_type nettype);

    // See free-standing `buildTagHash`; returns the tag as a hex string.
    static std::string buildTagHex(std::string_view baseTag, cryptonote::network_type nettype);

    // See free-standing `buildTagHex`. This class's network type is passed in.
    std::string buildTagHex(std::string_view baseTag) const;

    // See free-standing `buildTagHash`. This class's network type is passed in.
    crypto::hash buildTagHash(std::string_view baseTag) const;

    static constexpr inline std::string_view proofOfPossessionTag = "BLS_SIG_TRYANDINCREMENT_POP";
    static constexpr inline std::string_view rewardTag = "BLS_SIG_TRYANDINCREMENT_REWARD";
    static constexpr inline std::string_view exitTag = "BLS_SIG_TRYANDINCREMENT_REMOVE";
    static constexpr inline std::string_view liquidateTag = "BLS_SIG_TRYANDINCREMENT_LIQUIDATE";
    static constexpr inline std::string_view hashToG2Tag = "BLS_SIG_HASH_TO_FIELD_TAG";
};

}  // namespace eth
