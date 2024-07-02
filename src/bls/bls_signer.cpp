#include "bls_signer.h"

#include <epee/memwipe.h>
#include <fmt/core.h>
#include <oxenc/hex.h>

#include <bls/bls.hpp>
#include <ethyl/utils.hpp>
#include <mcl/op.hpp>

#include "bls_utils.h"
#include "common/bigint.h"
#include "common/guts.h"
#include "common/oxen.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("bls_signer");

BLSSigner::BLSSigner(const cryptonote::network_type nettype, const crypto::bls_secret_key* key) :
        nettype{nettype} {
    bls_utils::init();

    if (key) {
        // This interface to load a key from an existing chunk of memory by having to first copy it
        // into a std::string is just terrible.
        std::string key_bytes;
        OXEN_DEFER {
            memwipe(key_bytes.data(), key_bytes.size());
        };
        key_bytes.reserve(sizeof(crypto::bls_secret_key));
        key_bytes.append(reinterpret_cast<const char*>(key->data()), key->size());
        secretKey.setStr(key_bytes, mcl::IoSerialize | mcl::IoBigEndian);
    } else {
        // This init function generates a secret key calling blsSecretKeySetByCSPRNG
        secretKey.init();
    }
}

crypto::hash BLSSigner::buildTagHash(std::string_view baseTag, cryptonote::network_type nettype) {
    const auto config = get_config(nettype);
    return crypto::keccak(
            baseTag,
            tools::encode_integer_be<32>(config.ETHEREUM_CHAIN_ID),
            ethyl::utils::fromHexString(config.ETHEREUM_REWARDS_CONTRACT));
}

crypto::hash BLSSigner::buildTagHash(std::string_view baseTag) const {
    return buildTagHash(baseTag, nettype);
}

std::string BLSSigner::buildTagHex(std::string_view baseTag, cryptonote::network_type nettype) {
    return tools::hex_guts(buildTagHash(baseTag, nettype));
}

std::string BLSSigner::buildTagHex(std::string_view baseTag) const {
    return buildTagHex(baseTag, nettype);
}

static void expand_message_xmd_keccak256(
        std::span<uint8_t> out, std::span<const uint8_t> msg, std::span<const uint8_t> dst)
{
    // NOTE: Setup parameters (note: Our implementation restricts the output to <= 256 bytes)
    const size_t KECCAK256_OUTPUT_SIZE = 256 / 8;
    const uint16_t len_in_bytes        = static_cast<uint16_t>(out.size());
    const size_t b_in_bytes            = KECCAK256_OUTPUT_SIZE; // the output size of H [Keccak] in bits
    const size_t ell                   = len_in_bytes / b_in_bytes;

    // NOTE: Assert invariants
    assert((out.size() % KECCAK256_OUTPUT_SIZE) == 0 && 0 < out.size() && out.size() <= 256);
    assert(dst.size() <= 255);

    // NOTE: Construct (4) Z_pad
    //
    //   s_in_bytes = Input Block Size     = 1088 bits = 136 bytes
    //   Z_pad      = I2OSP(0, s_in_bytes) = [0 .. INPUT_BLOCK_SIZE) => {0 .. 0}
    const        size_t  INPUT_BLOCK_SIZE        = 136;
    static const uint8_t Z_pad[INPUT_BLOCK_SIZE] = {};

    // NOTE: Construct (5) l_i_b_str
    //
    //   l_i_b_str    = I2OSP(len_in_bytes, 2) => output length expressed in big
    //                  endian in 2 bytes.
    uint16_t l_i_b_str = oxenc::host_to_big(static_cast<uint16_t>(out.size()));

    // NOTE: Construct I2OSP(len(DST), 1) for DST_prime
    //   DST_prime          = (DST || I2OSP(len(DST), 1)
    //   I2OSP(len(DST), 1) = DST length expressed in big endian as 1 byte.
    uint8_t I2OSP_0_1 = 0;
    uint8_t I2OSP_len_dst = static_cast<uint8_t>(dst.size());

    // NOTE: Construct (7) b0 = H(msg_prime)
    uint8_t b0[KECCAK256_OUTPUT_SIZE] = {};
    {
        // NOTE: Construct (6) msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
        KECCAK_CTX msg_prime = {};
        keccak_init(&msg_prime);
        keccak_update(&msg_prime, Z_pad, sizeof(Z_pad));
        keccak_update(&msg_prime, msg.data(), msg.size());
        keccak_update(&msg_prime, reinterpret_cast<uint8_t *>(&l_i_b_str), sizeof(l_i_b_str));
        keccak_update(&msg_prime, &I2OSP_0_1, sizeof(I2OSP_0_1));
        keccak_update(&msg_prime, dst.data(), dst.size());
        keccak_update(&msg_prime, &I2OSP_len_dst, sizeof(I2OSP_len_dst));

        // NOTE: Executes H(msg_prime)
        keccak_finish(&msg_prime, b0, sizeof(b0));
    }

    // NOTE: Construct (8) b1 = H(b0 || I2OSP(1, 1) || DST_prime)
    uint8_t b1[KECCAK256_OUTPUT_SIZE] = {};
    {
        uint8_t I2OSP_1_1 = 1;
        KECCAK_CTX ctx    = {};
        keccak_init(&ctx);
        keccak_update(&ctx, b0, sizeof(b0));
        keccak_update(&ctx, &I2OSP_1_1, sizeof(I2OSP_1_1));
        keccak_update(&ctx, dst.data(), dst.size());
        keccak_update(&ctx, &I2OSP_len_dst, sizeof(I2OSP_len_dst));

        // NOTE: Executes H(...)
        keccak_finish(&ctx, b1, sizeof(b1));
    }

    // NOTE: Construct (11) uniform_bytes = b1 ... b_ell
    std::memcpy(out.data(), b1, sizeof(b1));

    for (size_t i = 1; i < ell; i++) {

        // NOTE: Construct strxor(b0, b(i-1))
        uint8_t strxor_b0_bi[KECCAK256_OUTPUT_SIZE] = {};
        for (size_t j = 0; j < KECCAK256_OUTPUT_SIZE; j++) {
            strxor_b0_bi[j] = b0[j] ^ out[KECCAK256_OUTPUT_SIZE * (i - 1) + j];
        }

        // NOTE: Construct (10) bi = H(strxor(b0, b(i - 1)) || I2OSP(i, 1) || DST_prime)
        uint8_t bi[KECCAK256_OUTPUT_SIZE] = {};
        {
            uint8_t I2OSP_i_1 = static_cast<uint8_t>(i + 1);
            KECCAK_CTX ctx    = {};
            keccak_init(&ctx);
            keccak_update(&ctx, strxor_b0_bi, sizeof(strxor_b0_bi));
            keccak_update(&ctx, &I2OSP_i_1, sizeof(I2OSP_i_1));
            keccak_update(&ctx, dst.data(), dst.size());
            keccak_update(&ctx, &I2OSP_len_dst, sizeof(I2OSP_len_dst));

            // NOTE: Executes H(...)
            keccak_finish(&ctx, bi, sizeof(bi));
        }

        // NOTE: Transfer bi to uniform_bytes
        std::memcpy(out.data() + KECCAK256_OUTPUT_SIZE * i, bi, sizeof(bi));
    }
}


static mcl::bn::G2 map_to_g2(std::span<const uint8_t> msg, std::span<const uint8_t> hashToG2Tag) {

    mcl::bn::G2 result = {};
    result.clear();

    std::vector<uint8_t> messageWithI(msg.size() + 1);
    std::memcpy(messageWithI.data(), msg.data(), msg.size());

    for (uint8_t increment = 0;; increment++) {
        messageWithI[messageWithI.size() - 1] = increment;

        // NOTE: Solidity's BN256G2.hashToField(msg, tag) => (x1, x2, b)
        mcl::bn::Fp x1 = {}, x2 = {};
        bool b = false;
        {
            uint8_t expandedBytes[128] = {};
            expand_message_xmd_keccak256(expandedBytes, messageWithI, hashToG2Tag);

            bool converted;
            x1.setBigEndianMod(&converted, expandedBytes + 0,  48);
            assert(converted);
            x2.setBigEndianMod(&converted, expandedBytes + 48, 48);
            assert(converted);

            b = ((expandedBytes[127] & 1) == 1);
        }

        // NOTE: herumi/bls MapTo::mapToEC
        mcl::bn::G2::Fp x = mcl::bn::G2::Fp(x1, x2);
        mcl::bn::G2::Fp y;
        mcl::bn::G2::getWeierstrass(y, x);
        if (mcl::bn::G2::Fp::squareRoot(y, y)) { // Check if this is a point
            if (b)                               // Let b => {0, 1} to choose between the two roots.
                y = -y;
            bool converted;
            result.set(&converted, x, y, false);
            assert(converted);
            return result;                       // Successfully mapped to curve, exit the loop
        }
    }

    return result;
}

bls::Signature BLSSigner::signSig2(std::span<const uint8_t> msg) const {
    // NOTE: This is herumi's 'blsSignHash' deconstructed to its primitive
    // function calls but instead of executing herumi's 'tryAndIncMapTo' which
    // maps a hash to a point we execute our own mapping function. herumi's
    // method increments the x-coordinate to try and map the point.
    //
    // This approach does not follow the original BLS paper's construction of the
    // hash to curve method which does `H(m||i)` e.g. it hashes the message with
    // an integer appended on the end. This integer is incremented and the
    // message is re-hashed if the resulting hash could not be mapped onto the
    // field.

    // NOTE: mcl::bn::blsSignHash(...) -> toG(...)
    // Map a string of `bytes` to a point on the curve for BLS
    mcl::bn::G2 Hm;
    {
        crypto::hash tag = buildTagHash(hashToG2Tag);
        Hm = map_to_g2(msg, tag);
        mcl::bn::BN::param.mapTo.mulByCofactor(Hm);
    }

    // NOTE: mcl::bn::blsSignHash(...) -> GmulCT(...) -> G2::mulCT
    bls::Signature result = {};
    result.clear();
    {
        mcl::bn::Fr s;
        std::memcpy(const_cast<uint64_t*>(s.getUnit()), &secretKey.getPtr()->v, sizeof(s));
        static_assert(sizeof(s) == sizeof(secretKey.getPtr()->v));

        mcl::bn::G2 g2;
        mcl::bn::G2::mulCT(g2, Hm, s);
        std::memcpy(&result.getPtr()->v.x, &g2.x, sizeof(g2.x));
        std::memcpy(&result.getPtr()->v.y, &g2.y, sizeof(g2.y));
        std::memcpy(&result.getPtr()->v.z, &g2.z, sizeof(g2.z));
        static_assert(sizeof(g2) == sizeof(result.getPtr()->v));
    }

    return result;
}

bool BLSSigner::verifyHash(cryptonote::network_type nettype, const bls::Signature& signature, const bls::PublicKey &pubKey, std::span<const uint8_t> hash)
{
    // NOTE: blsVerifyHash => if (cast(&pub->v)->isZero()) return 0;
    if (blsPublicKeyIsZero(pubKey.getPtr()))
        return false;

    // NOTE: blsVerifyHash => toG(*cast(&Hm.v), h, size)
    mcl::bn::G2 Hm;
    {
        crypto::hash tag = BLSSigner::buildTagHash(BLSSigner::hashToG2Tag, nettype);
        Hm = map_to_g2(hash, tag);
        mcl::bn::BN::param.mapTo.mulByCofactor(Hm);
    }

    // NOTE: Create the hm_signature to verify pairing by copying the G2 element in to the signature
    blsSignature hm_signature{};
    std::memcpy(&hm_signature.v, &Hm, sizeof(Hm));
    static_assert(sizeof(hm_signature.v) == sizeof(Hm));

    // NOTE: blsVerifyHash => blsVerifyPairing(sig, &Hm, pub);
    bool result = blsVerifyPairing(signature.getPtr(), &hm_signature, pubKey.getPtr());
    return result;
}

bls::Signature BLSSigner::signHashSig(const crypto::hash& hash) const {
    bls::Signature sig;
    secretKey.signHash(sig, hash.data(), hash.size());
    return sig;
}

crypto::bls_signature BLSSigner::signHash(const crypto::hash& hash) const {
    return bls_utils::to_crypto_signature(signHashSig(hash));
}

crypto::bls_signature BLSSigner::proofOfPossession(
        crypto::eth_address sender, const crypto::public_key& serviceNodePubkey) const {
    auto tag = buildTagHash(proofOfPossessionTag);

    crypto::bls_public_key bls_pkey = getCryptoPubkey();

    // TODO(doyle): Pass in a array of spans to avoid having to do this allocation.
    std::vector<uint8_t> msg;
    msg.reserve(tag.size() + bls_pkey.size() + sender.size() + serviceNodePubkey.size());
    msg.insert(msg.end(), tag.begin(), tag.end());
    msg.insert(msg.end(), bls_pkey.begin(), bls_pkey.end());
    msg.insert(msg.end(), sender.begin(), sender.end());
    msg.insert(msg.end(), serviceNodePubkey.begin(), serviceNodePubkey.end());

    bls::Signature sig = signSig2(msg);
    return bls_utils::to_crypto_signature(sig);
}

std::string BLSSigner::getPublicKeyHex() const {
    auto pk = getCryptoPubkey();
    return oxenc::to_hex(pk.begin(), pk.end());
}

bls::PublicKey BLSSigner::getPublicKey() const {
    bls::PublicKey publicKey;
    secretKey.getPublicKey(publicKey);
    return publicKey;
}

crypto::bls_public_key BLSSigner::getCryptoPubkey() const {
    return bls_utils::to_crypto_pubkey(getPublicKey());
}

crypto::bls_secret_key BLSSigner::getCryptoSeckey() const {
    std::string sec_key = secretKey.getStr(mcl::IoSerialize | mcl::IoBigEndian);
    assert(sec_key.size() == sizeof(crypto::bls_secret_key));

    crypto::bls_secret_key csk;
    std::memcpy(csk.data(), sec_key.data(), sizeof(csk));
    memwipe(sec_key.data(), sec_key.size());
    return csk;
}
