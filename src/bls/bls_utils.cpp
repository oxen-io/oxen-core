#include "bls_utils.h"

#include <oxenc/hex.h>

#include <cstring>

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

std::string bls_utils::SignatureToHex(const bls::Signature& sig) {
    const mclSize serializedSignatureSize = 32;
    std::array<char, serializedSignatureSize* 4> serialized_signature = {};
    char* dst = serialized_signature.data();
    const blsSignature* blssig = sig.getPtr();
    const mcl::bn::G2* g2Point = reinterpret_cast<const mcl::bn::G2*>(&blssig->v);
    mcl::bn::G2 g2Point2 = *g2Point;
    g2Point2.normalize();
    if (g2Point2.x.a.serialize(dst, serializedSignatureSize, mcl::IoSerialize | mcl::IoBigEndian) ==
        0)
        throw std::runtime_error("size of x.a is zero");
    if (g2Point2.x.b.serialize(
                dst + serializedSignatureSize,
                serializedSignatureSize,
                mcl::IoSerialize | mcl::IoBigEndian) == 0)
        throw std::runtime_error("size of x.b is zero");
    if (g2Point2.y.a.serialize(
                dst + serializedSignatureSize * 2,
                serializedSignatureSize,
                mcl::IoSerialize | mcl::IoBigEndian) == 0)
        throw std::runtime_error("size of y.a is zero");
    if (g2Point2.y.b.serialize(
                dst + serializedSignatureSize * 3,
                serializedSignatureSize,
                mcl::IoSerialize | mcl::IoBigEndian) == 0)
        throw std::runtime_error("size of y.b is zero");
    return oxenc::to_hex(serialized_signature.begin(), serialized_signature.end());
}

std::string bls_utils::PublicKeyToHex(const bls::PublicKey& publicKey) {
    const mclSize KEY_SIZE = 32;
    std::array<char, KEY_SIZE* 2 /*X, Y component*/> serializedKeyHex = {};

    char* dst = serializedKeyHex.data();
    const blsPublicKey* rawKey = publicKey.getPtr();

    mcl::bn::G1 g1Point = {};
    g1Point.clear();

    // NOTE: const_cast is legal because the original g1Point was not declared
    // const
    static_assert(
            sizeof(*g1Point.x.getUnit()) * g1Point.x.maxSize == sizeof(rawKey->v.x.d),
            "We memcpy the key X,Y,Z component into G1 point's X,Y,Z component, hence, the sizes "
            "must match");
    std::memcpy(const_cast<uint64_t*>(g1Point.x.getUnit()), rawKey->v.x.d, sizeof(rawKey->v.x.d));
    std::memcpy(const_cast<uint64_t*>(g1Point.y.getUnit()), rawKey->v.y.d, sizeof(rawKey->v.y.d));
    std::memcpy(const_cast<uint64_t*>(g1Point.z.getUnit()), rawKey->v.z.d, sizeof(rawKey->v.z.d));
    g1Point.normalize();

    if (g1Point.x.serialize(dst, KEY_SIZE, mcl::IoSerialize | mcl::IoBigEndian) == 0)
        throw std::runtime_error("size of x is zero");
    if (g1Point.y.serialize(dst + KEY_SIZE, KEY_SIZE, mcl::IoSerialize | mcl::IoBigEndian) == 0)
        throw std::runtime_error("size of y is zero");

    std::string result = oxenc::to_hex(serializedKeyHex.begin(), serializedKeyHex.end());
    return result;
}
