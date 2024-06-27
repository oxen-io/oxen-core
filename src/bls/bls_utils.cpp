#include "bls_utils.h"

#include <oxenc/hex.h>
#include <oxenc/endian.h>

#include <cstring>
#include <type_traits>

#include "common/guts.h"
#include "common/exception.h"
#include "crypto/crypto.h"

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

namespace bls_utils {

static bool _need_init = true;
static std::mutex _init_mutex;

void init() {
    if (!_need_init) [[likely]]
        return;

    std::lock_guard lock{_init_mutex};
    if (!_need_init) [[unlikely]]
        return;

    // Initialize parameters for BN256 curve, this has a different name in our library
    bls::init(mclBn_CurveSNARK1);
    // Try and Inc method for hashing to the curve
    mclBn_setMapToMode(MCL_MAP_TO_MODE_TRY_AND_INC);
    // Our generator point was created using the old hash to curve method, redo it again using Try
    // and Inc method
    mcl::bn::G1 gen;
    bool b;
    mcl::bn::mapToG1(&b, gen, 1);

    blsPublicKey publicKey;
    static_assert(
            sizeof(publicKey.v) == sizeof(gen),
            "We memcpy into a C structure hence sizes must be the same");
    std::memcpy(&publicKey.v, &gen, sizeof(gen));

    blsSetGeneratorOfPublicKey(&publicKey);

    _need_init = false;
}

/// Serialize a bls point-backed type (bls::Signature, bls::PublicKey) into our desired
/// serialization format (to be compatible with Solidity's BN256G1 library), which wants a
/// normalized (z == 1) form, with decompressed x and y values in big-endian byte format.
///
/// For signatures, that is G2 (with 64-bit x and y); for pubkeys G1 (with 32-bit x and y), but
/// aside from which curve is used, the operation here is identical (and hence this templated
/// function).
///
/// Herumi BLS makes this difficult, though, as it wants to use its own serialization functions, but
/// they won't do what we need, hence this code which gets a little dirty with the herumi BLS
/// internals to do our own serialization.
template <typename CryptoT, typename Gx, typename BLS_T>
static CryptoT to_normalized_crypto(const BLS_T& in) {
    init();
    CryptoT serialized{};

    // Divide the output into the X,Y components:
    auto [x, y] = tools::subspans<sizeof(CryptoT) / 2>(serialized);

    const auto* blsraw = in.getPtr();
    static_assert(sizeof(blsraw->v) == sizeof(Gx));
    const Gx* point_in = reinterpret_cast<const Gx*>(&blsraw->v);

    // Copy the point from then input because we need to normalize it to z == 1 (so that we don't
    // have to serialize the z value at all).
    Gx point = *point_in;
    point.normalize();
    if (point.x.serialize(x.data(), x.size(), BLS_MODE_BINARY) == 0)
        throw oxen::runtime_error("size of x is zero");
    if (point.y.serialize(y.data(), y.size(), BLS_MODE_BINARY) == 0)
        throw oxen::runtime_error("size of y is zero");

    return serialized;
}

crypto::bls_signature to_crypto_signature(const bls::Signature& sig) {
    return to_normalized_crypto<crypto::bls_signature, mcl::bn::G2>(sig);
}

crypto::bls_public_key to_crypto_pubkey(const bls::PublicKey& publicKey) {
    return to_normalized_crypto<crypto::bls_public_key, mcl::bn::G1>(publicKey);
}
static_assert(std::is_same_v<char*, std::remove_const_t<std::remove_pointer_t<const char*>>*>);

/// This is the reverse of to_normalized_crypto: it takes a crypto::bls_signature or
/// crypto::bls_pubkey value, encoded in Solidity's BN256G1/2 form, and deserializes it into a
/// herumi bls::Signature of bls::PublicKey object.
template <typename BLS_T, typename Gx, typename CryptoT>
static BLS_T from_normalized_crypto(const CryptoT& in) {
    init();

    // This herumi API is atrocious.
    //
    // TODO: It's impossible to create a bls::PublicKey from a G1 point through the C++ interface.
    // It allows deserialization from a hex or binary string, but, the hex string must originally
    // have been serialised through its member function.
    //
    // Since we have a custom format for Solidity, although we can reconstruct the individual
    // components of the public key in binary we have to go a roundabout way to load these bytes
    // into the key with this not-very-nice casting.

    BLS_T bls;
    bls.clear();

    // const_cast away the pointer's constness which is gross but legal because the original object
    // was not declared const and the herumi C++ API forces const on them for no good reason.
    using BlsRawT = std::remove_const_t<std::remove_pointer_t<decltype(bls.getPtr())>>;
    auto* blsraw = const_cast<BlsRawT*>(bls.getPtr());
    static_assert(sizeof(blsraw->v) == sizeof(Gx));
    static_assert(alignof(decltype(blsraw->v)) >= alignof(Gx));
    auto* point = reinterpret_cast<Gx*>(&blsraw->v);

    constexpr size_t component_size = sizeof(CryptoT) / 2;
    static_assert(component_size == sizeof(blsraw->v.x));

    // When serializing we normalize, which means we have an implicit z = 1 to load (which we load
    // from this little endian value for convenience):
    constexpr std::array<unsigned char, component_size> z = {1, 0, /*..., 0*/};

    auto [x, y] = tools::subspans<component_size>(in);
    size_t readX = point->x.deserialize(x.data(), x.size(), BLS_MODE_BINARY);
    size_t readY = point->y.deserialize(y.data(), y.size(), BLS_MODE_BINARY);
    [[maybe_unused]] size_t readZ = point->z.deserialize(z.data(), z.size(), mcl::IoSerialize);

    assert(readZ == z.size());
    if (bool x_fail = readX != x.size(); x_fail || readY != x.size())
        throw oxen::runtime_error{
                "Failed to deserialize BLS {} component from input value '{:x}'"_format(
                        x_fail ? 'x' : 'y', in)};
    return bls;
}

bls::Signature from_crypto_signature(const crypto::bls_signature& sig) {
    return from_normalized_crypto<bls::Signature, mcl::bn::G2>(sig);
}

bls::PublicKey from_crypto_pubkey(const crypto::bls_public_key& pk) {
    return from_normalized_crypto<bls::PublicKey, mcl::bn::G1>(pk);
}

[[nodiscard]] bool verify(
        const crypto::bls_signature& sig,
        const crypto::hash& hash,
        const crypto::bls_public_key& pk) {
    init();

    return from_crypto_signature(sig).verifyHash(from_crypto_pubkey(pk), hash.data(), hash.size());
}

std::string PublicKeyToHex(const bls::PublicKey& publicKey) {
    auto pk = to_crypto_pubkey(publicKey);
    return oxenc::to_hex(pk.begin(), pk.end());
}
std::string SignatureToHex(const bls::Signature& sig) {
    auto s = to_crypto_signature(sig);
    return oxenc::to_hex(s.begin(), s.end());
}
}  // namespace bls_utils
