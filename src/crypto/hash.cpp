#include "hash.h"

#include "crypto/cn_heavy_hash.hpp"

namespace crypto {

static_assert(sizeof(hash) == HASH_SIZE, "Invalid structure size");
static_assert(sizeof(hash8) == 8, "Invalid structure size");

constexpr size_t SIZE_TS_IN_HASH = crypto::hash::size() / sizeof(size_t);
static_assert(
        SIZE_TS_IN_HASH * sizeof(size_t) == sizeof(crypto::hash) &&
                alignof(crypto::hash) >= alignof(size_t),
        "Expected crypto::hash size/alignment not satisfied");

crypto::hash& crypto::hash::operator^=(const crypto::hash& b) {
    const auto* src = reinterpret_cast<const size_t*>(b.data());
    auto* dest = reinterpret_cast<size_t*>(data());
    for (size_t i = 0; i < SIZE_TS_IN_HASH; ++i)
        dest[i] ^= src[i];
    return *this;
}

crypto::hash crypto::hash::operator^(const crypto::hash& b) const {
    crypto::hash c = *this;
    c ^= b;
    return c;
}

crypto::hash& crypto::hash::operator=(const crypto::hash8& h) {
    zero();
    std::copy(h.data(), h.data() + h.size(), data());
    return *this;
}

void cn_slow_hash(const void* data, std::size_t length, hash& hash, cn_slow_hash_type type) {
    switch (type) {
        case cn_slow_hash_type::heavy_v1:
        case cn_slow_hash_type::heavy_v2: {
            static thread_local cn_heavy_hash_v2 v2;
            static thread_local cn_heavy_hash_v1 v1 = cn_heavy_hash_v1::make_borrowed(v2);

            if (type == cn_slow_hash_type::heavy_v1)
                v1.hash(data, length, hash.data());
            else
                v2.hash(data, length, hash.data());
        } break;

#ifdef ENABLE_MONERO_SLOW_HASH
        case cn_slow_hash_type::cryptonight_v0:
        case cn_slow_hash_type::cryptonight_v1_prehashed: {
            int variant = 0, prehashed = 0;
            if (type == cn_slow_hash_type::cryptonight_v1_prehashed) {
                prehashed = 1;
                variant = 1;
            } else if (type == cn_slow_hash_type::cryptonight_v0_prehashed) {
                prehashed = 1;
            }

            cn_monero_hash(data, length, hash.data(), variant, prehashed);
        } break;
#endif

        case cn_slow_hash_type::turtle_lite_v2:
        default: {
            constexpr uint32_t CN_TURTLE_SCRATCHPAD = 262144;
            constexpr uint32_t CN_TURTLE_ITERATIONS = 131072;
            cn_turtle_hash(
                    data,
                    length,
                    hash.data(),
                    1,  // light
                    2,  // variant
                    0,  // pre-hashed
                    CN_TURTLE_SCRATCHPAD,
                    CN_TURTLE_ITERATIONS);
        } break;
    }
}

}  // namespace crypto
