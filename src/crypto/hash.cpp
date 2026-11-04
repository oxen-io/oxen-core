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

// The heavy v1 context borrows the (larger) scratchpad of the thread's heavy v2 context, so that a
// thread using both allocates only one.
static cn_heavy_hash_v2& heavy_v2_context() {
    static thread_local cn_heavy_hash_v2 v2;
    return v2;
}
static cn_heavy_hash_v1& heavy_v1_context() {
    static thread_local cn_heavy_hash_v1 v1 = cn_heavy_hash_v1::make_borrowed(heavy_v2_context());
    return v1;
}

void cn_heavy_v1(std::span<const char> data, std::span<unsigned char, HASH_SIZE> out) {
    heavy_v1_context().hash(data.data(), data.size(), out.data());
}

hash cn_heavy_v1(std::span<const char> data) {
    hash h;
    cn_heavy_v1(data, h.data_);
    return h;
}

hash cn_heavy_v2(std::span<const char> data) {
    hash h;
    heavy_v2_context().hash(data.data(), data.size(), h.data());
    return h;
}

hash cn_turtle_lite_v2(std::span<const char> data) {
    constexpr uint32_t CN_TURTLE_SCRATCHPAD = 262144;
    constexpr uint32_t CN_TURTLE_ITERATIONS = 131072;
    hash h;
    cn_turtle_hash(
            data.data(),
            data.size(),
            h.data(),
            1,  // light
            2,  // variant
            0,  // pre-hashed
            CN_TURTLE_SCRATCHPAD,
            CN_TURTLE_ITERATIONS);
    return h;
}

#ifdef ENABLE_MONERO_SLOW_HASH
hash cn_monero_v0(std::span<const char> data) {
    hash h;
    cn_monero_hash(data.data(), data.size(), h.data(), 0 /*variant*/, 0 /*prehashed*/);
    return h;
}

hash cn_monero_v0_prehashed(std::span<const char> data) {
    hash h;
    cn_monero_hash(data.data(), data.size(), h.data(), 0 /*variant*/, 1 /*prehashed*/);
    return h;
}

hash cn_monero_v1_prehashed(std::span<const char> data) {
    hash h;
    cn_monero_hash(data.data(), data.size(), h.data(), 1 /*variant*/, 1 /*prehashed*/);
    return h;
}
#endif

}  // namespace crypto
