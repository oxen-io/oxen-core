#include "chacha.h"

#include "cn_heavy_hash.hpp"
#include "hash.h"

namespace crypto {

static_assert(
        sizeof(chacha_key) == CHACHA_KEY_SIZE && sizeof(chacha_iv) == CHACHA_IV_SIZE,
        "Invalid structure size");

void chacha8(
        const void* data,
        std::size_t length,
        const chacha_key& key,
        const chacha_iv& iv,
        char* cipher) {
    chacha8(data, length, key.data(), reinterpret_cast<const uint8_t*>(&iv), cipher);
}

void chacha20(
        const void* data,
        std::size_t length,
        const chacha_key& key,
        const chacha_iv& iv,
        char* cipher) {
    chacha20(data, length, key.data(), reinterpret_cast<const uint8_t*>(&iv), cipher);
}

void generate_chacha_key(std::string password, chacha_key& key, uint64_t kdf_rounds) {
    return generate_chacha_key(password.data(), password.size(), key, kdf_rounds);
}

void generate_chacha_key(const void* data, size_t size, chacha_key& key, uint64_t kdf_rounds) {
    static_assert(
            sizeof(chacha_key) <= hash::size(), "Size of hash must be at least that of chacha_key");
    epee::mlocked<tools::scrubbed_arr<char, HASH_SIZE>> pwd_hash;
    static thread_local cn_heavy_hash_v1 ctx;
    ctx.hash(data, size, pwd_hash.data());
    for (uint64_t n = 1; n < kdf_rounds; ++n)
        ctx.hash(pwd_hash.data(), pwd_hash.size(), pwd_hash.data());
    memcpy(&unwrap(unwrap(key)), pwd_hash.data(), sizeof(key));
}

void generate_chacha_key_prehashed(
        const void* data, size_t size, chacha_key& key, uint64_t kdf_rounds) {
    static_assert(
            sizeof(chacha_key) <= hash::size(), "Size of hash must be at least that of chacha_key");
    epee::mlocked<tools::scrubbed_arr<char, HASH_SIZE>> pwd_hash;
    static thread_local cn_heavy_hash_v1 ctx;
    ctx.hash(data, size, pwd_hash.data(), true);
    for (uint64_t n = 1; n < kdf_rounds; ++n)
        ctx.hash(pwd_hash.data(), pwd_hash.size(), pwd_hash.data());
    memcpy(&unwrap(unwrap(key)), pwd_hash.data(), sizeof(key));
}

}  // namespace crypto
