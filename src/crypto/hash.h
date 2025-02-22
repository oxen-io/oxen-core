// Copyright (c) 2014-2019, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <cstddef>
#include <span>
#include <type_traits>

#include "base.h"
#include "hash-ops.h"
#include "keccak.h"

namespace crypto {

struct hash8 : bytes<8, true> {
    explicit operator bool() const { return data_ != null<hash8>.data_; }
};

struct hash4 : bytes<4, true, uint32_t> {};

struct hash : bytes<HASH_SIZE, true> {
    explicit operator bool() const { return data_ != null<hash>.data_; }

    // Combine hashes together via XORs.
    hash& operator^=(const crypto::hash& h);
    hash operator^(const crypto::hash& h) const;

    // Assigning a hash8 copies the 8 bytes from the hash8 into the first 8 bytes of the hash and
    // zeros the rest.
    hash& operator=(const crypto::hash8& h);
};

/*
  Cryptonight hash functions
*/

using ::cn_fast_hash;
inline void cn_fast_hash(const void* data, std::size_t length, hash& hash) {
    cn_fast_hash(data, length, hash.data());
}

inline hash cn_fast_hash(const void* data, std::size_t length) {
    hash h;
    cn_fast_hash(data, length, h);
    return h;
}

inline void keccak_update(KECCAK_CTX& ctx, std::span<const unsigned char> piece) {
    ::keccak_update(&ctx, piece.data(), piece.size());
}
inline void keccak_update(KECCAK_CTX& ctx, std::span<const char> piece) {
    ::keccak_update(&ctx, reinterpret_cast<const uint8_t*>(piece.data()), piece.size());
}
inline void keccak_update(KECCAK_CTX& ctx, std::span<const std::byte> piece) {
    ::keccak_update(&ctx, reinterpret_cast<const uint8_t*>(piece.data()), piece.size());
}

template <typename T>
concept byte_span_convertible = std::convertible_to<T, std::span<const char>> ||
                                std::convertible_to<T, std::span<const unsigned char>> ||
                                std::convertible_to<T, std::span<const std::byte>>;

template <typename Hash>
concept keccak_hashable = Hash::size() % 8 == 0 && (Hash::size() <= 100 || Hash::size() == 200);

// C++ version of keccak() that takes any number of char or unsigned char character spans (such as
// vectors, arrays, strings) and keccaks them, writing the hash into a `Hash` that gets returned.
template <keccak_hashable Hash = crypto::hash, byte_span_convertible... T>
Hash keccak(T&&... piece) {
    Hash hash;
    if constexpr (sizeof...(T) == 1) {
        (::keccak(
                 reinterpret_cast<const uint8_t*>(piece.data()),
                 piece.size(),
                 hash.data(),
                 hash.size()),
         ...);
    } else {
        KECCAK_CTX ctx;
        ::keccak_init(&ctx);
        (crypto::keccak_update(ctx, std::forward<T>(piece)), ...);
        ::keccak_finish(&ctx, hash.data(), hash.size());
    }
    return hash;
}

// Multi-argument version of keccak_update (so that you can provide multiple update arguments at
// once), like with the `keccak()` function above, when building a more complex hashed value.
template <byte_span_convertible... T>
    requires(sizeof...(T) > 1)
void keccak_update(KECCAK_CTX& ctx, T&&... piece) {
    (keccak_update(ctx, std::forward<T>(piece)), ...);
}

// Version of keccak that always does a 32-byte keccak but then truncates the results to fit into
// the given Hash type.  This is used for some ETH smart contract functionality (such as calling
// functions inside contracts) that does a 32-byte keccak but then keeps just the first 4 bytes of
// it by using this with `Hash=crypto::hash4`.
//
// (This is in contract with the `keccak()` function above that does a `Hash`-sized keccak hash).
template <typename Hash, byte_span_convertible... T>
    requires(std::is_trivially_copyable_v<Hash> && Hash::size() < crypto::hash::size())
Hash keccak_prefix(T&&... piece) {
    crypto::hash full = keccak(std::forward<T>(piece)...);
    Hash result;
    std::memcpy(result.data(), full.data(), result.size());
    return result;
}

enum struct cn_slow_hash_type {
#ifdef ENABLE_MONERO_SLOW_HASH
    // NOTE: Monero's slow hash for Android only, we still use the old hashing algorithm for hashing
    // the KeyStore containing private keys
    cryptonight_v0 = 0,
    cryptonight_v0_prehashed,
    cryptonight_v1_prehashed,
#endif

    heavy_v1 = 3,
    heavy_v2,
    turtle_lite_v2,
};

void cn_slow_hash(const void* data, std::size_t length, hash& hash, cn_slow_hash_type type);

using ::tree_hash;
inline void tree_hash(const hash* hashes, std::size_t count, hash& root_hash) {
    tree_hash(reinterpret_cast<const unsigned char(*)[HASH_SIZE]>(hashes), count, root_hash.data());
}

}  // namespace crypto

template <>
struct std::hash<crypto::hash> : crypto::raw_hasher<crypto::hash> {};
template <>
struct std::hash<crypto::hash8> : crypto::raw_hasher<crypto::hash8> {};
