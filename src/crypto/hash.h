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

#include <stddef.h>
#include <iostream>

#include "generic-ops.h"
#include "epee/hex.h"
#include "epee/span.h"
#include "crypto/cn_heavy_hash.hpp"

namespace crypto {

  extern "C" {
#include "hash-ops.h"
  }

  struct alignas(size_t) hash {
    char data[HASH_SIZE];
    static constexpr hash null() { return {0}; }
    operator bool() const { return memcmp(data, null().data, sizeof(data)); }
  };
  struct hash8 {
    char data[8];
  };

  static_assert(sizeof(hash) == HASH_SIZE, "Invalid structure size");
  static_assert(sizeof(hash8) == 8, "Invalid structure size");

  /*
    Cryptonight hash functions
  */

  inline void cn_fast_hash(const void *data, std::size_t length, hash &hash) {
    cn_fast_hash(data, length, reinterpret_cast<char *>(&hash));
  }

  inline hash cn_fast_hash(const void *data, std::size_t length) {
    hash h;
    cn_fast_hash(data, length, reinterpret_cast<char *>(&h));
    return h;
  }

  enum struct cn_slow_hash_type
  {
#ifdef ENABLE_MONERO_SLOW_HASH
    // NOTE: Monero's slow hash for Android only, we still use the old hashing algorithm for hashing the KeyStore containing private keys
    cryptonight_v0,
    cryptonight_v0_prehashed,
    cryptonight_v1_prehashed,
#endif

    heavy_v1,
    heavy_v2,
    turtle_lite_v2,
  };

  inline void cn_slow_hash(const void *data, std::size_t length, hash &hash, cn_slow_hash_type type) {
    switch(type)
    {
      case cn_slow_hash_type::heavy_v1:
      case cn_slow_hash_type::heavy_v2:
      {
        static thread_local cn_heavy_hash_v2 v2;
        static thread_local cn_heavy_hash_v1 v1 = cn_heavy_hash_v1::make_borrowed(v2);

        if (type == cn_slow_hash_type::heavy_v1) v1.hash(data, length, hash.data);
        else                                     v2.hash(data, length, hash.data);
      }
      break;

#ifdef ENABLE_MONERO_SLOW_HASH
      case cn_slow_hash_type::cryptonight_v0:
      case cn_slow_hash_type::cryptonight_v1_prehashed:
      {
        int variant = 0, prehashed = 0;
        if (type == cn_slow_hash_type::cryptonight_v1_prehashed)
        {
          prehashed = 1;
          variant   = 1;
        }
        else if (type == cn_slow_hash_type::cryptonight_v0_prehashed)
        {
          prehashed = 1;
        }

        cn_monero_hash(data, length, hash.data, variant, prehashed);
      }
      break;
#endif

      case cn_slow_hash_type::turtle_lite_v2:
      default:
      {
         const uint32_t CN_TURTLE_SCRATCHPAD = 262144;
         const uint32_t CN_TURTLE_ITERATIONS = 131072;
         cn_turtle_hash(data,
             length,
             hash.data,
             1, // light
             2, // variant
             0, // pre-hashed
             CN_TURTLE_SCRATCHPAD, CN_TURTLE_ITERATIONS);
      }
      break;
    }
  }

  inline void tree_hash(const hash *hashes, std::size_t count, hash &root_hash) {
    tree_hash(reinterpret_cast<const char (*)[HASH_SIZE]>(hashes), count, reinterpret_cast<char *>(&root_hash));
  }

  constexpr size_t SIZE_TS_IN_HASH = sizeof(crypto::hash) / sizeof(size_t);
  static_assert(SIZE_TS_IN_HASH * sizeof(size_t) == sizeof(crypto::hash) && alignof(crypto::hash) >= alignof(size_t),
      "Expected crypto::hash size/alignment not satisfied");

  // Combine hashes together via XORs.
  inline crypto::hash& operator^=(crypto::hash& a, const crypto::hash& b) {
    size_t (&dest)[SIZE_TS_IN_HASH] = reinterpret_cast<size_t (&)[SIZE_TS_IN_HASH]>(a);
    const size_t (&src)[SIZE_TS_IN_HASH] = reinterpret_cast<const size_t (&)[SIZE_TS_IN_HASH]>(b);
    for (size_t i = 0; i < SIZE_TS_IN_HASH; ++i)
      dest[i] ^= src[i];
    return a;
  }
  inline crypto::hash operator^(const crypto::hash& a, const crypto::hash& b) {
    crypto::hash c = a;
    c ^= b;
    return c;
  }

  inline std::ostream &operator <<(std::ostream &o, const crypto::hash &v) {
    epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
  }
  inline std::ostream &operator <<(std::ostream &o, const crypto::hash8 &v) {
    epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
  }

  constexpr inline crypto::hash null_hash = {};
  constexpr inline crypto::hash8 null_hash8 = {};
}

CRYPTO_MAKE_HASHABLE(hash)
CRYPTO_MAKE_COMPARABLE(hash8)
