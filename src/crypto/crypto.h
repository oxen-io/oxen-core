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
#include <iostream>
#include <optional>
#include <type_traits>
#include <vector>
#include <random>

#include "memwipe.h"
#include "mlocker.h"
#include "generic-ops.h"
#include "hex.h"
#include "span.h"
#include "hash.h"

namespace crypto {

  extern "C" {
#include "random.h"
  }

  struct alignas(size_t) ec_point {
    char data[32];
    // Returns true if non-null, i.e. not 0.
    operator bool() const { static constexpr char null[32] = {0}; return memcmp(data, null, sizeof(data)); }
  };

  struct alignas(size_t) ec_scalar {
    char data[32];
  };

  struct public_key : ec_point {};

  using secret_key = epee::mlocked<tools::scrubbed<ec_scalar>>;

  struct public_keyV {
    std::vector<public_key> keys;
    int rows;
  };

  struct secret_keyV {
    std::vector<secret_key> keys;
    int rows;
  };

  struct public_keyM {
    int cols;
    int rows;
    std::vector<secret_keyV> column_vectors;
  };

  struct key_derivation: ec_point {};

  struct key_image: ec_point {};

  struct signature {
    ec_scalar c, r;

    // Returns true if non-null, i.e. not 0.
    operator bool() const { static constexpr char null[64] = {0}; return memcmp(this, null, sizeof(null)); }
  };

  // The sizes below are all provided by sodium.h, but we don't want to depend on it here; we check
  // that they agree with the actual constants from sodium.h when compiling cryptonote_core.cpp.
  struct alignas(size_t) ed25519_public_key {
    unsigned char data[32]; // 32 = crypto_sign_ed25519_PUBLICKEYBYTES
    static constexpr ed25519_public_key null() { return {0}; }
    /// Returns true if non-null
    operator bool() const { return memcmp(data, null().data, sizeof(data)); }
  };

  struct alignas(size_t) ed25519_secret_key_ {
    // 64 = crypto_sign_ed25519_SECRETKEYBYTES (but we don't depend on libsodium header here)
    unsigned char data[64];
  };
  using ed25519_secret_key = epee::mlocked<tools::scrubbed<ed25519_secret_key_>>;

  struct alignas(size_t) ed25519_signature {
    unsigned char data[64]; // 64 = crypto_sign_BYTES
    static constexpr ed25519_signature null() { return {0}; }
    // Returns true if non-null, i.e. not 0.
    operator bool() const { auto z = null(); return memcmp(this, &z, sizeof(z)); }
  };

  struct alignas(size_t) x25519_public_key {
    unsigned char data[32]; // crypto_scalarmult_curve25519_BYTES
    static constexpr x25519_public_key null() { return {0}; }
    /// Returns true if non-null
    operator bool() const { return memcmp(data, null().data, sizeof(data)); }
  };

  struct alignas(size_t) x25519_secret_key_ {
    unsigned char data[32]; // crypto_scalarmult_curve25519_BYTES
  };
  using x25519_secret_key = epee::mlocked<tools::scrubbed<x25519_secret_key_>>;

  void hash_to_scalar(const void *data, size_t length, ec_scalar &res);
  void random32_unbiased(unsigned char *bytes);

  static_assert(sizeof(ec_point) == 32 && sizeof(ec_scalar) == 32 &&
    sizeof(public_key) == 32 && sizeof(secret_key) == 32 &&
    sizeof(key_derivation) == 32 && sizeof(key_image) == 32 &&
    sizeof(signature) == 64, "Invalid structure size");

  void generate_random_bytes_thread_safe(size_t N, uint8_t *bytes);
  void add_extra_entropy_thread_safe(const void *ptr, size_t bytes);

  /* Generate N random bytes
   */
  inline void rand(size_t N, uint8_t *bytes) {
    generate_random_bytes_thread_safe(N, bytes);
  }

  /* Generate a value filled with random bytes.
   */
  template<typename T>
  typename std::enable_if<std::is_pod<T>::value, T>::type rand() {
    typename std::remove_cv<T>::type res;
    generate_random_bytes_thread_safe(sizeof(T), (uint8_t*)&res);
    return res;
  }

  /* UniformRandomBitGenerator using crypto::rand<uint64_t>()
   */
  struct random_device
  {
    typedef uint64_t result_type;
    static constexpr result_type min() { return 0; }
    static constexpr result_type max() { return result_type(-1); }
    result_type operator()() const { return crypto::rand<result_type>(); }
  };

  /* Generate a random value between range_min and range_max
   */
  template<typename T>
  typename std::enable_if<std::is_integral<T>::value, T>::type rand_range(T range_min, T range_max) {
    crypto::random_device rd;
    std::uniform_int_distribution<T> dis(range_min, range_max);
    return dis(rd);
  }

  /* Generate a random index between 0 and sz-1
   */
  template<typename T>
  typename std::enable_if<std::is_unsigned<T>::value, T>::type rand_idx(T sz) {
    return crypto::rand_range<T>(0, sz-1);
  }

  /* Generate a new key pair
   */
  secret_key generate_keys(public_key &pub, secret_key &sec, const secret_key& recovery_key = secret_key(), bool recover = false);

  /* Check a public key. Returns true if it is valid, false otherwise.
   */
  bool check_key(const public_key &key);

  /* Checks a private key and computes the corresponding public key.
   */
  bool secret_key_to_public_key(const secret_key &sec, public_key &pub);

  /* To generate an ephemeral key used to send money to:
   * * The sender generates a new key pair, which becomes the transaction key. The public transaction key is included in "extra" field.
   * * Both the sender and the receiver generate key derivation from the transaction key, the receivers' "view" key and the output index.
   * * The sender uses key derivation and the receivers' "spend" key to derive an ephemeral public key.
   * * The receiver can either derive the public key (to check that the transaction is addressed to him) or the private key (to spend the money).
   */
  bool generate_key_derivation(const public_key &key1, const secret_key &key2, key_derivation &derivation);
  bool derive_public_key(const key_derivation &derivation, std::size_t output_index, const public_key &base, public_key &derived_key);
  void derivation_to_scalar(const key_derivation &derivation, size_t output_index, ec_scalar &res);
  void derive_secret_key(const key_derivation &derivation, std::size_t output_index, const secret_key &base, secret_key &derived_key);
  bool derive_subaddress_public_key(const public_key &out_key, const key_derivation &derivation, std::size_t output_index, public_key &result);

  /* Generation and checking of a standard signature.
   */
  void generate_signature(const hash &prefix_hash, const public_key &pub, const secret_key &sec, signature &sig);
  bool check_signature(const hash &prefix_hash, const public_key &pub, const signature &sig);

  /* Generation and checking of a tx proof; given a tx pubkey R, the recipient's view pubkey A, and the key 
   * derivation D, the signature proves the knowledge of the tx secret key r such that R=r*G and D=r*A
   * When the recipient's address is a subaddress, the tx pubkey R is defined as R=r*B where B is the recipient's spend pubkey
   */
  void generate_tx_proof(const hash &prefix_hash, const public_key &R, const public_key &A, const std::optional<public_key> &B, const public_key &D, const secret_key &r, signature &sig);
  bool check_tx_proof(const hash &prefix_hash, const public_key &R, const public_key &A, const std::optional<public_key> &B, const public_key &D, const signature &sig);

  /* To send money to a key:
   * * The sender generates an ephemeral key and includes it in transaction output.
   * * To spend the money, the receiver generates a key image from it.
   * * Then he selects a bunch of outputs, including the one he spends, and uses them to generate a ring signature.
   * To check the signature, it is necessary to collect all the keys that were used to generate it. To detect double spends, it is necessary to check that each key image is used at most once.
   */
  void generate_key_image(const public_key &pub, const secret_key &sec, key_image &image);
  void generate_ring_signature(const hash &prefix_hash, const key_image &image,
    const public_key *const *pubs, std::size_t pubs_count,
    const secret_key &sec, std::size_t sec_index,
    signature *sig);
  bool check_ring_signature(const hash &prefix_hash, const key_image &image,
    const public_key *const *pubs, std::size_t pubs_count,
    const signature *sig);

  /* Variants with vector<const public_key *> parameters.
   */
  inline void generate_ring_signature(const hash &prefix_hash, const key_image &image,
    const std::vector<const public_key *> &pubs,
    const secret_key &sec, std::size_t sec_index,
    signature *sig) {
    generate_ring_signature(prefix_hash, image, pubs.data(), pubs.size(), sec, sec_index, sig);
  }
  inline bool check_ring_signature(const hash &prefix_hash, const key_image &image,
    const std::vector<const public_key *> &pubs,
    const signature *sig) {
    return check_ring_signature(prefix_hash, image, pubs.data(), pubs.size(), sig);
  }

  inline std::ostream &operator <<(std::ostream &o, const crypto::public_key &v) {
    epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
  }
  inline std::ostream &operator <<(std::ostream &o, const crypto::secret_key &v) {
    epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
  }
  inline std::ostream &operator <<(std::ostream &o, const crypto::key_derivation &v) {
    epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
  }
  inline std::ostream &operator <<(std::ostream &o, const crypto::key_image &v) {
    epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
  }
  inline std::ostream &operator <<(std::ostream &o, const crypto::signature &v) {
    epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
  }
  inline std::ostream &operator <<(std::ostream &o, const crypto::ed25519_public_key &v) {
    epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
  }
  inline std::ostream &operator <<(std::ostream &o, const crypto::x25519_public_key &v) {
    epee::to_hex::formatted(o, epee::as_byte_span(v)); return o;
  }
  constexpr inline crypto::public_key null_pkey{};
  const inline crypto::secret_key null_skey{};
}

CRYPTO_MAKE_HASHABLE(public_key)
CRYPTO_MAKE_HASHABLE_CONSTANT_TIME(secret_key)
CRYPTO_MAKE_HASHABLE(key_image)
CRYPTO_MAKE_HASHABLE(signature)
CRYPTO_MAKE_HASHABLE(ed25519_public_key)
CRYPTO_MAKE_HASHABLE(x25519_public_key)
