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
#include <random>
#include <type_traits>
#include <vector>

#include "base.h"
#include "epee/memwipe.h"
#include "epee/mlocker.h"
#include "hash.h"

extern "C" {
#include "random.h"
}

namespace crypto {

struct ec_point : bytes<32, true> {
    // Returns true if non-null, i.e. not all 0.
    explicit operator bool() const { return data_ != null<ec_point>.data_; }
};

struct ec_scalar : bytes<32> {
    // constant-time (via libsodium)
    bool operator==(const ec_scalar& x) const;
    bool operator!=(const ec_scalar& x) const { return !(*this == x); }
    // constant-time returns true if not all 0.
    explicit operator bool() const;
};

struct public_key : ec_point {};

struct secret_key_ : ec_scalar {};
using secret_key = epee::mlocked<tools::scrubbed<secret_key_>>;

template <>
inline const secret_key null<secret_key>{};

struct key_derivation : ec_point {};

struct key_image : ec_point {};

struct signature : bytes<64, true> {
    // Returns or sets the "c" part of the signature bytes
    unsigned char* c() { return data(); }
    const unsigned char* c() const { return data(); }
    void c(const ec_scalar& c) { std::copy(c.data(), c.data() + c.size(), data()); }
    // Returns or sets the "r" part of the signature bytes
    unsigned char* r() { return data() + 32; }
    const unsigned char* r() const { return data() + 32; }
    void r(const ec_scalar& r) { std::copy(r.data(), r.data() + r.size(), data()); }

    // Returns true if non-null, i.e. not 0.
    explicit operator bool() const { return data_ != null<signature>.data_; }
};

struct ed25519_public_key : ec_point {};

// 64 = crypto_sign_ed25519_SECRETKEYBYTES (but we don't depend on libsodium header here)
struct ed25519_secret_key_ : bytes<64> {};
using ed25519_secret_key = epee::mlocked<tools::scrubbed<ed25519_secret_key_>>;

struct ed25519_signature : bytes<64, true> {
    // Returns true if non-null, i.e. not 0.
    explicit operator bool() const { return data_ != null<ed25519_signature>.data_; }
};

struct x25519_public_key : ec_point {};

struct x25519_secret_key_ : bytes<32> {};
using x25519_secret_key = epee::mlocked<tools::scrubbed<x25519_secret_key_>>;

struct eth_address : bytes<20, true, uint32_t> {
    // Returns true if non-null, i.e. not all 0.
    explicit operator bool() const { return data_ != null<eth_address>.data_; }
};

struct bls_public_key : bytes<64, true, uint32_t> {
    // Returns true if non-null, i.e. not all 0.
    explicit operator bool() const { return data_ != null<bls_public_key>.data_; }
};

void hash_to_scalar(const void* data, size_t length, ec_scalar& res);
ec_scalar hash_to_scalar(const void* data, size_t length);
void random_scalar(unsigned char* bytes);
void random_scalar(ec_scalar& res);
ec_scalar random_scalar();

void generate_random_bytes_thread_safe(size_t N, uint8_t* bytes);
void add_extra_entropy_thread_safe(const void* ptr, size_t bytes);

/* Generate N random bytes
 */
inline void rand(size_t N, uint8_t* bytes) {
    generate_random_bytes_thread_safe(N, bytes);
}

template <typename T>
concept trivially_copyable = std::is_trivially_copyable_v<T>;

/* Generate a value filled with random bytes.
 */
template <trivially_copyable T>
T rand() {
    using Plain = std::remove_cvref_t<T>;
    Plain res;
    generate_random_bytes_thread_safe(sizeof(res), reinterpret_cast<uint8_t*>(&res));
    return res;
}

/* UniformRandomBitGenerator using crypto::rand<uint64_t>()
 */
struct random_device {
    using result_type = uint64_t;
    static constexpr result_type min() { return 0; }
    static constexpr result_type max() { return std::numeric_limits<result_type>::max(); }
    result_type operator()() const { return crypto::rand<result_type>(); }
};

/* Generate a random value between range_min and range_max
 */
template <std::integral T>
T rand_range(T range_min, T range_max) {
    random_device rd;
    return std::uniform_int_distribution<T>{range_min, range_max}(rd);
}

/* Generate a random index between 0 and sz-1
 */
template <std::integral T>
T rand_idx(T sz) {
    return crypto::rand_range<T>(0, sz - 1);
}

/* Generate a new key pair
 */
secret_key generate_keys(
        public_key& pub,
        secret_key& sec,
        const secret_key& recovery_key = secret_key(),
        bool recover = false);

/* Check a public key. Returns true if it is valid, false otherwise.
 */
bool check_key(const public_key& key);

/* Checks a private key and computes the corresponding public key.
 */
bool secret_key_to_public_key(const secret_key& sec, public_key& pub);

/* To generate an ephemeral key used to send money to:
 * * The sender generates a new key pair, which becomes the transaction key. The public transaction
 * key is included in "extra" field.
 * * Both the sender and the receiver generate key derivation from the transaction key, the
 * receivers' "view" key and the output index.
 * * The sender uses key derivation and the receivers' "spend" key to derive an ephemeral public
 * key.
 * * The receiver can either derive the public key (to check that the transaction is addressed to
 * him) or the private key (to spend the money).
 */
crypto::key_derivation generate_key_derivation(const public_key& key1, const secret_key& key2);
bool generate_key_derivation(
        const public_key& key1, const secret_key& key2, key_derivation& derivation);
bool derive_public_key(
        const key_derivation& derivation,
        std::size_t output_index,
        const public_key& base,
        public_key& derived_key);
void derivation_to_scalar(const key_derivation& derivation, size_t output_index, ec_scalar& res);
void derive_secret_key(
        const key_derivation& derivation,
        std::size_t output_index,
        const secret_key& base,
        secret_key& derived_key);
bool derive_subaddress_public_key(
        const public_key& out_key,
        const key_derivation& derivation,
        std::size_t output_index,
        public_key& result);

/* Generation and checking of a non-standard Monero curve 25519 signature.  This is a custom
 * scheme that is not Ed25519 because it uses a random "r" (unlike Ed25519's use of a
 * deterministic value), it requires pre-hashing the message (Ed25519 does not), and produces
 * signatures that cannot be verified using Ed25519 verification methods (because the order of
 * hashed values differs).
 *
 * Given M = H(msg)
 * r = random scalar
 * R = rG
 * c = H(M || A || R)
 *
 * and then the signature for this is:
 *
 * s = r - ac
 * Signature is: (c, s)   (but in the struct these are named "c" and "r")
 *
 * Contrast this with standard Ed25519 signature:
 *
 * Given M = msg
 * r = H(seed_hash_2nd_half || M)
 * R = rG
 * c = H(R || A || M)
 * s = r + ac
 * Signature is: (R, s)
 *
 * For verification:
 *
 * Monero: given signature (c, s), message hash M, and pubkey A:
 *
 * R = sG + cA
 * Check: H(M||A||R) == c
 *
 * Ed25519: given signature (R, s), (unhashed) message M, pubkey A:
 * Check: sB == R + H(R||A||M)A
 */
signature generate_signature(const hash& prefix_hash, const public_key& pub, const secret_key& sec);
void generate_signature(
        const hash& prefix_hash, const public_key& pub, const secret_key& sec, signature& sig);
// See above.
bool check_signature(const hash& prefix_hash, const public_key& pub, const signature& sig);

/* Generation and checking of a tx proof; given a tx pubkey R, the recipient's view pubkey A, and
 * the key derivation D, the signature proves the knowledge of the tx secret key r such that R=r*G
 * and D=r*A When the recipient's address is a subaddress, the tx pubkey R is defined as R=r*B where
 * B is the recipient's spend pubkey
 */
void generate_tx_proof(
        const hash& prefix_hash,
        const public_key& R,
        const public_key& A,
        const std::optional<public_key>& B,
        const public_key& D,
        const secret_key& r,
        signature& sig);
bool check_tx_proof(
        const hash& prefix_hash,
        const public_key& R,
        const public_key& A,
        const std::optional<public_key>& B,
        const public_key& D,
        const signature& sig);

/* To send money to a key:
 * * The sender generates an ephemeral key and includes it in transaction output.
 * * To spend the money, the receiver generates a key image from it.
 * * Then he selects a bunch of outputs, including the one he spends, and uses them to generate a
 * ring signature. To check the signature, it is necessary to collect all the keys that were used to
 * generate it. To detect double spends, it is necessary to check that each key image is used at
 * most once.
 */
void generate_key_image(const public_key& pub, const secret_key& sec, key_image& image);
void generate_ring_signature(
        const hash& prefix_hash,
        const key_image& image,
        const std::vector<const public_key*>& pubs,
        const secret_key& sec,
        std::size_t sec_index,
        signature* sig);
bool check_ring_signature(
        const hash& prefix_hash,
        const key_image& image,
        const std::vector<const public_key*>& pubs,
        const signature* sig);

// Signature on a single key image.  The does the same thing as generate_ring_signature with 1
// pubkey (and secret index of 0), but slightly more efficiently, and with hardware device
// implementation.  (This is still used for key image export and for exposing key images in stake
// transactions).
void generate_key_image_signature(
        const key_image& image, const public_key& pub, const secret_key& sec, signature& sig);
bool check_key_image_signature(const key_image& image, const public_key& pub, const signature& sig);

}  // namespace crypto

template <>
struct std::hash<crypto::ec_point> : crypto::raw_hasher<crypto::ec_point> {};
template <>
struct std::hash<crypto::public_key> : crypto::raw_hasher<crypto::public_key> {};
template <>
struct std::hash<crypto::key_image> : crypto::raw_hasher<crypto::key_image> {};
template <>
struct std::hash<crypto::signature> : crypto::raw_hasher<crypto::signature> {};
template <>
struct std::hash<crypto::ed25519_public_key> : crypto::raw_hasher<crypto::ed25519_public_key> {};
template <>
struct std::hash<crypto::x25519_public_key> : crypto::raw_hasher<crypto::x25519_public_key> {};
template <>
struct std::hash<crypto::ed25519_signature> : crypto::raw_hasher<crypto::ed25519_signature> {};
