// Copyright (c) 2017-2019, The Monero Project
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

#include "device_default.hpp"

#include <sodium/crypto_generichash.h>

#include "common/exception.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/subaddress_index.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "epee/int-util.h"
#include "ringct/rctOps.h"

namespace hw::core {

static auto logcat = log::Cat("device");

/* ======================================================================= */
/*                              SETUP/TEARDOWN                             */
/* ======================================================================= */
bool device_default::set_name(std::string_view n) {
    name = n;
    return true;
}
std::string device_default::get_name() const {
    return name;
}

bool device_default::init() {
    return true;
}
bool device_default::release() {
    return true;
}

bool device_default::connect() {
    return true;
}
bool device_default::disconnect() {
    return true;
}

/* ======================================================================= */
/*  LOCKER                                                                 */
/* ======================================================================= */

void device_default::lock() {}

bool device_default::try_lock() {
    return true;
}

void device_default::unlock() {}

/* ======================================================================= */
/*                             WALLET & ADDRESS                            */
/* ======================================================================= */

bool device_default::generate_chacha_key(
        const cryptonote::account_keys& keys, crypto::chacha_key& key, uint64_t kdf_rounds) {
    const crypto::secret_key& view_key = keys.m_view_secret_key;
    const crypto::secret_key& spend_key = keys.m_spend_secret_key;
    epee::mlocked<tools::scrubbed_arr<char, sizeof(view_key) + sizeof(spend_key) + 1>> data;
    memcpy(data.data(), &view_key, sizeof(view_key));
    memcpy(data.data() + sizeof(view_key), &spend_key, sizeof(spend_key));
    data[sizeof(data) - 1] = cryptonote::hashkey::WALLET;
    crypto::generate_chacha_key(data.data(), sizeof(data), key, kdf_rounds);
    return true;
}
bool device_default::get_public_address(cryptonote::account_public_address& pubkey) {
    throw oxen::runtime_error{"device function not supported: get_public_address"};
}
bool device_default::get_secret_keys(crypto::secret_key& viewkey, crypto::secret_key& spendkey) {
    throw oxen::runtime_error{"device function not supported: get_secret_keys"};
}
/* ======================================================================= */
/*                               SUB ADDRESS                               */
/* ======================================================================= */

bool device_default::derive_subaddress_public_key(
        const crypto::public_key& out_key,
        const crypto::key_derivation& derivation,
        const std::size_t output_index,
        crypto::public_key& derived_key) {
    return crypto::derive_subaddress_public_key(out_key, derivation, output_index, derived_key);
}

crypto::public_key device_default::get_subaddress_spend_public_key(
        const cryptonote::account_keys& keys, const cryptonote::subaddress_index& index) {
    if (index.is_zero())
        return keys.m_account_address.m_spend_public_key;

    // m = Hs(a || index_major || index_minor)
    crypto::secret_key m = get_subaddress_secret_key(keys.m_view_secret_key, index);

    // M = m*G
    crypto::public_key M;
    crypto::secret_key_to_public_key(m, M);

    // D = B + M
    crypto::public_key D = rct::rct2pk(
            rct::addKeys(rct::pk2rct(keys.m_account_address.m_spend_public_key), rct::pk2rct(M)));
    return D;
}

std::vector<crypto::public_key> device_default::get_subaddress_spend_public_keys(
        const cryptonote::account_keys& keys, uint32_t account, uint32_t begin, uint32_t end) {
    CHECK_AND_ASSERT_THROW_MES(begin <= end, "begin > end");

    std::vector<crypto::public_key> pkeys;
    pkeys.reserve(end - begin);
    cryptonote::subaddress_index index = {account, begin};

    ge_p3 p3;
    ge_cached cached;
    CHECK_AND_ASSERT_THROW_MES(
            ge_frombytes_vartime(&p3, keys.m_account_address.m_spend_public_key.data()) == 0,
            "ge_frombytes_vartime failed to convert spend public key");
    ge_p3_to_cached(&cached, &p3);

    for (uint32_t idx = begin; idx < end; ++idx) {
        index.minor = idx;
        if (index.is_zero()) {
            pkeys.push_back(keys.m_account_address.m_spend_public_key);
            continue;
        }
        crypto::secret_key m = get_subaddress_secret_key(keys.m_view_secret_key, index);

        // M = m*G
        ge_scalarmult_base(&p3, m.data());

        // D = B + M
        crypto::public_key D;
        ge_p1p1 p1p1;
        ge_add(&p1p1, &p3, &cached);
        ge_p1p1_to_p3(&p3, &p1p1);
        ge_p3_tobytes(D.data(), &p3);

        pkeys.push_back(D);
    }
    return pkeys;
}

cryptonote::account_public_address device_default::get_subaddress(
        const cryptonote::account_keys& keys, const cryptonote::subaddress_index& index) {
    if (index.is_zero())
        return keys.m_account_address;

    crypto::public_key D = get_subaddress_spend_public_key(keys, index);

    // C = a*D
    crypto::public_key C =
            rct::rct2pk(rct::scalarmultKey(rct::pk2rct(D), rct::sk2rct(keys.m_view_secret_key)));

    // result: (C, D)
    cryptonote::account_public_address address;
    address.m_view_public_key = C;
    address.m_spend_public_key = D;
    return address;
}

crypto::secret_key device_default::get_subaddress_secret_key(
        const crypto::secret_key& a, const cryptonote::subaddress_index& index) {
    char
            data[cryptonote::hashkey::SUBADDRESS.size() + sizeof(crypto::secret_key) +
                 2 * sizeof(uint32_t)];
    memcpy(data, cryptonote::hashkey::SUBADDRESS.data(), cryptonote::hashkey::SUBADDRESS.size());
    memcpy(data + cryptonote::hashkey::SUBADDRESS.size(), &a, sizeof(crypto::secret_key));
    uint32_t idx = SWAP32LE(index.major);
    memcpy(data + cryptonote::hashkey::SUBADDRESS.size() + sizeof(crypto::secret_key),
           &idx,
           sizeof(uint32_t));
    idx = SWAP32LE(index.minor);
    memcpy(data + cryptonote::hashkey::SUBADDRESS.size() + sizeof(crypto::secret_key) +
                   sizeof(uint32_t),
           &idx,
           sizeof(uint32_t));
    crypto::secret_key m;
    crypto::hash_to_scalar(data, sizeof(data), m);
    return m;
}

/* ======================================================================= */
/*                            DERIVATION & KEY                             */
/* ======================================================================= */

bool device_default::verify_keys(
        const crypto::secret_key& secret_key, const crypto::public_key& public_key) {
    crypto::public_key calculated_pub;
    bool r = crypto::secret_key_to_public_key(secret_key, calculated_pub);
    return r && public_key == calculated_pub;
}

bool device_default::scalarmultKey(rct::key& aP, const rct::key& P, const rct::key& a) {
    rct::scalarmultKey(aP, P, a);
    return true;
}

bool device_default::scalarmultBase(rct::key& aG, const rct::key& a) {
    rct::scalarmultBase(aG, a);
    return true;
}

bool device_default::sc_secret_add(
        crypto::secret_key& r, const crypto::secret_key& a, const crypto::secret_key& b) {
    sc_add(r.data(), a.data(), b.data());
    return true;
}

crypto::secret_key device_default::generate_keys(
        crypto::public_key& pub,
        crypto::secret_key& sec,
        const crypto::secret_key& recovery_key,
        bool recover) {
    return crypto::generate_keys(pub, sec, recovery_key, recover);
}

crypto::key_derivation device_default::generate_key_derivation(
        const crypto::public_key& pub, const crypto::secret_key& sec) {
    return crypto::generate_key_derivation(pub, sec);
}

bool device_default::generate_key_derivation(
        const crypto::public_key& key1,
        const crypto::secret_key& key2,
        crypto::key_derivation& derivation) {
    return crypto::generate_key_derivation(key1, key2, derivation);
}

bool device_default::derivation_to_scalar(
        const crypto::key_derivation& derivation,
        const size_t output_index,
        crypto::ec_scalar& res) {
    crypto::derivation_to_scalar(derivation, output_index, res);
    return true;
}

bool device_default::derive_secret_key(
        const crypto::key_derivation& derivation,
        const std::size_t output_index,
        const crypto::secret_key& base,
        crypto::secret_key& derived_key) {
    crypto::derive_secret_key(derivation, output_index, base, derived_key);
    return true;
}

bool device_default::derive_public_key(
        const crypto::key_derivation& derivation,
        const std::size_t output_index,
        const crypto::public_key& base,
        crypto::public_key& derived_key) {
    return crypto::derive_public_key(derivation, output_index, base, derived_key);
}

bool device_default::secret_key_to_public_key(
        const crypto::secret_key& sec, crypto::public_key& pub) {
    return crypto::secret_key_to_public_key(sec, pub);
}

bool device_default::generate_key_image(
        const crypto::public_key& pub, const crypto::secret_key& sec, crypto::key_image& image) {
    crypto::generate_key_image(pub, sec, image);
    return true;
}

bool device_default::generate_key_image_signature(
        const crypto::key_image& image,
        const crypto::public_key& pub,
        const crypto::secret_key& sec,
        crypto::signature& sig) {
    crypto::generate_key_image_signature(image, pub, sec, sig);
    return true;
}

bool device_default::generate_unlock_signature(
        const crypto::public_key& pub, const crypto::secret_key& sec, crypto::signature& sig) {
    crypto::generate_signature(cryptonote::tx_extra_tx_key_image_unlock::HASH, pub, sec, sig);
    return true;
}

bool device_default::generate_ons_signature(
        std::string_view sig_data,
        const cryptonote::account_keys& keys,
        const cryptonote::subaddress_index& index,
        crypto::signature& sig) {
    crypto::hash hash;
    crypto_generichash(
            hash.data(),
            hash.size(),
            reinterpret_cast<const unsigned char*>(sig_data.data()),
            sig_data.size(),
            nullptr,
            0);

    crypto::secret_key skey = keys.m_spend_secret_key;
    if (!index.is_zero())
        sc_secret_add(skey, skey, get_subaddress_secret_key(keys.m_view_secret_key, index));

    crypto::public_key pkey;
    secret_key_to_public_key(skey, pkey);

    crypto::generate_signature(hash, pkey, skey, sig);
    return true;
}

bool device_default::conceal_derivation(
        crypto::key_derivation& derivation,
        const crypto::public_key& tx_pub_key,
        const std::vector<crypto::public_key>& additional_tx_pub_keys,
        const crypto::key_derivation& main_derivation,
        const std::vector<crypto::key_derivation>& additional_derivations) {
    return true;
}

/* ======================================================================= */
/*                               TRANSACTION                               */
/* ======================================================================= */
void device_default::generate_tx_proof(
        const crypto::hash& prefix_hash,
        const crypto::public_key& R,
        const crypto::public_key& A,
        const std::optional<crypto::public_key>& B,
        const crypto::public_key& D,
        const crypto::secret_key& r,
        crypto::signature& sig) {
    crypto::generate_tx_proof(prefix_hash, R, A, B, D, r, sig);
}

bool device_default::open_tx(
        crypto::secret_key& tx_key,
        cryptonote::txversion /*version*/,
        cryptonote::txtype /*type*/) {
    cryptonote::keypair txkey{*this};
    tx_key = txkey.sec;
    return true;
}

void device_default::get_transaction_prefix_hash(
        const cryptonote::transaction_prefix& tx, crypto::hash& h) {
    cryptonote::get_transaction_prefix_hash(tx, h);
}

bool device_default::generate_output_ephemeral_keys(
        const size_t tx_version,
        bool& found_change,
        const cryptonote::account_keys& sender_account_keys,
        const crypto::public_key& txkey_pub,
        const crypto::secret_key& tx_key,
        const cryptonote::tx_destination_entry& dst_entr,
        const std::optional<cryptonote::tx_destination_entry>& change_addr,
        const size_t output_index,
        const bool need_additional_txkeys,
        const std::vector<crypto::secret_key>& additional_tx_keys,
        std::vector<crypto::public_key>& additional_tx_public_keys,
        std::vector<rct::key>& amount_keys,
        crypto::public_key& out_eph_public_key) {

    // make additional tx pubkey if necessary
    cryptonote::keypair additional_txkey;
    if (need_additional_txkeys) {
        additional_txkey.sec = additional_tx_keys[output_index];
        if (dst_entr.is_subaddress)
            additional_txkey.pub = rct::rct2pk(rct::scalarmultKey(
                    rct::pk2rct(dst_entr.addr.m_spend_public_key),
                    rct::sk2rct(additional_txkey.sec)));
        else
            additional_txkey.pub =
                    rct::rct2pk(rct::scalarmultBase(rct::sk2rct(additional_txkey.sec)));
    }

    bool r;
    crypto::key_derivation derivation;
    if (change_addr && *change_addr == dst_entr && !found_change) {
        found_change = true;
        // sending change to yourself; derivation = a*R
        r = generate_key_derivation(txkey_pub, sender_account_keys.m_view_secret_key, derivation);
        CHECK_AND_ASSERT_MES(
                r,
                false,
                "at creation outs: failed to generate_key_derivation({}, {})",
                txkey_pub,
                tools::hex_guts(sender_account_keys.m_view_secret_key));

    } else {
        // sending to the recipient; derivation = r*A (or s*C in the subaddress scheme)
        r = generate_key_derivation(
                dst_entr.addr.m_view_public_key,
                dst_entr.is_subaddress && need_additional_txkeys ? additional_txkey.sec : tx_key,
                derivation);
        CHECK_AND_ASSERT_MES(
                r,
                false,
                "at creation outs: failed to generate_key_derivation({}, {})",
                dst_entr.addr.m_view_public_key,
                tools::hex_guts(
                        dst_entr.is_subaddress && need_additional_txkeys ? additional_txkey.sec
                                                                         : tx_key));
    }

    if (need_additional_txkeys) {
        additional_tx_public_keys.push_back(additional_txkey.pub);
    }

    if (tx_version > 1) {
        crypto::secret_key scalar1;
        derivation_to_scalar(derivation, output_index, scalar1);
        amount_keys.push_back(rct::sk2rct(scalar1));
    }

    r = derive_public_key(
            derivation, output_index, dst_entr.addr.m_spend_public_key, out_eph_public_key);
    CHECK_AND_ASSERT_MES(
            r,
            false,
            "at creation outs: failed to derive_public_key({}, {}, {})",
            derivation,
            output_index,
            dst_entr.addr.m_spend_public_key);
    return r;
}

bool device_default::encrypt_payment_id(
        crypto::hash8& payment_id,
        const crypto::public_key& public_key,
        const crypto::secret_key& secret_key) {
    crypto::key_derivation derivation;
    crypto::hash hash;
    char data[33]; /* A hash, and an extra byte */

    if (!generate_key_derivation(public_key, secret_key, derivation))
        return false;

    memcpy(data, &derivation, 32);
    data[32] = cryptonote::hashkey::ENCRYPTED_PAYMENT_ID;
    cn_fast_hash(data, 33, hash);

    for (size_t b = 0; b < 8; ++b)
        payment_id[b] ^= hash[b];

    return true;
}

rct::key device_default::genCommitmentMask(const rct::key& amount_key) {
    return rct::genCommitmentMask(amount_key);
}

bool device_default::ecdhEncode(
        rct::ecdhTuple& unmasked, const rct::key& sharedSec, bool short_amount) {
    rct::ecdhEncode(unmasked, sharedSec, short_amount);
    return true;
}

bool device_default::ecdhDecode(
        rct::ecdhTuple& masked, const rct::key& sharedSec, bool short_amount) {
    rct::ecdhDecode(masked, sharedSec, short_amount);
    return true;
}

bool device_default::clsag_prehash(
        const std::string& blob,
        size_t inputs_size,
        size_t outputs_size,
        const rct::keyV& hashes,
        const rct::ctkeyV& outPk,
        rct::key& prehash) {
    prehash = rct::cn_fast_hash(hashes);
    return true;
}

bool device_default::clsag_prepare(
        const rct::key& p,
        const rct::key& z,
        rct::key& I,
        rct::key& D,
        const rct::key& H,
        rct::key& a,
        rct::key& aG,
        rct::key& aH) {
    rct::skpkGen(a, aG);           // aG = a*G
    rct::scalarmultKey(aH, H, a);  // aH = a*H
    rct::scalarmultKey(I, H, p);   // I = p*H
    rct::scalarmultKey(D, H, z);   // D = z*H
    return true;
}

bool device_default::clsag_hash(const rct::keyV& data, rct::key& hash) {
    hash = rct::hash_to_scalar(data);
    return true;
}

bool device_default::clsag_sign(
        const rct::key& c,
        const rct::key& a,
        const rct::key& p,
        const rct::key& z,
        const rct::key& mu_P,
        const rct::key& mu_C,
        rct::key& s) {
    rct::key s0_p_mu_P;
    sc_mul(s0_p_mu_P.bytes, mu_P.bytes, p.bytes);
    rct::key s0_add_z_mu_C;
    sc_muladd(s0_add_z_mu_C.bytes, mu_C.bytes, z.bytes, s0_p_mu_P.bytes);
    sc_mulsub(s.bytes, c.bytes, s0_add_z_mu_C.bytes, a.bytes);

    return true;
}

bool device_default::update_staking_tx_secret_key([[maybe_unused]] crypto::secret_key& key) {
    return true;
}

bool device_default::close_tx() {
    return true;
}

void register_all(std::map<std::string, std::unique_ptr<device>>& registry) {
    auto dev = std::make_unique<device_default>();
    dev->set_name("default_core_device");
    registry.emplace("default", std::move(dev));
}

}  // namespace hw::core
