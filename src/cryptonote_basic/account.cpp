// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2018, The Loki Project
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

#include "account.h"

#include <fstream>

#include "crypto/crypto.h"
#include "epee/warnings.h"
extern "C" {
#include "crypto/keccak.h"
}
#include "common/meta.h"
#include "cryptonote_basic_impl.h"
#include "cryptonote_config.h"
#include "cryptonote_format_utils.h"

DISABLE_VS_WARNINGS(4244 4345)

namespace cryptonote {
static auto logcat = log::Cat("account");

//-----------------------------------------------------------------
hw::device& account_keys::get_device() const {
    return *m_device;
}
//-----------------------------------------------------------------
void account_keys::set_device(hw::device& hwdev) {
    m_device = &hwdev;
    log::debug(
            log::Cat("device"),
            "account_keys::set_device device type: {}",
            tools::type_name(typeid(hwdev)));
}
//-----------------------------------------------------------------
static void derive_key(const crypto::chacha_key& base_key, crypto::chacha_key& key) {
    static_assert(
            sizeof(base_key) == sizeof(crypto::hash),
            "chacha key and hash should be the same size");
    epee::mlocked<tools::scrubbed_arr<char, sizeof(base_key) + 1>> data;
    memcpy(data.data(), &base_key, sizeof(base_key));
    data[sizeof(base_key)] = cryptonote::hashkey::MEMORY;
    crypto::generate_chacha_key(data.data(), sizeof(data), key, 1);
}
//-----------------------------------------------------------------
static epee::wipeable_string get_key_stream(
        const crypto::chacha_key& base_key, const crypto::chacha_iv& iv, size_t bytes) {
    // derive a new key
    crypto::chacha_key key;
    derive_key(base_key, key);

    // chacha
    epee::wipeable_string buffer0(std::string(bytes, '\0'));
    epee::wipeable_string buffer1 = buffer0;
    crypto::chacha20(buffer0.data(), buffer0.size(), key, iv, buffer1.data());
    return buffer1;
}
//-----------------------------------------------------------------
void account_keys::xor_with_key_stream(const crypto::chacha_key& key) {
    // encrypt a large enough byte stream with chacha20
    epee::wipeable_string key_stream = get_key_stream(
            key, m_encryption_iv, sizeof(crypto::secret_key) * (2 + m_multisig_keys.size()));
    const char* ptr = key_stream.data();
    for (size_t i = 0; i < sizeof(crypto::secret_key); ++i)
        m_spend_secret_key[i] ^= *ptr++;
    for (size_t i = 0; i < sizeof(crypto::secret_key); ++i)
        m_view_secret_key[i] ^= *ptr++;
    for (crypto::secret_key& k : m_multisig_keys) {
        for (size_t i = 0; i < sizeof(crypto::secret_key); ++i)
            k[i] ^= *ptr++;
    }
}
//-----------------------------------------------------------------
void account_keys::encrypt(const crypto::chacha_key& key) {
    m_encryption_iv = crypto::rand<crypto::chacha_iv>();
    xor_with_key_stream(key);
}
//-----------------------------------------------------------------
void account_keys::decrypt(const crypto::chacha_key& key) {
    xor_with_key_stream(key);
}
//-----------------------------------------------------------------
void account_keys::encrypt_viewkey(const crypto::chacha_key& key) {
    // encrypt a large enough byte stream with chacha20
    epee::wipeable_string key_stream =
            get_key_stream(key, m_encryption_iv, sizeof(crypto::secret_key) * 2);
    const char* ptr = key_stream.data();
    ptr += sizeof(crypto::secret_key);
    for (size_t i = 0; i < sizeof(crypto::secret_key); ++i)
        m_view_secret_key[i] ^= *ptr++;
}
//-----------------------------------------------------------------
void account_keys::decrypt_viewkey(const crypto::chacha_key& key) {
    encrypt_viewkey(key);
}
//-----------------------------------------------------------------
account_base::account_base() {
    set_null();
}
//-----------------------------------------------------------------
void account_base::set_null() {
    m_keys = account_keys();
    m_creation_timestamp = 0;
}
//-----------------------------------------------------------------
void account_base::deinit() {
    try {
        m_keys.get_device().disconnect();
    } catch (const std::exception& e) {
        log::error(logcat, "Device disconnect exception: {}", e.what());
    }
}
//-----------------------------------------------------------------
void account_base::forget_spend_key() {
    m_keys.m_spend_secret_key = crypto::secret_key();
    m_keys.m_multisig_keys.clear();
}
//-----------------------------------------------------------------
static uint64_t creation_timestamp(bool use_genesis_timestamp) {
    uint64_t result = 0;
    if (use_genesis_timestamp) {
        tm timestamp = {};
        timestamp.tm_year = 2018 - 1900;  // 2018-05-03
        timestamp.tm_mon = 5 - 1;
        timestamp.tm_mday = 1;

        result = mktime(&timestamp);
        if (result == (uint64_t)-1)  // failure
            result = 0;              // lowest value
    } else {
        result = time(NULL);
    }

    return result;
}
//-----------------------------------------------------------------
crypto::secret_key account_base::generate(
        const crypto::secret_key& recovery_key, bool recover, bool two_random) {
    crypto::secret_key first = generate_keys(
            m_keys.m_account_address.m_spend_public_key,
            m_keys.m_spend_secret_key,
            recovery_key,
            recover);

    // rng for generating second set of keys is hash of first rng.  means only one set of
    // electrum-style words needed for recovery
    crypto::secret_key second;
    keccak((uint8_t*)&m_keys.m_spend_secret_key,
           sizeof(crypto::secret_key),
           (uint8_t*)&second,
           sizeof(crypto::secret_key));

    generate_keys(
            m_keys.m_account_address.m_view_public_key,
            m_keys.m_view_secret_key,
            second,
            two_random ? false : true);
    m_creation_timestamp = creation_timestamp(recover /*use_genesis_timestamp*/);
    return first;
}
//-----------------------------------------------------------------
void account_base::create_from_keys(
        const cryptonote::account_public_address& address,
        const crypto::secret_key& spendkey,
        const crypto::secret_key& viewkey) {
    m_keys.m_account_address = address;
    m_keys.m_spend_secret_key = spendkey;
    m_keys.m_view_secret_key = viewkey;
    m_creation_timestamp = creation_timestamp(true /*use_genesis_timestamp*/);
}

//-----------------------------------------------------------------
void account_base::create_from_device(const std::string& device_name) {
    hw::device& hwdev = hw::get_device(device_name);
    hwdev.set_name(device_name);
    create_from_device(hwdev);
}

void account_base::create_from_device(hw::device& hwdev) {
    m_keys.set_device(hwdev);
    log::debug(log::Cat("device"), "device type: {}", tools::type_name(typeid(hwdev)));
    CHECK_AND_ASSERT_THROW_MES(hwdev.init(), "Device init failed");
    CHECK_AND_ASSERT_THROW_MES(hwdev.connect(), "Device connect failed");
    try {
        CHECK_AND_ASSERT_THROW_MES(
                hwdev.get_public_address(m_keys.m_account_address), "Cannot get a device address");
        CHECK_AND_ASSERT_THROW_MES(
                hwdev.get_secret_keys(m_keys.m_view_secret_key, m_keys.m_spend_secret_key),
                "Cannot get device secret");
    } catch (const std::exception& e) {
        hwdev.disconnect();
        throw;
    }
    m_creation_timestamp = creation_timestamp(true /*use_genesis_timestamp*/);
}

//-----------------------------------------------------------------
void account_base::create_from_viewkey(
        const cryptonote::account_public_address& address, const crypto::secret_key& viewkey) {
    crypto::secret_key fake;
    memset(&unwrap(unwrap(fake)), 0, sizeof(fake));
    create_from_keys(address, fake, viewkey);
}
//-----------------------------------------------------------------
bool account_base::make_multisig(
        const crypto::secret_key& view_secret_key,
        const crypto::secret_key& spend_secret_key,
        const crypto::public_key& spend_public_key,
        const std::vector<crypto::secret_key>& multisig_keys) {
    m_keys.m_account_address.m_spend_public_key = spend_public_key;
    m_keys.m_view_secret_key = view_secret_key;
    m_keys.m_spend_secret_key = spend_secret_key;
    m_keys.m_multisig_keys = multisig_keys;
    return crypto::secret_key_to_public_key(
            view_secret_key, m_keys.m_account_address.m_view_public_key);
}
//-----------------------------------------------------------------
void account_base::finalize_multisig(const crypto::public_key& spend_public_key) {
    m_keys.m_account_address.m_spend_public_key = spend_public_key;
}
//-----------------------------------------------------------------
const account_keys& account_base::get_keys() const {
    return m_keys;
}
//-----------------------------------------------------------------
std::string account_base::get_public_address_str(network_type nettype) const {
    // TODO: change this code into base 58
    return get_account_address_as_str(nettype, false, m_keys.m_account_address);
}
//-----------------------------------------------------------------
std::string account_base::get_public_integrated_address_str(
        const crypto::hash8& payment_id, network_type nettype) const {
    // TODO: change this code into base 58
    return get_account_integrated_address_as_str(nettype, m_keys.m_account_address, payment_id);
}
//-----------------------------------------------------------------
}  // namespace cryptonote
