// The wallet keys file holds the account keys as a levin_kv message: these check that we read the
// ones epee wrote (recorded before the conversion), and that what we write says the same.

#include <gtest/gtest.h>
#include <oxenc/hex.h>

#include <nlohmann/json.hpp>

#include "common/guts.h"
#include "cryptonote_basic/account.h"
#include "levin_kv_dump.h"
#include "serialization/levin_kv/levin_kv.h"
#include "unit_tests_utils.h"
#include "wallet/wallet2.h"

namespace {

template <typename T>
T filled(uint8_t seed) {
    T x;
    auto bytes = tools::byte_span(x);
    for (size_t i = 0; i < bytes.size(); i++)
        bytes[i] = std::byte(seed + i);
    return x;
}

cryptonote::account_public_address address() {
    return {filled<crypto::public_key>(1), filled<crypto::public_key>(2)};
}

cryptonote::account_keys keys() {
    cryptonote::account_keys k{};
    k.m_account_address = address();
    k.m_spend_secret_key = filled<crypto::secret_key>(3);
    k.m_view_secret_key = filled<crypto::secret_key>(4);
    k.m_multisig_keys = {filled<crypto::secret_key>(5), filled<crypto::secret_key>(6)};
    k.m_encryption_iv = filled<crypto::chacha_iv>(7);
    return k;
}

cryptonote::account_base account() {
    cryptonote::account_base a;
    a.create_from_keys(address(), filled<crypto::secret_key>(3), filled<crypto::secret_key>(4));
    a.set_createtime(1'700'000'000);
    return a;
}

// clang-format off
constexpr auto epee_keys = "01110101010102010114116d5f6163636f756e745f616464726573730c08126d5f7370656e645f7075626c69635f6b65790a800102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20116d5f766965775f7075626c69635f6b65790a8002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210f6d5f656e6372797074696f6e5f69760a200708090a0b0c0d0e0f6d5f6d756c74697369675f6b6579730a010105060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425126d5f7370656e645f7365637265745f6b65790a80030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122116d5f766965775f7365637265745f6b65790a800405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223";
constexpr auto epee_account = "01110101010102010108146d5f6372656174696f6e5f74696d657374616d700500f1536500000000066d5f6b6579730c10116d5f6163636f756e745f616464726573730c08126d5f7370656e645f7075626c69635f6b65790a800102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20116d5f766965775f7075626c69635f6b65790a8002030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20210f6d5f656e6372797074696f6e5f69760a200000000000000000126d5f7370656e645f7365637265745f6b65790a80030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122116d5f766965775f7365637265745f6b65790a800405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223";
// clang-format on

void expect_keys_eq(const cryptonote::account_keys& a, const cryptonote::account_keys& b) {
    EXPECT_EQ(a.m_account_address, b.m_account_address);
    EXPECT_EQ(tools::view_guts(a.m_spend_secret_key), tools::view_guts(b.m_spend_secret_key));
    EXPECT_EQ(tools::view_guts(a.m_view_secret_key), tools::view_guts(b.m_view_secret_key));
    ASSERT_EQ(a.m_multisig_keys.size(), b.m_multisig_keys.size());
    for (size_t i = 0; i < a.m_multisig_keys.size(); i++)
        EXPECT_EQ(tools::view_guts(a.m_multisig_keys[i]), tools::view_guts(b.m_multisig_keys[i]));
    EXPECT_EQ(tools::view_guts(a.m_encryption_iv), tools::view_guts(b.m_encryption_iv));
}

}  // namespace

TEST(account_kv, reads_epees_keys) {
    cryptonote::account_keys k{};
    ASSERT_TRUE(levin_kv::decode(oxenc::from_hex(epee_keys), k));
    expect_keys_eq(k, keys());

    cryptonote::account_base a;
    ASSERT_TRUE(levin_kv::decode(oxenc::from_hex(epee_account), a));
    expect_keys_eq(a.get_keys(), account().get_keys());
    EXPECT_EQ(a.get_createtime(), 1'700'000'000);
}

TEST(account_kv, reads_a_real_keys_file) {
    // A testnet wallet's keys file from 2018, whose decrypted account (when the password's right)
    // must decode to secret keys matching its public keys
    auto keys_file = unit_test::data_dir / "wallet_testnet.keys";
    auto& device = hw::get_device("default");
    EXPECT_TRUE(tools::wallet2::verify_password(keys_file, "test", false, device, 1));
    EXPECT_FALSE(tools::wallet2::verify_password(keys_file, "wrong", false, device, 1));
}

TEST(account_kv, ours_says_what_epees_did) {
    using levin_kv_test::dump;
    EXPECT_EQ(dump(levin_kv::encode(keys())), dump(oxenc::from_hex(epee_keys)));

    // We leave out a null IV, which epee wrote, and read as null when it was missing
    auto expected = dump(oxenc::from_hex(epee_account));
    expected["m_keys"].erase("m_encryption_iv");
    EXPECT_EQ(dump(levin_kv::encode(account())), expected);
}

TEST(account_kv, round_trip) {
    cryptonote::account_keys k{};
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(keys()), k));
    expect_keys_eq(k, keys());

    // A null IV left out is read as null, over whatever was there
    cryptonote::account_base a;
    a.create_from_keys(address(), filled<crypto::secret_key>(9), filled<crypto::secret_key>(9));
    a.encrypt_keys(filled<crypto::chacha_key>(8));
    ASSERT_TRUE(levin_kv::decode(levin_kv::encode(account()), a));
    expect_keys_eq(a.get_keys(), account().get_keys());
}
