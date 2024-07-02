
#include <gtest/gtest.h>
#include <oxenc/hex.h>

#include <cstdint>

#include "bls/bls_signer.h"
#include "bls/bls_utils.h"
#include "common/guts.h"
#include "crypto/crypto.h"

using namespace oxenc::literals;

TEST(BLS, Format) {
    auto pk = tools::make_from_guts<crypto::bls_public_key>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex);
    EXPECT_EQ(
            "{}"_format(pk),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    EXPECT_EQ(
            "{:z}"_format(pk),
            "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    auto sig = tools::make_from_guts<crypto::bls_signature>(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"_hex);
    EXPECT_EQ(
            "{}"_format(sig),
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    EXPECT_EQ(
            "{:z}"_format(sig),
            "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
}

TEST(BLS, equality) {
    auto pk1 = tools::make_from_guts<crypto::bls_public_key>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex);
    crypto::bls_public_key pk2{};
    EXPECT_TRUE(pk1);
    EXPECT_FALSE(pk2);
    EXPECT_NE(pk1, crypto::null<crypto::bls_public_key>);
    EXPECT_EQ(pk2, crypto::null<crypto::bls_public_key>);

    crypto::bls_public_key pk3;
    std::copy(pk1.begin(), pk1.end(), pk3.begin());
    EXPECT_EQ("{}"_format(pk1), "{}"_format(pk3));
    pk3 = pk2;
    EXPECT_EQ("{}"_format(pk3), "{}"_format(pk2));

    EXPECT_LT(pk2, pk1);
    EXPECT_GT(pk1, pk2);
}

TEST(BLS, to_from_crypto) {
    auto pk = tools::make_from_guts<crypto::bls_public_key>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex);
    auto pk2 = bls_utils::to_crypto_pubkey(bls_utils::from_crypto_pubkey(pk));
    EXPECT_EQ("{}"_format(pk), "{}"_format(pk2));

    auto sig = tools::make_from_guts<crypto::bls_signature>(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"_hex);

    auto sig2 = bls_utils::to_crypto_signature(bls_utils::from_crypto_signature(sig));
    EXPECT_EQ("{}"_format(sig), "{}"_format(sig2));

    auto sk = tools::make_from_guts<crypto::bls_secret_key>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex);
    BLSSigner signer{cryptonote::network_type::MAINNET, &sk};
    EXPECT_EQ(
            oxenc::to_hex(signer.getPublicKey().getStr(bls_utils::BLS_MODE_BINARY)),
            "2c325c9d9c9593096528b2aa9d0d2cce042915e87a19c2a2a4cfbe4f5c61c694");
    auto pk3 = signer.getCryptoPubkey();
    EXPECT_EQ(
            tools::hex_guts(pk3),
            "14c6615c4fbecfa4a2c2197ae8152904ce2c0d9daab228650993959c9d5c322c"
            "1310113ec96bd4f56c1a3abb96dea45ffb8d785ea7a55faf38e12bfd92ba179b");
    auto pk4 = bls_utils::from_crypto_pubkey(pk3);
    EXPECT_EQ(
            oxenc::to_hex(pk4.getStr(bls_utils::BLS_MODE_BINARY)),
            "2c325c9d9c9593096528b2aa9d0d2cce042915e87a19c2a2a4cfbe4f5c61c694");
}

TEST(BLS, signatures) {
    auto sk = tools::make_from_guts<crypto::bls_secret_key>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex);
    BLSSigner signer{cryptonote::network_type::MAINNET, &sk};

    auto pk = signer.getCryptoPubkey();
    ASSERT_EQ(
            "{}"_format(pk),
            "14c6615c4fbecfa4a2c2197ae8152904ce2c0d9daab228650993959c9d5c322c"
            "1310113ec96bd4f56c1a3abb96dea45ffb8d785ea7a55faf38e12bfd92ba179b");

    auto hash1 = crypto::keccak("hello world!"sv);
    ASSERT_EQ(
            "{}"_format(hash1), "57caa176af1ac0433c5df30e8dabcd2ec1af1e92a26eced5f719b88458777cd6");

    auto hash2 = crypto::keccak("Hello World!\n"sv);
    ASSERT_EQ(
            "{}"_format(hash2), "dc85a6bbfd4658040ef305c9333cf0d5a82ede2854f112549f3925df6b2c0e71");

    auto sig1 = signer.signMsg(hash1);
    auto sig1a = bls_utils::from_crypto_signature(sig1);
    auto sig1b = bls_utils::to_crypto_signature(bls_utils::from_crypto_signature(sig1));
    EXPECT_EQ("{}"_format(sig1), "{}"_format(sig1b));
    EXPECT_EQ(sig1a.getStr(), bls_utils::from_crypto_signature(sig1b).getStr());
    EXPECT_TRUE(sig1a.verifyHash(signer.getPublicKey(), hash1.data(), hash1.size()));
    EXPECT_TRUE(sig1a.verifyHash(bls_utils::from_crypto_pubkey(pk), hash1.data(), hash1.size()));

    EXPECT_TRUE(bls_utils::from_crypto_signature(sig1).verifyHash(
            bls_utils::from_crypto_pubkey(pk), hash1.data(), hash1.size()));

    EXPECT_EQ(
            "{}"_format(sig1),
            "054a64cf51abcccf1e3db61b38bd84556834d652b59758d5860e541653eb2e44"
            "0900de2368d7bdf4a83233d96cb8ab81461ebfe87ea6e73b56864e03e693a2be"
            "29fcf509fa071fa7d8c569a2f8003ffc386ac07ad787815a5f906c4fd2405bef"
            "2a84e7afd7fcb6d3299312906d0f56b3ea80603ee8688f05f68cb03a7c0db4f6");
    EXPECT_TRUE(signer.verifyMsg(sig1, pk, hash1));

    auto sig2 = signer.signMsg(hash2);
    EXPECT_EQ(
            "{}"_format(sig2),
            "3025a58f31717081510467944556989cfb0676e0f135f2cd7151442dd404385e"
            "2671e7a21c2bee7840c54b839718dd2c665cc0376c6d78cd6d5ab62f3036ea14"
            "1d86c93f8884a2ca97b893fbea2d1629c237231668fd86ce43b00abf6d8d68fa"
            "2bc306182916f2d1633c82cd2b78794a049554da9ff68e72fefeb9680590e9fb");
    EXPECT_TRUE(signer.verifyMsg(sig2, pk, hash2));
}
