
#include <gtest/gtest.h>
#include <oxenc/hex.h>

#include <cstdint>

#include "bls/bls_signer.h"
#include "bls/bls_utils.h"
#include "common/guts.h"
#include "crypto/eth.h"

using namespace oxenc::literals;

TEST(BLS, Format) {
    auto pk = tools::make_from_guts<eth::bls_public_key>(
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

    auto sig = tools::make_from_guts<eth::bls_signature>(
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
    auto pk1 = tools::make_from_guts<eth::bls_public_key>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex);
    eth::bls_public_key pk2{};
    EXPECT_TRUE(pk1);
    EXPECT_FALSE(pk2);
    EXPECT_NE(pk1, crypto::null<eth::bls_public_key>);
    EXPECT_EQ(pk2, crypto::null<eth::bls_public_key>);

    eth::bls_public_key pk3;
    std::copy(pk1.begin(), pk1.end(), pk3.begin());
    EXPECT_EQ("{}"_format(pk1), "{}"_format(pk3));
    pk3 = pk2;
    EXPECT_EQ("{}"_format(pk3), "{}"_format(pk2));

    EXPECT_LT(pk2, pk1);
    EXPECT_GT(pk1, pk2);
}

TEST(BLS, to_from_crypto) {
    auto pk = tools::make_from_guts<eth::bls_public_key>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex);
    auto pk2 = bls_utils::to_crypto_pubkey(bls_utils::from_crypto_pubkey(pk));
    EXPECT_EQ("{}"_format(pk), "{}"_format(pk2));

    auto sig = tools::make_from_guts<eth::bls_signature>(
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"_hex);

    auto sig2 = bls_utils::to_crypto_signature(bls_utils::from_crypto_signature(sig));
    EXPECT_EQ("{}"_format(sig), "{}"_format(sig2));

    auto sk = tools::make_from_guts<eth::bls_secret_key>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex);
    eth::BLSSigner signer{cryptonote::network_type::MAINNET, &sk};
    EXPECT_EQ(
            oxenc::to_hex(signer.getPubkey().getStr(bls_utils::BLS_MODE_BINARY)),
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
    auto sk = tools::make_from_guts<eth::bls_secret_key>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_hex);
    eth::BLSSigner signer{cryptonote::network_type::MAINNET, &sk};

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
    EXPECT_TRUE(signer.verifyMsg(
            bls_utils::to_crypto_signature(sig1a),
            bls_utils::to_crypto_pubkey(signer.getPubkey()),
            hash1));
    EXPECT_TRUE(signer.verifyMsg(sig1b, pk, hash1));

    EXPECT_EQ(
            "{}"_format(sig1),
            "0935f61237111bdf49d7b67232def51e267ff84a9c76503d95aee6ba3a94443c16558636a14f7ab3767cde"
            "88e5b2021157888ca26908d0d052dfd44b3b8b5c6617a1f756b90523ecc8e9d9744b0e1f6a1ca310533227"
            "378fd44012cdf44bbaf826559955b29a5fc7a5af1ff0f0318747ce80101abe9ed97ab256977b7c25a7d6");
    EXPECT_TRUE(signer.verifyMsg(sig1, pk, hash1));

    auto sig2 = signer.signMsg(hash2);
    EXPECT_EQ(
            "{}"_format(sig2),
            "0a6f2c1693aceac3220fb57277d33203022339b21fca05bd2751cfdf50359ad628d633ff8e214bfa1fed23"
            "34fd1d7db512fcd43bba173a84d443fe6d333d64540960da53f247c635af26128574190e91f40d899fefdd"
            "a43b9f2c17fccf97cf062f82c037ba9e20e63e0bc72bc672e35643adad660e4afe60357c26c83bce7a2b");
    EXPECT_TRUE(signer.verifyMsg(sig2, pk, hash2));
}
