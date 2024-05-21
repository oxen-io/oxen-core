// Copyright (c) 2017-2018, The Monero Project
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

#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <string>

#include "common/guts.h"
#include "common/string_util.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"

namespace
{
  constexpr const std::array<uint8_t, 64> source = {
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
    0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea
  };

  constexpr std::string_view hex_full =
    "8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"
    "6c7251d54154cfa92c173a0dd39c1f948b655970153799af2aeadc9ff1add0ea"sv;

  template <size_t Size, std::enable_if_t<(2*Size <= hex_full.size()), int> = 0>
  constexpr std::string_view hex_data = hex_full.substr(0, 2*Size);


  template <typename T>
  T shove_into() {
    T val;
    static_assert(alignof(T) <= alignof(size_t), "T must have size_t (or smaller) alignment");
    static_assert(sizeof(T) <= source.size(), "T is too large for this test");

    std::memcpy(&val, source.data(), sizeof(T));
    return val;
  }
}

TEST(Crypto, Format)
{
  EXPECT_EQ("{}"_format(shove_into<crypto::hash8>()), "<{}>"_format(hex_data<8>));
  EXPECT_EQ("{}"_format(shove_into<crypto::hash>()), "<{}>"_format(hex_data<32>));
  EXPECT_EQ("{}"_format(shove_into<crypto::public_key>()), "<{}>"_format(hex_data<32>));
  EXPECT_EQ("{}"_format(shove_into<crypto::signature>()), "<{}>"_format(hex_data<64>));
  EXPECT_EQ("{}"_format(shove_into<crypto::key_derivation>()), "<{}>"_format(hex_data<32>));
  EXPECT_EQ("{}"_format(shove_into<crypto::key_image>()), "<{}>"_format(hex_data<32>));
}

TEST(Crypto, null_keys)
{
  char zero[32];
  memset(zero, 0, 32);
  ASSERT_EQ(memcmp(crypto::null<crypto::secret_key>.data(), zero, 32), 0);
  ASSERT_EQ(memcmp(crypto::null<crypto::public_key>.data(), zero, 32), 0);
  ASSERT_EQ(memcmp(crypto::public_key{}.data(), zero, 32), 0);
  ASSERT_EQ(memcmp(crypto::secret_key{}.data(), zero, 32), 0);
}

TEST(Crypto, equality)
{
  crypto::public_key pk1{};
  std::copy(source.data(), source.data() + 32, pk1.begin());
  ASSERT_EQ("{}"_format(pk1), "<{}>"_format(hex_full.substr(0, 64)));
  crypto::public_key pk2 = pk1;
  ASSERT_EQ(tools::view_guts(pk1), tools::view_guts(pk2));
  EXPECT_EQ(pk1, pk2);
  crypto::public_key pk3;
  std::copy(source.data(), source.data() + 32, pk3.begin());
  ASSERT_EQ(tools::view_guts(pk1), tools::view_guts(pk3));
  EXPECT_EQ(pk1, pk3);
  pk3.zero();
  ASSERT_EQ("{}"_format(pk3), "<{:064x}>"_format(0));
  ASSERT_NE(tools::view_guts(pk1), tools::view_guts(pk3));
  EXPECT_NE(pk1, pk3);
  EXPECT_LT(pk3, pk1);

  std::copy(source.data() + 32, source.data() + 64, pk2.begin());
  ASSERT_EQ("{}"_format(pk2), "<{}>"_format(hex_full.substr(64)));
  EXPECT_NE(pk1, pk2);
  EXPECT_LT(pk2, pk1);
  EXPECT_FALSE(pk1 == pk2);
  EXPECT_FALSE(pk1 < pk2);
}

TEST(Crypto, verify_32)
{
  // all bytes are treated the same, so we can brute force just one byte
  unsigned char k0[32] = {0}, k1[32] = {0};
  for (unsigned int i0 = 0; i0 < 256; ++i0)
  {
    k0[0] = i0;
    for (unsigned int i1 = 0; i1 < 256; ++i1)
    {
      k1[0] = i1;
      ASSERT_EQ(!crypto_verify_32(k0, k1), i0 == i1);
    }
  }
}
