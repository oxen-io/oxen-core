// Copyright (c) 2020, The Loki Project
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

#include "gtest/gtest.h"

#include "common/guts.h"
#include "common/string_util.h"
#include "common/hex.h"

using namespace std::literals;

TEST(common_string_util, parse_int)
{
  uint8_t u8;
  uint16_t u16;
  uint32_t u32;
  uint64_t u64;
  int8_t i8;
  int16_t i16;
  int32_t i32;
  int64_t i64;

  ASSERT_TRUE(tools::parse_int("123", u8)); ASSERT_EQ(u8, 123);
  ASSERT_TRUE(tools::parse_int("123", u16)); ASSERT_EQ(u16, 123);
  ASSERT_TRUE(tools::parse_int("123", u32)); ASSERT_EQ(u32, 123);
  ASSERT_TRUE(tools::parse_int("123", u64)); ASSERT_EQ(u64, 123);
  ASSERT_TRUE(tools::parse_int("123", i8)); ASSERT_EQ(i8, 123);
  ASSERT_TRUE(tools::parse_int("123", i16)); ASSERT_EQ(i16, 123);
  ASSERT_TRUE(tools::parse_int("123", i32)); ASSERT_EQ(i32, 123);
  ASSERT_TRUE(tools::parse_int("123", i64)); ASSERT_EQ(i64, 123);
  ASSERT_TRUE(tools::parse_int("-123", i8)); ASSERT_EQ(i8, -123);
  ASSERT_TRUE(tools::parse_int("-123", i16)); ASSERT_EQ(i16, -123);
  ASSERT_TRUE(tools::parse_int("-123", i32)); ASSERT_EQ(i32, -123);
  ASSERT_TRUE(tools::parse_int("-123", i64)); ASSERT_EQ(i64, -123);
  ASSERT_FALSE(tools::parse_int("-123", u8));
  ASSERT_FALSE(tools::parse_int("-123", u16));
  ASSERT_FALSE(tools::parse_int("-123", u32));
  ASSERT_FALSE(tools::parse_int("-123", u64));

  ASSERT_TRUE(tools::parse_int("127", i8)); ASSERT_EQ(i8, 127);
  ASSERT_FALSE(tools::parse_int("128", i8));
  ASSERT_TRUE(tools::parse_int("-128", i8)); ASSERT_EQ(i8, -128);
  ASSERT_FALSE(tools::parse_int("-129", i8));

  ASSERT_TRUE(tools::parse_int("255", u8)); ASSERT_EQ(u8, 255);
  ASSERT_FALSE(tools::parse_int("256", u8));

  ASSERT_TRUE(tools::parse_int("32767", i16)); ASSERT_EQ(i16, 32767);
  ASSERT_FALSE(tools::parse_int("32768", i16));
  ASSERT_TRUE(tools::parse_int("-32768", i16)); ASSERT_EQ(i16, -32768);
  ASSERT_FALSE(tools::parse_int("-32769", i16));

  ASSERT_TRUE(tools::parse_int("65535", u16)); ASSERT_EQ(u16, 65535);
  ASSERT_FALSE(tools::parse_int("65536", u16));

  ASSERT_TRUE(tools::parse_int("2147483647", i32)); ASSERT_EQ(i32, 2147483647);
  ASSERT_FALSE(tools::parse_int("2147483648", i32));
  ASSERT_TRUE(tools::parse_int("-2147483648", i32)); ASSERT_EQ(i32, -2147483648);
  ASSERT_FALSE(tools::parse_int("-2147483649", i32));

  ASSERT_TRUE(tools::parse_int("4294967295", u32)); ASSERT_EQ(u32, 4294967295);
  ASSERT_FALSE(tools::parse_int("4294967296", u32));

  ASSERT_TRUE(tools::parse_int("9223372036854775807", i64)); ASSERT_EQ(i64, std::numeric_limits<int64_t>::max());
  ASSERT_FALSE(tools::parse_int("9223372036854775808", i64));
  ASSERT_TRUE(tools::parse_int("-9223372036854775808", i64)); ASSERT_EQ(i64, std::numeric_limits<int64_t>::min());
  ASSERT_FALSE(tools::parse_int("-9223372036854775809", i64));

  ASSERT_TRUE(tools::parse_int("18446744073709551615", u64)); ASSERT_EQ(u64, std::numeric_limits<uint64_t>::max());
  ASSERT_FALSE(tools::parse_int("18446744073709551616", u64));

  ASSERT_TRUE(tools::parse_int("8f717e8ab9c8a61", i64, 16)); ASSERT_EQ(i64, 0x8f717e8ab9c8a61);
  ASSERT_TRUE(tools::parse_int("120120221", i64, 3)); ASSERT_EQ(i64, 11365);
  ASSERT_TRUE( tools::parse_int("11101010110110101011101", i64, 2)); ASSERT_EQ(i64, 0b11101010110110101011101);
  ASSERT_FALSE(tools::parse_int("11101010110110101021101", i64, 2));

  ASSERT_FALSE(tools::parse_int("", i32));
  ASSERT_FALSE(tools::parse_int("+", i32));
  ASSERT_FALSE(tools::parse_int("-", i32));
}

TEST(common_string_util, split)
{
  ASSERT_EQ(tools::split("ab--c----de", "--"), std::vector<std::string_view>({"ab", "c", "", "de"}));
  ASSERT_EQ(tools::split("abc", ""), std::vector<std::string_view>({"a", "b", "c"}));
  ASSERT_EQ(tools::split("abc", "c"), std::vector<std::string_view>({"ab", ""}));
  ASSERT_EQ(tools::split("abc", "c", true), std::vector<std::string_view>({"ab"}));
  ASSERT_EQ(tools::split("-a--b--", "-"), std::vector<std::string_view>({"", "a", "", "b", "", ""}));
  ASSERT_EQ(tools::split("-a--b--", "-", true), std::vector<std::string_view>({"a", "", "b"}));
}

TEST(common_string_util, split_any)
{
  ASSERT_EQ(tools::split_any("ab--c----de", "-"), std::vector<std::string_view>({"ab", "c", "de"}));
  ASSERT_EQ(tools::split_any("abc", ""), std::vector<std::string_view>({"a", "b", "c"}));
  ASSERT_EQ(tools::split_any("abc", "c"), std::vector<std::string_view>({"ab", ""}));
  ASSERT_EQ(tools::split_any("abc", "c", true), std::vector<std::string_view>({"ab"}));
  ASSERT_EQ(tools::split_any("abc", "ca", true), std::vector<std::string_view>({"b"}));
  ASSERT_EQ(tools::split_any("-a--b--", "-b"), std::vector<std::string_view>({"", "a", ""}));
  ASSERT_EQ(tools::split_any("-a--b--", "b-", true), std::vector<std::string_view>({"a"}));
  ASSERT_EQ(tools::split_any("abcdedf", "dcx"), std::vector<std::string_view>({"ab", "e", "f"}));
}

TEST(common_string_util, trim)
{
  std::vector<std::string_view> abc{{
    "abc"sv, "abc "sv, " abc"sv, " abc "sv, "\tabc\n\n\n \t\r\r"sv, "\n\r\t \t \r\nabc"sv
  }};
  for (auto& s : abc) {
    tools::trim(s);
    ASSERT_EQ(s, "abc"sv);
  }
  std::string_view def{" \n\rd e \t\r\nf   \t"};
  tools::trim(def);
  ASSERT_EQ(def, "d e \t\r\nf"sv);
}

TEST(common_string_util, string_iequal)
{
  ASSERT_TRUE(tools::string_iequal("abc", "abc"));
  ASSERT_TRUE(tools::string_iequal("ABC", "abc"));
  ASSERT_TRUE(tools::string_iequal("aBc", "ABc"));
  ASSERT_TRUE(tools::string_iequal("abc", "ABC"));
  ASSERT_TRUE(tools::string_iequal("abC", "ABc"));
  ASSERT_TRUE(tools::string_iequal("ABC", "ABC"));
  ASSERT_FALSE(tools::string_iequal("abc", "abcd"));
  ASSERT_FALSE(tools::string_iequal("abc", "ABCD"));
  ASSERT_FALSE(tools::string_iequal("abcd", "ABC"));
  ASSERT_FALSE(tools::string_iequal("zabc", "ABC"));
}

TEST(common_string_util, string_iequal_any)
{
  ASSERT_TRUE(tools::string_iequal_any("abc", "abc", "def"));
  ASSERT_TRUE(tools::string_iequal_any("ABC", "def", "abc"));
  ASSERT_TRUE(tools::string_iequal_any("aBc", "zzz", "ABc"));
  ASSERT_TRUE(tools::string_iequal_any("abc", "", "ABC"));
  ASSERT_TRUE(tools::string_iequal_any("abC", "x", "y", "z", "o", "m", "g", "ABc"));
  ASSERT_TRUE(tools::string_iequal_any("ABC", "ABC"));
  ASSERT_FALSE(tools::string_iequal_any("abc", "abcd", "xyz", "x"));
  ASSERT_FALSE(tools::string_iequal_any("abc", "ABCD", "ab", "bc", "ac"));
  ASSERT_FALSE(tools::string_iequal_any("abcd"));
}

TEST(common_string_util, view_guts)
{
  struct foo { char x[5]; };
  foo x{"abcd"};
  foo y{{0x31,0x32,0x33,0x34,0x35}};
  ASSERT_EQ(tools::view_guts(x), "abcd\0"sv);
  ASSERT_EQ(tools::view_guts(y), "12345"sv);
  ASSERT_EQ(tools::copy_guts(y), "12345"s);
}

TEST(common_string_util, hex_to_type)
{
  struct Foo { char abcd[4]; };
  Foo f;
  tools::hex_to_type("61626364", f);
  ASSERT_EQ(std::string_view(f.abcd, sizeof(f.abcd)), "abcd"sv);

  ASSERT_FALSE(tools::hex_to_type("616263", f)); // hex too short
  ASSERT_FALSE(tools::hex_to_type("6162636465", f)); // hex too long
  ASSERT_FALSE(tools::hex_to_type("6162636g", f)); // not hex
  ASSERT_FALSE(tools::hex_to_type("012345678", f)); // odd number of hex chars
}
