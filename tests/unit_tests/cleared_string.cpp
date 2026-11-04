// Copyright (c) 2018, The Monero Project
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

#include <cstring>
#include <optional>
#include "gtest/gtest.h"

#include "crypto/cleared_string.h"

using crypto::cleared_string;

TEST(cleared_string, ctor)
{
  cleared_string s0;
  ASSERT_EQ(s0.size(), 0);

  cleared_string s1(std::string("foo"));
  ASSERT_EQ(s1.size(), 3);
  ASSERT_TRUE(!memcmp(s1.data(), "foo", s1.size()));

  std::string moved = "quux";
  cleared_string s2(std::move(moved));
  ASSERT_EQ(s2.view(), "quux");
}

TEST(cleared_string, shrinking_zeroes)
{
  cleared_string s0(std::string("foo"));
  const char* p = s0.data();
  s0.resize(1);
  ASSERT_EQ(s0.view(), "f");
  // Still in the buffer's capacity, which shrinking doesn't release
  ASSERT_EQ(p, s0.data());
  ASSERT_TRUE(!memcmp(p + 1, "\0\0", 2));
}

TEST(cleared_string, clear)
{
  cleared_string s0(std::string("foo"));
  ASSERT_EQ(s0.size(), 3);
  s0.clear();
  ASSERT_EQ(s0.size(), 0);
}

TEST(cleared_string, push_back)
{
  cleared_string s0(std::string("fo"));
  ASSERT_EQ(s0.size(), 2);
  s0.push_back('o');
  ASSERT_EQ(s0.size(), 3);
  ASSERT_TRUE(!memcmp(s0.data(), "foo", s0.size()));
}

TEST(cleared_string, append_char)
{
  cleared_string s0(std::string("fo"));
  ASSERT_EQ(s0.size(), 2);
  s0 += 'o';
  ASSERT_EQ(s0.size(), 3);
  ASSERT_TRUE(!memcmp(s0.data(), "foo", s0.size()));
}

TEST(cleared_string, append_string)
{
  cleared_string s0(std::string("foo"));
  ASSERT_EQ(s0.size(), 3);
  s0 += "bar";
  ASSERT_EQ(s0.size(), 6);
  ASSERT_TRUE(!memcmp(s0.data(), "foobar", s0.size()));
}

TEST(cleared_string, empty)
{
  cleared_string s0;
  ASSERT_TRUE(s0.empty());
  s0.push_back(' ');
  ASSERT_FALSE(s0.empty());
  ASSERT_EQ(s0.pop_back(), ' ');
  ASSERT_TRUE(s0.empty());
  ASSERT_THROW(s0.pop_back(), std::runtime_error);
}

TEST(cleared_string, pop_back)
{
  cleared_string s = "test";
  ASSERT_EQ(s.size(), 4);
  ASSERT_EQ(s.pop_back(), 't');
  ASSERT_EQ(s.size(), 3);
  ASSERT_TRUE(!memcmp(s.data(), "tes", s.size()));
}

TEST(cleared_string, equal)
{
  cleared_string s0 = "foo";
  cleared_string s1 = "bar";
  cleared_string s0_2 = "foo";
  ASSERT_TRUE(s0 == s0);
  ASSERT_TRUE(s0 == s0_2);
  ASSERT_TRUE(s1 == s1);
  ASSERT_FALSE(s1 == s0);
  ASSERT_FALSE(s1 == s0_2);
  ASSERT_FALSE(s0 != s0_2);
  ASSERT_TRUE(s1 != s0);
}

static cleared_string trimmed(const char *s)
{
  cleared_string str(s);
  str.trim();
  return str;
}

TEST(cleared_string, trim)
{
  ASSERT_TRUE(trimmed("") == "");
  ASSERT_TRUE(trimmed(" ") == "");
  ASSERT_TRUE(trimmed("  ") == "");
  ASSERT_TRUE(trimmed("a") == "a");
  ASSERT_TRUE(trimmed(" a") == "a");
  ASSERT_TRUE(trimmed("  a") == "a");
  ASSERT_TRUE(trimmed("a ") == "a");
  ASSERT_TRUE(trimmed("a  ") == "a");
  ASSERT_TRUE(trimmed(" a  ") == "a");
  ASSERT_TRUE(trimmed("  a  ") == "a");
  ASSERT_TRUE(trimmed("  ab  ") == "ab");
  ASSERT_TRUE(trimmed("  a b  ") == "a b");
  ASSERT_TRUE(trimmed("  a  b  ") == "a  b");
}

static bool check_split(const char *s, const std::vector<cleared_string> &v)
{
  return cleared_string{s}.split() == v;
}

TEST(cleared_string, split)
{
  ASSERT_TRUE(check_split("", {}));
  ASSERT_TRUE(check_split("foo", {"foo"}));
  ASSERT_TRUE(check_split("  foo   ", {"foo"}));
  ASSERT_TRUE(check_split("foo bar", {"foo", "bar"}));
  ASSERT_TRUE(check_split("foo     bar", {"foo", "bar"}));
  ASSERT_TRUE(check_split("foo     bar   baz", {"foo", "bar", "baz"}));
  ASSERT_TRUE(check_split(" foo     bar   baz         ", {"foo", "bar", "baz"}));
  ASSERT_TRUE(check_split("  foo     bar   baz", {"foo", "bar", "baz"}));
  ASSERT_TRUE(check_split("foo     bar   baz ", {"foo", "bar", "baz"}));
  ASSERT_TRUE(check_split("\tfoo\n bar\r\nbaz", {"foo", "bar", "baz"}));
}

TEST(cleared_string, parse_hexstr)
{
  std::optional<cleared_string> s;

  ASSERT_EQ(std::nullopt, cleared_string("x").parse_hexstr());
  ASSERT_EQ(std::nullopt, cleared_string("x0000000000000000").parse_hexstr());
  ASSERT_EQ(std::nullopt, cleared_string("0000000000000000x").parse_hexstr());
  ASSERT_EQ(std::nullopt, cleared_string("0").parse_hexstr());
  ASSERT_EQ(std::nullopt, cleared_string("000").parse_hexstr());

  ASSERT_TRUE((s = cleared_string("").parse_hexstr()) != std::nullopt);
  ASSERT_EQ(*s, "");
  ASSERT_TRUE((s = cleared_string("00").parse_hexstr()) != std::nullopt);
  ASSERT_EQ(*s, cleared_string("", 1));
  ASSERT_TRUE((s = cleared_string("41").parse_hexstr()) != std::nullopt);
  ASSERT_EQ(*s, cleared_string("A"));
  ASSERT_TRUE((s = cleared_string("414243").parse_hexstr()) != std::nullopt);
  ASSERT_EQ(*s, cleared_string("ABC"));
  ASSERT_TRUE((s = cleared_string("4a4B").parse_hexstr()) != std::nullopt);
  ASSERT_EQ(*s, cleared_string("JK"));
}

TEST(cleared_string, hex_to_pod)
{
  uint32_t x = 7;
  ASSERT_FALSE(cleared_string("0102").hex_to_pod(x));
  ASSERT_FALSE(cleared_string("0102030x").hex_to_pod(x));
  ASSERT_EQ(x, 7);
  ASSERT_TRUE(cleared_string("01020304").hex_to_pod(x));
  ASSERT_TRUE(!memcmp(&x, "\x01\x02\x03\x04", 4));
}
