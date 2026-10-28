// Copyright (c) 2014-2018, The Monero Project
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

#include <array>
#include <oxenc/endian.h>
#include <cstdint>
#include <gtest/gtest.h>
#include <iterator>
#include <string>
#include <sstream>
#include <type_traits>
#include <vector>

#include "epee/shared_sv.h"
#include "crypto/crypto.h"
#include "epee/net/net_utils_base.h"
#include "epee/net/buffer.h"
#include "net/address.h"

namespace
{
  #define CHECK_EQUAL(lhs, rhs) \
    EXPECT_TRUE( lhs == rhs );  \
    EXPECT_TRUE( rhs == lhs );  \
    EXPECT_FALSE( lhs != rhs ); \
    EXPECT_FALSE( rhs != lhs ); \
    EXPECT_FALSE( lhs < rhs );  \
    EXPECT_FALSE( rhs < lhs );  \
    EXPECT_TRUE( lhs <= rhs );  \
    EXPECT_TRUE( rhs <= lhs );  \
    EXPECT_FALSE( lhs > rhs );  \
    EXPECT_FALSE( rhs > lhs );  \
    EXPECT_TRUE( lhs >= rhs );  \
    EXPECT_TRUE( rhs >= lhs )

  #define CHECK_LESS(lhs, rhs)   \
    EXPECT_FALSE( lhs == rhs );  \
    EXPECT_FALSE( rhs == lhs );  \
    EXPECT_TRUE( lhs != rhs );   \
    EXPECT_TRUE( rhs != lhs );   \
    EXPECT_TRUE( lhs < rhs );    \
    EXPECT_FALSE( rhs < lhs );   \
    EXPECT_TRUE( lhs <= rhs );   \
    EXPECT_FALSE( rhs <= lhs );  \
    EXPECT_FALSE( lhs > rhs );   \
    EXPECT_TRUE( rhs > lhs );    \
    EXPECT_FALSE( lhs >= rhs );  \
    EXPECT_TRUE( rhs >= lhs )
}

using namespace std::literals;

static_assert(std::is_default_constructible_v<epee::shared_sv>);
static_assert(std::is_move_constructible_v<epee::shared_sv>);
static_assert(std::is_copy_constructible_v<epee::shared_sv>);
static_assert(std::is_move_assignable_v<epee::shared_sv>);
static_assert(std::is_copy_assignable_v<epee::shared_sv>);
static_assert(std::is_nothrow_default_constructible_v<epee::shared_sv>);
static_assert(std::is_nothrow_move_constructible_v<epee::shared_sv>);
static_assert(std::is_nothrow_move_assignable_v<epee::shared_sv>);

TEST(SharedSV, Tests)
{
  epee::shared_sv slice{};
  auto& view = slice.view;

  EXPECT_TRUE(view.empty());
  EXPECT_EQ(0u, slice.extract_prefix(0).size());
  EXPECT_EQ(0u, slice.extract_prefix(1).size());

  using namespace std::literals;
  epee::shared_sv from_str{"abcdef"s};
  EXPECT_EQ("abcdef"sv, from_str.view);
  auto sv2 = from_str.extract_prefix(4);
  EXPECT_EQ(4, sv2.size());
  EXPECT_EQ(2, from_str.size());
  auto sv3 = sv2.extract_prefix(1);
  EXPECT_EQ("a"sv, sv3.view);
  EXPECT_EQ("bcd"sv, sv2.view);
  EXPECT_EQ("ef"sv, from_str.view);
  EXPECT_EQ(3, from_str.ptr.use_count());
  sv2 = {};
  EXPECT_EQ(2, from_str.ptr.use_count());
  sv3 = {};
  EXPECT_EQ(1, from_str.ptr.use_count());
  auto ptr = from_str.ptr;
  from_str = {};
  EXPECT_EQ(1, ptr.use_count());
  ptr.reset();
  EXPECT_EQ(0, from_str.size());
  EXPECT_EQ(0, sv2.size());
  EXPECT_EQ(0, sv3.size());
}

TEST(NetUtils, Address)
{
  const oxen::quic::Address address1{oxen::quic::ipv4{51, 0, 18, 255}, 65535};
  const oxen::quic::Address address2{oxen::quic::ipv4{51, 0, 18, 255}, 55};
  const oxen::quic::Address loopback{oxen::quic::ipv4{127, 0, 0, 1}, 0};
  const oxen::quic::Address local{oxen::quic::ipv4{10, 0, 0, 0}, 8080};
  const oxen::quic::Address ipv6{oxen::quic::ipv6{"2001:db8::1"s}, 22022};
  const oxen::quic::Address ipv6_loopback{oxen::quic::ipv6_loopback, 0};

  EXPECT_EQ(address1.to_string(), "51.0.18.255:65535");
  EXPECT_EQ(address1.host(), "51.0.18.255");
  EXPECT_EQ(ipv6.to_string(), "[2001:db8::1]:22022");
  EXPECT_EQ(ipv6.host(), "2001:db8::1");
  EXPECT_EQ(net::type_of(address1), net::address_type::ipv4);
  EXPECT_EQ(net::type_of(ipv6), net::address_type::ipv6);

  // Addresses order as they always have (which sets and maps of peers depend on): IPv4 before
  // IPv6, then by IP, then by port.
  CHECK_EQUAL(address1, oxen::quic::Address{address1});
  CHECK_LESS(local, address2);
  CHECK_LESS(address2, address1);
  CHECK_LESS(address1, loopback);
  CHECK_LESS(loopback, ipv6);

  EXPECT_TRUE(net::same_host(address1, address2));
  EXPECT_FALSE(net::same_host(address1, loopback));
  EXPECT_FALSE(net::same_host(address1, ipv6));

  // A 0 port doesn't stop an address being loopback.
  EXPECT_TRUE(net::is_loopback(loopback));
  EXPECT_TRUE(net::is_loopback(ipv6_loopback));
  EXPECT_FALSE(net::is_local(loopback));
  EXPECT_FALSE(net::is_loopback(address1));
  EXPECT_FALSE(net::is_local(address1));
  EXPECT_FALSE(net::is_loopback(local));
  EXPECT_TRUE(net::is_local(local));
}

static bool is_local(const char *s)
{
  return net::is_local(oxen::quic::Address{oxen::quic::ipv4{std::string{s}}, 0});
}

TEST(NetUtils, PrivateRanges)
{
  ASSERT_EQ(is_local("10.0.0.0"), true);
  ASSERT_EQ(is_local("10.255.0.0"), true);
  ASSERT_EQ(is_local("127.0.0.0"), false); // loopback is not considered local
  ASSERT_EQ(is_local("192.167.255.255"), false);
  ASSERT_EQ(is_local("192.168.0.0"), true);
  ASSERT_EQ(is_local("192.168.255.255"), true);
  ASSERT_EQ(is_local("192.169.0.0"), false);
  ASSERT_EQ(is_local("172.0.0.0"), false);
  ASSERT_EQ(is_local("172.15.255.255"), false);
  ASSERT_EQ(is_local("172.16.0.0"), true);
  ASSERT_EQ(is_local("172.16.255.255"), true);
  ASSERT_EQ(is_local("172.31.255.255"), true);
  ASSERT_EQ(is_local("172.32.0.0"), false);
  ASSERT_EQ(is_local("11.255.255.255"), false);
  // Not publicly routable, so local:
  ASSERT_EQ(is_local("0.0.0.0"), true);
  ASSERT_EQ(is_local("255.255.255.254"), true);
  // Byte-reversed private addresses (which a byte order mixup would confuse) are public:
  ASSERT_EQ(is_local("1.0.0.10"), false);
  ASSERT_EQ(is_local("1.0.168.192"), false);
  ASSERT_EQ(is_local("1.0.16.172"), false);
  ASSERT_EQ(is_local("1.0.0.127"), false);
}

TEST(net_buffer, basic)
{
  epee::net_utils::buffer buf;

  ASSERT_EQ(buf.size(), 0);
  EXPECT_THROW(buf.span(1), std::runtime_error);
  buf.append("a", 1);
  std::span<const uint8_t> span =buf.span(1);
  ASSERT_EQ(span.size(), 1);
  ASSERT_EQ(span.data()[0], 'a');
  EXPECT_THROW(buf.span(2), std::runtime_error);
  buf.append("bc", 2);
  buf.erase(1);
  EXPECT_THROW(buf.span(3), std::runtime_error);
  span = buf.span(2);
  ASSERT_EQ(span.size(), 2);
  ASSERT_EQ(span.data()[0], 'b');
  ASSERT_EQ(span.data()[1], 'c');
  buf.erase(1);
  EXPECT_THROW(buf.span(2), std::runtime_error);
  span = buf.span(1);
  ASSERT_EQ(span.size(), 1);
  ASSERT_EQ(span.data()[0], 'c');
  EXPECT_THROW(buf.erase(2), std::runtime_error);
  buf.erase(1);
  EXPECT_EQ(buf.size(), 0);
  EXPECT_THROW(buf.span(1), std::runtime_error);
}

TEST(net_buffer, existing_capacity)
{
  epee::net_utils::buffer buf;

  buf.append("123456789", 9);
  buf.erase(9);
  buf.append("abc", 3);
  buf.append("def", 3);
  ASSERT_EQ(buf.size(), 6);
  std::span<const uint8_t> span =buf.span(6);
  ASSERT_TRUE(!memcmp(span.data(), "abcdef", 6));
}

TEST(net_buffer, reallocate)
{
  epee::net_utils::buffer buf;

  buf.append(std::string(4000, ' ').c_str(), 4000);
  buf.append(std::string(8000, '0').c_str(), 8000);
  ASSERT_EQ(buf.size(), 12000);
  std::span<const uint8_t> span =buf.span(12000);
  ASSERT_TRUE(!memcmp(span.data(), std::string(4000, ' ').c_str(), 4000));
  ASSERT_TRUE(!memcmp(span.data() + 4000, std::string(8000, '0').c_str(), 8000));
}

TEST(net_buffer, move)
{
  epee::net_utils::buffer buf;

  buf.append(std::string(400, ' ').c_str(), 400);
  buf.erase(399);
  buf.append(std::string(4000, '0').c_str(), 4000);
  ASSERT_EQ(buf.size(), 4001);
  std::span<const uint8_t> span =buf.span(4001);
  ASSERT_TRUE(!memcmp(span.data(), std::string(1, ' ').c_str(), 1));
  ASSERT_TRUE(!memcmp(span.data() + 1, std::string(4000, '0').c_str(), 4000));
}
