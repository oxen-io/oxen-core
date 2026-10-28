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

#include "crypto/crypto.h"
#include "epee/net/net_utils_base.h"
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
