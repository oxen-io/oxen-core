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

#include <boost/predef/other/endian.h>
#include <gtest/gtest.h>
#include <oxenc/endian.h>

#include <array>
#include <boost/range/algorithm/equal.hpp>
#include <boost/range/algorithm_ext/iota.hpp>
#include <cstdint>
#include <iterator>
#include <sstream>
#include <string>
#include <type_traits>
#include <vector>

#ifndef _WIN32
#include <arpa/inet.h>
#endif

#include "boost/archive/portable_binary_iarchive.hpp"
#include "boost/archive/portable_binary_oarchive.hpp"
#include "crypto/crypto.h"
#include "epee/net/buffer.h"
#include "epee/net/local_ip.h"
#include "epee/net/net_utils_base.h"
#include "epee/shared_sv.h"
#include "epee/span.h"
#include "epee/storages/parserse_base_utils.h"
#include "epee/string_tools.h"
#include "p2p/net_peerlist_boost_serialization.h"

namespace {
template <typename Destination, typename Source>
bool can_construct() {
    const unsigned count = unsigned(std::is_constructible<Destination, Source>()) +
                           unsigned(std::is_constructible<Destination, Source&>()) +
                           unsigned(std::is_convertible<Source, Destination>()) +
                           unsigned(std::is_convertible<Source&, Destination>()) +
                           unsigned(std::is_assignable<Destination, Source>()) +
                           unsigned(std::is_assignable<Destination, Source&>());
    EXPECT_TRUE(count == 6 || count == 0)
            << "Mismatch on construction results - " << count << " were true";
    return count == 6;
}

// This is probably stressing the compiler more than the implementation ...
constexpr const epee::span<const char> test_string("a string");
static_assert(!test_string.empty(), "test failure");
static_assert(test_string.size() == 9, "test failure");
static_assert(test_string.size_bytes() == 9, "test_failure");
static_assert(test_string.begin() == test_string.cbegin(), "test failure");
static_assert(test_string.end() == test_string.cend(), "test failure");
static_assert(test_string.cend() - test_string.cbegin() == 9, "test failure");
static_assert(*test_string.cbegin() == 'a', "test failure");
static_assert(*(test_string.cend() - 2) == 'g', "test failure");
static_assert(
        epee::span<const char>(test_string).cbegin() + 3 == test_string.cbegin() + 3,
        "test failure");

static_assert(epee::span<char>().empty(), "test failure");
static_assert(epee::span<char>(nullptr).empty(), "test failure");
static_assert(epee::span<const char>("foo", 2).size() == 2, "test failure");

#define CHECK_EQUAL(lhs, rhs) \
    EXPECT_TRUE(lhs == rhs);  \
    EXPECT_TRUE(rhs == lhs);  \
    EXPECT_FALSE(lhs != rhs); \
    EXPECT_FALSE(rhs != lhs); \
    EXPECT_FALSE(lhs < rhs);  \
    EXPECT_FALSE(rhs < lhs);  \
    EXPECT_TRUE(lhs <= rhs);  \
    EXPECT_TRUE(rhs <= lhs);  \
    EXPECT_FALSE(lhs > rhs);  \
    EXPECT_FALSE(rhs > lhs);  \
    EXPECT_TRUE(lhs >= rhs);  \
    EXPECT_TRUE(rhs >= lhs)

#define CHECK_LESS(lhs, rhs)  \
    EXPECT_FALSE(lhs == rhs); \
    EXPECT_FALSE(rhs == lhs); \
    EXPECT_TRUE(lhs != rhs);  \
    EXPECT_TRUE(rhs != lhs);  \
    EXPECT_TRUE(lhs < rhs);   \
    EXPECT_FALSE(rhs < lhs);  \
    EXPECT_TRUE(lhs <= rhs);  \
    EXPECT_FALSE(rhs <= lhs); \
    EXPECT_FALSE(lhs > rhs);  \
    EXPECT_TRUE(rhs > lhs);   \
    EXPECT_FALSE(lhs >= rhs); \
    EXPECT_TRUE(rhs >= lhs)

#if BOOST_ENDIAN_LITTLE_BYTE
#define CHECK_LESS_ENDIAN(lhs, rhs) CHECK_LESS(rhs, lhs)
#else
#define CHECK_LESS_ENDIAN(lhs, rhs) CHECK_LESS(lhs, rhs)
#endif
}  // namespace

TEST(Span, Traits) {
    EXPECT_TRUE((std::is_same<std::size_t, typename epee::span<char>::size_type>()));
    EXPECT_TRUE((std::is_same<std::ptrdiff_t, typename epee::span<char>::difference_type>()));
    EXPECT_TRUE((std::is_same<char, typename epee::span<char>::value_type>()));
    EXPECT_TRUE((std::is_same<char*, typename epee::span<char>::pointer>()));
    EXPECT_TRUE((std::is_same<const char*, typename epee::span<char>::const_pointer>()));
    EXPECT_TRUE((std::is_same<char*, typename epee::span<char>::iterator>()));
    EXPECT_TRUE((std::is_same<const char*, typename epee::span<char>::const_iterator>()));
    EXPECT_TRUE((std::is_same<char&, typename epee::span<char>::reference>()));
    EXPECT_TRUE((std::is_same<const char&, typename epee::span<char>::const_reference>()));

    EXPECT_TRUE((std::is_same<std::size_t, typename epee::span<const char>::size_type>()));
    EXPECT_TRUE((std::is_same<std::ptrdiff_t, typename epee::span<const char>::difference_type>()));
    EXPECT_TRUE((std::is_same<const char, typename epee::span<const char>::value_type>()));
    EXPECT_TRUE((std::is_same<const char*, typename epee::span<const char>::pointer>()));
    EXPECT_TRUE((std::is_same<const char*, typename epee::span<const char>::const_pointer>()));
    EXPECT_TRUE((std::is_same<const char*, typename epee::span<const char>::iterator>()));
    EXPECT_TRUE((std::is_same<const char*, typename epee::span<const char>::const_iterator>()));
    EXPECT_TRUE((std::is_same<const char&, typename epee::span<const char>::reference>()));
    EXPECT_TRUE((std::is_same<const char&, typename epee::span<const char>::const_reference>()));
}

TEST(Span, MutableConstruction) {
    struct no_conversion {};
    struct inherited : no_conversion {};

    EXPECT_TRUE(std::is_constructible<epee::span<char>>());
    EXPECT_TRUE((std::is_constructible<epee::span<char>, char*, std::size_t>()));
    EXPECT_FALSE((std::is_constructible<epee::span<char>, const char*, std::size_t>()));
    EXPECT_FALSE((std::is_constructible<epee::span<char>, unsigned char*, std::size_t>()));

    EXPECT_TRUE(std::is_constructible<epee::span<no_conversion>>());
    EXPECT_TRUE((std::is_constructible<epee::span<no_conversion>, no_conversion*, std::size_t>()));
    EXPECT_FALSE((std::is_constructible<epee::span<no_conversion>, inherited*, std::size_t>()));

    EXPECT_TRUE((can_construct<epee::span<char>, std::nullptr_t>()));
    EXPECT_TRUE((can_construct<epee::span<char>, char(&)[1]>()));

    EXPECT_FALSE((can_construct<epee::span<char>, std::vector<char>>()));
    EXPECT_FALSE((can_construct<epee::span<char>, std::array<char, 1>>()));

    EXPECT_FALSE((can_construct<epee::span<char>, std::wstring>()));
    EXPECT_FALSE((can_construct<epee::span<char>, const std::vector<char>>()));
    EXPECT_FALSE((can_construct<epee::span<char>, std::vector<unsigned char>>()));
    EXPECT_FALSE((can_construct<epee::span<char>, const std::array<char, 1>>()));
    EXPECT_FALSE((can_construct<epee::span<char>, std::array<unsigned char, 1>>()));
    EXPECT_FALSE((can_construct<epee::span<char>, const char[1]>()));
    EXPECT_FALSE((can_construct<epee::span<char>, unsigned char[1]>()));
    EXPECT_FALSE((can_construct<epee::span<char>, epee::span<const char>>()));
    EXPECT_FALSE((can_construct<epee::span<char>, epee::span<unsigned char>>()));
    EXPECT_FALSE((can_construct<epee::span<char>, no_conversion>()));
}

TEST(Span, ImmutableConstruction) {
    struct no_conversion {};
    struct inherited : no_conversion {};

    EXPECT_TRUE(std::is_constructible<epee::span<const char>>());
    EXPECT_TRUE((std::is_constructible<epee::span<const char>, char*, std::size_t>()));
    EXPECT_TRUE((std::is_constructible<epee::span<const char>, const char*, std::size_t>()));
    EXPECT_FALSE((std::is_constructible<epee::span<const char>, unsigned char*, std::size_t>()));

    EXPECT_TRUE(std::is_constructible<epee::span<const no_conversion>>());
    EXPECT_TRUE((std::is_constructible<
                 epee::span<const no_conversion>,
                 const no_conversion*,
                 std::size_t>()));
    EXPECT_TRUE((
            std::is_constructible<epee::span<const no_conversion>, no_conversion*, std::size_t>()));
    EXPECT_FALSE((std::is_constructible<
                  epee::span<const no_conversion>,
                  const inherited*,
                  std::size_t>()));
    EXPECT_FALSE(
            (std::is_constructible<epee::span<const no_conversion>, inherited*, std::size_t>()));

    EXPECT_FALSE((can_construct<epee::span<const char>, std::string>()));
    EXPECT_FALSE((can_construct<epee::span<const char>, std::vector<char>>()));
    EXPECT_FALSE((can_construct<epee::span<const char>, const std::vector<char>>()));
    EXPECT_FALSE((can_construct<epee::span<const char>, std::array<char, 1>>()));
    EXPECT_FALSE((can_construct<epee::span<const char>, const std::array<char, 1>>()));

    EXPECT_TRUE((can_construct<epee::span<const char>, std::nullptr_t>()));
    EXPECT_TRUE((can_construct<epee::span<const char>, char[1]>()));
    EXPECT_TRUE((can_construct<epee::span<const char>, const char[1]>()));
    EXPECT_TRUE((can_construct<epee::span<const char>, epee::span<const char>>()));

    EXPECT_FALSE((can_construct<epee::span<const char>, std::wstring>()));
    EXPECT_FALSE((can_construct<epee::span<const char>, std::vector<unsigned char>>()));
    EXPECT_FALSE((can_construct<epee::span<const char>, std::array<unsigned char, 1>>()));
    EXPECT_FALSE((can_construct<epee::span<const char>, unsigned char[1]>()));
    EXPECT_FALSE((can_construct<epee::span<const char>, epee::span<unsigned char>>()));
    EXPECT_FALSE((can_construct<epee::span<const char>, no_conversion>()));
}

TEST(Span, NoExcept) {
    EXPECT_TRUE(std::is_nothrow_default_constructible<epee::span<char>>());
    EXPECT_TRUE(std::is_nothrow_move_constructible<epee::span<char>>());
    EXPECT_TRUE(std::is_nothrow_copy_constructible<epee::span<char>>());
    EXPECT_TRUE(std::is_move_assignable<epee::span<char>>());
    EXPECT_TRUE(std::is_copy_assignable<epee::span<char>>());

    char data[10];
    epee::span<char> lvalue(data);
    const epee::span<char> clvalue(data);
    EXPECT_TRUE(noexcept(epee::span<char>()));
    EXPECT_TRUE(noexcept(epee::span<char>(nullptr)));
    EXPECT_TRUE(noexcept(epee::span<char>(data)));
    EXPECT_TRUE(noexcept(epee::span<char>(lvalue)));
    EXPECT_TRUE(noexcept(epee::span<char>(clvalue)));

    // conversion from mutable to immutable not yet implemented
    // EXPECT_TRUE(noexcept(epee::span<const char>(lvalue)));
    // EXPECT_TRUE(noexcept(epee::span<const char>(clvalue)));

    EXPECT_TRUE(noexcept(epee::span<char>(epee::span<char>(lvalue))));
    EXPECT_TRUE(noexcept(lvalue = lvalue));
    EXPECT_TRUE(noexcept(lvalue = clvalue));
    EXPECT_TRUE(noexcept(lvalue = epee::span<char>(lvalue)));
}

TEST(Span, Nullptr) {
    const auto check_empty = [](epee::span<const char> data) {
        EXPECT_TRUE(data.empty());
        EXPECT_EQ(data.cbegin(), data.begin());
        EXPECT_EQ(data.cend(), data.end());
        EXPECT_EQ(data.cend(), data.cbegin());
        EXPECT_EQ(0, data.size());
        EXPECT_EQ(0, data.size_bytes());
    };
    check_empty({});
    check_empty(nullptr);
}

TEST(Span, Writing) {
    const int expected[] = {-5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
    std::vector<int> source;

    epee::span<int> span;
    EXPECT_TRUE(span.empty());
    EXPECT_EQ(0, span.size());
    EXPECT_EQ(0, span.size_bytes());

    source.resize(15);
    span = {source.data(), source.size()};
    EXPECT_FALSE(span.empty());
    EXPECT_EQ(15, span.size());
    EXPECT_EQ(15 * 4, span.size_bytes());

    boost::range::iota(span, -5);
    EXPECT_EQ(span.begin(), span.cbegin());
    EXPECT_EQ(span.end(), span.cend());
    EXPECT_TRUE(boost::range::equal(expected, source));
    EXPECT_TRUE(boost::range::equal(expected, span));
}

TEST(Span, RemovePrefix) {
    const std::array<unsigned, 4> expected{0, 1, 2, 3};
    auto span = epee::to_span(expected);

    EXPECT_EQ(expected.begin(), span.begin());
    EXPECT_EQ(expected.end(), span.end());

    EXPECT_EQ(2u, span.remove_prefix(2));
    EXPECT_EQ(expected.begin() + 2, span.begin());
    EXPECT_EQ(expected.end(), span.end());

    EXPECT_EQ(2u, span.remove_prefix(3));
    EXPECT_EQ(span.begin(), span.end());
    EXPECT_EQ(expected.end(), span.begin());

    EXPECT_EQ(0u, span.remove_prefix(100));
}

TEST(Span, ToByteSpan) {
    const char expected[] = {56, 44, 11, 5};
    EXPECT_TRUE(boost::range::equal(
            std::array<std::uint8_t, 4>{{56, 44, 11, 5}}, epee::to_byte_span<char>(expected)));
    EXPECT_TRUE(boost::range::equal(
            std::array<char, 4>{{56, 44, 11, 5}},
            epee::to_byte_span(epee::span<const char>{expected})));
}

TEST(Span, AsByteSpan) {
    struct some_pod {
        char value[4];
    };
    const some_pod immutable{{5, 10, 12, 127}};
    EXPECT_TRUE(boost::range::equal(
            std::array<unsigned char, 4>{{5, 10, 12, 127}}, epee::as_byte_span(immutable)));
    EXPECT_TRUE(boost::range::equal(
            std::array<std::uint8_t, 3>{{'a', 'y', 0x00}}, epee::as_byte_span("ay")));
}

TEST(Span, AsMutByteSpan) {
    struct some_pod {
        char value[4];
    };
    some_pod actual{};

    auto span = epee::as_mut_byte_span(actual);
    boost::range::iota(span, 1);
    EXPECT_TRUE(boost::range::equal(std::array<unsigned char, 4>{{1, 2, 3, 4}}, actual.value));
}

TEST(Span, ToMutSpan) {
    std::vector<unsigned> mut;
    mut.resize(4);

    auto span = epee::to_mut_span(mut);
    boost::range::iota(span, 1);
    EXPECT_EQ((std::vector<unsigned>{1, 2, 3, 4}), mut);
}

static_assert(std::is_default_constructible_v<epee::shared_sv>);
static_assert(std::is_move_constructible_v<epee::shared_sv>);
static_assert(std::is_copy_constructible_v<epee::shared_sv>);
static_assert(std::is_move_assignable_v<epee::shared_sv>);
static_assert(std::is_copy_assignable_v<epee::shared_sv>);
static_assert(std::is_nothrow_default_constructible_v<epee::shared_sv>);
static_assert(std::is_nothrow_move_constructible_v<epee::shared_sv>);
static_assert(std::is_nothrow_move_assignable_v<epee::shared_sv>);

TEST(SharedSV, Tests) {
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

TEST(StringTools, GetIpString) {
    EXPECT_EQ(std::string{"0.0.0.0"}, epee::string_tools::get_ip_string_from_int32(0));
    EXPECT_EQ(
            std::string{"255.0.255.0"},
            epee::string_tools::get_ip_string_from_int32(htonl(0xff00ff00)));
    EXPECT_EQ(
            std::string{"255.255.255.255"},
            epee::string_tools::get_ip_string_from_int32(htonl(0xffffffff)));
}

TEST(StringTools, GetIpInt32) {
    std::uint32_t ip = 0;
    EXPECT_FALSE(epee::string_tools::get_ip_int32_from_string(ip, ""));
    EXPECT_FALSE(epee::string_tools::get_ip_int32_from_string(ip, "1."));
    EXPECT_FALSE(epee::string_tools::get_ip_int32_from_string(ip, "1.1."));
    EXPECT_FALSE(epee::string_tools::get_ip_int32_from_string(ip, "1.1.1."));
    EXPECT_FALSE(epee::string_tools::get_ip_int32_from_string(ip, "ff.0.ff.0"));
    EXPECT_FALSE(epee::string_tools::get_ip_int32_from_string(ip, "1.1.1.256"));

    EXPECT_TRUE(epee::string_tools::get_ip_int32_from_string(ip, "1"));
    EXPECT_EQ(htonl(1), ip);

    EXPECT_TRUE(epee::string_tools::get_ip_int32_from_string(ip, "1.1"));
    EXPECT_EQ(htonl(0x1000001), ip);

    EXPECT_TRUE(epee::string_tools::get_ip_int32_from_string(ip, "1.1.1"));
    EXPECT_EQ(htonl(0x1010001), ip);

    EXPECT_TRUE(epee::string_tools::get_ip_int32_from_string(ip, "0.0.0.0"));
    EXPECT_EQ(0, ip);

    EXPECT_TRUE(epee::string_tools::get_ip_int32_from_string(ip, "1.1.1.1"));
    EXPECT_EQ(htonl(0x01010101), ip);

    /*
      The existing epee conversion function does not work with 255.255.255.255, for
      the reasons specified in the inet_addr documentation. Consider fixing in a
      future patch. This address is not likely to be used for purposes within
      monero.
      EXPECT_TRUE(epee::string_tools::get_ip_int32_from_string(ip, "255.255.255.255"));
      EXPECT_EQ(htonl(0xffffffff), ip);
    */

    EXPECT_TRUE(epee::string_tools::get_ip_int32_from_string(ip, "10.0377.0.0377"));
    EXPECT_EQ(htonl(0xaff00ff), ip);

    EXPECT_TRUE(epee::string_tools::get_ip_int32_from_string(ip, "0xff.10.0xff.0"));
    EXPECT_EQ(htonl(0xff0aff00), ip);
}

TEST(NetUtils, IPv4NetworkAddress) {
    static_assert(
            epee::net_utils::ipv4_network_address::get_type_id() ==
                    epee::net_utils::address_type::ipv4,
            "bad ipv4 type id");

    const auto ip1 = oxenc::host_to_big(0x330012FFu);
    const auto ip_loopback = oxenc::host_to_big(0x7F000001u);
    const auto ip_local = oxenc::host_to_big(0x0A000000u);

    epee::net_utils::ipv4_network_address address1{ip1, 65535};
    CHECK_EQUAL(address1, address1);
    EXPECT_STREQ("51.0.18.255:65535", address1.str().c_str());
    EXPECT_STREQ("51.0.18.255", address1.host_str().c_str());
    EXPECT_FALSE(address1.is_loopback());
    EXPECT_FALSE(address1.is_local());
    EXPECT_EQ(epee::net_utils::ipv4_network_address::get_type_id(), address1.get_type_id());
    EXPECT_EQ(ip1, address1.ip());
    EXPECT_EQ(65535, address1.port());
    EXPECT_TRUE(epee::net_utils::ipv4_network_address{std::move(address1)} == address1);
    EXPECT_TRUE(epee::net_utils::ipv4_network_address{address1} == address1);

    const epee::net_utils::ipv4_network_address loopback{ip_loopback, 0};
    CHECK_EQUAL(loopback, loopback);
    CHECK_LESS_ENDIAN(address1, loopback);
    EXPECT_STREQ("127.0.0.1:0", loopback.str().c_str());
    EXPECT_STREQ("127.0.0.1", loopback.host_str().c_str());
    EXPECT_TRUE(loopback.is_loopback());
    EXPECT_FALSE(loopback.is_local());
    EXPECT_EQ(epee::net_utils::ipv4_network_address::get_type_id(), address1.get_type_id());
    EXPECT_EQ(ip_loopback, loopback.ip());
    EXPECT_EQ(0, loopback.port());

    const epee::net_utils::ipv4_network_address local{ip_local, 8080};
    CHECK_EQUAL(local, local);
    CHECK_LESS(local, address1);
    CHECK_LESS(local, loopback);
    EXPECT_FALSE(local.is_loopback());
    EXPECT_TRUE(local.is_local());

    epee::net_utils::ipv4_network_address address2{ip1, 55};
    CHECK_EQUAL(address2, address2);
    CHECK_LESS_ENDIAN(address2, loopback);
    CHECK_LESS(local, address2);
    EXPECT_STREQ("51.0.18.255:55", address2.str().c_str());
    EXPECT_STREQ("51.0.18.255", address2.host_str().c_str());

    address2 = std::move(address1);
    CHECK_EQUAL(address2, address1);

    address2 = local;
    CHECK_EQUAL(address2, local);
    CHECK_LESS(address2, address1);

    {
        std::stringstream stream;
        {
            boost::archive::portable_binary_oarchive ostream{stream};
            ostream << address1;
        }
        {
            boost::archive::portable_binary_iarchive istream{stream};
            istream >> address2;
        }
    }
    CHECK_EQUAL(address1, address2);
    EXPECT_EQ(ip1, address2.ip());
    EXPECT_EQ(65535, address2.port());
}

TEST(NetUtils, NetworkAddress) {
    const auto ip1 = oxenc::host_to_big(0x330012FFu);
    const auto ip_loopback = oxenc::host_to_big(0x7F000001u);
    const auto ip_local = oxenc::host_to_big(0x0A000000u);

    struct custom_address {
        constexpr static bool equal(const custom_address&) noexcept { return false; }
        constexpr static bool less(const custom_address&) noexcept { return false; }
        constexpr static bool is_same_host(const custom_address&) noexcept { return false; }
        constexpr static bool is_loopback() noexcept { return false; }
        constexpr static bool is_local() noexcept { return false; }
        constexpr uint16_t port() const noexcept { return 0; };
        static std::string str() { return {}; }
        static std::string host_str() { return {}; }
        constexpr static epee::net_utils::address_type get_type_id() noexcept {
            return epee::net_utils::address_type(-1);
        }
        constexpr static epee::net_utils::zone get_zone() noexcept {
            return epee::net_utils::zone::invalid;
        }
        constexpr static bool is_blockable() noexcept { return false; }
    };

    const epee::net_utils::network_address empty;
    CHECK_EQUAL(empty, empty);
    EXPECT_TRUE(empty.is_same_host(empty));
    EXPECT_STREQ("<none>", empty.str().c_str());
    EXPECT_STREQ("<none>", empty.host_str().c_str());
    EXPECT_FALSE(empty.is_loopback());
    EXPECT_FALSE(empty.is_local());
    EXPECT_EQ(epee::net_utils::address_type::invalid, empty.get_type_id());
    EXPECT_EQ(epee::net_utils::zone::invalid, empty.get_zone());
    EXPECT_FALSE(empty.is_blockable());
    EXPECT_THROW(empty.as<custom_address>(), std::bad_cast);

    epee::net_utils::network_address address1{epee::net_utils::ipv4_network_address{ip1, 65535}};
    CHECK_EQUAL(address1, address1);
    CHECK_EQUAL(epee::net_utils::network_address{address1}, address1);
    CHECK_LESS(empty, address1);
    EXPECT_TRUE(address1.is_same_host(address1));
    EXPECT_FALSE(empty.is_same_host(address1));
    EXPECT_FALSE(address1.is_same_host(empty));
    EXPECT_STREQ("51.0.18.255:65535", address1.str().c_str());
    EXPECT_STREQ("51.0.18.255", address1.host_str().c_str());
    EXPECT_FALSE(address1.is_loopback());
    EXPECT_FALSE(address1.is_local());
    EXPECT_EQ(epee::net_utils::ipv4_network_address::get_type_id(), address1.get_type_id());
    EXPECT_EQ(epee::net_utils::zone::public_, address1.get_zone());
    EXPECT_TRUE(address1.is_blockable());
    EXPECT_NO_THROW(address1.as<epee::net_utils::ipv4_network_address>());
    EXPECT_THROW(address1.as<custom_address>(), std::bad_cast);

    const epee::net_utils::network_address loopback{
            epee::net_utils::ipv4_network_address{ip_loopback, 0}};
    CHECK_EQUAL(loopback, loopback);
    CHECK_LESS(empty, loopback);
    CHECK_LESS_ENDIAN(address1, loopback);
    EXPECT_TRUE(loopback.is_same_host(loopback));
    EXPECT_FALSE(loopback.is_same_host(address1));
    EXPECT_FALSE(address1.is_same_host(loopback));
    EXPECT_STREQ("127.0.0.1:0", loopback.str().c_str());
    EXPECT_STREQ("127.0.0.1", loopback.host_str().c_str());
    EXPECT_TRUE(loopback.is_loopback());
    EXPECT_FALSE(loopback.is_local());
    EXPECT_EQ(epee::net_utils::ipv4_network_address::get_type_id(), address1.get_type_id());
    EXPECT_EQ(epee::net_utils::zone::public_, address1.get_zone());
    EXPECT_EQ(epee::net_utils::ipv4_network_address::get_type_id(), address1.get_type_id());

    const epee::net_utils::network_address local{
            epee::net_utils::ipv4_network_address{ip_local, 8080}};
    CHECK_EQUAL(local, local);
    CHECK_LESS(local, loopback);
    CHECK_LESS(local, address1);
    EXPECT_FALSE(local.is_loopback());
    EXPECT_TRUE(local.is_local());

    epee::net_utils::network_address address2{epee::net_utils::ipv4_network_address{ip1, 55}};
    CHECK_EQUAL(address2, address2);
    CHECK_LESS(address2, address1);
    CHECK_LESS(local, address2);
    CHECK_LESS_ENDIAN(address2, loopback);
    EXPECT_TRUE(address1.is_same_host(address2));
    EXPECT_TRUE(address2.is_same_host(address1));
    EXPECT_STREQ("51.0.18.255:55", address2.str().c_str());
    EXPECT_STREQ("51.0.18.255", address2.host_str().c_str());

    address2 = std::move(address1);
    CHECK_EQUAL(address1, address1);
    CHECK_EQUAL(empty, address1);
    CHECK_LESS(address1, address2);
    EXPECT_FALSE(address1.is_same_host(address2));
    EXPECT_FALSE(address2.is_same_host(address1));
    EXPECT_STREQ("51.0.18.255:65535", address2.str().c_str());
    EXPECT_STREQ("51.0.18.255", address2.host_str().c_str());
    EXPECT_FALSE(address1.is_loopback());
    EXPECT_FALSE(address1.is_local());
    EXPECT_THROW(address1.as<epee::net_utils::ipv4_network_address>(), std::bad_cast);
    EXPECT_NO_THROW(address2.as<epee::net_utils::ipv4_network_address>());

    address2 = local;
    CHECK_EQUAL(address2, local);
    CHECK_LESS(address1, address2);
    EXPECT_TRUE(address2.is_same_host(local));
    EXPECT_TRUE(local.is_same_host(address2));
    EXPECT_FALSE(address2.is_same_host(address1));
    EXPECT_FALSE(address1.is_same_host(address2));

    {
        std::stringstream stream;
        {
            boost::archive::portable_binary_oarchive ostream{stream};
            ostream << address2;
        }
        {
            boost::archive::portable_binary_iarchive istream{stream};
            istream >> address1;
        }
    }
    CHECK_EQUAL(address1, address2);
    EXPECT_TRUE(address1.is_same_host(address2));
    EXPECT_TRUE(address2.is_same_host(address1));
    EXPECT_NO_THROW(address1.as<epee::net_utils::ipv4_network_address>());

    address1 = custom_address{};
    CHECK_EQUAL(address1, address1);
    CHECK_LESS(address2, address1);
    EXPECT_FALSE(address1.is_same_host(loopback));
    EXPECT_FALSE(loopback.is_same_host(address1));
    EXPECT_THROW(address1.as<epee::net_utils::ipv4_network_address>(), std::bad_cast);
    EXPECT_NO_THROW(address1.as<custom_address>());
}

static bool is_local(const char* s) {
    auto& logcat = epee::logcat;
    uint32_t ip;
    CHECK_AND_ASSERT_THROW_MES(
            epee::string_tools::get_ip_int32_from_string(ip, s), "Invalid IP address: {}", s);
    return epee::net_utils::is_ip_local(ip);
}

TEST(NetUtils, PrivateRanges) {
    ASSERT_EQ(is_local("10.0.0.0"), true);
    ASSERT_EQ(is_local("10.255.0.0"), true);
    ASSERT_EQ(is_local("127.0.0.0"), false);  // loopback is not considered local
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
    ASSERT_EQ(is_local("0.0.0.0"), false);
    ASSERT_EQ(is_local("255.255.255.254"), false);
    ASSERT_EQ(is_local("11.255.255.255"), false);
    ASSERT_EQ(is_local("0.0.0.10"), false);
    ASSERT_EQ(is_local("0.0.168.192"), false);
    ASSERT_EQ(is_local("0.0.30.172"), false);
    ASSERT_EQ(is_local("0.0.30.127"), false);
}

TEST(net_buffer, basic) {
    epee::net_utils::buffer buf;

    ASSERT_EQ(buf.size(), 0);
    EXPECT_THROW(buf.span(1), std::runtime_error);
    buf.append("a", 1);
    epee::span<const uint8_t> span = buf.span(1);
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

TEST(net_buffer, existing_capacity) {
    epee::net_utils::buffer buf;

    buf.append("123456789", 9);
    buf.erase(9);
    buf.append("abc", 3);
    buf.append("def", 3);
    ASSERT_EQ(buf.size(), 6);
    epee::span<const uint8_t> span = buf.span(6);
    ASSERT_TRUE(!memcmp(span.data(), "abcdef", 6));
}

TEST(net_buffer, reallocate) {
    epee::net_utils::buffer buf;

    buf.append(std::string(4000, ' ').c_str(), 4000);
    buf.append(std::string(8000, '0').c_str(), 8000);
    ASSERT_EQ(buf.size(), 12000);
    epee::span<const uint8_t> span = buf.span(12000);
    ASSERT_TRUE(!memcmp(span.data(), std::string(4000, ' ').c_str(), 4000));
    ASSERT_TRUE(!memcmp(span.data() + 4000, std::string(8000, '0').c_str(), 8000));
}

TEST(net_buffer, move) {
    epee::net_utils::buffer buf;

    buf.append(std::string(400, ' ').c_str(), 400);
    buf.erase(399);
    buf.append(std::string(4000, '0').c_str(), 4000);
    ASSERT_EQ(buf.size(), 4001);
    epee::span<const uint8_t> span = buf.span(4001);
    ASSERT_TRUE(!memcmp(span.data(), std::string(1, ' ').c_str(), 1));
    ASSERT_TRUE(!memcmp(span.data() + 1, std::string(4000, '0').c_str(), 4000));
}

TEST(parsing, isspace) {
    ASSERT_FALSE(epee::misc_utils::parse::isspace(0));
    for (int c = 1; c < 256; ++c) {
        ASSERT_EQ(epee::misc_utils::parse::isspace(c), strchr("\r\n\t\f\v ", c) != NULL);
    }
}

TEST(parsing, isdigit) {
    ASSERT_FALSE(epee::misc_utils::parse::isdigit(0));
    for (int c = 1; c < 256; ++c) {
        ASSERT_EQ(epee::misc_utils::parse::isdigit(c), strchr("0123456789", c) != NULL);
    }
}

TEST(parsing, number) {
    std::string_view val;
    std::string s;
    bool is_float, is_negative;

    // the parser expects another character to end the number, and accepts things
    // that aren't numbers, as it's meant as a pre-filter for strto* functions,
    // so we just check that numbers get accepted, but don't test non numbers

    s = "0 ";
    const char* i = s.data();
    const char* e = i + s.size();
    epee::misc_utils::parse::match_number2(i, e, val, is_float, is_negative);
    ASSERT_EQ(val, "0");
    ASSERT_FALSE(is_float);
    ASSERT_FALSE(is_negative);

    s = "000 ";
    i = s.data();
    e = i + s.size();
    epee::misc_utils::parse::match_number2(i, e, val, is_float, is_negative);
    ASSERT_EQ(val, "000");
    ASSERT_FALSE(is_float);
    ASSERT_FALSE(is_negative);

    s = "10x";
    i = s.data();
    e = i + s.size();
    epee::misc_utils::parse::match_number2(i, e, val, is_float, is_negative);
    ASSERT_EQ(val, "10");
    ASSERT_FALSE(is_float);
    ASSERT_FALSE(is_negative);

    s = "10.09/";
    i = s.data();
    e = i + s.size();
    epee::misc_utils::parse::match_number2(i, e, val, is_float, is_negative);
    ASSERT_EQ(val, "10.09");
    ASSERT_TRUE(is_float);
    ASSERT_FALSE(is_negative);

    s = "-1.r";
    i = s.data();
    e = i + s.size();
    epee::misc_utils::parse::match_number2(i, e, val, is_float, is_negative);
    ASSERT_EQ(val, "-1.");
    ASSERT_TRUE(is_float);
    ASSERT_TRUE(is_negative);

    s = "-49.;";
    i = s.data();
    e = i + s.size();
    epee::misc_utils::parse::match_number2(i, e, val, is_float, is_negative);
    ASSERT_EQ(val, "-49.");
    ASSERT_TRUE(is_float);
    ASSERT_TRUE(is_negative);

    s = "0.78/";
    i = s.data();
    e = i + s.size();
    epee::misc_utils::parse::match_number2(i, e, val, is_float, is_negative);
    ASSERT_EQ(val, "0.78");
    ASSERT_TRUE(is_float);
    ASSERT_FALSE(is_negative);

    s = "33E9$";
    i = s.data();
    e = i + s.size();
    epee::misc_utils::parse::match_number2(i, e, val, is_float, is_negative);
    ASSERT_EQ(val, "33E9");
    ASSERT_TRUE(is_float);
    ASSERT_FALSE(is_negative);

    s = ".34e2=";
    i = s.data();
    e = i + s.size();
    epee::misc_utils::parse::match_number2(i, e, val, is_float, is_negative);
    ASSERT_EQ(val, ".34e2");
    ASSERT_TRUE(is_float);
    ASSERT_FALSE(is_negative);

    s = "-9.34e-2=";
    i = s.data();
    e = i + s.size();
    epee::misc_utils::parse::match_number2(i, e, val, is_float, is_negative);
    ASSERT_EQ(val, "-9.34e-2");
    ASSERT_TRUE(is_float);
    ASSERT_TRUE(is_negative);

    s = "9.34e-2=";
    i = s.data();
    e = i + s.size();
    epee::misc_utils::parse::match_number2(i, e, val, is_float, is_negative);
    ASSERT_EQ(val, "9.34e-2");
    ASSERT_TRUE(is_float);
    ASSERT_FALSE(is_negative);

    s = "+9.34e+03=";
    i = s.data();
    e = i + s.size();
    epee::misc_utils::parse::match_number2(i, e, val, is_float, is_negative);
    ASSERT_EQ(val, "+9.34e+03");
    ASSERT_TRUE(is_float);
    ASSERT_FALSE(is_negative);
}

TEST(parsing, unicode) {
    std::string bs;
    std::string s;
    const char* si;

    s = "\"\"";
    si = s.data();
    ASSERT_NO_THROW(epee::misc_utils::parse::match_string2(si, s.data() + s.size(), bs));
    ASSERT_EQ(bs, "");
    s = "\"\\u0000\"";
    si = s.data();
    ASSERT_NO_THROW(epee::misc_utils::parse::match_string2(si, s.data() + s.size(), bs));
    ASSERT_EQ(bs, std::string(1, '\0'));
    s = "\"\\u0020\"";
    si = s.data();
    ASSERT_NO_THROW(epee::misc_utils::parse::match_string2(si, s.data() + s.size(), bs));
    ASSERT_EQ(bs, " ");
    s = "\"\\u1\"";
    si = s.data();
    ASSERT_ANY_THROW(epee::misc_utils::parse::match_string2(si, s.data() + s.size(), bs));
    s = "\"\\u12\"";
    si = s.data();
    ASSERT_ANY_THROW(epee::misc_utils::parse::match_string2(si, s.data() + s.size(), bs));
    s = "\"\\u123\"";
    si = s.data();
    ASSERT_ANY_THROW(epee::misc_utils::parse::match_string2(si, s.data() + s.size(), bs));
    s = "\"\\u1234\"";
    si = s.data();
    ASSERT_NO_THROW(epee::misc_utils::parse::match_string2(si, s.data() + s.size(), bs));
    ASSERT_EQ(bs, "ሴ");
    s = "\"foo\\u1234bar\"";
    si = s.data();
    ASSERT_NO_THROW(epee::misc_utils::parse::match_string2(si, s.data() + s.size(), bs));
    ASSERT_EQ(bs, "fooሴbar");
    s = "\"\\u3042\\u307e\\u3084\\u304b\\u3059\"";
    si = s.data();
    ASSERT_NO_THROW(epee::misc_utils::parse::match_string2(si, s.data() + s.size(), bs));
    ASSERT_EQ(bs, "あまやかす");
}
