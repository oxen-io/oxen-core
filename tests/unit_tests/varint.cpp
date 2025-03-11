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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "common/varint.h"

#include <limits>

#include "gtest/gtest.h"

using namespace std::literals;

TEST(varint, equal) {
    ASSERT_EQ(tools::get_varint_data(0U), "\x00"s);
    ASSERT_EQ(tools::get_varint_data(1U), "\x01"s);
    ASSERT_EQ(tools::get_varint_data(0x64U), "\x64"s);
    ASSERT_EQ(tools::get_varint_data(0x7fU), "\x7f"s);
    ASSERT_EQ(tools::get_varint_data(0x80U), "\x80\x01"s);
    ASSERT_EQ(tools::get_varint_data(0xccU), "\xcc\x01"s);
    ASSERT_EQ(tools::get_varint_data(0xffU), "\xff\x01"s);
    ASSERT_EQ(tools::get_varint_data(0x100U), "\x80\x02"s);
    ASSERT_EQ(tools::get_varint_data(0xbf04U), "\x84\xfe\x02"s);
    ASSERT_EQ(tools::get_varint_data(uint32_t{0xffff'ffff}), "\xff\xff\xff\xff\x0f"s);
    ASSERT_EQ(tools::get_varint_data(uint32_t{0x1fff'ffff}), "\xff\xff\xff\xff\x01"s);
    ASSERT_EQ(tools::get_varint_data(uint32_t{0x0fff'ffff}), "\xff\xff\xff\x7f"s);
    ASSERT_EQ(
            tools::get_varint_data(uint64_t{0xffff'ffff'ffff'ffff}),
            "\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01"s);
    ASSERT_EQ(
            tools::get_varint_data(uint64_t{0x7fff'ffff'ffff'ffff}),
            "\xff\xff\xff\xff\xff\xff\xff\xff\x7f"s);
    ASSERT_EQ(
            tools::get_varint_data(uint64_t{0xefff'ffff'ffff'ffff}),
            "\xff\xff\xff\xff\xff\xff\xff\xff\xef\x01"s);

    uint32_t v32;
    ASSERT_EQ(tools::read_varint("\x00\x00"s, v32), 1);
    ASSERT_EQ(v32, 0);
    ASSERT_EQ(tools::read_varint("\x64\x00"s, v32), 1);
    ASSERT_EQ(v32, 0x64);
    ASSERT_EQ(tools::read_varint("\x7f\x00"s, v32), 1);
    ASSERT_EQ(v32, 0x7f);
    ASSERT_EQ(tools::read_varint("\x80\x01\x00"s, v32), 2);
    ASSERT_EQ(v32, 0x80);
    ASSERT_EQ(tools::read_varint("\xcc\x01\x00"s, v32), 2);
    ASSERT_EQ(v32, 0xcc);
    ASSERT_EQ(tools::read_varint("\xff\x01\x00"s, v32), 2);
    ASSERT_EQ(v32, 0xff);
    ASSERT_EQ(tools::read_varint("\x80\x02\x00"s, v32), 2);
    ASSERT_EQ(v32, 0x100);
    ASSERT_EQ(tools::read_varint("\x84\xfe\x02\x00"s, v32), 3);
    ASSERT_EQ(v32, 0xbf04);
    ASSERT_EQ(tools::read_varint("\xff\xff\xff\xff\x0f\x00"s, v32), 5);
    ASSERT_EQ(v32, 0xffff'ffff);
    ASSERT_EQ(tools::read_varint("\xff\xff\xff\xff\x01\x00"s, v32), 5);
    ASSERT_EQ(v32, 0x1fff'ffff);
    ASSERT_EQ(tools::read_varint("\xff\xff\xff\x7f\x00"s, v32), 4);
    ASSERT_EQ(v32, 0x0fff'ffff);

    uint64_t v64;
    ASSERT_EQ(tools::read_varint("\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01\x00"s, v64), 10);
    ASSERT_EQ(v64, 0xffff'ffff'ffff'ffff);
    ASSERT_EQ(tools::read_varint("\xff\xff\xff\xff\xff\xff\xff\xff\x7f\x00"s, v64), 9);
    ASSERT_EQ(v64, 0x7fff'ffff'ffff'ffff);
    ASSERT_EQ(tools::read_varint("\xff\xff\xff\xff\xff\xff\xff\xff\xef\x01\x00"s, v64), 10);
    ASSERT_EQ(v64, 0xefff'ffff'ffff'ffff);

    uint16_t v16;
    ASSERT_EQ(tools::read_varint("\x00\x00"s, v16), 1);
    ASSERT_EQ(v16, 0);
    ASSERT_EQ(tools::read_varint("\xff\x7f\x00"s, v16), 2);
    ASSERT_EQ(v16, 0x3fff);
    ASSERT_EQ(tools::read_varint("\xff\xff\x01\x00"s, v16), 3);
    ASSERT_EQ(v16, 0x7fff);
    ASSERT_EQ(tools::read_varint("\xff\xff\x02\x00"s, v16), 3);
    ASSERT_EQ(v16, 0xbfff);
    ASSERT_EQ(tools::read_varint("\xff\xff\x03\x00"s, v16), 3);
    ASSERT_EQ(v16, 0xffff);
    ASSERT_EQ(tools::read_varint("\x80\x80\x02\x00"s, v16), 3);
    ASSERT_EQ(v16, 0x8000);

    uint8_t v8;
    ASSERT_EQ(tools::read_varint("\x00\x00"s, v8), 1);
    ASSERT_EQ(v8, 0);
    ASSERT_EQ(tools::read_varint("\xff\x01\x00"s, v8), 2);
    ASSERT_EQ(v8, 0xff);
    ASSERT_EQ(tools::read_varint("\xfe\x01\x00"s, v8), 2);
    ASSERT_EQ(v8, 0xfe);
}

TEST(variant, lvalue_iterator) {
    std::string data = "\xff\xff\x02\x00\x01\x02"s;
    auto it = data.begin();  // we pass an lvalue ref so it should get modified
    uint16_t v16;
    ASSERT_EQ(tools::read_varint(it, data.end(), v16), 3);
    ASSERT_EQ(std::distance(data.begin(), it), 3);
    ASSERT_EQ(std::string(it, data.end()), "\x00\x01\x02"s);

    const auto cit = data.begin();  // This should get copied instead
    ASSERT_EQ(tools::read_varint(cit, data.end(), v16), 3);
    ASSERT_EQ(std::distance(data.begin(), cit), 0);
    ASSERT_EQ(std::string(cit, data.end()), data);
}

TEST(varint, failures) {
    uint64_t v64;
    ASSERT_EQ(
            tools::read_varint("\xff\xff\xff\xff\xff\xff\xff\xff\xff\x02"s, v64),
            tools::EVARINT_OVERFLOW);

    uint16_t v16;
    ASSERT_EQ(tools::read_varint("\xff\xff\x00"s, v16), tools::EVARINT_REPRESENT);
    ASSERT_EQ(tools::read_varint("\x80\x80\x00"s, v16), tools::EVARINT_REPRESENT);
    ASSERT_EQ(tools::read_varint("\xff\xff\x04"s, v16), tools::EVARINT_OVERFLOW);
    ASSERT_EQ(tools::read_varint("\xff\xff\x08"s, v16), tools::EVARINT_OVERFLOW);
    ASSERT_EQ(tools::read_varint("\xff\xff\x80"s, v16), tools::EVARINT_OVERFLOW);
    ASSERT_EQ(tools::read_varint("\x80\x80\x80"s, v16), tools::EVARINT_OVERFLOW);

    uint8_t v8;
    ASSERT_EQ(tools::read_varint("\x80\x00"s, v8), tools::EVARINT_REPRESENT);
    ASSERT_EQ(tools::read_varint("\xff\x02"s, v8), tools::EVARINT_OVERFLOW);
    ASSERT_EQ(tools::read_varint("\x80\x02"s, v8), tools::EVARINT_OVERFLOW);
    ASSERT_EQ(tools::read_varint("\x80\x80"s, v8), tools::EVARINT_OVERFLOW);
}

TEST(varint, round_trip) {
    // Check each value in the range [mid-500, mid+500); most of these values deliberately bracket
    // 2^7n because 7-bit intervals are where the varint encoding adds another byte.
    for (uint64_t mid :
         {500ULL,
          1ULL << 14,
          1ULL << 21,
          1ULL << 28,
          1ULL << 35,
          1ULL << 42,
          1ULL << 49,
          1ULL << 56,
          1ULL << 63,
          0x1234'5678ULL,
          0xabcd'ef01'2345'6789ULL,
          std::numeric_limits<unsigned long long>::max() - 500}) {
        for (uint64_t val = mid - 500, top = mid + 500; val < top; ++val) {
            std::string s;
            tools::write_varint(std::back_inserter(s), val);
            size_t expected_length = 1;
            for (uint64_t x = val; x > 0b1111111; x >>= 7)
                expected_length++;
            ASSERT_EQ(s.size(), expected_length);

            s += '\x00';  // Should stop before reading this extra byte
            uint64_t val_round_trip;
            int read = tools::read_varint(s.begin(), s.end(), val_round_trip);
            ASSERT_EQ(read, expected_length);
            ASSERT_EQ(val, val_round_trip);
        }
    }
}
