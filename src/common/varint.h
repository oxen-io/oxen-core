// Copyright (c) 2018-2020, The Loki Project
// Copyright (c) 2014-2019, The Monero Project
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

#pragma once

#include <cassert>
#include <concepts>
#include <iterator>
#include <string>
#include <type_traits>

/*! \file varint.h
 * \brief provides the implementation of varint's
 *
 * Variable length integers ("varints") are serialized in little-endian order using 7 bits per byte
 * where the most significant bit of each byte is a continuation bit (1 = more bytes coming, 0 =
 * varint done) and the lower 7 bits are the next 7 significant bits.  The varint sequence ends when
 * there are no more significant bits to encode.
 *
 * Examples (with bit position drawings):
 *
 *     value       binary [' @ 7-bits]      encoded bytes    encoded binary
 *     =====       ===================      =============    ==============
 *     0x64                  0'1100100      \x64             0110'0100
 *                             └┴┴┼┴┴┘                   done┛└┴┴┬┴┴┴┘
 *                                ╰──────────────────────────────╯
 *
 *     0x80            0000001'0000000      \x80\x01         1000'0000  0000'0001
 *                     └┴┴┼┴┴┘ └┴┴┼┴┴┘               continue┛└┴┴┬┴┴┴┘  ┃└┴┴┬┴┴┴┘
 *                        │       ╰──────────────────────────────╯    done  │
 *                        ╰─────────────────────────────────────────────────╯
 *
 *     0xcc            0000001'1001100      \xcc\x01         1100'1100  0000'0001
 *                     └┴┴┼┴┴┘ └┴┴┼┴┴┘               continue┛└┴┴┬┴┴┴┘  ┃└┴┴┬┴┴┴┘
 *                        │       ╰──────────────────────────────╯    done  │
 *                        ╰─────────────────────────────────────────────────╯
 *
 *     0xbf04  0000010'1111110'0000100      \x84\xfe\x02     1000'0100  1111'1110  0000'0010)
 *             └┴┴┼┴┴┘ └┴┴┼┴┴┘ └┴┴┼┴┴┘               continue┛└┴┴┬┴┴┴┘  ┃└┴┴┬┴┴┴┘  ┃└┴┴┬┴┴┴┘
 *                │       │       ╰──────────────────────────────╯ continue │    done  │
 *                │       ╰─────────────────────────────────────────────────╯          │
 *                ╰────────────────────────────────────────────────────────────────────╯
 */

namespace tools {

/// Returned by read_varint in case of overflow
constexpr int EVARINT_OVERFLOW = -1;
/// Returned by read_varint in case of malformed varint representation
constexpr int EVARINT_REPRESENT = -2;
/// Returns by read_varint if the input range ends before we finish reading a value
constexpr int EVARINT_TRUNCATED = -3;

// Maximum number of bytes of a varint-encoded integer of the given type.
template <typename T>
constexpr size_t VARINT_MAX_LENGTH = (sizeof(T) * 8 + 6) / 7;  // i.e. integer ceil(bits / 7)

/*! \brief writes a varint to an output iterator.  Only supports unsigned integer types.  You
 * could static cast a signed type to an unsigned type, but note that any actual negative values
 * (which have a high bit set) will always end up full size since the high bit is set.
 */
template <std::unsigned_integral T, std::output_iterator<T> OutputIt>
void write_varint(OutputIt& it, T i) {
#ifndef NDEBUG
    size_t count = 0;
#endif
    while (i > 0b0111'1111) {
        // Write the lower 7 bits with the 8th continuation bit set:
        assert(++count < VARINT_MAX_LENGTH<T>);
        *it++ = static_cast<char>((i & 0b0111'1111) | 0b1000'0000);
        i >>= 7;
    }
    // Last byte (7 bits or less, no continuation bit)
    assert(++count <= VARINT_MAX_LENGTH<T>);
    *it++ = static_cast<char>(i);
}

template <std::unsigned_integral T, std::output_iterator<T> OutputIt>
void write_varint(OutputIt&& it, T i) {
    write_varint(it, i);
}

/*! \brief Returns the string that represents the varint
 */
template <typename T>
std::string get_varint_data(const T& v) {
    std::string result;
    write_varint(std::back_insert_iterator{result}, v);
    return result;
}

/*! \brief reads in the varint that is pointed to by InputIt into write.  `it` will modified to
 * the position after the varint bytes that we read.  Returns the number of bytes read on success,
 * or one of the negative EVARIANT_* constants on failure.
 */
template <std::unsigned_integral T, std::input_iterator It, std::sentinel_for<It> EndIt>
int read_varint(It& it, const EndIt& end, T& write) {
    constexpr size_t bits = sizeof(T) * 8;

    bool more = true;
    int read = 0;
    write = 0;
    for (size_t shift = 0; more && it != end; shift += 7) {
        auto byte = static_cast<unsigned char>(*it++);
        ++read;

        // If byte is all 0s and this isn't the first byte then something is wrong: we have a final
        // byte containing nothing significant, but we should never have produced that.
        if (byte == 0 && shift)
            return EVARINT_REPRESENT;

        // If we have <= 7 bits of space remaining then the value must fit and must not have a
        // continuation bit
        if (size_t bits_avail = bits - shift; bits_avail <= 7 && byte >= 1 << bits_avail)
            return EVARINT_OVERFLOW;

        more = byte & 0b1000'0000;  // continuation bit

        write |= static_cast<T>(byte & 0b0111'1111) << shift;  // 7-bit value
    }

    return more ? EVARINT_TRUNCATED : read;
}

template <std::unsigned_integral T, std::input_iterator It, std::sentinel_for<It> EndIt>
int read_varint(It&& it, const EndIt& end, T& write) {
    return read_varint(it, end, write);
}

// Overloads to allow {read,write}_varint to be called with const iterators
template <std::unsigned_integral T, std::output_iterator<T> OutputIt>
auto write_varint(const OutputIt& it_, T i) {
    return write_varint(OutputIt{it_}, i);
}

template <std::unsigned_integral T, std::input_iterator It, std::sentinel_for<It> EndIt>
int read_varint(const It& it, const EndIt& end, T& write) {
    return read_varint(It{it}, end, write);
}

/*! \brief reads the varint from an encoded string into `write`. Returns the number of bytes
 * consumed, or an error value (as above).
 */
template <std::unsigned_integral T>
int read_varint(std::string_view s, T& write) {
    return read_varint(s.begin(), s.end(), write);
}
}  // namespace tools
