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

#pragma once

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifndef _MSC_VER
#include <sys/param.h>
#endif

#if defined(__clang__) || defined(__GNUC__)
#define epee_int_utils_bswap_64(x) __builtin_bswap64(x)
#define epee_int_utils_bswap_32(x) __builtin_bswap32(x)
#else
#if defined(__linux__) || defined(__ANDROID__)
#include <byteswap.h>
#endif
#define epee_int_utils_bswap_64(x) bswap_64(x)
#define epee_int_utils_bswap_32(x) bswap_32(x)
#endif

#if defined(__sun) && defined(__SVR4)
#include <endian.h>
#endif

#if defined(_MSC_VER)
#include <stdlib.h>

static inline uint32_t rol32(uint32_t x, int r) {
    static_assert(sizeof(uint32_t) == sizeof(unsigned int), "this code assumes 32-bit integers");
    return _rotl(x, r);
}

static inline uint64_t rol64(uint64_t x, int r) {
    return _rotl64(x, r);
}

#else

static inline uint32_t rol32(uint32_t x, int r) {
    return (x << (r & 31)) | (x >> (-r & 31));
}

static inline uint64_t rol64(uint64_t x, int r) {
    return (x << (r & 63)) | (x >> (-r & 63));
}

#endif

#ifndef __SIZEOF_INT128__
static inline uint64_t hi_dword(uint64_t val) {
    return val >> 32;
}

static inline uint64_t lo_dword(uint64_t val) {
    return val & 0xFFFFFFFF;
}

static inline uint64_t div_with_remainder(
        uint64_t dividend, uint32_t divisor, uint32_t* remainder) {
    dividend |= ((uint64_t)*remainder) << 32;
    *remainder = dividend % divisor;
    return dividend / divisor;
}

static inline bool shl128(uint64_t* hi, uint64_t* lo) {
    bool carry = ((*hi) >> 63);
    *hi <<= 1;
    *hi += ((*lo) >> 63);
    *lo <<= 1;
    return carry;
}
#endif

static inline uint64_t mul128(uint64_t multiplier, uint64_t multiplicand, uint64_t* product_hi) {
#ifdef __SIZEOF_INT128__
    unsigned __int128 result = (unsigned __int128)multiplier * (unsigned __int128)multiplicand;
    *product_hi = result >> 64;
    return (uint64_t)result;
#else
    // multiplier   = ab = a * 2^32 + b
    // multiplicand = cd = c * 2^32 + d
    // ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d
    uint64_t a = hi_dword(multiplier);
    uint64_t b = lo_dword(multiplier);
    uint64_t c = hi_dword(multiplicand);
    uint64_t d = lo_dword(multiplicand);

    uint64_t ac = a * c;
    uint64_t ad = a * d;
    uint64_t bc = b * c;
    uint64_t bd = b * d;

    uint64_t adbc = ad + bc;
    uint64_t adbc_carry = adbc < ad ? 1 : 0;

    // multiplier * multiplicand = product_hi * 2^64 + product_lo
    uint64_t product_lo = bd + (adbc << 32);
    uint64_t product_lo_carry = product_lo < bd ? 1 : 0;
    *product_hi = ac + (adbc >> 32) + (adbc_carry << 32) + product_lo_carry;
    assert(ac <= *product_hi);

    return product_lo;
#endif
}

// Long division with 2^32 base
static inline void div128_32(
        uint64_t dividend_hi,
        uint64_t dividend_lo,
        uint32_t divisor,
        uint64_t* quotient_hi,
        uint64_t* quotient_lo) {
#ifdef __SIZEOF_INT128__
    unsigned __int128 result =
            (((unsigned __int128)dividend_hi) << 64 | ((unsigned __int128)dividend_lo)) / divisor;
    *quotient_lo = (uint64_t)result;
    *quotient_hi = (uint64_t)(result >> 64);
#else
    uint64_t dividend_dwords[4];
    uint32_t remainder = 0;

    dividend_dwords[3] = hi_dword(dividend_hi);
    dividend_dwords[2] = lo_dword(dividend_hi);
    dividend_dwords[1] = hi_dword(dividend_lo);
    dividend_dwords[0] = lo_dword(dividend_lo);

    *quotient_hi = div_with_remainder(dividend_dwords[3], divisor, &remainder) << 32;
    *quotient_hi |= div_with_remainder(dividend_dwords[2], divisor, &remainder);
    *quotient_lo = div_with_remainder(dividend_dwords[1], divisor, &remainder) << 32;
    *quotient_lo |= div_with_remainder(dividend_dwords[0], divisor, &remainder);
#endif
}

// Long division with 2^64 base
static inline void div128_64(
        uint64_t dividend_hi,
        uint64_t dividend_lo,
        uint64_t divisor,
        uint64_t* quotient_hi,
        uint64_t* quotient_lo) {
#ifdef __SIZEOF_INT128__
    unsigned __int128 result =
            (((unsigned __int128)dividend_hi) << 64 | ((unsigned __int128)dividend_lo)) / divisor;
    *quotient_lo = (uint64_t)result;
    *quotient_hi = (uint64_t)(result >> 64);
#else
    uint64_t remainder = 0;
    for (size_t i = 0; i < 128; i++) {
        bool carry = remainder >> 63;
        remainder <<= 1;
        if (shl128(&dividend_hi, &dividend_lo))
            remainder |= 1;
        if (carry || remainder >= divisor) {
            remainder -= divisor;
            dividend_lo |= 1;
        }
    }
    *quotient_hi = dividend_hi;
    *quotient_lo = dividend_lo;
#endif
}

// Calculates a*b/c, using 128-bit precision to avoid overflow.  This assumes that the result is
// 64-bits, but only checks it (via assertion) in debug builds.  As such you should only call this
// when this is true: for instance, when c is known to be greater than either a or b.
static inline uint64_t mul128_div64(uint64_t a, uint64_t b, uint64_t c) {
#ifdef __SIZEOF_INT128__
    return (uint64_t)((unsigned __int128)a) * ((unsigned __int128)b) / ((unsigned __int128)c);
#else
    uint64_t hi;
    uint64_t lo = mul128(a, b, &hi);
    uint64_t resulthi, resultlo;
    div128_64(hi, lo, c, &resulthi, &resultlo);
    assert(resulthi == 0);
    return resultlo;
#endif
}

#ifdef _MSC_VER
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN 4321
#define BYTE_ORDER LITTLE_ENDIAN
#endif

#if !defined(BYTE_ORDER) || !defined(LITTLE_ENDIAN) || !defined(BIG_ENDIAN)
static_assert(false, "BYTE_ORDER is undefined. Perhaps, GNU extensions are not enabled");
#endif

#if BYTE_ORDER == LITTLE_ENDIAN

#define SWAP64LE(x) ((uint64_t)(x))
#define SWAP64BE epee_int_utils_bswap_64
#define SWAP32LE(x) ((uint32_t)(x))
#define SWAP32BE(x) epee_int_utils_bswap_32

static inline void memcpy_swap64le(void* dst, const void* src, size_t n) {
    memcpy(dst, src, 8 * n);
}

#else

#define SWAP64BE(x) ((uint64_t)(x))
#define SWAP64LE epee_int_utils_bswap_64
#define SWAP32BE(x) ((uint32_t)(x))
#define SWAP32LE(x) epee_int_utils_bswap_32

static inline void memcpy_swap64le(void* dst, const void* src, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        ((uint64_t*)dst)[i] = swap64(((const uint64_t*)src)[i]);
    }
}

#endif
