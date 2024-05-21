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

#include <cstddef>
#include <fstream>
#include <ios>
#include <string>
#include <string_view>
#include <cfenv>

#include "crypto/hash.h"
#include "crypto/variant2_int_sqrt.h"
#include "../io.h"

using namespace std::literals;
using namespace crypto;
typedef crypto::hash chash;

#define X_MACRO \
    HASH_X_MACRO(invalid,         "INVALID") \
    HASH_X_MACRO(fast,            "fast") \
    HASH_X_MACRO(tree,            "tree") \
    HASH_X_MACRO(extra_blake,     "extra-blake") \
    HASH_X_MACRO(extra_groestl,   "extra-groestl") \
    HASH_X_MACRO(extra_jh,        "extra-jh") \
    HASH_X_MACRO(extra_skein,     "extra-skein") \
    HASH_X_MACRO(heavy_v1,        "heavy-v1") \
    HASH_X_MACRO(heavy_v2,        "heavy-v2") \
    HASH_X_MACRO(turtle_light_v2, "turtle-light-v2") \
    HASH_X_MACRO(count,           "INVALID_COUNT")

#define HASH_X_MACRO(hash_type, str) hash_type,
enum struct hash_type { X_MACRO };
#undef HASH_X_MACRO

#define HASH_X_MACRO(hash_type, cmd_line_str) cmd_line_str,
char const *hash_type_str[] { X_MACRO };
#undef HASH_X_MACRO
#undef X_MACRO

int test_variant2_int_sqrt();
int test_variant2_int_sqrt_ref();

int main(int argc, char *argv[]) {
  std::fstream input;
  std::vector<unsigned char> data;
  chash expected, actual;
  size_t test = 0;
  bool error = false;
  if (argc != 3) {
    if ((argc == 2) && (strcmp(argv[1], "variant2_int_sqrt") == 0)) {
      if (test_variant2_int_sqrt_ref() != 0) {
        return 1;
      }
      const int round_modes[3] = { FE_DOWNWARD, FE_TONEAREST, FE_UPWARD };
      for (int i = 0; i < 3; ++i) {
        std::fesetround(round_modes[i]);
        const int result = test_variant2_int_sqrt();
        if (result != 0) {
          fmt::print(stderr, "FPU round mode was set to {}\n",
              round_modes[i] == FE_DOWNWARD ? "FE_DOWNWARD" :
              round_modes[i] == FE_TONEAREST ? "FE_TONEAREST" :
              round_modes[i] == FE_UPWARD ? "FE_UPWARD" :
              "unknown");
          return result;
        }
      }
      return 0;
    }
    fmt::print(stderr, "Wrong arguments.  Usage: {} TESTTYPE test-file.txt\n", argv[0]);
    return 1;
  }

  hash_type type = hash_type::invalid;
  for (size_t hash_type_index = 0; hash_type_index < static_cast<size_t>(hash_type::count); ++hash_type_index)
  {
    if (strcmp(argv[1], hash_type_str[hash_type_index]) == 0)
    {
      type = static_cast<hash_type>(hash_type_index);
      break;
    }
  }

  if (type == hash_type::invalid)
  {
    std::cerr << "Unknown hashing function\n";
    return 1;
  }

  input.open(argv[2], std::ios_base::in);
  for (;;) {
    ++test;
    input.exceptions(std::ios_base::badbit);
    get(input, expected);
    if (input.rdstate() & std::ios_base::eofbit) {
      break;
    }
    input.exceptions(std::ios_base::badbit | std::ios_base::failbit | std::ios_base::eofbit);
    input.clear(input.rdstate());
    get(input, data);

    void const *buf   = data.data();
    size_t len        = data.size();
    auto *actual_byte_ptr = actual.data();
    switch(type)
    {
      case hash_type::fast: cn_fast_hash(buf, len, actual_byte_ptr); break;
      case hash_type::tree:
      {
        if ((len & 31) != 0)
          throw std::ios_base::failure("Invalid input length for tree_hash");
        tree_hash((const unsigned char (*)[HASH_SIZE]) buf, len >> 5, actual_byte_ptr);
      }
      break;

      case hash_type::extra_blake:     hash_extra_blake  (buf, len, actual_byte_ptr); break;
      case hash_type::extra_groestl:   hash_extra_groestl(buf, len, actual_byte_ptr); break;
      case hash_type::extra_jh:        hash_extra_jh     (buf, len, actual_byte_ptr); break;
      case hash_type::extra_skein:     hash_extra_skein  (buf, len, actual_byte_ptr); break;
      case hash_type::heavy_v1:        cn_slow_hash      (buf, len, actual, cn_slow_hash_type::heavy_v1); break;
      case hash_type::heavy_v2:        cn_slow_hash      (buf, len, actual, cn_slow_hash_type::heavy_v2); break;
      case hash_type::turtle_light_v2: cn_slow_hash      (buf, len, actual, cn_slow_hash_type::turtle_lite_v2); break;
      default: throw std::runtime_error{"Unknown hashing function"};
    }

    if (expected != actual) {
      fmt::print(stderr, "Hash mismatch on test {}\nInput: {}\nExpected hash: {}\nActual hash: {}\n",
          test, (data.empty() ? "Empty" : oxenc::to_hex(data.begin(), data.end())), expected, actual);
      error = true;
    }
  }
  return error ? 1 : 0;
}

#if defined(__x86_64__) || (defined(_MSC_VER) && defined(_WIN64))

#include <emmintrin.h>

#if defined(_MSC_VER) || defined(__MINGW32__)
  #include <intrin.h>
#else
  #include <wmmintrin.h>
#endif

#endif

static inline bool test_variant2_int_sqrt_sse(const uint64_t sqrt_input, const uint64_t correct_result)
{
#if defined(__x86_64__) || (defined(_MSC_VER) && defined(_WIN64))
  uint64_t sqrt_result;
  VARIANT2_INTEGER_MATH_SQRT_STEP_SSE2();
  VARIANT2_INTEGER_MATH_SQRT_FIXUP(sqrt_result);
  if (sqrt_result != correct_result) {
    std::cerr << "Integer sqrt (SSE2 version) returned incorrect result for N = " << sqrt_input << "\n";
    std::cerr << "Expected result: " << correct_result << "\n";
    std::cerr << "Returned result: " << sqrt_result << "\n";
    return false;
  }
#endif

  return true;
}

static inline bool test_variant2_int_sqrt_fp64(const uint64_t sqrt_input, const uint64_t correct_result)
{
#if defined DBL_MANT_DIG && (DBL_MANT_DIG >= 50)
  uint64_t sqrt_result;
  VARIANT2_INTEGER_MATH_SQRT_STEP_FP64();
  VARIANT2_INTEGER_MATH_SQRT_FIXUP(sqrt_result);
  if (sqrt_result != correct_result) {
    std::cerr << "Integer sqrt (FP64 version) returned incorrect result for N = " << sqrt_input << "\n";
    std::cerr << "Expected result: " << correct_result << "\n";
    std::cerr << "Returned result: " << sqrt_result << "\n";
    return false;
  }
#endif

  return true;
}

static inline bool test_variant2_int_sqrt_ref(const uint64_t sqrt_input, const uint64_t correct_result)
{
  uint64_t sqrt_result;
  VARIANT2_INTEGER_MATH_SQRT_STEP_REF();
  if (sqrt_result != correct_result) {
    std::cerr << "Integer sqrt (reference version) returned incorrect result for N = " << sqrt_input << "\n";
    std::cerr << "Expected result: " << correct_result << "\n";
    std::cerr << "Returned result: " << sqrt_result << "\n";
    return false;
  }

  return true;
}

static inline bool test_variant2_int_sqrt(const uint64_t sqrt_input, const uint64_t correct_result)
{
  if (!test_variant2_int_sqrt_sse(sqrt_input, correct_result)) {
    return false;
  }
  if (!test_variant2_int_sqrt_fp64(sqrt_input, correct_result)) {
    return false;
  }

  return true;
}

int test_variant2_int_sqrt()
{
  if (!test_variant2_int_sqrt(0, 0)) {
    return 1;
  }
  if (!test_variant2_int_sqrt(1ULL << 63, 1930543745UL)) {
    return 1;
  }
  if (!test_variant2_int_sqrt(uint64_t(-1), 3558067407UL)) {
    return 1;
  }

  const char* full = std::getenv("V2_INT_SQRT_FULL_TEST");
  const uint64_t incr = full && full == "1"sv
      ? 1 : 83;

  for (uint64_t i = 1; i <= 3558067407UL; i += incr) {
    // "i" is integer part of "sqrt(2^64 + n) * 2 - 2^33"
    // n = (i/2 + 2^32)^2 - 2^64

    const uint64_t i0 = i >> 1;
    uint64_t n1;
    if ((i & 1) == 0) {
      // n = (i/2 + 2^32)^2 - 2^64
      // n = i^2/4 + 2*2^32*i/2 + 2^64 - 2^64
      // n = i^2/4 + 2^32*i
      // i is even, so i^2 is divisible by 4:
      // n = (i^2 >> 2) + (i << 32)

      // int_sqrt_v2(i^2/4 + 2^32*i - 1) must be equal to i - 1
      // int_sqrt_v2(i^2/4 + 2^32*i) must be equal to i
      n1 = i0 * i0 + (i << 32) - 1;
    }
    else {
      // n = (i/2 + 2^32)^2 - 2^64
      // n = i^2/4 + 2*2^32*i/2 + 2^64 - 2^64
      // n = i^2/4 + 2^32*i
      // i is odd, so i = i0*2+1 (i0 = i >> 1)
      // n = (i0*2+1)^2/4 + 2^32*i
      // n = (i0^2*4+i0*4+1)/4 + 2^32*i
      // n = i0^2+i0+1/4 + 2^32*i
      // i0^2+i0 + 2^32*i < n < i0^2+i0+1 + 2^32*i

      // int_sqrt_v2(i0^2+i0 + 2^32*i) must be equal to i - 1
      // int_sqrt_v2(i0^2+i0+1 + 2^32*i) must be equal to i
      n1 = i0 * i0 + i0 + (i << 32);
    }

    if (!test_variant2_int_sqrt(n1, i - 1)) {
      return 1;
    }
    if (!test_variant2_int_sqrt(n1 + 1, i)) {
      return 1;
    }
  }

  return 0;
}

int test_variant2_int_sqrt_ref()
{
  if (!test_variant2_int_sqrt_ref(0, 0)) {
    return 1;
  }
  if (!test_variant2_int_sqrt_ref(1ULL << 63, 1930543745UL)) {
    return 1;
  }
  if (!test_variant2_int_sqrt_ref(uint64_t(-1), 3558067407UL)) {
    return 1;
  }

  // Reference version is slow, so we test only every 83th edge case
  // "i += 83" because 1 + 83 * 42868282 = 3558067407
  for (uint64_t i = 1; i <= 3558067407UL; i += 83) {
    const uint64_t i0 = i >> 1;
    uint64_t n1;
    if ((i & 1) == 0) {
      n1 = i0 * i0 + (i << 32) - 1;
    }
    else {
      n1 = i0 * i0 + i0 + (i << 32);
    }

    if (!test_variant2_int_sqrt_ref(n1, i - 1)) {
      return 1;
    }
    if (!test_variant2_int_sqrt_ref(n1 + 1, i)) {
      return 1;
    }
  }

  return 0;
}
