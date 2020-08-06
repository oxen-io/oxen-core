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

#include <boost/endian/conversion.hpp>
#include <optional>
#include <memory>
#include <string>
#include <chrono>

#include "crypto/hash.h"
#include "cryptonote_config.h"

/*! \brief Dumping ground for random functions.  Please think long and hard before you add anything
 * here.
 *
 *  
 * 
 */
namespace tools
{
  bool sanitize_locale();

  bool disable_core_dumps();

  bool on_startup();

  ssize_t get_lockable_memory();

  void set_max_concurrency(unsigned n);
  unsigned get_max_concurrency();

  bool is_local_address(const std::string &address);
  int vercmp(std::string_view v0, std::string_view v1); // returns < 0, 0, > 0, similar to strcmp, but more human friendly than lexical - does not attempt to validate

  std::optional<std::pair<uint32_t, uint32_t>> parse_subaddress_lookahead(const std::string& str);

#ifdef _WIN32
  std::string input_line_win();
#endif

  std::string get_human_readable_timestamp(uint64_t ts);
  std::string get_human_readable_timespan(std::chrono::seconds seconds);
  std::string get_human_readable_bytes(uint64_t bytes);

  template <typename Duration, std::enable_if_t<!std::is_same_v<Duration, std::chrono::seconds>, int> = 0>
  std::string get_human_readable_timespan(Duration d)
  {
    return get_human_readable_timespan(std::chrono::duration_cast<std::chrono::seconds>(d));
  }

  namespace detail {
    // Copy an integer type, swapping to little-endian if needed
    template <typename T, std::enable_if_t<std::is_integral<T>::value, int> = 0>
    void memcpy_one(char*& dest, T t) {
      boost::endian::native_to_little_inplace(t);
      std::memcpy(dest, &t, sizeof(T));
      dest += sizeof(T);
    }

    // Copy a class byte-for-byte (but only if it is standard layout and has byte alignment)
    template <typename T, std::enable_if_t<std::is_class<T>::value, int> = 0>
    void memcpy_one(char*& dest, const T& t) {
      // We don't *actually* require byte alignment here but it's quite possibly an error (i.e.
      // passing in a type containing integer members) so disallow it.
      static_assert(std::is_trivially_copyable<T>::value && alignof(T) == 1, "memcpy_le() may only be used on simple (1-byte alignment) struct types");
      std::memcpy(dest, &t, sizeof(T));
      dest += sizeof(T);
    }

    // Copy a string literal
    template <typename T, size_t N>
    void memcpy_one(char*& dest, const T (&arr)[N]) {
      for (const T &t : arr)
        memcpy_one(dest, t);
    }
  }

  // Does a memcpy of one or more values into a char array; for any given values that are basic
  // integer types the value is first converted from native to little-endian representation (if
  // necessary).  Non-integer types with alignment of 1 (typically meaning structs containing only
  // char, bools, and arrays of those) and fixed-size arrays of the above (including string
  // literals) are also permitted; more complex types are not.
  //
  // The 1-byte alignment is here to protect you: if you have a larger alignment that usually means
  // you have a contained type with a larger alignment, which is probably an integer.
  template <typename... T>
  auto memcpy_le(const T &...t) {
    std::array<char, (0 + ... + sizeof(T))> r;
    char* dest = r.data();
    (..., detail::memcpy_one(dest, t));
    return r;
  }

  // Returns the `_count` element of a scoped enum, cast to the enum's underlying type
  template <typename Enum>
  constexpr auto enum_count = static_cast<std::underlying_type_t<Enum>>(Enum::_count);

  template <typename Enum>
  constexpr Enum enum_top = static_cast<Enum>(enum_count<Enum> - 1);

  uint64_t cumulative_block_sync_weight(cryptonote::network_type nettype, uint64_t start_block, uint64_t num_blocks);
}
