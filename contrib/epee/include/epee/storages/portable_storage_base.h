// Copyright (c) 2006-2013, Andrey N. Sabelnikov, www.sabelnikov.net
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// * Neither the name of the Andrey N. Sabelnikov nor the
// names of its contributors may be used to endorse or promote products
// derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER  BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 



#pragma once 

#include <variant>
#include <string>
#include <vector>
#include <deque>
#include <cstdint>
#include <map>
#include "../misc_log_ex.h"
#include "../int-util.h"

namespace epee
{

  namespace serialization
  {
    constexpr uint32_t PORTABLE_STORAGE_SIGNATUREA = SWAP32LE(0x01011101);
    constexpr uint32_t PORTABLE_STORAGE_SIGNATUREB = SWAP32LE(0x01020101); // bender's nightmare 
    constexpr uint8_t PORTABLE_STORAGE_FORMAT_VER = 1;

    // When sending a "varint" the binary serialization uses the bottom 2 bits to store the size,
    // either 1, 2, 4, or 8 bytes for 6/14/30/62 bits of storage.  God help you if you want to store
    // something >= 2^62 (but don't worry, it throws an exception if you try).
    constexpr uint8_t
      PORTABLE_RAW_SIZE_MARK_MASK  = 0b11,
      PORTABLE_RAW_SIZE_MARK_6BIT  = 0,
      PORTABLE_RAW_SIZE_MARK_14BIT = 1,
      PORTABLE_RAW_SIZE_MARK_30BIT = 2,
      PORTABLE_RAW_SIZE_MARK_62BIT = 3;

    constexpr size_t MAX_STRING_LEN_POSSIBLE = 2000000000; //do not let string be so big

    struct section;

    template <typename T>
    using array_t = std::conditional_t<std::is_same_v<T, bool>, std::deque<bool>, std::vector<T>>;

    using array_entry = std::variant<
      array_t<uint64_t>,
      array_t<uint32_t>,
      array_t<uint16_t>,
      array_t<uint8_t>,
      array_t<int64_t>,
      array_t<int32_t>,
      array_t<int16_t>,
      array_t<int8_t>,
      array_t<double>,
      array_t<bool>,
      array_t<std::string>,
      array_t<section>
    >;
    // FIXME: dropped recursive arrays -- is this okay?

    using storage_entry = std::variant<
      uint64_t,
      uint32_t,
      uint16_t,
      uint8_t,
      int64_t,
      int32_t,
      int16_t,
      int8_t,
      double,
      bool,
      std::string,
      section,
      array_entry
    >;

    template <typename T, typename = void>
    constexpr bool variant_contains = false;

    template <typename T, typename... Us>
    constexpr bool variant_contains<T, std::variant<Us...>> = (... || std::is_same_v<T, Us>);

    /************************************************************************/
    /*                                                                      */
    /************************************************************************/
    struct section
    {
      std::map<std::string, storage_entry> m_entries;
    };

    template <typename T> constexpr bool TYPE_IS_NOT_SERIALIZABLE = false;

    template <typename T>
    constexpr uint8_t no_such_type() { static_assert(TYPE_IS_NOT_SERIALIZABLE<T>); return 0; }

    //data types
    template <typename T> constexpr uint8_t SERIALIZE_TYPE_TAG = no_such_type<T>();
    template <> inline constexpr uint8_t SERIALIZE_TYPE_TAG<int64_t>     = 1;
    template <> inline constexpr uint8_t SERIALIZE_TYPE_TAG<int32_t>     = 2;
    template <> inline constexpr uint8_t SERIALIZE_TYPE_TAG<int16_t>     = 3;
    template <> inline constexpr uint8_t SERIALIZE_TYPE_TAG<int8_t>      = 4;
    template <> inline constexpr uint8_t SERIALIZE_TYPE_TAG<uint64_t>    = 5;
    template <> inline constexpr uint8_t SERIALIZE_TYPE_TAG<uint32_t>    = 6;
    template <> inline constexpr uint8_t SERIALIZE_TYPE_TAG<uint16_t>    = 7;
    template <> inline constexpr uint8_t SERIALIZE_TYPE_TAG<uint8_t>     = 8;
    template <> inline constexpr uint8_t SERIALIZE_TYPE_TAG<double>      = 9;
    template <> inline constexpr uint8_t SERIALIZE_TYPE_TAG<std::string> = 10;
    template <> inline constexpr uint8_t SERIALIZE_TYPE_TAG<bool>        = 11;
    template <> inline constexpr uint8_t SERIALIZE_TYPE_TAG<section>     = 12;
    //template <> inline constexpr uint8_t SERIALIZE_TYPE_TAG<array>       = 13; // nested array

    constexpr uint8_t SERIALIZE_FLAG_ARRAY = 0x80;

  }
}
