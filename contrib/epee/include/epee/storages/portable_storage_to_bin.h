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

#include <oxenc/endian.h>
#include <oxenc/variant.h>

#include <limits>

#include "../pragma_comp_defs.h"
#include "portable_storage_base.h"

namespace epee::serialization {

namespace detail {
    template <class IntT>
    void pack_varint(std::ostream& strm, uint8_t type_or, IntT v);
}  // namespace detail

inline void pack_varint(std::ostream& strm, uint64_t val) {
    // the two least significant bits are used for size information
    if (val < (1ULL << 6))
        detail::pack_varint(strm, PORTABLE_RAW_SIZE_MARK_6BIT, static_cast<uint8_t>(val));
    else if (val < (1ULL << 14))
        detail::pack_varint(strm, PORTABLE_RAW_SIZE_MARK_14BIT, static_cast<uint16_t>(val));
    else if (val < (1ULL << 30))
        detail::pack_varint(strm, PORTABLE_RAW_SIZE_MARK_30BIT, static_cast<uint32_t>(val));
    else if (val < (1ULL << 62))
        detail::pack_varint(strm, PORTABLE_RAW_SIZE_MARK_62BIT, val);
    else
        ASSERT_MES_AND_THROW("failed to pack varint -- integer value too large: {} >= 2^62", val);
}

inline void pack_entry_to_buff(std::ostream& strm, const std::string& v) {
    CHECK_AND_ASSERT_THROW_MES(
            v.size() < MAX_STRING_LEN_POSSIBLE, "string to store is too large: {}", v.size());
    pack_varint(strm, v.size());
    if (!v.empty())
        strm.write(v.data(), v.size());
}

template <typename T, std::enable_if_t<std::is_integral_v<T>, int> = 0>
void pack_entry_to_buff(std::ostream& strm, T v) {
    if constexpr (sizeof(T) > 1)
        oxenc::host_to_little_inplace(v);
    strm.write(reinterpret_cast<const char*>(&v), sizeof(v));
}

inline void pack_entry_to_buff(std::ostream& strm, double v) {
    static_assert(
            std::numeric_limits<double>::is_iec559 && sizeof(double) == 8 &&
            (oxenc::little_endian || oxenc::big_endian));
    char* buff = reinterpret_cast<char*>(&v);
    if constexpr (oxenc::big_endian) {
        size_t i = 8;
        while (i)
            strm.put(buff[--i]);
    } else {
        strm.write(buff, 8);
    }
}

void pack_entry_to_buff(std::ostream& strm, const storage_entry& se);
void pack_entry_to_buff(std::ostream& strm, const section& se);

inline void pack_entry_to_buff(std::ostream& strm, const array_entry& ae) {
    var::visit(
            [&strm](const auto& arr) {
                using T = typename std::remove_const_t<
                        std::remove_reference_t<decltype(arr)>>::value_type;

                constexpr uint8_t tag = SERIALIZE_FLAG_ARRAY | SERIALIZE_TYPE_TAG<T>;
                strm.write(reinterpret_cast<const char*>(&tag), 1);
                pack_varint(strm, arr.size());

                for (auto& v : arr)
                    pack_entry_to_buff(strm, v);
            },
            ae);
}

inline void pack_entry_to_buff(std::ostream& strm, const storage_entry& se) {
    var::visit(
            [&strm](const auto& v) {
                using T = std::remove_const_t<std::remove_reference_t<decltype(v)>>;

                if constexpr (!std::is_same_v<T, array_entry>)  // array_entries get a combined
                                                                // flag+value instead.
                    strm.write(reinterpret_cast<const char*>(&SERIALIZE_TYPE_TAG<T>), 1);

                pack_entry_to_buff(strm, v);
            },
            se);
}

inline void pack_entry_to_buff(std::ostream& strm, const section& sec) {
    typedef std::map<std::string, storage_entry>::value_type section_pair;
    pack_varint(strm, sec.m_entries.size());
    for (const section_pair& se : sec.m_entries) {
        CHECK_AND_ASSERT_THROW_MES(
                se.first.size() < std::numeric_limits<uint8_t>::max(),
                "storage_entry_name is too long: {}, val: {}",
                se.first.size(),
                se.first);
        uint8_t len = static_cast<uint8_t>(se.first.size());
        strm.write((const char*)&len, sizeof(len));
        strm.write(se.first.data(), size_t(len));
        pack_entry_to_buff(strm, se.second);
    }
}

namespace detail {

    template <class IntT>
    void pack_varint(std::ostream& strm, uint8_t type_or, IntT v) {
        // Left shift it and store the size tag in the bottom two bits.  We're always guaranteed
        // (below) to have enough space for the shift to not drop significant bits.
        v <<= 2;
        v |= type_or;
        pack_entry_to_buff(strm, v);
    }

}  // namespace detail

}  // namespace epee::serialization
