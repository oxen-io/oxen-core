// Copyright (c) 2018-2020, The Loki Project
// Copyright (c) 2014-2017, The Monero Project
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

#include <type_traits>

#include "serialization.h"

namespace serialization {

template <class Archive>
concept serializing = Archive::is_serializer;
template <class Archive>
concept deserializing = Archive::is_deserializer;

// Consumes everything left in a deserialization archiver stream (without knowing the number of
// elements in advance) into the given container (which must supply an stl-like `emplace_back()`).
// Throws on serialization error, including the case where we run out of data that *isn't* on a
// deserialization value boundary.
template <deserializing Archive, typename Container>
void deserialize_all(Archive& ar, Container& c) {
    while (ar.remaining_bytes() > 0)
        value(ar, c.emplace_back());
}

namespace detail {

    /// True if `val.reserve(0)` exists for `T val`.
    template <typename T>
    concept reservable = requires(T val) { val.reserve(size_t{}); };

    /// True if `val.emplace_back()` exists for `T val`, and that T::value_type is default
    /// constructible.
    template <typename T>
    concept back_emplaceable = requires(T val) { val.emplace_back(); };

    /// True if `val.insert(V{})` exists for `T val` and `using V = T::value_type`.
    template <typename T>
    concept value_insertable = requires(T val) { val.insert(typename T::value_type{}); };

    template <typename Archive, class T>
    void serialize_container_element(Archive& ar, T& e) {
        using I = std::remove_cv_t<T>;
        if constexpr (std::is_same_v<I, uint32_t> || std::is_same_v<I, uint64_t>)
            varint(ar, e);
        else
            value(ar, e);
    }

    // Deserialize into the container.
    template <deserializing Archive, typename C>
        requires detail::back_emplaceable<C> || detail::value_insertable<C>
    void serialize_container(Archive& ar, C& v) {
        using T = std::remove_cv_t<typename C::value_type>;

        size_t cnt;
        auto arr = ar.begin_array(cnt);

        // very basic sanity check
        // disabled because it is wrong: a type could, for example, pack multiple values into a
        // byte (e.g. something like std::vector<bool> does), in which cases values >= bytes
        // need not be true. ar.remaining_bytes(cnt);

        v.clear();
        if constexpr (reservable<C>)
            v.reserve(cnt);

        for (size_t i = 0; i < cnt; i++) {
            if constexpr (detail::back_emplaceable<C>)
                detail::serialize_container_element(ar, v.emplace_back());
            else {
                T e{};
                detail::serialize_container_element(ar, e);
                e.insert(std::move(e));
            }
        }
    }

    // Serialize the container
    template <serializing Archive, typename C>
    void serialize_container(Archive& ar, C& v) {
        size_t cnt = v.size();
        auto arr = ar.begin_array(cnt);
        for (auto& e : v)
            serialize_container_element(ar, e);
    }
}  // namespace detail

}  // namespace serialization
