// Copyright (c) 2020-2024, The Oxen Project
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

#pragma once

#include <map>
#include <unordered_map>

#include "container.h"

namespace serialization {

namespace detail {

    template <serializing Archive, typename Map>
    void serialize_map(Archive& ar, Map& m) {
        size_t cnt = m.size();
        auto arr = ar.begin_array(cnt);
        for (auto& [k, v] : m) {
            // We're serializing so this won't actually change k, despite casting away the
            // const, but the serialization code is a bit inflexible with const types.
            serialize_container_element(ar, const_cast<typename Map::key_type&>(k));
            serialize_container_element(ar, v);
        }
    }

    template <deserializing Archive, typename Map>
    void serialize_map(Archive& ar, Map& m) {
        size_t cnt;
        auto arr = ar.begin_array(cnt);

        m.clear();

        for (size_t i = 0; i < cnt; i++) {
            std::pair<typename Map::key_type, typename Map::mapped_type> e{};
            auto& [k, v] = e;
            serialize_container_element(ar, k);
            serialize_container_element(ar, v);
            m.insert(std::move(e));
        }
    }

}  // namespace detail

template <typename Archive, class K, class V, class Cmp, class Alloc>
void serialize_value(Archive& ar, std::map<K, V, Cmp, Alloc>& m) {
    detail::serialize_map(ar, m);
}
template <typename Archive, class K, class V, class Hash, class KEq, class Alloc>
void serialize_value(Archive& ar, std::unordered_map<K, V, Hash, KEq, Alloc>& m) {
    detail::serialize_map(ar, m);
}

}  // namespace serialization
