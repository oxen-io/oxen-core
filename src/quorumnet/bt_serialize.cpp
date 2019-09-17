// Copyright (c)      2019, The Loki Project
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

#include "bt_serialize.h"

namespace quorumnet {

namespace detail {

template void bt_expect<bt_deserialize_invalid>(std::istream &is, char expect);
template void bt_expect<bt_deserialize_invalid_type>(std::istream &is, char expect);

void bt_deserialize<std::string>::operator()(std::istream &is, std::string &val) {
    char first = is.peek();
    bt_no_eof(is);
    if (first < '0' || first > '9')
        throw bt_deserialize_invalid_type("Expected 0-9 but found '" + std::string(1, first) + "' at input location " + std::to_string(is.tellg()));
    uint64_t len;
    is >> len;
    char colon = is.peek();
    if (colon == ':')
        is.ignore();
    else
        throw bt_deserialize_invalid("Expected : but found '" + std::string(1, colon) + "' at input location " + std::to_string(is.tellg()));

    if (len <= 4096) {
        val.clear();
        val.resize(len);
        is.read(&val[0], len);
        bt_no_eof(is);
        return;
    }
    // Otherwise the serialization contains a large (>4K) value: don't trust the caller by
    // pre-reserving (so that they can't run us out of memory by sending a malformed fake huge value
    // to deserialize).  Instead just let `val` reallocate as std::string sees fit.
    val.clear();
    char buffer[4096];
    while (len) {
        auto read = std::min<uint64_t>(len, 4096);
        is.read(buffer, read);
        bt_no_eof(is);
        val.append(buffer, read);
        len -= read;
    }
}

// Check that we are on a 2's complement architecture.  It's highly unlikely that this code ever
// runs on a non-2s-complement architecture, but check at compile time because we rely on these
// relations below.
static_assert(std::numeric_limits<int64_t>::min() + std::numeric_limits<int64_t>::max() == -1 &&
        static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + uint64_t{1} == (uint64_t{1} << 63),
        "Non 2s-complement architecture not supported!");

std::pair<maybe_signed_int64_t, bool> bt_deserialize_integer(std::istream &is) {
    bt_expect<bt_deserialize_invalid_type>(is, 'i');
    std::pair<maybe_signed_int64_t, bool> result;
    char first = is.peek();
    if (first == '-') {
        result.second = true;
        is.ignore();
        first = is.peek();
    }
    bt_no_eof(is);
    if (first < '0' || first > '9')
        throw bt_deserialize_invalid("Expected 0-9 but found '" + std::string(1, first) + "' at input location " + std::to_string(is.tellg()));

    uint64_t uval;
    is >> uval;
    bt_expect(is, 'e');
    if (result.second) {
        if (uval > (uint64_t{1} << 63))
            throw bt_deserialize_invalid("Found too-large negative value just before input location " + std::to_string(is.tellg()));
        result.first.i64 = -uval;
    }
    else {
        result.first.u64 = uval;
    }
    return result;
}

template struct bt_deserialize<int64_t>;
template struct bt_deserialize<uint64_t>;

void bt_deserialize<bt_value, void>::operator()(std::istream &is, bt_value &val) {
    auto next = is.peek();
    bt_no_eof(is);
    switch (next) {
        case 'd': {
            using dict_t = std::unordered_map<std::string, bt_value>;
            dict_t dict;
            bt_deserialize<dict_t>{}(is, dict);
            val = std::move(dict);
            break;
        }
        case 'l': {
            using list_t = std::list<bt_value>;
            list_t list;
            bt_deserialize<list_t>{}(is, list);
            val = std::move(list);
            break;
        }
        case 'i': {
            int64_t num;
            bt_deserialize<int64_t>{}(is, num);
            val = num;
            break;
        }
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9': {
            std::string str;
            bt_deserialize<std::string>{}(is, str);
            val = std::move(str);
            break;
        }
        default:
            throw bt_deserialize_invalid("Deserialize failed: encountered invalid value '" + std::string(1, next) + "'; expected one of [0-9idl]");
    }
}

} // namespace detail
} // namespace quorumnet
