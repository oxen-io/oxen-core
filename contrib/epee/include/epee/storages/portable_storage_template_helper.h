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

#include <string>
#include <string_view>

#include "parserse_base_utils.h"
#include "portable_storage.h"

namespace epee::serialization {
//-----------------------------------------------------------------------------------------------------------
template <typename T>
bool load_t_from_json(T& out, std::string_view json_buff) {
    portable_storage ps;
    bool rs = ps.load_from_json(json_buff);
    if (!rs)
        return false;

    return out.load(ps);
}
//-----------------------------------------------------------------------------------------------------------
template <class t_struct>
bool store_t_to_json(
        t_struct& str_in, std::string& json_buff, size_t indent = 0, bool insert_newlines = true) {
    portable_storage ps;
    str_in.store(ps);
    ps.dump_as_json(json_buff, indent, insert_newlines);
    return true;
}
//-----------------------------------------------------------------------------------------------------------
template <class t_struct>
std::string store_t_to_json(t_struct& str_in, size_t indent = 0, bool insert_newlines = true) {
    std::string json_buff;
    store_t_to_json(str_in, json_buff, indent, insert_newlines);
    return json_buff;
}
//-----------------------------------------------------------------------------------------------------------
template <class t_struct>
bool load_t_from_binary(t_struct& out, const epee::span<const uint8_t> binary_buff) {
    portable_storage ps;
    bool rs = ps.load_from_binary(binary_buff);
    if (!rs)
        return false;

    return out.load(ps);
}
//-----------------------------------------------------------------------------------------------------------
template <class t_struct>
bool load_t_from_binary(t_struct& out, std::string_view binary_buff) {
    portable_storage ps;
    if (!ps.load_from_binary(binary_buff))
        return false;

    return out.load(ps);
}
//-----------------------------------------------------------------------------------------------------------
template <class t_struct>
bool store_t_to_binary(
        t_struct& str_in, std::string& binary_buff, [[maybe_unused]] size_t indent = 0) {
    portable_storage ps;
    str_in.store(ps);
    return ps.store_to_binary(binary_buff);
}
//-----------------------------------------------------------------------------------------------------------
template <class t_struct>
std::string store_t_to_binary(t_struct& str_in, size_t indent = 0) {
    std::string binary_buff;
    store_t_to_binary(str_in, binary_buff, indent);
    return binary_buff;
}
}  // namespace epee::serialization
