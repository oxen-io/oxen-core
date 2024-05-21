// Copyright (c) 2018-2022, The Loki Project
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

/*! \file json_archive.h
 *
 * \brief JSON archiver
 */

#pragma once

#include <cassert>
#include <exception>
#include <nlohmann/json.hpp>
#include <vector>

#include "base.h"
#include "common/json_binary_proxy.h"
#include "serialization.h"

namespace serialization {

/*! \struct json_archiver
 *
 * \brief serialize data to JSON via nlohmann::json
 *
 * \detailed there is no deserializing counterpart; we only support JSON serializing here.
 */
struct json_archiver : public serializer {
    using variant_tag_type = std::string_view;

    explicit json_archiver(
            tools::json_binary_proxy::fmt bin_format = tools::json_binary_proxy::fmt::hex) :
            bin_format_{bin_format} {}

    /// Returns the current nlohmann::json.
    const nlohmann::json& json() const& { return top_; }
    nlohmann::json&& json() && { return std::move(top_); }

    /// Dumps the current nlohmann::json; arguments are forwarded to nlohmann::json::dump()
    template <typename... T>
    auto dump(T&&... args) const {
        return top_.dump(std::forward<T>(args)...);
    }

    // Sets the tag for the next object value we will write.
    void tag(std::string_view tag) { tag_ = tag; }

    struct nested_value {
        json_archiver& ar;
        ~nested_value() {
            assert(ar.stack_.size() >= 1);
            ar.stack_.pop_back();
        }

        nested_value(json_archiver& ar) : ar{ar} {}

        nested_value(const nested_value&) = delete;
        nested_value& operator=(const nested_value&) = delete;
        nested_value(nested_value&&) = delete;
        nested_value& operator=(nested_value&&) = delete;
    };

    [[nodiscard]] nested_value begin_object() {
        stack_.emplace_back(set(nlohmann::json::object()));
        return {*this};
    }

    [[nodiscard]] nested_value begin_array(size_t /*s*/ = 0) {
        stack_.emplace_back(set(nlohmann::json::array()));
        return {*this};
    }

    template <class T>
    void serialize_int(T v) {
        set(v);
    }

    template <class T>
    void serialize_varint(T& v) {
        serialize_int(v);
    }

    void serialize_blob(const void* buf, size_t len) {
        nlohmann::json val;
        tools::json_binary_proxy{val, bin_format_} =
                std::string_view{static_cast<const char*>(buf), len};
        set(std::move(val));
    }

    template <typename T>
    void serialize_blobs(const std::vector<T>& blobs) {
        serialize_blob(blobs.data(), blobs.size() * sizeof(T));
    }

    void write_variant_tag(std::string_view t) { tag(t); }

  private:
    nlohmann::json& curr() {
        if (stack_.empty())
            return top_;
        else
            return stack_.back();
    }

    template <typename T>
    nlohmann::json& set(T&& val) {
        auto& c = curr();
        if (stack_.empty()) {
            c = std::forward<T>(val);
            return c;
        }
        if (c.is_array()) {
            c.push_back(std::forward<T>(val));
            return c.back();
        }
        return (c[tag_] = std::forward<T>(val));
    }

    nlohmann::json top_;
    std::vector<std::reference_wrapper<nlohmann::json>> stack_{};
    tools::json_binary_proxy::fmt bin_format_;
    std::string tag_;
};

/*! serializes the data in v to a string.  Throws on error.
 */
template <class T>
std::string dump_json(T& v, int indent = -1) {
    json_archiver oar;
    serialize(oar, v);
    return oar.dump(indent);
}

}  // namespace serialization
