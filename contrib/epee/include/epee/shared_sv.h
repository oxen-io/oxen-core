// Copyright (c) 2020, The Loki Project
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
#include <memory>
#include <string>
#include <string_view>

namespace epee {

/// Class that holds a shared pointer to a string plus a separate string_view referencing some
/// substring of that shared string.
struct shared_sv {
    std::shared_ptr<std::string> ptr;
    std::string_view view;
    shared_sv() = default;
    /// Constructs from a shared_ptr to a string; the view is initialized to refer to the entire
    /// string
    explicit shared_sv(std::shared_ptr<std::string> src_ptr) :
            ptr{std::move(src_ptr)}, view{*ptr} {}
    /// Constructs a new shared ptr by moving from a given string rvalue reference
    explicit shared_sv(std::string&& str) :
            shared_sv{std::make_shared<std::string>(std::move(str))} {}
    /// Constructs from a shared_ptr and a view
    shared_sv(std::shared_ptr<std::string> src_ptr, std::string_view view) :
            ptr{std::move(src_ptr)}, view{view} {}

    /// Shortcut for obj.view.size()
    auto size() const { return view.size(); }
    /// Shortcut for obj.view.data()
    auto data() const { return view.data(); }

    /// Extracts a view prefix of up to size bytes and returns it in a new shared_sv that shares
    /// ownership with this shared_sv.  The prefix is removed from the view of this.
    shared_sv extract_prefix(size_t size) {
        auto prefix_view = view.substr(0, size);
        view.remove_prefix(prefix_view.size());
        return {ptr, prefix_view};
    }
};

}  // namespace epee
