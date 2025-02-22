// Copyright (c) 2019, The Monero Project
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

#include <fmt/core.h>

#include <string>
#include <string_view>
#include <vector>

#include "common/format.h"
#include "fs.h"

namespace tools {

class Notify {
  public:
    explicit Notify(std::string_view spec);

    template <typename T, typename... MoreTags>
    int notify(std::string_view tag, const T& value, MoreTags&&... more) const {
        std::vector<std::string> margs{args};
        replace_tags(margs, tag, value, std::forward<MoreTags>(more)...);
        return spawn(margs);
    }

  private:
    fs::path filename;
    std::vector<std::string> args;

    int spawn(const std::vector<std::string>& margs) const;

    template <typename T, typename... MoreTags>
    static void replace_tags(
            std::vector<std::string>& margs,
            std::string_view tag,
            const T& value,
            MoreTags&&... more) {
        replace_tag(margs, tag, "{}"_format(value));
        if constexpr (sizeof...(MoreTags) > 0)
            replace_tags(margs, std::forward<MoreTags>(more)...);
    }

    static void replace_tag(
            std::vector<std::string>& margs, std::string_view tag, std::string_view value);
};

}  // namespace tools
