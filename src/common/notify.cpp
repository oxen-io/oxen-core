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

#include "notify.h"

#include <fmt/std.h>

#include "epee/misc_log_ex.h"
#include "logging/oxen_logger.h"
#include "spawn.h"
#include "string_util.h"

namespace tools {

static auto logcat = log::Cat("notify");

/*
  TODO:
  - Improve tokenization to handle paths containing whitespaces, quotes, etc.
  - Windows unicode support (implies implementing unicode command line parsing code)
*/
Notify::Notify(std::string_view spec) {
    CHECK_AND_ASSERT_THROW_MES(!spec.empty(), "Empty spec");

    auto pieces = tools::split_any(spec, " \t", true);
    CHECK_AND_ASSERT_THROW_MES(pieces.size() > 0, "Failed to parse spec");
    filename = tools::utf8_path(pieces[0]);
    CHECK_AND_ASSERT_THROW_MES(fs::exists(filename), "File not found: {}", filename);

    args.reserve(pieces.size());
    for (const auto& piece : pieces)
        args.emplace_back(piece);
}

void Notify::replace_tag(
        std::vector<std::string>& margs, std::string_view tag, std::string_view value) {
    if (tag.empty())
        return;
    // Skip margs[0], it's the binary name
    for (size_t i = 1; i < margs.size(); i++) {
        size_t pos = 0;
        while ((pos = margs[i].find(tag, pos)) != std::string::npos) {
            margs[i].replace(pos, tag.size(), value);
            pos += value.size();
        }
    }
}

int Notify::spawn(const std::vector<std::string>& margs) const {
    return tools::spawn(filename, margs, false);
}

}  // namespace tools
