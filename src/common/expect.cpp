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

#include "expect.h"

#include <string>
#include <common/exception.h>

#include "common/fs.h"

namespace detail {
namespace {
    std::string generate_error(const char* msg, const char* file, unsigned line) {
        std::string error_msg{};
        if (msg) {
            error_msg.append(msg);
            if (file)
                error_msg.append(" (");
        }
        if (file) {
            error_msg.append("thrown at ");

            // remove path, get just filename + extension
            error_msg.append(fs::path(file).filename().string());

            error_msg.push_back(':');
            error_msg.append(std::to_string(line));
        }
        if (msg && file)
            error_msg.push_back(')');
        return error_msg;
    }
}  // namespace

void expect::throw_(std::error_code ec, const char* msg, const char* file, unsigned line) {
    if (msg || file)
        throw oxen::traced<std::system_error>{ec, generate_error(msg, file, line)};
    throw oxen::traced<std::system_error>{ec, msg};
}
}  // namespace detail
