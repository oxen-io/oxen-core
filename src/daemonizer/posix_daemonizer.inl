// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2018, The Loki Project
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

#include "common/command_line.h"
#include "common/file.h"
#include "common/scoped_message_writer.h"

namespace daemonizer {
namespace {
    // deprecated, but still here to print an error msg if you try to use it:
    const command_line::arg_flag arg_detach = {"detach", ""};
    const command_line::arg_flag arg_non_interactive = {"non-interactive", "Run non-interactive"};
}  // namespace

inline void init_options(
        boost::program_options::options_description& hidden_options,
        boost::program_options::options_description& normal_options) {
    command_line::add_arg(hidden_options, arg_detach);
    command_line::add_arg(normal_options, arg_non_interactive);
}

inline fs::path get_default_data_dir() {
    return fs::absolute(tools::get_default_data_dir());
}

inline fs::path get_relative_path_base(boost::program_options::variables_map const& vm) {
    return fs::current_path();
}

template <typename Application, typename... Args>
bool daemonize(
        const char* name,
        int argc,
        const char* argv[],
        boost::program_options::variables_map vm,
        Args&&... args) {
    (void)name;
    (void)argc;
    (void)argv;  // Only used for Windows
    if (command_line::get_arg(vm, arg_detach)) {
        oxen::log::error(
                globallogcat,
                "--detach is no longer supported. Use systemd (or another process manager), tmux, "
                "screen, or nohup instead");
        return false;
    }
    bool interactive = !command_line::get_arg(vm, arg_non_interactive);
    return Application{std::move(vm), std::forward<Args>(args)...}.run(interactive);
}
}  // namespace daemonizer
