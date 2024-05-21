// Copyright (c) 2018-2020, The Loki Project
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

#ifndef DAEMON_COMMAND_LINE_ARGS_H
#define DAEMON_COMMAND_LINE_ARGS_H

#include "common/command_line.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_core.h"
#include "daemonizer/daemonizer.h"

namespace daemon_args {
const command_line::arg_descriptor<std::string> arg_config_file = {
        "config-file",
        "Specify configuration file",
        "<data-dir>/" + tools::convert_str<char>(cryptonote::CONF_FILENAME.u8string())};

const command_line::arg_descriptor<std::string> arg_log_file = {
        "log-file",
        "Specify log file",
        "<data-dir>/" + tools::convert_str<char>(cryptonote::LOG_FILENAME.u8string())};
const command_line::arg_descriptor<std::size_t> arg_max_log_file_size = {
        "max-log-file-size", "Specify maximum log file size [B]", 104850000};
const command_line::arg_descriptor<std::size_t> arg_max_log_files = {
        "max-log-files",
        "Specify maximum number of rotated log files to be saved (no limit by setting to 0)",
        50};
const command_line::arg_descriptor<std::string> arg_log_level = {"log-level", "", ""};
const command_line::arg_descriptor<std::vector<std::string>> arg_command = {
        "daemon_command", "Hidden"};
const command_line::arg_descriptor<unsigned> arg_max_concurrency = {
        "max-concurrency", "Max number of threads to use for a parallel job", 0};

}  // namespace daemon_args

#endif  // DAEMON_COMMAND_LINE_ARGS_H
