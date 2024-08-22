// Copyright (c) 2016-2018, The Monero Project
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

#include <spdlog/sinks/basic_file_sink.h>

#include <oxen/log.hpp>

#include "common/file.h"
#include "epee/misc_log_ex.h"
#include "gtest/gtest.h"
#include "logging/oxen_logger.h"
#include "random_path.h"

static std::string log_filename;

static void init() {
    fs::path p = random_tmp_file();
    log_filename = p.string();

    oxen::log::reset_level(oxen::log::Level::info);
    try {
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_filename);
        oxen::log::add_sink(std::move(file_sink));
    } catch (const spdlog::spdlog_ex& ex) {
        oxen::log::error(
                globallogcat,
                "Failed to open {} for logging: {}.  File logging disabled.",
                log_filename,
                ex.what());
        return;
    }
}

static void cleanup() {
    // windows does not let files be deleted if still in use, so leave droppings there
#ifndef _WIN32
    fs::remove(log_filename);
#endif
}

static bool load_log_to_string(const std::string& filename, std::string& str) {
    oxen::log::flush();
    if (!tools::slurp_file(filename, str))
        return false;
    for (const char* ptr = str.c_str(); *ptr; ++ptr) {
        if (*ptr == '\n') {
            std::string prefix = std::string(str.c_str(), ptr - str.c_str());
            if (prefix.find("New log categories") != std::string::npos) {
                str = std::string(ptr + 1, strlen(ptr + 1));
                break;
            }
        }
    }
    return true;
}

static void log() {
    oxen::log::error(globallogcat, "fatal");
    oxen::log::error(globallogcat, "error");
    oxen::log::warning(globallogcat, "warning");
    oxen::log::info(globallogcat, "info");
    oxen::log::debug(globallogcat, "debug");
    oxen::log::trace(globallogcat, "trace");

    oxen::log::info(oxen::log::Cat("first"), "a.b.c.d");
    oxen::log::info(oxen::log::Cat("second"), "a.b.c.e");
    oxen::log::info(oxen::log::Cat("third"), "x.y.z");
    oxen::log::info(oxen::log::Cat("forth"), "y.y.z");
    oxen::log::info(oxen::log::Cat("fifth"), "x.y.x");
}

TEST(logging, no_logs) {
    init();
    oxen::logging::apply_categories_string("*:critical");
    log();
    std::string str;
    ASSERT_TRUE(load_log_to_string(log_filename, str));
    ASSERT_TRUE(str == "");
    cleanup();
}

TEST(logging, default) {
    init();
    log();
    std::string str;
    ASSERT_TRUE(load_log_to_string(log_filename, str));
    ASSERT_TRUE(str.find("global") != std::string::npos);
    ASSERT_TRUE(str.find("fatal") != std::string::npos);
    ASSERT_TRUE(str.find("error") != std::string::npos);
    ASSERT_TRUE(str.find("debug") == std::string::npos);
    ASSERT_TRUE(str.find("trace") == std::string::npos);
    cleanup();
}

TEST(logging, all) {
    init();
    oxen::logging::apply_categories_string("*:trace");
    log();
    std::string str;
    ASSERT_TRUE(load_log_to_string(log_filename, str));
    ASSERT_TRUE(str.find("global") != std::string::npos);
    ASSERT_TRUE(str.find("fatal") != std::string::npos);
    ASSERT_TRUE(str.find("error") != std::string::npos);
    ASSERT_TRUE(str.find("debug") != std::string::npos);
#ifndef NDEBUG
    ASSERT_TRUE(str.find("trace") != std::string::npos);
#endif
    cleanup();
}

TEST(logging, last_precedence) {
    init();
    oxen::logging::apply_categories_string("*:warning,global:critical,global:debug");
    log();
    std::string str;
    ASSERT_TRUE(load_log_to_string(log_filename, str));
    ASSERT_TRUE(str.find("global") != std::string::npos);
    ASSERT_TRUE(str.find("x.y.z") == std::string::npos);
    ASSERT_TRUE(str.find("x.y.x") == std::string::npos);
    ASSERT_TRUE(str.find("y.y.z") == std::string::npos);
    cleanup();
}
