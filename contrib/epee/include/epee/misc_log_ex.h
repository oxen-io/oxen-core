#pragma once

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


#ifndef __cplusplus
#error "this header is c++ only"
#endif

#include <cassert>
#include <string>
#include <sstream>
#include <iostream>
#include <oxen/log.hpp>

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "default"

namespace epee
{
namespace log = oxen::log;

inline auto logcat = oxen::log::Cat("epee");

#define TRY_ENTRY() try {
#define CATCH_ENTRY(location, return_val) } \
  catch(const std::exception& ex) \
{ \
    oxen::log::error(logcat, "Exception at [{}]: {}", location, ex.what()); \
  return return_val; \
}\
  catch(...)\
{\
    oxen::log::error(logcat, "Unknown exception at [{}]", location); \
  return return_val; \
}

#define ASSERT_MES_AND_THROW(...) do { \
    auto msg = fmt::format(__VA_ARGS__); \
    oxen::log::error(logcat, "{}", msg); \
    throw std::runtime_error{msg}; } while(0)
#define CHECK_AND_ASSERT_THROW_MES(expr, ...) do {if(!(expr)) ASSERT_MES_AND_THROW(__VA_ARGS__);} while(0)

#ifndef CHECK_AND_ASSERT
#define CHECK_AND_ASSERT(expr, fail_ret_val)   do{if(!(expr)){return fail_ret_val;};}while(0)
#endif

#ifndef CHECK_AND_ASSERT_MES
#define CHECK_AND_ASSERT_MES(expr, fail_ret_val, ...)   do{if(!(expr)) {oxen::log::error(logcat, __VA_ARGS__); return fail_ret_val;};}while(0)
#endif

enum console_colors
{
  console_color_default,
  console_color_white,
  console_color_red,
  console_color_green,
  console_color_blue,
  console_color_cyan,
  console_color_magenta,
  console_color_yellow
};

bool is_stdout_a_tty();
}
