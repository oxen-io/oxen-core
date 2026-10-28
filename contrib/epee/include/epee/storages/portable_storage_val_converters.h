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

#include <type_traits>
#include <charconv>
#include <utility>

#include "portable_storage_base.h"

namespace epee
{
  namespace serialization
  {
#define ASSERT_AND_THROW_WRONG_CONVERSION() do { \
      auto msg = fmt::format("WRONG DATA CONVERSION: {} to {}", typeid(from).name(), typeid(to).name()); \
      oxen::log::error(logcat, "{}", msg); \
      throw std::runtime_error{msg}; } while (0)

    template<typename From, typename To, typename SFINAE = void>
    struct converter
    {
      void operator()(const From& from, To& to)
      {
        ASSERT_AND_THROW_WRONG_CONVERSION();
      }
    };

    template<typename From, typename To>
    struct converter<From, To, std::enable_if_t<
      !std::is_same_v<To, From> && std::is_integral_v<To> && std::is_integral_v<From> &&
      !std::is_same_v<From, bool> && !std::is_same_v<To, bool>>>
    {
      void operator()(const From& from, To& to)
      {
        if (!(std::in_range<To>(from))) {
          auto msg = fmt::format("int value overflow: cannot convert value {} to integer type with range [{}, {}]", +from, +std::numeric_limits<To>::min(), +std::numeric_limits<To>::max());
          oxen::log::error(logcat, "{}", msg);
          throw std::runtime_error{msg};
        }
        to = static_cast<To>(from);
      }
    };

    // Accepts amounts given as numeric strings, which JSON clients sometimes send to avoid
    // precision loss in languages without 64-bit integers.
    template<>
    struct converter<std::string, uint64_t>
    {
      void operator()(const std::string& from, uint64_t& to)
      {
        const auto* strend = from.data() + from.size();
        if (auto [p, ec] = std::from_chars(from.data(), strend, to); ec == std::errc{} && p == strend)
          return;
        ASSERT_AND_THROW_WRONG_CONVERSION();
      }
    };

    template<typename From, typename To>
    struct converter<From, To, std::enable_if_t<std::is_same<To, From>::value>>
    {
      void operator()(const From& from, To& to)
      {
        to = from;
      }
    };

    template<class From, class To>
    void convert_t(const From& from, To& to)
    {
      converter<From, To>{}(from, to);
    }
  }
}
