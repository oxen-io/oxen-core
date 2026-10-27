#pragma once

#include <oxenc/common.h>

#include <span>
#include <string_view>

namespace epee
{
  /// Views the bytes of a string as a span of some other byte-sized type.
  template<oxenc::basic_char T>
  std::span<const T> strspan(std::string_view s) noexcept
  {
    return {reinterpret_cast<const T*>(s.data()), s.size()};
  }
}
