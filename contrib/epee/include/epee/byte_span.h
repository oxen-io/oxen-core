#pragma once

#include <oxenc/common.h>

#include <span>
#include <string_view>
#include <type_traits>

namespace epee
{
  /// True if a T can be viewed and copied as raw bytes.  Wrapper types whose own representation
  /// isn't unique but whose contents are byte-spannable (e.g. tools::scrubbed<T>) specialize this.
  template<typename T>
  constexpr bool is_byte_spannable = std::has_unique_object_representations_v<T>;

  /// Views the bytes of a string as a span of some other byte-sized type.
  template<oxenc::basic_char T>
  std::span<const T> strspan(std::string_view s) noexcept
  {
    return {reinterpret_cast<const T*>(s.data()), s.size()};
  }
}
