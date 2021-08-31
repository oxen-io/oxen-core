#pragma once

#include <cstddef>
#include <string_view>

#include "keys.hpp"

namespace wallet
{

  class DBKeys : public Keys
  {
    using bytestring_view = std::basic_string_view<std::byte>;

  public:

    DBKeys();
  };

} // namespace wallet
