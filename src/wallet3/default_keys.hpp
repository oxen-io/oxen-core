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

    DBKeys() = delete;

    DBKeys(std::function<bytestring_view()> private_spendkey_cb = nullptr,
           bytestring_view public_spend_key,
           bytestring_view private_view_key,
           bytestring_view private_spend_key);

  private:

    std::function<bytestring_view()> GetSpendKey;

} // namespace wallet
