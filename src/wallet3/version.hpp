#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace wallet {
// Given a full wallet version of: wallet-1.2.3-abc these are:
extern const std::array<uint16_t, 3> VERSION;  // [1, 2, 3]
extern const std::string_view VERSION_STR;     // "1.2.3"
extern const std::string_view VERSION_TAG;     // "abc"
extern const std::string_view VERSION_FULL;    // "wallet-1.2.3-abc"
}  // namespace wallet
