#pragma once

#include <cstdint>
#include <utility>

namespace cryptonote::rpc {

using version_t = std::pair<uint16_t, uint16_t>;

/// Makes a version array from a packed 32-bit integer version
constexpr version_t make_version(uint32_t version) {
    return {static_cast<uint16_t>(version >> 16), static_cast<uint16_t>(version & 0xffff)};
}
/// Packs a version array into a packed 32-bit integer version
constexpr uint32_t pack_version(version_t version) {
    return (uint32_t(version.first) << 16) | version.second;
}

}  // namespace cryptonote::rpc
