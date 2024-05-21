#pragma once
#include <oxenc/hex.h>

#include <type_traits>

#include "epee/span.h"  // epee

namespace tools {

template <typename T>
concept convertible_from_hex =
        !std::is_const_v<T> && (std::is_trivially_copyable_v<T> || epee::is_byte_spannable<T>);

template <typename T>
concept convertible_to_hex =
        (std::is_standard_layout_v<T> && std::has_unique_object_representations_v<T>) ||
        epee::is_byte_spannable<T>;

// Reads a hex string directly into a trivially copyable type T without performing any temporary
// allocation.  Returns false if the given string is not hex or does not match T in length,
// otherwise copies directly into `x` and returns true.
template <convertible_from_hex T>
bool hex_to_type(std::string_view hex, T& x) {
    if (!oxenc::is_hex(hex) || hex.size() != 2 * sizeof(T))
        return false;
    oxenc::from_hex(hex.begin(), hex.end(), reinterpret_cast<char*>(&x));
    return true;
}

/// Converts a standard layout, padding-free type into a hex string of its contents.
template <convertible_to_hex T>
std::string type_to_hex(const T& val) {
    return oxenc::to_hex(std::string_view{reinterpret_cast<const char*>(&val), sizeof(val)});
}
}  // namespace tools
