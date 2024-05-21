#pragma once

#include <cstring>
#include <string_view>

#include "epee/span.h"  // epee

namespace tools {

/// Returns a string_view that views the data of the given object; this is not something you want to
/// do unless the struct is specifically design to be used this way.  The value must be a standard
/// layout type; it should really require is_trivial, too, but we have classes (like crypto keys)
/// that aren't C++-trivial but are still designed to be accessed this way.
template <typename T>
std::string_view view_guts(const T& val) {
    static_assert(
            (std::is_standard_layout_v<T> && std::has_unique_object_representations_v<T>) ||
                    epee::is_byte_spannable<T>,
            "cannot safely access non-trivial class as string_view");
    return {reinterpret_cast<const char*>(&val), sizeof(val)};
}

/// Convenience wrapper around the above that also copies the result into a new string
template <typename T>
std::string copy_guts(const T& val) {
    return std::string{view_guts(val)};
}

/// Function to reverse the above view_guts
template <typename T>
T make_from_guts(std::string_view s) {
    static_assert(
            (std::is_standard_layout_v<T> && std::has_unique_object_representations_v<T>) ||
                    epee::is_byte_spannable<T>,
            "cannot safely reconstitute a non-trivial class from data");
    if (s.size() != sizeof(T))
        throw std::runtime_error("Cannot reconstitute type: wrong type content size");
    T x;
    std::memcpy(static_cast<void*>(&x), s.data(), sizeof(T));
    return x;
}

}  // namespace tools
