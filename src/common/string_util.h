#pragma once
#include <fmt/format.h>

#include <charconv>
#include <chrono>
#include <concepts>
#include <cstring>
#include <iterator>
#include <string_view>
#include <vector>

#include "basic_char.h"

namespace tools {

using namespace std::literals;

/// Returns true if the first string is equal to the second string, compared case-insensitively.
inline bool string_iequal(std::string_view s1, std::string_view s2) {
    return std::equal(s1.begin(), s1.end(), s2.begin(), s2.end(), [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) ==
               std::tolower(static_cast<unsigned char>(b));
    });
}

/// Returns true if the first string matches any of the given strings case-insensitively.  Arguments
/// must be string literals, std::string, or std::string_views
template <typename S1, typename... S>
bool string_iequal_any(const S1& s1, const S&... s) {
    return (... || string_iequal(s1, s));
}

/// Splits a string on some delimiter string and returns a vector of string_view's pointing into the
/// pieces of the original string.  The pieces are valid only as long as the original string remains
/// valid.  Leading and trailing empty substrings are not removed.  If delim is empty you get back a
/// vector of string_views each viewing one character.  If `trim` is true then leading and trailing
/// empty values will be suppressed.
///
///     auto v = split("ab--c----de", "--"); // v is {"ab", "c", "", "de"}
///     auto v = split("abc", ""); // v is {"a", "b", "c"}
///     auto v = split("abc", "c"); // v is {"ab", ""}
///     auto v = split("abc", "c", true); // v is {"ab"}
///     auto v = split("-a--b--", "-"); // v is {"", "a", "", "b", "", ""}
///     auto v = split("-a--b--", "-", true); // v is {"a", "", "b"}
///
std::vector<std::string_view> split(
        std::string_view str, std::string_view delim, bool trim = false);

/// Splits a string on any 1 or more of the given delimiter characters and returns a vector of
/// string_view's pointing into the pieces of the original string.  If delims is empty this works
/// the same as split().  `trim` works like split (suppresses leading and trailing empty string
/// pieces).
///
///     auto v = split_any("abcdedf", "dcx"); // v is {"ab", "e", "f"}
std::vector<std::string_view> split_any(
        std::string_view str, std::string_view delims, bool trim = false);

/// Joins [begin, end) with a delimiter and returns the resulting string.  Elements can be anything
/// that can be formatted.  Semi-deprecated: this just uses fmt to join.
template <typename It>
std::string join(std::string_view delimiter, It begin, It end) {
    return fmt::format("{}", fmt::join(begin, end, delimiter));
}

/// Same as the above, but works on a container.  Just use fmt::join.
template <typename Container>
std::string join(std::string_view delimiter, const Container& c) {
    return fmt::format("{}", fmt::join(c, delimiter));
}

/// Similar to join(), but first applies a transformation to each element.
template <typename It, typename UnaryOperation>
std::string join_transform(std::string_view delimiter, It begin, It end, UnaryOperation transform) {
    std::string result;
    auto append = std::back_inserter(result);
    if (begin != end)
        result = fmt::format("{}", transform(*begin++));
    while (begin != end)
        fmt::format_to(append, "{}{}", delimiter, transform(*begin++));
    return result;
}

/// Wrapper around the above that takes a container and passes c.begin(), c.end().
template <typename Container, typename UnaryOperation>
std::string join_transform(
        std::string_view delimiter, const Container& c, UnaryOperation&& transform) {
    return join_transform(delimiter, c.begin(), c.end(), std::forward<UnaryOperation>(transform));
}

/// Concatenates a bunch of random values together with delim as a separator via fmt::format.
/// Returns the result as a string.
template <typename T, typename... Ts>
std::string join_stuff(std::string_view delim, T&& first, Ts&&... stuff) {
    std::string result = fmt::format(std::forward<T>(first));
    auto append = std::back_inserter(result);
    (fmt::format_to(append, "{}{}", delim, std::forward<Ts>(stuff)), ...);
    return result;
}

/// Concatenates arguments via fmt::format operator, returns as a string.
template <typename... T>
std::string concat(T&&... stuff) {
    std::string result;
    auto append = std::back_inserter(result);
    (fmt::format_to(append, "{}", std::forward<T>(stuff)), ...);
    return result;
}

/// Simple version of whitespace trimming: mutates the given string view to remove leading
/// space, \t, \r, \n.  (More exotic and locale-dependent whitespace is not removed).
void trim(std::string_view& s);

/// Parses an integer of some sort from a string, requiring that the entire string be consumed
/// during parsing.  Return false if parsing failed, sets `value` and returns true if the entire
/// string was consumed.
template <typename T>
bool parse_int(const std::string_view str, T& value, int base = 10) {
    T tmp;
    auto* strend = str.data() + str.size();
    auto [p, ec] = std::from_chars(str.data(), strend, tmp, base);
    if (ec != std::errc() || p != strend)
        return false;
    value = tmp;
    return true;
}

std::string lowercase_ascii_string(std::string_view src);

// Converts between basic_string_view<T> for different 1-byte T values
template <basic_char To, basic_char From>
std::basic_string_view<To> convert_sv(std::basic_string_view<From> from) {
    return {reinterpret_cast<const To*>(from.data()), from.size()};
}
// Same as above, but converting from a string rather than view.
template <basic_char To, basic_char From>
std::basic_string_view<To> convert_sv(const std::basic_string<From>& from) {
    return {reinterpret_cast<const To*>(from.data()), from.size()};
}

// Same as above, but makes a copy into a basic_string
template <basic_char To, basic_char From>
std::basic_string<To> convert_str(std::basic_string_view<From> from) {
    return {reinterpret_cast<const To*>(from.data()), from.size()};
}
// Same as above, but converting from a string rather than view.
template <basic_char To, basic_char From>
std::basic_string<To> convert_str(const std::basic_string<From>& from) {
    return {reinterpret_cast<const To*>(from.data()), from.size()};
}

/// Converts a duration into a human friendlier string, such as "3d7d47m12s" or "347µs"
std::string friendly_duration(std::chrono::nanoseconds dur);

/// Converts a duration into a shorter, single-unit fractional display such as `42.3min`
std::string short_duration(std::chrono::duration<double> dur);

/// Given an array of string arguments, look for strings of the format <prefix><value> and return
/// <value> Returns empty string view if not found.
template <typename It>
    requires std::convertible_to<std::iter_reference_t<It>, std::string_view>
std::string_view find_prefixed_value(It begin, It end, std::string_view prefix) {
    auto it = std::find_if(begin, end, [&](const auto& s) { return s.starts_with(prefix); });
    if (it == end)
        return {};
    return std::string_view{*it}.substr(prefix.size());
}
}  // namespace tools
