#pragma once
#include <string_view>
#include <vector>
#include <cstring>
#include <iterator>
#include <charconv>
#include <sstream>
#include <chrono>
#include "epee/span.h" // epee

namespace tools {

using namespace std::literals;

/// Returns true if the first string is equal to the second string, compared case-insensitively.
inline bool string_iequal(std::string_view s1, std::string_view s2) {
  return std::equal(s1.begin(), s1.end(), s2.begin(), s2.end(), [](char a, char b) {
      return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b)); });
}

/// Returns true if the first string matches any of the given strings case-insensitively.  Arguments
/// must be string literals, std::string, or std::string_views
template <typename S1, typename... S>
bool string_iequal_any(const S1& s1, const S&... s) {
  return (... || string_iequal(s1, s));
}

/// Returns true if the first argument begins with the second argument
inline bool starts_with(std::string_view str, std::string_view prefix) {
  return str.substr(0, prefix.size()) == prefix;
}

/// Returns true if the first argument ends with the second argument
inline bool ends_with(std::string_view str, std::string_view suffix) {
  return str.size() >= suffix.size() && str.substr(str.size() - suffix.size()) == suffix;
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
std::vector<std::string_view> split(std::string_view str, std::string_view delim, bool trim = false);

/// Splits a string on any 1 or more of the given delimiter characters and returns a vector of
/// string_view's pointing into the pieces of the original string.  If delims is empty this works
/// the same as split().  `trim` works like split (suppresses leading and trailing empty string
/// pieces).
///
///     auto v = split_any("abcdedf", "dcx"); // v is {"ab", "e", "f"}
std::vector<std::string_view> split_any(std::string_view str, std::string_view delims, bool trim = false);

/// Joins [begin, end) with a delimiter and returns the resulting string.  Elements can be anything
/// that can be sent to an ostream via `<<`.
template <typename It>
std::string join(std::string_view delimiter, It begin, It end) {
    std::ostringstream o;
    if (begin != end)
        o << *begin++;
    while (begin != end)
        o << delimiter << *begin++;
    return o.str();
}

/// Wrapper around the above that takes a container and passes c.begin(), c.end() to the above.
template <typename Container>
std::string join(std::string_view delimiter, const Container& c) { return join(delimiter, c.begin(), c.end()); }

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

/// Returns a string_view that views the data of the given object; this is not something you want to
/// do unless the struct is specifically design to be used this way.  The value must be a standard
/// layout type; it should really require is_trivial, too, but we have classes (like crypto keys)
/// that aren't C++-trivial but are still designed to be accessed this way.
template <typename T>
std::string_view view_guts(const T& val) {
    static_assert((std::is_standard_layout_v<T> && std::has_unique_object_representations_v<T>)
        || epee::is_byte_spannable<T>,
        "cannot safely access non-trivial class as string_view");
    return {reinterpret_cast<const char *>(&val), sizeof(val)};
}

/// Convenience wrapper around the above that also copies the result into a new string
template <typename T>
std::string copy_guts(const T& val) {
  return std::string{view_guts(val)};
}

/// Function to reverse the above view_guts
template <typename T>
T make_from_guts(std::string_view s) {
    static_assert((std::is_standard_layout_v<T> && std::has_unique_object_representations_v<T>)
        || epee::is_byte_spannable<T>,
        "cannot safely reconstitute a non-trivial class from data");
    if (s.size() != sizeof(T))
        throw std::runtime_error("Cannot reconstitute type: wrong type content size");
    T x;
    std::memcpy(&x, s.data(), sizeof(T));
    return x;
}

std::string lowercase_ascii_string(std::string_view src);

/// Converts a duration into a human friendlier string, such as "3d7d47m12s" or "347µs"
std::string friendly_duration(std::chrono::nanoseconds dur);

/// Converts a duration into a shorter, single-unit fractional display such as `42.3min`
std::string short_duration(std::chrono::duration<double> dur);

/// Given an array of string arguments, look for strings of the format <prefix><value> and return <value>
/// Returns empty string view if not found.
template <typename It>
std::string_view find_prefixed_value(It begin, It end, std::string_view prefix)
{
  auto it = std::find_if(begin, end, [&](const auto& s) { return starts_with(s, prefix); });
  if (it == end) return {};
  return std::string_view{*it}.substr(prefix.size());
}
}
