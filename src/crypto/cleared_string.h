#pragma once

#include <cstring>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "cleared.h"

namespace crypto {

/// A string of secret characters (a password, a mnemonic seed) whose characters are zeroed when it
/// lets go of them: when its buffer is freed or reallocated, and when it shrinks.  Unlike a
/// std::string with a clearing allocator, it never keeps characters inside the object itself,
/// where the small string optimization would leave them unzeroed.
class cleared_string {
  public:
    using value_type = char;

    cleared_string() = default;
    cleared_string(std::string_view s) : buffer{s.begin(), s.end()} {}
    cleared_string(const char* s) : cleared_string{std::string_view{s}} {}
    cleared_string(const char* s, size_t len) : cleared_string{std::string_view{s, len}} {}
    cleared_string(const std::string& s) : cleared_string{std::string_view{s}} {}
    /// Copies, then zeroes, the given string's characters.
    cleared_string(std::string&& s);

    const char* data() const noexcept { return buffer.data(); }
    char* data() noexcept { return buffer.data(); }
    size_t size() const noexcept { return buffer.size(); }
    size_t length() const noexcept { return buffer.size(); }
    bool empty() const noexcept { return buffer.empty(); }
    std::string_view view() const noexcept { return {data(), size()}; }

    void push_back(char c) { buffer.push_back(c); }
    void append(const char* ptr, size_t len) { buffer.insert(buffer.end(), ptr, ptr + len); }
    cleared_string& operator+=(char c) {
        push_back(c);
        return *this;
    }
    cleared_string& operator+=(std::string_view s) {
        append(s.data(), s.size());
        return *this;
    }
    cleared_string& operator+=(const cleared_string& s) { return *this += s.view(); }
    cleared_string& operator+=(const char* s) { return *this += std::string_view{s}; }
    cleared_string& operator+=(const std::string& s) { return *this += std::string_view{s}; }

    /// Removes and returns the last character; throws if empty.
    char pop_back();
    void resize(size_t size);
    void reserve(size_t size) { buffer.reserve(size); }
    void clear() { resize(0); }

    /// Removes leading and trailing spaces.
    void trim();
    /// Splits into the words separated by whitespace.
    std::vector<cleared_string> split() const;
    /// Decodes a hex string, or returns nullopt if it isn't one.
    std::optional<cleared_string> parse_hexstr() const;
    /// Decodes a hex string into `pod`, returning false (leaving `pod` unchanged) if it isn't hex
    /// of exactly the right size.
    template <typename T>
        requires std::is_trivially_copyable_v<T>
    bool hex_to_pod(T& pod) const {
        if (size() != sizeof(T) * 2)
            return false;
        auto blob = parse_hexstr();
        if (!blob)
            return false;
        std::memcpy(&pod, blob->data(), sizeof(T));
        return true;
    }

    bool operator==(const cleared_string& other) const noexcept { return buffer == other.buffer; }

  private:
    cleared_vector<char> buffer;
};

}  // namespace crypto

template <>
struct std::hash<crypto::cleared_string> {
    size_t operator()(const crypto::cleared_string& s) const {
        return std::hash<std::string_view>{}(s.view());
    }
};
