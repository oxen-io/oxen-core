#pragma once

#include <fmt/core.h>
#include <fmt/format.h>
#include <oxenc/base32z.h>
#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <span>
#include <string_view>
#include <type_traits>

namespace formattable {

// Types can opt-in to being formattable as a string by specializing this to true.  Such a type
// must have one of:
//
// - a `to_string()` method on the type; when formatted we will call `val.to_string()` to format
//   it as a string.
// - a `to_string(val)` function in the same namespace as the type; we will call it to format it
//   as a string.
//
// The function should return something string-like (string, string_view, const char*).
//
// For instance to opt-in MyType for such string formatting, use:
//
//     template <> inline constexpr bool formattable::via_to_string<MyType> = true;
//
// You can also partially specialize via concepts; for instance to make all derived classes of a
// common base type formattable via to_string you could do:
//
//     template <std::derived_from<MyBaseType> T>
//     inline constexpr bool formattable::via_to_string<T> = true;
//
template <typename T>
constexpr bool via_to_string = false;

// Scoped enums can alternatively be formatted as their underlying integer value by specializing
// this function to true:
template <typename T>
constexpr bool via_underlying = false;

namespace detail {

    template <typename T>
    concept callable_to_string_method = requires(T v) { v.to_string(); };
    template <typename T>
    concept callable_to_hex_string_method = requires(T v) { v.to_hex_string(); };

}  // namespace detail

template <typename T>
struct to_string_formatter : fmt::formatter<std::string_view> {
    template <typename FormatContext>
    auto format(const T& val, FormatContext& ctx) const {
        if constexpr (::formattable::detail::callable_to_string_method<T>)
            return formatter<std::string_view>::format(val.to_string(), ctx);
        else
            return formatter<std::string_view>::format(to_string(val), ctx);
    }
};

// fmt-compatible formatter for things like pubkeys that have a .data() and .size(); if printed bare
// (i.e. "{}") then these get output as `<00000000000000000123456789abcdef>`, but we also permit
// them to be formatted using a format of `{:x}`, `{:z}`, `{:a}`, `{:b}`, or `{:r}` where `x` means
// the full hex byte value, `z` means the hex value without leading 0's, `:a` is base32z, `:b` is
// base64, and `:r` means output raw bytes.  If no format string is given at all (i.e. just "{}")
// then the format is equivalent to `{:x}`, i.e. we return the full hex value.  Other flags (such as
// alignment, fill, width) are not currently supported.
//
// For example, for input span \0\0\0\0\0\0\0\x02 `fmt::format("0x{:z} 0x{:x} {}", val)` would
// produced the string `"0x2 0x0000000000000002 0000000000000002"`.
//
// Some types extend this to override the default format -- for example, eth::address's
// default format is `0xabc...` rather than `abc...`.
struct hex_span_formatter {
  protected:
    enum class output { default_, full_hex, stripped_hex, b32z, b64, raw };
    output mode = output::default_;

  public:
    constexpr fmt::format_parse_context::iterator parse(fmt::format_parse_context& ctx) {
        auto it = ctx.begin();
        const auto end = ctx.end();
        mode = output::default_;

        if (it == end)
            return it;
        char c = *it;
        switch (c) {
            case '}': return it;
            case 'x': mode = output::full_hex; break;
            case 'z': mode = output::stripped_hex; break;
            case 'r': mode = output::raw; break;
            case 'a': mode = output::b32z; break;
            case 'b': mode = output::b64; break;
            default: throw fmt::format_error{"invalid format type for hex-formattable value"};
        }
        if (++it != end && *it != '}')
            throw fmt::format_error{"invalid format for hex-formattable value"};

        return it;
    }

    // Called to produce a default format; subclasses can override to change the default.
    virtual fmt::format_context::iterator default_format(
            std::span<const unsigned char> val, fmt::format_context& ctx) const {
        auto out = ctx.out();
        out = oxenc::to_hex(val.begin(), val.end(), out);
        return out;
    }

    auto format(std::span<const unsigned char> val, fmt::format_context& ctx) const {
        if (mode == output::default_)
            return default_format(val, ctx);

        using namespace fmt;
        auto out = ctx.out();
        auto it = val.begin();
        if (mode == output::raw)
            out = std::copy(it, val.end(), out);
        else if (mode == output::b64)
            out = oxenc::to_base64(it, val.end(), out);
        else if (mode == output::b32z)
            out = oxenc::to_base32z(it, val.end(), out);
        else {
            if (mode == output::stripped_hex) {
                // Skip leading 0 bytes:
                while (it != val.end() && *it == 0)
                    ++it;
                // If it's *all* 0s we just write a single 0:
                if (it == val.end())
                    *out++ = '0';
                else {
                    // If the first value is going to be 0X then we want to skip the 0 and start
                    // directly with the X
                    if (*it < 16) {
                        char hexpair[2];
                        oxenc::to_hex(it, it + 1, hexpair);
                        assert(hexpair[0] == '0');
                        *out++ = hexpair[1];
                        ++it;
                    }
                }
            }
            // Anything else is regular hex byte encoding:
            out = oxenc::to_hex(it, val.end(), out);
        }
        return out;
    }
    auto format(std::span<const char> val, fmt::format_context& ctx) const {
        return format(
                std::span<const unsigned char>{
                        reinterpret_cast<const unsigned char*>(val.data()), val.size()},
                ctx);
    }
    auto format(std::span<const std::byte> val, fmt::format_context& ctx) const {
        return format(
                std::span<const unsigned char>{
                        reinterpret_cast<const unsigned char*>(val.data()), val.size()},
                ctx);
    }
};

template <typename T>
struct underlying_t_formatter : fmt::formatter<std::underlying_type_t<T>> {
#ifdef __cpp_lib_is_scoped_enum  // C++23
    static_assert(std::is_scoped_enum_v<T>);
#else
    static_assert(
            std::is_enum_v<T> && !std::is_convertible_v<T, std::underlying_type_t<T>>,
            "formattable::via_underlying<T> type is not a scoped enum");
#endif
    template <typename FormatContext>
    auto format(const T& val, FormatContext& ctx) const {
        using Underlying = std::underlying_type_t<T>;
        return fmt::formatter<Underlying>::format(static_cast<Underlying>(val), ctx);
    }
};

}  // namespace formattable

namespace fmt {

template <typename T, typename Char>
    requires ::formattable::via_to_string<T>
struct formatter<T, Char> : ::formattable::to_string_formatter<T> {};

template <typename T, typename Char>
    requires ::formattable::via_underlying<T>
struct formatter<T, Char> : ::formattable::underlying_t_formatter<T> {};

}  // namespace fmt
