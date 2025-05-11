#pragma once

#include <fmt/core.h>
#include <fmt/format.h>
#include <oxenc/base32z.h>
#include <oxenc/base64.h>
#include <oxenc/hex.h>

#include <concepts>
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
// For instance to opt-in MyType for such string formatting, either specialize via_to_string with a
// true value:
//
//     template <> inline constexpr bool formattable::via_to_string<MyType> = true;
//
// or have a `static constexpr bool to_string_formattable = true;` in the class.
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
    concept callable_to_string_method = requires(const T v) {
        { v.to_string() } -> std::convertible_to<std::string_view>;
    };
    template <typename T>
    concept callable_to_hex_string_method = requires(const T v) {
        { v.to_hex_string() } -> std::convertible_to<std::string_view>;
    };

    template <typename T>
    concept static_member_to_string_formattable =
            T::to_string_formattable && callable_to_string_method<T>;

}  // namespace detail

template <typename T>
struct to_string_formatter : fmt::formatter<std::string_view> {
    auto format(const T& val, fmt::format_context& ctx) const {
        if constexpr (::formattable::detail::callable_to_string_method<T>)
            return formatter<std::string_view>::format(val.to_string(), ctx);
        else
            return formatter<std::string_view>::format(to_string(val), ctx);
    }
};

// fmt-compatible formatter for things like pubkeys that have a .data() and .size(); we permit them
// to be formatted using a format of `{:x}`, `{:z}`, `{:a}`, `{:b}`, or `{:r}` where `x` means the
// full hex byte value, `z` means the hex value without leading 0's, `:a` is base32z, `:b` is
// base64, and `:r` means output raw bytes.  If no format string is given at all (i.e. just "{}")
// then the format is (by default) equivalent to `{:x}`, i.e. we return the full hex value, but some
// types override that -- for example, eth::address's default format is `0xaBc...` rather than
// `abc...`.
//
// Width and precision formats can be used to ellipsize the value, where width is the number of
// output characters in total (including the single ellipsis character) and precision is the number
// of characters after the ellipsis.  For instance, {:10.2x} would produce "abcdef1…89".  When
// ellipsizing, you must specify at least width and '.'; omitting the trailing width is the same as
// specifying 0 (which means: do not include any trailing value).  Width must be at least 2, and at
// least 2 larger than the trailing char size.
//
// Other flags (such as alignment and fill), and width without precision, are not currently
// supported, but are also less useful as this is generally used with fixed-width types (and so
// alignment and fill characters can easily be put into the format string itself).
//
// For example, for input span \0\0\0\0\0\0\0\x02 `fmt::format("0x{0:z} 0x{0:9.4x} {0}", val)` would
// produce the string `"0x2 0x0000…0002 0000000000000002"`.
struct hex_span_formatter {
  protected:
    enum class output { default_, full_hex, stripped_hex, b32z, b64, raw };
    output mode = output::default_;
    bool ellipsis = false;
    int ellipsis_width = -1, ellipsis_tail = -1;

  public:
    constexpr fmt::format_parse_context::iterator parse(fmt::format_parse_context& ctx) {
        mode = output::default_;

        auto it = ctx.begin();
        for (; it != ctx.end(); ++it) {
            char c = *it;
            if (c == '}')
                break;
            switch (c) {
                case 'x': mode = output::full_hex; break;
                case 'z': mode = output::stripped_hex; break;
                case 'r': mode = output::raw; break;
                case 'a': mode = output::b32z; break;
                case 'b': mode = output::b64; break;
                case '0':
                    if (!ellipsis && !ellipsis_width)
                        throw fmt::format_error{
                                "invalid format for hex-formattable value: 0-fill not currently "
                                "supported"};
                    [[fallthrough]];
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9': {
                    auto& v = ellipsis ? ellipsis_tail : ellipsis_width;
                    v = (v == -1 ? 0 : v) * 10 + (c - '0');
                    break;
                }
                case '.':
                    if (!ellipsis && ellipsis_width >= 2) {
                        ellipsis = true;
                        break;
                    } else
                        [[fallthrough]];
                default: throw fmt::format_error{"invalid format type for hex-formattable value"};
            }

            // If we found a mode then that should be terminal, i.e. immediately followed by '}':
            if (mode != output::default_) {
                if (++it == ctx.end() || *it != '}')
                    throw fmt::format_error{"invalid format for hex-formattable value"};
                break;
            }
        }

        if (ellipsis) {
            if (ellipsis_tail < 0)
                throw fmt::format_error{
                        "invalid ellipsis format for hex-formattable value: "
                        "missing ellipsis suffix length"};
            if (ellipsis_tail > ellipsis_width - 2)
                throw fmt::format_error{
                        "invalid ellipsis format for hex-formattable value: "
                        "ellipsis suffix too long"};
        } else if (ellipsis_width > 0)
            throw fmt::format_error{
                    "invalid format for hex-formattable value: width without ellipsizing precision "
                    "is not currently supported"};

        return it;
    }

    // Called to produce a default format; subclasses can override to change the default.
    virtual fmt::format_context::iterator default_format(
            std::span<const unsigned char> val, fmt::format_context::iterator& out) const {
        return oxenc::to_hex(val.begin(), val.end(), out);
    }

    auto format(std::span<const unsigned char> val, fmt::format_context& ctx) const {
        fmt::memory_buffer buf;

        auto out = ellipsis ? fmt::appender(buf) : ctx.out();

        using namespace fmt;
        auto it = val.begin();
        if (mode == output::default_)
            out = default_format(val, out);
        else if (mode == output::raw)
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

        if (!ellipsis)
            return out;

        assert(ellipsis_tail >= 0);
        assert(ellipsis_width >= ellipsis_tail + 2);
        std::string_view full{buf.data(), buf.size()};
        auto final_out = ctx.out();
        if (full.size() <= static_cast<size_t>(ellipsis_width))
            std::copy(full.begin(), full.end(), final_out);
        else {
            std::copy(full.begin(), full.begin() + (ellipsis_width - 1 - ellipsis_tail), final_out);
            constexpr std::string_view ellipsis{"…"};
            std::copy(ellipsis.begin(), ellipsis.end(), final_out);
            std::copy(full.begin() + (full.size() - ellipsis_tail), full.end(), final_out);
        }
        return final_out;
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
    auto format(const T& val, fmt::format_context& ctx) const {
        using Underlying = std::underlying_type_t<T>;
        return fmt::formatter<Underlying>::format(static_cast<Underlying>(val), ctx);
    }
};

}  // namespace formattable

namespace fmt {

template <typename T, typename Char>
    requires ::formattable::via_to_string<T> ||
             ::formattable::detail::static_member_to_string_formattable<T>
struct formatter<T, Char> : ::formattable::to_string_formatter<T> {};

template <typename T, typename Char>
    requires ::formattable::via_underlying<T>
struct formatter<T, Char> : ::formattable::underlying_t_formatter<T> {};

}  // namespace fmt
