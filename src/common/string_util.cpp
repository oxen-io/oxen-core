#include "string_util.h"

#include <fmt/core.h>

#include <cassert>

namespace tools {

using namespace std::literals;

std::vector<std::string_view> split(std::string_view str, const std::string_view delim, bool trim) {
    std::vector<std::string_view> results;
    // Special case for empty delimiter: splits on each character boundary:
    if (delim.empty()) {
        results.reserve(str.size());
        for (size_t i = 0; i < str.size(); i++)
            results.emplace_back(str.data() + i, 1);
        return results;
    }

    for (size_t pos = str.find(delim); pos != std::string_view::npos; pos = str.find(delim)) {
        if (!trim || !results.empty() || pos > 0)
            results.push_back(str.substr(0, pos));
        str.remove_prefix(pos + delim.size());
    }
    if (!trim || str.size())
        results.push_back(str);
    else
        while (!results.empty() && results.back().empty())
            results.pop_back();
    return results;
}

std::vector<std::string_view> split_any(
        std::string_view str, const std::string_view delims, bool trim) {
    if (delims.empty())
        return split(str, delims, trim);
    std::vector<std::string_view> results;
    for (size_t pos = str.find_first_of(delims); pos != std::string_view::npos;
         pos = str.find_first_of(delims)) {
        if (!trim || !results.empty() || pos > 0)
            results.push_back(str.substr(0, pos));
        size_t until = str.find_first_not_of(delims, pos + 1);
        if (until == std::string_view::npos)
            str.remove_prefix(str.size());
        else
            str.remove_prefix(until);
    }
    if (!trim || str.size())
        results.push_back(str);
    else
        while (!results.empty() && results.back().empty())
            results.pop_back();
    return results;
}

void trim(std::string_view& s) {
    constexpr auto simple_whitespace = " \t\r\n"sv;
    auto pos = s.find_first_not_of(simple_whitespace);
    if (pos == std::string_view::npos) {  // whole string is whitespace
        s.remove_prefix(s.size());
        return;
    }
    s.remove_prefix(pos);
    pos = s.find_last_not_of(simple_whitespace);
    assert(pos != std::string_view::npos);
    s.remove_suffix(s.size() - (pos + 1));
}

std::string lowercase_ascii_string(std::string_view src) {
    std::string result;
    result.reserve(src.size());
    for (char ch : src)
        result += ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch;
    return result;
}

std::string uppercase_ascii_string(std::string_view src) {
    std::string result;
    result.reserve(src.size());
    for (char ch : src)
        result += ch >= 'a' && ch <= 'z' ? ch - ('a' - 'A') : ch;
    return result;
}

std::string friendly_duration(std::chrono::nanoseconds dur) {
    std::string friendly;
    auto append = std::back_inserter(friendly);
    bool some = false;
    if (dur >= 24h) {
        fmt::format_to(append, "{}d", dur / 24h);
        dur %= 24h;
        some = true;
    }
    if (dur >= 1h || some) {
        fmt::format_to(append, "{}h", dur / 1h);
        dur %= 1h;
        some = true;
    }
    if (dur >= 1min || some) {
        fmt::format_to(append, "{}m", dur / 1min);
        dur %= 1min;
        some = true;
    }
    if (some || dur % 1s == 0ns) {
        // If we have >= minutes or its an integer number of seconds then don't bother with
        // fractional seconds
        fmt::format_to(append, "{}s", dur / 1s);
    } else {
        double seconds = std::chrono::duration<double>(dur).count();
        if (dur >= 1s)
            fmt::format_to(append, "{:.3f}s", seconds);
        else if (dur >= 1ms)
            fmt::format_to(append, "{:.3f}ms", seconds * 1000);
        else if (dur >= 1us)
            fmt::format_to(append, "{:.3f}µs", seconds * 1'000'000);
        else
            fmt::format_to(append, "{:.0f}ns", seconds * 1'000'000'000);
    }
    return friendly;
}

std::string_view string_safe_substr(std::string_view src, size_t pos, size_t size) noexcept {
    std::string_view result = std::string_view(src.end(), 0);
    if (pos < src.size()) {
        result = src.substr(pos, size);
    }
    return result;
}
}  // namespace tools
