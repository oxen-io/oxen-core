#include "cleared_string.h"

#include <oxenc/hex.h>

#include <cctype>
#include <stdexcept>

namespace crypto {

cleared_string::cleared_string(std::string&& s) : cleared_string{std::string_view{s}} {
    sodium_zero_buffer(s.data(), s.size());
    s.clear();
}

char cleared_string::pop_back() {
    if (empty())
        throw std::runtime_error{"Popping from an empty string"};
    const char c = buffer.back();
    resize(size() - 1);
    return c;
}

void cleared_string::resize(size_t size) {
    // The characters dropped stay in the buffer's capacity, so they're zeroed now, rather than
    // when the buffer is eventually freed.
    if (size < buffer.size())
        sodium_zero_buffer(buffer.data() + size, buffer.size() - size);
    buffer.resize(size);
}

void cleared_string::trim() {
    const auto v = view();
    const size_t start = v.find_first_not_of(' ');
    if (start == std::string_view::npos)
        return clear();
    const size_t end = v.find_last_not_of(' ') + 1;
    if (start > 0)
        std::memmove(buffer.data(), buffer.data() + start, end - start);
    resize(end - start);
}

std::vector<cleared_string> cleared_string::split() const {
    std::vector<cleared_string> fields;
    bool space = true;
    for (char c : buffer) {
        const bool space_prev = space;
        space = std::isspace(static_cast<unsigned char>(c));
        if (!space) {
            if (space_prev)
                fields.emplace_back();
            fields.back().push_back(c);
        }
    }
    return fields;
}

std::optional<cleared_string> cleared_string::parse_hexstr() const {
    if (!oxenc::is_hex(view()))
        return std::nullopt;
    std::optional<cleared_string> res{std::in_place};
    res->buffer.resize(size() / 2);
    oxenc::from_hex(buffer.begin(), buffer.end(), res->buffer.begin());
    return res;
}

}  // namespace crypto
