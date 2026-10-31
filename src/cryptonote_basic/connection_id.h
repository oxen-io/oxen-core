#pragma once

#include <fmt/ranges.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <functional>
#include <string>

namespace cryptonote {

// Identifies a p2p connection (only locally: it's never sent anywhere).
struct connection_id_t : std::array<unsigned char, 16> {
    // Makes a random connection id.  *NOT* cryptographically secure random.
    static connection_id_t random();

    constexpr bool is_nil() const {
        return std::all_of(begin(), end(), [](auto x) { return x == 0; });
    }

    // Returns the id in uuid form, e.g. 00112233-4455-6677-8899-101112131415
    std::string to_string() const;
    static constexpr bool to_string_formattable = true;
};

}  // namespace cryptonote

// connection_id_t is a std::array, which fmt would otherwise also consider formattable as a range,
// making it ambiguous with its to_string formatting.
template <typename T, typename Char>
    requires std::same_as<std::remove_cv_t<T>, cryptonote::connection_id_t>
struct fmt::is_range<T, Char> {
    static constexpr bool value = false;
};

template <>
struct std::hash<cryptonote::connection_id_t> {
    size_t operator()(const cryptonote::connection_id_t& id) const {
        constexpr size_t inverse_golden_ratio =
                sizeof(size_t) >= 8 ? 0x9e37'79b9'7f4a'7c15 : 0x9e37'79b9;

        uint64_t a, b;
        std::memcpy(&a, id.data(), 8);
        std::memcpy(&b, id.data() + 8, 8);
        auto h = hash<uint64_t>{}(a);
        return hash<uint64_t>{}(b) + inverse_golden_ratio + (h << 6) + (h >> 2);
    }
};
