#pragma once

#include <oxenc/endian.h>

#include <cstring>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <string_view>

// A levin_kv message as JSON, read as epee read one (into a tree of the values as sent, whatever
// their order or integer types), and apart from levin_kv's own reader: so that tests can check
// that two messages say the same things.
namespace levin_kv_test {

namespace detail {
    struct cursor {
        std::string_view data;

        std::string_view take(size_t n) {
            if (n > data.size())
                throw std::runtime_error{"truncated levin_kv message"};
            auto s = data.substr(0, n);
            data.remove_prefix(n);
            return s;
        }

        template <typename T>
        T fixed() {
            T v;
            std::memcpy(&v, take(sizeof(T)).data(), sizeof(T));
            return oxenc::little_to_host(v);
        }

        uint64_t varint() {
            if (data.empty())
                throw std::runtime_error{"truncated levin_kv message"};
            switch (static_cast<uint8_t>(data[0]) & 0b11) {
                case 0: return fixed<uint8_t>() >> 2;
                case 1: return fixed<uint16_t>() >> 2;
                case 2: return fixed<uint32_t>() >> 2;
                default: return fixed<uint64_t>() >> 2;
            }
        }

        nlohmann::json element(uint8_t type) {
            switch (type) {
                case 1: return fixed<int64_t>();
                case 2: return fixed<int32_t>();
                case 3: return fixed<int16_t>();
                case 4: return fixed<int8_t>();
                case 5: return fixed<uint64_t>();
                case 6: return fixed<uint32_t>();
                case 7: return fixed<uint16_t>();
                case 8: return fixed<uint8_t>();
                case 10: return std::string{take(varint())};
                case 11: return fixed<uint8_t>() != 0;
                case 12: return map();
            }
            throw std::runtime_error{"unknown levin_kv type"};
        }

        nlohmann::json map() {
            auto obj = nlohmann::json::object();
            for (auto n = varint(); n > 0; n--) {
                std::string name{take(fixed<uint8_t>())};
                auto type = fixed<uint8_t>();
                auto value = type & 0x80 ? array(type & 0x7f) : element(type);
                // emplace keeps the first of a repeated name, as epee did
                obj.emplace(std::move(name), std::move(value));
            }
            return obj;
        }

        nlohmann::json array(uint8_t type) {
            auto arr = nlohmann::json::array();
            for (auto n = varint(); n > 0; n--)
                arr.push_back(element(type));
            return arr;
        }
    };
}  // namespace detail

inline nlohmann::json dump(std::string_view msg) {
    using namespace std::literals;
    if (!msg.starts_with("\x01\x11\x01\x01\x01\x01\x02\x01\x01"sv))
        throw std::runtime_error{"not a levin_kv message"};
    detail::cursor c{msg.substr(9)};
    return c.map();
}

}  // namespace levin_kv_test
