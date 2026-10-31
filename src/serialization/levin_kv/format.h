#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <type_traits>

// The format's constants, shared by the writer and reader.
namespace levin_kv::format {

using namespace std::literals;

// Two signatures (written by epee as two little-endian u32s, 0x01011101 and 0x01020101) and the
// format version, 1.
inline constexpr auto HEADER = "\x01\x11\x01\x01\x01\x01\x02\x01\x01"sv;

inline constexpr uint8_t TYPE_INT64 = 1;
inline constexpr uint8_t TYPE_INT32 = 2;
inline constexpr uint8_t TYPE_INT16 = 3;
inline constexpr uint8_t TYPE_INT8 = 4;
inline constexpr uint8_t TYPE_UINT64 = 5;
inline constexpr uint8_t TYPE_UINT32 = 6;
inline constexpr uint8_t TYPE_UINT16 = 7;
inline constexpr uint8_t TYPE_UINT8 = 8;
// 9 is a double, which epee's reader never supported (refusing any message with one), so neither
// do we.
inline constexpr uint8_t TYPE_STRING = 10;
inline constexpr uint8_t TYPE_BOOL = 11;
inline constexpr uint8_t TYPE_MAP = 12;
// Set on the element type for an array
inline constexpr uint8_t FLAG_ARRAY = 0x80;

// Deeper nesting than this (of maps and arrays together) is refused when reading.
inline constexpr int MAX_DEPTH = 50;

// Varints carry their size in the bottom two bits of their first byte: 1, 2, 4 or 8 bytes,
// little-endian, holding 6, 14, 30 or 62 bits.
inline constexpr uint64_t VARINT_MAX = (uint64_t{1} << 62) - 1;

// The size of a value of a fixed-width type (an integer or bool); 0 for any other type.
constexpr size_t fixed_width(uint8_t type) {
    switch (type) {
        case TYPE_INT64:
        case TYPE_UINT64: return 8;
        case TYPE_INT32:
        case TYPE_UINT32: return 4;
        case TYPE_INT16:
        case TYPE_UINT16: return 2;
        case TYPE_INT8:
        case TYPE_UINT8:
        case TYPE_BOOL: return 1;
    }
    return 0;
}

// Calls `f(std::type_identity<T>{})` with the C++ type of a fixed-width type.
template <typename F>
constexpr decltype(auto) visit_fixed(uint8_t type, F&& f) {
    switch (type) {
        case TYPE_INT64: return f(std::type_identity<int64_t>{});
        case TYPE_INT32: return f(std::type_identity<int32_t>{});
        case TYPE_INT16: return f(std::type_identity<int16_t>{});
        case TYPE_INT8: return f(std::type_identity<int8_t>{});
        case TYPE_UINT64: return f(std::type_identity<uint64_t>{});
        case TYPE_UINT32: return f(std::type_identity<uint32_t>{});
        case TYPE_UINT16: return f(std::type_identity<uint16_t>{});
        case TYPE_UINT8: return f(std::type_identity<uint8_t>{});
        case TYPE_BOOL: return f(std::type_identity<bool>{});
    }
    throw std::logic_error{"levin_kv: not a fixed-width type"};
}

}  // namespace levin_kv::format
