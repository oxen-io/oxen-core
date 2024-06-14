#pragma once

#include "exception.h"

#include <oxenc/endian.h>

#include <array>
#include <cstddef>
#include <cstdint>

namespace tools {

// Constructs an array containing a big-endian representation of the given integer value.  E.g.
// `encode_integer_be<32>(100)` will give you the 32-byte big-integer integer representation of 100.
template <size_t Bytes>
    requires(Bytes >= 8)
std::array<std::byte, Bytes> encode_integer_be(uint64_t val) {
    std::array<std::byte, Bytes> result = {};
    oxenc::write_host_as_big(val, &result[Bytes - 8]);
    return result;
}

// Same as above, but returns a little-endian encoded integer value.
template <size_t Bytes>
    requires(Bytes >= 8)
std::array<std::byte, Bytes> encode_integer_le(uint64_t val) {
    std::array<std::byte, Bytes> result = {};
    oxenc::write_host_as_little(val, &result[0]);
    return result;
}

// Opposite of the above: these decodes an array of big-endian encoded bytes to a uint64_t.  Throws
// if the value doesn't fit in a uint64_t.
template <size_t Bytes>
    requires(Bytes >= 8)
uint64_t decode_integer_be(const std::array<std::byte, Bytes>& be_val) {
    for (size_t i = 0; i < Bytes - 8; i++)
        if (be_val[i] != std::byte{0})
            throw oxen::overflow_error{"integer too large for u64"};
    return oxenc::load_big_to_host<uint64_t>(be_val.data() + (be_val.size() - 8));
}

// Opposite of the above: these decodes an array of little-endian encoded bytes to a uint64_t.
// Throws if the value doesn't fit in a uint64_t.
template <size_t Bytes>
    requires(Bytes >= 8)
uint64_t decode_integer_le(const std::array<std::byte, Bytes>& le_val) {
    for (size_t i = 8; i < Bytes; i++)
        if (le_val[i] != std::byte{0})
            throw oxen::overflow_error{"integer too large for u64"};
    return oxenc::load_little_to_host<uint64_t>(le_val.data());
}

// Constructs an array containing a big integer representation of a 128-bit value, passed as a high
// and low value pair (i.e. representing the quantity high << 64 + low).
template <size_t Bytes>
    requires(Bytes >= 16)
std::array<std::byte, Bytes> encode_integer_be(uint64_t high, uint64_t low) {
    std::array<std::byte, Bytes> result = {};
    oxenc::write_host_as_big(high, &result[Bytes - 16]);
    oxenc::write_host_as_big(low, &result[Bytes - 8]);
    return result;
}

// Same as above, but little endian.
template <size_t Bytes>
    requires(Bytes >= 16)
std::array<std::byte, Bytes> encode_integer_le(uint64_t high, uint64_t low) {
    std::array<std::byte, Bytes> result = {};
    oxenc::write_host_as_little(low, &result[0]);
    oxenc::write_host_as_little(high, &result[8]);
    return result;
}

// Opposite of the above: these decodes an array of big-endian encoded bytes to an unsigned 128-bit
// quantity, returned as a pair of uint64_t (the first element of the pair is the high value).
// Throws if the value doesn't fit in a uint64_t.
template <size_t Bytes>
    requires(Bytes >= 16)
std::pair<uint64_t, uint64_t> decode_integer_be128(const std::array<std::byte, Bytes>& be_val) {
    for (size_t i = 0; i < Bytes - 16; i++)
        if (be_val[i] != std::byte{0})
            throw oxen::overflow_error{"integer too large for u128"};
    return {oxenc::load_big_to_host<uint64_t>(be_val.data() + (be_val.size() - 16)),
            oxenc::load_big_to_host<uint64_t>(be_val.data() + (be_val.size() - 8))};
}

// Opposite of the above: these decodes an array of big-endian encoded bytes to an unsigned 128-bit
// quantity, returned as a pair of uint64_t (the first element of the pair is the high value).
// Throws if the value doesn't fit in a uint64_t.
template <size_t Bytes>
    requires(Bytes >= 16)
std::pair<uint64_t, uint64_t> decode_integer_le128(const std::array<std::byte, Bytes>& le_val) {
    for (size_t i = 16; i < Bytes; i++)
        if (le_val[i] != std::byte{0})
            throw oxen::overflow_error{"integer too large for u128"};
    return {oxenc::load_little_to_host<uint64_t>(le_val.data() + 8),
            oxenc::load_little_to_host<uint64_t>(le_val.data())};
}

}  // namespace tools
