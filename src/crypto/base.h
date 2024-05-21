#pragma once

#include <array>
#include <type_traits>

#include "common/format.h"
#include "common/formattable.h"
#include "common/hex.h"

namespace crypto {

/// constexpr null (all-0) value for various crypto types; use as `crypto::null<crypto::whatever>`.
template <typename T>
    requires std::is_standard_layout_v<T> && std::is_default_constructible_v<T>
constexpr T null{};

// Base type for fixed-byte quantities (points, scalars, signatures, hashes).  The bool controls
// whether the type should have ==, !=, std::hash, and to_hex_string.
template <size_t Bytes, bool MemcmpHashHex = false, typename AlignAs = size_t>
struct alignas(AlignAs) bytes {
    std::array<unsigned char, Bytes> data_;

    unsigned char* data() { return data_.data(); }
    const unsigned char* data() const { return data_.data(); }
    static constexpr size_t size() { return Bytes; }
    auto begin() { return data_.begin(); }
    auto begin() const { return data_.begin(); }
    auto cbegin() const { return data_.cbegin(); }
    auto end() { return data_.end(); }
    auto end() const { return data_.end(); }
    auto cend() const { return data_.cend(); }

    // Set the bytes to all 0's
    void zero() { data_.fill(0); }

    unsigned char& operator[](size_t i) { return data_[i]; }
    const unsigned char& operator[](size_t i) const { return data_[i]; }

    static constexpr bool compare_hash_hex = MemcmpHashHex;
};

template <typename T>
concept hash_hex_comparable = T::compare_hash_hex || false;

template <hash_hex_comparable T>
bool operator==(const T& left, const T& right) {
    return left.data_ == right.data_;
}
template <hash_hex_comparable T>
bool operator!=(const T& left, const T& right) {
    return left.data_ != right.data_;
}
template <hash_hex_comparable T>
auto operator<=>(const T& left, const T& right) {
    return left.data_ <=> right.data_;
}

template <hash_hex_comparable T>
std::string to_hex_string(const T& val) {
    return "<{}>"_format(tools::type_to_hex(val));
}

template <hash_hex_comparable T>
    requires(
            std::is_standard_layout_v<T> && sizeof(T) >= sizeof(size_t) &&
            alignof(T) >= sizeof(size_t))
struct raw_hasher {
    size_t operator()(const T& val) const { return *reinterpret_cast<const size_t*>(val.data()); }
};
}  // namespace crypto

template <crypto::hash_hex_comparable T>
inline constexpr bool formattable::via_to_hex_string<T> = true;
