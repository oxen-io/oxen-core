#pragma once

#include <oxenc/common.h>

#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <type_traits>
#include <vector>

// The types here are copied from libsession-util's session/sodium_array.hpp, and should be replaced
// with direct use of libsession-util if oxen-core ever adds it as a dependency.  (is_byte_spannable
// is oxen-core specific).

namespace crypto {

// Calls sodium_memzero to zero a buffer.  (Out of line so that key headers don't need to include
// libsodium headers).
void sodium_zero_buffer(void* ptr, size_t size);

// Wrapper around a type that uses `sodium_memzero` to zero the value on destruction; may only be
// used with trivially destructible types.
template <typename T>
    requires std::is_trivially_destructible_v<T>
struct sodium_cleared : T {
    using T::T;

    ~sodium_cleared() { sodium_zero_buffer(this, sizeof(*this)); }
};

template <oxenc::basic_char Char, size_t N>
struct cleared_array : sodium_cleared<std::array<Char, N>> {
    using sodium_cleared<std::array<Char, N>>::sodium_cleared;

    // Provide implicit conversion to fixed extent span because otherwise span's built-in is dynamic
    // extent (because span uses CTAD which detects std::array but not our subclass).
    operator std::span<Char, N>() { return std::span{static_cast<std::array<Char, N>&>(*this)}; }
    operator std::span<const Char, N>() const {
        return std::span{static_cast<const std::array<Char, N>&>(*this)};
    }
};

template <size_t N>
using cleared_bytes = cleared_array<std::byte, N>;
using cleared_b32 = cleared_bytes<32>;
using cleared_b64 = cleared_bytes<64>;

// Like std::allocator but zeros memory before freeing.
template <typename T>
struct clearing_allocator {
    using value_type = T;

    [[nodiscard]] static T* allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }

    static void deallocate(T* p, std::size_t n) {
        sodium_zero_buffer(p, n * sizeof(T));
        std::allocator<T>{}.deallocate(p, n);
    }

    template <typename T2>
    bool operator==(const clearing_allocator<T2>&) const noexcept {
        return true;
    }
};

/// Vector that zeros its buffer on deallocation (including when resizing).
template <typename T>
using cleared_vector = std::vector<T, clearing_allocator<T>>;

/// True if a T can be viewed and copied as raw bytes.  The cleared wrappers have a non-trivial
/// destructor, which makes them fail std::has_unique_object_representations even though their
/// contents are just the wrapped bytes, so they are specialized here.
template <typename T>
constexpr bool is_byte_spannable = std::has_unique_object_representations_v<T>;
template <typename T>
constexpr bool is_byte_spannable<sodium_cleared<T>> = is_byte_spannable<T>;
template <typename Char, size_t N>
constexpr bool is_byte_spannable<cleared_array<Char, N>> = true;

}  // namespace crypto
