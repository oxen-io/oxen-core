#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>

namespace crypto {

using hash_chunk_t = std::conditional_t<(sizeof(std::uint_fast32_t) > sizeof(std::size_t)), std::uint_fast32_t, std::size_t>;

template <std::size_t Bytes>
struct alignas(hash_chunk_t) hash_t {
  constexpr static std::size_t size = Bytes;
  static_assert(size % sizeof(hash_chunk_t) == 0);

  std::byte data[size];

  static const hash_t null;

  explicit operator bool() const { return *this != null; }

  bool operator==(const hash_t& h) const { return !memcmp(data, h.data, size); }
  bool operator!=(const hash_t& h) const { return !(*this == h); }
  bool operator<(const hash_t& h) const { return memcmp(data, h.data, size) < 0; }

  // Implicit conversion to unsigned char* to make it much easier to pass around to C functions
  operator unsigned char*() { return reinterpret_cast<unsigned char*>(data); }
  operator const unsigned char*() const { return reinterpret_cast<const unsigned char*>(data); }

  // Combine hashes together via XORs.
  hash_t& operator^=(const hash_t& h) {
    auto* mine = reinterpret_cast<hash_chunk_t*>(data);
    auto* theirs = reinterpret_cast<const hash_chunk_t*>(h.data);
    constexpr std::size_t len = size / sizeof(hash_chunk_t);
    for (std::size_t i = 0; i < len; i++)
      mine[i] ^= theirs[i];
    return *this;
  }
  hash_t& operator^(const hash_t& b) {
    hash_t h{*this};
    h ^= b;
    return h;
  }
};
template <std::size_t S>
constexpr hash_t<S> hash_t<S>::null{};

using hash = hash_t<32>;
using hash8 = hash_t<8>;

static_assert(sizeof(hash) == 32, "unexpected padding in hash type");
static_assert(sizeof(hash8) == 8, "unexpected padding in hash8 type");

} // namespace crypto

namespace std {
  template<std::size_t Bytes>
  struct hash<crypto::hash_t<Bytes>> {
    std::size_t operator()(const crypto::hash_t<Bytes>& v) const {
      return *reinterpret_cast<const size_t*>(v.data);
    }
  };
}
