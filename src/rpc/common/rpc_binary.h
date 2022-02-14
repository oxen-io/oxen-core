#pragma once

#include "ringct/rctTypes.h"
#include "crypto/crypto.h"
#include <string_view>
#include <nlohmann/json.hpp>
#include <unordered_set>

using namespace std::literals;

namespace cryptonote::rpc {

  // Binary types that we support for rpc input/output.  For json, these must be specified as hex or
  // base64; for bt-encoded requests these can be accepted as binary, hex, or base64.
  template <typename T>
  inline constexpr bool is_binary_parameter = false;
  template <> inline constexpr bool is_binary_parameter<crypto::hash> = true;
  template <> inline constexpr bool is_binary_parameter<crypto::public_key> = true;
  template <> inline constexpr bool is_binary_parameter<crypto::ed25519_public_key> = true;
  template <> inline constexpr bool is_binary_parameter<crypto::x25519_public_key> = true;
  template <> inline constexpr bool is_binary_parameter<crypto::key_image> = true;
  template <> inline constexpr bool is_binary_parameter<rct::key> = true;

  template <typename T>
  inline constexpr bool is_binary_container = false;
  template <typename T>
  inline constexpr bool is_binary_container<std::vector<T>> = is_binary_parameter<T>;
  template <typename T>
  inline constexpr bool is_binary_container<std::unordered_set<T>> = is_binary_parameter<T>;

  // De-referencing wrappers around the above:
  template <typename T> inline constexpr bool is_binary_parameter<const T&> = is_binary_parameter<T>;
  template <typename T> inline constexpr bool is_binary_parameter<T&&> = is_binary_parameter<T>;
  template <typename T> inline constexpr bool is_binary_container<const T&> = is_binary_container<T>;
  template <typename T> inline constexpr bool is_binary_container<T&&> = is_binary_container<T>;


  void load_binary_parameter_impl(std::string_view bytes, size_t raw_size, bool allow_raw, uint8_t* val_data);

  // Loads a binary value from a string_view which may contain hex, base64, and (optionally) raw
  // bytes.
  template <typename T, typename = std::enable_if_t<is_binary_parameter<T>>>
  void load_binary_parameter(std::string_view bytes, bool allow_raw, T& val) {
    load_binary_parameter_impl(bytes, sizeof(T), allow_raw, reinterpret_cast<uint8_t*>(&val));
  }

  // Wrapper around a nlohmann::json that assigns a binary value either as binary (for bt-encoding);
  // or as hex or base64 (for json-encoding).
  class json_binary_proxy {
    public:
    nlohmann::json& e;
    enum class fmt { bt, hex, base64 } format;
    explicit json_binary_proxy(nlohmann::json& elem, fmt format)
      : e{elem}, format{format} {}
    json_binary_proxy() = delete;

    json_binary_proxy(const json_binary_proxy&) = default;
    json_binary_proxy(json_binary_proxy&&) = default;

    /// Dereferencing a proxy element accesses the underlying nlohmann::json
    nlohmann::json& operator*() { return e; }
    nlohmann::json* operator->() { return &e; }

    /// Descends into the json object, returning a new binary value proxy around the child element.
    template <typename T>
    json_binary_proxy operator[](T&& key) {
      return json_binary_proxy{e[std::forward<T>(key)], format};
    }

    /// Returns a binary value proxy around the first/last element (requires an underlying list)
    json_binary_proxy front() { return json_binary_proxy{e.front(), format}; }
    json_binary_proxy back() { return json_binary_proxy{e.back(), format}; }

    /// Assigns binary data from a string_view/string/etc.
    nlohmann::json& operator=(std::string_view binary_data);

    /// Assigns binary data from a string_view over a 1-byte, non-char type (e.g. unsigned char or
    /// uint8_t).
    template <typename Char, std::enable_if_t<sizeof(Char) == 1 && !std::is_same_v<Char, char>, int> = 0>
    nlohmann::json& operator=(std::basic_string_view<Char> binary_data) {
      return *this = std::string_view{reinterpret_cast<const char*>(binary_data.data()), binary_data.size()};
    }

    /// Takes a trivial, no-padding data structure (e.g. a crypto::hash) as the value and dumps its
    /// contents as the binary value.
    template <typename T, std::enable_if_t<is_binary_parameter<T>, int> = 0>
    nlohmann::json& operator=(const T& val) {
      return *this = std::string_view{reinterpret_cast<const char*>(&val), sizeof(val)};
    }

    /// Takes a vector of some json_binary_proxy-assignable type and builds an array by assigning
    /// each one into a new array of binary values.
    template <typename T, std::enable_if_t<is_binary_container<T>, int> = 0>
    nlohmann::json& operator=(const T& vals) {
      auto a = nlohmann::json::array();
      for (auto& val : vals)
        json_binary_proxy{a.emplace_back(), format} = val;
      return e = std::move(a);
    }
  };

}

// Specializations of binary types for deserialization; when receiving these from json we expect
// them encoded in hex or base64.  These may *not* be used for serialization, and will throw if so
// invoked; for serialization you need to use RPC_COMMAND::response_hex (or _b64) instead.
namespace nlohmann {
  template <typename T>
  struct adl_serializer<T, std::enable_if_t<cryptonote::rpc::is_binary_parameter<T>>> {
    static_assert(std::is_trivially_copyable_v<T> && std::has_unique_object_representations_v<T>);

    static void to_json(json& j, const T&) {
      throw std::logic_error{"Internal error: binary types are not directly serializable"};
    }
    static void from_json(const json& j, T& val) {
      cryptonote::rpc::load_binary_parameter(j.get<std::string_view>(), false /*no raw*/, val);
    }
  };
}

