#pragma once

#include <algorithm>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iterator>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <variant>
#include <vector>

#include "common/guts.h"
#include "fwd.h"

// The binary key-value format of levin p2p message bodies, which the core RPC's binary endpoints
// use too (epee called it "portable storage"): a map of named fields, each an integer, bool, byte
// string, nested map, or homogeneous array of any of those.
namespace levin_kv {

namespace detail {
    template <typename T, typename... U>
    concept one_of = (std::same_as<T, U> || ...);
}

/// Any integer type but bool and the character types
template <typename T>
concept integer = std::integral<T> && sizeof(T) <= 8 &&
                  !detail::one_of<T, bool, char, wchar_t, char8_t, char16_t, char32_t>;

/// A single value of one of the format's types: an integer, bool or string.
template <typename T>
concept scalar = integer<T> || detail::one_of<T, bool, std::string>;

/// Sent as its underlying integer
template <typename T>
concept enumeration = std::is_enum_v<T> && integer<std::underlying_type_t<T>>;

/// A type serialized as a nested map of its fields, by a `void serialize(levin_kv::archive&)`
/// member or a `void serialize(levin_kv::archive&, T&)` found by ADL.
template <typename T>
concept serializable = requires(T& v, archive& ar) { v.serialize(ar); } ||
                       requires(T& v, archive& ar) { serialize(ar, v); };

/// The element types of arrays: each of the format's types, exactly (as epee had).
template <typename T>
concept array_element = detail::one_of<
        T,
        int64_t,
        int32_t,
        int16_t,
        int8_t,
        uint64_t,
        uint32_t,
        uint16_t,
        uint8_t,
        bool,
        std::string>;

/// A value sent as its bytes (a hash, a key, a signature), which a vector of is sent as one string
/// of all their bytes.
template <typename T>
concept blob_element =
        tools::safe_to_memcpy<T> && !scalar<T> && !enumeration<T> && !serializable<T>;

/// A container that can be iterated and constructed from an iterator range (std::list, std::set,
/// std::deque, ...).
template <typename C>
concept range_container =
        std::ranges::sized_range<C> && !std::same_as<C, std::string> &&
        std::constructible_from<
                C,
                std::move_iterator<typename std::vector<typename C::value_type>::iterator>,
                std::move_iterator<typename std::vector<typename C::value_type>::iterator>>;

namespace detail {
    template <typename T>
    constexpr bool is_vector = false;
    template <typename T, typename A>
    constexpr bool is_vector<std::vector<T, A>> = true;

    template <typename T>
    constexpr bool vector_field = false;
    template <typename T>
    constexpr bool vector_field<std::vector<T>> =
            array_element<T> || serializable<T> || blob_element<T>;

    template <typename C>
    concept container_field =
            range_container<C> && !is_vector<C> &&
            (array_element<typename C::value_type> || serializable<typename C::value_type>);

    template <integer T>
    using fixed_int_t = std::conditional_t<
            std::is_signed_v<T>,
            std::conditional_t<
                    sizeof(T) == 1,
                    int8_t,
                    std::conditional_t<
                            sizeof(T) == 2,
                            int16_t,
                            std::conditional_t<sizeof(T) == 4, int32_t, int64_t>>>,
            std::conditional_t<
                    sizeof(T) == 1,
                    uint8_t,
                    std::conditional_t<
                            sizeof(T) == 2,
                            uint16_t,
                            std::conditional_t<sizeof(T) == 4, uint32_t, uint64_t>>>>;
}  // namespace detail

/// Serializes a type's fields through an archive, by its serialize() member or free function: for
/// archive implementations, and encode()/decode().
template <serializable T>
void serialize_fields(archive& ar, T& v) {
    if constexpr (requires { v.serialize(ar); })
        v.serialize(ar);
    else
        serialize(ar, v);
}

/// What `archive::value()` takes (and so what an optional can hold, or `value_or` default)
template <typename T>
concept field = scalar<T> || enumeration<T> || serializable<T> || detail::vector_field<T> ||
                detail::container_field<T>;

/// What a type's serialize() works through, in both directions: it calls the archive with each
/// field, which a writer writes from, and a reader sets from what it read.
///
/// When reading, a field that wasn't sent, or that can't be converted to the field's type, is left
/// as it was (as epee did).  Integers convert to any integer type they're in range of; other types
/// only to their own.
///
/// When writing, the fields are written in the order given, and integers are written with the
/// narrowest of the format's types that holds the value (or every value of an array): readers have
/// always converted integers between types.
class archive {
  public:
    virtual ~archive() = default;

    /// True for a reader, false for a writer
    bool loading() const { return is_loading; }

    /// Each of these returns true if it wrote the value, or set it from what was read.

    template <scalar T>
    bool value(std::string_view name, T& v) {
        if constexpr (array_element<T>)
            return scalar_value(name, std::ref(v));
        else {
            // An integer type with the size and signedness of a fixed one but not that type (such
            // as long long, where int64_t is long).
            detail::fixed_int_t<T> x = v;
            if (!scalar_value(name, std::ref(x)))
                return false;
            v = x;
            return true;
        }
    }

    template <enumeration T>
    bool value(std::string_view name, T& v) {
        auto i = static_cast<std::underlying_type_t<T>>(v);
        if (!value(name, i))
            return false;
        v = static_cast<T>(i);
        return true;
    }

    /// A value sent as a string of its bytes, which must be the size of the span to be read: see
    /// tools::byte_span().
    bool value(std::string_view name, std::span<std::byte> v) { return bytes(name, v); }

    /// A nested map, of the object's fields
    template <serializable T>
    bool value(std::string_view name, T& obj) {
        return map(name, [&obj](archive& ar) { serialize_fields(ar, obj); });
    }

    /// An array; an empty one isn't written.
    template <array_element T>
    bool value(std::string_view name, std::vector<T>& v) {
        return array(name, std::ref(v));
    }

    /// An array of maps; an empty one isn't written.
    template <serializable T>
    bool value(std::string_view name, std::vector<T>& v) {
        return maps(
                name,
                v.size(),
                [&v](size_t n) { v.resize(n); },
                [&v](size_t i, archive& ar) { serialize_fields(ar, v[i]); });
    }

    /// Values sent as one string of all their bytes; an empty vector isn't written.
    template <blob_element T>
    bool value(std::string_view name, std::vector<T>& v) {
        return blobs(name, sizeof(T), v.size(), [&v](size_t n) {
            v.resize(n);
            return std::as_writable_bytes(std::span{v});
        });
    }

    /// Any other container of array elements or serializable types, sent as a vector of them is
    /// (through a vector copy, as the virtual interface, which can't be generic, takes vectors).
    /// When read, a set keeps only the first of equal elements.
    template <detail::container_field C>
    bool value(std::string_view name, C& c) {
        std::vector<typename C::value_type> v;
        if (!loading())
            v.assign(c.begin(), c.end());
        if (!value(name, v))
            return false;
        if (loading())
            c = C(std::make_move_iterator(v.begin()), std::make_move_iterator(v.end()));
        return true;
    }

    /// Written only if set.  When read, set if the field was sent and converts; reset otherwise.
    template <field T>
    bool value(std::string_view name, std::optional<T>& v) {
        if (!loading())
            return v && value(name, *v);
        v.emplace();
        if (value(name, *v))
            return true;
        v.reset();
        return false;
    }

    /// Not written if it equals `def`; set to `def` if it isn't read.
    template <field T, typename D>
        requires std::equality_comparable_with<T, D> && std::assignable_from<T&, const D&>
    bool value_or(std::string_view name, T& v, const D& def) {
        if (!loading())
            return v != def && value(name, v);
        if (value(name, v))
            return true;
        v = def;
        return false;
    }

    /// A value sent as its bytes (see tools::byte_span()), not written if they're `def`'s; set to
    /// `def` if it isn't read.
    template <size_t N>
        requires(N != std::dynamic_extent)
    bool value_or(
            std::string_view name, std::span<std::byte, N> v, std::span<const std::byte, N> def) {
        if (!loading())
            return !std::ranges::equal(v, def) && value(name, v);
        if (value(name, v))
            return true;
        std::ranges::copy(def, v.begin());
        return false;
    }

    /// Unsigned integers written as one string of their fixed-width little-endian bytes, as epee
    /// sent some vectors, which only a string is accepted for by older readers.  Reading accepts
    /// either that or an array (as does value()), so that once nothing older is left these can be
    /// changed to value().  An empty vector isn't written.
    template <detail::one_of<uint64_t, uint32_t, uint16_t, uint8_t> T>
    bool packed(std::string_view name, std::vector<T>& v) {
        return packed_array(name, std::ref(v));
    }

  protected:
    explicit archive(bool loading) : is_loading{loading} {}

    template <typename... T>
    using ref_to_one_of = std::variant<std::reference_wrapper<T>...>;
    using scalar_ref = ref_to_one_of<
            int64_t,
            int32_t,
            int16_t,
            int8_t,
            uint64_t,
            uint32_t,
            uint16_t,
            uint8_t,
            bool,
            std::string>;
    using array_ref = ref_to_one_of<
            std::vector<int64_t>,
            std::vector<int32_t>,
            std::vector<int16_t>,
            std::vector<int8_t>,
            std::vector<uint64_t>,
            std::vector<uint32_t>,
            std::vector<uint16_t>,
            std::vector<uint8_t>,
            std::vector<bool>,
            std::vector<std::string>>;
    using packed_ref = ref_to_one_of<
            std::vector<uint64_t>,
            std::vector<uint32_t>,
            std::vector<uint16_t>,
            std::vector<uint8_t>>;

    virtual bool scalar_value(std::string_view name, scalar_ref v) = 0;
    virtual bool array(std::string_view name, array_ref v) = 0;
    virtual bool packed_array(std::string_view name, packed_ref v) = 0;
    virtual bool bytes(std::string_view name, std::span<std::byte> v) = 0;
    /// A string of `elem_size`-byte values: `count` of them when writing; when reading, any whole
    /// number of them.  `storage(n)` resizes to `n` values and gives their bytes, to write from or
    /// read into.
    virtual bool blobs(
            std::string_view name,
            size_t elem_size,
            size_t count,
            const std::function<std::span<std::byte>(size_t)>& storage) = 0;
    /// A nested map: `f` serializes its fields, through the archive it's given.
    virtual bool map(std::string_view name, const std::function<void(archive&)>& f) = 0;
    /// An array of `count` maps, when writing.  When reading, `resize` is called with the number
    /// read, then `each` for each of them.
    virtual bool maps(
            std::string_view name,
            size_t count,
            const std::function<void(size_t)>& resize,
            const std::function<void(size_t, archive&)>& each) = 0;

  private:
    const bool is_loading;
};

}  // namespace levin_kv
