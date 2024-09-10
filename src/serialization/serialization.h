// Copyright (c) 2014-2019, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

/*! \file serialization.h
 *
 * \brief Serialization base types
 *
 * This header provides the basic types for some primitive type serialization for for extending
 * serialization for custom types.
 *
 * In order to use this serialization to serialize an entire, self-contained value you generally
 * want to call:
 *
 *     serialize(archive, value);
 *
 * or, to append a serialized value to an ongoing composite serialization:
 *
 *     value(archive, value);
 *     varint(archive, value);
 *     field(archive, "key", value);
 *     field_varint(archive, "key", value);
 *
 * where `archive` is a serializer or deserializer from binary_archive.h or json_archive.h (or
 * something compatible with their shared interface).  Depending on whether `archive` is a
 * serializer or deserializer this will either serialize from the given value, or deserialize into
 * the given value.
 *
 * `serialization::serialize` is a wrapper around `serialization::value` to be used when an entire
 * serialized value is the (only) content of an input or output stream.  The others, in contrast,
 * takes the same arguments but only appends or reads one value from the input stream; as such
 * they are the building blocks for building aggregate serialization types.
 *
 * Serialized types
 * ================
 *
 * By including just this header you get serialization of basic integer types and opt-in
 * byte-for-byte serialization of binary types.  Integers written with `value()/field()` are written
 * as little-endian byte values.  Integers written with `varint()` use a custom variable length (7
 * bits per byte) binary format, and binary values are copied byte-for-byte.  See the various other
 * serialization/ headers for additional serialization capabilities.
 *
 * Custom serialization
 * --------------------
 * To enable custom type serialization, include this header and then use one of the following two
 * approaches.
 *
 * Approach 1: create a free function to do serialization.  Ideally put this in the same namespace
 * as your type, named either `serialize_value` or `serialize_object` that takes a templated Archive
 * type and the type to be serialized as a non-const lvalue reference.
 *
 * `serialize_object` is equivalent to using `serialize_value` but automatically adds a `auto o =
 * ar.begin_object();` around the function; this is generally what you want when using the `field`
 * functions for properly supporting named fields.
 *
 * For example:
 *
 *     namespace myns {
 *     struct MyType { int v1; int v2; };
 *
 *     template <class Archive>
 *     void serialize_object(Archive& ar, MyType& x) {
 *       field(ar, "v1", x.v1);
 *       field(ar, "v2", x.v2);
 *     }
 *     }
 *
 * The `serialize_value`/`serialize_object` function will be found via ADL.  If you cannot define it
 * in the same namespace (for example, because you want to serialization some type from some
 * external namespace such as an stl type) then you can also define the function inside the
 * `serialization` namespace:
 *
 *     namespace serialization {
 *     template <class Archive>
 *     void serialize_value(Archive& ar, myns::MyType& x) { ... }
 *     }
 *
 * Approach 2: create a public `serialize_value` or `serialize_object` member function in the type
 * itself that takes the generic Archive type as the only argument.  This is useful, in particular,
 * where the serialization logic must access private members.  For example:
 *
 *     struct MyType {
 *     private:
 *       int v1;
 *       SomeType v2;
 *       // ...
 *
 *     public:
 *       template <class Archive>
 *       void serialize_object(Archive& ar) {
 *         field(ar, v1);
 *         field(ar, v2);
 *       }
 *     };
 *
 * Existing legacy code uses a bunch of disgusting macros to do this (which basically expand to
 * approach 2, above).  New code should avoid such nasty macros.
 *
 * Within the serialize_value function you generally want to perform sub-serialization, as shown in
 * the above examples.  Typically this involves calling a single `serialization::value(ar, val)` or
 * else starting an RAII `auto obj = ar.begin_object();` (or just providing a `serialize_object`
 * instead of `serialize_value` to do this for you) and then writing multiple fields using calls to
 * the the `field...` functions.  Unlike serialization::serialize, these functions append (or read)
 * an additional value but do not require that the additional value consume the entire
 * serialization.
 *
 * In the case of error, throw an exception that is derived from std::exception.  (Custom exception
 * types *not* ultimately derived from std::exception are not handled and should not be used).
 *
 * Binary serialization
 * --------------------
 *
 * To enable binary serialization for a type (i.e. where we just memcpy the object) you need to
 * include this header and then opt-in for the type using either of these techniques:
 *
 * Technique 1: add a `binary_serializable` static constexpr bool:
 *
 *     struct MyType {
 *       ...
 *       static constexpr bool binary_serializable = true;
 *     };
 *
 * Technique 2: explicitly specialize the serializable::binary_serializable<T> constexpr:
 *
 *     namespace x {
 *     struct MyType { ... };
 *     }
 *     BLOB_SERIALIZER(x::MyType);
 *     // equivalent to:
 *     namespace serialization { template<> constexpr binary_serializable<x::MyType> = true; }
 *
 * Be very careful with binary serialization: there are myriad ways in which binary object dumps can
 * be non-portable.
 */

#pragma once
#include <stdexcept>
#include <string_view>
#include <type_traits>

#include "base.h"
#include "common/exception.h"
#include "epee/span.h"  // for detecting epee-wrapped byte spannable objects

namespace serialization {

using namespace std::literals;

template <class Archive>
concept serializing = Archive::is_serializer;
template <class Archive>
concept deserializing = Archive::is_deserializer;

/** serialization::binary_serializable<T>
 *
 * a specializable constexpr for indicating a byte-serializable type.  You can specialize this *or*
 * provide a `binary_serializable` constexpr static bool member.
 */
template <typename T>
constexpr bool binary_serializable = false;

/// Macro to add a specialization.  Must be used out of any namespace.
#define BLOB_SERIALIZER(T)                                   \
    namespace serialization {                                \
        template <>                                          \
        inline constexpr bool binary_serializable<T> = true; \
    }

namespace detail {

    /// True if `serialize_value(ar, t)` exists for non-const `ar` and `t`
    template <typename T, typename Archive>
    concept free_serializable_value = requires(Archive& a, T v) { serialize_value(a, v); };

    /// Likewise, for `serialize_object(ar, t)`.
    template <typename T, typename Archive>
    concept free_serializable_object = requires(Archive& a, T v) { serialize_object(a, v); };

    /// True if `t.serialize_value(ar)` exists (and returns void) for non-const `ar` and `t`
    template <typename T, typename Archive>
    concept memfn_serializable_value = requires(Archive& a, T v) { v.serialize_value(a); };

    /// Likewise, for `t.serialize_object(ar)`.
    template <typename T, typename Archive>
    concept memfn_serializable_object = requires(Archive& a, T v) { v.serialize_object(a); };

}  // namespace detail

/// Serialization functions.  These are used to add/read a value to/from an ongoing serialization.

// Integer serializer
template <class Archive, std::integral T>
void value(Archive& ar, T& v) {
    ar.serialize_int(v);
}

// Blob serialization
template <class Archive, typename T>
    requires T::binary_serializable || binary_serializable<T>
void value(Archive& ar, T& v) {
    static_assert(
            std::has_unique_object_representations_v<T> || epee::is_byte_spannable<T>,
            "Type is not safe for binary serialization");
    ar.serialize_blob(&v, sizeof(v));
}

// Serializes some non-integer, non-binary value, when a `serialize_value(ar, x)` exists.
template <class Archive, detail::free_serializable_value<Archive> T>
void value(Archive& ar, T& v) {
    serialize_value(ar, v);
}
template <class Archive, detail::free_serializable_object<Archive> T>
void value(Archive& ar, T& v) {
    auto o = ar.begin_object();
    serialize_object(ar, v);
}

// Serializes some non-integer, non-binary value, when a `x.serialize_value(ar)` exists.
template <class Archive, detail::memfn_serializable_value<Archive> T>
void value(Archive& ar, T& v) {
    v.serialize_value(ar);
}
template <class Archive, detail::memfn_serializable_object<Archive> T>
void value(Archive& ar, T& v) {
    auto o = ar.begin_object();
    v.serialize_object(ar);
}

// Helper bool used in the serialize() fallback to annotate what went wrong.  (Templatized so that
// the value relies on the dependent type T to defer a static_assert).
template <typename T>
constexpr bool TYPE_IS_NOT_SERIALIZABLE = false;

// Generic fallback: if we reach here it means we failed all of the concepts above and thus this is
// something not serializable:
template <class Archive, typename T>
void value(Archive&, T&) {
    static_assert(
            !std::is_const_v<T> && TYPE_IS_NOT_SERIALIZABLE<T>,
            "type is not an integer, is not tagged binary-serializable, and does not have an "
            "appropriate serialize_value() function or method");
}

// Serializes some value with a predicate that must be satisfied when deserializing.  If the
// predicate fails the value serialization raises an exception.  The predicate is invoked (during
// deserialization) with a reference to `v` (which has already been updated).
template <class Archive, typename T, std::predicate<const T&> Predicate>
void value(Archive& ar, T& v, Predicate test) {
    value(ar, v);
    if (Archive::is_deserializer && !test(v))
        throw oxen::traced<std::out_of_range>{"Invalid value during deserialization"};
}

/// Serializes an integer value using varint encoding.
template <class Archive, std::integral T>
void varint(Archive& ar, T& val) {
    ar.serialize_varint(val);
}

/// Serializes an enum value using varint encoding of the underlying integer value.
template <class Archive, typename T>
    requires std::is_enum_v<T>
void varint(Archive& ar, T& val) {
    using UType = std::underlying_type_t<T>;
    UType tmp;
    if (Archive::is_serializer)
        tmp = static_cast<UType>(val);

    varint(ar, tmp);

    if (Archive::is_deserializer)
        val = static_cast<T>(tmp);
}

/// Serializes an integer or enum value using varint encoding with a Predicate (see value()).
template <class Archive, typename T, std::predicate<const T&> Predicate>
    requires std::is_integral_v<T> || std::is_enum_v<T>
void varint(Archive& ar, T& val, Predicate test) {
    varint(ar, val);
    if (Archive::is_deserializer && !test(val))
        throw oxen::traced<std::out_of_range>{
                "Invalid integer or enum value during deserialization"};
}

/// Adds a key-value pair
template <class Archive, typename T>
void field(Archive& ar, [[maybe_unused]] std::string_view name, T& val) {
    if constexpr (Archive::is_serializer)
        ar.tag(name);

    value(ar, val);
}

/// Adds a key-value pair with a predicate.
template <class Archive, typename T, std::predicate<const T&> Predicate>
void field(Archive& ar, [[maybe_unused]] std::string_view name, T& val, Predicate&& test) {
    if constexpr (Archive::is_serializer)
        ar.tag(name);

    value(ar, val, std::forward<Predicate>(test));
}

/// Serializes a key-value pair where the value is an integer or an enum using varint encoding of
/// the value.
template <class Archive, typename T>
    requires std::is_integral_v<T> || std::is_enum_v<T>
void field_varint(Archive& ar, [[maybe_unused]] std::string_view name, T& val) {
    if constexpr (Archive::is_serializer)
        ar.tag(name);

    varint(ar, val);
}

/// Serializes using field_varint(ar,name,val) with an additional predicate that must be satisfied
/// when deserializing.
template <class Archive, typename T, std::predicate<const T&> Predicate>
    requires std::is_integral_v<T> || std::is_enum_v<T>
void field_varint(Archive& ar, [[maybe_unused]] std::string_view name, T& val, Predicate&& test) {
    if constexpr (Archive::is_serializer)
        ar.tag(name);

    varint(ar, val, std::forward<Predicate>(test));
}

/// Checks that the entire input stream has been consumed, when deserializing.  Does nothing when
/// serializing.  Throws a std::runtime_error if unconsumed data is still present.  This is
/// typically invoked indirectly via serialization::serialize().
template <class Archive>
void done(Archive& ar) {
    if constexpr (Archive::is_deserializer)
        if (auto remaining = ar.remaining_bytes(); remaining > 0)
            throw oxen::traced<std::runtime_error>(
                    "Expected end of serialization data but not all data was consumed (" +
                    std::to_string(remaining) + ")");
}

/// Serializes a value and then calls done() to make sure that the entire stream was consumed.  You
/// do *not* want to call this to serialize a single value as part of a larger serialization: you
/// want value() or field() for that.
template <class Archive, typename T>
void serialize(Archive& ar, T& v) {
    value(ar, v);
    done(ar);
}

}  // namespace serialization
