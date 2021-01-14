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

/*! \file variant.h
 *
 * \brief for dealing with variants
 *
 * \detailed Variant: OOP Union
 */
#pragma once

#include <oxenmq/variant.h>
#include "serialization.h"
#include "common/meta.h"

namespace serialization {

// Helper bool to annotate what went wrong.
template <typename T, typename Tag>
constexpr bool VARIANT_NOT_REGISTERED = false;

// Fallback function; this is only instantiated (and fails to compile) if no specialization (create
// with one of the VARIANT_TAG macros) is defined at the point of instantiation.  This `is_same_v`
// is meant to convey some type information via the compiler (which usually expands the types that
// caused the static assert condition to fail).
template <typename T, typename TagType>
constexpr TagType variant_not_registered() {
  static_assert(VARIANT_NOT_REGISTERED<T, TagType>, "Variant type was not registered with the appropriate VARIANT_TAG, BINARY_VARIANT_TAG, or JSON_VARIANT_TAG");
}

/*! variant_serialization_tag is a constexpr template variable holds a variant type and tag.
 *
 * The base case is not usable; it must be specialized, typically using the VARIANT_TAG macro.
 */
template <class T, class TagType>
constexpr auto variant_serialization_tag = variant_not_registered<T, TagType>();

/*! \macro BINARY_VARIANT_TAG
 *
 * \brief Registers a uint8_t variant tag for binary variant serialization
 */
#define BINARY_VARIANT_TAG(Type, BinaryTag) \
namespace serialization { template<> inline constexpr uint8_t variant_serialization_tag<Type, uint8_t>{BinaryTag}; }

/*! \macro JSON_VARIANT_TAG
 *
 * \brief Registers a string_view variant tag for json variant serialization
 */
#define JSON_VARIANT_TAG(Type, JSONTag) \
namespace serialization { template<> inline constexpr std::string_view variant_serialization_tag<Type, std::string_view>{JSONTag}; }

/*! \macro VARIANT_TAG
 *
 * \brief Registers a variant type using the given json (string view) and binary (uint8_t) tags
 */
#define VARIANT_TAG(Type, JSONTag, BinaryTag) \
  JSON_VARIANT_TAG(Type, JSONTag) \
  BINARY_VARIANT_TAG(Type, BinaryTag)

namespace detail {

template <size_t I, class Archive, typename Variant, typename Tag>
bool read_variant_impl_one(Archive& ar, Variant& v, const Tag& tag)
{
  if (tag != variant_serialization_tag<std::variant_alternative_t<I, Variant>, Tag>)
    return false;
  value(ar, v.template emplace<I>());
  return true;
}

template <class Archive, typename... T, size_t... I>
void read_variant_impl(Archive& ar, std::variant<T...>& v, std::index_sequence<I...>)
{
  typename Archive::variant_tag_type tag;
  auto obj = ar.begin_object();
  ar.read_variant_tag(tag);
  if (!(... || read_variant_impl_one<I>(ar, v, tag)))
    throw std::runtime_error("failed to read variant");
}

template <class Archive, typename... T, typename Indices = std::make_index_sequence<sizeof...(T)>>
void read_variant(Archive& ar, std::variant<T...>& v)
{
  read_variant_impl(ar, v, std::make_index_sequence<sizeof...(T)>{});
}

/// Writes a variant
template <class Archive, typename... T>
void write_variant(Archive& ar, std::variant<T...>& v)
{
  return var::visit([&ar](auto& rv) {
      using Type = std::decay_t<decltype(rv)>;
      auto obj = ar.begin_object();
      ar.write_variant_tag(variant_serialization_tag<Type, typename Archive::variant_tag_type>);
      value(ar, rv);
  }, v);
}

} // namespace detail


template <typename Archive, typename... T>
void serialize_value(Archive& ar, std::variant<T...>& v)
{
  if constexpr (Archive::is_serializer)
    return detail::write_variant(ar, v);
  else
    return detail::read_variant(ar, v);
}

} // namespace serialization
