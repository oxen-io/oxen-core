#pragma once

/// Serialization of std::optionals.

#include <cstdint>
#include <optional>
#include <type_traits>

#include "serialization.h"

namespace serialization {

template <class Archive, class T>
void serialize_value(Archive& ar, std::optional<T>& v) {
    using I = std::remove_cv_t<T>;

    bool have_value = v.has_value();
    if constexpr (is_binary<Archive>)
        ar.serialize_int(have_value);

    if (have_value) {
        if (Archive::is_deserializer && !v.has_value())
            v.emplace();
        if constexpr (std::is_same_v<I, uint32_t> || std::is_same_v<I, uint64_t>)
            varint(ar, *v);
        else
            value(ar, *v);
    } else if constexpr (Archive::is_serializer) {
        if constexpr (!is_binary<Archive>)
            ar.serialize_null();
    } else {  // deserializing && !have_value
        v.reset();
    }
}

}  // namespace serialization
