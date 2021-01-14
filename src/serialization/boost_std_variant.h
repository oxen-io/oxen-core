#pragma once

// Adapts boost::serialization to support std::variant, serializing just as a boost::variant would
// be serialized (so that the serialized boost::variant<T...> and std::variant<T...> values are
// interchangeable).
//

#include <oxenmq/variant.h>

#include <boost/archive/archive_exception.hpp>

#include <boost/serialization/split_free.hpp>
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/nvp.hpp>

namespace boost::serialization {

template <class Archive, typename... T>
void save(Archive& ar, std::variant<T...> const& v, unsigned int /*version*/) {
    int index = static_cast<int>(v.index());
    ar << boost::serialization::make_nvp("which", index);
    var::visit([&ar](const auto& v) { ar << boost::serialization::make_nvp("value", v); }, v);
}

template <class Archive, typename Variant, typename T, typename... More>
void load_variant_impl(Archive& ar, int index, Variant& v) {
    if (index == 0) {
        T value;
        ar >> boost::serialization::make_nvp("value", value);
        v = value;
        ar.reset_object_address(&var::get<T>(v), &value);
    }
    else if constexpr (sizeof...(More) > 0) {
        return load_variant_impl<Archive, Variant, More...>(ar, index - 1, v);
    }
}

template <class Archive, typename... T>
void load(Archive & ar, std::variant<T...>& v, const unsigned int version) {
    int index;
    ar >> boost::serialization::make_nvp("which", index);
    if (index < 0 || index >= (int) sizeof...(T))
        throw boost::archive::archive_exception{boost::archive::archive_exception::unsupported_version};
    load_variant_impl<Archive, std::variant<T...>, T...>(ar, index, v);
}

template <class Archive, typename... T>
inline void serialize(Archive& ar, std::variant<T...>& v, const unsigned int file_version) {
    split_free(ar,v,file_version);
}

} // namespace boost::serialization
