#pragma once

// Adapts boost::serialization to support std::optional, serializing just as a boost::optional would
// be serialized (so that the serialized boost::optional<T> and std::optional<T> values are
// interchangeable).
//

#include <boost/archive/basic_archive.hpp>
#include <boost/serialization/item_version_type.hpp>
#include <boost/serialization/nvp.hpp>
#include <boost/serialization/serialization.hpp>
#include <boost/serialization/split_free.hpp>
#include <boost/serialization/version.hpp>
#include <optional>
#include <type_traits>

namespace boost::serialization {

template <class Archive, typename T>
void save(Archive& ar, std::optional<T> const& v, unsigned int /*version*/) {
    static_assert(std::is_default_constructible_v<T> || std::is_pointer_v<T>);

    const bool have = v.has_value();
    ar << boost::serialization::make_nvp("initialized", have);
    if (have)
        ar << boost::serialization::make_nvp("value", *v);
}

template <class Archive, typename T>
void load(Archive& ar, std::optional<T>& v, const unsigned int version) {
    bool have;
    ar >> boost::serialization::make_nvp("initialized", have);
    if (!have) {
        v.reset();
        return;
    }

    if (version == 0 && ar.get_library_version() > boost::archive::library_version_type{3}) {
        boost::serialization::item_version_type ver{0};
        ar >> boost::serialization::make_nvp("item_version", ver);
    }

    if (!v)
        v = std::make_optional<T>();

    ar >> boost::serialization::make_nvp("value", *v);
}

template <class Archive, typename T>
inline void serialize(Archive& ar, std::optional<T>& v, const unsigned int file_version) {
    split_free(ar, v, file_version);
}

}  // namespace boost::serialization
