#pragma once

#include <exception>
#include <span>
#include <string>
#include <string_view>

#include "archive.h"
#include "reader.h"
#include "writer.h"

namespace levin_kv {

/// Serializes `v` (through its serialize()) as a message.
template <serializable T>
std::string encode(const T& v) {
    writer w;
    // serialize() takes its fields by non-const reference so as to serve reading too; the writer
    // only reads them.
    serialize_fields(w, const_cast<T&>(v));
    return std::move(w).finish();
}

/// Sets `v`'s fields from a message.  Returns false if `data` isn't a message, or if serialize()
/// throws (as epee's load did, for a type that checks what it reads); fields missing from it, or
/// that don't convert, are left as they were.
template <serializable T>
bool decode(std::string_view data, T& v) {
    auto r = reader::parse(data);
    if (!r)
        return false;
    try {
        serialize_fields(*r, v);
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

template <serializable T>
bool decode(std::span<const uint8_t> data, T& v) {
    return decode({reinterpret_cast<const char*>(data.data()), data.size()}, v);
}

}  // namespace levin_kv
