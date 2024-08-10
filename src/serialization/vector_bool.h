#pragma once

#include <cstdint>
#include <vector>

namespace serialization {

// Serializes a vector<bool> by encoding it as a length followed by bit-packed bytes, in little
// endian order (i.e. v[0] becomes the least significant bit of the first uint8_t byte after the
// length).
template <class Archive>
void serialize_value(Archive& ar, std::vector<bool>& v) {
    size_t len = v.size();
    auto arr = ar.begin_array(len);
    if constexpr (Archive::is_serializer) {
        for (size_t i = 0; i < v.size(); i += 8) {
            uint8_t val = 0;
            for (size_t j = 0; j < 8 && i + j < v.size(); j++)
                val |= v[i + j] << j;
            value(ar, val);
        }
    } else {  // is_deserializer:
        v.resize(len);
        uint8_t curr;
        for (size_t i = 0; i < len; i += 8) {
            value(ar, curr);
            for (size_t j = 0; j < 8 && i + j < len; j++)
                v[i + j] = curr & (1 << j);
        }
    }
}

}  // namespace serialization
