#pragma once

namespace serialization {

// Base type tags for serialization
struct serializer {
    static constexpr bool is_serializer = true;
    static constexpr bool is_deserializer = false;
};
struct deserializer {
    static constexpr bool is_serializer = false;
    static constexpr bool is_deserializer = true;
};

}  // namespace serialization
