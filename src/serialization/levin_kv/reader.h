#pragma once

#include <optional>
#include <string_view>
#include <vector>

#include "archive.h"

namespace levin_kv {

namespace detail {
    // A value as parsed, viewing the message (nothing is converted or copied until a field is
    // read into).
    struct parsed {
        std::string_view name;
        // A scalar's bytes, or a string's (without its length).  An array's elements' bytes, or
        // for an array of strings, each string's length and bytes.
        std::string_view data;
        // A map's number of fields, or an array's number of elements
        size_t count = 0;
        // A map's first field in `reader::fields`, or an array of maps' first in `reader::maps`
        size_t first = 0;
        uint8_t type = 0;
    };

    // The fields of a map, which are `count` consecutive elements of `reader::fields`
    struct parsed_map {
        size_t first = 0;
        size_t count = 0;
    };
}  // namespace detail

/// Gives a type's serialize() the fields of a parsed message: see decode().
class reader final : public archive {
  public:
    /// Parses a message, which must outlive the reader; nullopt if it isn't one.  Anything after
    /// the message is ignored, as epee did.
    static std::optional<reader> parse(std::string_view data);

  protected:
    bool scalar_value(std::string_view name, scalar_ref v) override;
    bool array(std::string_view name, array_ref v) override;
    bool packed_array(std::string_view name, packed_ref v) override;
    bool bytes(std::string_view name, std::span<std::byte> v) override;
    bool blobs(
            std::string_view name,
            size_t elem_size,
            size_t count,
            const std::function<std::span<std::byte>(size_t)>& storage) override;
    bool map(std::string_view name, const std::function<void(archive&)>& f) override;
    bool maps(
            std::string_view name,
            size_t count,
            const std::function<void(size_t)>& resize,
            const std::function<void(size_t, archive&)>& each) override;

  private:
    reader(std::vector<detail::parsed> fields,
           std::vector<detail::parsed_map> maps_in_arrays,
           detail::parsed_map root);

    // Every map's fields, each map's together (the root's first)
    std::vector<detail::parsed> fields;
    // The maps of arrays of maps, each array's together
    std::vector<detail::parsed_map> maps_in_arrays;
    // The map whose fields are being read: the root, or one nested in it
    std::vector<detail::parsed_map> stack;

    // The first field of the name, as epee read
    const detail::parsed* find(std::string_view name) const;
};

}  // namespace levin_kv
