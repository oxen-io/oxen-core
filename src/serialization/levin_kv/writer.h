#pragma once

#include <string>
#include <vector>

#include "archive.h"

namespace levin_kv {

/// Writes what a type's serialize() gives it, as a whole message: see encode().
class writer final : public archive {
  public:
    writer();

    /// The message, once the fields have all been written.
    std::string finish() &&;

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
    std::string out;

    // A map being written, whose entry count (a varint, which comes before its entries) can't be
    // written until they all have been: a one-byte placeholder for it is at `count_pos`.
    struct open_map {
        size_t count_pos;
        size_t count = 0;
    };
    std::vector<open_map> stack;

    void begin_map();
    void end_map();
    void entry(std::string_view name, uint8_t type);
};

}  // namespace levin_kv
