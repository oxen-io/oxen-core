#pragma once

#include <nlohmann/json.hpp>
#include <stdexcept>

#include "epee/storages/portable_storage_base.h"
#include "serialization/levin_kv/archive.h"

// Conversion between JSON and the types the wallet RPC serializes (through levin_kv's archive),
// with the semantics the wallet RPC has always had: those of epee's KV serialization.
namespace tools::kv_json {

/// Converts a JSON object into a section.  JSON nulls and empty arrays are omitted.  Throws
/// std::invalid_argument for JSON that has no section equivalent: a non-object value, nested
/// arrays, or arrays of mixed types.
epee::serialization::section to_section(const nlohmann::json& obj);

/// Converts a section into a JSON object.
nlohmann::json to_json(const epee::serialization::section& sec);

/// Writes a type's fields into a JSON object: see to_json().
class json_writer final : public levin_kv::archive {
  public:
    json_writer() : archive{false} {}

    nlohmann::json finish() && { return std::move(root); }

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
    nlohmann::json root = nlohmann::json::object();
    // The object being written into: the root, or one nested in it
    nlohmann::json* current = &root;
};

/// Sets a type's fields from a JSON object: see from_json().
class json_reader final : public levin_kv::archive {
  public:
    explicit json_reader(const nlohmann::json& obj) : archive{true}, current{&obj} {}

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
    // The object being read from: the root, or one nested in it
    const nlohmann::json* current;

    // The field of the name; nullptr if there isn't one, or it's null.
    const nlohmann::json* find(std::string_view name) const;
};

/// Throws std::invalid_argument for JSON that the wallet RPC has never accepted: a non-object, or
/// one holding nested arrays, arrays of nulls or of mixed types, or integer arrays with values
/// beyond the range of both uint64_t and int64_t.
void validate(const nlohmann::json& obj);

/// A type's fields as a JSON object.  Empty containers, unset optionals and fields at their
/// value_or default are left out.
template <levin_kv::serializable T>
nlohmann::json to_json(const T& v) {
    json_writer w;
    // serialize() takes its fields by non-const reference so as to serve reading too
    levin_kv::serialize_fields(w, const_cast<T&>(v));
    return std::move(w).finish();
}

/// Sets a type's fields from a JSON object.  Fields that are missing, null, empty arrays, or that
/// don't convert to the field's type are left as they were.  Integers convert to any integer type
/// they're in range of, and strings of digits to a uint64_t.  Throws std::invalid_argument (see
/// validate()) for unacceptable JSON; returns false if the type's serialize() throws.
template <levin_kv::serializable T>
bool from_json(const nlohmann::json& obj, T& v) {
    validate(obj);
    json_reader r{obj};
    try {
        levin_kv::serialize_fields(r, v);
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

}  // namespace tools::kv_json
