#pragma once

#include <nlohmann/json_fwd.hpp>

#include "epee/storages/portable_storage_base.h"

// Conversion between JSON and the portable_storage sections that KV_SERIALIZE types load from and
// store into.
namespace tools::kv_json {

/// Converts a JSON object into a section.  JSON nulls and empty arrays are omitted.  Throws
/// std::invalid_argument for JSON that has no section equivalent: a non-object value, nested
/// arrays, or arrays of mixed types.
epee::serialization::section to_section(const nlohmann::json& obj);

/// Converts a section into a JSON object.
nlohmann::json to_json(const epee::serialization::section& sec);

}  // namespace tools::kv_json
