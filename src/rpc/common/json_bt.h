#pragma once

#include <nlohmann/json.hpp>
#include <oxenmq/bt_value.h>

using nlohmann::json;

namespace oxen {

oxenmq::bt_value json_to_bt(json&& j);

} // namespace oxen
