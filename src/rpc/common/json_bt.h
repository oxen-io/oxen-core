#pragma once

#include <oxenc/bt_value.h>

#include <nlohmann/json.hpp>

using nlohmann::json;

namespace oxen {

oxenc::bt_value json_to_bt(json&& j);

}  // namespace oxen
