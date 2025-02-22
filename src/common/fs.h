#pragma once

#include <filesystem>
#include <string_view>

#include "string_util.h"

namespace fs = std::filesystem;

namespace tools {

inline fs::path utf8_path(std::string_view p) {
    return fs::path{convert_sv<char8_t>(p)};
}

}  // namespace tools
