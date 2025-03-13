#pragma once

#include <filesystem>
#include <string_view>

namespace fs = std::filesystem;

namespace tools {

inline fs::path utf8_path(std::string_view p) {
    return fs::path{std::u8string_view{reinterpret_cast<const char8_t*>(p.data()), p.size()}};
}

inline std::string path_to_str(const fs::path& p) {
    auto u8path = p.u8string();
    return {reinterpret_cast<const char*>(u8path.data()), u8path.size()};
}

}  // namespace tools
