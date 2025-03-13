#pragma once
#include <oxenc/common.h>

#include <string>
#include <string_view>
#include <type_traits>

#include "fs.h"

namespace crypto {
struct hash;
}

namespace tools {

// Calculates sha256 checksum of the given data
bool sha256sum_str(std::span<const unsigned char> data, crypto::hash& hash);
bool sha256sum_str(std::span<const char> data, crypto::hash& hash);
bool sha256sum_str(std::span<const std::byte> data, crypto::hash& hash);

// Opens the given file and calculates a sha256sum of its contents
bool sha256sum_file(const fs::path& filename, crypto::hash& hash);

}  // namespace tools
