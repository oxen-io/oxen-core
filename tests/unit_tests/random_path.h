#pragma once

#include <random>
#include <string>
#include <string_view>

#include "common/fs.h"

inline fs::path random_tmp_file() {
    // Not the more secure, but fine for test suite code:
    static std::mt19937_64 rng{std::random_device{}()};
    using namespace std::literals;
    constexpr auto chars = "abcdefghijklmnopqrstuvwxyz0123456789"sv;
    std::uniform_int_distribution<size_t> r_idx(0, chars.size() - 1);
    std::string result;
    for (int i = 0; i < 12; i++)
        result += chars[r_idx(rng)];
    return fs::temp_directory_path() / result;
}
