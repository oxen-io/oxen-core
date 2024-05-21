#pragma once

#include <concepts>
#include <cstddef>

namespace tools {

template <typename Char>
concept basic_char = sizeof(Char) == 1 && !std::same_as<Char, bool> &&
                     (std::integral<Char> || std::same_as<Char, std::byte>);

}
