#include "eth.h"

#include <oxenc/hex.h>

#include "crypto/hash.h"

fmt::format_context::iterator fmt::formatter<eth::address>::default_format(
        std::span<const unsigned char> val, fmt::format_context& ctx) const {
    auto out = ctx.out();
    *out++ = '0';
    *out++ = 'x';

    if (val.size() == 20) {
        std::array<char, 40> buf;
        oxenc::to_hex(val.begin(), val.end(), buf.begin());
        auto csum = crypto::keccak(buf);
        constexpr char to_uc = 'a' - 'A';
        for (size_t i = 0; i < 20; i++) {
            char c1 = buf[2 * i], c2 = buf[2 * i + 1];
            *out++ = c1 - ((c1 >= 'a' && (csum[i] & 0x80)) ? to_uc : 0);
            *out++ = c2 - ((c2 >= 'a' && (csum[i] & 0x08)) ? to_uc : 0);
        }
        return out;
    } else {
        return oxenc::to_hex(val.begin(), val.end(), out);
    }
};
