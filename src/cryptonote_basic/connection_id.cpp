#include "connection_id.h"

#include <oxenc/hex.h>

#include <iterator>
#include <random>

namespace cryptonote {

static std::mt19937_64 seed_rng() {
    std::random_device dev;
    // each dev() gives us 32 bits of random data; 256 bits ought to be plenty for what we need:
    std::seed_seq seed{{dev(), dev(), dev(), dev(), dev(), dev(), dev(), dev()}};
    std::mt19937_64 rng{seed};
    return rng;
}

connection_id_t connection_id_t::random() {
    static thread_local auto rng = seed_rng();
    uint64_t x[2];
    x[0] = rng();
    x[1] = rng();
    connection_id_t conn_id;
    static_assert(sizeof(conn_id) == sizeof(x));
    std::memcpy(conn_id.data(), &x, sizeof(x));
    return conn_id;
}

std::string connection_id_t::to_string() const {
    std::string s;
    s.reserve(36);
    auto out = std::back_inserter(s);
    oxenc::to_hex(begin(), begin() + 4, out);
    s += '-';
    oxenc::to_hex(begin() + 4, begin() + 6, out);
    s += '-';
    oxenc::to_hex(begin() + 6, begin() + 8, out);
    s += '-';
    oxenc::to_hex(begin() + 8, begin() + 10, out);
    s += '-';
    oxenc::to_hex(begin() + 10, end(), out);
    return s;
}

}  // namespace cryptonote
