
#include "sha256sum.h"

#include <sodium/crypto_hash_sha256.h>

#include <fstream>

#include "crypto/hash.h"
#include "fs.h"

namespace tools {

bool sha256sum_str(std::string_view data, crypto::hash& hash) {
    crypto_hash_sha256(
            hash.data(), reinterpret_cast<const unsigned char*>(data.data()), data.size());
    return true;
}

bool sha256sum_file(const fs::path& filename, crypto::hash& hash) {
    if (std::error_code ec; !fs::exists(filename, ec) || ec)
        return false;
    std::ifstream f;
    f.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    f.open(filename, std::ios_base::binary | std::ios_base::in | std::ios::ate);
    if (!f)
        return false;
    std::ifstream::pos_type file_size = f.tellg();
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    size_t size_left = file_size;
    f.seekg(0, std::ios::beg);

    std::array<unsigned char, 16384> buf;
    while (size_left) {
        auto read_size = std::min(size_left, buf.size());
        f.read(reinterpret_cast<char*>(buf.data()), read_size);
        if (!f || !f.good())
            return false;
        crypto_hash_sha256_update(&st, buf.data(), read_size);
        size_left -= read_size;
    }
    f.close();
    crypto_hash_sha256_final(&st, hash.data());
    return true;
}

}  // namespace tools
