#pragma once

#include <crypto/crypto.h>
#include <cryptonote_basic/cryptonote_basic.h>

#include "block_tx.hpp"

namespace wallet {
struct Block {
    int64_t height;
    crypto::hash hash;
    int64_t timestamp;

    std::vector<BlockTX> transactions;

    bool operator<(const Block& other) { return height < other.height; }
};

}  // namespace wallet
