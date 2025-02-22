#pragma once

#include <crypto/crypto.h>
#include <cryptonote_basic/cryptonote_basic.h>

namespace wallet {
struct BlockTX {
    crypto::hash hash;

    // output global indices to reference when spending
    std::vector<int64_t> global_indices;

    cryptonote::transaction tx;
};

}  // namespace wallet
