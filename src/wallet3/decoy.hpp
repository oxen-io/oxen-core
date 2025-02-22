#pragma once

#include <crypto/crypto.h>
#include <cryptonote_basic/cryptonote_basic.h>

#include "output.hpp"

namespace wallet {
struct Decoy {
    // outs - array of structure outkey as follows:
    // height - int; block height of the output
    // key - crypto::public_key; the public key of the output
    // mask - rct::key;
    // txid - String; transaction id
    // unlocked - boolean; States if output is locked (false) or not (true)
    // index - int; absolute index of the decoy

    int64_t height;
    crypto::public_key key;  // Hex public key of the output
    rct::key mask;
    std::string txid;
    bool unlocked;
    int64_t global_index;
};
}  // namespace wallet
