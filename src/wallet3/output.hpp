#pragma once

#include <cstdint>
#include <string>

#include <crypto/crypto.h>

namespace wallet
{

  struct Output
  {
    uint64_t rowid; // FIXME: not sure if needed...
    uint64_t amount;
    uint64_t output_index;
    uint64_t unlock_time;
    uint64_t block_height;
    uint64_t block_time;
    bool spending = false;
    uint64_t spent_height;
    uint64_t spent_time;

    crypto::hash tx_hash;
    crypto::public_key key;

  };

} // namespace wallet
