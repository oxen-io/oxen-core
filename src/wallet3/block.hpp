#pragma once

#include <crypto/hash.h>
#include <cryptonote_basic/cryptonote_basic.h>

#include <vector>

namespace wallet
{

  struct Block
  {
    uint64_t height;
    crypto::hash hash;
    uint64_t timestamp;

    // this includes the miner transaction
    std::vector<cryptonote::transaction_prefix> transactions;
  };

} // namespace wallet
