#pragma once

#include <vector>

#include <cryptonote_basic/cryptonote_basic.h>

#include "output.hpp"
#include "keys.hpp"

namespace wallet
{

  class TransactionScanner
  {
  public:

    TransactionScanner(std::shared_ptr<Keys> _keys) : wallet_keys(_keys) {}

    std::vector<Output> ScanTransactionReceived(const cryptonote::transaction& tx, const crypto::hash& tx_hash, uint64_t height, uint64_t timestamp);
    std::vector<Output> ScanTransactionSpent(const cryptonote::transaction& tx, const crypto::hash& tx_hash, uint64_t height, uint64_t timestamp);

  private:

    std::shared_ptr<Keys> wallet_keys;
  };

} // namespace wallet

