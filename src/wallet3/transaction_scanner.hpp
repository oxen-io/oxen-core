#pragma once

#include <vector>

#include <src/cryptonote_basic/cryptonote_basic.hpp>
#include "output.hpp"

namespace wallet
{

  class TransactionScanner
  {
  public:

    virtual std::vector<Output> ScanTransactionReceived(cryptonote::transaction_prefix tx, uint64_t height, uint64_t timestamp) = 0;
    virtual std::vector<Output> ScanTransactionSpent(cryptonote::transaction_prefix tx, uint64_t height, uint64_t timestamp) = 0;
  };

} // namespace wallet

