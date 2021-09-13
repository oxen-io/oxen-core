#pragma once
#include <cstdint>
#include <vector>
#include "address.hpp"

namespace wallet
{

  struct PendingTransaction;

  class TransactionConstructor
  {

    virtual PendingTransaction CreateTransaction(const std::vector<std::pair<address, uint64_t> >& recipients, uint64_t feePerKB) const;

  };

} // namespace wallet
