#include "transaction_scanner.hpp"

#include <common/string_util.h>

namespace wallet
{

  std::vector<Output> TransactionScanner::ScanTransactionReceived(cryptonote::transaction_prefix tx, uint64_t height, uint64_t timestamp)
  {
    return {};
  }

  std::vector<Output> TransactionScanner::ScanTransactionSpent(cryptonote::transaction_prefix tx, uint64_t height, uint64_t timestamp)
  {
    return {};
  }

} // namespace wallet
