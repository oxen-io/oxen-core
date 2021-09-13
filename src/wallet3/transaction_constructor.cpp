#include "transaction_constructor.hpp"
#include "pending_transaction.hpp"

namespace wallet
{

    PendingTransaction TransactionConstructor::CreateTransaction(const std::vector<std::pair<address, uint64_t> >& recipients, uint64_t feePerKB) const
    {
      return {};
    }

} // namespace wallet
