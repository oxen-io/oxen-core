#include "defualt_transaction_constructor.hpp"
#include "pending_transaction.hpp"

namespace wallet
{

    PendingTransaction DefaultTransactionConstructor::CreateTransaction(const std::vector<std::pair<address, uint64_t> >& recipients, uint64_t feePerKB) const
    {
    }

} // namespace wallet
