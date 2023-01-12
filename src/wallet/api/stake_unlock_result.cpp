#include "stake_unlock_result.h"
#include "common_defines.h"
#include "pending_transaction.h"

namespace Wallet {

StakeUnlockResultImpl::StakeUnlockResultImpl(WalletImpl& w, tools::wallet2::request_stake_unlock_result res)
    : wallet{w}, result(std::move(res))
{
}

StakeUnlockResultImpl::~StakeUnlockResultImpl()
{
    log::trace(logcat, "Stake Unlock Result Deleted");
}

//----------------------------------------------------------------------------------------------------
bool StakeUnlockResultImpl::success()
{
    return result.success;
}

//----------------------------------------------------------------------------------------------------
std::string StakeUnlockResultImpl::msg()
{
    return result.msg;
}

//----------------------------------------------------------------------------------------------------
PendingTransaction* StakeUnlockResultImpl::ptx()
{
    return new PendingTransactionImpl{wallet, {{result.ptx}}};
}

} // namespace
