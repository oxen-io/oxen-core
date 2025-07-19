#pragma once
#include <crypto/eth.h>

#include <cstdint>
#include <span>

namespace cryptonote::snapshots {

// The archive block height for the following snapshot data
extern const int64_t height;

struct DelayedPayment {
    eth::address addr;
    int64_t amount;
    int payout_height;
    int height;
    int block_height;
    int block_tx_index;
    int contributor_index;
    int64_t liquidation_amount;
};
extern const std::span<const DelayedPayment> delayed_payments;

struct BatchedPaymentAccrued {
    eth::address addr;
    int64_t amount;
    // payout_offset: omitted -- this is only used for HF21+ where that is always null
    // height: all rows are for the `height` constant declared above
    int64_t lifetime_locked_stakes;
    int64_t lifetime_unlocked_stakes;
    int64_t lifetime_liquidated_stakes;
    int64_t lifetime_rewards;
};
extern const std::span<const BatchedPaymentAccrued> batched_payments;

}  // namespace cryptonote::snapshots
