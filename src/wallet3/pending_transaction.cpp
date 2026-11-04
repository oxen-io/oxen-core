#include "pending_transaction.hpp"

#include "oxen_economy.h"
#include "transaction_constructor.hpp"

namespace wallet {
PendingTransaction::PendingTransaction(
        const std::vector<cryptonote::tx_destination_entry>& new_recipients) :
        recipients(new_recipients) {
    tx = cryptonote::transaction{};
    int64_t sum_recipient_amounts = 0;
    for (const auto& recipient : new_recipients) {
        if (sum_recipient_amounts < 0)
            throw std::runtime_error("Transaction amounts must be positive");
        sum_recipient_amounts += recipient.amount;
    }
    if (sum_recipient_amounts < 0)
        throw std::runtime_error("Transaction amounts must be positive");
}

void PendingTransaction::update_change() {
    change.amount = sum_inputs() - sum_outputs() - get_fee();
}

int64_t PendingTransaction::sum_inputs() const {
    return std::accumulate(
            chosen_outputs.begin(),
            chosen_outputs.end(),
            int64_t{0},
            [](int64_t accumulator, const Output& output) { return accumulator + output.amount; });
}

int64_t PendingTransaction::sum_outputs() const {
    return std::accumulate(
            recipients.begin(),
            recipients.end(),
            int64_t{0},
            [](int64_t accumulator, const cryptonote::tx_destination_entry& recipient) {
                return accumulator + recipient.amount;
            });
}

int64_t PendingTransaction::get_fee() const {
    return get_fee(chosen_outputs.size());
}
int64_t PendingTransaction::get_fee(int64_t n_inputs) const {
    int64_t fixed_fee = burn_fixed;
    // TODO sean add this
    int64_t burn_pct = 0;
    int64_t fee_percent = oxen::BLINK_BURN_TX_FEE_PERCENT_V18;  // 100%
    if (blink)
        fee_percent = oxen::BLINK_MINER_TX_FEE_PERCENT + oxen::BLINK_BURN_TX_FEE_PERCENT_V18 +
                      burn_pct;  // Blink ends up being 300%

    int64_t fee =
            (get_tx_weight(n_inputs) * fee_per_byte + (recipients.size() + 1) * fee_per_output) *
            fee_percent / 100;
    // Add fixed amount to the fee for items such as burning. This is defined in the pending
    // transactions
    fee += fixed_fee;
    return fee;
}

size_t PendingTransaction::get_tx_weight(int64_t n_inputs) const {
    size_t size = 0;
    // If there is no inputs then we estimate using one input
    if (n_inputs == 0)
        n_inputs = 1;

    size_t n_outputs = recipients.size() + 1;  // Recipients plus change
    if (n_outputs == 0)
        throw std::runtime_error{
                "Get Transaction Weight called on a transaction with no recipients"};

    size += 1 + 6;                                            // tx prefix, first few bytes
    size += n_inputs * (1 + 6 + (mixin_count + 1) * 2 + 32);  // vin
    size += n_outputs * (6 + 32);                             // vout
    size += extra_size();                                     // extra
    // rct signatures
    size += 1;  // type
    size_t log_padded_outputs = 0;
    while ((uint64_t(1) << log_padded_outputs) < n_outputs)
        ++log_padded_outputs;
    size += (2 * (6 + static_cast<int64_t>(log_padded_outputs)) + 4 + 5) * 32 + 3;  // rangeSigs

    size += n_inputs * (32 * (mixin_count + 1) + 64);  // CLSAGs
    size += 32 * n_inputs;                             // pseudoOuts
    size += 8 * n_outputs;                             // ecdhInfo
    size += 32 * n_outputs;                            // outPk - only commitment is saved
    size += 4;                                         // txnFee

    if (n_outputs > 2) {
        const uint64_t bp_base = 368;
        size_t log_padded_outputs = 2;
        while ((uint64_t(1) << log_padded_outputs) < n_outputs)
            ++log_padded_outputs;
        uint64_t nlr = 2 * (6 + log_padded_outputs);
        const uint64_t bp_size = 32 * (9 + nlr);
        const uint64_t bp_clawback = (bp_base * (1 << log_padded_outputs) - bp_size) * 4 / 5;
        size += bp_clawback;
    }
    return size;
}

bool PendingTransaction::finalise() {
    if ((sum_inputs() - sum_outputs() - fee - change.amount) != 0)
        return false;
    for (size_t i = 0; i < recipients.size(); i++)
        tx.output_unlock_times.push_back(unlock_time);
    tx.output_unlock_times.push_back(change_unlock_time);

    tx.extra = std::move(extra);

    return true;
}

}  // namespace wallet
