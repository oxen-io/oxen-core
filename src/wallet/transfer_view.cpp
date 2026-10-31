#include "transfer_view.h"

#include "serialization/levin_kv/archive.h"

namespace wallet {

void transfer_view::serialize(levin_kv::archive& ar) {
    ar.value("txid", txid);
    ar.value("payment_id", payment_id);
    ar.value("height", height);
    ar.value("timestamp", timestamp);
    ar.value("amount", amount);
    ar.value("fee", fee);
    ar.value("note", note);
    ar.value("destinations", destinations);

    // TODO(oxen): This discrepancy between having to use pay_type if type is
    // empty and type if pay type is neither is super unintuitive.
    if (type.empty()) {
        std::string from_pay_type = pay_type_string(pay_type);
        ar.value("type", from_pay_type);
    } else
        ar.value("type", type);

    ar.value("unlock_time", unlock_time);
    ar.value("subaddr_index", subaddr_index);
    ar.value("subaddr_indices", subaddr_indices);
    ar.value("address", address);
    ar.value("double_spend_seen", double_spend_seen);
    ar.value_or("confirmations", confirmations, uint64_t{0});
    ar.value_or(
            "suggested_confirmations_threshold", suggested_confirmations_threshold, uint64_t{0});
    ar.value("checkpointed", checkpointed);
    ar.value("blink_mempool", blink_mempool);
    ar.value("was_blink", was_blink);
}

void transfer_destination::serialize(levin_kv::archive& ar) {
    ar.value("amount", amount);
    ar.value("address", address);
}

}  // namespace wallet
