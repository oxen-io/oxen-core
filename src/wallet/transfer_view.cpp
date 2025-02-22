#include "transfer_view.h"

namespace wallet {

KV_SERIALIZE_MAP_CODE_BEGIN(transfer_view)
KV_SERIALIZE(txid);
KV_SERIALIZE(payment_id);
KV_SERIALIZE(height);
KV_SERIALIZE(timestamp);
KV_SERIALIZE(amount);
KV_SERIALIZE(fee);
KV_SERIALIZE(note);
KV_SERIALIZE(destinations);

// TODO(oxen): This discrepancy between having to use pay_type if type is
// empty and type if pay type is neither is super unintuitive.
if (this_ref.type.empty()) {
    std::string type = pay_type_string(this_ref.pay_type);
    KV_SERIALIZE_VALUE(type)
} else {
    KV_SERIALIZE(type)
}

KV_SERIALIZE(unlock_time)
KV_SERIALIZE(subaddr_index);
KV_SERIALIZE(subaddr_indices);
KV_SERIALIZE(address);
KV_SERIALIZE(double_spend_seen)
KV_SERIALIZE_OPT(confirmations, (uint64_t)0)
KV_SERIALIZE_OPT(suggested_confirmations_threshold, (uint64_t)0)
KV_SERIALIZE(checkpointed)
KV_SERIALIZE(blink_mempool)
KV_SERIALIZE(was_blink)
KV_SERIALIZE_MAP_CODE_END()

}  // namespace wallet
