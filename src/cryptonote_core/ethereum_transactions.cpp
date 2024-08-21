#include "ethereum_transactions.h"

namespace eth {

event::StateChangeVariant extract_event(
        cryptonote::hf hf_version, cryptonote::transaction const& tx, std::string& fail_reason) {
    event::StateChangeVariant result;
    if (hf_version < cryptonote::feature::ETH_BLS) {
        fail_reason = "Cannot extract an ethereum event from a HF{} transaction"_format(
                static_cast<int>(hf_version));
        return result;
    }
    if (!is_l2_event_tx(tx.type)) {
        fail_reason = "Transaction {} is not a eth state change tx type"_format(tx);
        return result;
    }
    if (tx.type == cryptonote::txtype::ethereum_new_service_node) {
        if (extract_event(tx, result.emplace<event::NewServiceNode>(), fail_reason))
            return result;
    } else if (tx.type == cryptonote::txtype::ethereum_service_node_removal_request) {
        if (extract_event(tx, result.emplace<event::ServiceNodeRemovalRequest>(), fail_reason))
            return result;
    } else {
        assert(tx.type == cryptonote::txtype::ethereum_service_node_removal);
        if (extract_event(tx, result.emplace<event::ServiceNodeRemoval>(), fail_reason))
            return result;
    }
    result = std::monostate{};
    return result;
}

std::optional<uint64_t> extract_event_l2_height(
        cryptonote::hf hf_version, const cryptonote::transaction& tx) {
    std::string fail;
    auto result = std::visit(
            []<typename T>(const T& e) -> std::optional<uint64_t> {
                if constexpr (std::is_same_v<std::monostate, T>)
                    return std::nullopt;
                else
                    return e.l2_height;
            },
            extract_event(hf_version, tx, fail));
    if (!result)
        log::debug(
                log::Cat("l2"),
                "Failed to extract L2 event height from {}: {}",
                get_transaction_hash(tx),
                fail);
    return result;
}

}  // namespace eth
