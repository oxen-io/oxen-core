#include "ethereum_transactions.h"

#include "blockchain.h"
#include "l2_tracker/events.h"

namespace eth {

event::StateChangeVariant extract_event(
        cryptonote::transaction const& tx, std::string* fail_reason) {
    event::StateChangeVariant result;
    if (!is_l2_event_tx(tx.type)) {
        if (fail_reason)
            *fail_reason = "Transaction {} is not a eth state change tx type"_format(tx);
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

event::StateChangeVariant extract_event(
        cryptonote::Blockchain& blockchain, const crypto::hash& txid, std::string* fail_reason) {
    try {
        return extract_event(blockchain.db().get_tx(txid), fail_reason);
    } catch (const std::runtime_error& e) {
        if (fail_reason)
            *fail_reason = "Could not retrieve L2 event: {}"_format(e.what());
        return std::monostate{};
    }
}

std::optional<uint64_t> extract_event_l2_height(
        const cryptonote::transaction& tx, std::string* fail_reason) {
    std::string fail;
    if (!fail_reason)
        fail_reason = &fail;
    auto result = std::visit(
            []<typename T>(const T& e) -> std::optional<uint64_t> {
                if constexpr (std::is_same_v<std::monostate, T>)
                    return std::nullopt;
                else
                    return e.l2_height;
            },
            extract_event(tx, fail_reason));
    if (!result)
        log::debug(
                log::Cat("l2"),
                "Failed to extract L2 event height from {}: {}",
                get_transaction_hash(tx),
                *fail_reason);
    return result;
}

}  // namespace eth
