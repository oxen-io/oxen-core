#include "ethereum_transactions.h"

#include "cryptonote_basic/cryptonote_format_utils.h"

using cryptonote::hf;

#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("l2_tracker");

namespace eth {

template <typename... T>
static bool check_condition(
        bool condition, std::string* reason, fmt::format_string<T...> format, T&&... args) {
    if (condition && reason)
        *reason = fmt::format(format, std::forward<T>(args)...);
    return condition;
}

bool validate_ethereum_new_service_node_tx(
        hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_ethereum_new_service_node& eth_extra,
        std::string* reason) {

    {
        if (check_condition(
                    tx.type != cryptonote::txtype::ethereum_new_service_node,
                    reason,
                    "{} uses wrong tx type, expected={}",
                    tx,
                    cryptonote::txtype::ethereum_new_service_node))
            return false;
        if (check_condition(
                    !cryptonote::get_field_from_tx_extra(tx.extra, eth_extra),
                    reason,
                    "{} didn't have ethereum new service node data in the tx_extra",
                    tx))
            return false;
    }

    return true;
}

bool validate_ethereum_service_node_removal_request_tx(
        hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_ethereum_service_node_removal_request& eth_extra,
        std::string* reason) {

    {
        if (check_condition(
                    tx.type != cryptonote::txtype::ethereum_service_node_removal_request,
                    reason,
                    "{} uses wrong tx type, expected={}",
                    tx,
                    cryptonote::txtype::ethereum_service_node_removal_request))
            return false;

        if (check_condition(
                    !cryptonote::get_field_from_tx_extra(tx.extra, eth_extra),
                    reason,
                    "{} didn't have ethereum service node removal request data in the tx_extra",
                    tx))
            return false;
    }

    return true;
}

bool validate_ethereum_service_node_removal_tx(
        hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_ethereum_service_node_removal& eth_extra,
        std::string* reason) {

    {
        if (check_condition(
                    tx.type != cryptonote::txtype::ethereum_service_node_removal,
                    reason,
                    "{} uses wrong tx type, expected={}",
                    tx,
                    cryptonote::txtype::ethereum_service_node_removal))
            return false;

        if (check_condition(
                    !cryptonote::get_field_from_tx_extra(tx.extra, eth_extra),
                    reason,
                    "{} didn't have ethereum service node removal data in the tx_extra",
                    tx))
            return false;
    }

    return true;
}

bool validate_ethereum_service_node_liquidated_tx(
        hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_ethereum_service_node_liquidated& eth_extra,
        std::string* reason) {

    {
        if (check_condition(
                    tx.type != cryptonote::txtype::ethereum_service_node_liquidated,
                    reason,
                    "{} uses wrong tx type, expected={}",
                    tx,
                    cryptonote::txtype::ethereum_service_node_liquidated))
            return false;

        if (check_condition(
                    !cryptonote::get_field_from_tx_extra(tx.extra, eth_extra),
                    reason,
                    "{} didn't have ethereum service node liquidated data in the tx_extra",
                    tx))
            return false;
    }

    return true;
}

}  // namespace eth
