#pragma once

#include <cstdint>
#include <string>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_config.h"

namespace ethereum {

bool validate_ethereum_address_notification_tx(
        cryptonote::hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_ethereum_address_notification& eth_extra,
        std::string* reason);

bool validate_ethereum_new_service_node_tx(
        cryptonote::hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_ethereum_new_service_node& eth_extra,
        std::string* reason);

bool validate_ethereum_service_node_leave_request_tx(
        cryptonote::hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_ethereum_service_node_leave_request& eth_extra,
        std::string* reason);

bool validate_ethereum_service_node_exit_tx(
        cryptonote::hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_ethereum_service_node_exit& eth_extra,
        std::string* reason);

bool validate_ethereum_service_node_deregister_tx(
        cryptonote::hf hf_version,
        uint64_t blockchain_height,
        cryptonote::transaction const& tx,
        cryptonote::tx_extra_ethereum_service_node_deregister& eth_extra,
        std::string* reason);

}  // namespace ethereum
