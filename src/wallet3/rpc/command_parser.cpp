#include "command_parser.h"

#include "oxenmq/bt_serialize.h"
#include "rpc/common/param_parser.hpp"

#include <nlohmann/json.hpp>

namespace wallet::rpc {

using nlohmann::json;
using cryptonote::rpc::required;

using rpc_input = std::variant<std::monostate, nlohmann::json, oxenmq::bt_dict_consumer>;


void parse_request(GET_BALANCE& argname, rpc_input in) {
}

void parse_request(GET_ADDRESS& argname, rpc_input in) {
}

void parse_request(GET_ADDRESS_INDEX& argname, rpc_input in) {
}

void parse_request(CREATE_ADDRESS& argname, rpc_input in) {
}

void parse_request(LABEL_ADDRESS& argname, rpc_input in) {
}

void parse_request(GET_ACCOUNTS& argname, rpc_input in) {
}

void parse_request(CREATE_ACCOUNT& argname, rpc_input in) {
}

void parse_request(LABEL_ACCOUNT& argname, rpc_input in) {
}

void parse_request(GET_ACCOUNT_TAGS& argname, rpc_input in) {
}

void parse_request(TAG_ACCOUNTS& argname, rpc_input in) {
}

void parse_request(UNTAG_ACCOUNTS& argname, rpc_input in) {
}

void parse_request(SET_ACCOUNT_TAG_DESCRIPTION& argname, rpc_input in) {
}

void parse_request(GET_HEIGHT& argname, rpc_input in) {
}

void parse_request(TRANSFER& argname, rpc_input in) {
}

void parse_request(TRANSFER_SPLIT& argname, rpc_input in) {
}

void parse_request(DESCRIBE_TRANSFER& argname, rpc_input in) {
}

void parse_request(SIGN_TRANSFER& argname, rpc_input in) {
}

void parse_request(SUBMIT_TRANSFER& argname, rpc_input in) {
}

void parse_request(SWEEP_DUST& argname, rpc_input in) {
}

void parse_request(SWEEP_ALL& argname, rpc_input in) {
}

void parse_request(SWEEP_SINGLE& argname, rpc_input in) {
}

void parse_request(RELAY_TX& argname, rpc_input in) {
}

void parse_request(STORE& argname, rpc_input in) {
}

void parse_request(GET_PAYMENTS& argname, rpc_input in) {
}

void parse_request(GET_BULK_PAYMENTS& argname, rpc_input in) {
}

void parse_request(INCOMING_TRANSFERS& argname, rpc_input in) {
}

void parse_request(QUERY_KEY& argname, rpc_input in) {
}

void parse_request(MAKE_INTEGRATED_ADDRESS& argname, rpc_input in) {
}

void parse_request(SPLIT_INTEGRATED_ADDRESS& argname, rpc_input in) {
}

void parse_request(STOP_WALLET& argname, rpc_input in) {
}

void parse_request(RESCAN_BLOCKCHAIN& argname, rpc_input in) {
}

void parse_request(SET_TX_NOTES& argname, rpc_input in) {
}

void parse_request(GET_TX_NOTES& argname, rpc_input in) {
}

void parse_request(SET_ATTRIBUTE& argname, rpc_input in) {
}

void parse_request(GET_ATTRIBUTE& argname, rpc_input in) {
}

void parse_request(GET_TX_KEY& argname, rpc_input in) {
}

void parse_request(CHECK_TX_KEY& argname, rpc_input in) {
}

void parse_request(GET_TX_PROOF& argname, rpc_input in) {
}

void parse_request(CHECK_TX_PROOF& argname, rpc_input in) {
}

void parse_request(GET_SPEND_PROOF& argname, rpc_input in) {
}

void parse_request(CHECK_SPEND_PROOF& argname, rpc_input in) {
}

void parse_request(GET_RESERVE_PROOF& argname, rpc_input in) {
}

void parse_request(CHECK_RESERVE_PROOF& argname, rpc_input in) {
}

void parse_request(GET_TRANSFERS& argname, rpc_input in) {
}

void parse_request(GET_TRANSFERS_CSV& argname, rpc_input in) {
}

void parse_request(GET_TRANSFER_BY_TXID& argname, rpc_input in) {
}

void parse_request(SIGN& argname, rpc_input in) {
}

void parse_request(VERIFY& argname, rpc_input in) {
}

void parse_request(EXPORT_OUTPUTS& argname, rpc_input in) {
}

void parse_request(EXPORT_TRANSFERS& argname, rpc_input in) {
}

void parse_request(IMPORT_OUTPUTS& argname, rpc_input in) {
}

void parse_request(EXPORT_KEY_IMAGES& argname, rpc_input in) {
}

void parse_request(IMPORT_KEY_IMAGES& argname, rpc_input in) {
}

void parse_request(MAKE_URI& argname, rpc_input in) {
}

void parse_request(PARSE_URI& argname, rpc_input in) {
}

void parse_request(ADD_ADDRESS_BOOK_ENTRY& argname, rpc_input in) {
}

void parse_request(EDIT_ADDRESS_BOOK_ENTRY& argname, rpc_input in) {
}

void parse_request(GET_ADDRESS_BOOK_ENTRY& argname, rpc_input in) {
}

void parse_request(DELETE_ADDRESS_BOOK_ENTRY& argname, rpc_input in) {
}

void parse_request(RESCAN_SPENT& argname, rpc_input in) {
}

void parse_request(REFRESH& argname, rpc_input in) {
}

void parse_request(AUTO_REFRESH& argname, rpc_input in) {
}

void parse_request(START_MINING& argname, rpc_input in) {
}

void parse_request(STOP_MINING& argname, rpc_input in) {
}

void parse_request(GET_LANGUAGES& argname, rpc_input in) {
}

void parse_request(CREATE_WALLET& argname, rpc_input in) {
}

void parse_request(OPEN_WALLET& argname, rpc_input in) {
}

void parse_request(CLOSE_WALLET& argname, rpc_input in) {
}

void parse_request(CHANGE_WALLET_PASSWORD& argname, rpc_input in) {
}

void parse_request(GENERATE_FROM_KEYS& argname, rpc_input in) {
}

void parse_request(RESTORE_DETERMINISTIC_WALLET& argname, rpc_input in) {
}

void parse_request(IS_MULTISIG& argname, rpc_input in) {
}

void parse_request(PREPARE_MULTISIG& argname, rpc_input in) {
}

void parse_request(MAKE_MULTISIG& argname, rpc_input in) {
}

void parse_request(EXPORT_MULTISIG& argname, rpc_input in) {
}

void parse_request(IMPORT_MULTISIG& argname, rpc_input in) {
}

void parse_request(FINALIZE_MULTISIG& argname, rpc_input in) {
}

void parse_request(EXCHANGE_MULTISIG_KEYS& argname, rpc_input in) {
}

void parse_request(SIGN_MULTISIG& argname, rpc_input in) {
}

void parse_request(SUBMIT_MULTISIG& argname, rpc_input in) {
}

void parse_request(GET_VERSION& argname, rpc_input in) {
}

void parse_request(STAKE& argname, rpc_input in) {
}

void parse_request(REGISTER_SERVICE_NODE& argname, rpc_input in) {
}

void parse_request(REQUEST_STAKE_UNLOCK& argname, rpc_input in) {
}

void parse_request(CAN_REQUEST_STAKE_UNLOCK& argname, rpc_input in) {
}

void parse_request(VALIDATE_ADDRESS& argname, rpc_input in) {
}

void parse_request(SET_DAEMON& argname, rpc_input in) {
}

void parse_request(SET_LOG_LEVEL& argname, rpc_input in) {
}

void parse_request(SET_LOG_CATEGORIES& argname, rpc_input in) {
}

void parse_request(ONS_BUY_MAPPING& argname, rpc_input in) {
}

void parse_request(ONS_RENEW_MAPPING& argname, rpc_input in) {
}

void parse_request(ONS_UPDATE_MAPPING& argname, rpc_input in) {
}

void parse_request(ONS_MAKE_UPDATE_SIGNATURE& argname, rpc_input in) {
}

void parse_request(ONS_HASH_NAME& argname, rpc_input in) {
}

void parse_request(ONS_KNOWN_NAMES& argname, rpc_input in) {
}

void parse_request(ONS_ADD_KNOWN_NAMES& argname, rpc_input in) {
}

void parse_request(ONS_ENCRYPT_VALUE& argname, rpc_input in) {
}

void parse_request(ONS_DECRYPT_VALUE& argname, rpc_input in) {
}

} // namespace wallet::rpc
