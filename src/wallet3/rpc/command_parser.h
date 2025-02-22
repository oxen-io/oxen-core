#pragma once

#include <oxenc/bt_serialize.h>

#include <nlohmann/json.hpp>

#include "commands.h"

namespace wallet::rpc {

using rpc_input = std::variant<std::monostate, nlohmann::json, oxenc::bt_dict_consumer>;

inline void parse_request(NO_ARGS&, rpc_input) {}

void parse_request(GET_BALANCE& req, rpc_input in);
void parse_request(GET_ADDRESS& req, rpc_input in);
void parse_request(GET_ADDRESS_INDEX& req, rpc_input in);
void parse_request(CREATE_ADDRESS& req, rpc_input in);
void parse_request(LABEL_ADDRESS& req, rpc_input in);
void parse_request(GET_ACCOUNTS& req, rpc_input in);
void parse_request(CREATE_ACCOUNT& req, rpc_input in);
void parse_request(LABEL_ACCOUNT& req, rpc_input in);
void parse_request(GET_ACCOUNT_TAGS& req, rpc_input in);
void parse_request(TAG_ACCOUNTS& req, rpc_input in);
void parse_request(UNTAG_ACCOUNTS& req, rpc_input in);
void parse_request(SET_ACCOUNT_TAG_DESCRIPTION& req, rpc_input in);
void parse_request(GET_HEIGHT& req, rpc_input in);
void parse_request(TRANSFER& req, rpc_input in);
void parse_request(TRANSFER_SPLIT& req, rpc_input in);
void parse_request(DESCRIBE_TRANSFER& req, rpc_input in);
void parse_request(SIGN_TRANSFER& req, rpc_input in);
void parse_request(SUBMIT_TRANSFER& req, rpc_input in);
void parse_request(SWEEP_DUST& req, rpc_input in);
void parse_request(SWEEP_ALL& req, rpc_input in);
void parse_request(SWEEP_SINGLE& req, rpc_input in);
void parse_request(RELAY_TX& req, rpc_input in);
void parse_request(STORE& req, rpc_input in);
void parse_request(GET_PAYMENTS& req, rpc_input in);
void parse_request(GET_BULK_PAYMENTS& req, rpc_input in);
void parse_request(INCOMING_TRANSFERS& req, rpc_input in);
void parse_request(EXPORT_VIEW_KEY& req, rpc_input in);
void parse_request(EXPORT_SPEND_KEY& req, rpc_input in);
void parse_request(EXPORT_MNEMONIC_KEY& req, rpc_input in);
void parse_request(MAKE_INTEGRATED_ADDRESS& req, rpc_input in);
void parse_request(SPLIT_INTEGRATED_ADDRESS& req, rpc_input in);
void parse_request(STOP_WALLET& req, rpc_input in);
void parse_request(RESCAN_BLOCKCHAIN& req, rpc_input in);
void parse_request(SET_TX_NOTES& req, rpc_input in);
void parse_request(GET_TX_NOTES& req, rpc_input in);
void parse_request(SET_ATTRIBUTE& req, rpc_input in);
void parse_request(GET_ATTRIBUTE& req, rpc_input in);
void parse_request(GET_TX_KEY& req, rpc_input in);
void parse_request(CHECK_TX_KEY& req, rpc_input in);
void parse_request(GET_TX_PROOF& req, rpc_input in);
void parse_request(CHECK_TX_PROOF& req, rpc_input in);
void parse_request(GET_SPEND_PROOF& req, rpc_input in);
void parse_request(CHECK_SPEND_PROOF& req, rpc_input in);
void parse_request(GET_RESERVE_PROOF& req, rpc_input in);
void parse_request(CHECK_RESERVE_PROOF& req, rpc_input in);
void parse_request(GET_TRANSFERS& req, rpc_input in);
void parse_request(GET_TRANSFERS_CSV& req, rpc_input in);
void parse_request(GET_TRANSFER_BY_TXID& req, rpc_input in);
void parse_request(SIGN& req, rpc_input in);
void parse_request(VERIFY& req, rpc_input in);
void parse_request(EXPORT_OUTPUTS& req, rpc_input in);
void parse_request(EXPORT_TRANSFERS& req, rpc_input in);
void parse_request(IMPORT_OUTPUTS& req, rpc_input in);
void parse_request(EXPORT_KEY_IMAGES& req, rpc_input in);
void parse_request(IMPORT_KEY_IMAGES& req, rpc_input in);
void parse_request(MAKE_URI& req, rpc_input in);
void parse_request(PARSE_URI& req, rpc_input in);
void parse_request(ADD_ADDRESS_BOOK_ENTRY& req, rpc_input in);
void parse_request(EDIT_ADDRESS_BOOK_ENTRY& req, rpc_input in);
void parse_request(GET_ADDRESS_BOOK_ENTRY& req, rpc_input in);
void parse_request(DELETE_ADDRESS_BOOK_ENTRY& req, rpc_input in);
void parse_request(RESCAN_SPENT& req, rpc_input in);
void parse_request(REFRESH& req, rpc_input in);
void parse_request(AUTO_REFRESH& req, rpc_input in);
void parse_request(START_MINING& req, rpc_input in);
void parse_request(STOP_MINING& req, rpc_input in);
void parse_request(GET_LANGUAGES& req, rpc_input in);
void parse_request(CREATE_WALLET& req, rpc_input in);
void parse_request(OPEN_WALLET& req, rpc_input in);
void parse_request(CLOSE_WALLET& req, rpc_input in);
void parse_request(CHANGE_WALLET_PASSWORD& req, rpc_input in);
void parse_request(GENERATE_FROM_KEYS& req, rpc_input in);
void parse_request(RESTORE_DETERMINISTIC_WALLET& req, rpc_input in);
void parse_request(IS_MULTISIG& req, rpc_input in);
void parse_request(PREPARE_MULTISIG& req, rpc_input in);
void parse_request(MAKE_MULTISIG& req, rpc_input in);
void parse_request(EXPORT_MULTISIG& req, rpc_input in);
void parse_request(IMPORT_MULTISIG& req, rpc_input in);
void parse_request(FINALIZE_MULTISIG& req, rpc_input in);
void parse_request(EXCHANGE_MULTISIG_KEYS& req, rpc_input in);
void parse_request(SIGN_MULTISIG& req, rpc_input in);
void parse_request(SUBMIT_MULTISIG& req, rpc_input in);
void parse_request(GET_VERSION& req, rpc_input in);
void parse_request(STAKE& req, rpc_input in);
void parse_request(REGISTER_SERVICE_NODE& req, rpc_input in);
void parse_request(REQUEST_STAKE_UNLOCK& req, rpc_input in);
void parse_request(CAN_REQUEST_STAKE_UNLOCK& req, rpc_input in);
void parse_request(VALIDATE_ADDRESS& req, rpc_input in);
void parse_request(SET_DAEMON& req, rpc_input in);
void parse_request(SET_LOG_LEVEL& req, rpc_input in);
void parse_request(SET_LOG_CATEGORIES& req, rpc_input in);
void parse_request(ONS_BUY_MAPPING& req, rpc_input in);
void parse_request(ONS_RENEW_MAPPING& req, rpc_input in);
void parse_request(ONS_UPDATE_MAPPING& req, rpc_input in);
void parse_request(ONS_MAKE_UPDATE_SIGNATURE& req, rpc_input in);
void parse_request(ONS_HASH_NAME& req, rpc_input in);
void parse_request(ONS_KNOWN_NAMES& req, rpc_input in);
void parse_request(ONS_ADD_KNOWN_NAMES& req, rpc_input in);
void parse_request(ONS_ENCRYPT_VALUE& req, rpc_input in);
void parse_request(ONS_DECRYPT_VALUE& req, rpc_input in);

}  // namespace wallet::rpc
