#pragma once

#include <oxenc/bt_value.h>

#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>
#include <wallet3/pending_transaction.hpp>

#include "commands.h"
#include "rpc/common/rpc_command.h"

namespace wallet {
class Wallet;
}
namespace wallet::rpc {

class RequestHandler;

using cryptonote::rpc::rpc_context;
using cryptonote::rpc::rpc_request;

/// Stores an RPC command callback.  These are set up in request_handler.cpp.
struct rpc_command {
    using result_type = std::variant<oxenc::bt_value, nlohmann::json, std::string>;
    // Called with the incoming command data; returns the response body if all goes well,
    // otherwise throws an exception.
    result_type (*invoke)(rpc_request&&, RequestHandler&);
    bool is_restricted;  // only callable via restricted RPC
};

/// RPC command registration; to add a new command, define it in commands.h
/// and then actually do the registration in request_handler.cpp.
extern const std::unordered_map<std::string, std::shared_ptr<const rpc_command>> rpc_commands;

class RequestHandler {

    std::weak_ptr<wallet::Wallet> wallet;

  public:
    void set_wallet(std::weak_ptr<wallet::Wallet> wallet);

    std::string submit_transaction(wallet::PendingTransaction& ptx);

    void invoke(GET_BALANCE& command, rpc_context context);
    void invoke(GET_ADDRESS& command, rpc_context context);
    void invoke(GET_ADDRESS_INDEX& command, rpc_context context);
    void invoke(CREATE_ADDRESS& command, rpc_context context);
    void invoke(LABEL_ADDRESS& command, rpc_context context);
    void invoke(GET_ACCOUNTS& command, rpc_context context);
    void invoke(CREATE_ACCOUNT& command, rpc_context context);
    void invoke(LABEL_ACCOUNT& command, rpc_context context);
    void invoke(GET_ACCOUNT_TAGS& command, rpc_context context);
    void invoke(TAG_ACCOUNTS& command, rpc_context context);
    void invoke(UNTAG_ACCOUNTS& command, rpc_context context);
    void invoke(SET_ACCOUNT_TAG_DESCRIPTION& command, rpc_context context);
    void invoke(GET_HEIGHT& command, rpc_context context);
    void invoke(TRANSFER& command, rpc_context context);
    void invoke(TRANSFER_SPLIT& command, rpc_context context);
    void invoke(DESCRIBE_TRANSFER& command, rpc_context context);
    void invoke(SIGN_TRANSFER& command, rpc_context context);
    void invoke(SUBMIT_TRANSFER& command, rpc_context context);
    void invoke(SWEEP_DUST& command, rpc_context context);
    void invoke(SWEEP_ALL& command, rpc_context context);
    void invoke(SWEEP_SINGLE& command, rpc_context context);
    void invoke(RELAY_TX& command, rpc_context context);
    void invoke(STORE& command, rpc_context context);
    void invoke(GET_PAYMENTS& command, rpc_context context);
    void invoke(GET_BULK_PAYMENTS& command, rpc_context context);
    void invoke(INCOMING_TRANSFERS& command, rpc_context context);
    void invoke(EXPORT_VIEW_KEY& command, rpc_context context);
    void invoke(EXPORT_SPEND_KEY& command, rpc_context context);
    void invoke(EXPORT_MNEMONIC_KEY& command, rpc_context context);
    void invoke(MAKE_INTEGRATED_ADDRESS& command, rpc_context context);
    void invoke(SPLIT_INTEGRATED_ADDRESS& command, rpc_context context);
    void invoke(STOP_WALLET& command, rpc_context context);
    void invoke(RESCAN_BLOCKCHAIN& command, rpc_context context);
    void invoke(SET_TX_NOTES& command, rpc_context context);
    void invoke(GET_TX_NOTES& command, rpc_context context);
    void invoke(SET_ATTRIBUTE& command, rpc_context context);
    void invoke(GET_ATTRIBUTE& command, rpc_context context);
    void invoke(GET_TX_KEY& command, rpc_context context);
    void invoke(CHECK_TX_KEY& command, rpc_context context);
    void invoke(GET_TX_PROOF& command, rpc_context context);
    void invoke(CHECK_TX_PROOF& command, rpc_context context);
    void invoke(GET_SPEND_PROOF& command, rpc_context context);
    void invoke(CHECK_SPEND_PROOF& command, rpc_context context);
    void invoke(GET_RESERVE_PROOF& command, rpc_context context);
    void invoke(CHECK_RESERVE_PROOF& command, rpc_context context);
    void invoke(GET_TRANSFERS& command, rpc_context context);
    void invoke(GET_TRANSFERS_CSV& command, rpc_context context);
    void invoke(GET_TRANSFER_BY_TXID& command, rpc_context context);
    void invoke(SIGN& command, rpc_context context);
    void invoke(VERIFY& command, rpc_context context);
    void invoke(EXPORT_OUTPUTS& command, rpc_context context);
    void invoke(EXPORT_TRANSFERS& command, rpc_context context);
    void invoke(IMPORT_OUTPUTS& command, rpc_context context);
    void invoke(EXPORT_KEY_IMAGES& command, rpc_context context);
    void invoke(IMPORT_KEY_IMAGES& command, rpc_context context);
    void invoke(MAKE_URI& command, rpc_context context);
    void invoke(PARSE_URI& command, rpc_context context);
    void invoke(ADD_ADDRESS_BOOK_ENTRY& command, rpc_context context);
    void invoke(EDIT_ADDRESS_BOOK_ENTRY& command, rpc_context context);
    void invoke(GET_ADDRESS_BOOK_ENTRY& command, rpc_context context);
    void invoke(DELETE_ADDRESS_BOOK_ENTRY& command, rpc_context context);
    void invoke(RESCAN_SPENT& command, rpc_context context);
    void invoke(REFRESH& command, rpc_context context);
    void invoke(AUTO_REFRESH& command, rpc_context context);
    void invoke(START_MINING& command, rpc_context context);
    void invoke(STOP_MINING& command, rpc_context context);
    void invoke(GET_LANGUAGES& command, rpc_context context);
    void invoke(CREATE_WALLET& command, rpc_context context);
    void invoke(OPEN_WALLET& command, rpc_context context);
    void invoke(CLOSE_WALLET& command, rpc_context context);
    void invoke(CHANGE_WALLET_PASSWORD& command, rpc_context context);
    void invoke(GENERATE_FROM_KEYS& command, rpc_context context);
    void invoke(RESTORE_DETERMINISTIC_WALLET& command, rpc_context context);
    void invoke(IS_MULTISIG& command, rpc_context context);
    void invoke(PREPARE_MULTISIG& command, rpc_context context);
    void invoke(MAKE_MULTISIG& command, rpc_context context);
    void invoke(EXPORT_MULTISIG& command, rpc_context context);
    void invoke(IMPORT_MULTISIG& command, rpc_context context);
    void invoke(FINALIZE_MULTISIG& command, rpc_context context);
    void invoke(EXCHANGE_MULTISIG_KEYS& command, rpc_context context);
    void invoke(SIGN_MULTISIG& command, rpc_context context);
    void invoke(SUBMIT_MULTISIG& command, rpc_context context);
    void invoke(GET_VERSION& command, rpc_context context);
    void invoke(STAKE& command, rpc_context context);
    void invoke(REGISTER_SERVICE_NODE& command, rpc_context context);
    void invoke(REQUEST_STAKE_UNLOCK& command, rpc_context context);
    void invoke(CAN_REQUEST_STAKE_UNLOCK& command, rpc_context context);
    void invoke(VALIDATE_ADDRESS& command, rpc_context context);
    void invoke(SET_DAEMON& command, rpc_context context);
    void invoke(SET_LOG_LEVEL& command, rpc_context context);
    void invoke(SET_LOG_CATEGORIES& command, rpc_context context);
    void invoke(ONS_BUY_MAPPING& command, rpc_context context);
    void invoke(ONS_RENEW_MAPPING& command, rpc_context context);
    void invoke(ONS_UPDATE_MAPPING& command, rpc_context context);
    void invoke(ONS_MAKE_UPDATE_SIGNATURE& command, rpc_context context);
    void invoke(ONS_HASH_NAME& command, rpc_context context);
    void invoke(ONS_KNOWN_NAMES& command, rpc_context context);
    void invoke(ONS_ADD_KNOWN_NAMES& command, rpc_context context);
    void invoke(ONS_ENCRYPT_VALUE& command, rpc_context context);
    void invoke(ONS_DECRYPT_VALUE& command, rpc_context context);
    void invoke(STATUS& command, rpc_context context);
};

}  // namespace wallet::rpc
