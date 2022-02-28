#include "request_handler.h"

#include "commands.h"
#include "command_parser.h"
#include <wallet3/wallet.hpp>

#include <wallet3/db_schema.hpp>

#include <unordered_map>
#include <memory>


namespace wallet::rpc {

using cryptonote::rpc::rpc_context;
using cryptonote::rpc::rpc_request;

  namespace {

  template <typename RPC>
  void register_rpc_command(std::unordered_map<std::string, std::shared_ptr<const rpc_command>>& regs)
  {
    using cryptonote::rpc::RPC_COMMAND;
    using cryptonote::rpc::RESTRICTED;

    static_assert(std::is_base_of_v<RPC_COMMAND, RPC>);
    auto cmd = std::make_shared<rpc_command>();
    cmd->is_restricted = std::is_base_of_v<RESTRICTED, RPC>;

    cmd->invoke = cryptonote::rpc::make_invoke<RPC, RequestHandler, rpc_command>();
      
    for (const auto& name : RPC::names())
      regs.emplace(name, cmd);
  }

  template <typename... RPC, typename... BinaryRPC>
  std::unordered_map<std::string, std::shared_ptr<const rpc_command>> register_rpc_commands(tools::type_list<RPC...>) {
    std::unordered_map<std::string, std::shared_ptr<const rpc_command>> regs;

    (register_rpc_command<RPC>(regs), ...);

    return regs;
  }

  } // anonymous namespace

const std::unordered_map<std::string, std::shared_ptr<const rpc_command>> rpc_commands = register_rpc_commands(wallet_rpc_types{});

void RequestHandler::invoke(GET_BALANCE& command, rpc_context context) {
}

void RequestHandler::invoke(GET_ADDRESS& command, rpc_context context) {
}

void RequestHandler::invoke(GET_ADDRESS_INDEX& command, rpc_context context) {
}

void RequestHandler::invoke(CREATE_ADDRESS& command, rpc_context context) {
}

void RequestHandler::invoke(LABEL_ADDRESS& command, rpc_context context) {
}

void RequestHandler::invoke(GET_ACCOUNTS& command, rpc_context context) {
}

void RequestHandler::invoke(CREATE_ACCOUNT& command, rpc_context context) {
}

void RequestHandler::invoke(LABEL_ACCOUNT& command, rpc_context context) {
}

void RequestHandler::invoke(GET_ACCOUNT_TAGS& command, rpc_context context) {
}

void RequestHandler::invoke(TAG_ACCOUNTS& command, rpc_context context) {
}

void RequestHandler::invoke(UNTAG_ACCOUNTS& command, rpc_context context) {
}

void RequestHandler::invoke(SET_ACCOUNT_TAG_DESCRIPTION& command, rpc_context context) {
}

void RequestHandler::invoke(GET_HEIGHT& command, rpc_context context) {
  auto height = wallet.db->scan_target_height();
  command.response["height"] = height;

  //TODO: this
  command.response["immutable_height"] = height;
}

void RequestHandler::invoke(TRANSFER& command, rpc_context context) {
}

void RequestHandler::invoke(TRANSFER_SPLIT& command, rpc_context context) {
}

void RequestHandler::invoke(DESCRIBE_TRANSFER& command, rpc_context context) {
}

void RequestHandler::invoke(SIGN_TRANSFER& command, rpc_context context) {
}

void RequestHandler::invoke(SUBMIT_TRANSFER& command, rpc_context context) {
}

void RequestHandler::invoke(SWEEP_DUST& command, rpc_context context) {
}

void RequestHandler::invoke(SWEEP_ALL& command, rpc_context context) {
}

void RequestHandler::invoke(SWEEP_SINGLE& command, rpc_context context) {
}

void RequestHandler::invoke(RELAY_TX& command, rpc_context context) {
}

void RequestHandler::invoke(STORE& command, rpc_context context) {
}

void RequestHandler::invoke(GET_PAYMENTS& command, rpc_context context) {
}

void RequestHandler::invoke(GET_BULK_PAYMENTS& command, rpc_context context) {
}

void RequestHandler::invoke(INCOMING_TRANSFERS& command, rpc_context context) {
}

void RequestHandler::invoke(QUERY_KEY& command, rpc_context context) {
}

void RequestHandler::invoke(MAKE_INTEGRATED_ADDRESS& command, rpc_context context) {
}

void RequestHandler::invoke(SPLIT_INTEGRATED_ADDRESS& command, rpc_context context) {
}

void RequestHandler::invoke(STOP_WALLET& command, rpc_context context) {
}

void RequestHandler::invoke(RESCAN_BLOCKCHAIN& command, rpc_context context) {
}

void RequestHandler::invoke(SET_TX_NOTES& command, rpc_context context) {
}

void RequestHandler::invoke(GET_TX_NOTES& command, rpc_context context) {
}

void RequestHandler::invoke(SET_ATTRIBUTE& command, rpc_context context) {
}

void RequestHandler::invoke(GET_ATTRIBUTE& command, rpc_context context) {
}

void RequestHandler::invoke(GET_TX_KEY& command, rpc_context context) {
}

void RequestHandler::invoke(CHECK_TX_KEY& command, rpc_context context) {
}

void RequestHandler::invoke(GET_TX_PROOF& command, rpc_context context) {
}

void RequestHandler::invoke(CHECK_TX_PROOF& command, rpc_context context) {
}

void RequestHandler::invoke(GET_SPEND_PROOF& command, rpc_context context) {
}

void RequestHandler::invoke(CHECK_SPEND_PROOF& command, rpc_context context) {
}

void RequestHandler::invoke(GET_RESERVE_PROOF& command, rpc_context context) {
}

void RequestHandler::invoke(CHECK_RESERVE_PROOF& command, rpc_context context) {
}

void RequestHandler::invoke(GET_TRANSFERS& command, rpc_context context) {
}

void RequestHandler::invoke(GET_TRANSFERS_CSV& command, rpc_context context) {
}

void RequestHandler::invoke(GET_TRANSFER_BY_TXID& command, rpc_context context) {
}

void RequestHandler::invoke(SIGN& command, rpc_context context) {
}

void RequestHandler::invoke(VERIFY& command, rpc_context context) {
}

void RequestHandler::invoke(EXPORT_OUTPUTS& command, rpc_context context) {
}

void RequestHandler::invoke(EXPORT_TRANSFERS& command, rpc_context context) {
}

void RequestHandler::invoke(IMPORT_OUTPUTS& command, rpc_context context) {
}

void RequestHandler::invoke(EXPORT_KEY_IMAGES& command, rpc_context context) {
}

void RequestHandler::invoke(IMPORT_KEY_IMAGES& command, rpc_context context) {
}

void RequestHandler::invoke(MAKE_URI& command, rpc_context context) {
}

void RequestHandler::invoke(PARSE_URI& command, rpc_context context) {
}

void RequestHandler::invoke(ADD_ADDRESS_BOOK_ENTRY& command, rpc_context context) {
}

void RequestHandler::invoke(EDIT_ADDRESS_BOOK_ENTRY& command, rpc_context context) {
}

void RequestHandler::invoke(GET_ADDRESS_BOOK_ENTRY& command, rpc_context context) {
}

void RequestHandler::invoke(DELETE_ADDRESS_BOOK_ENTRY& command, rpc_context context) {
}

void RequestHandler::invoke(RESCAN_SPENT& command, rpc_context context) {
}

void RequestHandler::invoke(REFRESH& command, rpc_context context) {
}

void RequestHandler::invoke(AUTO_REFRESH& command, rpc_context context) {
}

void RequestHandler::invoke(START_MINING& command, rpc_context context) {
}

void RequestHandler::invoke(STOP_MINING& command, rpc_context context) {
}

void RequestHandler::invoke(GET_LANGUAGES& command, rpc_context context) {
}

void RequestHandler::invoke(CREATE_WALLET& command, rpc_context context) {
}

void RequestHandler::invoke(OPEN_WALLET& command, rpc_context context) {
}

void RequestHandler::invoke(CLOSE_WALLET& command, rpc_context context) {
}

void RequestHandler::invoke(CHANGE_WALLET_PASSWORD& command, rpc_context context) {
}

void RequestHandler::invoke(GENERATE_FROM_KEYS& command, rpc_context context) {
}

void RequestHandler::invoke(RESTORE_DETERMINISTIC_WALLET& command, rpc_context context) {
}

void RequestHandler::invoke(IS_MULTISIG& command, rpc_context context) {
}

void RequestHandler::invoke(PREPARE_MULTISIG& command, rpc_context context) {
}

void RequestHandler::invoke(MAKE_MULTISIG& command, rpc_context context) {
}

void RequestHandler::invoke(EXPORT_MULTISIG& command, rpc_context context) {
}

void RequestHandler::invoke(IMPORT_MULTISIG& command, rpc_context context) {
}

void RequestHandler::invoke(FINALIZE_MULTISIG& command, rpc_context context) {
}

void RequestHandler::invoke(EXCHANGE_MULTISIG_KEYS& command, rpc_context context) {
}

void RequestHandler::invoke(SIGN_MULTISIG& command, rpc_context context) {
}

void RequestHandler::invoke(SUBMIT_MULTISIG& command, rpc_context context) {
}

void RequestHandler::invoke(GET_VERSION& command, rpc_context context) {
}

void RequestHandler::invoke(STAKE& command, rpc_context context) {
}

void RequestHandler::invoke(REGISTER_SERVICE_NODE& command, rpc_context context) {
}

void RequestHandler::invoke(REQUEST_STAKE_UNLOCK& command, rpc_context context) {
}

void RequestHandler::invoke(CAN_REQUEST_STAKE_UNLOCK& command, rpc_context context) {
}

void RequestHandler::invoke(VALIDATE_ADDRESS& command, rpc_context context) {
}

void RequestHandler::invoke(SET_DAEMON& command, rpc_context context) {
}

void RequestHandler::invoke(SET_LOG_LEVEL& command, rpc_context context) {
}

void RequestHandler::invoke(SET_LOG_CATEGORIES& command, rpc_context context) {
}

void RequestHandler::invoke(ONS_BUY_MAPPING& command, rpc_context context) {
}

void RequestHandler::invoke(ONS_RENEW_MAPPING& command, rpc_context context) {
}

void RequestHandler::invoke(ONS_UPDATE_MAPPING& command, rpc_context context) {
}

void RequestHandler::invoke(ONS_MAKE_UPDATE_SIGNATURE& command, rpc_context context) {
}

void RequestHandler::invoke(ONS_HASH_NAME& command, rpc_context context) {
}

void RequestHandler::invoke(ONS_KNOWN_NAMES& command, rpc_context context) {
}

void RequestHandler::invoke(ONS_ADD_KNOWN_NAMES& command, rpc_context context) {
}

void RequestHandler::invoke(ONS_ENCRYPT_VALUE& command, rpc_context context) {
}

void RequestHandler::invoke(ONS_DECRYPT_VALUE& command, rpc_context context) {
}


} // namespace wallet::rpc
