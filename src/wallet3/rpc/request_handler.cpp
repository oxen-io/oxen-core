#include "request_handler.h"

#include "commands.h"
#include "command_parser.h"
#include <wallet3/wallet.hpp>
#include <wallet3/db_schema.hpp>
#include <wallet3/version.hpp>

#include <cryptonote_core/cryptonote_tx_utils.h>

#include <unordered_map>
#include <memory>

#include <common/hex.h>
#include "mnemonics/electrum-words.h"



namespace wallet::rpc {

using cryptonote::rpc::rpc_context;
using cryptonote::rpc::rpc_request;
using cryptonote::rpc::rpc_error;

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
  if (auto w = wallet.lock())
  {
    command.response["balance"] = w->get_balance();
    command.response["unlocked_balance"] = w->get_unlocked_balance();
  }
  //TODO handle subaddresses and params passed for them
}

void RequestHandler::invoke(GET_ADDRESS& command, rpc_context context) {
  if (auto w = wallet.lock())
  {
    auto& addresses = (command.response["addresses"] = json::array());
    if (command.request.address_index.size() == 0)
    {
      auto address = w->get_subaddress(command.request.account_index, 0);
      addresses.push_back(json{
        {"address", address.as_str(cryptonote::MAINNET)},
        {"label", ""},
        {"address_index", command.request.address_index},
        {"used", true}
      });
    } else {
      for (const auto& address_index: command.request.address_index)
      {
        auto address = w->get_subaddress(command.request.account_index, address_index);
        addresses.push_back(json{
          {"address", address.as_str(cryptonote::MAINNET)},
          {"label", ""},
          {"address_index", command.request.address_index},
          {"used", true}
        });
      }
    }
  }
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
  if (auto w = wallet.lock())
  {
    auto height = w->db->scan_target_height();
    command.response["height"] = height;

    //TODO: this
    command.response["immutable_height"] = height;
  }
}

void RequestHandler::invoke(TRANSFER& command, rpc_context context) {
  if (auto w = wallet.lock())
  {
    // TODO: arg checking
    // TODO: actually use all args

    std::vector<cryptonote::tx_destination_entry> recipients;
    for (const auto& [dest, amount] : command.request.destinations)
    {
      auto& entry = recipients.emplace_back();
      cryptonote::address_parse_info addr_info;

      if (not cryptonote::get_account_address_from_str(addr_info, w->nettype, dest))
        //TODO: is 500 the "correct" error code?
        throw rpc_error(500, std::string("Invalid destination: ") + dest);

      entry.original = dest;
      entry.amount = amount;
      entry.addr = addr_info.address;
      entry.is_subaddress = addr_info.is_subaddress;
      entry.is_integrated = addr_info.has_payment_id;
    }

    auto ptx = w->tx_constructor->create_transaction(recipients);
  }
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

void RequestHandler::invoke(EXPORT_VIEW_KEY& command, rpc_context context) {
  if (auto w = wallet.lock())
  {
    const auto& keys = w->export_keys();
    command.response["key"] = tools::type_to_hex(keys.m_view_secret_key);
  }
}

void RequestHandler::invoke(EXPORT_SPEND_KEY& command, rpc_context context) {
  if (auto w = wallet.lock())
  {
    const auto& keys = w->export_keys();
    command.response["key"] = tools::type_to_hex(keys.m_spend_secret_key);
  }
}

void RequestHandler::invoke(EXPORT_MNEMONIC_KEY& command, rpc_context context) {
  if (auto w = wallet.lock())
  {
    const auto keys = w->export_keys();
    const crypto::secret_key& key = keys.m_spend_secret_key;
    //if (!passphrase.empty())
      //key = cryptonote::encrypt_key(key, passphrase);
    std::string electrum_words;
    command.response["mnemonic"] = crypto::ElectrumWords::bytes_to_words(key, command.request.language);
  }
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
  if (auto w = wallet.lock())
  {
    command.response["version"] = VERSION_STR;
  }
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
  if (auto w = wallet.lock())
  {
    if (command.request.address != "")
      w->config.daemon.address = command.request.address;

    if (command.request.proxy != "")
      w->config.daemon.proxy = command.request.proxy;

    w->config.daemon.trusted = command.request.trusted;

    if (command.request.ssl_private_key_path != "")
      w->config.daemon.ssl_private_key_path = command.request.ssl_private_key_path;

    if (command.request.ssl_certificate_path != "")
      w->config.daemon.ssl_certificate_path = command.request.ssl_certificate_path;

    if (command.request.ssl_ca_file != "")
      w->config.daemon.ssl_ca_file = command.request.ssl_ca_file;

    w->config.daemon.ssl_allow_any_cert = command.request.ssl_allow_any_cert;

    w->propogate_config();
  }
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
