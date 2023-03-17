#include "request_handler.h"

#include <common/hex.h>
#include <cryptonote_core/cryptonote_tx_utils.h>
#include <oxenc/base64.h>
#include <version.h>

#include <memory>
#include <unordered_map>
#include <wallet3/db/walletdb.hpp>
#include <wallet3/wallet.hpp>

#include "command_parser.h"
#include "commands.h"
#include "mnemonics/electrum-words.h"

namespace wallet::rpc {

using cryptonote::rpc::rpc_context;
using cryptonote::rpc::rpc_error;
using cryptonote::rpc::rpc_request;

namespace {

    static auto logcat = oxen::log::Cat("wallet");

    template <typename RPC>
    void register_rpc_command(
            std::unordered_map<std::string, std::shared_ptr<const rpc_command>>& regs) {
        using cryptonote::rpc::RESTRICTED;
        using cryptonote::rpc::RPC_COMMAND;

        static_assert(std::is_base_of_v<RPC_COMMAND, RPC>);
        auto cmd = std::make_shared<rpc_command>();
        cmd->is_restricted = std::is_base_of_v<RESTRICTED, RPC>;

        cmd->invoke = cryptonote::rpc::make_invoke<RPC, RequestHandler, rpc_command>();

        for (const auto& name : RPC::names())
            regs.emplace(name, cmd);
    }

    template <typename... RPC, typename... BinaryRPC>
    std::unordered_map<std::string, std::shared_ptr<const rpc_command>> register_rpc_commands(
            tools::type_list<RPC...>) {
        std::unordered_map<std::string, std::shared_ptr<const rpc_command>> regs;

        (register_rpc_command<RPC>(regs), ...);

        return regs;
    }

}  // anonymous namespace

void RequestHandler::set_wallet(std::weak_ptr<wallet::Wallet> ptr) {
    wallet = ptr;
}

std::string RequestHandler::submit_transaction(wallet::PendingTransaction& ptx)
{
  std::string response;
  if (auto w = wallet.lock())
  {
    w->keys->sign_transaction(ptx);

        auto submit_future = w->daemon_comms->submit_transaction(ptx.tx, false);

        if (submit_future.wait_for(5s) != std::future_status::ready)
            throw rpc_error(500, "request to daemon timed out");
        response = submit_future.get();
    }
    return response;
}

const std::unordered_map<std::string, std::shared_ptr<const rpc_command>> rpc_commands =
        register_rpc_commands(wallet_rpc_types{});

void RequestHandler::invoke(GET_BALANCE& command, rpc_context context) {
    if (auto w = wallet.lock()) {
        command.response["balance"] = w->get_balance();
        command.response["unlocked_balance"] = w->get_unlocked_balance();
    }
    // TODO handle subaddresses and params passed for them
}

void RequestHandler::invoke(GET_ADDRESS& command, rpc_context context) {
    // TODO: implement fetching address/subaddress from db/keyring
    if (auto w = wallet.lock()) {
        command.response["address"] = w->keys->get_main_address();
        // auto& addresses = (command.response["addresses"] = json::array());
        // if (command.request.address_index.size() == 0)
        //{
        // auto address = w->get_subaddress(command.request.account_index, 0);
        // addresses.push_back(json{
        //{"address", address.as_str(cryptonote::network_type::MAINNET)},
        //{"label", ""},
        //{"address_index", command.request.address_index},
        //{"used", true}
        //});
        //} else {
        // for (const auto& address_index: command.request.address_index)
        //{
        // auto address = w->get_subaddress(command.request.account_index, address_index);
        // addresses.push_back(json{
        //{"address", address.as_str(cryptonote::network_type::MAINNET)},
        //{"label", ""},
        //{"address_index", command.request.address_index},
        //{"used", true}
        //});
        //}
        //}
    }
}

void RequestHandler::invoke(GET_ADDRESS_INDEX& command, rpc_context context) {}

void RequestHandler::invoke(CREATE_ADDRESS& command, rpc_context context) {}

void RequestHandler::invoke(LABEL_ADDRESS& command, rpc_context context) {}

void RequestHandler::invoke(GET_ACCOUNTS& command, rpc_context context) {}

void RequestHandler::invoke(CREATE_ACCOUNT& command, rpc_context context) {}

void RequestHandler::invoke(LABEL_ACCOUNT& command, rpc_context context) {}

void RequestHandler::invoke(GET_ACCOUNT_TAGS& command, rpc_context context) {}

void RequestHandler::invoke(TAG_ACCOUNTS& command, rpc_context context) {}

void RequestHandler::invoke(UNTAG_ACCOUNTS& command, rpc_context context) {}

void RequestHandler::invoke(SET_ACCOUNT_TAG_DESCRIPTION& command, rpc_context context) {}

void RequestHandler::invoke(GET_HEIGHT& command, rpc_context context) {
    if (auto w = wallet.lock()) {
        const auto immutable_height = w->db->scan_target_height();
        const auto height = w->db->current_height();

        command.response["height"] = height;

        command.response["immutable_height"] = immutable_height;
    }
}

void RequestHandler::invoke(TRANSFER& command, rpc_context context) {
    oxen::log::info(logcat, "RPC Handler received TRANSFER command");
    wallet::PendingTransaction ptx;
    if (auto w = wallet.lock()) {
        // TODO: arg checking
        // TODO: actually use all args

        std::vector<cryptonote::tx_destination_entry> recipients;
        for (const auto& [dest, amount] : command.request.destinations) {
            auto& entry = recipients.emplace_back();
            cryptonote::address_parse_info addr_info;

            if (not cryptonote::get_account_address_from_str(addr_info, w->nettype, dest))
                // TODO: is 500 the "correct" error code?
                throw rpc_error(500, std::string("Invalid destination: ") + dest);

            entry.original = dest;
            entry.amount = amount;
            entry.addr = addr_info.address;
            entry.is_subaddress = addr_info.is_subaddress;
            entry.is_integrated = addr_info.has_payment_id;
        }

        // TODO: change subaddress as arg, for now just use main address
        cryptonote::tx_destination_entry change_dest;
        change_dest.original = w->db->get_address(0, 0);
        cryptonote::address_parse_info change_addr_info;
        cryptonote::get_account_address_from_str(
                change_addr_info, w->nettype, change_dest.original);
        change_dest.amount = 0;
        change_dest.addr = change_addr_info.address;
        change_dest.is_subaddress = change_addr_info.is_subaddress;
        change_dest.is_integrated = change_addr_info.has_payment_id;

        ptx = w->tx_constructor->create_transaction(recipients, change_dest);
    }
    command.response["result"] = submit_transaction(ptx);
    command.response["status"] = "200";
}

void RequestHandler::invoke(TRANSFER_SPLIT& command, rpc_context context) {}

void RequestHandler::invoke(DESCRIBE_TRANSFER& command, rpc_context context) {}

void RequestHandler::invoke(SIGN_TRANSFER& command, rpc_context context) {}

void RequestHandler::invoke(SUBMIT_TRANSFER& command, rpc_context context) {}

void RequestHandler::invoke(SWEEP_DUST& command, rpc_context context) {}

void RequestHandler::invoke(SWEEP_ALL& command, rpc_context context) {}

void RequestHandler::invoke(SWEEP_SINGLE& command, rpc_context context) {}

void RequestHandler::invoke(RELAY_TX& command, rpc_context context) {}

void RequestHandler::invoke(STORE& command, rpc_context context) {}

void RequestHandler::invoke(GET_PAYMENTS& command, rpc_context context) {}

void RequestHandler::invoke(GET_BULK_PAYMENTS& command, rpc_context context) {}

void RequestHandler::invoke(INCOMING_TRANSFERS& command, rpc_context context) {}

void RequestHandler::invoke(EXPORT_VIEW_KEY& command, rpc_context context) {
    if (auto w = wallet.lock()) {
        const auto& keys = w->export_keys();
        command.response["key"] = tools::type_to_hex(keys.m_view_secret_key);
    }
}

void RequestHandler::invoke(EXPORT_SPEND_KEY& command, rpc_context context) {
    if (auto w = wallet.lock()) {
        const auto& keys = w->export_keys();
        command.response["key"] = tools::type_to_hex(keys.m_spend_secret_key);
    }
}

void RequestHandler::invoke(EXPORT_MNEMONIC_KEY& command, rpc_context context) {
    if (auto w = wallet.lock()) {
        const auto keys = w->export_keys();
        const crypto::secret_key& key = keys.m_spend_secret_key;
        // if (!passphrase.empty())
        // key = cryptonote::encrypt_key(key, passphrase);
        std::string electrum_words;
        command.response["mnemonic"] =
                crypto::ElectrumWords::bytes_to_words(key, command.request.language);
    }
}
void RequestHandler::invoke(MAKE_INTEGRATED_ADDRESS& command, rpc_context context) {}

void RequestHandler::invoke(SPLIT_INTEGRATED_ADDRESS& command, rpc_context context) {}

void RequestHandler::invoke(STOP_WALLET& command, rpc_context context) {}

void RequestHandler::invoke(RESCAN_BLOCKCHAIN& command, rpc_context context) {}

void RequestHandler::invoke(SET_TX_NOTES& command, rpc_context context) {}

void RequestHandler::invoke(GET_TX_NOTES& command, rpc_context context) {}

void RequestHandler::invoke(SET_ATTRIBUTE& command, rpc_context context) {}

void RequestHandler::invoke(GET_ATTRIBUTE& command, rpc_context context) {}

void RequestHandler::invoke(GET_TX_KEY& command, rpc_context context) {}

void RequestHandler::invoke(CHECK_TX_KEY& command, rpc_context context) {}

void RequestHandler::invoke(GET_TX_PROOF& command, rpc_context context) {}

void RequestHandler::invoke(CHECK_TX_PROOF& command, rpc_context context) {}

void RequestHandler::invoke(GET_SPEND_PROOF& command, rpc_context context) {}

void RequestHandler::invoke(CHECK_SPEND_PROOF& command, rpc_context context) {}

void RequestHandler::invoke(GET_RESERVE_PROOF& command, rpc_context context) {}

void RequestHandler::invoke(CHECK_RESERVE_PROOF& command, rpc_context context) {}

void RequestHandler::invoke(GET_TRANSFERS& command, rpc_context context) {}

void RequestHandler::invoke(GET_TRANSFERS_CSV& command, rpc_context context) {}

void RequestHandler::invoke(GET_TRANSFER_BY_TXID& command, rpc_context context) {}

void RequestHandler::invoke(SIGN& command, rpc_context context) {}

void RequestHandler::invoke(VERIFY& command, rpc_context context) {}

void RequestHandler::invoke(EXPORT_OUTPUTS& command, rpc_context context) {}

void RequestHandler::invoke(EXPORT_TRANSFERS& command, rpc_context context) {}

void RequestHandler::invoke(IMPORT_OUTPUTS& command, rpc_context context) {}

void RequestHandler::invoke(EXPORT_KEY_IMAGES& command, rpc_context context) {}

void RequestHandler::invoke(IMPORT_KEY_IMAGES& command, rpc_context context) {}

void RequestHandler::invoke(MAKE_URI& command, rpc_context context) {}

void RequestHandler::invoke(PARSE_URI& command, rpc_context context) {}

void RequestHandler::invoke(ADD_ADDRESS_BOOK_ENTRY& command, rpc_context context) {}

void RequestHandler::invoke(EDIT_ADDRESS_BOOK_ENTRY& command, rpc_context context) {}

void RequestHandler::invoke(GET_ADDRESS_BOOK_ENTRY& command, rpc_context context) {}

void RequestHandler::invoke(DELETE_ADDRESS_BOOK_ENTRY& command, rpc_context context) {}

void RequestHandler::invoke(RESCAN_SPENT& command, rpc_context context) {}

void RequestHandler::invoke(REFRESH& command, rpc_context context) {}

void RequestHandler::invoke(AUTO_REFRESH& command, rpc_context context) {}

void RequestHandler::invoke(START_MINING& command, rpc_context context) {}

void RequestHandler::invoke(STOP_MINING& command, rpc_context context) {}

void RequestHandler::invoke(GET_LANGUAGES& command, rpc_context context) {}

void RequestHandler::invoke(CREATE_WALLET& command, rpc_context context) {}

void RequestHandler::invoke(OPEN_WALLET& command, rpc_context context) {}

void RequestHandler::invoke(CLOSE_WALLET& command, rpc_context context) {}

void RequestHandler::invoke(CHANGE_WALLET_PASSWORD& command, rpc_context context) {}

void RequestHandler::invoke(GENERATE_FROM_KEYS& command, rpc_context context) {}

void RequestHandler::invoke(RESTORE_DETERMINISTIC_WALLET& command, rpc_context context) {}

void RequestHandler::invoke(IS_MULTISIG& command, rpc_context context) {}

void RequestHandler::invoke(PREPARE_MULTISIG& command, rpc_context context) {}

void RequestHandler::invoke(MAKE_MULTISIG& command, rpc_context context) {}

void RequestHandler::invoke(EXPORT_MULTISIG& command, rpc_context context) {}

void RequestHandler::invoke(IMPORT_MULTISIG& command, rpc_context context) {}

void RequestHandler::invoke(FINALIZE_MULTISIG& command, rpc_context context) {}

void RequestHandler::invoke(EXCHANGE_MULTISIG_KEYS& command, rpc_context context) {}

void RequestHandler::invoke(SIGN_MULTISIG& command, rpc_context context) {}

void RequestHandler::invoke(SUBMIT_MULTISIG& command, rpc_context context) {}

void RequestHandler::invoke(GET_VERSION& command, rpc_context context) {
    if (auto w = wallet.lock()) {
        command.response["version"] = OXEN_VERSION_STR;
    }
}

void RequestHandler::invoke(STAKE& command, rpc_context context) {
  oxen::log::info(logcat, "RPC Handler received STAKE command");
  wallet::PendingTransaction ptx;
  if (auto w = wallet.lock())
  {
    cryptonote::tx_destination_entry change_dest;
    change_dest.original = w->keys->get_main_address();
    cryptonote::address_parse_info change_addr_info;
    cryptonote::get_account_address_from_str(change_addr_info, w->nettype, change_dest.original);
    change_dest.amount = 0;
    change_dest.addr = change_addr_info.address;
    change_dest.is_subaddress = change_addr_info.is_subaddress;
    change_dest.is_integrated = change_addr_info.has_payment_id;

    ptx = w->tx_constructor->create_stake_transaction(
      command.request.destination,
      command.request.service_node_key,
      command.request.amount,
      change_dest
      );
  }
  command.response["result"] = submit_transaction(ptx);
  command.response["status"] = "200";
}

void RequestHandler::invoke(REGISTER_SERVICE_NODE& command, rpc_context context) {}

void RequestHandler::invoke(REQUEST_STAKE_UNLOCK& command, rpc_context context) {}

void RequestHandler::invoke(CAN_REQUEST_STAKE_UNLOCK& command, rpc_context context) {}

void RequestHandler::invoke(VALIDATE_ADDRESS& command, rpc_context context) {}

void RequestHandler::invoke(SET_DAEMON& command, rpc_context context) {
    if (auto w = wallet.lock()) {
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

void RequestHandler::invoke(SET_LOG_LEVEL& command, rpc_context context) {}

void RequestHandler::invoke(SET_LOG_CATEGORIES& command, rpc_context context) {}

void RequestHandler::invoke(ONS_BUY_MAPPING& command, rpc_context context) {
    // TODO sean these params need to be accounted for
    //   "do_not_relay", req.request.do_not_relay.
    //   "get_tx_hex", req.request.get_tx_hex.
    //   "get_tx_key", req.request.get_tx_key.
    //   "get_tx_metadata", req.request.get_tx_metadata.
    //   "priority", req.request.priority,
    //   "subaddr_indices", req.request.subaddr_indices,

    oxen::log::info(logcat, "RPC Handler received ONS_BUY_MAPPING command");
    wallet::PendingTransaction ptx;
    if (auto w = wallet.lock()) {
        cryptonote::tx_destination_entry change_dest;
        change_dest.original = w->keys->get_main_address();
        cryptonote::address_parse_info change_addr_info;
        cryptonote::get_account_address_from_str(
                change_addr_info, w->nettype, change_dest.original);
        change_dest.amount = 0;
        change_dest.addr = change_addr_info.address;
        change_dest.is_subaddress = change_addr_info.is_subaddress;
        change_dest.is_integrated = change_addr_info.has_payment_id;

        ptx = w->tx_constructor->create_ons_buy_transaction(
                command.request.name,
                command.request.type,
                command.request.value,
                command.request.owner,
                command.request.backup_owner,
                change_dest);
    }
    command.response["result"] = submit_transaction(ptx);
    command.response["status"] = "200";
}

void RequestHandler::invoke(ONS_RENEW_MAPPING& command, rpc_context context) {}

void RequestHandler::invoke(ONS_UPDATE_MAPPING& command, rpc_context context) {
    oxen::log::info(logcat, "RPC Handler received ONS_UPDATE_MAPPING command");
    wallet::PendingTransaction ptx;
    if (auto w = wallet.lock()) {
        cryptonote::tx_destination_entry change_dest;
        change_dest.original = w->keys->get_main_address();
        cryptonote::address_parse_info change_addr_info;
        cryptonote::get_account_address_from_str(
                change_addr_info, w->nettype, change_dest.original);
        change_dest.amount = 0;
        change_dest.addr = change_addr_info.address;
        change_dest.is_subaddress = change_addr_info.is_subaddress;
        change_dest.is_integrated = change_addr_info.has_payment_id;

        ptx = w->tx_constructor->create_ons_update_transaction(
                command.request.name,
                command.request.type,
                command.request.value,
                command.request.owner,
                command.request.backup_owner,
                change_dest,
                w->keys);
    }
    command.response["result"] = submit_transaction(ptx);
    command.response["status"] = "200";
}

void RequestHandler::invoke(ONS_MAKE_UPDATE_SIGNATURE& command, rpc_context context) {}

void RequestHandler::invoke(ONS_HASH_NAME& command, rpc_context context) {}

void RequestHandler::invoke(ONS_KNOWN_NAMES& command, rpc_context context) {}

void RequestHandler::invoke(ONS_ADD_KNOWN_NAMES& command, rpc_context context) {}

void RequestHandler::invoke(ONS_ENCRYPT_VALUE& command, rpc_context context) {}

void RequestHandler::invoke(ONS_DECRYPT_VALUE& command, rpc_context context) {}

void RequestHandler::invoke(STATUS& command, rpc_context context) {
    if (auto w = wallet.lock()) {
        const auto sync_height = w->db->current_height();
        const auto target_height = w->db->scan_target_height();

        command.response["sync_height"] = sync_height;
        command.response["target_height"] = target_height;

        command.response["syncing"] = sync_height < target_height;
    }
}

}  // namespace wallet::rpc
