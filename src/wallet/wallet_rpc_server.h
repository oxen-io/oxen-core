// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2018, The Loki Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <uWebSockets/App.h>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <string>

#include "common/fs.h"
#include "common/periodic_task.h"
#include "common/util.h"
#include "rpc/common/http_server_base.h"
#include "wallet2.h"
#include "wallet_rpc_server_commands_defs.h"

namespace tools {
using HttpRequest = uWS::HttpRequest;
using HttpResponse = uWS::HttpResponse<false /*SSL*/>;

/************************************************************************/
/*                                                                      */
/************************************************************************/
class wallet_rpc_server final : public cryptonote::rpc::http_server_base {
  public:
    static const char* tr(const char* str);

    wallet_rpc_server(boost::program_options::variables_map vm);

    bool init();
    bool run(bool /*interactive - ignored (rpc wallet is always non-interactive) */);
    void stop();  // Makes run() start cleaning up and shutting down

    /// Thrown if we get invalid/unparseable JSON data.
    struct parse_error : std::runtime_error {
        using std::runtime_error::runtime_error;
    };

    // json_rpc
    wallet_rpc::GET_BALANCE::response invoke(wallet_rpc::GET_BALANCE::request&& req);
    wallet_rpc::GET_ADDRESS::response invoke(wallet_rpc::GET_ADDRESS::request&& req);
    wallet_rpc::GET_ADDRESS_INDEX::response invoke(wallet_rpc::GET_ADDRESS_INDEX::request&& req);
    wallet_rpc::CREATE_ADDRESS::response invoke(wallet_rpc::CREATE_ADDRESS::request&& req);
    wallet_rpc::LABEL_ADDRESS::response invoke(wallet_rpc::LABEL_ADDRESS::request&& req);
    wallet_rpc::GET_ACCOUNTS::response invoke(wallet_rpc::GET_ACCOUNTS::request&& req);
    wallet_rpc::CREATE_ACCOUNT::response invoke(wallet_rpc::CREATE_ACCOUNT::request&& req);
    wallet_rpc::LABEL_ACCOUNT::response invoke(wallet_rpc::LABEL_ACCOUNT::request&& req);
    wallet_rpc::GET_ACCOUNT_TAGS::response invoke(wallet_rpc::GET_ACCOUNT_TAGS::request&& req);
    wallet_rpc::TAG_ACCOUNTS::response invoke(wallet_rpc::TAG_ACCOUNTS::request&& req);
    wallet_rpc::UNTAG_ACCOUNTS::response invoke(wallet_rpc::UNTAG_ACCOUNTS::request&& req);
    wallet_rpc::SET_ACCOUNT_TAG_DESCRIPTION::response invoke(
            wallet_rpc::SET_ACCOUNT_TAG_DESCRIPTION::request&& req);
    wallet_rpc::GET_HEIGHT::response invoke(wallet_rpc::GET_HEIGHT::request&& req);
    wallet_rpc::TRANSFER::response invoke(wallet_rpc::TRANSFER::request&& req);
    wallet_rpc::TRANSFER_SPLIT::response invoke(wallet_rpc::TRANSFER_SPLIT::request&& req);
    wallet_rpc::SIGN_TRANSFER::response invoke(wallet_rpc::SIGN_TRANSFER::request&& req);
    wallet_rpc::DESCRIBE_TRANSFER::response invoke(wallet_rpc::DESCRIBE_TRANSFER::request&& req);
    wallet_rpc::SUBMIT_TRANSFER::response invoke(wallet_rpc::SUBMIT_TRANSFER::request&& req);
    wallet_rpc::SWEEP_DUST::response invoke(wallet_rpc::SWEEP_DUST::request&& req);
    wallet_rpc::SWEEP_ALL::response invoke(wallet_rpc::SWEEP_ALL::request&& req);
    wallet_rpc::SWEEP_SINGLE::response invoke(wallet_rpc::SWEEP_SINGLE::request&& req);
    wallet_rpc::RELAY_TX::response invoke(wallet_rpc::RELAY_TX::request&& req);
    wallet_rpc::MAKE_INTEGRATED_ADDRESS::response invoke(
            wallet_rpc::MAKE_INTEGRATED_ADDRESS::request&& req);
    wallet_rpc::SPLIT_INTEGRATED_ADDRESS::response invoke(
            wallet_rpc::SPLIT_INTEGRATED_ADDRESS::request&& req);
    wallet_rpc::STORE::response invoke(wallet_rpc::STORE::request&& req);
    wallet_rpc::GET_PAYMENTS::response invoke(wallet_rpc::GET_PAYMENTS::request&& req);
    wallet_rpc::GET_BULK_PAYMENTS::response invoke(wallet_rpc::GET_BULK_PAYMENTS::request&& req);
    wallet_rpc::INCOMING_TRANSFERS::response invoke(wallet_rpc::INCOMING_TRANSFERS::request&& req);
    wallet_rpc::STOP_WALLET::response invoke(wallet_rpc::STOP_WALLET::request&& req);
    wallet_rpc::RESCAN_BLOCKCHAIN::response invoke(wallet_rpc::RESCAN_BLOCKCHAIN::request&& req);
    wallet_rpc::SET_TX_NOTES::response invoke(wallet_rpc::SET_TX_NOTES::request&& req);
    wallet_rpc::GET_TX_NOTES::response invoke(wallet_rpc::GET_TX_NOTES::request&& req);
    wallet_rpc::SET_ATTRIBUTE::response invoke(wallet_rpc::SET_ATTRIBUTE::request&& req);
    wallet_rpc::GET_ATTRIBUTE::response invoke(wallet_rpc::GET_ATTRIBUTE::request&& req);
    wallet_rpc::GET_TX_KEY::response invoke(wallet_rpc::GET_TX_KEY::request&& req);
    wallet_rpc::CHECK_TX_KEY::response invoke(wallet_rpc::CHECK_TX_KEY::request&& req);
    wallet_rpc::GET_TX_PROOF::response invoke(wallet_rpc::GET_TX_PROOF::request&& req);
    wallet_rpc::CHECK_TX_PROOF::response invoke(wallet_rpc::CHECK_TX_PROOF::request&& req);
    wallet_rpc::GET_SPEND_PROOF::response invoke(wallet_rpc::GET_SPEND_PROOF::request&& req);
    wallet_rpc::CHECK_SPEND_PROOF::response invoke(wallet_rpc::CHECK_SPEND_PROOF::request&& req);
    wallet_rpc::GET_RESERVE_PROOF::response invoke(wallet_rpc::GET_RESERVE_PROOF::request&& req);
    wallet_rpc::CHECK_RESERVE_PROOF::response invoke(
            wallet_rpc::CHECK_RESERVE_PROOF::request&& req);
    wallet_rpc::GET_TRANSFERS::response invoke(wallet_rpc::GET_TRANSFERS::request&& req);
    wallet_rpc::GET_TRANSFERS_CSV::response invoke(wallet_rpc::GET_TRANSFERS_CSV::request&& req);
    wallet_rpc::GET_TRANSFER_BY_TXID::response invoke(
            wallet_rpc::GET_TRANSFER_BY_TXID::request&& req);
    wallet_rpc::SIGN::response invoke(wallet_rpc::SIGN::request&& req);
    wallet_rpc::VERIFY::response invoke(wallet_rpc::VERIFY::request&& req);
    wallet_rpc::EXPORT_OUTPUTS::response invoke(wallet_rpc::EXPORT_OUTPUTS::request&& req);
    wallet_rpc::EXPORT_TRANSFERS::response invoke(wallet_rpc::EXPORT_TRANSFERS::request&& req);
    wallet_rpc::IMPORT_OUTPUTS::response invoke(wallet_rpc::IMPORT_OUTPUTS::request&& req);
    wallet_rpc::EXPORT_KEY_IMAGES::response invoke(wallet_rpc::EXPORT_KEY_IMAGES::request&& req);
    wallet_rpc::IMPORT_KEY_IMAGES::response invoke(wallet_rpc::IMPORT_KEY_IMAGES::request&& req);
    wallet_rpc::MAKE_URI::response invoke(wallet_rpc::MAKE_URI::request&& req);
    wallet_rpc::PARSE_URI::response invoke(wallet_rpc::PARSE_URI::request&& req);
    wallet_rpc::GET_ADDRESS_BOOK_ENTRY::response invoke(
            wallet_rpc::GET_ADDRESS_BOOK_ENTRY::request&& req);
    wallet_rpc::ADD_ADDRESS_BOOK_ENTRY::response invoke(
            wallet_rpc::ADD_ADDRESS_BOOK_ENTRY::request&& req);
    wallet_rpc::EDIT_ADDRESS_BOOK_ENTRY::response invoke(
            wallet_rpc::EDIT_ADDRESS_BOOK_ENTRY::request&& req);
    wallet_rpc::DELETE_ADDRESS_BOOK_ENTRY::response invoke(
            wallet_rpc::DELETE_ADDRESS_BOOK_ENTRY::request&& req);
    wallet_rpc::REFRESH::response invoke(wallet_rpc::REFRESH::request&& req);
    wallet_rpc::AUTO_REFRESH::response invoke(wallet_rpc::AUTO_REFRESH::request&& req);
    wallet_rpc::RESCAN_SPENT::response invoke(wallet_rpc::RESCAN_SPENT::request&& req);
    wallet_rpc::START_MINING::response invoke(wallet_rpc::START_MINING::request&& req);
    wallet_rpc::STOP_MINING::response invoke(wallet_rpc::STOP_MINING::request&& req);
    wallet_rpc::GET_LANGUAGES::response invoke(wallet_rpc::GET_LANGUAGES::request&& req);
    wallet_rpc::CREATE_WALLET::response invoke(wallet_rpc::CREATE_WALLET::request&& req);
    wallet_rpc::OPEN_WALLET::response invoke(wallet_rpc::OPEN_WALLET::request&& req);
    wallet_rpc::CLOSE_WALLET::response invoke(wallet_rpc::CLOSE_WALLET::request&& req);
    wallet_rpc::CHANGE_WALLET_PASSWORD::response invoke(
            wallet_rpc::CHANGE_WALLET_PASSWORD::request&& req);
    wallet_rpc::GENERATE_FROM_KEYS::response invoke(wallet_rpc::GENERATE_FROM_KEYS::request&& req);
    wallet_rpc::RESTORE_DETERMINISTIC_WALLET::response invoke(
            wallet_rpc::RESTORE_DETERMINISTIC_WALLET::request&& req);
    wallet_rpc::IS_MULTISIG::response invoke(wallet_rpc::IS_MULTISIG::request&& req);
    wallet_rpc::PREPARE_MULTISIG::response invoke(wallet_rpc::PREPARE_MULTISIG::request&& req);
    wallet_rpc::MAKE_MULTISIG::response invoke(wallet_rpc::MAKE_MULTISIG::request&& req);
    wallet_rpc::EXPORT_MULTISIG::response invoke(wallet_rpc::EXPORT_MULTISIG::request&& req);
    wallet_rpc::IMPORT_MULTISIG::response invoke(wallet_rpc::IMPORT_MULTISIG::request&& req);
    wallet_rpc::FINALIZE_MULTISIG::response invoke(wallet_rpc::FINALIZE_MULTISIG::request&& req);
    wallet_rpc::EXCHANGE_MULTISIG_KEYS::response invoke(
            wallet_rpc::EXCHANGE_MULTISIG_KEYS::request&& req);
    wallet_rpc::SIGN_MULTISIG::response invoke(wallet_rpc::SIGN_MULTISIG::request&& req);
    wallet_rpc::SUBMIT_MULTISIG::response invoke(wallet_rpc::SUBMIT_MULTISIG::request&& req);
    wallet_rpc::VALIDATE_ADDRESS::response invoke(wallet_rpc::VALIDATE_ADDRESS::request&& req);
    wallet_rpc::SET_DAEMON::response invoke(wallet_rpc::SET_DAEMON::request&& req);
    wallet_rpc::SET_LOG_LEVEL::response invoke(wallet_rpc::SET_LOG_LEVEL::request&& req);
    wallet_rpc::SET_LOG_CATEGORIES::response invoke(wallet_rpc::SET_LOG_CATEGORIES::request&& req);
    wallet_rpc::GET_VERSION::response invoke(wallet_rpc::GET_VERSION::request&& req);
    wallet_rpc::STAKE::response invoke(wallet_rpc::STAKE::request&& req);
    wallet_rpc::REGISTER_SERVICE_NODE::response invoke(
            wallet_rpc::REGISTER_SERVICE_NODE::request&& req);
    wallet_rpc::CAN_REQUEST_STAKE_UNLOCK::response invoke(
            wallet_rpc::CAN_REQUEST_STAKE_UNLOCK::request&& req);
    wallet_rpc::REQUEST_STAKE_UNLOCK::response invoke(
            wallet_rpc::REQUEST_STAKE_UNLOCK::request&& req);
    wallet_rpc::ONS_BUY_MAPPING::response invoke(wallet_rpc::ONS_BUY_MAPPING::request&& req);
    wallet_rpc::ONS_RENEW_MAPPING::response invoke(wallet_rpc::ONS_RENEW_MAPPING::request&& req);
    wallet_rpc::ONS_UPDATE_MAPPING::response invoke(wallet_rpc::ONS_UPDATE_MAPPING::request&& req);
    wallet_rpc::ONS_MAKE_UPDATE_SIGNATURE::response invoke(
            wallet_rpc::ONS_MAKE_UPDATE_SIGNATURE::request&& req);
    wallet_rpc::ONS_HASH_NAME::response invoke(wallet_rpc::ONS_HASH_NAME::request&& req);
    wallet_rpc::ONS_KNOWN_NAMES::response invoke(wallet_rpc::ONS_KNOWN_NAMES::request&& req);
    wallet_rpc::ONS_ADD_KNOWN_NAMES::response invoke(
            wallet_rpc::ONS_ADD_KNOWN_NAMES::request&& req);
    wallet_rpc::ONS_DECRYPT_VALUE::response invoke(wallet_rpc::ONS_DECRYPT_VALUE::request&& req);
    wallet_rpc::ONS_ENCRYPT_VALUE::response invoke(wallet_rpc::ONS_ENCRYPT_VALUE::request&& req);
    wallet_rpc::QUERY_KEY::response invoke(wallet_rpc::QUERY_KEY::request&& req);

  private:
    /// Handles a POST request to /json_rpc.
    void handle_json_rpc_request(HttpResponse& res, HttpRequest& req);

    // Checks that a wallet is open; if not, throws an error.
    void require_open();

    // Safely and cleanly closes the currently open wallet (if one is open)
    void close_wallet(bool save_current);

    template <typename Ts, typename Tu>
    void fill_response(
            std::vector<tools::wallet2::pending_tx>& ptx_vector,
            bool get_tx_key,
            Ts& tx_key,
            Tu& amount,
            Tu& fee,
            std::string& multisig_txset,
            std::string& unsigned_txset,
            bool do_not_relay,
            bool blink,
            Ts& tx_hash,
            bool get_tx_hex,
            Ts& tx_blob,
            bool get_tx_metadata,
            Ts& tx_metadata);

    cryptonote::address_parse_info extract_account_addr(
            cryptonote::network_type nettype, std::string_view addr_or_url);

    void validate_transfer(
            const std::list<wallet::transfer_destination>& destinations,
            const std::string& payment_id,
            std::vector<cryptonote::tx_destination_entry>& dsts,
            std::vector<uint8_t>& extra,
            bool at_least_one_destination);

    // Parse options and opens the wallet.  Returns nullptr if in directory mode (i.e. no wallet
    // gets opened).  Throws on error.
    std::unique_ptr<tools::wallet2> load_wallet();

    // Sets up the RPC endpoints (called before listening).
    void create_rpc_endpoints(uWS::App& http);

    // Runs the server event loop; does not return until the server is shut down (by a signal or a
    // remote STOP command).
    void run_loop();

    // Starts the long poll thread, if not already active and m_long_poll_disabled is not set.
    // m_wallet must already be set.
    void start_long_poll_thread();

    // Stops the long poll thread and joins it.  This must be done before resetting m_wallet.
    // After the call `m_long_poll_disabled` will be false (and must be set back to true if you
    // want to re-start the thread).
    void stop_long_poll_thread();

    std::unique_ptr<wallet2> m_wallet;
    fs::path m_wallet_dir;
    std::vector<std::tuple<std::string /*ip*/, uint16_t /*port*/, bool /*required*/>> m_bind;
    tools::private_file rpc_login_file;
    std::atomic<bool> m_stop;
    bool m_restricted;
    boost::program_options::variables_map m_vm;
    std::chrono::milliseconds m_auto_refresh_period;
    std::chrono::steady_clock::time_point m_last_auto_refresh_time;
    std::atomic<bool> m_long_poll_new_changes;
    std::atomic<bool> m_long_poll_disabled;
    std::thread m_long_poll_thread;
};
}  // namespace tools
