// Copyright (c) 2014-2019, The Monero Project
// Copyright (c) 2018-2019, The Loki Project
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

/*!
 * \file simplewallet.cpp
 *
 * \brief Source file that defines simple_wallet class.
 */

#include "common/string_util.h"
#include "oxen_economy.h"
#include <algorithm>
#include <chrono>
#ifdef _WIN32
 #define __STDC_FORMAT_MACROS // NOTE(oxen): Explicitly define the PRIu64 macro on Mingw
#endif

#include <locale.h>
#include <thread>
#include <iostream>
#include <sstream>
#include <fstream>
#include <ctype.h>
#include <string_view>
#include <regex>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <boost/format.hpp>
#include <fmt/core.h>
#include <oxenc/hex.h>
#include "epee/console_handler.h"
#include "common/i18n.h"
#include "common/command_line.h"
#include "common/util.h"
#include "common/signal_handler.h"
#include "common/base58.h"
#include "common/scoped_message_writer.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "cryptonote_core/service_node_voting.h"
#include "cryptonote_core/service_node_list.h"
#include "cryptonote_core/oxen_name_system.h"
#include "simplewallet.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "crypto/crypto.h"  // for crypto::secret_key definition
#include "mnemonics/electrum-words.h"
#include "rapidjson/document.h"
#include "common/json_util.h"
#include "ringct/rctSigs.h"
#include "multisig/multisig.h"
#include "wallet/wallet_args.h"
#include "version.h"
#include <stdexcept>
#include "epee/int-util.h"
#include "epee/readline_suspend.h"
#ifdef WALLET_ENABLE_MMS
#include "wallet/message_store.h"
#endif
#include "wallet/wallet_rpc_server_commands_defs.h"

extern "C"
{
#include <sodium.h>
}

using namespace cryptonote;
namespace po = boost::program_options;
namespace string_tools = epee::string_tools;
using sw = cryptonote::simple_wallet;

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "wallet.simplewallet"

#define EXTENDED_LOGS_FILE "wallet_details.log"

#define OUTPUT_EXPORT_FILE_MAGIC "Loki output export\003"

#define LOCK_IDLE_SCOPE() \
  bool auto_refresh_enabled = m_auto_refresh_enabled.load(std::memory_order_relaxed); \
  m_auto_refresh_enabled.store(false, std::memory_order_relaxed); \
  /* stop any background refresh, and take over */ \
  m_wallet->stop(); \
  std::unique_lock lock{m_idle_mutex}; \
  m_idle_cond.notify_all(); \
  OXEN_DEFER { \
      m_auto_refresh_enabled.store(auto_refresh_enabled, std::memory_order_relaxed); \
      m_idle_cond.notify_one(); \
  }

#define SCOPED_WALLET_UNLOCK_ON_BAD_PASSWORD(code) \
  LOCK_IDLE_SCOPE(); \
  std::optional<tools::password_container> pwd_container{}; \
  if (m_wallet->ask_password() && !(pwd_container = get_and_verify_password())) { code; } \
  tools::wallet_keys_unlocker unlocker(*m_wallet, pwd_container);

#define SCOPED_WALLET_UNLOCK() SCOPED_WALLET_UNLOCK_ON_BAD_PASSWORD(return true;)

#define PRINT_USAGE(usage_help) fail_msg_writer() << boost::format(tr("usage: %s")) % usage_help;

namespace
{
  const auto arg_wallet_file = wallet_args::arg_wallet_file();
  const command_line::arg_descriptor<std::string> arg_generate_new_wallet = {"generate-new-wallet", sw::tr("Generate new wallet and save it to <arg>"), ""};
  const command_line::arg_descriptor<std::string> arg_generate_from_device = {"generate-from-device", sw::tr("Generate new wallet from device and save it to <arg>"), ""};
  const command_line::arg_descriptor<std::string> arg_generate_from_view_key = {"generate-from-view-key", sw::tr("Generate incoming-only wallet from view key"), ""};
  const command_line::arg_descriptor<std::string> arg_generate_from_spend_key = {"generate-from-spend-key", sw::tr("Generate deterministic wallet from spend key"), ""};
  const command_line::arg_descriptor<std::string> arg_generate_from_keys = {"generate-from-keys", sw::tr("Generate wallet from private keys"), ""};
  const command_line::arg_descriptor<std::string> arg_generate_from_multisig_keys = {"generate-from-multisig-keys", sw::tr("Generate a master wallet from multisig wallet keys"), ""};
  const auto arg_generate_from_json = wallet_args::arg_generate_from_json();
  const command_line::arg_descriptor<std::string> arg_mnemonic_language = {"mnemonic-language", sw::tr("Language for mnemonic"), ""};
  const command_line::arg_descriptor<std::string> arg_electrum_seed = {"electrum-seed", sw::tr("Specify Electrum seed for wallet recovery/creation"), ""};
  const command_line::arg_descriptor<bool> arg_restore_deterministic_wallet = {"restore-deterministic-wallet", sw::tr("Recover wallet using Electrum-style mnemonic seed"), false};
  const command_line::arg_descriptor<bool> arg_restore_multisig_wallet = {"restore-multisig-wallet", sw::tr("Recover multisig wallet using Electrum-style mnemonic seed"), false};
  const command_line::arg_descriptor<bool> arg_non_deterministic = {"non-deterministic", sw::tr("Generate non-deterministic view and spend keys"), false};
  const command_line::arg_descriptor<bool> arg_allow_mismatched_daemon_version = {"allow-mismatched-daemon-version", sw::tr("Allow communicating with a daemon that uses a different RPC version"), false};
  const command_line::arg_descriptor<uint64_t> arg_restore_height = {"restore-height", sw::tr("Restore from specific blockchain height"), 0};
  const command_line::arg_descriptor<std::string> arg_restore_date = {"restore-date", sw::tr("Restore from estimated blockchain height on specified date"), ""};
  const command_line::arg_descriptor<bool> arg_do_not_relay = {"do-not-relay", sw::tr("The newly created transaction will not be relayed to the oxen network"), false};
  const command_line::arg_descriptor<bool> arg_create_address_file = {"create-address-file", sw::tr("Create an address file for new wallets"), false};
  const command_line::arg_descriptor<std::string> arg_create_hwdev_txt = {"create-hwdev-txt", sw::tr("Create a .hwdev.txt file for new hardware-backed wallets containing the given comment")};
  const command_line::arg_descriptor<std::string> arg_subaddress_lookahead = {"subaddress-lookahead", tools::wallet2::tr("Set subaddress lookahead sizes to <major>:<minor>"), ""};
  const command_line::arg_descriptor<bool> arg_use_english_language_names = {"use-english-language-names", sw::tr("Display English language names"), false};

  const command_line::arg_descriptor< std::vector<std::string> > arg_command = {"command", ""};

  const char* USAGE_START_MINING("start_mining [<number_of_threads>]");
  const char* USAGE_SET_DAEMON("set_daemon <host>[:<port>] [trusted|untrusted]");
  const char* USAGE_SHOW_BALANCE("balance [detail]");
  const char* USAGE_INCOMING_TRANSFERS("incoming_transfers [available|unavailable] [verbose] [uses] [index=<N1>[,<N2>[,...]]]");
  const char* USAGE_PAYMENTS("payments <PID_1> [<PID_2> ... <PID_N>]");
  const char* USAGE_PAYMENT_ID("payment_id");
  const char* USAGE_TRANSFER("transfer [index=<N1>[,<N2>,...]] [blink|unimportant] (<URI> | <address> <amount>) [<payment_id>]");
  const char* USAGE_LOCKED_TRANSFER("locked_transfer [index=<N1>[,<N2>,...]] [<priority>] (<URI> | <addr> <amount>) <lockblocks> [<payment_id (obsolete)>]");
  const char* USAGE_LOCKED_SWEEP_ALL("locked_sweep_all [index=<N1>[,<N2>,...] | index=all] [<priority>] [<address>] <lockblocks> [<payment_id (obsolete)>]");
  const char* USAGE_SWEEP_ALL("sweep_all [index=<N1>[,<N2>,...] | index=all] [blink|unimportant] [outputs=<N>] [<address> [<payment_id (obsolete)>]]");
  const char* USAGE_SWEEP_BELOW("sweep_below <amount_threshold> [index=<N1>[,<N2>,...]] [blink|unimportant] [<address> [<payment_id (obsolete)>]]");
  const char* USAGE_SWEEP_SINGLE("sweep_single [blink|unimportant] [outputs=<N>] <key_image> <address> [<payment_id (obsolete)>]");
  const char* USAGE_SWEEP_ACCOUNT("sweep_account <account> [index=<N1>[,<N2>,...] | index=all] [<priority>] [<ring_size>] [outputs=<N>] <address> [<payment_id (obsolete)>]");
  const char* USAGE_SIGN_TRANSFER("sign_transfer [export_raw]");
  const char* USAGE_SET_LOG("set_log <level>|{+,-,}<categories>");
  const char* USAGE_ACCOUNT("account\n"
                            "  account new <label text with white spaces allowed>\n"
                            "  account switch <index> \n"
                            "  account label <index> <label text with white spaces allowed>\n"
                            "  account tag <tag_name> <account_index_1> [<account_index_2> ...]\n"
                            "  account untag <account_index_1> [<account_index_2> ...]\n"
                            "  account tag_description <tag_name> <description>");
  const char* USAGE_ADDRESS("address [ new <label text with white spaces allowed> | all | <index_min> [<index_max>] | label <index> <label text with white spaces allowed> | device [<index>]]");
  const char* USAGE_INTEGRATED_ADDRESS("integrated_address [device] [<payment_id> | <address>]");
  const char* USAGE_ADDRESS_BOOK("address_book [(add (<address>|<integrated address>) [<description possibly with whitespaces>])|(delete <index>)]");
  const char* USAGE_SET_VARIABLE("set <option> [<value>]");
  const char* USAGE_GET_TX_KEY("get_tx_key <txid>");
  const char* USAGE_SET_TX_KEY("set_tx_key <txid> <tx_key>");
  const char* USAGE_CHECK_TX_KEY("check_tx_key <txid> <txkey> <address>");
  const char* USAGE_GET_TX_PROOF("get_tx_proof <txid> <address> [<message>]");
  const char* USAGE_CHECK_TX_PROOF("check_tx_proof <txid> <address> <signature_file> [<message>]");
  const char* USAGE_GET_SPEND_PROOF("get_spend_proof <txid> [<message>]");
  const char* USAGE_CHECK_SPEND_PROOF("check_spend_proof <txid> <signature_file> [<message>]");
  const char* USAGE_GET_RESERVE_PROOF("get_reserve_proof (all|<amount>) [<message>]");
  const char* USAGE_CHECK_RESERVE_PROOF("check_reserve_proof <address> <signature_file> [<message>]");
  const char* USAGE_SHOW_TRANSFERS("show_transfers [in] [out] [stake] [all] [pending] [failed] [coinbase] [index=<N1>[,<N2>,...]] [<min_height> [<max_height>]]");
  const char* USAGE_EXPORT_TRANSFERS("export_transfers [in|out|all|pending|failed] [index=<N1>[,<N2>,...]] [<min_height> [<max_height>]] [output=<path>]");
  const char* USAGE_UNSPENT_OUTPUTS("unspent_outputs [index=<N1>[,<N2>,...]] [<min_amount> [<max_amount>]]");
  const char* USAGE_RESCAN_BC("rescan_bc [hard|soft|keep_ki] [start_height=0]");
  const char* USAGE_SET_TX_NOTE("set_tx_note <txid> [free text note]");
  const char* USAGE_GET_TX_NOTE("get_tx_note <txid>");
  const char* USAGE_GET_DESCRIPTION("get_description");
  const char* USAGE_SET_DESCRIPTION("set_description [free text note]");
  const char* USAGE_SIGN("sign [<account_index>,<address_index>] <filename>");
  const char* USAGE_SIGN_VALUE("sign_value [<account_index>,<address_index>] <value>");
  const char* USAGE_VERIFY("verify <filename> <address> <signature>");
  const char* USAGE_VERIFY_VALUE("verify_value <address> <signature> <value>");
  const char* USAGE_EXPORT_KEY_IMAGES("export_key_images <filename> [requested-only]");
  const char* USAGE_IMPORT_KEY_IMAGES("import_key_images <filename>");
  const char* USAGE_HW_KEY_IMAGES_SYNC("hw_key_images_sync");
  const char* USAGE_HW_RECONNECT("hw_reconnect");
  const char* USAGE_EXPORT_OUTPUTS("export_outputs [all] <filename>");
  const char* USAGE_IMPORT_OUTPUTS("import_outputs <filename>");
  const char* USAGE_SHOW_TRANSFER("show_transfer <txid>");
  const char* USAGE_MAKE_MULTISIG("make_multisig <threshold> <string1> [<string>...]");
  const char* USAGE_FINALIZE_MULTISIG("finalize_multisig <string> [<string>...]");
  const char* USAGE_EXCHANGE_MULTISIG_KEYS("exchange_multisig_keys <string> [<string>...]");
  const char* USAGE_EXPORT_MULTISIG_INFO("export_multisig_info <filename>");
  const char* USAGE_IMPORT_MULTISIG_INFO("import_multisig_info <filename> [<filename>...]");
  const char* USAGE_SIGN_MULTISIG("sign_multisig <filename>");
  const char* USAGE_SUBMIT_MULTISIG("submit_multisig <filename>");
  const char* USAGE_EXPORT_RAW_MULTISIG_TX("export_raw_multisig_tx <filename>");
#ifdef WALLET_ENABLE_MMS
  const char* USAGE_MMS("mms [<subcommand> [<subcommand_parameters>]]");
  const char* USAGE_MMS_INIT("mms init <required_signers>/<authorized_signers> <own_label> <own_transport_address>");
  const char* USAGE_MMS_INFO("mms info");
  const char* USAGE_MMS_SIGNER("mms signer [<number> <label> [<transport_address> [<oxen_address>]]]");
  const char* USAGE_MMS_LIST("mms list");
  const char* USAGE_MMS_NEXT("mms next [sync]");
  const char* USAGE_MMS_SYNC("mms sync");
  const char* USAGE_MMS_TRANSFER("mms transfer <transfer_command_arguments>");
  const char* USAGE_MMS_DELETE("mms delete (<message_id> | all)");
  const char* USAGE_MMS_SEND("mms send [<message_id>]");
  const char* USAGE_MMS_RECEIVE("mms receive");
  const char* USAGE_MMS_EXPORT("mms export <message_id>");
  const char* USAGE_MMS_NOTE("mms note [<label> <text>]");
  const char* USAGE_MMS_SHOW("mms show <message_id>");
  const char* USAGE_MMS_SET("mms set <option_name> [<option_value>]");
  const char* USAGE_MMS_SEND_SIGNER_CONFIG("mms send_signer_config");
  const char* USAGE_MMS_START_AUTO_CONFIG("mms start_auto_config [<label> <label> ...]");
  const char* USAGE_MMS_STOP_AUTO_CONFIG("mms stop_auto_config");
  const char* USAGE_MMS_AUTO_CONFIG("mms auto_config <auto_config_token>");
#endif
  const char* USAGE_PRINT_RING("print_ring <key_image> | <txid>");
  const char* USAGE_SET_RING("set_ring <filename> | ( <key_image> absolute|relative <index> [<index>...] )");
  const char* USAGE_UNSET_RING("unset_ring <txid> | ( <key_image> [<key_image>...] )");
  const char* USAGE_SAVE_KNOWN_RINGS("save_known_rings");
  const char* USAGE_MARK_OUTPUT_SPENT("mark_output_spent <amount>/<offset> | <filename> [add]");
  const char* USAGE_MARK_OUTPUT_UNSPENT("mark_output_unspent <amount>/<offset>");
  const char* USAGE_IS_OUTPUT_SPENT("is_output_spent <amount>/<offset>");
  const char* USAGE_FREEZE("freeze <key_image>");
  const char* USAGE_THAW("thaw <key_image>");
  const char* USAGE_FROZEN("frozen <key_image>");
  const char* USAGE_LOCK("lock");
  const char* USAGE_NET_STATS("net_stats");
  const char* USAGE_WELCOME("welcome");
  const char* USAGE_VERSION("version");
  const char* USAGE_HELP("help [<command>]");

  //
  // Oxen
  //
  const char* USAGE_REGISTER_SERVICE_NODE("register_service_node [index=<N1>[,<N2>,...]] [<priority>] <operator cut> <address1> <fraction1> [<address2> <fraction2> [...]] <expiration timestamp> <pubkey> <signature>");
  const char* USAGE_STAKE("stake [index=<N1>[,<N2>,...]] [<priority>] <service node pubkey> <amount|percent%>");
  const char* USAGE_REQUEST_STAKE_UNLOCK("request_stake_unlock <service_node_pubkey>");
  const char* USAGE_PRINT_LOCKED_STAKES("print_locked_stakes [+key_images]");

  const char* USAGE_ONS_BUY_MAPPING("ons_buy_mapping [index=<N1>[,<N2>,...]] [<priority>] [type=session|lokinet|lokinet_2y|lokinet_5y|lokinet_10y] [owner=<value>] [backup_owner=<value>] <name> <value>");
  const char* USAGE_ONS_RENEW_MAPPING("ons_renew_mapping [index=<N1>[,<N2>,...]] [<priority>] [type=lokinet|lokinet_2y|lokinet_5y|lokinet_10y] <name>");
  const char* USAGE_ONS_UPDATE_MAPPING("ons_update_mapping [index=<N1>[,<N2>,...]] [<priority>] [type=session|lokinet] [owner=<value>] [backup_owner=<value>] [value=<ons_value>] [signature=<hex_signature>] <name>");

  const char* USAGE_ONS_ENCRYPT("ons_encrypt [type=session|lokinet] <name> <value>");
  const char* USAGE_ONS_MAKE_UPDATE_MAPPING_SIGNATURE("ons_make_update_mapping_signature [type=session|lokinet] [owner=<value>] [backup_owner=<value>] [value=<encrypted_ons_value>] <name>");
  const char* USAGE_ONS_BY_OWNER("ons_by_owner [<owner> ...]");
  const char* USAGE_ONS_LOOKUP("ons_lookup [type=session|wallet|lokinet] <name> [<name> ...]");

  std::string input_line(const std::string& prompt, bool yesno = false)
  {
    std::string buf;
    rdln::suspend_readline pause_readline;

    std::cout << prompt;
    if (yesno)
      std::cout << " (Y/Yes/N/No)";
    std::cout << ": " << std::flush;

#ifdef _WIN32
    buf = tools::input_line_win();
#else
    std::getline(std::cin, buf);
#endif

    epee::string_tools::trim(buf);
    return buf;
  }

  epee::wipeable_string input_secure_line(const char *prompt)
  {
    rdln::suspend_readline pause_readline;
    auto pwd_container = tools::password_container::prompt(false, prompt, false);
    if (!pwd_container)
    {
      MERROR("Failed to read secure line");
      return "";
    }

    epee::wipeable_string buf = pwd_container->password();

    buf.trim();
    return buf;
  }

  std::optional<tools::password_container> password_prompter(const char *prompt, bool verify)
  {
    rdln::suspend_readline pause_readline;
    auto pwd_container = tools::password_container::prompt(verify, prompt);
    if (!pwd_container)
    {
      tools::fail_msg_writer() << sw::tr("failed to read wallet password");
    }
    return pwd_container;
  }

  std::optional<tools::password_container> default_password_prompter(bool verify)
  {
    return password_prompter(verify ? sw::tr("Enter a new password for the wallet") : sw::tr("Wallet password"), verify);
  }

  inline std::string interpret_rpc_response(bool ok, const std::string& status)
  {
    std::string err;
    if (ok)
    {
      if (status == rpc::STATUS_BUSY)
      {
        err = sw::tr("daemon is busy. Please try again later.");
      }
      else if (status != rpc::STATUS_OK)
      {
        err = status;
      }
    }
    else
    {
      err = sw::tr("possibly lost connection to daemon");
    }
    return err;
  }

  tools::scoped_message_writer success_msg_writer(bool color = false)
  {
    return tools::scoped_message_writer(color ? epee::console_color_green : epee::console_color_default, false, std::string{}, el::Level::Info);
  }

  tools::scoped_message_writer message_writer(epee::console_colors color = epee::console_color_default, bool bright = false)
  {
    return tools::scoped_message_writer(color, bright);
  }

  tools::scoped_message_writer fail_msg_writer()
  {
    return tools::scoped_message_writer(epee::console_color_red, true, sw::tr("Error: "), el::Level::Error);
  }

  tools::scoped_message_writer warn_msg_writer()
  {
    return tools::scoped_message_writer(epee::console_color_red, true, sw::tr("Warning: "), el::Level::Error);
  }

  bool parse_bool(const std::string& s, bool& result)
  {
    if (command_line::is_yes(s, "1", "true", simple_wallet::tr("true")))
    {
      result = true;
      return true;
    }
    if (command_line::is_no(s, "0", "false", simple_wallet::tr("false")))
    {
      result = false;
      return true;
    }
    return false;
  }

  template <typename F>
  bool parse_bool_and_use(const std::string& s, F func)
  {
    bool r;
    if (parse_bool(s, r))
    {
      func(r);
      return true;
    }
    else
    {
      fail_msg_writer() << sw::tr("invalid argument: must be either 0/1, true/false, y/n, yes/no");
      return false;
    }
  }

  const struct
  {
    const char *name;
    tools::wallet2::RefreshType refresh_type;
  } refresh_type_names[] =
  {
    { "full", tools::wallet2::RefreshFull },
    { "optimize-coinbase", tools::wallet2::RefreshOptimizeCoinbase },
    { "optimized-coinbase", tools::wallet2::RefreshOptimizeCoinbase },
    { "no-coinbase", tools::wallet2::RefreshNoCoinbase },
    { "default", tools::wallet2::RefreshDefault },
  };

  bool parse_refresh_type(const std::string &s, tools::wallet2::RefreshType &refresh_type)
  {
    for (size_t n = 0; n < sizeof(refresh_type_names) / sizeof(refresh_type_names[0]); ++n)
    {
      if (s == refresh_type_names[n].name)
      {
        refresh_type = refresh_type_names[n].refresh_type;
        return true;
      }
    }
    fail_msg_writer() << cryptonote::simple_wallet::tr("failed to parse refresh type");
    return false;
  }

  std::string get_refresh_type_name(tools::wallet2::RefreshType type)
  {
    for (size_t n = 0; n < sizeof(refresh_type_names) / sizeof(refresh_type_names[0]); ++n)
    {
      if (type == refresh_type_names[n].refresh_type)
        return refresh_type_names[n].name;
    }
    return "invalid";
  }

  std::optional<std::pair<uint32_t, uint32_t>> parse_subaddress_lookahead(const std::string& str)
  {
    auto r = tools::parse_subaddress_lookahead(str);
    if (!r)
      fail_msg_writer() << sw::tr("invalid format for subaddress lookahead; must be <major>:<minor>");
    return r;
  }

  void handle_transfer_exception(const std::exception_ptr &e, bool trusted_daemon)
  {
    bool warn_of_possible_attack = !trusted_daemon;
    try
    {
      std::rethrow_exception(e);
    }
    catch (const tools::error::daemon_busy&)
    {
      fail_msg_writer() << sw::tr("daemon is busy. Please try again later.");
    }
    catch (const tools::error::no_connection_to_daemon&)
    {
      fail_msg_writer() << sw::tr("no connection to daemon. Please make sure daemon is running.");
    }
    catch (const tools::error::wallet_rpc_error& e)
    {
      LOG_ERROR("RPC error: " << e.to_string());
      fail_msg_writer() << sw::tr("RPC error: ") << e.what();
    }
    catch (const tools::error::get_outs_error &e)
    {
      fail_msg_writer() << sw::tr("failed to get random outputs to mix: ") << e.what();
    }
    catch (const tools::error::not_enough_unlocked_money& e)
    {
      LOG_PRINT_L0(boost::format("not enough money to transfer, available only %s, sent amount %s") %
        print_money(e.available()) %
        print_money(e.tx_amount()));
      fail_msg_writer() << sw::tr("Not enough money in unlocked balance");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::not_enough_money& e)
    {
      LOG_PRINT_L0(boost::format("not enough money to transfer, available only %s, sent amount %s") %
        print_money(e.available()) %
        print_money(e.tx_amount()));
      fail_msg_writer() << sw::tr("Not enough money in unlocked balance");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::tx_not_possible& e)
    {
      LOG_PRINT_L0(boost::format("not enough money to transfer, available only %s, transaction amount %s = %s + %s (fee)") %
        print_money(e.available()) %
        print_money(e.tx_amount() + e.fee())  %
        print_money(e.tx_amount()) %
        print_money(e.fee()));
      fail_msg_writer() << sw::tr("Failed to find a way to create transactions. This is usually due to dust which is so small it cannot pay for itself in fees, or trying to send more money than the unlocked balance, or not leaving enough for fees");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::not_enough_outs_to_mix& e)
    {
      auto writer = fail_msg_writer();
      writer << sw::tr("not enough outputs for specified ring size") << " = " << (e.mixin_count() + 1) << ":";
      for (std::pair<uint64_t, uint64_t> outs_for_amount : e.scanty_outs())
      {
        writer << "\n" << sw::tr("output amount") << " = " << print_money(outs_for_amount.first) << ", " << sw::tr("found outputs to use") << " = " << outs_for_amount.second;
      }
      writer << "\n" << sw::tr("Please use sweep_unmixable.");
    }
    catch (const tools::error::tx_not_constructed&)
    {
      fail_msg_writer() << sw::tr("transaction was not constructed");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::tx_rejected& e)
    {
      fail_msg_writer() << (boost::format(sw::tr("transaction %s was rejected by daemon")) % get_transaction_hash(e.tx()));
      std::string reason = e.reason();
      if (!reason.empty())
        fail_msg_writer() << sw::tr("Reason: ") << reason;
    }
    catch (const tools::error::tx_sum_overflow& e)
    {
      fail_msg_writer() << e.what();
      warn_of_possible_attack = false;
    }
    catch (const tools::error::zero_destination&)
    {
      fail_msg_writer() << sw::tr("one of destinations is zero");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::tx_too_big& e)
    {
      fail_msg_writer() << sw::tr("failed to find a suitable way to split transactions");
      warn_of_possible_attack = false;
    }
    catch (const tools::error::transfer_error& e)
    {
      LOG_ERROR("unknown transfer error: " << e.to_string());
      fail_msg_writer() << sw::tr("unknown transfer error: ") << e.what();
    }
    catch (const tools::error::multisig_export_needed& e)
    {
      LOG_ERROR("Multisig error: " << e.to_string());
      fail_msg_writer() << sw::tr("Multisig error: ") << e.what();
      warn_of_possible_attack = false;
    }
    catch (const tools::error::wallet_internal_error& e)
    {
      LOG_ERROR("internal error: " << e.to_string());
      fail_msg_writer() << sw::tr("internal error: ") << e.what();
    }
    catch (const std::exception& e)
    {
      LOG_ERROR("unexpected error: " << e.what());
      fail_msg_writer() << sw::tr("unexpected error: ") << e.what();
    }

    if (warn_of_possible_attack)
      fail_msg_writer() << sw::tr("There was an error, which could mean the node may be trying to get you to retry creating a transaction, and zero in on which outputs you own. Or it could be a bona fide error. It may be prudent to disconnect from this node, and not try to send a transaction immediately. Alternatively, connect to another node so the original node cannot correlate information.");
  }

  bool check_file_overwrite(const fs::path& filename)
  {
    if (std::error_code ec; fs::exists(filename, ec))
    {
      if (filename.extension() == ".keys")
      {
        fail_msg_writer() << boost::format(sw::tr("File %s likely stores wallet private keys! Use a different file name.")) % filename.u8string();
        return false;
      }
      return command_line::is_yes(input_line((boost::format(sw::tr("File %s already exists. Are you sure to overwrite it?")) % filename.u8string()).str(), true));
    }
    return true;
  }

  void print_secret_key(const crypto::secret_key &k)
  {
    std::string_view data{k.data, sizeof(k.data)};
    std::ostream_iterator<char> osi{std::cout};
    oxenc::to_hex(data.begin(), data.end(), osi);
  }

  bool long_payment_id_failure(bool ret)
  {
    fail_msg_writer() << tr("Error: Long payment IDs are obsolete.");
    fail_msg_writer() << tr("Long payment IDs were not encrypted on the blockchain and would harm your privacy.");
    fail_msg_writer() << tr("If the party you're sending to still requires a long payment ID, please notify them.");
    return ret;
  }
}

std::string join_priority_strings(const char *delimiter)
{
  std::string s;
  for (size_t n = 0; n < tools::allowed_priority_strings.size(); ++n)
  {
    if (!s.empty())
      s += delimiter;
    s += tools::allowed_priority_strings[n];
  }
  return s;
}

std::string simple_wallet::get_commands_str()
{
  std::stringstream ss;
  ss << tr("Commands: ") << "\n";
  m_cmd_binder.for_each([&ss](auto&, const std::string& usage, auto&) { ss << "  " << usage << "\n"; });
  return ss.str();
}

std::string simple_wallet::get_command_usage(const std::vector<std::string> &args)
{
  std::pair<std::string, std::string> documentation = m_cmd_binder.get_documentation(args);
  std::stringstream ss;
  if(documentation.first.empty())
  {
    ss << tr("Unknown command: ") << args.front();
  }
  else
  {
    std::string usage = documentation.second.empty() ? args.front() : documentation.first;
    std::string description = documentation.second.empty() ? documentation.first : documentation.second;
    ss << tr("Command usage: ") << "\n  " << usage << "\n\n";
    ss << tr("Command description: ") << "\n  ";
    for (char c : description)
    {
      if (c == '\n')
        ss << "\n  ";
      else
        ss << c;
    }
  }
  return ss.str();
}

bool simple_wallet::viewkey(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  // don't log
  rdln::suspend_readline pause_readline;
  if (m_wallet->key_on_device()) {
    std::cout << "secret: On device. Not available" << std::endl;
  } else {
    SCOPED_WALLET_UNLOCK();
    std::cout << "secret: ";
    print_secret_key(m_wallet->get_account().get_keys().m_view_secret_key);
    std::cout << '\n';
  }
  std::cout << "public: " << tools::type_to_hex(m_wallet->get_account().get_keys().m_account_address.m_view_public_key) << std::endl;

  return true;
}

bool simple_wallet::spendkey(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  if (m_wallet->watch_only())
  {
    fail_msg_writer() << tr("wallet is watch-only and has no spend key");
    return true;
  }
  // don't log
  rdln::suspend_readline pause_readline;
  if (m_wallet->key_on_device()) {
    std::cout << "secret: On device. Not available" << std::endl;
  } else {
    SCOPED_WALLET_UNLOCK();

    warn_msg_writer() << tr("NEVER give your Oxen wallet private spend key (or seed phrase) to ANYONE else. "
            "NEVER input your Oxen private spend key (or seed phrase) into any software or website other than the OFFICIAL "
            "Oxen CLI or GUI wallets, downloaded directly from the Oxen GitHub (https://github.com/oxen-io/) or compiled from source.");
    std::string confirm = input_line(tr("Are you sure you want to access your private spend key?"), true);
    if (std::cin.eof() || !command_line::is_yes(confirm))
      return false;

    std::cout << "secret: ";
    print_secret_key(m_wallet->get_account().get_keys().m_spend_secret_key);
    std::cout << '\n';
  }
  std::cout << "public: " << tools::type_to_hex(m_wallet->get_account().get_keys().m_account_address.m_spend_public_key) << std::endl;

  return true;
}

bool simple_wallet::print_seed(bool encrypted)
{
  bool success =  false;
  epee::wipeable_string seed;
  bool ready, multisig;

  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return true;
  }
  if (m_wallet->watch_only())
  {
    fail_msg_writer() << tr("wallet is watch-only and has no seed");
    return true;
  }

  multisig = m_wallet->multisig(&ready);
  if (multisig)
  {
    if (!ready)
    {
      fail_msg_writer() << tr("wallet is multisig but not yet finalized");
      return true;
    }
  }

  SCOPED_WALLET_UNLOCK();

  if (!multisig && !m_wallet->is_deterministic())
  {
    fail_msg_writer() << tr("wallet is non-deterministic and has no seed");
    return true;
  }

  epee::wipeable_string seed_pass;
  if (encrypted)
  {
    auto pwd_container = password_prompter(tr("Enter optional seed offset passphrase, empty to see raw seed"), true);
    if (std::cin.eof() || !pwd_container)
      return true;
    seed_pass = pwd_container->password();
  }

  if (multisig)
    success = m_wallet->get_multisig_seed(seed, seed_pass);
  else if (m_wallet->is_deterministic())
    success = m_wallet->get_seed(seed, seed_pass);

  if (success)
  {
    print_seed(seed);
  }
  else
  {
    fail_msg_writer() << tr("Failed to retrieve seed");
  }
  return true;
}

bool simple_wallet::seed(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  return print_seed(false);
}

bool simple_wallet::encrypted_seed(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  return print_seed(true);
}

bool simple_wallet::restore_height(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  success_msg_writer() << m_wallet->get_refresh_from_block_height();
  return true;
}

bool simple_wallet::seed_set_language(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return true;
  }
  if (m_wallet->multisig())
  {
    fail_msg_writer() << tr("wallet is multisig and has no seed");
    return true;
  }
  if (m_wallet->watch_only())
  {
    fail_msg_writer() << tr("wallet is watch-only and has no seed");
    return true;
  }

  epee::wipeable_string password;
  {
    SCOPED_WALLET_UNLOCK();

    if (!m_wallet->is_deterministic())
    {
      fail_msg_writer() << tr("wallet is non-deterministic and has no seed");
      return true;
    }

    // we need the password, even if ask-password is unset
    if (!pwd_container)
    {
      pwd_container = get_and_verify_password();
      if (!pwd_container)
      {
        fail_msg_writer() << tr("Incorrect password");
        return true;
      }
    }
    password = pwd_container->password();
  }

  std::string mnemonic_language = get_mnemonic_language();
  if (mnemonic_language.empty())
    return true;

  m_wallet->set_seed_language(std::move(mnemonic_language));
  m_wallet->rewrite(m_wallet_file, password);
  return true;
}

bool simple_wallet::change_password(const std::vector<std::string> &args)
{
  const auto orig_pwd_container = get_and_verify_password();

  if(!orig_pwd_container)
  {
    fail_msg_writer() << tr("Your original password was incorrect.");
    return true;
  }

  // prompts for a new password, pass true to verify the password
  const auto pwd_container = default_password_prompter(true);
  if(!pwd_container)
    return true;

  try
  {
    m_wallet->change_password(m_wallet_file, orig_pwd_container->password(), pwd_container->password());
  }
  catch (const tools::error::wallet_logic_error& e)
  {
    fail_msg_writer() << tr("Error with wallet rewrite: ") << e.what();
    return true;
  }

  return true;
}

bool simple_wallet::print_fee_info(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  if (!try_connect_to_daemon())
    return true;
  const auto base_fee = m_wallet->get_base_fees();
  const uint64_t typical_size = 2500, typical_outs = 2;
  message_writer() << (boost::format(tr("Current base fee is %s %s per byte + %s %s per output")) %
          print_money(base_fee.first) % cryptonote::get_unit() %
          print_money(base_fee.second) % cryptonote::get_unit()).str();

  std::vector<uint64_t> fees;
  std::ostringstream typical_fees;
  uint64_t pct = m_wallet->get_fee_percent(1, txtype::standard);
  uint64_t typical_fee = (base_fee.first * typical_size + base_fee.second * typical_outs) * pct / 100;
  fees.push_back(typical_fee);
  typical_fees << print_money(typical_fee) << " (" << tools::allowed_priority_strings[1] << ")";

  auto hf_version = m_wallet->get_hard_fork_version();
  if (hf_version && *hf_version >= feature::BLINK)
  {
    uint64_t pct = m_wallet->get_fee_percent(tools::tx_priority_blink, txtype::standard);
    uint64_t fixed = oxen::BLINK_BURN_FIXED;

    uint64_t typical_blink_fee = (base_fee.first * typical_size + base_fee.second * typical_outs) * pct / 100 + fixed;

    if (fixed)
      message_writer() << (boost::format(tr("Current blink fee is %s %s per byte + %s %s per output + %s %s")) %
          print_money(base_fee.first * pct / 100) % cryptonote::get_unit() %
          print_money(base_fee.second * pct / 100) % cryptonote::get_unit() %
          print_money(fixed) % cryptonote::get_unit()).str();
    else
      message_writer() << (boost::format(tr("Current blink fee is %s %s per byte + %s %s per output")) %
          print_money(base_fee.first * pct / 100) % cryptonote::get_unit() %
          print_money(base_fee.second * pct / 100) % cryptonote::get_unit()).str();

    typical_fees << ", " << print_money(typical_blink_fee) << " (blink)";
  }

  message_writer() << "Estimated typical small transaction fees: " << typical_fees.str();

  return true;
}

bool simple_wallet::prepare_multisig(const std::vector<std::string> &args)
{
  prepare_multisig_main(args ENABLE_IF_MMS(, false));
  return true;
}

bool simple_wallet::prepare_multisig_main(const std::vector<std::string> &args ENABLE_IF_MMS(, bool called_by_mms))
{
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return false;
  }
  if (m_wallet->multisig())
  {
    fail_msg_writer() << tr("This wallet is already multisig");
    return false;
  }
  if (m_wallet->watch_only())
  {
    fail_msg_writer() << tr("wallet is watch-only and cannot be made multisig");
    return false;
  }

  if(m_wallet->get_num_transfer_details())
  {
    fail_msg_writer() << tr("This wallet has been used before, please use a new wallet to create a multisig wallet");
    return false;
  }

  SCOPED_WALLET_UNLOCK_ON_BAD_PASSWORD(return false;);

  std::string multisig_info = m_wallet->get_multisig_info();
  success_msg_writer() << multisig_info;
  success_msg_writer() << tr("Send this multisig info to all other participants, then use make_multisig <threshold> <info1> [<info2>...] with others' multisig info");
  success_msg_writer() << tr("This includes the PRIVATE view key, so needs to be disclosed only to that multisig wallet's participants ");

#ifdef WALLET_ENABLE_MMS
  if (called_by_mms)
  {
    get_message_store().process_wallet_created_data(get_multisig_wallet_state(), mms::message_type::key_set, multisig_info);
  }
#endif

  return true;
}

bool simple_wallet::make_multisig(const std::vector<std::string> &args)
{
  make_multisig_main(args ENABLE_IF_MMS(, false));
  return true;
}

bool simple_wallet::make_multisig_main(const std::vector<std::string> &args ENABLE_IF_MMS(, bool called_by_mms))
{
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return false;
  }
  if (m_wallet->multisig())
  {
    fail_msg_writer() << tr("This wallet is already multisig");
    return false;
  }
  if (m_wallet->watch_only())
  {
    fail_msg_writer() << tr("wallet is watch-only and cannot be made multisig");
    return false;
  }

  if(m_wallet->get_num_transfer_details())
  {
    fail_msg_writer() << tr("This wallet has been used before, please use a new wallet to create a multisig wallet");
    return false;
  }

  if (args.size() < 2)
  {
    PRINT_USAGE(USAGE_MAKE_MULTISIG);
    return false;
  }

  // parse threshold
  uint32_t threshold;
  if (!string_tools::get_xtype_from_string(threshold, args[0]))
  {
    fail_msg_writer() << tr("Invalid threshold");
    return false;
  }

  const auto orig_pwd_container = get_and_verify_password();
  if(!orig_pwd_container)
  {
    fail_msg_writer() << tr("Your original password was incorrect.");
    return false;
  }

  LOCK_IDLE_SCOPE();

  try
  {
    auto local_args = args;
    local_args.erase(local_args.begin());
    std::string multisig_extra_info = m_wallet->make_multisig(orig_pwd_container->password(), local_args, threshold);
    if (!multisig_extra_info.empty())
    {
      success_msg_writer() << tr("Another step is needed");
      success_msg_writer() << multisig_extra_info;
      success_msg_writer() << tr("Send this multisig info to all other participants, then use exchange_multisig_keys <info1> [<info2>...] with others' multisig info");
#ifdef WALLET_ENABLE_MMS
      if (called_by_mms)
      {
        get_message_store().process_wallet_created_data(get_multisig_wallet_state(), mms::message_type::additional_key_set, multisig_extra_info);
      }
#endif
      return true;
    }
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("Error creating multisig: ") << e.what();
    return false;
  }

  uint32_t total;
  if (!m_wallet->multisig(NULL, &threshold, &total))
  {
    fail_msg_writer() << tr("Error creating multisig: new wallet is not multisig");
    return false;
  }
  success_msg_writer() << std::to_string(threshold) << "/" << total << tr(" multisig address: ")
      << m_wallet->get_account().get_public_address_str(m_wallet->nettype());

  return true;
}

bool simple_wallet::finalize_multisig(const std::vector<std::string> &args)
{
  bool ready;
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return true;
  }

  const auto pwd_container = get_and_verify_password();
  if(!pwd_container)
  {
    fail_msg_writer() << tr("Your original password was incorrect.");
    return true;
  }

  if (!m_wallet->multisig(&ready))
  {
    fail_msg_writer() << tr("This wallet is not multisig");
    return true;
  }
  if (ready)
  {
    fail_msg_writer() << tr("This wallet is already finalized");
    return true;
  }

  LOCK_IDLE_SCOPE();

  if (args.size() < 2)
  {
    PRINT_USAGE(USAGE_FINALIZE_MULTISIG);
    return true;
  }

  try
  {
    if (!m_wallet->finalize_multisig(pwd_container->password(), args))
    {
      fail_msg_writer() << tr("Failed to finalize multisig");
      return true;
    }
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("Failed to finalize multisig: ") << e.what();
    return true;
  }

  return true;
}

bool simple_wallet::exchange_multisig_keys(const std::vector<std::string> &args)
{
  exchange_multisig_keys_main(args ENABLE_IF_MMS(, false));
  return true;
}

bool simple_wallet::exchange_multisig_keys_main(const std::vector<std::string> &args ENABLE_IF_MMS(, bool called_by_mms)) {
    bool ready;
    if (m_wallet->key_on_device())
    {
      fail_msg_writer() << tr("command not supported by HW wallet");
      return false;
    }
    if (!m_wallet->multisig(&ready))
    {
      fail_msg_writer() << tr("This wallet is not multisig");
      return false;
    }
    if (ready)
    {
      fail_msg_writer() << tr("This wallet is already finalized");
      return false;
    }

    const auto orig_pwd_container = get_and_verify_password();
    if(!orig_pwd_container)
    {
      fail_msg_writer() << tr("Your original password was incorrect.");
      return false;
    }

    if (args.size() < 2)
    {
      PRINT_USAGE(USAGE_EXCHANGE_MULTISIG_KEYS);
      return false;
    }

    try
    {
      std::string multisig_extra_info = m_wallet->exchange_multisig_keys(orig_pwd_container->password(), args);
      if (!multisig_extra_info.empty())
      {
        message_writer() << tr("Another step is needed");
        message_writer() << multisig_extra_info;
        message_writer() << tr("Send this multisig info to all other participants, then use exchange_multisig_keys <info1> [<info2>...] with others' multisig info");
#ifdef WALLET_ENABLE_MMS
        if (called_by_mms)
        {
          get_message_store().process_wallet_created_data(get_multisig_wallet_state(), mms::message_type::additional_key_set, multisig_extra_info);
        }
#endif
        return true;
      } else {
        uint32_t threshold, total;
        m_wallet->multisig(NULL, &threshold, &total);
        success_msg_writer() << tr("Multisig wallet has been successfully created. Current wallet type: ") << threshold << "/" << total;
        success_msg_writer() << tr("Multisig address: ") << m_wallet->get_account().get_public_address_str(m_wallet->nettype());
      }
    }
    catch (const std::exception &e)
    {
      fail_msg_writer() << tr("Failed to perform multisig keys exchange: ") << e.what();
      return false;
    }

    return true;
}

bool simple_wallet::export_multisig(const std::vector<std::string> &args)
{
  export_multisig_main(args ENABLE_IF_MMS(, false));
  return true;
}

bool simple_wallet::export_multisig_main(const std::vector<std::string> &args ENABLE_IF_MMS(, bool called_by_mms))
{
  bool ready;
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return false;
  }
  if (!m_wallet->multisig(&ready))
  {
    fail_msg_writer() << tr("This wallet is not multisig");
    return false;
  }
  if (!ready)
  {
    fail_msg_writer() << tr("This multisig wallet is not yet finalized");
    return false;
  }
  if (args.size() != 1)
  {
    PRINT_USAGE(USAGE_EXPORT_MULTISIG_INFO);
    return false;
  }

  const fs::path filename = fs::u8path(args[0]);
  if (
#ifdef WALLET_ENABLE_MMS
          !called_by_mms &&
#endif
          m_wallet->confirm_export_overwrite() && !check_file_overwrite(filename))
    return true;

  SCOPED_WALLET_UNLOCK_ON_BAD_PASSWORD(return false;);

  try
  {
    std::string ciphertext = m_wallet->export_multisig();

#ifdef WALLET_ENABLE_MMS
    if (called_by_mms)
    {
      get_message_store().process_wallet_created_data(get_multisig_wallet_state(), mms::message_type::multisig_sync_data, ciphertext);
    }
    else
#endif
    {
      bool r = tools::dump_file(filename, ciphertext);
      if (!r)
      {
        fail_msg_writer() << tr("failed to save file ") << filename.u8string();
        return false;
      }
    }
  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Error exporting multisig info: " << e.what());
    fail_msg_writer() << tr("Error exporting multisig info: ") << e.what();
    return false;
  }

  success_msg_writer() << tr("Multisig info exported to ") << filename.u8string();
  return true;
}

bool simple_wallet::import_multisig(const std::vector<std::string> &args)
{
  import_multisig_main(args ENABLE_IF_MMS(, false));
  return true;
}

bool simple_wallet::import_multisig_main(const std::vector<std::string> &args ENABLE_IF_MMS(, bool called_by_mms))
{
  bool ready;
  uint32_t threshold, total;
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return false;
  }
  if (!m_wallet->multisig(&ready, &threshold, &total))
  {
    fail_msg_writer() << tr("This wallet is not multisig");
    return false;
  }
  if (!ready)
  {
    fail_msg_writer() << tr("This multisig wallet is not yet finalized");
    return false;
  }
  if (args.size() < threshold - 1)
  {
    PRINT_USAGE(USAGE_IMPORT_MULTISIG_INFO);
    return false;
  }

  std::vector<std::string> info;
  for (size_t n = 0; n < args.size(); ++n)
  {
#ifdef WALLET_ENABLE_MMS
    if (called_by_mms)
    {
      info.push_back(args[n]);
    }
    else
#endif
    {
      const fs::path filename = fs::u8path(args[n]);
      std::string data;
      bool r = tools::slurp_file(filename, data);
      if (!r)
      {
        fail_msg_writer() << tr("failed to read file ") << filename.u8string();
        return false;
      }
      info.push_back(std::move(data));
    }
  }

  SCOPED_WALLET_UNLOCK_ON_BAD_PASSWORD(return false;);

  // all read and parsed, actually import
  try
  {
    m_in_manual_refresh.store(true, std::memory_order_relaxed);
    OXEN_DEFER { m_in_manual_refresh.store(false, std::memory_order_relaxed); };
    size_t n_outputs = m_wallet->import_multisig(info);
    // Clear line "Height xxx of xxx"
    std::cout << "\r                                                                \r";
    success_msg_writer() << tr("Multisig info imported");
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("Failed to import multisig info: ") << e.what();
    return false;
  }
  if (m_wallet->is_trusted_daemon())
  {
    try
    {
      m_wallet->rescan_spent();
    }
    catch (const std::exception &e)
    {
      message_writer() << tr("Failed to update spent status after importing multisig info: ") << e.what();
      return false;
    }
  }
  else
  {
    message_writer() << tr("Untrusted daemon, spent status may be incorrect. Use a trusted daemon and run \"rescan_spent\"");
    return false;
  }
  return true;
}

bool simple_wallet::accept_loaded_tx(const tools::wallet2::multisig_tx_set &txs)
{
  std::string extra_message;
  return accept_loaded_tx([&txs](){return txs.m_ptx.size();}, [&txs](size_t n)->const wallet::tx_construction_data&{return txs.m_ptx[n].construction_data;}, extra_message);
}

bool simple_wallet::sign_multisig(const std::vector<std::string> &args)
{
  sign_multisig_main(args ENABLE_IF_MMS(, false));
  return true;
}

bool simple_wallet::sign_multisig_main(const std::vector<std::string> &args ENABLE_IF_MMS(, bool called_by_mms))
{
  bool ready;
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return false;
  }
  if(!m_wallet->multisig(&ready))
  {
    fail_msg_writer() << tr("This is not a multisig wallet");
    return false;
  }
  if (!ready)
  {
    fail_msg_writer() << tr("This multisig wallet is not yet finalized");
    return false;
  }
  if (args.size() != 1)
  {
    PRINT_USAGE(USAGE_SIGN_MULTISIG);
    return false;
  }

  SCOPED_WALLET_UNLOCK_ON_BAD_PASSWORD(return false;);

  fs::path filename = fs::u8path(args[0]);
  std::vector<crypto::hash> txids;
  uint32_t signers = 0;
  try
  {
#ifdef WALLET_ENABLE_MMS
    if (called_by_mms)
    {
      tools::wallet2::multisig_tx_set exported_txs;
      std::string ciphertext;
      bool r = m_wallet->load_multisig_tx(args[0], exported_txs, [&](const tools::wallet2::multisig_tx_set &tx){ signers = tx.m_signers.size(); return accept_loaded_tx(tx); });
      if (r)
      {
        r = m_wallet->sign_multisig_tx(exported_txs, txids);
      }
      if (r)
      {
        ciphertext = m_wallet->save_multisig_tx(exported_txs);
        if (ciphertext.empty())
        {
          r = false;
        }
      }
      if (r)
      {
        mms::message_type message_type = mms::message_type::fully_signed_tx;
        if (txids.empty())
        {
          message_type = mms::message_type::partially_signed_tx;
        }
        get_message_store().process_wallet_created_data(get_multisig_wallet_state(), message_type, ciphertext);
        filename = "MMS";   // for the messages below
      }
      else
      {
        fail_msg_writer() << tr("Failed to sign multisig transaction");
        return false;
      }
    }
    else
#endif
    {
      bool r = m_wallet->sign_multisig_tx_from_file(filename, txids, [&](const tools::wallet2::multisig_tx_set &tx){ signers = tx.m_signers.size(); return accept_loaded_tx(tx); });
      if (!r)
      {
        fail_msg_writer() << tr("Failed to sign multisig transaction");
        return false;
      }
    }
  }
  catch (const tools::error::multisig_export_needed& e)
  {
    fail_msg_writer() << tr("Multisig error: ") << e.what();
    return false;
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("Failed to sign multisig transaction: ") << e.what();
    return false;
  }

  if (txids.empty())
  {
    uint32_t threshold{0};
    m_wallet->multisig(NULL, &threshold);
    uint32_t signers_needed = threshold - signers - 1;
    success_msg_writer(true) << tr("Transaction successfully signed to file ") << filename.u8string() << ", "
        << signers_needed << " more signer(s) needed";
    return true;
  }
  else
  {
    std::string txids_as_text;
    for (const auto &txid: txids)
    {
      if (!txids_as_text.empty())
        txids_as_text += (", ");
      txids_as_text += tools::type_to_hex(txid);
    }
    success_msg_writer(true) << tr("Transaction successfully signed to file ") << filename.u8string() << ", txid " << txids_as_text;
    success_msg_writer(true) << tr("It may be relayed to the network with submit_multisig");
  }
  return true;
}

bool simple_wallet::submit_multisig(const std::vector<std::string> &args)
{
  submit_multisig_main(args ENABLE_IF_MMS(, false));
  return true;
}

bool simple_wallet::submit_multisig_main(const std::vector<std::string> &args ENABLE_IF_MMS(, bool called_by_mms))
{
  bool ready;
  uint32_t threshold;
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return false;
  }
  if (!m_wallet->multisig(&ready, &threshold))
  {
    fail_msg_writer() << tr("This is not a multisig wallet");
    return false;
  }
  if (!ready)
  {
    fail_msg_writer() << tr("This multisig wallet is not yet finalized");
    return false;
  }
  if (args.size() != 1)
  {
    PRINT_USAGE(USAGE_SUBMIT_MULTISIG);
    return false;
  }

  if (!try_connect_to_daemon())
    return false;

  SCOPED_WALLET_UNLOCK_ON_BAD_PASSWORD(return false;);

  fs::path filename = fs::u8path(args[0]);
  try
  {
    tools::wallet2::multisig_tx_set txs;
#ifdef WALLET_ENABLE_MMS
    if (called_by_mms)
    {
      bool r = m_wallet->load_multisig_tx(args[0], txs, [&](const tools::wallet2::multisig_tx_set &tx){ return accept_loaded_tx(tx); });
      if (!r)
      {
        fail_msg_writer() << tr("Failed to load multisig transaction from MMS");
        return false;
      }
    }
    else
#endif
    {
      bool r = m_wallet->load_multisig_tx_from_file(filename, txs, [&](const tools::wallet2::multisig_tx_set &tx){ return accept_loaded_tx(tx); });
      if (!r)
      {
        fail_msg_writer() << tr("Failed to load multisig transaction from file");
        return false;
      }
    }
    if (txs.m_signers.size() < threshold)
    {
      fail_msg_writer() << (boost::format(tr("Multisig transaction signed by only %u signers, needs %u more signatures"))
          % txs.m_signers.size() % (threshold - txs.m_signers.size())).str();
      return false;
    }

    constexpr bool FIXME_blink = false; // Blink not supported yet for multisig wallets

    // actually commit the transactions
    for (auto &ptx: txs.m_ptx)
    {
      m_wallet->commit_tx(ptx, FIXME_blink);
      success_msg_writer(true) << tr("Transaction successfully submitted, transaction ") << get_transaction_hash(ptx.tx) << "\n"
          << tr("You can check its status by using the `show_transfers` command.");
    }
  }
  catch (const std::exception &e)
  {
    handle_transfer_exception(std::current_exception(), m_wallet->is_trusted_daemon());
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << tr("unknown error");
    return false;
  }

  return true;
}

bool simple_wallet::export_raw_multisig(const std::vector<std::string> &args)
{
  bool ready;
  uint32_t threshold;
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return true;
  }
  if (!m_wallet->multisig(&ready, &threshold))
  {
    fail_msg_writer() << tr("This is not a multisig wallet");
    return true;
  }
  if (!ready)
  {
    fail_msg_writer() << tr("This multisig wallet is not yet finalized");
    return true;
  }
  if (args.size() != 1)
  {
    PRINT_USAGE(USAGE_EXPORT_RAW_MULTISIG_TX);
    return true;
  }

  fs::path filename = fs::u8path(args[0]);
  if (m_wallet->confirm_export_overwrite() && !check_file_overwrite(filename))
    return true;

  SCOPED_WALLET_UNLOCK();

  try
  {
    tools::wallet2::multisig_tx_set txs;
    bool r = m_wallet->load_multisig_tx_from_file(filename, txs, [&](const tools::wallet2::multisig_tx_set &tx){ return accept_loaded_tx(tx); });
    if (!r)
    {
      fail_msg_writer() << tr("Failed to load multisig transaction from file");
      return true;
    }
    if (txs.m_signers.size() < threshold)
    {
      fail_msg_writer() << (boost::format(tr("Multisig transaction signed by only %u signers, needs %u more signatures"))
          % txs.m_signers.size() % (threshold - txs.m_signers.size())).str();
      return true;
    }

    // save the transactions
    std::string filenames;
    for (auto &ptx: txs.m_ptx)
    {
      const crypto::hash txid = cryptonote::get_transaction_hash(ptx.tx);
      const fs::path fn = fs::u8path("raw_multisig_oxen_tx_" + tools::type_to_hex(txid));
      if (!filenames.empty())
        filenames += ", ";
      filenames += fn.u8string();
      if (!tools::dump_file(fn, cryptonote::tx_to_blob(ptx.tx)))
      {
        fail_msg_writer() << tr("Failed to export multisig transaction to file ") << fn.u8string();
        return true;
      }
    }
    success_msg_writer() << tr("Saved exported multisig transaction file(s): ") << filenames;
  }
  catch (const std::exception& e)
  {
    LOG_ERROR("unexpected error: " << e.what());
    fail_msg_writer() << tr("unexpected error: ") << e.what();
  }
  catch (...)
  {
    LOG_ERROR("Unknown error");
    fail_msg_writer() << tr("unknown error");
  }

  return true;
}

bool simple_wallet::print_ring(const std::vector<std::string> &args)
{
  crypto::key_image key_image;
  crypto::hash txid;
  if (args.size() != 1)
  {
    PRINT_USAGE(USAGE_PRINT_RING);
    return true;
  }

  if (!tools::hex_to_type(args[0], key_image))
  {
    fail_msg_writer() << tr("Invalid key image");
    return true;
  }
  // this one will always work, they're all 32 byte hex
  if (!tools::hex_to_type(args[0], txid))
  {
    fail_msg_writer() << tr("Invalid txid");
    return true;
  }

  std::vector<uint64_t> ring;
  std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> rings;
  try
  {
    if (m_wallet->get_ring(key_image, ring))
      rings.push_back({key_image, ring});
    else if (!m_wallet->get_rings(txid, rings))
    {
      fail_msg_writer() << tr("Key image either not spent, or spent with ring size 1");
      return true;
    }

    for (const auto &ring: rings)
    {
      std::stringstream str;
      for (const auto &x: ring.second)
        str << x<< " ";
      // do NOT translate this "absolute" below, the lin can be used as input to set_ring
      success_msg_writer() << tools::type_to_hex(ring.first) <<  " absolute " << str.str();
    }
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("Failed to get key image ring: ") << e.what();
  }

  return true;
}

bool simple_wallet::set_ring(const std::vector<std::string> &args)
{
  crypto::key_image key_image;

  // try filename first
  if (args.size() == 1)
  {
    auto ring_path = fs::u8path(args[0]);
    if (std::error_code ec; !fs::exists(ring_path, ec) || ec)
    {
      fail_msg_writer() << tr("File doesn't exist");
      return true;
    }

    char str[4096];
    std::unique_ptr<FILE, tools::close_file> f(fopen(args[0].c_str(), "r"));
    if (f)
    {
      while (!feof(f.get()))
      {
        if (!fgets(str, sizeof(str), f.get()))
          break;
        const size_t len = strlen(str);
        if (len > 0 && str[len - 1] == '\n')
          str[len - 1] = 0;
        if (!str[0])
          continue;
        char key_image_str[65], type_str[9];
        int read_after_key_image = 0, read = 0;
        int fields = sscanf(str, "%64[abcdefABCDEF0123456789] %n%8s %n", key_image_str, &read_after_key_image, type_str, &read);
        if (fields != 2)
        {
          fail_msg_writer() << tr("Invalid ring specification: ") << str;
          continue;
        }
        key_image_str[64] = 0;
        type_str[8] = 0;
        crypto::key_image key_image;
        if (read_after_key_image == 0 || !tools::hex_to_type(key_image_str, key_image))
        {
          fail_msg_writer() << tr("Invalid key image: ") << str;
          continue;
        }
        if (read == read_after_key_image+8 || (strcmp(type_str, "absolute") && strcmp(type_str, "relative")))
        {
          fail_msg_writer() << tr("Invalid ring type, expected relative or abosolute: ") << str;
          continue;
        }
        bool relative = !strcmp(type_str, "relative");
        if (read < 0 || (size_t)read > strlen(str))
        {
          fail_msg_writer() << tr("Error reading line: ") << str;
          continue;
        }
        bool valid = true;
        std::vector<uint64_t> ring;
        const char *ptr = str + read;
        while (*ptr)
        {
          unsigned long offset;
          int elements = sscanf(ptr, "%lu %n", &offset, &read);
          if (elements == 0 || read <= 0 || (size_t)read > strlen(str))
          {
            fail_msg_writer() << tr("Error reading line: ") << str;
            valid = false;
            break;
          }
          ring.push_back(offset);
          ptr += read;
        }
        if (!valid)
          continue;
        if (ring.empty())
        {
          fail_msg_writer() << tr("Invalid ring: ") << str;
          continue;
        }
        if (relative)
        {
          for (size_t n = 1; n < ring.size(); ++n)
          {
            if (ring[n] <= 0)
            {
              fail_msg_writer() << tr("Invalid relative ring: ") << str;
              valid = false;
              break;
            }
          }
        }
        else
        {
          for (size_t n = 1; n < ring.size(); ++n)
          {
            if (ring[n] <= ring[n-1])
            {
              fail_msg_writer() << tr("Invalid absolute ring: ") << str;
              valid = false;
              break;
            }
          }
        }
        if (!valid)
          continue;
        if (!m_wallet->set_ring(key_image, ring, relative))
          fail_msg_writer() << tr("Failed to set ring for key image: ") << key_image << ". " << tr("Continuing.");
      }
      f.reset();
    }
    return true;
  }

  if (args.size() < 3)
  {
    PRINT_USAGE(USAGE_SET_RING);
    return true;
  }

  if (!tools::hex_to_type(args[0], key_image))
  {
    fail_msg_writer() << tr("Invalid key image");
    return true;
  }

  bool relative;
  if (args[1] == "absolute")
  {
    relative = false;
  }
  else if (args[1] == "relative")
  {
    relative = true;
  }
  else
  {
    fail_msg_writer() << tr("Missing absolute or relative keyword");
    return true;
  }

  std::vector<uint64_t> ring;
  for (size_t n = 2; n < args.size(); ++n)
  {
    ring.resize(ring.size() + 1);
    if (!string_tools::get_xtype_from_string(ring.back(), args[n]))
    {
      fail_msg_writer() << tr("invalid index: must be a strictly positive unsigned integer");
      return true;
    }
    if (relative)
    {
      if (ring.size() > 1 && !ring.back())
      {
        fail_msg_writer() << tr("invalid index: must be a strictly positive unsigned integer");
        return true;
      }
      uint64_t sum = 0;
      for (uint64_t out: ring)
      {
        if (out > std::numeric_limits<uint64_t>::max() - sum)
        {
          fail_msg_writer() << tr("invalid index: indices wrap");
          return true;
        }
        sum += out;
      }
    }
    else
    {
      if (ring.size() > 1 && ring[ring.size() - 2] >= ring[ring.size() - 1])
      {
        fail_msg_writer() << tr("invalid index: indices should be in strictly ascending order");
        return true;
      }
    }
  }
  if (!m_wallet->set_ring(key_image, ring, relative))
  {
    fail_msg_writer() << tr("failed to set ring");
    return true;
  }

  return true;
}

bool simple_wallet::unset_ring(const std::vector<std::string> &args)
{
  crypto::hash txid;
  std::vector<crypto::key_image> key_images;

  if (args.size() < 1)
  {
    PRINT_USAGE(USAGE_UNSET_RING);
    return true;
  }

  key_images.resize(args.size());
  for (size_t i = 0; i < args.size(); ++i)
  {
    if (!tools::hex_to_type(args[i], key_images[i]))
    {
      fail_msg_writer() << tr("Invalid key image or txid");
      return true;
    }
  }
  static_assert(sizeof(crypto::hash) == sizeof(crypto::key_image), "hash and key_image must have the same size");
  memcpy(&txid, &key_images[0], sizeof(txid));

  if (!m_wallet->unset_ring(key_images) && !m_wallet->unset_ring(txid))
  {
    fail_msg_writer() << tr("failed to unset ring");
    return true;
  }

  return true;
}

bool simple_wallet::blackball(const std::vector<std::string> &args)
{
  uint64_t amount = std::numeric_limits<uint64_t>::max(), offset, num_offsets;
  if (args.size() == 0)
  {
    PRINT_USAGE(USAGE_MARK_OUTPUT_SPENT);
    return true;
  }

  try
  {
    if (sscanf(args[0].c_str(), "%" PRIu64 "/%" PRIu64, &amount, &offset) == 2)
    {
      m_wallet->blackball_output(std::make_pair(amount, offset));
    }
    else if (std::error_code ec; fs::exists(fs::u8path(args[0]), ec) && !ec)
    {
      std::vector<std::pair<uint64_t, uint64_t>> outputs;
      char str[256];

      std::unique_ptr<FILE, tools::close_file> f(fopen(args[0].c_str(), "r"));
      if (f)
      {
        while (!feof(f.get()))
        {
          if (!fgets(str, sizeof(str), f.get()))
            break;
          const size_t len = strlen(str);
          if (len > 0 && str[len - 1] == '\n')
            str[len - 1] = 0;
          if (!str[0])
            continue;
          if (sscanf(str, "@%" PRIu64, &amount) == 1)
          {
            continue;
          }
          if (amount == std::numeric_limits<uint64_t>::max())
          {
            fail_msg_writer() << tr("First line is not an amount");
            return true;
          }
          if (sscanf(str, "%" PRIu64 "*%" PRIu64, &offset, &num_offsets) == 2 && num_offsets <= std::numeric_limits<uint64_t>::max() - offset)
          {
            while (num_offsets--)
              outputs.push_back(std::make_pair(amount, offset++));
          }
          else if (sscanf(str, "%" PRIu64, &offset) == 1)
          {
            outputs.push_back(std::make_pair(amount, offset));
          }
          else
          {
            fail_msg_writer() << tr("Invalid output: ") << str;
            return true;
          }
        }
        f.reset();
        bool add = false;
        if (args.size() > 1)
        {
          if (args[1] != "add")
          {
            fail_msg_writer() << tr("Bad argument: ") + args[1] + ": " + tr("should be \"add\"");
            return true;
          }
          add = true;
        }
        m_wallet->set_blackballed_outputs(outputs, add);
      }
      else
      {
        fail_msg_writer() << tr("Failed to open file");
        return true;
      }
    }
    else
    {
      fail_msg_writer() << tr("Invalid output key, and file doesn't exist");
      return true;
    }
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("Failed to mark output spent: ") << e.what();
  }

  return true;
}

bool simple_wallet::unblackball(const std::vector<std::string> &args)
{
  std::pair<uint64_t, uint64_t> output;
  if (args.size() != 1)
  {
    PRINT_USAGE(USAGE_MARK_OUTPUT_UNSPENT);
    return true;
  }

  if (sscanf(args[0].c_str(), "%" PRIu64 "/%" PRIu64, &output.first, &output.second) != 2)
  {
    fail_msg_writer() << tr("Invalid output");
    return true;
  }

  try
  {
    m_wallet->unblackball_output(output);
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("Failed to mark output unspent: ") << e.what();
  }

  return true;
}

bool simple_wallet::blackballed(const std::vector<std::string> &args)
{
  std::pair<uint64_t, uint64_t> output;
  if (args.size() != 1)
  {
    PRINT_USAGE(USAGE_IS_OUTPUT_SPENT);
    return true;
  }

  if (sscanf(args[0].c_str(), "%" PRIu64 "/%" PRIu64, &output.first, &output.second) != 2)
  {
    fail_msg_writer() << tr("Invalid output");
    return true;
  }

  try
  {
    if (m_wallet->is_output_blackballed(output))
      message_writer() << tr("Spent: ") << output.first << "/" << output.second;
    else
      message_writer() << tr("Not spent: ") << output.first << "/" << output.second;
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("Failed to check whether output is spent: ") << e.what();
  }

  return true;
}

bool simple_wallet::save_known_rings(const std::vector<std::string> &args)
{
  try
  {
    LOCK_IDLE_SCOPE();
    m_wallet->find_and_save_rings();
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("Failed to save known rings: ") << e.what();
  }
  return true;
}

bool simple_wallet::freeze_thaw(const std::vector<std::string> &args, bool freeze)
{
  if (args.empty())
  {
    fail_msg_writer() << boost::format(tr("usage: %s <key_image>|<pubkey>")) % (freeze ? "freeze" : "thaw");
    return true;
  }
  crypto::key_image ki;
  if (!tools::hex_to_type(args[0], ki))
  {
    fail_msg_writer() << tr("failed to parse key image");
    return true;
  }
  try
  {
    if (freeze)
      m_wallet->freeze(ki);
    else
      m_wallet->thaw(ki);
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << e.what();
    return true;
  }

  return true;
}

bool simple_wallet::freeze(const std::vector<std::string> &args)
{
  return freeze_thaw(args, true);
}

bool simple_wallet::thaw(const std::vector<std::string> &args)
{
  return freeze_thaw(args, false);
}

bool simple_wallet::frozen(const std::vector<std::string> &args)
{
  if (args.empty())
  {
    size_t ntd = m_wallet->get_num_transfer_details();
    for (size_t i = 0; i < ntd; ++i)
    {
      if (!m_wallet->frozen(i))
        continue;
      const auto& td = m_wallet->get_transfer_details(i);
      message_writer() << tr("Frozen: ") << td.m_key_image << " " << cryptonote::print_money(td.amount());
    }
  }
  else
  {
    crypto::key_image ki;
    if (!tools::hex_to_type(args[0], ki))
    {
      fail_msg_writer() << tr("failed to parse key image");
      return true;
    }
    if (m_wallet->frozen(ki))
      message_writer() << tr("Frozen: ") << ki;
    else
      message_writer() << tr("Not frozen: ") << ki;
  }
  return true;
}

bool simple_wallet::lock(const std::vector<std::string> &args)
{
  m_locked = true;
  check_for_inactivity_lock(true);
  return true;
}

bool simple_wallet::net_stats(const std::vector<std::string> &args)
{
  message_writer() << std::to_string(m_wallet->get_bytes_sent()) + tr(" bytes sent");
  message_writer() << std::to_string(m_wallet->get_bytes_received()) + tr(" bytes received");
  return true;
}

bool simple_wallet::welcome(const std::vector<std::string> &args)
{
  message_writer() << tr("Welcome to Oxen, the private cryptocurrency based on Monero");
  message_writer() << "";
  message_writer() << tr("Oxen, like Bitcoin, is a cryptocurrency. That is, it is digital money.");
  message_writer() << tr("Unlike Bitcoin, your Oxen transactions and balance stay private and are not visible to the world by default.");
  message_writer() << tr("However, you have the option of making those available to select parties if you choose to.");
  message_writer() << "";
  message_writer() << tr("Oxen protects your privacy on the blockchain, and while Oxen strives to improve all the time,");
  message_writer() << tr("no privacy technology can be 100% perfect, Monero and consequently Oxen included.");
  message_writer() << tr("Oxen cannot protect you from malware, and it may not be as effective as we hope against powerful adversaries.");
  message_writer() << tr("Flaws in Oxen may be discovered in the future, and attacks may be developed to peek under some");
  message_writer() << tr("of the layers of privacy Oxen provides. Be safe and practice defense in depth.");
  message_writer() << "";
  message_writer() << tr("Welcome to Oxen and financial privacy. For more information, see https://oxen.io");
  return true;
}

bool simple_wallet::version(const std::vector<std::string> &args)
{
  message_writer() << "Oxen '" << OXEN_RELEASE_NAME << "' (v" << OXEN_VERSION_FULL << ")";
  return true;
}

bool simple_wallet::on_cancelled_command()
{
  check_for_inactivity_lock(false);
  return true;
}

bool simple_wallet::cold_sign_tx(const std::vector<tools::wallet2::pending_tx>& ptx_vector, tools::wallet2::signed_tx_set &exported_txs, std::vector<cryptonote::address_parse_info> const &dsts_info, std::function<bool(const tools::wallet2::signed_tx_set &)> accept_func)
{
  std::vector<std::string> tx_aux;

  message_writer(epee::console_color_white, false) << tr("Please confirm the transaction on the device");

  m_wallet->cold_sign_tx(ptx_vector, exported_txs, dsts_info, tx_aux);

  if (accept_func && !accept_func(exported_txs))
  {
    MERROR("Transactions rejected by callback");
    return false;
  }

  // aux info
  m_wallet->cold_tx_aux_import(exported_txs.ptx, tx_aux);

  // import key images
  return m_wallet->import_key_images(exported_txs, 0, true);
}

bool simple_wallet::set_always_confirm_transfers(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool r) {
      m_wallet->always_confirm_transfers(r);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}

bool simple_wallet::set_print_ring_members(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool r) {
      m_wallet->print_ring_members(r);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}

bool simple_wallet::set_store_tx_info(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  if (m_wallet->watch_only())
  {
    fail_msg_writer() << tr("wallet is watch-only and cannot transfer");
    return true;
  }

  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool r) {
      m_wallet->store_tx_info(r);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}

bool simple_wallet::set_default_priority(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  int priority = -1;
  if (args[1].size() == 1 && args[1][0] >= '0' && args[1][0] <= '5')
    priority = args[1][0] - '0';
  else
  {
    auto it = std::find(tools::allowed_priority_strings.begin(), tools::allowed_priority_strings.end(), args[1]);
    if (it != tools::allowed_priority_strings.end())
      priority = it - tools::allowed_priority_strings.begin();
  }
  if (priority == -1)
  {
    fail_msg_writer() << tr("priority must be a 0-5 value or one of: ") << join_priority_strings(", ");
    return true;
  }

  try {
    const auto pwd_container = get_and_verify_password();
    if (pwd_container)
    {
      m_wallet->set_default_priority(priority);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    }
    return true;
  }
  catch(...)
  {
    fail_msg_writer() << tr("could not change default priority");
    return true;
  }
}

bool simple_wallet::set_auto_refresh(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool auto_refresh) {
      m_auto_refresh_enabled.store(false, std::memory_order_relaxed);
      m_wallet->auto_refresh(auto_refresh);
      m_idle_mutex.lock();
      m_auto_refresh_enabled.store(auto_refresh, std::memory_order_relaxed);
      m_idle_cond.notify_one();
      m_idle_mutex.unlock();

      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}

bool simple_wallet::set_refresh_type(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  tools::wallet2::RefreshType refresh_type;
  if (!parse_refresh_type(args[1], refresh_type))
  {
    return true;
  }

  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    m_wallet->set_refresh_type(refresh_type);
    m_wallet->rewrite(m_wallet_file, pwd_container->password());
  }
  return true;
}

bool simple_wallet::set_ask_password(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    tools::wallet2::AskPasswordType ask = tools::wallet2::AskPasswordToDecrypt;
    if (args[1] == "never" || args[1] == "0")
      ask = tools::wallet2::AskPasswordNever;
    else if (args[1] == "action" || args[1] == "1")
      ask = tools::wallet2::AskPasswordOnAction;
    else if (args[1] == "encrypt" || args[1] == "decrypt" || args[1] == "2")
      ask = tools::wallet2::AskPasswordToDecrypt;
    else
    {
      fail_msg_writer() << tr("invalid argument: must be either 0/never, 1/action, or 2/encrypt/decrypt");
      return true;
    }

    const tools::wallet2::AskPasswordType cur_ask = m_wallet->ask_password();
    if (!m_wallet->watch_only())
    {
      if (cur_ask == tools::wallet2::AskPasswordToDecrypt && ask != tools::wallet2::AskPasswordToDecrypt)
        m_wallet->decrypt_keys(pwd_container->password());
      else if (cur_ask != tools::wallet2::AskPasswordToDecrypt && ask == tools::wallet2::AskPasswordToDecrypt)
        m_wallet->encrypt_keys(pwd_container->password());
    }
    m_wallet->ask_password(ask);
    m_wallet->rewrite(m_wallet_file, pwd_container->password());
  }
  return true;
}

bool simple_wallet::set_min_output_count(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  uint32_t count;
  if (!string_tools::get_xtype_from_string(count, args[1]))
  {
    fail_msg_writer() << tr("invalid count: must be an unsigned integer");
    return true;
  }

  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    m_wallet->set_min_output_count(count);
    m_wallet->rewrite(m_wallet_file, pwd_container->password());
  }
  return true;
}

bool simple_wallet::set_min_output_value(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  auto value = cryptonote::parse_amount(args[1]);
  if (!value)
  {
    fail_msg_writer() << tr("invalid value");
    return true;
  }

  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    m_wallet->set_min_output_value(*value);
    m_wallet->rewrite(m_wallet_file, pwd_container->password());
  }
  return true;
}

bool simple_wallet::set_merge_destinations(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool r) {
      m_wallet->merge_destinations(r);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}

bool simple_wallet::set_confirm_export_overwrite(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool r) {
      m_wallet->confirm_export_overwrite(r);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}

bool simple_wallet::set_refresh_from_block_height(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    uint64_t height;
    if (!epee::string_tools::get_xtype_from_string(height, args[1]))
    {
      fail_msg_writer() << tr("Invalid height");
      return true;
    }
    m_wallet->set_refresh_from_block_height(height);
    m_wallet->rewrite(m_wallet_file, pwd_container->password());
  }
  return true;
}

bool simple_wallet::set_segregate_pre_fork_outputs(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool r) {
      m_wallet->segregate_pre_fork_outputs(r);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}

bool simple_wallet::set_key_reuse_mitigation2(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool r) {
      m_wallet->key_reuse_mitigation2(r);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}

bool simple_wallet::set_subaddress_lookahead(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    auto lookahead = parse_subaddress_lookahead(args[1]);
    if (lookahead)
    {
      m_wallet->set_subaddress_lookahead(lookahead->first, lookahead->second);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    }
  }
  return true;
}

bool simple_wallet::set_segregation_height(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    uint64_t height;
    if (!epee::string_tools::get_xtype_from_string(height, args[1]))
    {
      fail_msg_writer() << tr("Invalid height");
      return true;
    }
    m_wallet->segregation_height(height);
    m_wallet->rewrite(m_wallet_file, pwd_container->password());
  }
  return true;
}

bool simple_wallet::set_ignore_outputs_above(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    auto amount = cryptonote::parse_amount(args[1]);
    if (!amount)
    {
      fail_msg_writer() << tr("Invalid amount");
      return true;
    }
    if (*amount == 0)
      amount = oxen::MONEY_SUPPLY;
    m_wallet->ignore_outputs_above(*amount);
    m_wallet->rewrite(m_wallet_file, pwd_container->password());
  }
  return true;
}

bool simple_wallet::set_ignore_outputs_below(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    auto amount = cryptonote::parse_amount(args[1]);
    if (!amount)
    {
      fail_msg_writer() << tr("Invalid amount");
      return true;
    }
    m_wallet->ignore_outputs_below(*amount);
    m_wallet->rewrite(m_wallet_file, pwd_container->password());
  }
  return true;
}

bool simple_wallet::set_track_uses(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    parse_bool_and_use(args[1], [&](bool r) {
      m_wallet->track_uses(r);
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    });
  }
  return true;
}

bool simple_wallet::set_inactivity_lock_timeout(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
#ifdef _WIN32
  tools::fail_msg_writer() << tr("Inactivity lock timeout disabled on Windows");
  return true;
#endif
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    uint32_t r;
    if (tools::parse_int(args[1], r))
    {
      m_wallet->inactivity_lock_timeout(std::chrono::seconds{r});
      m_wallet->rewrite(m_wallet_file, pwd_container->password());
    }
    else
    {
      tools::fail_msg_writer() << tr("Invalid number of seconds");
    }
  }
  return true;
}

bool simple_wallet::set_device_name(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  const auto pwd_container = get_and_verify_password();
  if (pwd_container)
  {
    if (args.size() == 0){
      fail_msg_writer() << tr("Device name not specified");
      return true;
    }

    m_wallet->device_name(args[1]);
    bool r = false;
    try {
      r = m_wallet->reconnect_device();
      if (!r){
        fail_msg_writer() << tr("Device reconnect failed");
      }

    } catch(const std::exception & e){
      MWARNING("Device reconnect failed: " << e.what());
      fail_msg_writer() << tr("Device reconnect failed: ") << e.what();
    }

  }
  return true;
}

bool simple_wallet::help(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  if(args.empty())
  {
    success_msg_writer() << get_commands_str();
  }
#ifdef WALLET_ENABLE_MMS
  else if ((args.size() == 2) && (args.front() == "mms"))
  {
    // Little hack to be able to do "help mms <subcommand>"
    std::vector<std::string> mms_args(1, args.front() + " " + args.back());
    success_msg_writer() << get_command_usage(mms_args);
  }
#endif
  else
  {
    success_msg_writer() << get_command_usage(args);
  }
  return true;
}

simple_wallet::simple_wallet()
  : m_allow_mismatched_daemon_version(false)
  , m_refresh_progress_reporter(*this)
  , m_idle_run(true)
  , m_auto_refresh_enabled(false)
  , m_auto_refresh_refreshing(false)
  , m_in_manual_refresh(false)
  , m_current_subaddress_account(0)
  , m_last_activity_time(time(NULL))
  , m_locked(false)
  , m_in_command(false)
{

  m_cmd_binder.pre_handler([this] ([[maybe_unused]] const std::string& cmd) {
    m_last_activity_time = time(NULL);
    m_in_command = true;
    check_for_inactivity_lock(false);
  });
  m_cmd_binder.post_handler([this] ([[maybe_unused]] const std::string& cmd, [[maybe_unused]] bool& result, [[maybe_unused]] std::any pre_result) {
    m_last_activity_time = time(NULL);
    m_in_command = false;
  });

  m_cmd_binder.set_handler("start_mining",
                           [this](const auto& x) { return start_mining(x); },
                           tr(USAGE_START_MINING),
                           tr("Start mining in the daemon"));
  m_cmd_binder.set_handler("stop_mining",
                           [this](const auto& x) { return stop_mining(x); },
                           tr("Stop mining in the daemon."));
  m_cmd_binder.set_handler("set_daemon",
                           [this](const auto& x) { return set_daemon(x); },
                           tr(USAGE_SET_DAEMON),
                           tr("Set another daemon to connect to."));
  m_cmd_binder.set_handler("save_bc",
                           [this](const auto& x) { return save_bc(x); },
                           tr("Save the current blockchain data."));
  m_cmd_binder.set_handler("refresh",
                           [this](const auto& x) { return refresh(x); },
                           tr("Synchronize the transactions and balance."));
  m_cmd_binder.set_handler("balance",
                           [this](const auto& x) { return show_balance(x); },
                           tr(USAGE_SHOW_BALANCE),
                           tr("Show the wallet's balance of the currently selected account."));
  m_cmd_binder.set_handler("incoming_transfers",
                           [this](const auto& x) { return show_incoming_transfers(x); },
                           tr(USAGE_INCOMING_TRANSFERS),
                           tr("Show the incoming transfers, all or filtered by availability and address index.\n\n"
                              "Output format:\n"
                              "Amount, Spent(\"T\"|\"F\"), \"frozen\"|\"locked\"|\"unlocked\", RingCT, Global Index, Transaction Hash, Address Index, [Public Key, Key Image] "));
  m_cmd_binder.set_handler("payments",
                           [this](const auto& x) { return show_payments(x); },
                           tr(USAGE_PAYMENTS),
                           tr("Show the payments for the given payment IDs."));
  m_cmd_binder.set_handler("bc_height",
                           [this](const auto& x) { return show_blockchain_height(x); },
                           tr("Show the blockchain height."));
  m_cmd_binder.set_handler("transfer", [this](const auto& x) { return transfer(x); },
                           tr(USAGE_TRANSFER),
                           tr("Transfer <amount> to <address>. If the parameter \"index=<N1>[,<N2>,...]\" is specified, the wallet uses outputs received by addresses of those indices. If omitted, the wallet randomly chooses address indices to be used. In any case, it tries its best not to combine outputs across multiple addresses. <priority> is the priority of the transaction, or \"blink\" for an instant transaction. The higher the priority, the higher the transaction fee. Valid values in priority order (from lowest to highest) are: unimportant, normal, elevated, priority. If omitted, the default value (see the command \"set priority\") is used. Multiple payments can be made at once by adding <address_2> <amount_2> et cetera (before the payment ID, if it's included)"));
  m_cmd_binder.set_handler("locked_transfer",
                           [this](const auto& x) { return locked_transfer(x); },
                           tr(USAGE_LOCKED_TRANSFER),
                           tr("Transfer <amount> to <address> and lock it for <lockblocks> (max. 1000000). If the parameter \"index=<N1>[,<N2>,...]\" is specified, the wallet uses outputs received by addresses of those indices. If omitted, the wallet randomly chooses address indices to be used. In any case, it tries its best not to combine outputs across multiple addresses. <priority> is the priority of the transaction. The higher the priority, the higher the transaction fee. Valid values in priority order (from lowest to highest) are: unimportant, normal, elevated, priority. If omitted, the default value (see the command \"set priority\") is used. Multiple payments can be made at once by adding URI_2 or <address_2> <amount_2> et cetera (before the <lockblocks>)"));
  m_cmd_binder.set_handler("locked_sweep_all",
                           [this](const auto& x) { return locked_sweep_all(x); },
                           tr(USAGE_LOCKED_SWEEP_ALL),
                           tr("Send all unlocked balance to an address and lock it for <lockblocks> (max. 1000000). If no address is specified the address of the currently selected account will be used. If the parameter \"index<N1>[,<N2>,...]\" or \"index=all\" is specified, the wallet sweeps outputs received by those address indices. If omitted, the wallet randomly chooses an address index to be used. <priority> is the priority of the sweep. The higher the priority, the higher the transaction fee. Valid values in priority order (from lowest to highest) are: unimportant, normal, elevated, priority. If omitted, the default value (see the command \"set priority\") is used."));
  m_cmd_binder.set_handler("sweep_unmixable",
                           [this](const auto& x) { return sweep_unmixable(x); },
                           tr("Deprecated"));
  m_cmd_binder.set_handler("sweep_all", [this](const auto& x) { return sweep_all(x); },
                           tr(USAGE_SWEEP_ALL),
                           tr("Send all unlocked balance to an address.If no address is specified the address of the currently selected account will be used. If the parameter \"index<N1>[,<N2>,...]\" or \"index=all\" is specified, the wallet sweeps outputs received by those address indices. If omitted, the wallet randomly chooses an address index to be used. If the parameter \"outputs=<N>\" is specified and  N > 0, wallet splits the transaction into N even outputs."));
  m_cmd_binder.set_handler("sweep_account", [this](const auto& x) { return sweep_account(x); },
                           tr(USAGE_SWEEP_ACCOUNT),
                           tr("Send all unlocked balance from a given account to an address. If the parameter \"index=<N1>[,<N2>,...]\" or \"index=all\" is specified, the wallet sweeps outputs received by those or all address indices, respectively. If omitted, the wallet randomly chooses an address index to be used. If the parameter \"outputs=<N>\" is specified and  N > 0, wallet splits the transaction into N even outputs."));
  m_cmd_binder.set_handler("sweep_below",
                           [this](const auto& x) { return sweep_below(x); },
                           tr(USAGE_SWEEP_BELOW),
                           tr("Send all unlocked outputs below the threshold to an address. If no address is specified the address of the currently selected account will be used"));
  m_cmd_binder.set_handler("sweep_single",
                           [this](const auto& x) { return sweep_single(x); },
                           tr(USAGE_SWEEP_SINGLE),
                           tr("Send a single output of the given key image to an address without change."));
  m_cmd_binder.set_handler("sweep_unmixable",
                           [this](const auto& x) { return sweep_unmixable(x); },
                           tr("Deprecated"));
  m_cmd_binder.set_handler("sign_transfer",
                           [this](const auto& x) { return sign_transfer(x); },
                           tr(USAGE_SIGN_TRANSFER),
                           tr("Sign a transaction from a file. If the parameter \"export_raw\" is specified, transaction raw hex data suitable for the daemon RPC /sendrawtransaction is exported."));
  m_cmd_binder.set_handler("submit_transfer",
                           [this](const auto& x) { return submit_transfer(x); },
                           tr("Submit a signed transaction from a file."));
  m_cmd_binder.set_handler("set_log",
                           [this](const auto& x) { return set_log(x); },
                           tr(USAGE_SET_LOG),
                           tr("Change the current log detail (level must be <0-4>)."));
  m_cmd_binder.set_handler("account",
                           [this](const auto& x) { return account(x); },
                           tr(USAGE_ACCOUNT),
                           tr("If no arguments are specified, the wallet shows all the existing accounts along with their balances.\n"
                              "If the \"new\" argument is specified, the wallet creates a new account with its label initialized by the provided label text (which can be empty).\n"
                              "If the \"switch\" argument is specified, the wallet switches to the account specified by <index>.\n"
                              "If the \"label\" argument is specified, the wallet sets the label of the account specified by <index> to the provided label text.\n"
                              "If the \"tag\" argument is specified, a tag <tag_name> is assigned to the specified accounts <account_index_1>, <account_index_2>, ....\n"
                              "If the \"untag\" argument is specified, the tags assigned to the specified accounts <account_index_1>, <account_index_2> ..., are removed.\n"
                              "If the \"tag_description\" argument is specified, the tag <tag_name> is assigned an arbitrary text <description>."));
  m_cmd_binder.set_handler("address",
                           [this](const auto& x) { return print_address(x); },
                           tr(USAGE_ADDRESS),
                           tr("If no arguments are specified or <index> is specified, the wallet shows the default or specified address. If \"all\" is specified, the wallet shows all the existing addresses in the currently selected account. If \"new \" is specified, the wallet creates a new address with the provided label text (which can be empty). If \"label\" is specified, the wallet sets the label of the address specified by <index> to the provided label text."));
  m_cmd_binder.set_handler("integrated_address",
                           [this](const auto& x) { return print_integrated_address(x); },
                           tr(USAGE_INTEGRATED_ADDRESS),
                           tr("Encode a payment ID into an integrated address for the current wallet public address (no argument uses a random payment ID), or decode an integrated address to standard address and payment ID"));
  m_cmd_binder.set_handler("address_book",
                           [this](const auto& x) { return address_book(x); },
                           tr(USAGE_ADDRESS_BOOK),
                           tr("Print all entries in the address book, optionally adding/deleting an entry to/from it."));
  m_cmd_binder.set_handler("save",
                           [this](const auto& x) { return save(x); },
                           tr("Save the wallet data."));
  m_cmd_binder.set_handler("save_watch_only",
                           [this](const auto& x) { return save_watch_only(x); },
                           tr("Save a watch-only keys file."));
  m_cmd_binder.set_handler("viewkey",
                           [this](const auto& x) { return viewkey(x); },
                           tr("Display the private view key."));
  m_cmd_binder.set_handler("spendkey",
                           [this](const auto& x) { return spendkey(x); },
                           tr("Display the private spend key."));
  m_cmd_binder.set_handler("seed",
                           [this](const auto& x) { return seed(x); },
                           tr("Display the Electrum-style mnemonic seed"));
  m_cmd_binder.set_handler("restore_height",
                           [this](const auto& x) { return restore_height(x); },
                           tr("Display the restore height"));
  m_cmd_binder.set_handler("set",
                           [this](const auto& x) { return set_variable(x); },
                           tr(USAGE_SET_VARIABLE),
                           tr(R"(Available options:
 seed language
   Set the wallet's seed language.
 always-confirm-transfers <1|0>
   Whether to confirm unsplit txes.
 print-ring-members <1|0>
   Whether to print detailed information about ring members during confirmation.
 store-tx-info <1|0>
   Whether to store outgoing tx info (destination address, payment ID, tx secret key) for future reference.
 auto-refresh <1|0>
   Whether to automatically synchronize new blocks from the daemon.
 refresh-type <full|optimize-coinbase|no-coinbase|default>
   Set the wallet's refresh behaviour.
 priority <0|1|2|3|4|5>
 priority <default|unimportant|normal|elevated|priority|blink>
   Set the default transaction priority to the given numeric or string value.  Note that
   for ordinary transactions, all values other than 1/"unimportant" will result in blink
   transactions.
 ask-password <0|1|2>
 ask-password <never|action|decrypt>
   action: ask the password before many actions such as transfer, etc
   decrypt: same as action, but keeps the spend key encrypted in memory when not needed
 min-outputs-count [n]
   Try to keep at least that many outputs of value at least min-outputs-value.
 min-outputs-value [n]
   Try to keep at least min-outputs-count outputs of at least that value.
 merge-destinations <1|0>
   Whether to merge multiple payments to the same destination address.
 confirm-export-overwrite <1|0>
   Whether to warn if the file to be exported already exists.
 refresh-from-block-height [n]
   Set the height before which to ignore blocks.
 segregate-pre-fork-outputs <1|0>
   Set this if you intend to spend outputs on both Oxen AND a key reusing fork.
 key-reuse-mitigation2 <1|0>
   Set this if you are not sure whether you will spend on a key reusing Oxen fork later.
 subaddress-lookahead <major>:<minor>
   Set the lookahead sizes for the subaddress hash table.
   Set this if you are not sure whether you will spend on a key reusing Oxen fork later.
 segregation-height <n>
   Set to the height of a key reusing fork you want to use, 0 to use default.
 ignore-outputs-above <amount>
   Ignore outputs of amount above this threshold when spending. Value 0 is translated to the maximum value (18 million) which disables this filter.
 ignore-outputs-below <amount>
   Ignore outputs of amount below this threshold when spending.
 track-uses <1|0>
   Whether to keep track of owned outputs uses.
 device-name <device_name[:device_spec]>
   Device name for hardware wallet.
 export-format <binary"|"ascii">
   Save all exported files as binary (cannot be copied and pasted) or ascii (can be).
 inactivity-lock-timeout <unsigned int>
   How many seconds to wait before locking the wallet (0 to disable).)"));

  m_cmd_binder.set_handler("encrypted_seed",
                           [this](const auto& x) { return encrypted_seed(x); },
                           tr("Display the encrypted Electrum-style mnemonic seed."));
  m_cmd_binder.set_handler("rescan_spent",
                           [this](const auto& x) { return rescan_spent(x); },
                           tr("Rescan the blockchain for spent outputs."));
  m_cmd_binder.set_handler("get_tx_key",
                           [this](const auto& x) { return get_tx_key(x); },
                           tr(USAGE_GET_TX_KEY),
                           tr("Get the transaction key (r) for a given <txid>."));
  m_cmd_binder.set_handler("set_tx_key",
                           [this](const auto& x) { return set_tx_key(x); },
                           tr(USAGE_SET_TX_KEY),
                           tr("Set the transaction key (r) for a given <txid> in case the tx was made by some other device or 3rd party wallet."));
  m_cmd_binder.set_handler("check_tx_key",
                           [this](const auto& x) { return check_tx_key(x); },
                           tr(USAGE_CHECK_TX_KEY),
                           tr("Check the amount going to <address> in <txid>."));
  m_cmd_binder.set_handler("get_tx_proof",
                           [this](const auto& x) { return get_tx_proof(x); },
                           tr(USAGE_GET_TX_PROOF),
                           tr("Generate a signature proving funds sent to <address> in <txid>, optionally with a challenge string <message>, using either the transaction secret key (when <address> is not your wallet's address) or the view secret key (otherwise), which does not disclose the secret key."));
  m_cmd_binder.set_handler("check_tx_proof",
                           [this](const auto& x) { return check_tx_proof(x); },
                           tr(USAGE_CHECK_TX_PROOF),
                           tr("Check the proof for funds going to <address> in <txid> with the challenge string <message> if any."));
  m_cmd_binder.set_handler("get_spend_proof",
                           [this](const auto& x) { return get_spend_proof(x); },
                           tr(USAGE_GET_SPEND_PROOF),
                           tr("Generate a signature proving that you generated <txid> using the spend secret key, optionally with a challenge string <message>."));
  m_cmd_binder.set_handler("check_spend_proof",
                           [this](const auto& x) { return check_spend_proof(x); },
                           tr(USAGE_CHECK_SPEND_PROOF),
                           tr("Check a signature proving that the signer generated <txid>, optionally with a challenge string <message>."));
  m_cmd_binder.set_handler("get_reserve_proof",
                           [this](const auto& x) { return get_reserve_proof(x); },
                           tr(USAGE_GET_RESERVE_PROOF),
                           tr("Generate a signature proving that you own at least this much, optionally with a challenge string <message>.\n"
                              "If 'all' is specified, you prove the entire sum of all of your existing accounts' balances.\n"
                              "Otherwise, you prove the reserve of the smallest possible amount above <amount> available in your current account."));
  m_cmd_binder.set_handler("check_reserve_proof",
                           [this](const auto& x) { return check_reserve_proof(x); },
                           tr(USAGE_CHECK_RESERVE_PROOF),
                           tr("Check a signature proving that the owner of <address> holds at least this much, optionally with a challenge string <message>."));
  m_cmd_binder.set_handler("show_transfers",
                           [this](const auto& x) { return show_transfers(x); },
                           tr(USAGE_SHOW_TRANSFERS),
                           tr(R"(Show the incoming/outgoing transfers within an optional height range.

Output format:
In or Coinbase:    Block Number, "block"|"in", Lock, Checkpointed, Time, Amount,  Transaction Hash, Payment ID, Subaddress Index,                     "-", Note
Out:               Block Number,        "out", Lock, Checkpointed, Time, Amount*, Transaction Hash, Payment ID, Fee, Destinations, Input addresses**, "-", Note
Pool:              "pool",               "in", Lock, Checkpointed, Time, Amount,  Transaction Hash, Payment ID, Subaddress Index,                     "-", Note, Double Spend Note
Pending or Failed: "failed"|"pending",  "out", Lock, Checkpointed, Time, Amount*, Transaction Hash, Payment ID, Fee, Input addresses**,               "-", Note

* Excluding change and fee.
** Set of address indices used as inputs in this transfer.)"));

   m_cmd_binder.set_handler("export_transfers",
                           [this](const auto& x) { return export_transfers(x); },
                           tr(USAGE_EXPORT_TRANSFERS),
                           tr("Export to CSV the incoming/outgoing transfers within an optional height range."));
  m_cmd_binder.set_handler("unspent_outputs",
                           [this](const auto& x) { return unspent_outputs(x); },
                           tr(USAGE_UNSPENT_OUTPUTS),
                           tr("Show the unspent outputs of a specified address within an optional amount range."));
  m_cmd_binder.set_handler("rescan_bc",
                           [this](const auto& x) { return rescan_blockchain(x); },
                           tr(USAGE_RESCAN_BC),
                           tr("Rescan the blockchain from scratch. If \"hard\" is specified, you will lose any information which can not be recovered from the blockchain itself."));
  m_cmd_binder.set_handler("set_tx_note",
                           [this](const auto& x) { return set_tx_note(x); },
                           tr(USAGE_SET_TX_NOTE),
                           tr("Set an arbitrary string note for a <txid>."));
  m_cmd_binder.set_handler("get_tx_note",
                           [this](const auto& x) { return get_tx_note(x); },
                           tr(USAGE_GET_TX_NOTE),
                           tr("Get a string note for a txid."));
  m_cmd_binder.set_handler("set_description",
                           [this](const auto& x) { return set_description(x); },
                           tr(USAGE_SET_DESCRIPTION),
                           tr("Set an arbitrary description for the wallet."));
  m_cmd_binder.set_handler("get_description",
                           [this](const auto& x) { return get_description(x); },
                           tr(USAGE_GET_DESCRIPTION),
                           tr("Get the description of the wallet."));
  m_cmd_binder.set_handler("status",
                           [this](const auto& x) { return status(x); },
                           tr("Show the wallet's status."));
  m_cmd_binder.set_handler("wallet_info",
                           [this](const auto& x) { return wallet_info(x); },
                           tr("Show the wallet's information."));
  m_cmd_binder.set_handler("sign",
                           [this](const auto& x) { return sign(x); },
                           tr(USAGE_SIGN),
                           tr("Sign the contents of a file with the given subaddress (or the main address if not specified)"));
  m_cmd_binder.set_handler("sign_value",
                           [this](const auto& x) { return sign_value(x); },
                           tr(USAGE_SIGN_VALUE),
                           tr("Sign a short string value with the given subaddress (or the main address if not specified)"));
  m_cmd_binder.set_handler("verify",
                           [this](const auto& x) { return verify(x); },
                           tr(USAGE_VERIFY),
                           tr("Verify a signature on the contents of a file."));
  m_cmd_binder.set_handler("verify_value",
                           [this](const auto& x) { return verify_value(x); },
                           tr(USAGE_VERIFY_VALUE),
                           tr("Verify a signature on the given short string value."));
  m_cmd_binder.set_handler("export_key_images",
                           [this](const auto& x) { return export_key_images(x); },
                           tr(USAGE_EXPORT_KEY_IMAGES),
                           tr("Export a signed set of key images to a <filename>. By default exports all key images. If 'requested-only' is specified export key images for outputs not previously imported."));
  m_cmd_binder.set_handler("import_key_images",
                           [this](const auto& x) { return import_key_images(x); },
                           tr(USAGE_IMPORT_KEY_IMAGES),
                           tr("Import a signed key images list and verify their spent status."));
  m_cmd_binder.set_handler("hw_key_images_sync",
                           [this](const auto& x) { return hw_key_images_sync(x); },
                           tr(USAGE_HW_KEY_IMAGES_SYNC),
                           tr("Synchronizes key images with the hw wallet."));
  m_cmd_binder.set_handler("hw_reconnect",
                           [this](const auto& x) { return hw_reconnect(x); },
                           tr(USAGE_HW_RECONNECT),
                           tr("Attempts to reconnect HW wallet."));
  m_cmd_binder.set_handler("export_outputs",
                           [this](const auto& x) { return export_outputs(x); },
                           tr(USAGE_EXPORT_OUTPUTS),
                           tr("Export a set of outputs owned by this wallet."));
  m_cmd_binder.set_handler("import_outputs",
                           [this](const auto& x) { return import_outputs(x); },
                           tr(USAGE_IMPORT_OUTPUTS),
                           tr("Import a set of outputs owned by this wallet."));
  m_cmd_binder.set_handler("show_transfer",
                           [this](const auto& x) { return show_transfer(x); },
                           tr(USAGE_SHOW_TRANSFER),
                           tr("Show information about a transfer to/from this address."));
  m_cmd_binder.set_handler("password",
                           [this](const auto& x) { return change_password(x); },
                           tr("Change the wallet's password."));
  m_cmd_binder.set_handler("fee",
                           [this](const auto& x) { return print_fee_info(x); },
                           tr("Print information about the current transaction fees."));
  m_cmd_binder.set_handler("prepare_multisig",
                           [this](const auto& x) { return prepare_multisig(x); },
                           tr("Export data needed to create a multisig wallet"));
  m_cmd_binder.set_handler("make_multisig",
                           [this](const auto& x) { return make_multisig(x); },
                           tr(USAGE_MAKE_MULTISIG),
                           tr("Turn this wallet into a multisig wallet"));
  m_cmd_binder.set_handler("finalize_multisig",
                           [this](const auto& x) { return finalize_multisig(x); },
                           tr(USAGE_FINALIZE_MULTISIG),
                           tr("Turn this wallet into a multisig wallet, extra step for N-1/N wallets"));
  m_cmd_binder.set_handler("exchange_multisig_keys",
                           [this](const auto& x) { return exchange_multisig_keys(x); },
                           tr(USAGE_EXCHANGE_MULTISIG_KEYS),
                           tr("Performs extra multisig keys exchange rounds. Needed for arbitrary M/N multisig wallets"));
  m_cmd_binder.set_handler("export_multisig_info",
                           [this](const auto& x) { return export_multisig(x); },
                           tr(USAGE_EXPORT_MULTISIG_INFO),
                           tr("Export multisig info for other participants"));
  m_cmd_binder.set_handler("import_multisig_info",
                           [this](const auto& x) { return import_multisig(x); },
                           tr(USAGE_IMPORT_MULTISIG_INFO),
                           tr("Import multisig info from other participants"));
  m_cmd_binder.set_handler("sign_multisig",
                           [this](const auto& x) { return sign_multisig(x); },
                           tr(USAGE_SIGN_MULTISIG),
                           tr("Sign a multisig transaction from a file"));
  m_cmd_binder.set_handler("submit_multisig",
                           [this](const auto& x) { return submit_multisig(x); },
                           tr(USAGE_SUBMIT_MULTISIG),
                           tr("Submit a signed multisig transaction from a file"));
  m_cmd_binder.set_handler("export_raw_multisig_tx",
                           [this](const auto& x) { return export_raw_multisig(x); },
                           tr(USAGE_EXPORT_RAW_MULTISIG_TX),
                           tr("Export a signed multisig transaction to a file"));
#ifdef WALLET_ENABLE_MMS
  m_cmd_binder.set_handler("mms",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS),
                           tr("Interface with the MMS (Multisig Messaging System)\n"
                              "<subcommand> is one of:\n"
                              "  init, info, signer, list, next, sync, transfer, delete, send, receive, export, note, show, set, help\n"
                              "  send_signer_config, start_auto_config, stop_auto_config, auto_config\n"
                              "Get help about a subcommand with: help mms <subcommand>, or mms help <subcommand>"));
  m_cmd_binder.set_handler("mms init",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_INIT),
                           tr("Initialize and configure the MMS for M/N = number of required signers/number of authorized signers multisig"));
  m_cmd_binder.set_handler("mms info",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_INFO),
                           tr("Display current MMS configuration"));
  m_cmd_binder.set_handler("mms signer",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_SIGNER),
                           tr("Set or modify authorized signer info (single-word label, transport address, Oxen address), or list all signers"));
  m_cmd_binder.set_handler("mms list",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_LIST),
                           tr("List all messages"));
  m_cmd_binder.set_handler("mms next",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_NEXT),
                           tr("Evaluate the next possible multisig-related action(s) according to wallet state, and execute or offer for choice\n"
                              "By using 'sync' processing of waiting messages with multisig sync info can be forced regardless of wallet state"));
  m_cmd_binder.set_handler("mms sync",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_SYNC),
                           tr("Force generation of multisig sync info regardless of wallet state, to recover from special situations like \"stale data\" errors"));
  m_cmd_binder.set_handler("mms transfer",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_TRANSFER),
                           tr("Initiate transfer with MMS support; arguments identical to normal 'transfer' command arguments, for info see there"));
  m_cmd_binder.set_handler("mms delete",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_DELETE),
                           tr("Delete a single message by giving its id, or delete all messages by using 'all'"));
  m_cmd_binder.set_handler("mms send",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_SEND),
                           tr("Send a single message by giving its id, or send all waiting messages"));
  m_cmd_binder.set_handler("mms receive",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_RECEIVE),
                           tr("Check right away for new messages to receive"));
  m_cmd_binder.set_handler("mms export",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_EXPORT),
                           tr("Write the content of a message to a file \"mms_message_content\""));
  m_cmd_binder.set_handler("mms note",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_NOTE),
                           tr("Send a one-line message to an authorized signer, identified by its label, or show any waiting unread notes"));
  m_cmd_binder.set_handler("mms show",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_SHOW),
                           tr("Show detailed info about a single message"));
  m_cmd_binder.set_handler("mms set",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_SET),
                           tr("Available options:\n "
                                  "auto-send <1|0>\n "
                                  "  Whether to automatically send newly generated messages right away.\n "));
  m_cmd_binder.set_handler("mms send_signer_config",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_SEND_SIGNER_CONFIG),
                           tr("Send completed signer config to all other authorized signers"));
  m_cmd_binder.set_handler("mms start_auto_config",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_START_AUTO_CONFIG),
                           tr("Start auto-config at the auto-config manager's wallet by issuing auto-config tokens and optionally set others' labels"));
  m_cmd_binder.set_handler("mms stop_auto_config",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_STOP_AUTO_CONFIG),
                           tr("Delete any auto-config tokens and abort a auto-config process"));
  m_cmd_binder.set_handler("mms auto_config",
                           [this](const auto& x) { return mms(x); },
                           tr(USAGE_MMS_AUTO_CONFIG),
                           tr("Start auto-config by using the token received from the auto-config manager"));
#endif
  m_cmd_binder.set_handler("print_ring",
                           [this](const auto& x) { return print_ring(x); },
                           tr(USAGE_PRINT_RING),
                           tr("Print the ring(s) used to spend a given key image or transaction (if the ring size is > 1)\n\n"
                              "Output format:\n"
                              "Key Image, \"absolute\", list of rings"));
  m_cmd_binder.set_handler("set_ring",
                           [this](const auto& x) { return set_ring(x); },
                           tr(USAGE_SET_RING),
                           tr("Set the ring used for a given key image, so it can be reused in a fork"));
  m_cmd_binder.set_handler("unset_ring",
                           [this](const auto& x) { return unset_ring(x); },
                           tr(USAGE_UNSET_RING),
                           tr("Unsets the ring used for a given key image or transaction"));
  m_cmd_binder.set_handler("save_known_rings",
                           [this](const auto& x) { return save_known_rings(x); },
                           tr(USAGE_SAVE_KNOWN_RINGS),
                           tr("Save known rings to the shared rings database"));
  m_cmd_binder.set_handler("mark_output_spent",
                           [this](const auto& x) { return blackball(x); },
                           tr(USAGE_MARK_OUTPUT_SPENT),
                           tr("Mark output(s) as spent so they never get selected as fake outputs in a ring"));
  m_cmd_binder.set_handler("mark_output_unspent",
                           [this](const auto& x) { return unblackball(x); },
                           tr(USAGE_MARK_OUTPUT_UNSPENT),
                           tr("Marks an output as unspent so it may get selected as a fake output in a ring"));
  m_cmd_binder.set_handler("is_output_spent",
                           [this](const auto& x) { return blackballed(x); },
                           tr(USAGE_IS_OUTPUT_SPENT),
                           tr("Checks whether an output is marked as spent"));
  m_cmd_binder.set_handler("freeze",
                           [this](const auto& x) { return freeze(x); },
                           tr(USAGE_FREEZE),
                           tr("Freeze a single output by key image so it will not be used"));
  m_cmd_binder.set_handler("thaw",
                           [this](const auto& x) { return thaw(x); },
                           tr(USAGE_THAW),
                           tr("Thaw a single output by key image so it may be used again"));
  m_cmd_binder.set_handler("frozen",
                           [this](const auto& x) { return frozen(x); },
                           tr(USAGE_FROZEN),
                           tr("Checks whether a given output is currently frozen by key image"));
  m_cmd_binder.set_handler("lock",
                           [this](const auto& x) { return lock(x); },
                           tr(USAGE_LOCK),
                           tr("Lock the wallet console, requiring the wallet password to continue"));
  m_cmd_binder.set_handler("net_stats",
                           [this](const auto& x) { return net_stats(x); },
                           tr(USAGE_NET_STATS),
                           tr("Prints simple network stats"));
  m_cmd_binder.set_handler("welcome",
                           [this](const auto& x) { return welcome(x); },
                           tr(USAGE_WELCOME),
                           tr("Display the welcome message for the wallet"));
  m_cmd_binder.set_handler("version",
                           [this](const auto& x) { return version(x); },
                           tr(USAGE_VERSION),
                           tr("Returns version information"));
  m_cmd_binder.set_handler("help",
                           [this](const auto& x) { return help(x); },
                           tr(USAGE_HELP),
                           tr("Show the help section or the documentation about a <command>."));

  m_cmd_binder.set_cancel_handler([this] { return on_cancelled_command(); });

  //
  // Oxen
  //
  m_cmd_binder.set_handler("register_service_node",
                           [this](const auto& x) { return register_service_node(x); },
                           tr(USAGE_REGISTER_SERVICE_NODE),
                           tr("Send <amount> to this wallet's main account and lock it as an operator stake for a new Service Node. This command is typically generated on the Service Node via the `prepare_registration' oxend command. The optional index= and <priority> parameters work as in the `transfer' command."));
  m_cmd_binder.set_handler("stake",
                           [this](const auto& x) { return stake(x); },
                           tr(USAGE_STAKE),
                           tr("Send a transfer to this wallet's main account and lock it as a contribution stake to the given Service Node (which must be registered and awaiting contributions). The stake amount may be specified either as a fixed amount or as a percentage of the Service Node's total stake. The optional index= and <priority> parameters work as in the `transfer' command."));
  m_cmd_binder.set_handler("request_stake_unlock",
                           [this](const auto& x) { return request_stake_unlock(x); },
                           tr(USAGE_REQUEST_STAKE_UNLOCK),
                           tr("Request a stake currently locked in the given Service Node to be unlocked on the network"));
  m_cmd_binder.set_handler("print_locked_stakes",
                           [this](const auto& x) { return print_locked_stakes(x); },
                           tr(USAGE_PRINT_LOCKED_STAKES),
                           tr("Print stakes currently locked on the Service Node network"));

  m_cmd_binder.set_handler("ons_buy_mapping",
                           [this](const auto& x) { return ons_buy_mapping(x); },
                           tr(USAGE_ONS_BUY_MAPPING),
                           tr(tools::wallet_rpc::ONS_BUY_MAPPING::description));

  m_cmd_binder.set_handler("ons_renew_mapping",
                           [this](const auto& x) { return ons_renew_mapping(x); },
                           tr(USAGE_ONS_RENEW_MAPPING),
                           tr(tools::wallet_rpc::ONS_RENEW_MAPPING::description));

  m_cmd_binder.set_handler("ons_update_mapping",
                           [this](const auto& x) { return ons_update_mapping(x); },
                           tr(USAGE_ONS_UPDATE_MAPPING),
                           tr(tools::wallet_rpc::ONS_UPDATE_MAPPING::description));

  m_cmd_binder.set_handler("ons_encrypt",
                           [this](const auto& x) { return ons_encrypt(x); },
                           tr(USAGE_ONS_ENCRYPT),
                           tr("Encrypts a ONS mapping value with a given name; primarily intended for use with external mapping update signing"));

  m_cmd_binder.set_handler("ons_by_owner",
                           [this](const auto& x) { return ons_by_owner(x); },
                           tr(USAGE_ONS_BY_OWNER),
                           tr("Query the Oxen Name Service names that the keys have purchased. If no keys are specified, it defaults to the current wallet."));

  m_cmd_binder.set_handler("ons_lookup",
                           [this](const auto& x) { return ons_lookup(x); },
                           tr(USAGE_ONS_LOOKUP),
                           tr("Query the ed25519 public keys that own the Oxen Name System names."));

  m_cmd_binder.set_handler("ons_make_update_mapping_signature",
                           [this](const auto& x) { return ons_make_update_mapping_signature(x); },
                           tr(USAGE_ONS_MAKE_UPDATE_MAPPING_SIGNATURE),
                           tr(tools::wallet_rpc::ONS_MAKE_UPDATE_SIGNATURE::description));
}

simple_wallet::~simple_wallet()
{
  if (m_wallet) {
    m_wallet->cancel_long_poll();
  }
  if (m_long_poll_thread.joinable())
      m_long_poll_thread.join();
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::set_variable(const std::vector<std::string> &args)
{
  if (args.empty())
  {
    std::string seed_language = m_wallet->get_seed_language();
    if (m_use_english_language_names)
      seed_language = crypto::ElectrumWords::get_english_name_for(seed_language);
    std::string priority_string = "invalid";
    uint32_t priority = m_wallet->get_default_priority();
    if (priority < tools::allowed_priority_strings.size())
      priority_string = tools::allowed_priority_strings[priority];
    std::string ask_password_string = "invalid";
    switch (m_wallet->ask_password())
    {
      case tools::wallet2::AskPasswordNever: ask_password_string = "never"; break;
      case tools::wallet2::AskPasswordOnAction: ask_password_string = "action"; break;
      case tools::wallet2::AskPasswordToDecrypt: ask_password_string = "decrypt"; break;
    }
    success_msg_writer() << "seed = " << seed_language;
    success_msg_writer() << "always-confirm-transfers = " << m_wallet->always_confirm_transfers();
    success_msg_writer() << "print-ring-members = " << m_wallet->print_ring_members();
    success_msg_writer() << "store-tx-info = " << m_wallet->store_tx_info();
    success_msg_writer() << "auto-refresh = " << m_wallet->auto_refresh();
    success_msg_writer() << "refresh-type = " << get_refresh_type_name(m_wallet->get_refresh_type());
    success_msg_writer() << "priority = " << priority<< " (" << priority_string << ")";
    success_msg_writer() << "ask-password = " << m_wallet->ask_password() << " (" << ask_password_string << ")";
    success_msg_writer() << "min-outputs-count = " << m_wallet->get_min_output_count();
    success_msg_writer() << "min-outputs-value = " << cryptonote::print_money(m_wallet->get_min_output_value());
    success_msg_writer() << "merge-destinations = " << m_wallet->merge_destinations();
    success_msg_writer() << "confirm-export-overwrite = " << m_wallet->confirm_export_overwrite();
    success_msg_writer() << "refresh-from-block-height = " << m_wallet->get_refresh_from_block_height();
    success_msg_writer() << "segregate-pre-fork-outputs = " << m_wallet->segregate_pre_fork_outputs();
    success_msg_writer() << "key-reuse-mitigation2 = " << m_wallet->key_reuse_mitigation2();
    const std::pair<size_t, size_t> lookahead = m_wallet->get_subaddress_lookahead();
    success_msg_writer() << "subaddress-lookahead = " << lookahead.first << ":" << lookahead.second;
    success_msg_writer() << "segregation-height = " << m_wallet->segregation_height();
    success_msg_writer() << "ignore-outputs-above = " << cryptonote::print_money(m_wallet->ignore_outputs_above());
    success_msg_writer() << "ignore-outputs-below = " << cryptonote::print_money(m_wallet->ignore_outputs_below());
    success_msg_writer() << "track-uses = " << m_wallet->track_uses();
    success_msg_writer() << "device_name = " << m_wallet->device_name();
    success_msg_writer() << "inactivity-lock-timeout = " << m_wallet->inactivity_lock_timeout().count()
#ifdef _WIN32
        << " (disabled on Windows)"
#endif
        ;
    return true;
  }
  else
  {

#define CHECK_SIMPLE_VARIABLE(name, f, help) do \
  if (args[0] == name) { \
    if (args.size() <= 1) \
    { \
      fail_msg_writer() << "set " << #name << ": " << tr("needs an argument") << " (" << help << ")"; \
      return true; \
    } \
    else \
    { \
      f(args); \
      return true; \
    } \
  } while(0)

    if (args[0] == "seed")
    {
      if (args.size() == 1)
      {
        fail_msg_writer() << tr("set seed: needs an argument. available options: language");
        return true;
      }
      else if (args[1] == "language")
      {
        seed_set_language(args);
        return true;
      }
    }
    CHECK_SIMPLE_VARIABLE("always-confirm-transfers", set_always_confirm_transfers, tr("0 or 1"));
    CHECK_SIMPLE_VARIABLE("print-ring-members", set_print_ring_members, tr("0 or 1"));
    CHECK_SIMPLE_VARIABLE("store-tx-info", set_store_tx_info, tr("0 or 1"));
    CHECK_SIMPLE_VARIABLE("auto-refresh", set_auto_refresh, tr("0 or 1"));
    CHECK_SIMPLE_VARIABLE("refresh-type", set_refresh_type, tr("full (slowest, no assumptions); optimize-coinbase (fast, assumes the whole coinbase is paid to a single address); no-coinbase (fastest, assumes we receive no coinbase transaction), default (same as optimize-coinbase)"));
    CHECK_SIMPLE_VARIABLE("priority", set_default_priority, tr("0-5 or one of ") << join_priority_strings(", "));
    CHECK_SIMPLE_VARIABLE("ask-password", set_ask_password, tr("0|1|2 (or never|action|decrypt)"));
    CHECK_SIMPLE_VARIABLE("min-outputs-count", set_min_output_count, tr("unsigned integer"));
    CHECK_SIMPLE_VARIABLE("min-outputs-value", set_min_output_value, tr("amount"));
    CHECK_SIMPLE_VARIABLE("merge-destinations", set_merge_destinations, tr("0 or 1"));
    CHECK_SIMPLE_VARIABLE("confirm-export-overwrite", set_confirm_export_overwrite, tr("0 or 1"));
    CHECK_SIMPLE_VARIABLE("refresh-from-block-height", set_refresh_from_block_height, tr("block height"));
    CHECK_SIMPLE_VARIABLE("segregate-pre-fork-outputs", set_segregate_pre_fork_outputs, tr("0 or 1"));
    CHECK_SIMPLE_VARIABLE("key-reuse-mitigation2", set_key_reuse_mitigation2, tr("0 or 1"));
    CHECK_SIMPLE_VARIABLE("subaddress-lookahead", set_subaddress_lookahead, tr("<major>:<minor>"));
    CHECK_SIMPLE_VARIABLE("segregation-height", set_segregation_height, tr("unsigned integer"));
    CHECK_SIMPLE_VARIABLE("ignore-outputs-above", set_ignore_outputs_above, tr("amount"));
    CHECK_SIMPLE_VARIABLE("ignore-outputs-below", set_ignore_outputs_below, tr("amount"));
    CHECK_SIMPLE_VARIABLE("track-uses", set_track_uses, tr("0 or 1"));
    CHECK_SIMPLE_VARIABLE("inactivity-lock-timeout", set_inactivity_lock_timeout, tr("unsigned integer (seconds, 0 to disable)"));
    CHECK_SIMPLE_VARIABLE("device-name", set_device_name, tr("<device_name[:device_spec]>"));
  }
  fail_msg_writer() << tr("set: unrecognized argument(s)");
  return true;
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::set_log(const std::vector<std::string> &args)
{
  if(args.size() > 1)
  {
    PRINT_USAGE(USAGE_SET_LOG);
    return true;
  }
  if(!args.empty())
  {
    uint16_t level = 0;
    if(epee::string_tools::get_xtype_from_string(level, args[0]))
    {
      if(4 < level)
      {
        fail_msg_writer() << boost::format(tr("wrong number range, use: %s")) % USAGE_SET_LOG;
        return true;
      }
      mlog_set_log_level(level);
    }
    else
    {
      mlog_set_log(args[0].c_str());
    }
  }

  success_msg_writer() << "New log categories: " << mlog_get_categories();
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::ask_wallet_create_if_needed()
{
  LOG_PRINT_L3("simple_wallet::ask_wallet_create_if_needed() started");
  fs::path wallet_path;
  std::string confirm_creation;
  bool wallet_name_valid = false;
  bool keys_file_exists;
  bool wallet_file_exists;

  do{
      LOG_PRINT_L3("User asked to specify wallet file name.");
      wallet_path = fs::u8path(input_line(
        tr(m_restoring ? "Specify a new wallet file name for your restored wallet (e.g., MyWallet).\n"
        "Wallet file name (or Ctrl-C to quit)" :
        "Specify wallet file name (e.g., MyWallet). If the wallet doesn't exist, it will be created.\n"
        "Wallet file name (or Ctrl-C to quit)")
      ));
      if(std::cin.eof())
      {
        LOG_ERROR("Unexpected std::cin.eof() - Exited simple_wallet::ask_wallet_create_if_needed()");
        return false;
      }
      if(wallet_path.empty())
      {
        fail_msg_writer() << tr("No wallet name provided. Please try again or use Ctrl-C to quit.");
        wallet_name_valid = false;
      }
      else
      {
        tools::wallet2::wallet_exists(wallet_path, keys_file_exists, wallet_file_exists);
        LOG_PRINT_L3("wallet_path: " << wallet_path);
        LOG_PRINT_L3("keys_file_exists: " << std::boolalpha << keys_file_exists << std::noboolalpha
        << "  wallet_file_exists: " << std::boolalpha << wallet_file_exists << std::noboolalpha);

        if((keys_file_exists || wallet_file_exists) && (!m_generate_new.empty() || m_restoring))
        {
          fail_msg_writer() << tr("Attempting to generate or restore wallet, but specified file(s) exist.  Exiting to not risk overwriting.");
          return false;
        }
        if(wallet_file_exists && keys_file_exists) //Yes wallet, yes keys
        {
          success_msg_writer() << tr("Wallet and key files found, loading...");
          m_wallet_file = wallet_path;
          return true;
        }
        else if(!wallet_file_exists && keys_file_exists) //No wallet, yes keys
        {
          success_msg_writer() << tr("Key file found but not wallet file. Regenerating...");
          m_wallet_file = wallet_path;
          return true;
        }
        else if(wallet_file_exists && !keys_file_exists) //Yes wallet, no keys
        {
          fail_msg_writer() << tr("Key file not found. Failed to open wallet: ") << wallet_path << ". Exiting.";
          return false;
        }
        else if(!wallet_file_exists && !keys_file_exists) //No wallet, no keys
        {
          bool ok = true;
          if (!m_restoring)
          {
            std::string prompt = tr("No wallet found with that name. Confirm creation of new wallet named: ");
            prompt += "\"" + wallet_path.u8string() + "\"";
            confirm_creation = input_line(prompt, true);
            if(std::cin.eof())
            {
              LOG_ERROR("Unexpected std::cin.eof() - Exited simple_wallet::ask_wallet_create_if_needed()");
              return false;
            }
            ok = command_line::is_yes(confirm_creation);
          }
          if (ok)
          {
            success_msg_writer() << tr("Generating new wallet...");
            m_generate_new = wallet_path;
            return true;
          }
        }
      }
    } while(!wallet_name_valid);

  LOG_ERROR("Failed out of do-while loop in ask_wallet_create_if_needed()");
  return false;
}

/*!
 * \brief Prints the seed with a nice message
 * \param seed seed to print
 */
void simple_wallet::print_seed(const epee::wipeable_string &seed)
{
  success_msg_writer(true) << "\n" << boost::format(tr("NOTE: the following %s can be used to recover access to your wallet. "
    "Write them down and store them somewhere safe and secure. Please do not store them in "
    "your email or on file storage services outside of your immediate control.\n")) % (m_wallet->multisig() ? tr("string") : tr("25 words"));

  warn_msg_writer() << tr("NEVER give your Oxen wallet seed to ANYONE else. NEVER input your Oxen "
          "wallet seed into any software or website other than the OFFICIAL Oxen CLI or GUI wallets, "
          "downloaded directly from the Oxen GitHub (https://github.com/oxen-io/) or compiled from source.");
  std::string confirm = input_line(tr("Are you sure you want to access your wallet seed?"), true);
  if (std::cin.eof() || !command_line::is_yes(confirm))
    return;

  // don't log
  int space_index = 0;
  size_t len  = seed.size();
  for (const char *ptr = seed.data(); len--; ++ptr)
  {
    if (*ptr == ' ')
    {
      if (space_index == 15 || space_index == 7)
        putchar('\n');
      else
        putchar(*ptr);
      ++space_index;
    }
    else
      putchar(*ptr);
  }
  putchar('\n');
  fflush(stdout);
}
//----------------------------------------------------------------------------------------------------
static bool might_be_partial_seed(const epee::wipeable_string &words)
{
  std::vector<epee::wipeable_string> seed;

  words.split(seed);
  return seed.size() < 24;
}
//----------------------------------------------------------------------------------------------------
static bool datestr_to_int(const std::string &heightstr, uint16_t &year, uint8_t &month, uint8_t &day)
{
  if (heightstr.size() != 10 || heightstr[4] != '-' || heightstr[7] != '-')
  {
    fail_msg_writer() << tr("date format must be YYYY-MM-DD");
    return false;
  }
  try
  {
    year  = boost::lexical_cast<uint16_t>(heightstr.substr(0,4));
    // lexical_cast<uint8_t> won't work because uint8_t is treated as character type
    month = boost::lexical_cast<uint16_t>(heightstr.substr(5,2));
    day   = boost::lexical_cast<uint16_t>(heightstr.substr(8,2));
  }
  catch (const boost::bad_lexical_cast &)
  {
    fail_msg_writer() << tr("bad height parameter: ") << heightstr;
    return false;
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::init(const boost::program_options::variables_map& vm)
{
  OXEN_DEFER { m_electrum_seed.wipe(); };

  if (auto deprecations = tools::wallet2::has_deprecated_options(vm); !deprecations.empty())
  {
    for (auto msg : deprecations)
      message_writer(epee::console_color_red, true) << tr("Warning: option is deprecated and will be removed in the future: ") << msg;
  }

  const bool testnet = tools::wallet2::has_testnet_option(vm);
  const bool devnet = tools::wallet2::has_devnet_option(vm);
  if (testnet && devnet)
  {
    fail_msg_writer() << tr("Can't specify more than one of --testnet and --devnet");
    return false;
  }
  network_type const nettype = testnet ? network_type::TESTNET : devnet ? network_type::DEVNET : network_type::MAINNET;

  epee::wipeable_string multisig_keys;
  epee::wipeable_string password;

  if (!handle_command_line(vm))
    return false;

  bool welcome = false;

  if((!m_generate_new.empty()) + (!m_wallet_file.empty()) + (!m_generate_from_device.empty()) + (!m_generate_from_view_key.empty()) + (!m_generate_from_spend_key.empty()) + (!m_generate_from_keys.empty()) + (!m_generate_from_multisig_keys.empty()) + (!m_generate_from_json.empty()) > 1)
  {
    fail_msg_writer() << tr("can't specify more than one of --generate-new-wallet=\"wallet_name\", --wallet-file=\"wallet_name\", --generate-from-view-key=\"wallet_name\", --generate-from-spend-key=\"wallet_name\", --generate-from-keys=\"wallet_name\", --generate-from-multisig-keys=\"wallet_name\", --generate-from-json=\"jsonfilename\" and --generate-from-device=\"wallet_name\"");
    return false;
  }
  else if (m_generate_new.empty() && m_wallet_file.empty() && m_generate_from_device.empty() && m_generate_from_view_key.empty() && m_generate_from_spend_key.empty() && m_generate_from_keys.empty() && m_generate_from_multisig_keys.empty() && m_generate_from_json.empty())
  {
    if(!ask_wallet_create_if_needed()) return false;
  }

  std::string default_restore_value = "0";

  if (!m_generate_new.empty() || m_restoring)
  {
    if (!m_subaddress_lookahead.empty() && !parse_subaddress_lookahead(m_subaddress_lookahead))
      return false;

    std::string old_language;
    // check for recover flag.  if present, require electrum word list (only recovery option for now).
    if (m_restore_deterministic_wallet || m_restore_multisig_wallet)
    {
      if (m_non_deterministic)
      {
        fail_msg_writer() << tr("can't specify both --restore-deterministic-wallet or --restore-multisig-wallet and --non-deterministic");
        return false;
      }
      if (!m_wallet_file.empty())
      {
        if (m_restore_multisig_wallet)
          fail_msg_writer() << tr("--restore-multisig-wallet uses --generate-new-wallet, not --wallet-file");
        else
          fail_msg_writer() << tr("--restore-deterministic-wallet uses --generate-new-wallet, not --wallet-file");
        return false;
      }

      if (m_electrum_seed.empty())
      {
        if (m_restore_multisig_wallet)
        {
            const char *prompt = "Specify multisig seed";
            m_electrum_seed = input_secure_line(prompt);
            if (std::cin.eof())
              return false;
            if (m_electrum_seed.empty())
            {
              fail_msg_writer() << tr("specify a recovery parameter with the --electrum-seed=\"multisig seed here\"");
              return false;
            }
        }
        else
        {
          m_electrum_seed = "";
          do
          {
            const char *prompt = m_electrum_seed.empty() ? "Specify Electrum seed" : "Electrum seed continued";
            epee::wipeable_string electrum_seed = input_secure_line(prompt);
            if (std::cin.eof())
              return false;
            if (electrum_seed.empty())
            {
              fail_msg_writer() << tr("specify a recovery parameter with the --electrum-seed=\"words list here\"");
              return false;
            }
            m_electrum_seed += electrum_seed;
            m_electrum_seed += ' ';
          } while (might_be_partial_seed(m_electrum_seed));
        }
      }

      if (m_restore_multisig_wallet)
      {
        auto parsed = m_electrum_seed.parse_hexstr();
        if (!parsed)
        {
          fail_msg_writer() << tr("Multisig seed failed verification");
          return false;
        }
        multisig_keys = *parsed;
      }
      else
      {
        if (!crypto::ElectrumWords::words_to_bytes(m_electrum_seed, m_recovery_key, old_language))
        {
          fail_msg_writer() << tr("Electrum-style word list failed verification");
          return false;
        }
      }

      auto pwd_container = password_prompter(tr("Enter seed offset passphrase, empty if none"), false);
      if (std::cin.eof() || !pwd_container)
        return false;
      epee::wipeable_string seed_pass = pwd_container->password();
      if (!seed_pass.empty())
      {
        if (m_restore_multisig_wallet)
        {
          crypto::secret_key key;
          crypto::cn_slow_hash(seed_pass.data(), seed_pass.size(), (crypto::hash&)key, crypto::cn_slow_hash_type::heavy_v1);
          sc_reduce32((unsigned char*)key.data);
          multisig_keys = m_wallet->decrypt(std::string(multisig_keys.data(), multisig_keys.size()), key, true);
        }
        else
          m_recovery_key = cryptonote::decrypt_key(m_recovery_key, seed_pass);
      }
    }
    if (!m_generate_from_view_key.empty())
    {
      m_wallet_file = m_generate_from_view_key;
      // parse address
      std::string address_string = input_line("Standard address");
      if (std::cin.eof())
        return false;
      if (address_string.empty()) {
        fail_msg_writer() << tr("No data supplied, cancelled");
        return false;
      }
      cryptonote::address_parse_info info;
      if(!get_account_address_from_str(info, nettype, address_string))
      {
          fail_msg_writer() << tr("failed to parse address");
          return false;
      }
      if (info.is_subaddress)
      {
        fail_msg_writer() << tr("This address is a subaddress which cannot be used here.");
        return false;
      }

      // parse view secret key
      epee::wipeable_string viewkey_string = input_secure_line("Secret view key");
      if (std::cin.eof())
        return false;
      if (viewkey_string.empty()) {
        fail_msg_writer() << tr("No data supplied, cancelled");
        return false;
      }
      crypto::secret_key viewkey;
      if (!viewkey_string.hex_to_pod(unwrap(unwrap(viewkey))))
      {
        fail_msg_writer() << tr("failed to parse view key secret key");
        return false;
      }

      m_wallet_file=m_generate_from_view_key;

      // check the view key matches the given address
      crypto::public_key pkey;
      if (!crypto::secret_key_to_public_key(viewkey, pkey)) {
        fail_msg_writer() << tr("failed to verify view key secret key");
        return false;
      }
      if (info.address.m_view_public_key != pkey) {
        fail_msg_writer() << tr("view key does not match standard address");
        return false;
      }

      auto r = new_wallet(vm, info.address, std::nullopt, viewkey);
      CHECK_AND_ASSERT_MES(r, false, tr("account creation failed"));
      password = *r;
      welcome = true;
    }
    else if (!m_generate_from_spend_key.empty())
    {
      m_wallet_file = m_generate_from_spend_key;
      // parse spend secret key
      epee::wipeable_string spendkey_string = input_secure_line("Secret spend key");
      if (std::cin.eof())
        return false;
      if (spendkey_string.empty()) {
        fail_msg_writer() << tr("No data supplied, cancelled");
        return false;
      }
      if (!spendkey_string.hex_to_pod(unwrap(unwrap(m_recovery_key))))
      {
        fail_msg_writer() << tr("failed to parse spend key secret key");
        return false;
      }
      auto r = new_wallet(vm, m_recovery_key, true, false, "");
      CHECK_AND_ASSERT_MES(r, false, tr("account creation failed"));
      password = *r;
      welcome = true;
    }
    else if (!m_generate_from_keys.empty())
    {
      m_wallet_file = m_generate_from_keys;
      // parse address
      std::string address_string = input_line("Standard address");
      if (std::cin.eof())
        return false;
      if (address_string.empty()) {
        fail_msg_writer() << tr("No data supplied, cancelled");
        return false;
      }
      cryptonote::address_parse_info info;
      if(!get_account_address_from_str(info, nettype, address_string))
      {
          fail_msg_writer() << tr("failed to parse address");
          return false;
      }
      if (info.is_subaddress)
      {
        fail_msg_writer() << tr("This address is a subaddress which cannot be used here.");
        return false;
      }

      // parse spend secret key
      epee::wipeable_string spendkey_string = input_secure_line("Secret spend key");
      if (std::cin.eof())
        return false;
      if (spendkey_string.empty()) {
        fail_msg_writer() << tr("No data supplied, cancelled");
        return false;
      }
      crypto::secret_key spendkey;
      if (!spendkey_string.hex_to_pod(unwrap(unwrap(spendkey))))
      {
        fail_msg_writer() << tr("failed to parse spend key secret key");
        return false;
      }

      // parse view secret key
      epee::wipeable_string viewkey_string = input_secure_line("Secret view key");
      if (std::cin.eof())
        return false;
      if (viewkey_string.empty()) {
        fail_msg_writer() << tr("No data supplied, cancelled");
        return false;
      }
      crypto::secret_key viewkey;
      if(!viewkey_string.hex_to_pod(unwrap(unwrap(viewkey))))
      {
        fail_msg_writer() << tr("failed to parse view key secret key");
        return false;
      }

      m_wallet_file=m_generate_from_keys;

      // check the spend and view keys match the given address
      crypto::public_key pkey;
      if (!crypto::secret_key_to_public_key(spendkey, pkey)) {
        fail_msg_writer() << tr("failed to verify spend key secret key");
        return false;
      }
      if (info.address.m_spend_public_key != pkey) {
        fail_msg_writer() << tr("spend key does not match standard address");
        return false;
      }
      if (!crypto::secret_key_to_public_key(viewkey, pkey)) {
        fail_msg_writer() << tr("failed to verify view key secret key");
        return false;
      }
      if (info.address.m_view_public_key != pkey) {
        fail_msg_writer() << tr("view key does not match standard address");
        return false;
      }
      auto r = new_wallet(vm, info.address, spendkey, viewkey);
      CHECK_AND_ASSERT_MES(r, false, tr("account creation failed"));
      password = *r;
      welcome = true;
    }

    // Asks user for all the data required to merge secret keys from multisig wallets into one master wallet, which then gets full control of the multisig wallet. The resulting wallet will be the same as any other regular wallet.
    else if (!m_generate_from_multisig_keys.empty())
    {
      m_wallet_file = m_generate_from_multisig_keys;
      unsigned int multisig_m;
      unsigned int multisig_n;

      // parse multisig type
      std::string multisig_type_string = input_line("Multisig type (input as M/N with M <= N and M > 1)");
      if (std::cin.eof())
        return false;
      if (multisig_type_string.empty())
      {
        fail_msg_writer() << tr("No data supplied, cancelled");
        return false;
      }
      if (sscanf(multisig_type_string.c_str(), "%u/%u", &multisig_m, &multisig_n) != 2)
      {
        fail_msg_writer() << tr("Error: expected M/N, but got: ") << multisig_type_string;
        return false;
      }
      if (multisig_m <= 1 || multisig_m > multisig_n)
      {
        fail_msg_writer() << tr("Error: expected N > 1 and N <= M, but got: ") << multisig_type_string;
        return false;
      }
      if (multisig_m != multisig_n)
      {
        fail_msg_writer() << tr("Error: M/N is currently unsupported. ");
        return false;
      }
      message_writer() << boost::format(tr("Generating master wallet from %u of %u multisig wallet keys")) % multisig_m % multisig_n;

      // parse multisig address
      std::string address_string = input_line("Multisig wallet address");
      if (std::cin.eof())
        return false;
      if (address_string.empty()) {
        fail_msg_writer() << tr("No data supplied, cancelled");
        return false;
      }
      cryptonote::address_parse_info info;
      if(!get_account_address_from_str(info, nettype, address_string))
      {
          fail_msg_writer() << tr("failed to parse address");
          return false;
      }

      // parse secret view key
      epee::wipeable_string viewkey_string = input_secure_line("Secret view key");
      if (std::cin.eof())
        return false;
      if (viewkey_string.empty())
      {
        fail_msg_writer() << tr("No data supplied, cancelled");
        return false;
      }
      crypto::secret_key viewkey;
      if(!viewkey_string.hex_to_pod(unwrap(unwrap(viewkey))))
      {
        fail_msg_writer() << tr("failed to parse secret view key");
        return false;
      }

      // check that the view key matches the given address
      crypto::public_key pkey;
      if (!crypto::secret_key_to_public_key(viewkey, pkey))
      {
        fail_msg_writer() << tr("failed to verify secret view key");
        return false;
      }
      if (info.address.m_view_public_key != pkey)
      {
        fail_msg_writer() << tr("view key does not match standard address");
        return false;
      }

      // parse multisig spend keys
      crypto::secret_key spendkey;
      // parsing N/N
      if(multisig_m == multisig_n)
      {
        std::vector<crypto::secret_key> multisig_secret_spendkeys(multisig_n);
        epee::wipeable_string spendkey_string;
        std::string spendkey_data;
        // get N secret spend keys from user
        for(unsigned int i=0; i<multisig_n; ++i)
        {
          spendkey_string = input_secure_line(tr((boost::format(tr("Secret spend key (%u of %u)")) % (i+1) % multisig_m).str().c_str()));
          if (std::cin.eof())
            return false;
          if (spendkey_string.empty())
          {
            fail_msg_writer() << tr("No data supplied, cancelled");
            return false;
          }
          if(!spendkey_string.hex_to_pod(unwrap(unwrap(multisig_secret_spendkeys[i]))))
          {
            fail_msg_writer() << tr("failed to parse spend key secret key");
            return false;
          }
        }

        // sum the spend keys together to get the master spend key
        spendkey = multisig_secret_spendkeys[0];
        for(unsigned int i=1; i<multisig_n; ++i)
          sc_add(reinterpret_cast<unsigned char*>(&spendkey), reinterpret_cast<unsigned char*>(&spendkey), reinterpret_cast<unsigned char*>(&multisig_secret_spendkeys[i]));
      }
      // parsing M/N
      else
      {
        fail_msg_writer() << tr("Error: M/N is currently unsupported");
        return false;
      }

      // check that the spend key matches the given address
      if (!crypto::secret_key_to_public_key(spendkey, pkey))
      {
        fail_msg_writer() << tr("failed to verify spend key secret key");
        return false;
      }
      if (info.address.m_spend_public_key != pkey)
      {
        fail_msg_writer() << tr("spend key does not match standard address");
        return false;
      }

      // create wallet
      auto r = new_wallet(vm, info.address, spendkey, viewkey);
      CHECK_AND_ASSERT_MES(r, false, tr("account creation failed"));
      password = *r;
      welcome = true;
    }

    else if (!m_generate_from_json.empty())
    {
      try
      {
        auto rc = tools::wallet2::make_from_json(vm, false, m_generate_from_json, password_prompter);
        m_wallet = std::move(rc.first);
        password = rc.second.password();
        m_wallet_file = m_wallet->path();
      }
      catch (const std::exception &e)
      {
        fail_msg_writer() << e.what();
        return false;
      }
      if (!m_wallet)
        return false;
    }
    else if (!m_generate_from_device.empty())
    {
      m_wallet_file = m_generate_from_device;
      // create wallet
      auto r = new_device_wallet(vm);
      CHECK_AND_ASSERT_MES(r, false, tr("account creation failed"));
      password = *r;
      welcome = true;
      default_restore_value = "curr";
    }
    else
    {
      if (m_generate_new.empty()) {
        fail_msg_writer() << tr("specify a wallet path with --generate-new-wallet (not --wallet-file)");
        return false;
      }
      m_wallet_file = m_generate_new;
      std::optional<epee::wipeable_string> r;
      if (m_restore_multisig_wallet)
        r = new_wallet(vm, multisig_keys, old_language);
      else
        r = new_wallet(vm, m_recovery_key, m_restore_deterministic_wallet, m_non_deterministic, old_language);
      CHECK_AND_ASSERT_MES(r, false, tr("account creation failed"));
      password = *r;
      welcome = true;
    }

    if (m_restoring && m_generate_from_json.empty())
    {
      m_wallet->explicit_refresh_from_block_height(!(command_line::is_arg_defaulted(vm, arg_restore_height) &&
        command_line::is_arg_defaulted(vm, arg_restore_date)));
      if (command_line::is_arg_defaulted(vm, arg_restore_height) && !command_line::is_arg_defaulted(vm, arg_restore_date))
      {
        uint16_t year;
        uint8_t month;
        uint8_t day;
        if (!datestr_to_int(m_restore_date, year, month, day))
          return false;
        try
        {
          m_restore_height = m_wallet->get_blockchain_height_by_date(year, month, day);
          success_msg_writer() << tr("Restore height is: ") << m_restore_height;
        }
        catch (const std::runtime_error& e)
        {
          fail_msg_writer() << e.what();
          return false;
        }
      }
    }
    if (!m_wallet->explicit_refresh_from_block_height() && m_restoring)
    {
      rpc::version_t version;
      bool connected = try_connect_to_daemon(false, &version);
      while (true)
      {
        std::string prompt =
            "\nEnter wallet restore blockchain height (e.g. 123456) or restore date\n"
            "(e.g. 2020-07-21). Enter \"curr\" to use the current blockchain height.\n"
            "NOTE: transactions before the restore height will not be detected.\n"
            "[";
        prompt += default_restore_value;
        prompt += "]";
        std::string heightstr = input_line(prompt);
        if (std::cin.eof())
          return false;
        if (heightstr.empty())
          heightstr = default_restore_value;
        if (heightstr == "curr") {
          m_restore_height = m_wallet->estimate_blockchain_height();
          if (m_restore_height) --m_restore_height;
          break;
        }

        try
        {
          m_restore_height = boost::lexical_cast<uint64_t>(heightstr);
          break;
        }
        catch (const boost::bad_lexical_cast &)
        {
          if (!connected || version < rpc::version_t{1, 6})
          {
            fail_msg_writer() << tr("bad m_restore_height parameter: ") << heightstr;
            continue;
          }
          uint16_t year;
          uint8_t month;  // 1, 2, ..., 12
          uint8_t day;    // 1, 2, ..., 31
          try
          {
            if (!datestr_to_int(heightstr, year, month, day))
              return false;
            m_restore_height = m_wallet->get_blockchain_height_by_date(year, month, day);
            success_msg_writer() << tr("Restore height is: ") << m_restore_height;
            std::string confirm = input_line(tr("Is this okay?"), true);
            if (std::cin.eof())
              return false;
            if(command_line::is_yes(confirm))
              break;
          }
          catch (const boost::bad_lexical_cast &)
          {
            fail_msg_writer() << tr("bad m_restore_height parameter: ") << heightstr;
          }
          catch (const std::runtime_error& e)
          {
            fail_msg_writer() << e.what();
          }
        }
      }
    }
    if (m_restoring)
    {
      uint64_t estimate_height = m_wallet->estimate_blockchain_height();
      if (m_restore_height >= estimate_height)
      {
        success_msg_writer() << tr("Restore height ") << m_restore_height << (" is not yet reached. The current estimated height is ") << estimate_height;
        std::string confirm = input_line(tr("Still apply restore height?"), true);
        if (std::cin.eof() || command_line::is_no(confirm))
          m_restore_height = 0;
      }
      m_wallet->set_refresh_from_block_height(m_restore_height);
    }
    m_wallet->rewrite(m_wallet_file, password);
  }
  else
  {
    assert(!m_wallet_file.empty());
    if (!m_subaddress_lookahead.empty())
    {
      fail_msg_writer() << tr("can't specify --subaddress-lookahead and --wallet-file at the same time");
      return false;
    }
    auto r = open_wallet(vm);
    CHECK_AND_ASSERT_MES(r, false, tr("failed to open account"));
    password = *r;
  }
  if (!m_wallet)
  {
    fail_msg_writer() << tr("wallet is null");
    return false;
  }

  if (!m_wallet->is_trusted_daemon())
  {
    message_writer(epee::console_color_yellow, true) << (boost::format(tr("Warning: using an untrusted daemon at %s")) % m_wallet->get_daemon_address()).str();
    message_writer(epee::console_color_yellow, true) << tr("Using a third party daemon can be detrimental to your security and privacy");
    bool ssl = false;
    if (m_wallet->check_connection(nullptr, &ssl) && !ssl)
      message_writer(epee::console_color_yellow, true) << tr("Using your own without SSL exposes your RPC traffic to monitoring");
    message_writer(epee::console_color_yellow, true) << tr("You are strongly encouraged to connect to the Oxen network using your own daemon");
    message_writer(epee::console_color_yellow, true) << tr("If you or someone you trust are operating this daemon, you can use --trusted-daemon");
    message_writer();

    cryptonote::rpc::GET_INFO::request req;
    cryptonote::rpc::GET_INFO::response res;
    bool r = m_wallet->invoke_http<rpc::GET_INFO>(req, res);
    std::string err = interpret_rpc_response(r, res.status);
    if (r && err.empty() && res.untrusted)
      message_writer(epee::console_color_yellow, true) << tr("Moreover, a daemon is also less secure when running in bootstrap mode");
  }

  if (m_wallet->get_ring_database().empty())
    fail_msg_writer() << tr("Failed to initialize ring database: privacy enhancing features will be inactive");

  m_wallet->callback(this);

  if (welcome)
    message_writer(epee::console_color_yellow, true) << tr("If you are new to Oxen, type \"welcome\" for a brief overview.");

  m_last_activity_time = time(NULL);
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::deinit()
{
  if (!m_wallet.get())
    return true;

  return close_wallet();
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::handle_command_line(const boost::program_options::variables_map& vm)
{
  m_wallet_file                   = fs::u8path(command_line::get_arg(vm, arg_wallet_file));
  m_generate_new                  = fs::u8path(command_line::get_arg(vm, arg_generate_new_wallet));
  m_generate_from_device          = fs::u8path(command_line::get_arg(vm, arg_generate_from_device));
  m_generate_from_view_key        = fs::u8path(command_line::get_arg(vm, arg_generate_from_view_key));
  m_generate_from_spend_key       = fs::u8path(command_line::get_arg(vm, arg_generate_from_spend_key));
  m_generate_from_keys            = fs::u8path(command_line::get_arg(vm, arg_generate_from_keys));
  m_generate_from_multisig_keys   = fs::u8path(command_line::get_arg(vm, arg_generate_from_multisig_keys));
  m_generate_from_json            = fs::u8path(command_line::get_arg(vm, arg_generate_from_json));
  m_mnemonic_language             = command_line::get_arg(vm, arg_mnemonic_language);
  m_electrum_seed                 = command_line::get_arg(vm, arg_electrum_seed);
  m_restore_deterministic_wallet  = command_line::get_arg(vm, arg_restore_deterministic_wallet);
  m_restore_multisig_wallet       = command_line::get_arg(vm, arg_restore_multisig_wallet);
  m_non_deterministic             = command_line::get_arg(vm, arg_non_deterministic);
  m_allow_mismatched_daemon_version = command_line::get_arg(vm, arg_allow_mismatched_daemon_version);
  m_restore_height                = command_line::get_arg(vm, arg_restore_height);
  m_restore_date                  = command_line::get_arg(vm, arg_restore_date);
  m_do_not_relay                  = command_line::get_arg(vm, arg_do_not_relay);
  m_subaddress_lookahead          = command_line::get_arg(vm, arg_subaddress_lookahead);
  m_use_english_language_names    = command_line::get_arg(vm, arg_use_english_language_names);
  m_restoring                     = !m_generate_from_view_key.empty() ||
                                    !m_generate_from_spend_key.empty() ||
                                    !m_generate_from_keys.empty() ||
                                    !m_generate_from_multisig_keys.empty() ||
                                    !m_generate_from_json.empty() ||
                                    !m_generate_from_device.empty() ||
                                    m_restore_deterministic_wallet ||
                                    m_restore_multisig_wallet;

  if (!command_line::is_arg_defaulted(vm, arg_restore_date))
  {
    uint16_t year;
    uint8_t month, day;
    if (!datestr_to_int(m_restore_date, year, month, day))
      return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::try_connect_to_daemon(bool silent, rpc::version_t* version)
{
  rpc::version_t version_{};
  if (!version)
    version = &version_;
  bool good = false;
  bool threw = false;
  constexpr const char* bad_msg = "Check the port and daemon address; if incorrect you can use the 'set_daemon' command or '--daemon-address' option to change them.";
  try {
    good = m_wallet->check_connection(version, nullptr, !silent);
  } catch (const std::exception& e) {
    threw = true;
    if (!silent)
      fail_msg_writer() << tr("wallet failed to connect to daemon at ") << m_wallet->get_daemon_address() << ": " << e.what() << ".\n"
        << tr(bad_msg);
  }
  if (!good)
  {
    if (!silent && !threw)
      // If we get here, the above didn't throw, which means we connected and got a response but the daemon returned a non-okay status
      fail_msg_writer() << tr("wallet got bad status from daemon at ") << m_wallet->get_daemon_address() << ".\n" << tr(bad_msg);
    return false;
  }
  if (!m_allow_mismatched_daemon_version && version->first != rpc::VERSION.first)
  {
    if (!silent)
      fail_msg_writer() << boost::format(tr("Daemon uses a different RPC major version (%u) than the wallet (%u): %s. Either update one of them, or use --allow-mismatched-daemon-version.")) % version->first % rpc::VERSION.first % m_wallet->get_daemon_address();
    return false;
  }
  return true;
}

/*!
 * \brief Gets the word seed language from the user.
 *
 * User is asked to choose from a list of supported languages.
 *
 * \return The chosen language.
 */
std::string simple_wallet::get_mnemonic_language()
{
  std::vector<std::string> language_list_self, language_list_english;
  const std::vector<std::string> &language_list = m_use_english_language_names ? language_list_english : language_list_self;
  std::string language_choice;
  int language_number = -1;
  crypto::ElectrumWords::get_language_list(language_list_self, false);
  crypto::ElectrumWords::get_language_list(language_list_english, true);
  std::cout << tr("List of available languages for your wallet's seed:") << std::endl;
  std::cout << tr("If your display freezes, exit blind with ^C, then run again with --use-english-language-names") << std::endl;
  int ii;
  std::vector<std::string>::const_iterator it;
  for (it = language_list.begin(), ii = 0; it != language_list.end(); it++, ii++)
  {
    std::cout << ii << " : " << *it << std::endl;
  }
  while (language_number < 0)
  {
    language_choice = input_line(tr("Enter the number corresponding to the language of your choice"));
    if (std::cin.eof())
      return std::string();
    try
    {
      language_number = std::stoi(language_choice);
      if (!((language_number >= 0) && (static_cast<unsigned int>(language_number) < language_list.size())))
      {
        language_number = -1;
        fail_msg_writer() << tr("invalid language choice entered. Please try again.\n");
      }
    }
    catch (const std::exception &e)
    {
      fail_msg_writer() << tr("invalid language choice entered. Please try again.\n");
    }
  }
  return language_list_self[language_number];
}
//----------------------------------------------------------------------------------------------------
std::optional<tools::password_container> simple_wallet::get_and_verify_password() const
{
  auto pwd_container = default_password_prompter(m_wallet_file.empty());
  if (!pwd_container)
    return std::nullopt;

  if (!m_wallet->verify_password(pwd_container->password()))
  {
    fail_msg_writer() << tr("invalid password");
    return std::nullopt;
  }
  return pwd_container;
}
//----------------------------------------------------------------------------------------------------
std::optional<epee::wipeable_string> simple_wallet::new_wallet(const boost::program_options::variables_map& vm,
  const crypto::secret_key& recovery_key, bool recover, bool two_random, const std::string &old_language)
{
  std::pair<std::unique_ptr<tools::wallet2>, tools::password_container> rc;
  try { rc = tools::wallet2::make_new(vm, false, password_prompter); }
  catch(const std::exception &e) { fail_msg_writer() << tr("Error creating wallet: ") << e.what(); return {}; }
  m_wallet = std::move(rc.first);
  if (!m_wallet)
  {
    return {};
  }
  epee::wipeable_string password = rc.second.password();

  if (!m_subaddress_lookahead.empty())
  {
    auto lookahead = parse_subaddress_lookahead(m_subaddress_lookahead);
    assert(lookahead);
    m_wallet->set_subaddress_lookahead(lookahead->first, lookahead->second);
  }

  bool was_deprecated_wallet = m_restore_deterministic_wallet && ((old_language == crypto::ElectrumWords::old_language_name) ||
    crypto::ElectrumWords::get_is_old_style_seed(m_electrum_seed));

  std::string mnemonic_language = old_language;

  std::vector<std::string> language_list;
  crypto::ElectrumWords::get_language_list(language_list);
  if (mnemonic_language.empty() && std::find(language_list.begin(), language_list.end(), m_mnemonic_language) != language_list.end())
  {
    mnemonic_language = m_mnemonic_language;
  }

  // Ask for seed language if:
  // it's a deterministic wallet AND
  // a seed language is not already specified AND
  // (it is not a wallet restore OR if it was a deprecated wallet
  // that was earlier used before this restore)
  if ((!two_random) && (mnemonic_language.empty() || mnemonic_language == crypto::ElectrumWords::old_language_name) && (!m_restore_deterministic_wallet || was_deprecated_wallet))
  {
    if (was_deprecated_wallet)
    {
      // The user had used an older version of the wallet with old style mnemonics.
      message_writer(epee::console_color_green, false) << "\n" << tr("You had been using "
        "a deprecated version of the wallet. Please use the new seed that we provide.\n");
    }
    mnemonic_language = get_mnemonic_language();
    if (mnemonic_language.empty())
      return {};
  }

  m_wallet->set_seed_language(mnemonic_language);

  bool create_address_file = command_line::get_arg(vm, arg_create_address_file);

  crypto::secret_key recovery_val;
  try
  {
    recovery_val = m_wallet->generate(m_wallet_file, std::move(rc.second).password(), recovery_key, recover, two_random, create_address_file);
    message_writer(epee::console_color_white, true) << tr("Generated new wallet: ")
      << m_wallet->get_account().get_public_address_str(m_wallet->nettype());
    rdln::suspend_readline pause_readline;
    std::cout << tr("View key: ");
    print_secret_key(m_wallet->get_account().get_keys().m_view_secret_key);
    std::cout << '\n';
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << tr("failed to generate new wallet: ") << e.what();
    return {};
  }

  // convert rng value to electrum-style word list
  epee::wipeable_string electrum_words;

  crypto::ElectrumWords::bytes_to_words(recovery_val, electrum_words, mnemonic_language);

  success_msg_writer() <<
    "**********************************************************************\n" <<
    tr("Your wallet has been generated!\n"
    "To start synchronizing with the daemon, use the \"refresh\" command.\n"
    "Use the \"help\" command to see the list of available commands.\n"
    "Use \"help <command>\" to see a command's documentation.\n"
    "Always use the \"exit\" command when closing oxen-wallet-cli to save \n"
    "your current session's state. Otherwise, you might need to synchronize \n"
    "your wallet again (your wallet keys are NOT at risk in any case).\n")
  ;

  if (!two_random)
  {
    print_seed(electrum_words);
  }
  success_msg_writer() << "**********************************************************************";

  return password;
}
//----------------------------------------------------------------------------------------------------
std::optional<epee::wipeable_string> simple_wallet::new_wallet(const boost::program_options::variables_map& vm,
  const cryptonote::account_public_address& address, const std::optional<crypto::secret_key>& spendkey,
  const crypto::secret_key& viewkey)
{
  std::pair<std::unique_ptr<tools::wallet2>, tools::password_container> rc;
  try { rc = tools::wallet2::make_new(vm, false, password_prompter); }
  catch(const std::exception &e) { fail_msg_writer() << tr("Error creating wallet: ") << e.what(); return {}; }
  m_wallet = std::move(rc.first);
  if (!m_wallet)
  {
    return {};
  }
  epee::wipeable_string password = rc.second.password();

  if (!m_subaddress_lookahead.empty())
  {
    auto lookahead = parse_subaddress_lookahead(m_subaddress_lookahead);
    assert(lookahead);
    m_wallet->set_subaddress_lookahead(lookahead->first, lookahead->second);
  }

  if (m_restore_height)
    m_wallet->set_refresh_from_block_height(m_restore_height);

  bool create_address_file = command_line::get_arg(vm, arg_create_address_file);

  try
  {
    if (spendkey)
    {
      m_wallet->generate(m_wallet_file, std::move(rc.second).password(), address, *spendkey, viewkey, create_address_file);
    }
    else
    {
      m_wallet->generate(m_wallet_file, std::move(rc.second).password(), address, viewkey, create_address_file);
    }
    message_writer(epee::console_color_white, true) << tr("Generated new wallet: ")
      << m_wallet->get_account().get_public_address_str(m_wallet->nettype());
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << tr("failed to generate new wallet: ") << e.what();
    return {};
  }


  return password;
}

//----------------------------------------------------------------------------------------------------
std::optional<epee::wipeable_string> simple_wallet::new_device_wallet(const boost::program_options::variables_map& vm)
{
  std::pair<std::unique_ptr<tools::wallet2>, tools::password_container> rc;
  try { rc = tools::wallet2::make_new(vm, false, password_prompter); }
  catch(const std::exception &e) { fail_msg_writer() << tr("Error creating wallet: ") << e.what(); return {}; }
  m_wallet = std::move(rc.first);
  m_wallet->callback(this);
  if (!m_wallet)
  {
    return {};
  }
  epee::wipeable_string password = rc.second.password();

  if (!m_subaddress_lookahead.empty())
  {
    auto lookahead = parse_subaddress_lookahead(m_subaddress_lookahead);
    assert(lookahead);
    m_wallet->set_subaddress_lookahead(lookahead->first, lookahead->second);
  }

  if (m_restore_height)
    m_wallet->set_refresh_from_block_height(m_restore_height);

  auto device_desc = tools::wallet2::device_name_option(vm);
  auto device_derivation_path = tools::wallet2::device_derivation_path_option(vm);
  try
  {
    bool create_address_file = command_line::get_arg(vm, arg_create_address_file);
    std::optional<std::string> create_hwdev_txt;
    if (!command_line::is_arg_defaulted(vm, arg_create_hwdev_txt))
      create_hwdev_txt = command_line::get_arg(vm, arg_create_hwdev_txt);
    m_wallet->device_derivation_path(device_derivation_path);
    message_writer(epee::console_color_white, true) << tr("Connecting to hardware device");
    message_writer() << tr("Your hardware device will ask for permission to export your wallet view key.\n"
                           "This is optional, but will significantly improve wallet syncing speed. Your\n"
                           "spend key (needed to spend funds) does not leave the device.");
    m_wallet->restore_from_device(
            m_wallet_file, std::move(rc.second).password(), device_desc.empty() ? "Ledger" : device_desc, create_address_file,
            std::move(create_hwdev_txt), [](const std::string& msg) { message_writer(epee::console_color_green, true) << msg; });
    message_writer(epee::console_color_white, true) << tr("Finished setting up wallet from hw device");
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << tr("failed to generate new wallet: ") << e.what();
    return {};
  }

  return password;
}
//----------------------------------------------------------------------------------------------------
std::optional<epee::wipeable_string> simple_wallet::new_wallet(const boost::program_options::variables_map& vm,
    const epee::wipeable_string &multisig_keys, const std::string &old_language)
{
  std::pair<std::unique_ptr<tools::wallet2>, tools::password_container> rc;
  try { rc = tools::wallet2::make_new(vm, false, password_prompter); }
  catch(const std::exception &e) { fail_msg_writer() << tr("Error creating wallet: ") << e.what(); return {}; }
  m_wallet = std::move(rc.first);
  if (!m_wallet)
  {
    return {};
  }
  epee::wipeable_string password = rc.second.password();

  if (!m_subaddress_lookahead.empty())
  {
    auto lookahead = parse_subaddress_lookahead(m_subaddress_lookahead);
    assert(lookahead);
    m_wallet->set_subaddress_lookahead(lookahead->first, lookahead->second);
  }

  std::string mnemonic_language = old_language;

  std::vector<std::string> language_list;
  crypto::ElectrumWords::get_language_list(language_list);
  if (mnemonic_language.empty() && std::find(language_list.begin(), language_list.end(), m_mnemonic_language) != language_list.end())
  {
    mnemonic_language = m_mnemonic_language;
  }

  m_wallet->set_seed_language(mnemonic_language);

  bool create_address_file = command_line::get_arg(vm, arg_create_address_file);

  try
  {
    m_wallet->generate(m_wallet_file, std::move(rc.second).password(), multisig_keys, create_address_file);
    bool ready;
    uint32_t threshold, total;
    if (!m_wallet->multisig(&ready, &threshold, &total) || !ready)
    {
      fail_msg_writer() << tr("failed to generate new mutlisig wallet");
      return {};
    }
    message_writer(epee::console_color_white, true) << boost::format(tr("Generated new %u/%u multisig wallet: ")) % threshold % total
      << m_wallet->get_account().get_public_address_str(m_wallet->nettype());
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << tr("failed to generate new wallet: ") << e.what();
    return {};
  }

  return password;
}
//----------------------------------------------------------------------------------------------------
std::optional<epee::wipeable_string> simple_wallet::open_wallet(const boost::program_options::variables_map& vm)
{
  if (m_wallet_file.empty())
  {
    fail_msg_writer() << tr("no wallet file provided");
    return {};
  }

  bool keys_file_exists;
  bool wallet_file_exists;

  tools::wallet2::wallet_exists(m_wallet_file, keys_file_exists, wallet_file_exists);
  if(!keys_file_exists)
  {
    fail_msg_writer() << tr("Key file not found. Failed to open wallet");
    return {};
  }

  epee::wipeable_string password;
  try
  {
    auto rc = tools::wallet2::make_from_file(vm, false, "", password_prompter);
    m_wallet = std::move(rc.first);
    password = std::move(std::move(rc.second).password());
    if (!m_wallet)
    {
      return {};
    }

    m_wallet->callback(this);
    m_wallet->load(m_wallet_file, password);
    std::string prefix;
    bool ready;
    uint32_t threshold, total;
    if (m_wallet->watch_only())
      prefix = tr("Opened watch-only wallet");
    else if (m_wallet->multisig(&ready, &threshold, &total))
      prefix = (boost::format(tr("Opened %u/%u multisig wallet%s")) % threshold % total % (ready ? "" : " (not yet finalized)")).str();
    else
      prefix = tr("Opened wallet");
    message_writer(epee::console_color_green, true) <<
      prefix << ": " << m_wallet->get_account().get_public_address_str(m_wallet->nettype());
    if (m_wallet->get_account().get_device().is_hardware_device()) {
       message_writer(epee::console_color_white, true) << "Wallet is on device: " << m_wallet->get_account().get_device().get_name();
    }
    // If the wallet file is deprecated, we should ask for mnemonic language again and store
    // everything in the new format.
    // NOTE: this is_deprecated() refers to the wallet file format before becoming JSON. It does not refer to the "old english" seed words form of "deprecated" used elsewhere.
    if (m_wallet->is_deprecated())
    {
      bool is_deterministic;
      {
        SCOPED_WALLET_UNLOCK_ON_BAD_PASSWORD(return {};);
        is_deterministic = m_wallet->is_deterministic();
      }
      if (is_deterministic)
      {
        message_writer(epee::console_color_green, false) << "\n" << tr("You had been using "
          "a deprecated version of the wallet. Please proceed to upgrade your wallet.\n");
        std::string mnemonic_language = get_mnemonic_language();
        if (mnemonic_language.empty())
          return {};
        m_wallet->set_seed_language(mnemonic_language);
        m_wallet->rewrite(m_wallet_file, password);

        // Display the seed
        epee::wipeable_string seed;
        m_wallet->get_seed(seed);
        print_seed(seed);
      }
      else
      {
        message_writer(epee::console_color_green, false) << "\n" << tr("You had been using "
          "a deprecated version of the wallet. Your wallet file format is being upgraded now.\n");
        m_wallet->rewrite(m_wallet_file, password);
      }
    }
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << tr("failed to load wallet: ") << e.what();
    if (m_wallet)
    {
      // only suggest removing cache if the password was actually correct
      bool password_is_correct = false;
      try
      {
        password_is_correct = m_wallet->verify_password(password);
      }
      catch (...) { } // guard against I/O errors
      if (password_is_correct)
        fail_msg_writer() << boost::format(tr("You may want to remove the file \"%s\" and try again")) % m_wallet_file;
    }
    return {};
  }
  success_msg_writer() <<
    "**********************************************************************\n" <<
    tr("Use the \"help\" command to see the list of available commands.\n") <<
    tr("Use \"help <command>\" to see a command's documentation.\n") <<
    "**********************************************************************";
  return password;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::close_wallet()
{
  try
  {
    m_wallet->store();
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << e.what();
    return false;
  }

  if (m_idle_run.load(std::memory_order_relaxed))
  {
    m_idle_run.store(false, std::memory_order_relaxed);
    m_wallet->stop();
    {
      std::unique_lock lock{m_idle_mutex};
      m_idle_cond.notify_one();
    }
    m_idle_thread.join();
  }

  bool r = m_wallet->deinit();
  if (!r)
  {
    fail_msg_writer() << tr("failed to deinitialize wallet");
    return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::save(const std::vector<std::string> &args)
{
  try
  {
    LOCK_IDLE_SCOPE();
    m_wallet->store();
    success_msg_writer() << tr("Wallet data saved");
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << e.what();
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::save_watch_only(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  if (m_wallet->multisig())
  {
    fail_msg_writer() << tr("wallet is multisig and cannot save a watch-only version");
    return true;
  }

  const auto pwd_container = password_prompter(tr("Password for new watch-only wallet"), true);

  if (!pwd_container)
  {
    fail_msg_writer() << tr("failed to read wallet password");
    return true;
  }

  try
  {
    fs::path new_keys_filename;
    m_wallet->write_watch_only_wallet(m_wallet_file, pwd_container->password(), new_keys_filename);
    success_msg_writer() << tr("Watch only wallet saved as: ") << new_keys_filename.u8string();
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("Failed to save watch only wallet: ") << e.what();
    return true;
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::start_mining(const std::vector<std::string>& args)
{
  if (!m_wallet->is_trusted_daemon())
  {
    fail_msg_writer() << tr("this command requires a trusted daemon. Enable with --trusted-daemon");
    return true;
  }

  if (!try_connect_to_daemon())
    return true;

  if (!m_wallet)
  {
    fail_msg_writer() << tr("wallet is null");
    return true;
  }
  rpc::START_MINING::request req{};
  req.miner_address = m_wallet->get_account().get_public_address_str(m_wallet->nettype());

  bool ok = true;
  size_t arg_size = args.size();
  if(arg_size >= 1)
  {
    uint16_t num = 1;
    ok = string_tools::get_xtype_from_string(num, args[0]);
    ok = ok && 1 <= num;
    req.threads_count = num;
  }
  else
  {
    req.threads_count = 1;
  }

  if (!ok)
  {
    PRINT_USAGE(USAGE_START_MINING);
    return true;
  }

  rpc::START_MINING::response res{};
  bool r = m_wallet->invoke_http<rpc::START_MINING>(req, res);
  std::string err = interpret_rpc_response(r, res.status);
  if (err.empty())
    success_msg_writer() << tr("Mining started in daemon");
  else
    fail_msg_writer() << tr("mining has NOT been started: ") << err;
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::stop_mining(const std::vector<std::string>& args)
{
  if (!try_connect_to_daemon())
    return true;

  if (!m_wallet)
  {
    fail_msg_writer() << tr("wallet is null");
    return true;
  }

  rpc::STOP_MINING::response res{};
  bool r = m_wallet->invoke_http<rpc::STOP_MINING>({}, res);
  std::string err = interpret_rpc_response(r, res.status);
  if (err.empty())
    success_msg_writer() << tr("Mining stopped in daemon");
  else
    fail_msg_writer() << tr("mining has NOT been stopped: ") << err;
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::set_daemon(const std::vector<std::string>& args)
{
  std::string daemon_url;

  if (args.size() < 1)
  {
    PRINT_USAGE(USAGE_SET_DAEMON);
    return true;
  }

  bool is_local = false;
  try {
    auto [proto, host, port, uri] = rpc::http_client::parse_url(args[0]);
    if (proto.empty())
      proto = "http";
    if (port == 0)
      port = get_config(m_wallet->nettype()).RPC_DEFAULT_PORT;
    daemon_url = std::move(proto) + "://" + host + ":" + std::to_string(port) + uri;
    is_local = tools::is_local_address(host);
  } catch (const std::exception& e) {
    fail_msg_writer() << tr("This does not seem to be a valid daemon URL; enter a URL such as: http://example.com:1234");
    return false;
  }

  LOCK_IDLE_SCOPE();
  m_wallet->init(daemon_url);

  if (args.size() == 2)
  {
    if (args[1] == "trusted")
      m_wallet->set_trusted_daemon(true);
    else if (args[1] == "untrusted")
      m_wallet->set_trusted_daemon(false);
    else
    {
      fail_msg_writer() << tr("Expected trusted or untrusted, got ") << args[1] << ": assuming untrusted";
      m_wallet->set_trusted_daemon(false);
    }
  }
  else if (is_local)
  {
    MINFO(tr("Daemon is local, assuming trusted"));
    m_wallet->set_trusted_daemon(true);
  }
  success_msg_writer() << "Daemon set to " << daemon_url << ", " << tr(m_wallet->is_trusted_daemon() ? "trusted" : "untrusted");
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::save_bc(const std::vector<std::string>& args)
{
  if (!try_connect_to_daemon())
    return true;

  if (!m_wallet)
  {
    fail_msg_writer() << tr("wallet is null");
    return true;
  }
  rpc::SAVE_BC::request req{};
  rpc::SAVE_BC::response res{};
  bool r = m_wallet->invoke_http<rpc::SAVE_BC>(req, res);
  std::string err = interpret_rpc_response(r, res.status);
  if (err.empty())
    success_msg_writer() << tr("Blockchain saved");
  else
    fail_msg_writer() << tr("blockchain can't be saved: ") << err;
  return true;
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_new_block(uint64_t height, const cryptonote::block& block)
{
  if (m_locked)
    return;
  if (!m_auto_refresh_refreshing)
    m_refresh_progress_reporter.update(height, false);
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index, uint64_t unlock_time, bool blink)
{
  if (m_locked)
    return;
  {
    auto m = message_writer(epee::console_color_green, false);
    m << "\r";
    if (height == 0 && blink)
      m << tr("Blink, ");
    else
      m << tr("Height ") << height << ", ";
    m << tr("txid ") << txid << ", " <<
      print_money(amount) << ", " <<
      tr("idx ") << subaddr_index;
  }

  const uint64_t warn_height = m_wallet->nettype() == network_type::TESTNET ? 1000000 : m_wallet->nettype() == network_type::DEVNET ? 0 : 1650000;
  if (height >= warn_height)
  {
    std::vector<tx_extra_field> tx_extra_fields;
    parse_tx_extra(tx.extra, tx_extra_fields); // failure ok
    tx_extra_nonce extra_nonce;
    tx_extra_pub_key extra_pub_key;
    crypto::hash8 payment_id8 = crypto::null_hash8;
    if (find_tx_extra_field_by_type(tx_extra_fields, extra_pub_key))
    {
      const crypto::public_key &tx_pub_key = extra_pub_key.pub_key;
      if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
      {
        if (get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
        {
          m_wallet->get_account().get_device().decrypt_payment_id(payment_id8, tx_pub_key, m_wallet->get_account().get_keys().m_view_secret_key);
        }
     }
    }

    if (payment_id8 != crypto::null_hash8)
      message_writer() <<
        tr("NOTE: this transaction uses an encrypted payment ID: consider using subaddresses instead");

    crypto::hash payment_id = crypto::null_hash;
    if (get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
      message_writer(epee::console_color_red, false) <<
        tr("WARNING: this transaction uses an unencrypted payment ID: these are obsolete and ignored. Use subaddresses instead.");
  }
  if (unlock_time && !cryptonote::is_coinbase(tx))
    message_writer() << tr("NOTE: This transaction is locked, see details with: show_transfer ") + tools::type_to_hex(txid);
  if (m_auto_refresh_refreshing)
    m_cmd_binder.print_prompt();
  else
    m_refresh_progress_reporter.update(height, true);
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index)
{
  if (m_locked)
    return;
  // Not implemented in CLI wallet
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_money_spent(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& in_tx, uint64_t amount, const cryptonote::transaction& spend_tx, const cryptonote::subaddress_index& subaddr_index)
{
  if (m_locked)
    return;
  message_writer(epee::console_color_magenta, false) << "\r" <<
    tr("Height ") << height << ", " <<
    tr("txid ") << txid << ", " <<
    tr("spent ") << print_money(amount) << ", " <<
    tr("idx ") << subaddr_index;
  if (m_auto_refresh_refreshing)
    m_cmd_binder.print_prompt();
  else
    m_refresh_progress_reporter.update(height, true);
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_skip_transaction(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx)
{
  if (m_locked)
    return;
}
//----------------------------------------------------------------------------------------------------
std::optional<epee::wipeable_string> simple_wallet::on_get_password(const char *reason)
{
  if (m_locked)
    return std::nullopt;
  // can't ask for password from a background thread
  if (!m_in_manual_refresh.load(std::memory_order_relaxed))
  {
    crypto::hash tx_pool_checksum = m_wallet->get_long_poll_tx_pool_checksum();
    if (m_password_asked_on_height   != m_wallet->get_blockchain_current_height() ||
        m_password_asked_on_checksum != tx_pool_checksum)
    {
      m_password_asked_on_height = m_wallet->get_blockchain_current_height();
      m_password_asked_on_checksum   = tx_pool_checksum;

      message_writer(epee::console_color_red, false) << boost::format(tr("Password needed %s")) % reason;
      m_cmd_binder.print_prompt();
    }
    return std::nullopt;
  }

  rdln::suspend_readline pause_readline;
  std::string msg = tr("Enter password ");
  if (reason && *reason)
    msg += reason;
  auto pwd_container = tools::password_container::prompt(false, msg.c_str());
  if (!pwd_container)
  {
    MERROR("Failed to read password");
    return std::nullopt;
  }

  return pwd_container->password();
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_device_button_request(uint64_t code)
{
  message_writer(epee::console_color_white, false) << tr("Device requires attention");
}
//----------------------------------------------------------------------------------------------------
std::optional<epee::wipeable_string> simple_wallet::on_device_pin_request()
{
  rdln::suspend_readline pause_readline;
  std::string msg = tr("Enter device PIN");
  auto pwd_container = tools::password_container::prompt(false, msg.c_str());
  THROW_WALLET_EXCEPTION_IF(!pwd_container, tools::error::password_entry_failed, tr("Failed to read device PIN"));
  return pwd_container->password();
}
//----------------------------------------------------------------------------------------------------
std::optional<epee::wipeable_string> simple_wallet::on_device_passphrase_request(bool & on_device)
{
  if (on_device) {
    std::string accepted = input_line(tr(
        "Device asks for passphrase. Do you want to enter the passphrase on device (Y) (or on the host (N))?"));
    if (std::cin.eof() || command_line::is_yes(accepted)) {
      message_writer(epee::console_color_white, true) << tr("Please enter the device passphrase on the device");
      return std::nullopt;
    }
  }

  rdln::suspend_readline pause_readline;
  on_device = false;
  std::string msg = tr("Enter device passphrase");
  auto pwd_container = tools::password_container::prompt(false, msg.c_str());
  THROW_WALLET_EXCEPTION_IF(!pwd_container, tools::error::password_entry_failed, tr("Failed to read device passphrase"));
  return pwd_container->password();
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::on_refresh_finished(uint64_t start_height, uint64_t fetched_blocks, bool is_init, bool received_money)
{
  const uint64_t rfbh = m_wallet->get_refresh_from_block_height();
  std::string err;
  const uint64_t dh = m_wallet->get_daemon_blockchain_height(err);
  if (err.empty() && rfbh > dh)
  {
    message_writer(epee::console_color_yellow, false) << tr("The wallet's refresh-from-block-height setting is higher than the daemon's height: this may mean your wallet will skip over transactions");
  }

  // Key image sync after the first refresh
  if (!m_wallet->get_account().get_device().has_tx_cold_sign() || m_wallet->get_account().get_device().has_ki_live_refresh()) {
    return;
  }

  if (!received_money || m_wallet->get_device_last_key_image_sync() != 0) {
    return;
  }

  // Finished first refresh for HW device and money received -> KI sync
  message_writer() << "\n" << tr("The first refresh has finished for the HW-based wallet with received money. hw_key_images_sync is needed. ");

  std::string accepted = input_line(tr("Do you want to do it now? (Y/Yes/N/No): "));
  if (std::cin.eof() || !command_line::is_yes(accepted)) {
    message_writer(epee::console_color_red, false) << tr("hw_key_images_sync skipped. Run command manually before a transfer.");
    return;
  }

  key_images_sync_intern();
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::refresh_main(uint64_t start_height, enum ResetType reset, bool is_init)
{
  if (!try_connect_to_daemon(is_init))
    return true;

  LOCK_IDLE_SCOPE();

  crypto::hash transfer_hash_pre{};
  uint64_t height_pre = 0, height_post = 0;
  if (reset != ResetNone)
  {
    if (reset == ResetSoftKeepKI)
      height_pre = m_wallet->hash_m_transfers(-1, transfer_hash_pre);

    m_wallet->rescan_blockchain(reset == ResetHard, false, reset == ResetSoftKeepKI);
  }

  rdln::suspend_readline pause_readline;

  message_writer() << tr("Starting refresh...");

  uint64_t fetched_blocks = 0;
  bool received_money = false;
  bool ok = false;
  std::ostringstream ss;
  try
  {
    m_in_manual_refresh.store(true, std::memory_order_relaxed);
    OXEN_DEFER { m_in_manual_refresh.store(false, std::memory_order_relaxed); };
    m_wallet->refresh(m_wallet->is_trusted_daemon(), start_height, fetched_blocks, received_money, true /*check_pool*/);

    if (reset == ResetSoftKeepKI)
    {
      m_wallet->finish_rescan_bc_keep_key_images(height_pre, transfer_hash_pre);

      height_post = m_wallet->get_num_transfer_details();
      if (height_pre != height_post)
      {
        message_writer() << tr("New transfer received since rescan was started. Key images are incomplete.");
      }
    }

    m_has_locked_key_images = query_locked_stakes(false /*print_result*/);
    ok = true;
    // Clear line "Height xxx of xxx"
    std::cout << "\r                                                                \r";
    success_msg_writer(true) << tr("Refresh done, blocks received: ") << fetched_blocks;
    if (is_init)
      print_accounts();
    show_balance_unlocked();
    on_refresh_finished(start_height, fetched_blocks, is_init, received_money);
  }
  catch (const tools::error::daemon_busy&)
  {
    ss << tr("daemon is busy. Please try again later.");
  }
  catch (const tools::error::no_connection_to_daemon&)
  {
    ss << tr("no connection to daemon. Please make sure daemon is running.");
  }
  catch (const tools::error::wallet_rpc_error& e)
  {
    LOG_ERROR("RPC error: " << e.to_string());
    ss << tr("RPC error: ") << e.what();
  }
  catch (const tools::error::refresh_error& e)
  {
    LOG_ERROR("refresh error: " << e.to_string());
    ss << tr("refresh error: ") << e.what();
  }
  catch (const tools::error::wallet_internal_error& e)
  {
    LOG_ERROR("internal error: " << e.to_string());
    ss << tr("internal error: ") << e.what();
  }
  catch (const std::exception& e)
  {
    LOG_ERROR("unexpected error: " << e.what());
    ss << tr("unexpected error: ") << e.what();
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    ss << tr("unknown error");
  }

  if (!ok)
  {
    fail_msg_writer() << tr("refresh failed: ") << ss.str() << ". " << tr("Blocks received: ") << fetched_blocks;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::refresh(const std::vector<std::string>& args)
{
  uint64_t start_height = 0;
  if(!args.empty()){
    try
    {
        start_height = boost::lexical_cast<uint64_t>( args[0] );
    }
    catch(const boost::bad_lexical_cast &)
    {
        start_height = 0;
    }
  }
  return refresh_main(start_height, ResetNone);
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_balance_unlocked(bool detailed)
{
  std::string extra;
  if (m_wallet->has_multisig_partial_key_images())
    extra = tr(" (Some owned outputs have partial key images - import_multisig_info needed)");
  else if (m_wallet->has_unknown_key_images())
    extra += tr(" (Some owned outputs have missing key images - import_key_images needed)");
  success_msg_writer() << tr("Currently selected account: [") << m_current_subaddress_account << tr("] ") << m_wallet->get_subaddress_label({m_current_subaddress_account, 0});
  const std::string tag = m_wallet->get_account_tags().second[m_current_subaddress_account];
  success_msg_writer() << tr("Tag: ") << (tag.empty() ? std::string{tr("(No tag assigned)")} : tag);
  uint64_t blocks_to_unlock, time_to_unlock;
  uint64_t unlocked_balance = m_wallet->unlocked_balance(m_current_subaddress_account, false, &blocks_to_unlock, &time_to_unlock);
  std::string unlock_time_message;
  if (blocks_to_unlock > 0 && time_to_unlock > 0)
    unlock_time_message = (boost::format(" (%lu block(s) and %s to unlock)") % blocks_to_unlock % tools::get_human_readable_timespan(std::chrono::seconds(time_to_unlock))).str();
  else if (blocks_to_unlock > 0)
    unlock_time_message = (boost::format(" (%lu block(s) to unlock)") % blocks_to_unlock).str();
  else if (time_to_unlock > 0)
    unlock_time_message = (boost::format(" (%s to unlock)") % tools::get_human_readable_timespan(std::chrono::seconds(time_to_unlock))).str();
  success_msg_writer() << tr("Balance: ") << print_money(m_wallet->balance(m_current_subaddress_account, false)) << ", "
    << tr("unlocked balance: ") << print_money(unlocked_balance) << unlock_time_message << extra;
  std::map<uint32_t, uint64_t> balance_per_subaddress = m_wallet->balance_per_subaddress(m_current_subaddress_account, false);
  std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> unlocked_balance_per_subaddress = m_wallet->unlocked_balance_per_subaddress(m_current_subaddress_account, false);

  if (m_current_subaddress_account == 0) { // Only the primary account can stake and earn rewards, currently
    if (auto stakes = m_wallet->get_staked_service_nodes(); !stakes.empty()) {
      auto my_addr = m_wallet->get_address_as_str();
      uint64_t total_staked = 0, stakes_unlocking = 0;
      for (auto& stake : stakes)
        for (auto& contr : stake.contributors)
          if (contr.address == my_addr)
          {
            total_staked += contr.amount;
            if (stake.requested_unlock_height > 0)
              stakes_unlocking += contr.amount;
          }
      success_msg_writer() << fmt::format(tr("Total staked: {}, {} unlocking"), print_money(total_staked), print_money(stakes_unlocking));
    }

    if (uint64_t batched_amount = m_wallet->get_batched_amount(); batched_amount > 0)
    {
      uint64_t next_payout_block = m_wallet->get_next_batch_payout();
      uint64_t blockchain_height = m_wallet->get_blockchain_current_height();
      std::string next_batch_payout = next_payout_block > 0
        ? fmt::format(tr(" (next payout: block {}, in about {})"),
            next_payout_block,
            tools::get_human_readable_timespan((next_payout_block - blockchain_height) * TARGET_BLOCK_TIME))
        : tr(" (next payout: unknown)");
      success_msg_writer() << tr("Pending SN rewards: ")
        << print_money(batched_amount) << ", "
        << next_batch_payout;
    }
  }
  if (!detailed || balance_per_subaddress.empty())
    return true;
  success_msg_writer() << tr("Balance per address:");
  success_msg_writer() << boost::format("%15s %21s %21s %21s %7s %21s") % tr("Address") % tr("Balance") % tr("Unlocked balance") % tr("Batched Amount") % tr("Outputs") % tr("Label");
  std::vector<wallet::transfer_details> transfers;
  m_wallet->get_transfers(transfers);
  for (const auto& i : balance_per_subaddress)
  {
    cryptonote::subaddress_index subaddr_index = {m_current_subaddress_account, i.first};
    std::string address_str = m_wallet->get_subaddress_as_str(subaddr_index).substr(0, 6);
    uint64_t batched_amount = m_wallet->get_batched_amount(address_str);
    uint64_t num_unspent_outputs = std::count_if(transfers.begin(), transfers.end(), [&subaddr_index](const wallet::transfer_details& td) { return !td.m_spent && td.m_subaddr_index == subaddr_index; });
    success_msg_writer() << boost::format(tr("%8u %6s %21s %21s %21s %7u %21s")) % i.first % address_str % print_money(i.second) % print_money(unlocked_balance_per_subaddress[i.first].first) % print_money(batched_amount) % num_unspent_outputs % m_wallet->get_subaddress_label(subaddr_index);
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_balance(const std::vector<std::string>& args/* = std::vector<std::string>()*/)
{
  if (args.size() > 1 || (args.size() == 1 && args[0] != "detail"))
  {
    PRINT_USAGE(USAGE_SHOW_BALANCE);
    return true;
  }
  LOCK_IDLE_SCOPE();
  show_balance_unlocked(args.size() == 1);
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_incoming_transfers(const std::vector<std::string>& args)
{
  if (args.size() > 3)
  {
    PRINT_USAGE(USAGE_INCOMING_TRANSFERS);
    return true;
  }
  auto local_args = args;
  LOCK_IDLE_SCOPE();

  bool filter = false;
  bool available = false;
  bool verbose = false;
  bool uses = false;
  if (local_args.size() > 0)
  {
    if (local_args[0] == "available")
    {
      filter = true;
      available = true;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "unavailable")
    {
      filter = true;
      available = false;
      local_args.erase(local_args.begin());
    }
  }
  while (local_args.size() > 0)
  {
    if (local_args[0] == "verbose")
      verbose = true;
    else if (local_args[0] == "uses")
      uses = true;
    else
    {
      fail_msg_writer() << tr("Invalid keyword: ") << local_args.front();
      break;
    }
    local_args.erase(local_args.begin());
  }

  const uint64_t blockchain_height = m_wallet->get_blockchain_current_height();

  rdln::suspend_readline pause_readline;

  std::set<uint32_t> subaddr_indices;
  if (local_args.size() > 0 && local_args[0].substr(0, 6) == "index=")
  {
    std::string parse_subaddr_err;
    if (!tools::parse_subaddress_indices(local_args[0], subaddr_indices, &parse_subaddr_err))
    {
      fail_msg_writer() << parse_subaddr_err;
      return true;
    }
    local_args.erase(local_args.begin());
  }

  if (local_args.size() > 0)
  {
    PRINT_USAGE(USAGE_INCOMING_TRANSFERS);
    return true;
  }

  tools::wallet2::transfer_container transfers;
  m_wallet->get_transfers(transfers);

  size_t transfers_found = 0;
  for (const auto& td : transfers)
  {
    if (!filter || available != td.m_spent)
    {
      if (m_current_subaddress_account != td.m_subaddr_index.major || (!subaddr_indices.empty() && subaddr_indices.count(td.m_subaddr_index.minor) == 0))
        continue;
      if (!transfers_found)
      {
        std::string verbose_string;
        if (verbose)
          verbose_string = (boost::format("%68s%68s") % tr("pubkey") % tr("key image")).str();
        message_writer() << boost::format("%21s%8s%12s%8s%16s%68s%16s%s") % tr("amount") % tr("spent") % tr("unlocked") % tr("ringct") % tr("global index") % tr("tx id") % tr("addr index") % verbose_string;
      }
      std::string extra_string;
      if (verbose)
        extra_string += (boost::format("%68s%68s") % td.get_public_key() % (td.m_key_image_known ? tools::type_to_hex(td.m_key_image) : td.m_key_image_partial ? (tools::type_to_hex(td.m_key_image) + "/p") : std::string(64, '?'))).str();
      if (uses)
      {
        std::vector<uint64_t> heights;
        uint64_t idx = 0;
        for (const auto &e: td.m_uses)
        {
          heights.push_back(e.first);
          if (e.first < td.m_spent_height)
            ++idx;
        }
        const std::pair<std::string, std::string> line = show_outputs_line(heights, blockchain_height, idx);
        extra_string += std::string("\n    ") + tr("Used at heights: ") + line.first + "\n    " + line.second;
      }
      message_writer(td.m_spent ? epee::console_color_magenta : epee::console_color_green, false) <<
        boost::format("%21s%8s%12s%8s%16u%68s%16u%s") %
        print_money(td.amount()) %
        (td.m_spent ? tr("T") : tr("F")) %
        (m_wallet->frozen(td) ? tr("[frozen]") : m_wallet->is_transfer_unlocked(td) ? tr("unlocked") : tr("locked")) %
        (td.is_rct() ? tr("RingCT") : tr("-")) %
        td.m_global_output_index %
        td.m_txid %
        td.m_subaddr_index.minor %
        extra_string;
      ++transfers_found;
    }
  }

  if (!transfers_found)
  {
    if (!filter)
    {
      success_msg_writer() << tr("No incoming transfers");
    }
    else if (available)
    {
      success_msg_writer() << tr("No incoming available transfers");
    }
    else
    {
      success_msg_writer() << tr("No incoming unavailable transfers");
    }
  }
  else
  {
    success_msg_writer() << boost::format("Found %u/%u transfers") % transfers_found % transfers.size();
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_payments(const std::vector<std::string> &args)
{
  if(args.empty())
  {
    PRINT_USAGE(USAGE_PAYMENTS);
    return true;
  }

  LOCK_IDLE_SCOPE();

  rdln::suspend_readline pause_readline;

  message_writer() << boost::format("%68s%68s%12s%21s%16s%16s") %
    tr("payment") % tr("transaction") % tr("height") % tr("amount") % tr("unlock time") % tr("addr index");

  bool payments_found = false;
  for(std::string arg : args)
  {
    crypto::hash payment_id;
    if(tools::wallet2::parse_payment_id(arg, payment_id))
    {
      std::list<tools::wallet2::payment_details> payments;
      m_wallet->get_payments(payment_id, payments);
      if(payments.empty())
      {
        success_msg_writer() << tr("No payments with id ") << payment_id;
        continue;
      }

      for (const tools::wallet2::payment_details& pd : payments)
      {
        if(!payments_found)
        {
          payments_found = true;
        }
        success_msg_writer(true) <<
          boost::format("%68s%68s%12s%21s%16s%16s") %
          payment_id %
          pd.m_tx_hash %
          pd.m_block_height %
          print_money(pd.m_amount) %
          pd.m_unlock_time %
          pd.m_subaddr_index.minor;
      }
    }
    else
    {
      fail_msg_writer() << tr("payment ID has invalid format, expected 16 or 64 character hex string: ") << arg;
    }
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
uint64_t simple_wallet::get_daemon_blockchain_height(std::string& err)
{
  if (!m_wallet)
  {
    throw std::runtime_error("simple_wallet null wallet");
  }
  return m_wallet->get_daemon_blockchain_height(err);
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_blockchain_height(const std::vector<std::string>& args)
{
  if (!try_connect_to_daemon())
    return true;

  std::string err;
  uint64_t bc_height = get_daemon_blockchain_height(err);
  if (err.empty())
    success_msg_writer() << bc_height;
  else
    fail_msg_writer() << tr("failed to get blockchain height: ") << err;
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::rescan_spent(const std::vector<std::string> &args)
{
  if (!m_wallet->is_trusted_daemon())
  {
    fail_msg_writer() << tr("this command requires a trusted daemon. Enable with --trusted-daemon");
    return true;
  }

  if (!try_connect_to_daemon())
    return true;

  try
  {
    LOCK_IDLE_SCOPE();
    m_wallet->rescan_spent();
  }
  catch (const tools::error::daemon_busy&)
  {
    fail_msg_writer() << tr("daemon is busy. Please try again later.");
  }
  catch (const tools::error::no_connection_to_daemon&)
  {
    fail_msg_writer() << tr("no connection to daemon. Please make sure daemon is running.");
  }
  catch (const tools::error::is_key_image_spent_error&)
  {
    fail_msg_writer() << tr("failed to get spent status");
  }
  catch (const tools::error::wallet_rpc_error& e)
  {
    LOG_ERROR("RPC error: " << e.to_string());
    fail_msg_writer() << tr("RPC error: ") << e.what();
  }
  catch (const std::exception& e)
  {
    LOG_ERROR("unexpected error: " << e.what());
    fail_msg_writer() << tr("unexpected error: ") << e.what();
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << tr("unknown error");
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
std::pair<std::string, std::string> simple_wallet::show_outputs_line(const std::vector<uint64_t> &heights, uint64_t blockchain_height, uint64_t highlight_idx) const
{
  std::stringstream ostr;

  for (uint64_t h: heights)
    blockchain_height = std::max(blockchain_height, h);

  for (size_t j = 0; j < heights.size(); ++j)
    ostr << (j == highlight_idx ? " *" : " ") << heights[j];

  // visualize the distribution, using the code by moneroexamples onion-monero-viewer
  const uint64_t resolution = 79;
  std::string ring_str(resolution, '_');
  for (size_t j = 0; j < heights.size(); ++j)
  {
    uint64_t pos = (heights[j] * resolution) / blockchain_height;
    ring_str[pos] = 'o';
  }
  if (highlight_idx < heights.size() && heights[highlight_idx] < blockchain_height)
  {
    uint64_t pos = (heights[highlight_idx] * resolution) / blockchain_height;
    ring_str[pos] = '*';
  }

  return std::make_pair(ostr.str(), ring_str);
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::process_ring_members(const std::vector<tools::wallet2::pending_tx>& ptx_vector, std::ostream& ostr, bool verbose)
{
  rpc::version_t version;
  if (!try_connect_to_daemon(false, &version))
  {
    fail_msg_writer() << tr("failed to connect to daemon");
    return false;
  }

  // available for RPC version 1.4 or higher
  if (version < rpc::version_t{1, 4})
    return true;

  std::string err;
  uint64_t blockchain_height = get_daemon_blockchain_height(err);
  if (!err.empty())
  {
    fail_msg_writer() << tr("failed to get blockchain height: ") << err;
    return false;
  }

  std::vector<rpc::GET_OUTPUTS_BIN::outkey> all_outs;
  {
    std::vector<rpc::get_outputs_out> outputs;
    for (const auto& ptx : ptx_vector)
      for (const auto& txin : ptx.tx.vin)
        if (auto* in_key = std::get_if<txin_to_key>(&txin))
          for (uint64_t index : cryptonote::relative_output_offsets_to_absolute(in_key->key_offsets))
            outputs.push_back({in_key->amount, index});

    all_outs.reserve(outputs.size());
    rpc::GET_OUTPUTS_BIN::request req{};
    req.get_txid = true;

    // Request MAX_COUNT outputs at a time (any more and we would fail when using a public RPC
    // server)
    for (auto it = outputs.begin(); it != outputs.end(); )
    {
      auto count = std::min<size_t>(std::distance(it, outputs.end()), rpc::GET_OUTPUTS_BIN::MAX_COUNT);
      req.outputs.clear();
      req.outputs.reserve(count);
      req.outputs.insert(req.outputs.end(), it, it + count);

      rpc::GET_OUTPUTS_BIN::response res{};
      bool r = m_wallet->invoke_http<rpc::GET_OUTPUTS_BIN>(req, res);

      err = interpret_rpc_response(r, res.status);
      if (!err.empty())
      {
        fail_msg_writer() << tr("failed to get output: ") << err;
        return false;
      }

      for (auto& out : res.outs)
        all_outs.push_back(std::move(out));

      it += count;
    }

    if (all_outs.size() != outputs.size())
    {
      fail_msg_writer() << tr("Failed to get output: ") << "wrong number of outputs returned (expected "
        << outputs.size() << " but got " << all_outs.size() << ")";
    }
  }

  auto out_it = all_outs.begin();

  // for each transaction
  for (size_t n = 0; n < ptx_vector.size(); ++n)
  {
    const cryptonote::transaction& tx = ptx_vector[n].tx;
    const wallet::tx_construction_data& construction_data = ptx_vector[n].construction_data;
    if (verbose)
      ostr << boost::format(tr("\nTransaction %llu/%llu: txid=%s")) % (n + 1) % ptx_vector.size() % cryptonote::get_transaction_hash(tx);
    // for each input
    std::vector<uint64_t>     spent_key_height(tx.vin.size());
    std::vector<crypto::hash> spent_key_txid  (tx.vin.size());
    for (size_t i = 0; i < tx.vin.size(); ++i)
    {
      if (!std::holds_alternative<cryptonote::txin_to_key>(tx.vin[i]))
        continue;
      const cryptonote::txin_to_key& in_key = var::get<cryptonote::txin_to_key>(tx.vin[i]);
      const wallet::transfer_details &td = m_wallet->get_transfer_details(construction_data.selected_transfers[i]);
      const cryptonote::tx_source_entry *sptr = NULL;
      for (const auto &src: construction_data.sources)
        if (src.outputs[src.real_output].second.dest == td.get_public_key())
          sptr = &src;
      if (!sptr)
      {
        fail_msg_writer() << tr("failed to find construction data for tx input");
        return false;
      }
      const cryptonote::tx_source_entry& source = *sptr;

      if (verbose)
        ostr << boost::format(tr("\nInput %llu/%llu (%s): amount=%s")) % (i + 1) % tx.vin.size() % tools::type_to_hex(in_key.k_image) % print_money(source.amount);

      // convert relative offsets of ring member keys into absolute offsets (indices) associated with the amount
      std::vector<uint64_t> absolute_offsets = cryptonote::relative_output_offsets_to_absolute(in_key.key_offsets);

      spent_key_height[i] = (out_it + source.real_output)->height;
      spent_key_txid  [i] = (out_it + source.real_output)->txid;

      auto out_begin = out_it;
      out_it += absolute_offsets.size();
      auto out_end = out_it;

      std::vector<uint64_t> heights;
      heights.reserve(absolute_offsets.size());
      // make sure that returned block heights are less than blockchain height
      for (auto it = out_begin; it != out_end; ++it)
      {
        if (it->height >= blockchain_height)
        {
          fail_msg_writer() << tr("output key's originating block height shouldn't be higher than the blockchain height");
          return false;
        }
        heights.push_back(it->height);
      }

      if (verbose)
        ostr << tr("\nOriginating block heights: ");
      std::pair<std::string, std::string> ring_str = show_outputs_line(heights, blockchain_height, source.real_output);
      if (verbose)
        ostr << ring_str.first << tr("\n|") << ring_str.second << tr("|\n");
    }
    // warn if rings contain keys originating from the same tx or temporally very close block heights
    bool are_keys_from_same_tx      = false;
    bool are_keys_from_close_height = false;
    for (size_t i = 0; i < tx.vin.size(); ++i) {
      for (size_t j = i + 1; j < tx.vin.size(); ++j)
      {
        if (spent_key_txid[i] == spent_key_txid[j])
          are_keys_from_same_tx = true;
        if (std::abs((int64_t)(spent_key_height[i] - spent_key_height[j])) < (int64_t)5)
          are_keys_from_close_height = true;
      }
    }
    if (are_keys_from_same_tx || are_keys_from_close_height)
    {
      ostr
        << tr("\nWarning: Some input keys being spent are from ")
        << (are_keys_from_same_tx ? tr("the same transaction") : tr("blocks that are temporally very close"))
        << tr(", which can break the anonymity of ring signatures. Make sure this is intentional!");
    }
    ostr << "\n";
  }
  return true;
}

//----------------------------------------------------------------------------------------------------
static bool locked_blocks_arg_valid(const std::string& arg, uint64_t& duration)
{
  try
  {
    duration = boost::lexical_cast<uint64_t>(arg);
  }
  catch (const std::exception &e)
  {
    return false;
  }

  if (duration > 1000000)
  {
    fail_msg_writer() << tr("Locked blocks too high, max 1000000 (~4 yrs)");
    return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
static bool parse_subaddr_indices_and_priority(tools::wallet2 &wallet, std::vector<std::string> &args, std::set<uint32_t> &subaddr_indices, uint32_t &priority, uint32_t subaddress_account, bool allow_parse_all_argument = false)
{
  if (args.size() > 0 && args[0].substr(0, 6) == "index=")
  {
    std::string parse_subaddr_err;
    if (allow_parse_all_argument && args[0] == "index=all")
    {
      for (uint32_t i = 0; i < wallet.get_num_subaddresses(subaddress_account); ++i)
        subaddr_indices.insert(i);
    }
    else if (!tools::parse_subaddress_indices(args[0], subaddr_indices, &parse_subaddr_err))
    {
      fail_msg_writer() << parse_subaddr_err;
      return false;
    }
    args.erase(args.begin());
  }

  if (args.size() > 0 && tools::parse_priority(args[0], priority))
    args.erase(args.begin());

  return true;
}
void simple_wallet::check_for_inactivity_lock(bool user)
{
  if (m_locked)
  {
    rdln::suspend_readline pause_readline;
    command_line::clear_screen();
    m_in_command = true;
    if (!user)
    {
        tools::msg_writer() << R"(
      ...........
    ...............
  ....OOOOOOOOOOO....   Your Oxen Wallet was locked to
 .......OOOOOOO.......  protect you while you were away.
 ..........O..........
 .......OOOOOOO.......  (Use `set inactivity-lock-timeout 0`
  ....OOOOOOOOOOO....   to disable this inactivity timeout)
    ...............
      ...........
)";
    }

    while (1)
    {
      const char *inactivity_msg = user ? "" : tr("Locked due to inactivity.");
      tools::msg_writer() << inactivity_msg << (inactivity_msg[0] ? " " : "") << tr("The wallet password is required to unlock the console.");
      try
      {
        if (get_and_verify_password())
          break;
      }
      catch (...) { /* do nothing, just let the loop loop */ }
    }
    m_last_activity_time = time(NULL);
    m_in_command = false;
    m_locked = false;
  }
}
//----------------------------------------------------------------------------------------------------
std::string eat_named_argument(std::vector<std::string> &args, std::string_view prefix)
{
  std::string result = {};
  for (auto it = args.begin(); it != args.end(); it++)
  {
    if (it->size() > prefix.size() && tools::starts_with(*it, prefix))
    {
      result = it->substr(prefix.size());
      args.erase(it);
      break;
    }
  }

  return result;
}
template <typename... Prefixes>
std::array<std::string, sizeof...(Prefixes)> eat_named_arguments(std::vector<std::string> &args, const Prefixes&... prefixes)
{
  return { eat_named_argument(args, prefixes)... };
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::confirm_and_send_tx(std::vector<cryptonote::address_parse_info> const &dests, std::vector<tools::wallet2::pending_tx> &ptx_vector, bool blink, uint64_t lock_time_in_blocks, uint64_t unlock_block ENABLE_IF_MMS(, bool called_by_mms))
{
  if (ptx_vector.empty())
    return false;

  // if more than one tx necessary, prompt user to confirm
  if (m_wallet->always_confirm_transfers() || ptx_vector.size() > 1)
  {
      uint64_t total_sent = 0;
      uint64_t total_fee = 0;
      uint64_t dust_not_in_fee = 0;
      uint64_t dust_in_fee = 0;
      uint64_t change = 0;
      for (size_t n = 0; n < ptx_vector.size(); ++n)
      {
        total_fee += ptx_vector[n].fee;
        for (auto i: ptx_vector[n].selected_transfers)
          total_sent += m_wallet->get_transfer_details(i).amount();
        total_sent -= ptx_vector[n].change_dts.amount + ptx_vector[n].fee;
        change += ptx_vector[n].change_dts.amount;

        if (ptx_vector[n].dust_added_to_fee)
          dust_in_fee += ptx_vector[n].dust;
        else
          dust_not_in_fee += ptx_vector[n].dust;
      }

      std::stringstream prompt;
      std::set<uint32_t> subaddr_indices;
      for (size_t n = 0; n < ptx_vector.size(); ++n)
      {
        prompt << tr("\nTransaction ") << (n + 1) << "/" << ptx_vector.size() << ":\n";
        subaddr_indices.clear();
        for (uint32_t i : ptx_vector[n].construction_data.subaddr_indices)
          subaddr_indices.insert(i);
        for (uint32_t i : subaddr_indices)
          prompt << boost::format(tr("Spending from address index %d\n")) % i;
        if (subaddr_indices.size() > 1)
          prompt << tr("WARNING: Outputs of multiple addresses are being used together, which might potentially compromise your privacy.\n");
      }
      prompt << boost::format(tr("Sending %s.  ")) % print_money(total_sent);
      if (ptx_vector.size() > 1)
      {
        prompt << boost::format(tr("Your transaction needs to be split into %llu transactions.  "
          "This will result in a transaction fee being applied to each transaction, for a total fee of %s")) %
          ((unsigned long long)ptx_vector.size()) % print_money(total_fee);
      }
      else
      {
        prompt << boost::format(tr("The transaction fee is %s")) %
          print_money(total_fee);
      }
      if (dust_in_fee != 0) prompt << boost::format(tr(", of which %s is dust from change")) % print_money(dust_in_fee);
      if (dust_not_in_fee != 0)  prompt << tr(".") << "\n" << boost::format(tr("A total of %s from dust change will be sent to dust address"))
                                                 % print_money(dust_not_in_fee);

      if (lock_time_in_blocks > 0)
      {
        double days = lock_time_in_blocks / (double) BLOCKS_PER_DAY;
        prompt << boost::format(tr(".\nThis transaction (including %s change) will unlock on block %llu, in approximately %s days (assuming 2 minutes per block)")) % cryptonote::print_money(change) % ((unsigned long long)unlock_block) % days;
      }

      if (!process_ring_members(ptx_vector, prompt, m_wallet->print_ring_members()))
        return false;

      bool default_ring_size = true;
      for (const auto &ptx: ptx_vector)
      {
        for (const auto &vin: ptx.tx.vin)
        {
          if (auto* in_to_key = std::get_if<txin_to_key>(&vin))
          {
            if (in_to_key->key_offsets.size() != cryptonote::TX_OUTPUT_DECOYS + 1)
              default_ring_size = false;
          }
        }
      }
      if (m_wallet->confirm_non_default_ring_size() && !default_ring_size)
      {
        prompt << tr("WARNING: this is a non default ring size, which may harm your privacy. Default is recommended.");
      }
      prompt << "\n\n" << tr("Is this okay?");

      std::string accepted = input_line(prompt.str(), true);
      if (std::cin.eof())
        return false;
      if (!command_line::is_yes(accepted))
      {
        fail_msg_writer() << tr("transaction cancelled.");

        return false;
      }
  }

  // actually commit the transactions
  if (m_wallet->multisig())
  {
#ifdef WALLET_ENABLE_MMS
    if (called_by_mms)
    {
      std::string ciphertext = m_wallet->save_multisig_tx(ptx_vector);
      if (!ciphertext.empty())
      {
        get_message_store().process_wallet_created_data(get_multisig_wallet_state(), mms::message_type::partially_signed_tx, ciphertext);
        success_msg_writer(true) << tr("Unsigned transaction(s) successfully written to MMS");
      }
    }
    else
#endif
    {
      bool r = m_wallet->save_multisig_tx(ptx_vector, "multisig_oxen_tx");
      if (!r)
      {
        fail_msg_writer() << tr("Failed to write transaction(s) to file");
        return false;
      }
      else
      {
        success_msg_writer(true) << tr("Unsigned transaction(s) successfully written to file: ") << "multisig_oxen_tx";
      }
    }
  }
  else if (m_wallet->get_account().get_device().has_tx_cold_sign())
  {
    try
    {
      tools::wallet2::signed_tx_set signed_tx;
      if (!cold_sign_tx(ptx_vector, signed_tx, dests, [&](const tools::wallet2::signed_tx_set &tx){ return accept_loaded_tx(tx); })){
        fail_msg_writer() << tr("Failed to cold sign transaction with HW wallet");
        return false;
      }

      commit_or_save(signed_tx.ptx, m_do_not_relay, blink);
    }
    catch (const std::exception& e)
    {
      handle_transfer_exception(std::current_exception(), m_wallet->is_trusted_daemon());
      return false;
    }
    catch (...)
    {
      LOG_ERROR("Unknown error");
      fail_msg_writer() << tr("unknown error");
      return false;
    }
  }
  else if (m_wallet->watch_only())
  {
    bool r = m_wallet->save_tx(ptx_vector, "unsigned_oxen_tx");
    if (!r)
    {
      fail_msg_writer() << tr("Failed to write transaction(s) to file");
      return false;
    }
    else
    {
      success_msg_writer(true) << tr("Unsigned transaction(s) successfully written to file: ") << "unsigned_oxen_tx";
    }
  }
  else
  {
    commit_or_save(ptx_vector, m_do_not_relay, blink);
  }

  return true;
}

//  "transfer [index=<N1>[,<N2>,...]] [<priority>] <address> <amount> [<payment_id>]"
bool simple_wallet::transfer_main(Transfer transfer_type, const std::vector<std::string> &args_ ENABLE_IF_MMS(, bool called_by_mms))
{
  if (!try_connect_to_daemon())
    return false;

  std::vector<std::string> local_args = args_;

  static constexpr auto BURN_PREFIX = "burn="sv;
  uint64_t burn_amount = 0;
  std::string burn_amount_str = eat_named_argument(local_args, BURN_PREFIX);
  if (!burn_amount_str.empty()) {
    if (auto b = cryptonote::parse_amount(burn_amount_str))
      burn_amount = *b;
    else {
      fail_msg_writer() << tr("Invalid amount");
      return true;
    }
  }

  uint32_t priority = 0;
  std::set<uint32_t> subaddr_indices  = {};
  if (!parse_subaddr_indices_and_priority(*m_wallet, local_args, subaddr_indices, priority, m_current_subaddress_account)) return false;

  if (priority == 0)
  {
    priority = m_wallet->get_default_priority();
    if (priority == 0)
      priority = transfer_type == Transfer::Locked ? tools::tx_priority_unimportant : tools::tx_priority_blink;
  }

  const size_t min_args = (transfer_type == Transfer::Locked) ? 2 : 1;
  if(local_args.size() < min_args)
  {
     fail_msg_writer() << tr("wrong number of arguments");
     return false;
  }


  std::vector<uint8_t> extra;
  if (!local_args.empty())
  {
    std::string payment_id_str = local_args.back();
    crypto::hash payment_id;
    if (tools::hex_to_type(payment_id_str, payment_id))
      return long_payment_id_failure(false);
  }

  uint64_t locked_blocks = 0;
  if (transfer_type == Transfer::Locked)
  {
    if (priority == tools::tx_priority_blink)
    {
      fail_msg_writer() << tr("blink priority cannot be used for locked transfers");
      return false;
    }

    if (!locked_blocks_arg_valid(local_args.back(), locked_blocks))
    {
      return true;
    }
    local_args.pop_back();
  }

  bool payment_id_seen = false;
  std::vector<cryptonote::address_parse_info> dsts_info;
  std::vector<cryptonote::tx_destination_entry> dsts;
  for (size_t i = 0; i < local_args.size(); )
  {
    dsts_info.emplace_back();
    cryptonote::address_parse_info& info = dsts_info.back();
    cryptonote::tx_destination_entry de;
    bool r = true;

    std::string addr, payment_id_uri, tx_description, recipient_name, error;
    std::vector<std::string> unknown_parameters;
    uint64_t amount = 0;
    bool has_uri = m_wallet->parse_uri(local_args[i], addr, payment_id_uri, amount, tx_description, recipient_name, unknown_parameters, error);

    if (i + 1 < local_args.size())
    {
      r = cryptonote::get_account_address_from_str(info, m_wallet->nettype(), local_args[i]);
      if (!r && m_wallet->is_trusted_daemon())
      {
        std::optional<std::string> address = m_wallet->resolve_address(local_args[i]);
        if (address)
          r = cryptonote::get_account_address_from_str(info, m_wallet->nettype(), *address);
      }
      if(!r)
      {
        fail_msg_writer() << tr("Could not resolve address");
        return false;
      }

      if (auto a = cryptonote::parse_amount(local_args[i + 1]); a && *a > 0)
        de.amount = *a;
      else
      {
        fail_msg_writer() << tr("amount is wrong: ") << local_args[i] << ' ' << local_args[i + 1] <<
          ", " << tr("expected number from 0 to ") << print_money(std::numeric_limits<uint64_t>::max());
        return false;
      }
      de.original = local_args[i];
      i += 2;
    }
    else
    {
      if (boost::starts_with(local_args[i], "oxen:"))
        fail_msg_writer() << tr("Invalid last argument: ") << local_args.back() << ": " << error;
      else
        fail_msg_writer() << tr("Invalid last argument: ") << local_args.back();
      return false;
    }


    de.addr = info.address;
    de.is_subaddress = info.is_subaddress;
    de.is_integrated = info.has_payment_id;

    if (info.has_payment_id || !payment_id_uri.empty())
    {
      if (payment_id_seen)
      {
        fail_msg_writer() << tr("a single transaction cannot use more than one payment id/integrated address");
        return false;
      }

      crypto::hash payment_id;
      std::string extra_nonce;
      if (info.has_payment_id)
      {
        set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, info.payment_id);
      }
      else if (tools::wallet2::parse_payment_id(payment_id_uri, payment_id))
      {
        return long_payment_id_failure(false);
      }
      else
      {
        fail_msg_writer() << tr("failed to parse payment id, though it was detected");
        return false;
      }
      bool r = add_extra_nonce_to_tx_extra(extra, extra_nonce);
      if(!r)
      {
        fail_msg_writer() << tr("failed to set up payment id, though it was decoded correctly");
        return false;
      }
      payment_id_seen = true;
    }

    dsts.push_back(de);
  }

  SCOPED_WALLET_UNLOCK_ON_BAD_PASSWORD(return false;);

  try
  {
    // figure out what tx will be necessary
    std::vector<tools::wallet2::pending_tx> ptx_vector;
    uint64_t bc_height, unlock_block = 0;
    std::string err;
    if (transfer_type == Transfer::Locked)
    {
      bc_height = get_daemon_blockchain_height(err);
      if (!err.empty())
      {
        fail_msg_writer() << tr("failed to get blockchain height: ") << err;
        return false;
      }
      unlock_block = bc_height + locked_blocks;
    }

    auto hf_version = m_wallet->get_hard_fork_version();
    if (!hf_version)
    {
      fail_msg_writer() << tools::wallet2::ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
      return false;
    }


    oxen_construct_tx_params tx_params = tools::wallet2::construct_params(*hf_version, txtype::standard, priority, burn_amount);
    ptx_vector = m_wallet->create_transactions_2(dsts, cryptonote::TX_OUTPUT_DECOYS, unlock_block, priority, extra, m_current_subaddress_account, subaddr_indices, tx_params);

    if (ptx_vector.empty())
    {
      fail_msg_writer() << tr("No outputs found, or daemon is not ready");
      return false;
    }

    if (!confirm_and_send_tx(dsts_info, ptx_vector, priority == tools::tx_priority_blink, locked_blocks, unlock_block ENABLE_IF_MMS(, called_by_mms)))
      return false;
  }
  catch (const std::exception &e)
  {
    handle_transfer_exception(std::current_exception(), m_wallet->is_trusted_daemon());
    return false;
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << tr("unknown error");
    return false;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::transfer(const std::vector<std::string> &args_)
{

  return transfer_main(Transfer::Normal, args_ ENABLE_IF_MMS(, false));
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::locked_transfer(const std::vector<std::string> &args_)
{
  return transfer_main(Transfer::Locked, args_ ENABLE_IF_MMS(, false));
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::locked_sweep_all(const std::vector<std::string> &args_)
{
  return sweep_main(m_current_subaddress_account, 0, Transfer::Locked, args_);
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::register_service_node(const std::vector<std::string> &args_)
{
  if (!try_connect_to_daemon())
    return true;

  SCOPED_WALLET_UNLOCK()
  tools::wallet2::register_service_node_result result = m_wallet->create_register_service_node_tx(args_, m_current_subaddress_account);
  if (result.status != tools::wallet2::register_service_node_result_status::success)
  {
    fail_msg_writer() << result.msg;
    if (result.status == tools::wallet2::register_service_node_result_status::insufficient_num_args ||
        result.status == tools::wallet2::register_service_node_result_status::service_node_key_parse_fail ||
        result.status == tools::wallet2::register_service_node_result_status::service_node_signature_parse_fail ||
        result.status == tools::wallet2::register_service_node_result_status::subaddr_indices_parse_fail ||
        result.status == tools::wallet2::register_service_node_result_status::convert_registration_args_failed)
    {
      fail_msg_writer() << USAGE_REGISTER_SERVICE_NODE;
    }
    return true;
  }

  address_parse_info info = {};
  info.address            = m_wallet->get_address();
  try
  {
    std::vector<tools::wallet2::pending_tx> ptx_vector = {result.ptx};
    if (!sweep_main_internal(sweep_type_t::register_stake, ptx_vector, info, false /* don't blink */))
    {
      fail_msg_writer() << tr("Sending register transaction failed");
      return true;
    }
  }
  catch (const std::exception& e)
  {
    handle_transfer_exception(std::current_exception(), m_wallet->is_trusted_daemon());
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << tr("unknown error");
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::stake(const std::vector<std::string> &args_)
{
  if (!try_connect_to_daemon())
    return true;

  //
  // Parse Arguments from Args
  //
  crypto::public_key service_node_key = {};
  uint32_t priority = 0;
  std::set<uint32_t> subaddr_indices = {};
  uint64_t amount = 0;
  double amount_fraction = 0;
  {
    std::vector<std::string> local_args = args_;
    uint32_t priority                   = 0;
    std::set<uint32_t> subaddr_indices  = {};
    if (!parse_subaddr_indices_and_priority(*m_wallet, local_args, subaddr_indices, priority, m_current_subaddress_account))
      return false;

    if (local_args.size() < 2)
    {
      fail_msg_writer() << tr(USAGE_STAKE);
      return true;
    }

    if (!tools::hex_to_type(local_args[0], service_node_key))
    {
      fail_msg_writer() << tr("failed to parse service node pubkey");
      return true;
    }

    if (local_args[1].back() == '%')
    {
      local_args[1].pop_back();
      amount = 0;
      try
      {
        amount_fraction = boost::lexical_cast<double>(local_args[1]) / 100.0;
      }
      catch (const std::exception &e)
      {
        fail_msg_writer() << tr("Invalid percentage");
        return true;
      }
      if (amount_fraction < 0 || amount_fraction > 1)
      {
        fail_msg_writer() << tr("Invalid percentage");
        return true;
      }
    }
    else
    {
      if (auto a = cryptonote::parse_amount(local_args[1]); a && *a > 0)
        amount = *a;
      else
      {
        fail_msg_writer() << tr("amount is wrong: ") << local_args[1] <<
          ", " << tr("expected number from ") << print_money(1) << " to " << print_money(std::numeric_limits<uint64_t>::max());
        return true;
      }
    }
  }

  //
  // Try Staking
  //
  SCOPED_WALLET_UNLOCK()
  {
    m_wallet->refresh(false);
    try
    {

      time_t begin_construct_time = time(nullptr);

      tools::wallet2::stake_result stake_result = m_wallet->create_stake_tx(service_node_key, amount, amount_fraction, priority, subaddr_indices);
      if (stake_result.status != tools::wallet2::stake_result_status::success)
      {
        fail_msg_writer() << stake_result.msg;
        return true;
      }

      if (!stake_result.msg.empty()) // i.e. warnings
        tools::msg_writer() << stake_result.msg;

      std::vector<tools::wallet2::pending_tx> ptx_vector = {stake_result.ptx};
      cryptonote::address_parse_info info = {};
      info.address = m_wallet->get_address();
      if (!sweep_main_internal(sweep_type_t::stake, ptx_vector, info, false /* don't blink */))
      {
        fail_msg_writer() << tr("Sending stake transaction failed");
        return true;
      }

      time_t end_construct_time = time(nullptr);
      time_t construct_time     = end_construct_time - begin_construct_time;
      if (construct_time > (60 * 10))
      {
        fail_msg_writer() << tr("Staking command has timed out due to waiting longer than 10 mins. This prevents the staking transaction from becoming invalid due to blocks mined interim. Please try again");
        return true;
      }
    }
    catch (const std::exception& e)
    {
      handle_transfer_exception(std::current_exception(), m_wallet->is_trusted_daemon());
    }
    catch (...)
    {
      LOG_ERROR("unknown error");
      fail_msg_writer() << tr("unknown error");
    }
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::request_stake_unlock(const std::vector<std::string> &args_)
{
  if (!try_connect_to_daemon())
    return true;

  if (args_.size() != 1)
  {
    fail_msg_writer() << tr(USAGE_REQUEST_STAKE_UNLOCK);
    return true;
  }

  crypto::public_key snode_key;
  if (!tools::hex_to_type(args_[0], snode_key))
  {
    fail_msg_writer() << tr("failed to parse service node pubkey: ") << args_[0];
    return true;
  }

  SCOPED_WALLET_UNLOCK();
  tools::wallet2::request_stake_unlock_result unlock_result = m_wallet->can_request_stake_unlock(snode_key);
  if (unlock_result.success)
  {
    tools::msg_writer() << unlock_result.msg;
  }
  else
  {
    fail_msg_writer() << unlock_result.msg;
    return true;
  }

  if (!command_line::is_yes(input_line("Is this okay?", true)))
    return true;

  // TODO(doyle): INF_STAKING(doyle): Do we support staking in these modes?
  if (m_wallet->multisig())
  {
    fail_msg_writer() << tr("Multi sig request stake unlock is unsupported");
    return true;
  }

  std::vector<tools::wallet2::pending_tx> ptx_vector = {unlock_result.ptx};
  if (m_wallet->watch_only())
  {
    if (m_wallet->save_tx(ptx_vector, "unsigned_oxen_tx"))
      success_msg_writer(true) << tr("Unsigned transaction(s) successfully written to file: ") << "unsigned_oxen_tx";
    else
      fail_msg_writer() << tr("Failed to write transaction(s) to file");

    return true;
  }

  try
  {
    commit_or_save(ptx_vector, m_do_not_relay, false /* don't blink */);
  }
  catch (const std::exception &e)
  {
    handle_transfer_exception(std::current_exception(), m_wallet->is_trusted_daemon());
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << tr("unknown error");
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::query_locked_stakes(bool print_details, bool print_key_images)
{
  if (!try_connect_to_daemon())
    return false;

  bool has_locked_stakes = false;
  std::string msg;
  auto my_addr = m_wallet->get_address_as_str();

  auto sum_contr = [](const auto& locked) {
    uint64_t total = 0;
    for (auto& c : locked)
      total += c.amount;
    return total;
  };

  auto sns = m_wallet->get_staked_service_nodes();

  // Sort the list by pubkey, and partition into unlocking and not-unlocking:
  std::stable_sort(sns.begin(), sns.end(), [](const auto& a, const auto& b) {
    return a.service_node_pubkey < b.service_node_pubkey; });
  std::stable_partition(sns.begin(), sns.end(), [](const auto& a) {
    return a.requested_unlock_height != service_nodes::KEY_IMAGE_AWAITING_UNLOCK_HEIGHT; });

  for (auto& node_info : sns)
  {
    auto& contributors = node_info.contributors;
    // Filter out any contributor rows without any actual contributions (i.e. from unfilled reserved
    // contributions):
    contributors.erase(
        std::remove_if(contributors.begin(), contributors.end(),
          [&sum_contr](const auto& c) { return sum_contr(c.locked_contributions) == 0; }),
        contributors.end());

    // Reorder contributors to put this wallet's contribution(s) first:
    std::stable_partition(contributors.begin(), contributors.end(),
        [&my_addr](const auto& x) { return x.address == my_addr; });

    if (contributors.empty() || contributors[0].address != my_addr)
      continue; // We filtered out ourself
    auto& me = contributors.front();

    has_locked_stakes = true;
    if (!print_details)
      continue;

    uint64_t total = 0;
    for (const auto& c : contributors)
      total += sum_contr(c.locked_contributions);

    // Formatting: first 1-2 lines of general info:
    //
    //     Service Node: abcdef123456...
    //     Unlock Height: 1234567         (omitted if not unlocking)
    //
    // If there are other contributors then we print a total line such as:
    //
    //     Total Contributions: 15000 OXEN of 15000 OXEN required
    //
    // For our own contribution, when we have a single contribution, we use one of:
    //
    //     Your Contribution: 5000 OXEN (Key image: abcdef123...)
    //     Your Contribution: 5000 OXEN of 15000 OXEN required (Key image: abcdef123...)
    //
    // (the second one applies if we are the only contributor so far).
    //
    // If we made multiple contributions then:
    //
    //     Your Contributions: 5000 OXEN in 2 contributions:
    //     Your Contributions: 5000 OXEN of 15000 OXEN required in 2 contributions:
    //
    // (the second one if we are the only contributor so far).
    //
    // This is followed by the individual contributions:
    //
    //         ‣ 4000.5 OXEN (Key image: abcdef123...)
    //         ‣ 999.5 OXEN (Key image: 789cba456...)
    //
    // If there are other contributors then we also print:
    //
    //     Other contributions: 10000 OXEN from 2 contributors:
    //         • 1234.565 OXEN (T6U7YGUcPJffbaF5p8NLC3VidwJyHSdMaGmSxTBV645v33CmLq2ZvMqBdY9AVB2z8uhbHPCZSuZbv68hE6NBXBc51Gg9MGUGr)
    //           Key image 123456789...
    //         • 8765.435 OXEN (T6Tpop5RZdwE39iBvoP5xpJVoMpYPUwQpef9zS2tLL8yVgbppBbtGnzZxzkSp53Coi88wbsTHiokr7k8MQU94mGF1zzERqELK)
    //           ‣ 7530 OXEN (Key image: 23456789a...)
    //           ‣ 1235.435 OXEN (Key image: 3456789ab...)
    //
    // If we aren't showing key images then all the key image details get omitted.

    msg += fmt::format("Service Node: {}\n", node_info.service_node_pubkey);
    if (node_info.requested_unlock_height != service_nodes::KEY_IMAGE_AWAITING_UNLOCK_HEIGHT)
      msg += fmt::format("Unlock height: {}\n", node_info.requested_unlock_height);

    bool just_me = contributors.size() == 1;

    auto required = fmt::format(" of {} required", cryptonote::format_money(node_info.staking_requirement));
    if (!just_me) {
      msg += fmt::format("Total Contributions: {}{}\n", cryptonote::format_money(total), required);
      required.clear();
    }

    auto my_total = sum_contr(me.locked_contributions);
    if (me.locked_contributions.size() == 1)
      msg += "Your Contribution: ";
    else
    {
      msg += fmt::format("Your Contributions: {}{} in {} contributions:\n    ‣ ",
          cryptonote::format_money(my_total),
          required,
          me.locked_contributions.size());
      required.clear();
    }

    for (size_t i = 0; i < me.locked_contributions.size(); i++)
    {
      auto& c = me.locked_contributions[i];
      if (i > 0) msg += "    ‣ ";
      msg += cryptonote::format_money(c.amount);
      if (!required.empty())
      {
        msg += required;
        required.clear();
      }
      if (print_key_images)
        msg += fmt::format(" (Key image: {})", c.key_image);
      msg += '\n';
    }

    if (contributors.size() > 1)
    {
      msg += fmt::format("Other Contributions: {} from {} contributor{}:\n",
          cryptonote::format_money(total - my_total),
          contributors.size() - 1,
          contributors.size() == 2 ? "" : "s");
      for (size_t i = 1; i < contributors.size(); i++)
      {
        const auto& contributor = contributors[i];
        const auto& locked = contributor.locked_contributions;
        msg += fmt::format("    • {} ({})\n",
            cryptonote::format_money(sum_contr(locked)), contributor.address);
        if (locked.size() == 1)
        {
          if (print_key_images)
            msg += fmt::format("      Key image: {}\n", locked[0].key_image);
        }
        else
        {
          for (auto& c : locked)
          {
            msg += "      ‣ ";
            msg += cryptonote::format_money(c.amount);
            if (print_key_images)
              msg += fmt::format(" (Key image: {})\n", c.key_image);
            else
              msg += '\n';
          }
        }
      }
    }
    msg += "\n";
  }

  // Find blacklisted key images (i.e. locked contributions from deregistered SNs) that belong to
  // this wallet.  If there are any, output will be:
  //
  //     Locked Stakes due to Service Node Deregistration:
  //         ‣ 234.567 OXEN (Unlock height 1234567; Key image: abcfed999...)
  //         ‣ 5000 OXEN (Unlock height 123333; Key image: cbcfef989...)
  //
  // where the "; Key image: ..." part is omitted if not printing key images.

  auto [success, blacklisted] = m_wallet->get_service_node_blacklisted_key_images();
  if (!success)
  {
    fail_msg_writer() << "Connection to daemon failed when retrieving blacklisted key images";
    return has_locked_stakes;
  }

  // Filter out key images that aren't ours:
  blacklisted.erase(std::remove_if(blacklisted.begin(), blacklisted.end(),
      [this](const auto& black) {
        if (crypto::key_image ki; tools::hex_to_type(black.key_image, ki))
          return !m_wallet->contains_key_image(ki);
        fail_msg_writer() << "Failed to parse key image hex: " << black.key_image;
        return true;
      }),
      blacklisted.end());

  if (!blacklisted.empty())
  {
    has_locked_stakes = true;
    if (print_details)
    {
      msg += "Locked Stakes due to Service Node Deregistration:\n";

      // Sort by unlock time (earliest first):
      std::stable_sort(blacklisted.begin(), blacklisted.end(),
          [](const auto& a, const auto& b) { return a.unlock_height < b.unlock_height; });

      for (const auto& black : blacklisted)
      {
        msg += fmt::format("    • {} (Unlock height {}", cryptonote::format_money(black.amount), black.unlock_height);
        if (print_key_images)
          msg += fmt::format("; Key image: {})\n", black.key_image);
        else
          msg += ")\n";
      }
    }
  }

  if (msg.empty() && print_details)
    msg = "No locked stakes known for this wallet on the network";
  if (!msg.empty())
    tools::msg_writer() << msg;

  return has_locked_stakes;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::print_locked_stakes(const std::vector<std::string>& args)
{
  SCOPED_WALLET_UNLOCK();
  bool print_kis = std::find(args.begin(), args.end(), "+key_images") != args.end();
  query_locked_stakes(/*print_details=*/ true, print_kis);
  return true;
}

// Parse a user-provided typestring value; if not provided, guess from the provided name and value.
static std::optional<ons::mapping_type> guess_ons_type(tools::wallet2& wallet, std::string_view typestr, std::string_view name, std::string_view value)
{
  if (typestr.empty())
  {
    if (tools::ends_with(name, ".loki") && (tools::ends_with(value, ".loki") || value.empty()))
      return ons::mapping_type::lokinet;
    if (!tools::ends_with(name, ".loki") && tools::starts_with(value, "05") && value.length() == 2*ons::SESSION_PUBLIC_KEY_BINARY_LENGTH)
      return ons::mapping_type::session;
    if (cryptonote::is_valid_address(std::string{value}, wallet.nettype()))
      return ons::mapping_type::wallet;

    fail_msg_writer() << tr("Could not infer ONS type from name/value; trying using the type= argument or see `help' for more details");
    return std::nullopt;
  }

  auto hf_version = wallet.get_hard_fork_version();
  if (!hf_version)
  {
    tools::fail_msg_writer() << tools::wallet2::ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
    return std::nullopt;
  }

  std::string reason;
  if (ons::mapping_type type; ons::validate_mapping_type(typestr, *hf_version, ons::ons_tx_type::buy, &type, &reason))
    return type;

  fail_msg_writer() << reason;
  return std::nullopt;
}

//----------------------------------------------------------------------------------------------------
static constexpr auto ONS_OWNER_PREFIX        = "owner="sv;
static constexpr auto ONS_BACKUP_OWNER_PREFIX = "backup_owner="sv;
static constexpr auto ONS_TYPE_PREFIX         = "type="sv;
static constexpr auto ONS_VALUE_PREFIX        = "value="sv;
static constexpr auto ONS_SIGNATURE_PREFIX    = "signature="sv;

static char constexpr NULL_STR[] = "(none)";

bool simple_wallet::ons_buy_mapping(std::vector<std::string> args)
{
  uint32_t priority = 0;
  std::set<uint32_t> subaddr_indices  = {};
  if (!parse_subaddr_indices_and_priority(*m_wallet, args, subaddr_indices, priority, m_current_subaddress_account)) return false;

  auto [owner, backup_owner, typestr] = eat_named_arguments(args, ONS_OWNER_PREFIX, ONS_BACKUP_OWNER_PREFIX, ONS_TYPE_PREFIX);

  if (args.size() != 2)
  {
    PRINT_USAGE(USAGE_ONS_BUY_MAPPING);
    return true;
  }

  std::string const &name  = args[0];
  std::string const &value = args[1];

  std::optional<ons::mapping_type> type = guess_ons_type(*m_wallet, typestr, name, value);
  if (!type) return false;

  SCOPED_WALLET_UNLOCK();
  std::string reason;
  std::vector<tools::wallet2::pending_tx> ptx_vector;

  try
  {
    ptx_vector = m_wallet->ons_create_buy_mapping_tx(*type,
                                                     owner.size() ? &owner : nullptr,
                                                     backup_owner.size() ? &backup_owner : nullptr,
                                                     name,
                                                     value,
                                                     &reason,
                                                     priority,
                                                     m_current_subaddress_account,
                                                     subaddr_indices);

    if (ptx_vector.empty())
    {
      tools::fail_msg_writer() << reason;
      return true;
    }

    std::vector<cryptonote::address_parse_info> dsts;
    cryptonote::address_parse_info info = {};
    info.address                        = m_wallet->get_subaddress({m_current_subaddress_account, 0});
    info.is_subaddress                  = m_current_subaddress_account != 0;
    dsts.push_back(info);

    std::cout << std::endl << tr("Buying Oxen Name System Record") << std::endl << std::endl;
    if (*type == ons::mapping_type::session)
      std::cout << boost::format(tr("Session Name: %s")) % name << std::endl;
    else if (*type == ons::mapping_type::wallet)
      std::cout << boost::format(tr("Wallet Name:  %s")) % name << std::endl;
    else if (ons::is_lokinet_type(*type))
    {
      std::cout << boost::format(tr("Lokinet Name: %s")) % name << std::endl;
      int years =
          *type == ons::mapping_type::lokinet_10years ? 10 :
          *type == ons::mapping_type::lokinet_5years ? 5 :
          *type == ons::mapping_type::lokinet_2years ? 2 :
          1;
      int blocks = years * ons::REGISTRATION_YEAR_DAYS * BLOCKS_PER_DAY;
      std::cout << boost::format(tr("Registration: %d years (%d blocks)")) % years % blocks << "\n";
    }
    else
      std::cout << boost::format(tr("Name:         %s")) % name << std::endl;
    std::cout << boost::format(tr("Value:        %s")) % value << std::endl;
    std::cout << boost::format(tr("Owner:        %s")) % (owner.size() ? owner : m_wallet->get_subaddress_as_str({m_current_subaddress_account, 0}) + " (this wallet) ") << std::endl;
    if(backup_owner.size()) {
      std::cout << boost::format(tr("Backup Owner: %s")) % backup_owner << std::endl;
    } else {
      std::cout << tr("Backup Owner: (none)") << std::endl;
    }

    if (!confirm_and_send_tx(dsts, ptx_vector, priority == tools::tx_priority_blink))
      return false;


    //Save the ONS record to the wallet cache
    std::string name_hash_str = ons::name_to_base64_hash(name);
    tools::wallet2::ons_detail detail = {
      *type,
      name,
      name_hash_str};
    m_wallet->set_ons_cache_record(detail);
  }
  catch (const std::exception &e)
  {
    handle_transfer_exception(std::current_exception(), m_wallet->is_trusted_daemon());
    return true;
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << tr("unknown error");
    return true;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::ons_renew_mapping(std::vector<std::string> args)
{
  uint32_t priority = 0;
  std::set<uint32_t> subaddr_indices  = {};
  if (!parse_subaddr_indices_and_priority(*m_wallet, args, subaddr_indices, priority, m_current_subaddress_account)) return false;

  std::string typestr = eat_named_argument(args, ONS_TYPE_PREFIX);
  if (args.empty())
  {
    PRINT_USAGE(USAGE_ONS_RENEW_MAPPING);
    return false;
  }
  std::string const &name = args[0];

  ons::mapping_type type;
  if (auto t = guess_ons_type(*m_wallet, typestr, name, ""))
    type = *t;
  else return false;

  SCOPED_WALLET_UNLOCK();
  std::string reason;
  std::vector<tools::wallet2::pending_tx> ptx_vector;
  std::vector<cryptonote::rpc::ONS_NAMES_TO_OWNERS::response_entry> response;
  try
  {
    ptx_vector = m_wallet->ons_create_renewal_tx(
        type,
        name,
        &reason,
        priority,
        m_current_subaddress_account,
        subaddr_indices,
        &response);
    if (ptx_vector.empty())
    {
      tools::fail_msg_writer() << reason;
      return true;
    }

    std::vector<cryptonote::address_parse_info> dsts;
    cryptonote::address_parse_info info = {};
    info.address                        = m_wallet->get_subaddress({m_current_subaddress_account, 0});
    info.is_subaddress                  = m_current_subaddress_account != 0;
    dsts.push_back(info);

    std::cout << "\n" << tr("Renew Oxen Name System Record") << "\n\n";
    if (ons::is_lokinet_type(type))
      std::cout << boost::format(tr("Lokinet Name:  %s")) % name << "\n";
    else
      std::cout << boost::format(tr("Name:          %s")) % name << "\n";

    int years = 1;
    if (type == ons::mapping_type::lokinet_2years) years = 2;
    else if (type == ons::mapping_type::lokinet_5years) years = 5;
    else if (type == ons::mapping_type::lokinet_10years) years = 10;
    int blocks = years * ons::REGISTRATION_YEAR_DAYS * BLOCKS_PER_DAY;
    std::cout << boost::format(tr("Renewal years: %d (%d blocks)")) % years % blocks << "\n";
    std::cout << boost::format(tr("New expiry:    Block %d")) % (*response[0].expiration_height + blocks) << "\n";
    std::cout << std::flush;

    if (!confirm_and_send_tx(dsts, ptx_vector, false /*blink*/))
      return false;

  }
  catch (const std::exception &e)
  {
    handle_transfer_exception(std::current_exception(), m_wallet->is_trusted_daemon());
    return true;
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << tr("unknown error");
    return true;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::ons_update_mapping(std::vector<std::string> args)
{
  uint32_t priority = 0;
  std::set<uint32_t> subaddr_indices  = {};
  if (!parse_subaddr_indices_and_priority(*m_wallet, args, subaddr_indices, priority, m_current_subaddress_account)) return false;


  auto [owner, backup_owner, value, signature, typestr] =
    eat_named_arguments(args, ONS_OWNER_PREFIX, ONS_BACKUP_OWNER_PREFIX, ONS_VALUE_PREFIX, ONS_SIGNATURE_PREFIX, ONS_TYPE_PREFIX);

  if (args.empty())
  {
    PRINT_USAGE(USAGE_ONS_UPDATE_MAPPING);
    return false;
  }
  std::string const &name = args[0];

  ons::mapping_type type;
  if (auto t = guess_ons_type(*m_wallet, typestr, name, value))
    type = *t;
  else return false;

  SCOPED_WALLET_UNLOCK();
  std::string reason;
  std::vector<tools::wallet2::pending_tx> ptx_vector;
  std::vector<cryptonote::rpc::ONS_NAMES_TO_OWNERS::response_entry> response;
  try
  {
    ptx_vector = m_wallet->ons_create_update_mapping_tx(type,
                                                        name,
                                                        value.size() ? &value : nullptr,
                                                        owner.size() ? &owner : nullptr,
                                                        backup_owner.size() ? &backup_owner : nullptr,
                                                        signature.size() ? &signature : nullptr,
                                                        &reason,
                                                        priority,
                                                        m_current_subaddress_account,
                                                        subaddr_indices,
                                                        &response);
    if (ptx_vector.empty())
    {
      tools::fail_msg_writer() << reason;
      return true;
    }

    auto& enc_hex = response[0].encrypted_value;
    if (!oxenc::is_hex(enc_hex) || enc_hex.size() > 2*ons::mapping_value::BUFFER_SIZE)
    {
      LOG_ERROR("invalid ONS data returned from oxend");
      fail_msg_writer() << tr("invalid ONS data returned from oxend");
      return true;
    }

    ons::mapping_value mval{};
    mval.len = enc_hex.size() / 2;
    mval.encrypted = true;
    oxenc::from_hex(enc_hex.begin(), enc_hex.end(), mval.buffer.begin());

    if (!mval.decrypt(tools::lowercase_ascii_string(name), type))
    {
      fail_msg_writer() << "Failed to decrypt the mapping value=" << enc_hex;
      return false;
    }

    std::vector<cryptonote::address_parse_info> dsts;
    cryptonote::address_parse_info info = {};
    info.address                        = m_wallet->get_subaddress({m_current_subaddress_account, 0});
    info.is_subaddress                  = m_current_subaddress_account != 0;
    dsts.push_back(info);

    std::cout << std::endl << tr("Updating Oxen Name System Record") << std::endl << std::endl;
    if (type == ons::mapping_type::session)
      std::cout << boost::format(tr("Session Name:     %s")) % name << std::endl;
    else if (ons::is_lokinet_type(type))
      std::cout << boost::format(tr("Lokinet Name:     %s")) % name << std::endl;
    else if (type == ons::mapping_type::wallet)
      std::cout << boost::format(tr("Wallet Name:     %s")) % name << std::endl;
    else
      std::cout << boost::format(tr("Name:             %s")) % name << std::endl;

    if(value.size()) {
      std::cout << boost::format(tr("Old Value:        %s")) % mval.to_readable_value(m_wallet->nettype(), type) << std::endl;
      std::cout << boost::format(tr("New Value:        %s")) % value << std::endl;
    } else {
      std::cout << boost::format(tr("Value:            %s (unchanged)")) % mval.to_readable_value(m_wallet->nettype(), type) << std::endl;
    }

    if(owner.size()) {
      std::cout << boost::format(tr("Old Owner:        %s")) % response[0].owner << std::endl;
      std::cout << boost::format(tr("New Owner:        %s")) % owner << std::endl;
    } else {
      std::cout << boost::format(tr("Owner:            %s (unchanged)")) % response[0].owner << std::endl;
    }

    if(backup_owner.size()) {
      std::cout << boost::format(tr("Old Backup Owner: %s")) % response[0].backup_owner.value_or(NULL_STR) << std::endl;
      std::cout << boost::format(tr("New Backup Owner: %s")) % backup_owner << std::endl;
    } else {
      std::cout << boost::format(tr("Backup Owner:     %s (unchanged)")) % response[0].backup_owner.value_or(NULL_STR) << std::endl;
    }
    if (!confirm_and_send_tx(dsts, ptx_vector, false /*blink*/))
      return false;

    // Save the updated ONS record to the wallet cache
    std::string name_hash_str = ons::name_to_base64_hash(name);
    m_wallet->delete_ons_cache_record(name_hash_str);
    tools::wallet2::ons_detail detail = {
      type,
      name,
      name_hash_str};
    m_wallet->set_ons_cache_record(detail);

  }
  catch (const std::exception &e)
  {
    handle_transfer_exception(std::current_exception(), m_wallet->is_trusted_daemon());
    return true;
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << tr("unknown error");
    return true;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::ons_encrypt(std::vector<std::string> args)
{
  std::string typestr = eat_named_argument(args, ONS_TYPE_PREFIX);

  if (args.size() != 2)
  {
    PRINT_USAGE(USAGE_ONS_ENCRYPT);
    return false;
  }
  const auto& name = args[0];
  const auto& value = args[1];

  ons::mapping_type type;
  if (auto t = guess_ons_type(*m_wallet, typestr, name, value))
    type = *t;
  else return false;

  if (value.size() > ons::mapping_value::BUFFER_SIZE)
  {
    fail_msg_writer() << "ONS value '" << value << "' is too long";
    return false;
  }

  auto hf_version = m_wallet->get_hard_fork_version();
  if (!hf_version)
  {
    tools::fail_msg_writer() << tools::wallet2::ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
    return false;
  }

  std::string reason;
  if (!ons::validate_ons_name(type, name, &reason))
  {
    tools::fail_msg_writer() << "Invalid ONS name '" << name << "': " << reason;
    return false;
  }

  ons::mapping_value mval;
  if (!ons::mapping_value::validate(m_wallet->nettype(), type, value, &mval, &reason))
  {
    tools::fail_msg_writer() << "Invalid ONS value '" << value << "': " << reason;
    return false;
  }

  bool old_argon2 = type == ons::mapping_type::session && hf_version < hf::hf16_pulse;
  if (!mval.encrypt(name, nullptr, old_argon2))
  {
    tools::fail_msg_writer() << "Value encryption failed";
    return false;
  }

  tools::success_msg_writer() << "encrypted value=" << oxenc::to_hex(mval.to_view());
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::ons_make_update_mapping_signature(std::vector<std::string> args)
{
  if (!try_connect_to_daemon())
    return true;

  auto [owner, backup_owner, value, typestr] =
    eat_named_arguments(args, ONS_OWNER_PREFIX, ONS_BACKUP_OWNER_PREFIX, ONS_VALUE_PREFIX, ONS_TYPE_PREFIX);

  if (args.empty())
  {
    PRINT_USAGE(USAGE_ONS_MAKE_UPDATE_MAPPING_SIGNATURE);
    return false;
  }

  std::string const &name = args[0];
  SCOPED_WALLET_UNLOCK();
  ons::generic_signature signature_binary;
  std::string reason;
  if (m_wallet->ons_make_update_mapping_signature(ons::mapping_type::session,
                                                  name,
                                                  value.size() ? &value : nullptr,
                                                  owner.size() ? &owner : nullptr,
                                                  backup_owner.size() ? &backup_owner : nullptr,
                                                  signature_binary,
                                                  m_current_subaddress_account,
                                                  &reason))
    tools::success_msg_writer() << "signature=" << tools::type_to_hex(signature_binary.ed25519);
  else
    fail_msg_writer() << reason;

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::ons_lookup(std::vector<std::string> args)
{
  if (!try_connect_to_daemon())
    return false;

  if (args.empty())
  {
    PRINT_USAGE(USAGE_ONS_LOOKUP);
    return true;
  }

  std::string typestr = eat_named_argument(args, ONS_TYPE_PREFIX);

  std::vector<uint16_t> requested_types;
  // Parse ONS Types
  if (!typestr.empty()) {
    auto hf_version = m_wallet->get_hard_fork_version();
    if (!hf_version)
    {
      fail_msg_writer() << tools::wallet2::ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
      return false;
    }

    for (auto type : tools::split(typestr, ","))
    {
      ons::mapping_type mapping_type;
      std::string reason;
      if (!ons::validate_mapping_type(type, *hf_version, ons::ons_tx_type::lookup, &mapping_type, &reason))
      {
        fail_msg_writer() << reason;
        return false;
      }
      requested_types.push_back(ons::db_mapping_type(mapping_type));
    }
  }

  if (requested_types.empty())
  {
    auto hf_version = m_wallet->get_hard_fork_version();
    if (!hf_version)
    {
      fail_msg_writer() << tools::wallet2::ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
      return false;
    }
    auto all_types = ons::all_mapping_types(static_cast<hf>(*hf_version));
    std::transform(all_types.begin(), all_types.end(), std::back_inserter(requested_types), ons::db_mapping_type);
  }

  if (args.empty())
  {
    PRINT_USAGE(USAGE_ONS_LOOKUP);
    return true;
  }

  rpc::ONS_NAMES_TO_OWNERS::request request = {};
  for (auto& name : args)
  {
    name = tools::lowercase_ascii_string(std::move(name));
    request.entries.push_back({ons::name_to_base64_hash(name), requested_types});
  }

  auto [success, response] = m_wallet->ons_names_to_owners(request);
  if (!success)
  {
    fail_msg_writer() << "Connection to daemon failed when requesting ONS owners";
    return false;
  }

  int last_index = -1;
  for (auto const &mapping : response)
  {
    auto& enc_hex = mapping.encrypted_value;
    if (mapping.entry_index >= args.size() || !oxenc::is_hex(enc_hex) || enc_hex.size() > 2*ons::mapping_value::BUFFER_SIZE)
    {
      fail_msg_writer() << "Received invalid ONS mapping data from oxend";
      return false;
    }

    // Print any skipped (i.e. not registered) results:
    for (size_t i = last_index + 1; i < mapping.entry_index; i++)
      fail_msg_writer() << args[i] << " not found\n";
    last_index = mapping.entry_index;

    const auto& name = args[mapping.entry_index];
    ons::mapping_value value{};
    value.len = enc_hex.size() / 2;
    value.encrypted = true;
    oxenc::from_hex(enc_hex.begin(), enc_hex.end(), value.buffer.begin());

    if (!value.decrypt(name, mapping.type))
    {
      fail_msg_writer() << "Failed to decrypt the mapping value=" << enc_hex;
      return false;
    }

    auto writer = tools::msg_writer();
    writer
      << "Name: " << name
      << "\n    Type: " << static_cast<ons::mapping_type>(mapping.type)
      << "\n    Value: " << value.to_readable_value(m_wallet->nettype(), mapping.type)
      << "\n    Owner: " << mapping.owner;
    if (mapping.backup_owner) writer
      << "\n    Backup owner: " << *mapping.backup_owner;
    writer
      << "\n    Last updated height: " << mapping.update_height;
    if (mapping.expiration_height) writer
      << "\n    Expiration height: " << *mapping.expiration_height;
    writer
      << "\n    Encrypted value: " << enc_hex;
    writer
      << "\n";

    tools::wallet2::ons_detail detail =
    {
      static_cast<ons::mapping_type>(mapping.type),
      name,
      request.entries[0].name_hash};
    m_wallet->set_ons_cache_record(detail);
  }
  for (size_t i = last_index + 1; i < args.size(); i++)
    fail_msg_writer() << args[i] << " not found\n";

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::ons_by_owner(const std::vector<std::string>& args)
{
  if (!try_connect_to_daemon())
    return false;

  std::vector<std::vector<cryptonote::rpc::ONS_OWNERS_TO_NAMES::response_entry>> rpc_results;
  std::vector<cryptonote::rpc::ONS_OWNERS_TO_NAMES::request> requests(1);

  std::unordered_map<std::string, tools::wallet2::ons_detail> cache = m_wallet->get_ons_cache();

  if (args.size() == 0)
  {
    for (uint32_t index = 0; index < m_wallet->get_num_subaddresses(m_current_subaddress_account); ++index)
    {

      if (requests.back().entries.size() >= cryptonote::rpc::ONS_OWNERS_TO_NAMES::MAX_REQUEST_ENTRIES)
        requests.emplace_back();
      requests.back().entries.push_back(m_wallet->get_subaddress_as_str({m_current_subaddress_account, index}));
    }
  }
  else
  {
    for (std::string const &arg : args)
    {
      size_t constexpr MAX_LEN = 128;
      if (arg.size() >=  MAX_LEN)
      {
        fail_msg_writer() << "arg too long, fails basic size sanity check max length = " << MAX_LEN << ", arg = " << arg;
        return false;
      }

      if (!(oxenc::is_hex(arg) && arg.size() == 64) && (!cryptonote::is_valid_address(arg, m_wallet->nettype())))
      {
        fail_msg_writer() << "arg contains non valid characters: " << arg;
        return false;
      }

      if (requests.back().entries.size() >= cryptonote::rpc::ONS_OWNERS_TO_NAMES::MAX_REQUEST_ENTRIES)
        requests.emplace_back();
      requests.back().entries.push_back(arg);
    }
  }

  rpc_results.reserve(requests.size());
  for (auto const &request : requests)
  {
    auto [success, result] = m_wallet->ons_owners_to_names(request);
    if (!success)
    {
      fail_msg_writer() << "Connection to daemon failed when requesting ONS names";
      return false;
    }
    rpc_results.emplace_back(std::move(result));
  }


  auto nettype = m_wallet->nettype();
  for (size_t i = 0; i < rpc_results.size(); i++)
  {
    auto const &rpc = rpc_results[i];
    for (auto const &entry : rpc)
    {
      std::string_view name;
      std::string value;
      if (auto got = cache.find(entry.name_hash); got != cache.end())
      {
        name = got->second.name;
        ons::mapping_value mv;
        if (ons::mapping_value::validate_encrypted(entry.type, oxenc::from_hex(entry.encrypted_value), &mv)
            && mv.decrypt(name, entry.type))
          value = mv.to_readable_value(nettype, entry.type);
      }

      auto writer = tools::msg_writer();
      writer
        << "Name (hashed): " << entry.name_hash;
      if (!name.empty()) writer
        << "\n    Name: " << name;
      writer
        << "\n    Type: " << entry.type;
      if (!value.empty()) writer
        << "\n    Value: " << value;
      writer
        << "\n    Owner: " << entry.owner;
      if (entry.backup_owner) writer
        << "\n    Backup owner: " << *entry.backup_owner;
      writer
        << "\n    Last updated height: " << entry.update_height;
      if (entry.expiration_height) writer
        << "\n    Expiration height: " << *entry.expiration_height;
      writer
        << "\n    Encrypted value: " << entry.encrypted_value;
    }
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::sweep_unmixable(const std::vector<std::string> &args_)
{
  if (!try_connect_to_daemon())
    return true;

  SCOPED_WALLET_UNLOCK();

  try
  {
    // figure out what tx will be necessary
    auto ptx_vector = m_wallet->create_unmixable_sweep_transactions();

    if (ptx_vector.empty())
    {
      fail_msg_writer() << tr("No unmixable outputs found");
      return true;
    }

    // give user total and fee, and prompt to confirm
    uint64_t total_fee = 0, total_unmixable = 0;
    for (size_t n = 0; n < ptx_vector.size(); ++n)
    {
      total_fee += ptx_vector[n].fee;
      for (auto i: ptx_vector[n].selected_transfers)
        total_unmixable += m_wallet->get_transfer_details(i).amount();
    }

    std::string prompt_str = tr("Sweeping ") + print_money(total_unmixable);
    if (ptx_vector.size() > 1) {
      prompt_str = (boost::format(tr("Sweeping %s in %llu transactions for a total fee of %s.  Is this okay?")) %
        print_money(total_unmixable) %
        ((unsigned long long)ptx_vector.size()) %
        print_money(total_fee)).str();
    }
    else {
      prompt_str = (boost::format(tr("Sweeping %s for a total fee of %s. Is this okay?")) %
        print_money(total_unmixable) %
        print_money(total_fee)).str();
    }
    std::string accepted = input_line(prompt_str, true);
    if (std::cin.eof())
      return true;
    if (!command_line::is_yes(accepted))
    {
      fail_msg_writer() << tr("transaction cancelled.");

      return true;
    }

    // actually commit the transactions
    if (m_wallet->multisig())
    {
      bool r = m_wallet->save_multisig_tx(ptx_vector, "multisig_oxen_tx");
      if (!r)
      {
        fail_msg_writer() << tr("Failed to write transaction(s) to file");
      }
      else
      {
        success_msg_writer(true) << tr("Unsigned transaction(s) successfully written to file: ") << "multisig_oxen_tx";
      }
    }
    else if (m_wallet->watch_only())
    {
      bool r = m_wallet->save_tx(ptx_vector, "unsigned_oxen_tx");
      if (!r)
      {
        fail_msg_writer() << tr("Failed to write transaction(s) to file");
      }
      else
      {
        success_msg_writer(true) << tr("Unsigned transaction(s) successfully written to file: ") << "unsigned_oxen_tx";
      }
    }
    else
    {
      commit_or_save(ptx_vector, m_do_not_relay, false /* don't blink */);
    }
  }
  catch (const std::exception &e)
  {
    handle_transfer_exception(std::current_exception(), m_wallet->is_trusted_daemon());
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << tr("unknown error");
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::sweep_main_internal(sweep_type_t sweep_type, std::vector<tools::wallet2::pending_tx> &ptx_vector, cryptonote::address_parse_info const &dest, bool blink)
{
  if ((sweep_type == sweep_type_t::stake || sweep_type == sweep_type_t::register_stake) && ptx_vector.size() > 1)
  {
    fail_msg_writer() << tr("Too many outputs. Please sweep_all first");
    return true;
  }

  if (sweep_type == sweep_type_t::single)
  {
    if (ptx_vector.size() > 1)
    {
      fail_msg_writer() << tr("Multiple transactions are created, which is not supposed to happen");
      return true;
    }

    if (ptx_vector[0].selected_transfers.size() != 1)
    {
      fail_msg_writer() << tr("The transaction uses multiple or no inputs, which is not supposed to happen");
      return true;
    }
  }

  if (ptx_vector.empty())
  {
    fail_msg_writer() << tr("No outputs found, or daemon is not ready");
    return false;
  }

  // give user total and fee, and prompt to confirm
  uint64_t total_fee = 0, total_sent = 0;
  for (size_t n = 0; n < ptx_vector.size(); ++n)
  {
    total_fee += ptx_vector[n].fee;
    for (auto i: ptx_vector[n].selected_transfers)
      total_sent += m_wallet->get_transfer_details(i).amount();

    if (sweep_type == sweep_type_t::stake || sweep_type == sweep_type_t::register_stake)
      total_sent -= ptx_vector[n].change_dts.amount + ptx_vector[n].fee;
  }

  std::ostringstream prompt;
  std::set<uint32_t> subaddr_indices;
  for (size_t n = 0; n < ptx_vector.size(); ++n)
  {
    prompt << tr("\nTransaction ") << (n + 1) << "/" << ptx_vector.size() << ":\n";
    subaddr_indices.clear();
    for (uint32_t i : ptx_vector[n].construction_data.subaddr_indices)
      subaddr_indices.insert(i);
    for (uint32_t i : subaddr_indices)
      prompt << boost::format(tr("Spending from address index %d\n")) % i;
    if (subaddr_indices.size() > 1)
      prompt << tr("WARNING: Outputs of multiple addresses are being used together, which might potentially compromise your privacy.\n");
  }

  if (!process_ring_members(ptx_vector, prompt, m_wallet->print_ring_members()))
    return true;

  const char *label = (sweep_type == sweep_type_t::stake || sweep_type == sweep_type_t::register_stake) ? "Staking" : "Sweeping";
  if (ptx_vector.size() > 1) {
    prompt << boost::format(tr("%s %s in %llu transactions for a total fee of %s. Is this okay?")) %
      label %
      print_money(total_sent) %
      ((unsigned long long)ptx_vector.size()) %
      print_money(total_fee);
  }
  else {
    prompt << boost::format(tr("%s %s for a total fee of %s. Is this okay?")) %
      label %
      print_money(total_sent) %
      print_money(total_fee);
  }
  std::string accepted = input_line(prompt.str(), true);
  if (std::cin.eof())
    return false;
  if (!command_line::is_yes(accepted))
  {
    fail_msg_writer() << tr("transaction cancelled.");
    return false;
  }

  // actually commit the transactions
  bool submitted_to_network = false;
  if (m_wallet->multisig())
  {
    bool r = m_wallet->save_multisig_tx(ptx_vector, "multisig_oxen_tx");
    if (!r)
    {
      fail_msg_writer() << tr("Failed to write transaction(s) to file");
    }
    else
    {
      success_msg_writer(true) << tr("Unsigned transaction(s) successfully written to file: ") << "multisig_oxen_tx";
    }
  }
  else if (m_wallet->get_account().get_device().has_tx_cold_sign())
  {
    try
    {
      tools::wallet2::signed_tx_set signed_tx;
      std::vector<cryptonote::address_parse_info> dsts_info;
      dsts_info.push_back(dest);

      if (!cold_sign_tx(ptx_vector, signed_tx, dsts_info, [&](const tools::wallet2::signed_tx_set &tx){ return accept_loaded_tx(tx); })){
        fail_msg_writer() << tr("Failed to cold sign transaction with HW wallet");
        return true;
      }

      commit_or_save(signed_tx.ptx, m_do_not_relay, blink);
    }
    catch (const std::exception& e)
    {
      handle_transfer_exception(std::current_exception(), m_wallet->is_trusted_daemon());
    }
    catch (...)
    {
      LOG_ERROR("Unknown error");
      fail_msg_writer() << tr("unknown error");
    }
  }
  else if (m_wallet->watch_only())
  {
    bool r = m_wallet->save_tx(ptx_vector, "unsigned_oxen_tx");
    if (!r)
    {
      fail_msg_writer() << tr("Failed to write transaction(s) to file");
    }
    else
    {
      success_msg_writer(true) << tr("Unsigned transaction(s) successfully written to file: ") << "unsigned_oxen_tx";
    }
  }
  else
  {
    commit_or_save(ptx_vector, m_do_not_relay, blink);
    submitted_to_network = true;
  }

  if (sweep_type == sweep_type_t::register_stake && submitted_to_network)
  {
    success_msg_writer() << tr("Wait for transaction to be included in a block before registration is complete.\n")
                         << tr("Use the print_sn command in the daemon to check the status.");
  }

  return true;
}

bool simple_wallet::sweep_main(uint32_t account, uint64_t below, Transfer transfer_type, const std::vector<std::string> &args_)
{
  auto print_usage = [this, account, below]()
  {
    if (below)
    {
      PRINT_USAGE(USAGE_SWEEP_BELOW);
    }
    else if (account == m_current_subaddress_account)
    {
      PRINT_USAGE(USAGE_SWEEP_ALL);
    }
    else
    {
      PRINT_USAGE(USAGE_SWEEP_ACCOUNT);
    }
  };


  if (!try_connect_to_daemon())
    return true;

  std::vector<std::string> local_args = args_;
  uint32_t priority = 0;
  std::set<uint32_t> subaddr_indices  = {};

  if (!parse_subaddr_indices_and_priority(*m_wallet, local_args, subaddr_indices, priority, m_current_subaddress_account, true /*allow_parse_all_argument*/))
    return false;

  if (priority == 0)
  {
    priority = m_wallet->get_default_priority();
    if (priority == 0)
      priority = transfer_type == Transfer::Locked ? tools::tx_priority_unimportant : tools::tx_priority_blink;
  }

  uint64_t unlock_block = 0;
  if (transfer_type == Transfer::Locked) {
    if (priority == tools::tx_priority_blink) {
      fail_msg_writer() << tr("blink priority cannot be used for locked transfers");
      return false;
    }
    uint64_t locked_blocks = 0;

    if (local_args.size() < 1) {
      fail_msg_writer() << tr("missing lockedblocks parameter");
      return true;
    }

    try
    {
      if (local_args.size() == 1)
        locked_blocks = boost::lexical_cast<uint64_t>(local_args[0]);
      else
        locked_blocks = boost::lexical_cast<uint64_t>(local_args[1]);
    }
    catch (const std::exception &e)
    {
      fail_msg_writer() << tr("bad locked_blocks parameter");
      return true;
    }
    if (locked_blocks > 1000000)
    {
      fail_msg_writer() << tr("Locked blocks too high, max 1000000 (~4 yrs)");
      return true;
    }
    std::string err;
    uint64_t bc_height = get_daemon_blockchain_height(err);
    if (!err.empty())
    {
      fail_msg_writer() << tr("failed to get blockchain height: ") << err;
      return true;
    }
    unlock_block = bc_height + locked_blocks;

    local_args.erase(local_args.begin() + 1);
  }

  size_t outputs = 1;
  if (local_args.size() > 0 && local_args[0].substr(0, 8) == "outputs=")
  {
    if (!epee::string_tools::get_xtype_from_string(outputs, local_args[0].substr(8)))
    {
      fail_msg_writer() << tr("Failed to parse number of outputs");
      return true;
    }
    else if (outputs < 1)
    {
      fail_msg_writer() << tr("Amount of outputs should be greater than 0");
      return true;
    }
    else
    {
      local_args.erase(local_args.begin());
    }
  }

  std::vector<uint8_t> extra;
  if (local_args.size() >= 2)
  {
    std::string payment_id_str = local_args.back();

    if (crypto::hash payment_id; tools::hex_to_type(payment_id_str, payment_id))
      return long_payment_id_failure(true);

    if(local_args.size() == 3)
    {
      fail_msg_writer() << tr("Standalone payment IDs are not longer supported; please use an integrated address or subaddress instead");
      print_usage();
      return true;
    }
  }

  cryptonote::address_parse_info info;
  std::string addr;
  if (local_args.size() > 0)
    addr = local_args[0];
  else
    addr = m_wallet->get_subaddress_as_str({m_current_subaddress_account, 0});

  if (!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), addr))
  {
    fail_msg_writer() << tr("failed to parse address");
    print_usage();
    return true;
  }

  if (info.has_payment_id)
  {
    std::string extra_nonce;
    set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, info.payment_id);
    bool r = add_extra_nonce_to_tx_extra(extra, extra_nonce);
    if(!r)
    {
      fail_msg_writer() << tr("failed to set up payment id, though it was decoded correctly");
      return true;
    }
  }

  SCOPED_WALLET_UNLOCK();
  try
  {
    auto ptx_vector = m_wallet->create_transactions_all(below, info.address, info.is_subaddress, outputs, cryptonote::TX_OUTPUT_DECOYS, unlock_block /* unlock_time */, priority, extra, account, subaddr_indices);
    sweep_main_internal(sweep_type_t::all_or_below, ptx_vector, info, priority == tools::tx_priority_blink);
  }
  catch (const std::exception &e)
  {
    handle_transfer_exception(std::current_exception(), m_wallet->is_trusted_daemon());
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << tr("unknown error");
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::sweep_single(const std::vector<std::string> &args_)
{
  if (!try_connect_to_daemon())
    return true;

  std::vector<std::string> local_args = args_;

  uint32_t priority = 0;
  if (local_args.size() > 0 && tools::parse_priority(local_args[0], priority))
    local_args.erase(local_args.begin());

  if (priority == 0)
  {
    priority = m_wallet->get_default_priority();
    if (priority == 0)
      priority = tools::tx_priority_blink;
  }

  size_t outputs = 1;
  if (local_args.size() > 0 && local_args[0].substr(0, 8) == "outputs=")
  {
    if (!epee::string_tools::get_xtype_from_string(outputs, local_args[0].substr(8)))
    {
      fail_msg_writer() << tr("Failed to parse number of outputs");
      return true;
    }
    else if (outputs < 1)
    {
      fail_msg_writer() << tr("Amount of outputs should be greater than 0");
      return true;
    }
    else
    {
      local_args.erase(local_args.begin());
    }
  }

  std::vector<uint8_t> extra;
  if (local_args.size() == 3)
  {
    fail_msg_writer() << tr("Standalone payment IDs are not longer supported; please use an integrated address or subaddress instead");
    return true;
  }

  if (local_args.size() != 2)
  {
    PRINT_USAGE(USAGE_SWEEP_SINGLE);
    return true;
  }

  crypto::key_image ki;
  if (!tools::hex_to_type(local_args[0], ki))
  {
    fail_msg_writer() << tr("failed to parse key image");
    return true;
  }

  cryptonote::address_parse_info info;
  if (!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), local_args[1]))
  {
    fail_msg_writer() << tr("failed to parse address");
    return true;
  }

  if (info.has_payment_id)
  {
    std::string extra_nonce;
    set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, info.payment_id);
    if (!add_extra_nonce_to_tx_extra(extra, extra_nonce))
    {
      fail_msg_writer() << tr("failed to set up payment id, though it was decoded correctly");
      return true;
    }
  }

  SCOPED_WALLET_UNLOCK();

  try
  {
    // figure out what tx will be necessary
    auto ptx_vector = m_wallet->create_transactions_single(ki, info.address, info.is_subaddress, outputs, cryptonote::TX_OUTPUT_DECOYS, 0 /* unlock_time */, priority, extra);
    sweep_main_internal(sweep_type_t::single, ptx_vector, info, priority == tools::tx_priority_blink);
  }
  catch (const std::exception& e)
  {
    handle_transfer_exception(std::current_exception(), m_wallet->is_trusted_daemon());
  }
  catch (...)
  {
    LOG_ERROR("unknown error");
    fail_msg_writer() << tr("unknown error");
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::sweep_all(const std::vector<std::string> &args_)
{
  return sweep_main(m_current_subaddress_account, 0, Transfer::Normal, args_);
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::sweep_account(const std::vector<std::string> &args_)
{
  auto local_args = args_;
  if (local_args.empty())
  {
    PRINT_USAGE(USAGE_SWEEP_ACCOUNT);
    return true;
  }
  uint32_t account = 0;
  if (!epee::string_tools::get_xtype_from_string(account, local_args[0]))
  {
    fail_msg_writer() << tr("Invalid account");
    return true;
  }
  local_args.erase(local_args.begin());

  sweep_main(account, 0, Transfer::Normal, local_args);
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::sweep_below(const std::vector<std::string> &args_)
{
  if (args_.size() < 1)
  {
    fail_msg_writer() << tr("missing threshold amount");
    return true;
  }
  auto below = cryptonote::parse_amount(args_[0]);
  if (!below)
  {
    fail_msg_writer() << tr("invalid amount threshold");
    return true;
  }
  return sweep_main(m_current_subaddress_account, *below, Transfer::Normal, std::vector<std::string>(++args_.begin(), args_.end()));
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::accept_loaded_tx(const std::function<size_t()> get_num_txes, const std::function<const wallet::tx_construction_data&(size_t)> &get_tx, const std::string &extra_message)
{
  // gather info to ask the user
  uint64_t amount = 0, amount_to_dests = 0, change = 0;
  size_t min_ring_size = ~0;
  std::unordered_map<cryptonote::account_public_address, std::pair<std::string, uint64_t>> dests;
  int first_known_non_zero_change_index = -1;
  std::string payment_id_string = "";
  for (size_t n = 0; n < get_num_txes(); ++n)
  {
    const wallet::tx_construction_data &cd = get_tx(n);

    std::vector<tx_extra_field> tx_extra_fields;
    bool has_encrypted_payment_id = false;
    crypto::hash8 payment_id8 = crypto::null_hash8;
    if (cryptonote::parse_tx_extra(cd.extra, tx_extra_fields))
    {
      tx_extra_nonce extra_nonce;
      if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
      {
        crypto::hash payment_id;
        if(get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
        {
          if (!payment_id_string.empty())
            payment_id_string += ", ";

          // if none of the addresses are integrated addresses, it's a dummy one
          bool is_dummy = true;
          for (const auto &e: cd.dests)
            if (e.is_integrated)
              is_dummy = false;

          if (is_dummy)
          {
            payment_id_string += std::string("dummy encrypted payment ID");
          }
          else
          {
            payment_id_string += std::string("encrypted payment ID ") + tools::type_to_hex(payment_id8);
            has_encrypted_payment_id = true;
          }
        }
        else if (get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
        {
          if (!payment_id_string.empty())
            payment_id_string += ", ";
          payment_id_string += std::string("unencrypted payment ID ") + tools::type_to_hex(payment_id);
          payment_id_string += " (OBSOLETE)";
        }
      }
    }

    for (size_t s = 0; s < cd.sources.size(); ++s)
    {
      amount += cd.sources[s].amount;
      size_t ring_size = cd.sources[s].outputs.size();
      if (ring_size < min_ring_size)
        min_ring_size = ring_size;
    }
    for (size_t d = 0; d < cd.splitted_dsts.size(); ++d)
    {
      const tx_destination_entry &entry = cd.splitted_dsts[d];
      std::string address, standard_address = get_account_address_as_str(m_wallet->nettype(), entry.is_subaddress, entry.addr);
      if (has_encrypted_payment_id && !entry.is_subaddress && standard_address != entry.original)
      {
        address = get_account_integrated_address_as_str(m_wallet->nettype(), entry.addr, payment_id8);
        address += std::string(" (" + standard_address + " with encrypted payment id " + tools::type_to_hex(payment_id8) + ")");
      }
      else
        address = standard_address;
      auto i = dests.find(entry.addr);
      if (i == dests.end())
        dests.insert(std::make_pair(entry.addr, std::make_pair(address, entry.amount)));
      else
        i->second.second += entry.amount;
      amount_to_dests += entry.amount;
    }
    if (cd.change_dts.amount > 0)
    {
      auto it = dests.find(cd.change_dts.addr);
      if (it == dests.end())
      {
        fail_msg_writer() << tr("Claimed change does not go to a paid address");
        return false;
      }
      if (it->second.second < cd.change_dts.amount)
      {
        fail_msg_writer() << tr("Claimed change is larger than payment to the change address");
        return false;
      }
      if (cd.change_dts.amount > 0)
      {
        if (first_known_non_zero_change_index == -1)
          first_known_non_zero_change_index = n;
        if (memcmp(&cd.change_dts.addr, &get_tx(first_known_non_zero_change_index).change_dts.addr, sizeof(cd.change_dts.addr)))
        {
          fail_msg_writer() << tr("Change goes to more than one address");
          return false;
        }
      }
      change += cd.change_dts.amount;
      it->second.second -= cd.change_dts.amount;
      if (it->second.second == 0)
        dests.erase(cd.change_dts.addr);
    }
  }

  if (payment_id_string.empty())
    payment_id_string = "no payment ID";

  std::string dest_string;
  size_t n_dummy_outputs = 0;
  for (auto i = dests.begin(); i != dests.end(); )
  {
    if (i->second.second > 0)
    {
      if (!dest_string.empty())
        dest_string += ", ";
      dest_string += (boost::format(tr("sending %s to %s")) % print_money(i->second.second) % i->second.first).str();
    }
    else
      ++n_dummy_outputs;
    ++i;
  }
  if (n_dummy_outputs > 0)
  {
    if (!dest_string.empty())
      dest_string += ", ";
    dest_string += std::to_string(n_dummy_outputs) + tr(" dummy output(s)");
  }
  if (dest_string.empty())
    dest_string = tr("with no destinations");

  std::string change_string;
  if (change > 0)
  {
    std::string address = get_account_address_as_str(m_wallet->nettype(), get_tx(0).subaddr_account > 0, get_tx(0).change_dts.addr);
    change_string += (boost::format(tr("%s change to %s")) % print_money(change) % address).str();
  }
  else
    change_string += tr("no change");

  uint64_t fee = amount - amount_to_dests;
  std::string prompt_str = (boost::format(tr("Loaded %lu transactions, for %s, fee %s, %s, %s, with min ring size %lu, %s. %sIs this okay?")) % (unsigned long)get_num_txes() % print_money(amount) % print_money(fee) % dest_string % change_string % (unsigned long)min_ring_size % payment_id_string % extra_message).str();
  return command_line::is_yes(input_line(prompt_str, true));
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::accept_loaded_tx(const tools::wallet2::unsigned_tx_set &txs)
{
  std::string extra_message;
  if (!txs.transfers.second.empty())
    extra_message = (boost::format("%u outputs to import. ") % (unsigned)txs.transfers.second.size()).str();
  return accept_loaded_tx([&txs](){return txs.txes.size();}, [&txs](size_t n)->const wallet::tx_construction_data&{return txs.txes[n];}, extra_message);
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::accept_loaded_tx(const tools::wallet2::signed_tx_set &txs)
{
  std::string extra_message;
  if (!txs.key_images.empty())
    extra_message = (boost::format("%u key images to import. ") % (unsigned)txs.key_images.size()).str();
  return accept_loaded_tx([&txs](){return txs.ptx.size();}, [&txs](size_t n)->const wallet::tx_construction_data&{return txs.ptx[n].construction_data;}, extra_message);
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::sign_transfer(const std::vector<std::string> &args_)
{
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return true;
  }
  if(m_wallet->multisig())
  {
     fail_msg_writer() << tr("This is a multisig wallet, it can only sign with sign_multisig");
     return true;
  }
  if(m_wallet->watch_only())
  {
     fail_msg_writer() << tr("This is a watch only wallet");
     return true;
  }
  if (args_.size() > 1 || (args_.size() == 1 && args_[0] != "export_raw"))
  {
    PRINT_USAGE(USAGE_SIGN_TRANSFER);
    return true;
  }

  SCOPED_WALLET_UNLOCK();
  const bool export_raw = args_.size() == 1;

  std::vector<tools::wallet2::pending_tx> ptx;
  try
  {
    bool r = m_wallet->sign_tx("unsigned_oxen_tx", "signed_oxen_tx", ptx, [&](const tools::wallet2::unsigned_tx_set &tx){ return accept_loaded_tx(tx); }, export_raw);
    if (!r)
    {
      fail_msg_writer() << tr("Failed to sign transaction");
      return true;
    }
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("Failed to sign transaction: ") << e.what();
    return true;
  }

  std::string txids_as_text;
  for (const auto &t: ptx)
  {
    if (!txids_as_text.empty())
      txids_as_text += (", ");
    txids_as_text += tools::type_to_hex(get_transaction_hash(t.tx));
  }
  success_msg_writer(true) << tr("Transaction successfully signed to file ") << "signed_oxen_tx" << ", txid " << txids_as_text;
  if (export_raw)
  {
    std::string rawfiles_as_text;
    for (size_t i = 0; i < ptx.size(); ++i)
    {
      if (i > 0)
        rawfiles_as_text += ", ";
      rawfiles_as_text += "signed_oxen_tx_raw" + (ptx.size() == 1 ? "" : ("_" + std::to_string(i)));
    }
    success_msg_writer(true) << tr("Transaction raw hex data exported to ") << rawfiles_as_text;
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::submit_transfer(const std::vector<std::string> &args_)
{
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return true;
  }
  if (!try_connect_to_daemon())
    return true;

  try
  {
    std::vector<tools::wallet2::pending_tx> ptx_vector;
    bool r = m_wallet->load_tx("signed_oxen_tx", ptx_vector, [&](const tools::wallet2::signed_tx_set &tx){ return accept_loaded_tx(tx); });
    if (!r)
    {
      fail_msg_writer() << tr("Failed to load transaction from file");
      return true;
    }

    // FIXME: store the blink status in the signed_oxen_tx somehow?
    constexpr bool FIXME_blink = false;

    commit_or_save(ptx_vector, false, FIXME_blink);
  }
  catch (const std::exception& e)
  {
    handle_transfer_exception(std::current_exception(), m_wallet->is_trusted_daemon());
  }
  catch (...)
  {
    LOG_ERROR("Unknown error");
    fail_msg_writer() << tr("unknown error");
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::get_tx_key(const std::vector<std::string> &args_)
{
  std::vector<std::string> local_args = args_;

  if (m_wallet->key_on_device() && m_wallet->get_account().get_device().get_type() != hw::device::type::TREZOR)
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return true;
  }
  if(local_args.size() != 1) {
    PRINT_USAGE(USAGE_GET_TX_KEY);
    return true;
  }

  crypto::hash txid;
  if (!tools::hex_to_type(local_args[0], txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  SCOPED_WALLET_UNLOCK();

  crypto::secret_key tx_key;
  std::vector<crypto::secret_key> additional_tx_keys;

  bool found_tx_key = m_wallet->get_tx_key(txid, tx_key, additional_tx_keys);
  if (found_tx_key)
  {
    std::ostringstream oss;
    oss << tools::type_to_hex(tx_key);
    for (size_t i = 0; i < additional_tx_keys.size(); ++i)
      oss << tools::type_to_hex(additional_tx_keys[i]);
    success_msg_writer() << tr("Tx key: ") << oss.str();
    return true;
  }
  else
  {
    fail_msg_writer() << tr("no tx keys found for this txid");
    return true;
  }
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::set_tx_key(const std::vector<std::string> &args_)
{
  std::vector<std::string> local_args = args_;

  if(local_args.size() != 2) {
    PRINT_USAGE(USAGE_SET_TX_KEY);
    return true;
  }

  crypto::hash txid;
  if (!tools::hex_to_type(local_args[0], txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  crypto::secret_key tx_key;
  std::vector<crypto::secret_key> additional_tx_keys;
  try
  {
    if (!tools::hex_to_type(local_args[1].substr(0, 64), tx_key))
    {
      fail_msg_writer() << tr("failed to parse tx_key");
      return true;
    }
    while(true)
    {
      local_args[1] = local_args[1].substr(64);
      if (local_args[1].empty())
        break;
      additional_tx_keys.resize(additional_tx_keys.size() + 1);
      if (!tools::hex_to_type(local_args[1].substr(0, 64), additional_tx_keys.back()))
      {
        fail_msg_writer() << tr("failed to parse tx_key");
        return true;
      }
    }
  }
  catch (const std::out_of_range &e)
  {
    fail_msg_writer() << tr("failed to parse tx_key");
    return true;
  }

  LOCK_IDLE_SCOPE();

  try
  {
    m_wallet->set_tx_key(txid, tx_key, additional_tx_keys);
    success_msg_writer() << tr("Tx key successfully stored.");
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("Failed to store tx key: ") << e.what();
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::get_tx_proof(const std::vector<std::string> &args)
{
  if (args.size() != 2 && args.size() != 3)
  {
    PRINT_USAGE(USAGE_GET_TX_PROOF);
    return true;
  }

  crypto::hash txid;
  if(!tools::hex_to_type(args[0], txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  cryptonote::address_parse_info info;
  if(!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), args[1]))
  {
    fail_msg_writer() << tr("failed to parse address");
    return true;
  }

  SCOPED_WALLET_UNLOCK();

  try
  {
    std::string sig_str = m_wallet->get_tx_proof(txid, info.address, info.is_subaddress, args.size() == 3 ? args[2] : "");
    const fs::path filename{"oxen_tx_proof"};
    if (tools::dump_file(filename, sig_str))
      success_msg_writer() << tr("signature file saved to: ") << filename.u8string();
    else
      fail_msg_writer() << tr("failed to save signature file");
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("error: ") << e.what();
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::check_tx_key(const std::vector<std::string> &args_)
{
  std::vector<std::string> local_args = args_;

  if(local_args.size() != 3) {
    PRINT_USAGE(USAGE_CHECK_TX_KEY);
    return true;
  }

  if (!try_connect_to_daemon())
    return true;

  if (!m_wallet)
  {
    fail_msg_writer() << tr("wallet is null");
    return true;
  }
  crypto::hash txid;
  if(!tools::hex_to_type(local_args[0], txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  crypto::secret_key tx_key;
  std::vector<crypto::secret_key> additional_tx_keys;
  if(!tools::hex_to_type(local_args[1].substr(0, 64), tx_key))
  {
    fail_msg_writer() << tr("failed to parse tx key");
    return true;
  }
  local_args[1] = local_args[1].substr(64);
  while (!local_args[1].empty())
  {
    additional_tx_keys.resize(additional_tx_keys.size() + 1);
    if(!tools::hex_to_type(local_args[1].substr(0, 64), additional_tx_keys.back()))
    {
      fail_msg_writer() << tr("failed to parse tx key");
      return true;
    }
    local_args[1] = local_args[1].substr(64);
  }

  cryptonote::address_parse_info info;
  if(!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), local_args[2]))
  {
    fail_msg_writer() << tr("failed to parse address");
    return true;
  }

  try
  {
    uint64_t received;
    bool in_pool = false;
    uint64_t confirmations;
    m_wallet->check_tx_key(txid, tx_key, additional_tx_keys, info.address, received, in_pool, confirmations);

    if (received > 0)
    {
      success_msg_writer() << get_account_address_as_str(m_wallet->nettype(), info.is_subaddress, info.address) << " " << tr("received") << " " << print_money(received) << " " << tr("in txid") << " " << txid;
      if (in_pool)
      {
        success_msg_writer() << tr("WARNING: this transaction is not yet included in the blockchain!");
      }
      else
      {
        if (confirmations != (uint64_t)-1)
        {
          success_msg_writer() << boost::format(tr("This transaction has %u confirmations")) % confirmations;
        }
        else
        {
          success_msg_writer() << tr("WARNING: failed to determine number of confirmations!");
        }
      }
    }
    else
    {
      fail_msg_writer() << get_account_address_as_str(m_wallet->nettype(), info.is_subaddress, info.address) << " " << tr("received nothing in txid") << " " << txid;
    }
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("error: ") << e.what();
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::check_tx_proof(const std::vector<std::string> &args)
{
  if(args.size() != 3 && args.size() != 4) {
    PRINT_USAGE(USAGE_CHECK_TX_PROOF);
    return true;
  }

  if (!try_connect_to_daemon())
    return true;

  // parse txid
  crypto::hash txid;
  if(!tools::hex_to_type(args[0], txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  // parse address
  cryptonote::address_parse_info info;
  if(!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), args[1]))
  {
    fail_msg_writer() << tr("failed to parse address");
    return true;
  }

  // read signature file
  std::string sig_str;
  if (!tools::slurp_file(args[2], sig_str))
  {
    fail_msg_writer() << tr("failed to load signature file");
    return true;
  }

  try
  {
    uint64_t received;
    bool in_pool;
    uint64_t confirmations;
    if (m_wallet->check_tx_proof(txid, info.address, info.is_subaddress, args.size() == 4 ? args[3] : "", sig_str, received, in_pool, confirmations))
    {
      success_msg_writer(true) << tr("Good signature");
      if (received > 0)
      {
        success_msg_writer() << get_account_address_as_str(m_wallet->nettype(), info.is_subaddress, info.address) << " " << tr("received") << " " << print_money(received) << " " << tr("in txid") << " " << txid;
        if (in_pool)
        {
          success_msg_writer() << tr("WARNING: this transaction is not yet included in the blockchain!");
        }
        else
        {
          if (confirmations != (uint64_t)-1)
          {
            success_msg_writer() << boost::format(tr("This transaction has %u confirmations")) % confirmations;
          }
          else
          {
            success_msg_writer() << tr("WARNING: failed to determine number of confirmations!");
          }
        }
      }
      else
      {
        fail_msg_writer() << get_account_address_as_str(m_wallet->nettype(), info.is_subaddress, info.address) << " " << tr("received nothing in txid") << " " << txid;
      }
    }
    else
    {
      fail_msg_writer() << tr("Bad signature");
    }
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("error: ") << e.what();
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::get_spend_proof(const std::vector<std::string> &args)
{
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return true;
  }
  if(args.size() != 1 && args.size() != 2) {
    PRINT_USAGE(USAGE_GET_SPEND_PROOF);
    return true;
  }

  if (m_wallet->watch_only())
  {
    fail_msg_writer() << tr("wallet is watch-only and cannot generate the proof");
    return true;
  }

  crypto::hash txid;
  if (!tools::hex_to_type(args[0], txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  if (!try_connect_to_daemon())
    return true;

  SCOPED_WALLET_UNLOCK();

  try
  {
    const std::string sig_str = m_wallet->get_spend_proof(txid, args.size() == 2 ? args[1] : "");
    const fs::path filename{"oxen_spend_proof"};
    if (tools::dump_file(filename, sig_str))
      success_msg_writer() << tr("signature file saved to: ") << filename.u8string();
    else
      fail_msg_writer() << tr("failed to save signature file");
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << e.what();
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::check_spend_proof(const std::vector<std::string> &args)
{
  if(args.size() != 2 && args.size() != 3) {
    PRINT_USAGE(USAGE_CHECK_SPEND_PROOF);
    return true;
  }

  crypto::hash txid;
  if (!tools::hex_to_type(args[0], txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  if (!try_connect_to_daemon())
    return true;

  std::string sig_str;
  if (!tools::slurp_file(args[1], sig_str))
  {
    fail_msg_writer() << tr("failed to load signature file");
    return true;
  }

  try
  {
    if (m_wallet->check_spend_proof(txid, args.size() == 3 ? args[2] : "", sig_str))
      success_msg_writer(true) << tr("Good signature");
    else
      fail_msg_writer() << tr("Bad signature");
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << e.what();
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::get_reserve_proof(const std::vector<std::string> &args)
{
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return true;
  }
  if(args.size() != 1 && args.size() != 2) {
    PRINT_USAGE(USAGE_GET_RESERVE_PROOF);
    return true;
  }

  if (m_wallet->watch_only() || m_wallet->multisig())
  {
    fail_msg_writer() << tr("The reserve proof can be generated only by a full wallet");
    return true;
  }

  std::optional<std::pair<uint32_t, uint64_t>> account_minreserve;
  if (args[0] != "all")
  {
    account_minreserve = std::pair<uint32_t, uint64_t>();
    account_minreserve->first = m_current_subaddress_account;
    if (auto r = cryptonote::parse_amount(args[0]))
      account_minreserve->second = *r;
    else
    {
      fail_msg_writer() << tr("amount is wrong: ") << args[0];
      return true;
    }
  }

  if (!try_connect_to_daemon())
    return true;

  SCOPED_WALLET_UNLOCK();

  try
  {
    const std::string sig_str = m_wallet->get_reserve_proof(account_minreserve, args.size() == 2 ? args[1] : "");
    const fs::path filename{"oxen_reserve_proof"};
    if (tools::dump_file(filename, sig_str))
      success_msg_writer() << tr("signature file saved to: ") << filename.u8string();
    else
      fail_msg_writer() << tr("failed to save signature file");
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << e.what();
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::check_reserve_proof(const std::vector<std::string> &args)
{
  if(args.size() != 2 && args.size() != 3) {
    PRINT_USAGE(USAGE_CHECK_RESERVE_PROOF);
    return true;
  }

  if (!try_connect_to_daemon())
    return true;

  cryptonote::address_parse_info info;
  if(!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), args[0]))
  {
    fail_msg_writer() << tr("failed to parse address");
    return true;
  }
  if (info.is_subaddress)
  {
    fail_msg_writer() << tr("Address must not be a subaddress");
    return true;
  }

  std::string sig_str;
  if (!tools::slurp_file(args[1], sig_str))
  {
    fail_msg_writer() << tr("failed to load signature file");
    return true;
  }

  LOCK_IDLE_SCOPE();

  try
  {
    uint64_t total, spent;
    if (m_wallet->check_reserve_proof(info.address, args.size() == 3 ? args[2] : "", sig_str, total, spent))
    {
      success_msg_writer(true) << boost::format(tr("Good signature -- total: %s, spent: %s, unspent: %s")) % print_money(total) % print_money(spent) % print_money(total - spent);
    }
    else
    {
      fail_msg_writer() << tr("Bad signature");
    }
  }
  catch (const std::exception& e)
  {
    fail_msg_writer() << e.what();
  }
  return true;
}
static bool parse_get_transfers_args(std::vector<std::string>& local_args, tools::wallet2::get_transfers_args_t& args)
{
  // optional in/out selector
  while (local_args.size() > 0)
  {
    if (local_args[0] == "in" || local_args[0] == "incoming") {
      args.in = args.coinbase = true;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "out" || local_args[0] == "outgoing") {
      args.out = args.stake = true;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "pending") {
      args.pending = true;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "failed") {
      args.failed = true;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "pool") {
      args.pool = true;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "coinbase") {
      args.coinbase = true;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "stake") {
      args.stake = true;
      local_args.erase(local_args.begin());
    }
    else if (local_args[0] == "all" || local_args[0] == "both") {
      args.in = args.out = args.stake = args.pending = args.failed = args.pool = args.coinbase = true;
      local_args.erase(local_args.begin());
    }
    else
    {
      break;
    }
  }

  // subaddr_index
  if (local_args.size() > 0 && local_args[0].substr(0, 6) == "index=")
  {
    std::string parse_subaddr_err;
    if (!tools::parse_subaddress_indices(local_args[0], args.subaddr_indices, &parse_subaddr_err))
    {
      fail_msg_writer() << parse_subaddr_err;
      return false;
    }
    local_args.erase(local_args.begin());
  }

  // min height
  if (local_args.size() > 0 && local_args[0].find('=') == std::string::npos) {
    try {
      args.min_height = boost::lexical_cast<uint64_t>(local_args[0]);
    }
    catch (const boost::bad_lexical_cast &) {
      fail_msg_writer() << tr("bad min_height parameter:") << " " << local_args[0];
      return false;
    }
    local_args.erase(local_args.begin());
  }

  // max height
  if (local_args.size() > 0 && local_args[0].find('=') == std::string::npos) {
    try {
      args.max_height = boost::lexical_cast<uint64_t>(local_args[0]);
    }
    catch (const boost::bad_lexical_cast &) {
      fail_msg_writer() << tr("bad max_height parameter:") << " " << local_args[0];
      return false;
    }
    local_args.erase(local_args.begin());
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
// mutates local_args as it parses and consumes arguments
bool simple_wallet::get_transfers(std::vector<std::string>& local_args, std::vector<wallet::transfer_view>& transfers)
{
  tools::wallet2::get_transfers_args_t args = {};
  if (!parse_get_transfers_args(local_args, args))
  {
    return false;
  }

  args.account_index = m_current_subaddress_account;
  m_wallet->get_transfers(args, transfers);
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_transfers(const std::vector<std::string> &args_)
{
  std::vector<std::string> local_args = args_;

  if(local_args.size() > 4)
  {
    PRINT_USAGE(USAGE_SHOW_TRANSFERS);
    return true;
  }

  LOCK_IDLE_SCOPE();

  std::vector<wallet::transfer_view> all_transfers;

  if (!get_transfers(local_args, all_transfers))
    return true;

  rdln::suspend_readline pause_readline;

  auto color = epee::console_color_white;

  auto formatter = boost::format("%8.8s %6.6s %8.8s %12.12s %16.16s %20.20s %64s %16s %14.14s %s %s - %s");

  message_writer(color, true) << formatter
      % "Height"
      % "Type"
      % "Locked"
      % "Checkpoint"
      % "Date"
      % "Amount"
      % "Hash"
      % "Payment ID"
      % "Fee"
      % "Destination"
      % "Subaddress"
      % "Note";

  for (const auto& transfer : all_transfers)
  {

    if (transfer.confirmed)
    {
      switch (transfer.pay_type)
      {
        case wallet::pay_type::in:           color = epee::console_color_green; break;
        case wallet::pay_type::out:          color = epee::console_color_yellow; break;
        case wallet::pay_type::miner:        color = epee::console_color_cyan; break;
        case wallet::pay_type::governance:   color = epee::console_color_cyan; break;
        case wallet::pay_type::stake:        color = epee::console_color_blue; break;
        case wallet::pay_type::ons:          color = epee::console_color_blue; break;
        case wallet::pay_type::service_node: color = epee::console_color_cyan; break;
        default:                            color = epee::console_color_magenta; break;
      }
    }

    if (transfer.type == "failed")
      color = epee::console_color_red;

    std::string destinations = "-";
    if (!transfer.destinations.empty())
    {
      destinations = "";
      for (const auto& output : transfer.destinations)
      {
        if (!destinations.empty())
          destinations += ", ";

        if (transfer.pay_type == wallet::pay_type::in ||
            transfer.pay_type == wallet::pay_type::governance ||
            transfer.pay_type == wallet::pay_type::service_node ||
            transfer.pay_type == wallet::pay_type::ons ||
            transfer.pay_type == wallet::pay_type::miner)
          destinations += output.address.substr(0, 6);
        else
          destinations += output.address;

        destinations += ":" + print_money(output.amount);
      }
    }


    std::vector<uint32_t> subaddr_minors;
    std::transform(transfer.subaddr_indices.begin(), transfer.subaddr_indices.end(), std::back_inserter(subaddr_minors),
        [](const auto& index) { return index.minor; });

    message_writer(color, false) << formatter
      % (transfer.type.size() ? transfer.type : (transfer.height == 0 && transfer.blink_mempool) ? "blink" : std::to_string(transfer.height))
      % wallet::pay_type_string(transfer.pay_type)
      % transfer.lock_msg
      % (transfer.checkpointed ? "checkpointed" : transfer.was_blink ? "blink" : "no")
      % tools::get_human_readable_timestamp(transfer.timestamp)
      % print_money(transfer.amount)
      % tools::type_to_hex(transfer.hash)
      % transfer.payment_id
      % print_money(transfer.fee)
      % destinations
      % tools::join(", ", subaddr_minors)
      % transfer.note;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::export_transfers(const std::vector<std::string>& args_)
{
  std::vector<std::string> local_args = args_;

  if(local_args.size() > 5)
  {
    PRINT_USAGE(USAGE_EXPORT_TRANSFERS);
    return true;
  }

  LOCK_IDLE_SCOPE();

  std::vector<wallet::transfer_view> all_transfers;

  // might consumes arguments in local_args
  if (!get_transfers(local_args, all_transfers))
    return true;

  // output filename
  std::string filename_str = (boost::format("output%u.csv") % m_current_subaddress_account).str();
  if (local_args.size() > 0 && local_args[0].substr(0, 7) == "output=")
  {
    filename_str = local_args[0].substr(7);
    local_args.erase(local_args.begin());
  }

  fs::ofstream file{fs::u8path(filename_str)};

  const bool formatting = true;
  file << m_wallet->transfers_to_csv(all_transfers, formatting);
  file.close();

  success_msg_writer() << tr("CSV exported to ") << filename_str;

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::unspent_outputs(const std::vector<std::string> &args_)
{
  if(args_.size() > 3)
  {
    PRINT_USAGE(USAGE_UNSPENT_OUTPUTS);
    return true;
  }
  auto local_args = args_;

  std::set<uint32_t> subaddr_indices;
  if (local_args.size() > 0 && local_args[0].substr(0, 6) == "index=")
  {
    std::string parse_subaddr_err;
    if (!tools::parse_subaddress_indices(local_args[0], subaddr_indices, &parse_subaddr_err))
    {
      fail_msg_writer() << parse_subaddr_err;
      return true;
    }
    local_args.erase(local_args.begin());
  }

  uint64_t min_amount = 0;
  uint64_t max_amount = std::numeric_limits<uint64_t>::max();
  if (local_args.size() > 0)
  {
    if (auto a = cryptonote::parse_amount(local_args[0]))
      min_amount = *a;
    else
    {
      fail_msg_writer() << tr("amount is wrong: ") << local_args[0];
      return true;
    }
    local_args.erase(local_args.begin());
    if (local_args.size() > 0)
    {
      if (auto a = cryptonote::parse_amount(local_args[0]))
        max_amount = *a;
      else
      {
        fail_msg_writer() << tr("amount is wrong: ") << local_args[0];
        return true;
      }
      local_args.erase(local_args.begin());
    }
    if (min_amount > max_amount)
    {
      fail_msg_writer() << tr("<min_amount> should be smaller than <max_amount>");
      return true;
    }
  }
  tools::wallet2::transfer_container transfers;
  m_wallet->get_transfers(transfers);
  std::map<uint64_t, tools::wallet2::transfer_container> amount_to_tds;
  uint64_t min_height = std::numeric_limits<uint64_t>::max();
  uint64_t max_height = 0;
  uint64_t found_min_amount = std::numeric_limits<uint64_t>::max();
  uint64_t found_max_amount = 0;
  uint64_t count = 0;
  for (const auto& td : transfers)
  {
    uint64_t amount = td.amount();
    if (td.m_spent || amount < min_amount || amount > max_amount || td.m_subaddr_index.major != m_current_subaddress_account || (subaddr_indices.count(td.m_subaddr_index.minor) == 0 && !subaddr_indices.empty()))
      continue;
    amount_to_tds[amount].push_back(td);
    if (min_height > td.m_block_height) min_height = td.m_block_height;
    if (max_height < td.m_block_height) max_height = td.m_block_height;
    if (found_min_amount > amount) found_min_amount = amount;
    if (found_max_amount < amount) found_max_amount = amount;
    ++count;
  }
  if (amount_to_tds.empty())
  {
    success_msg_writer() << tr("There is no unspent output in the specified address");
    return true;
  }
  for (const auto& amount_tds : amount_to_tds)
  {
    auto& tds = amount_tds.second;
    success_msg_writer() << tr("\nAmount: ") << print_money(amount_tds.first) << tr(", number of keys: ") << tds.size();
    for (size_t i = 0; i < tds.size(); )
    {
      std::ostringstream oss;
      for (size_t j = 0; j < 8 && i < tds.size(); ++i, ++j)
        oss << tds[i].m_block_height << tr(" ");
      success_msg_writer() << oss.str();
    }
  }
  success_msg_writer()
    << tr("\nMin block height: ") << min_height
    << tr("\nMax block height: ") << max_height
    << tr("\nMin amount found: ") << print_money(found_min_amount)
    << tr("\nMax amount found: ") << print_money(found_max_amount)
    << tr("\nTotal count: ") << count;
  const size_t histogram_height = 10;
  const size_t histogram_width  = 50;
  double bin_size = (max_height - min_height + 1.0) / histogram_width;
  size_t max_bin_count = 0;
  std::vector<size_t> histogram(histogram_width, 0);
  for (const auto& amount_tds : amount_to_tds)
  {
    for (auto& td : amount_tds.second)
    {
      uint64_t bin_index = (td.m_block_height - min_height + 1) / bin_size;
      if (bin_index >= histogram_width)
        bin_index = histogram_width - 1;
      histogram[bin_index]++;
      if (max_bin_count < histogram[bin_index])
        max_bin_count = histogram[bin_index];
    }
  }
  for (size_t x = 0; x < histogram_width; ++x)
  {
    double bin_count = histogram[x];
    if (max_bin_count > histogram_height)
      bin_count *= histogram_height / (double)max_bin_count;
    if (histogram[x] > 0 && bin_count < 1.0)
      bin_count = 1.0;
    histogram[x] = bin_count;
  }
  std::vector<std::string> histogram_line(histogram_height, std::string(histogram_width, ' '));
  for (size_t y = 0; y < histogram_height; ++y)
  {
    for (size_t x = 0; x < histogram_width; ++x)
    {
      if (y < histogram[x])
        histogram_line[y][x] = '*';
    }
  }
  double count_per_star = max_bin_count / (double)histogram_height;
  if (count_per_star < 1)
    count_per_star = 1;
  success_msg_writer()
    << tr("\nBin size: ") << bin_size
    << tr("\nOutputs per *: ") << count_per_star;
  std::ostringstream histogram_str;
  histogram_str << tr("count\n  ^\n");
  for (size_t y = histogram_height; y > 0; --y)
    histogram_str << tr("  |") << histogram_line[y - 1] << tr("|\n");
  histogram_str
    << tr("  +") << std::string(histogram_width, '-') << tr("+--> block height\n")
    << tr("   ^") << std::string(histogram_width - 2, ' ') << tr("^\n")
    << tr("  ") << min_height << std::string(histogram_width - 8, ' ') << max_height;
  success_msg_writer() << histogram_str.str();
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::rescan_blockchain(const std::vector<std::string> &args_)
{
  uint64_t start_height = 0;
  ResetType reset_type = ResetSoft;

  if (!args_.empty())
  {
    if (args_[0] == "hard")
    {
      reset_type = ResetHard;
    }
    else if (args_[0] == "soft")
    {
      reset_type = ResetSoft;
    }
    else if (args_[0] == "keep_ki")
    {
      reset_type = ResetSoftKeepKI;
    }
    else
    {
      PRINT_USAGE(USAGE_RESCAN_BC);
      return true;
    }

    if (args_.size() > 1)
    {
      try
      {
        start_height = boost::lexical_cast<uint64_t>( args_[1] );
      }
      catch(const boost::bad_lexical_cast &)
      {
        start_height = 0;
      }
    }
  }

  if (reset_type == ResetHard)
  {
    message_writer() << tr("Warning: this will lose any information which can not be recovered from the blockchain.");
    message_writer() << tr("This includes destination addresses, tx secret keys, tx notes, etc");
    std::string confirm = input_line(tr("Rescan anyway?"), true);
    if(!std::cin.eof())
    {
      if (!command_line::is_yes(confirm))
        return true;
    }
  }

  const uint64_t wallet_from_height = m_wallet->get_refresh_from_block_height();
  if (start_height > wallet_from_height)
  {
    message_writer() << tr("Warning: your restore height is higher than wallet restore height: ") << wallet_from_height;
    std::string confirm = input_line(tr("Rescan anyway ? (Y/Yes/N/No): "));
    if(!std::cin.eof())
    {
      if (!command_line::is_yes(confirm))
        return true;
    }
  }

  m_in_manual_refresh.store(true, std::memory_order_relaxed);
  OXEN_DEFER { m_in_manual_refresh.store(false, std::memory_order_relaxed); };
  return refresh_main(start_height, reset_type, true);
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::wallet_idle_thread()
{
  const auto start_time = std::chrono::steady_clock::now();
  while (true)
  {
    std::unique_lock lock{m_idle_mutex};
    if (!m_idle_run.load(std::memory_order_relaxed))
      break;

    // if another thread was busy (ie, a foreground refresh thread), we'll end up here at
    // some random time that's not what we slept for, so we should not call refresh now
    // or we'll be leaking that fact through timing
    const auto dt_actual = (std::chrono::steady_clock::now() - start_time) % 1s;
    constexpr auto threshold =
#ifdef _WIN32
        10ms;
#else
        2ms;
#endif

    if (dt_actual < threshold) // if less than a threshold... would a very slow machine always miss it ?
    {
#ifndef _WIN32
      m_inactivity_checker.do_call([this] { check_inactivity(); });
#endif
      m_refresh_checker.do_call([this] { check_refresh(false /*long_poll_trigger*/); });
#ifdef WALLET_ENABLE_MMS
      m_mms_checker.do_call([this] { check_mms(); });
#endif

      if (!m_idle_run.load(std::memory_order_relaxed))
        break;
    }

    // aim for the next multiple of 1 second
    const auto dt = std::chrono::steady_clock::now() - start_time;
    const auto wait = 1s - dt % 1s;
    m_idle_cond.wait_for(lock, wait);
  }
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::check_inactivity()
{
    // inactivity lock
    if (!m_locked && !m_in_command)
    {
      const auto timeout = m_wallet->inactivity_lock_timeout();
      if (timeout > 0s && std::chrono::seconds{time(NULL) - m_last_activity_time} > timeout)
      {
        m_locked = true;
        m_cmd_binder.cancel_input();
      }
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::check_refresh(bool long_poll_trigger)
{
    // auto refresh
    if (m_auto_refresh_enabled)
    {
      m_auto_refresh_refreshing = true;
      try
      {
        uint64_t fetched_blocks;
        bool received_money;
        if (try_connect_to_daemon(true))
          m_wallet->refresh(m_wallet->is_trusted_daemon(), 0, fetched_blocks, received_money, long_poll_trigger /*check pool*/);
      }
      catch(...) {}
      m_auto_refresh_refreshing = false;
    }
    return true;
}
//----------------------------------------------------------------------------------------------------
std::string simple_wallet::get_prompt() const
{
  if (m_locked)
    return std::string("[") + tr("locked due to inactivity") + "]";
  std::string addr_start = m_wallet->get_subaddress_as_str({m_current_subaddress_account, 0}).substr(0, 6);
  std::string prompt = std::string("[") + tr("wallet") + " " + addr_start;
  if (!m_wallet->check_connection())
    prompt += tr(" (no daemon)");
  else
  {
    if (m_wallet->is_synced())
    {
      if (m_has_locked_key_images)
      {
        prompt += tr(" (has locked stakes)");
      }
    }
    else
    {
      prompt += tr(" (out of sync)");
    }
  }
  prompt += "]: ";

  return prompt;
}
//----------------------------------------------------------------------------------------------------

bool simple_wallet::run()
{
  // check and display warning, but go on anyway
  try_connect_to_daemon();

  refresh_main(0, ResetNone, true);

  m_auto_refresh_enabled = m_wallet->auto_refresh();
  m_idle_thread          = std::thread([&] { wallet_idle_thread(); });

  m_long_poll_thread = std::thread([&] {
    for (;;)
    {
      if (m_wallet->m_long_poll_disabled)
        return true;
      try
      {
        if (m_auto_refresh_enabled && m_wallet->long_poll_pool_state())
          check_refresh(true /*long_poll_trigger*/);
      }
      catch (...)
      {
      }
      std::this_thread::sleep_for(25ms);
    }
  });

  message_writer(epee::console_color_green, false) << "Background refresh thread started";

  return m_cmd_binder.run_handling([this]() {return get_prompt(); }, "");
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::stop()
{
  m_cmd_binder.stop_handling();
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::account(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  // Usage:
  //   account
  //   account new <label text with white spaces allowed>
  //   account switch <index>
  //   account label <index> <label text with white spaces allowed>
  //   account tag <tag_name> <account_index_1> [<account_index_2> ...]
  //   account untag <account_index_1> [<account_index_2> ...]
  //   account tag_description <tag_name> <description>

  if (args.empty())
  {
    // print all the existing accounts
    LOCK_IDLE_SCOPE();
    print_accounts();
    return true;
  }

  std::vector<std::string> local_args = args;
  std::string command = local_args[0];
  local_args.erase(local_args.begin());
  if (command == "new")
  {
    // create a new account and switch to it
    std::string label = tools::join(" ", local_args);
    if (label.empty())
      label = tr("(Untitled account)");
    m_wallet->add_subaddress_account(label);
    m_current_subaddress_account = m_wallet->get_num_subaddress_accounts() - 1;
    // update_prompt();
    LOCK_IDLE_SCOPE();
    print_accounts();
  }
  else if (command == "switch" && local_args.size() == 1)
  {
    // switch to the specified account
    uint32_t index_major;
    if (!epee::string_tools::get_xtype_from_string(index_major, local_args[0]))
    {
      fail_msg_writer() << tr("failed to parse index: ") << local_args[0];
      return true;
    }
    if (index_major >= m_wallet->get_num_subaddress_accounts())
    {
      fail_msg_writer() << tr("specify an index between 0 and ") << (m_wallet->get_num_subaddress_accounts() - 1);
      return true;
    }
    m_current_subaddress_account = index_major;
    // update_prompt();
    show_balance();
  }
  else if (command == "label" && local_args.size() >= 1)
  {
    // set label of the specified account
    uint32_t index_major;
    if (!epee::string_tools::get_xtype_from_string(index_major, local_args[0]))
    {
      fail_msg_writer() << tr("failed to parse index: ") << local_args[0];
      return true;
    }
    local_args.erase(local_args.begin());
    std::string label = tools::join(" ", local_args);
    try
    {
      m_wallet->set_subaddress_label({index_major, 0}, label);
      LOCK_IDLE_SCOPE();
      print_accounts();
    }
    catch (const std::exception& e)
    {
      fail_msg_writer() << e.what();
    }
  }
  else if (command == "tag" && local_args.size() >= 2)
  {
    const std::string tag = local_args[0];
    std::set<uint32_t> account_indices;
    for (size_t i = 1; i < local_args.size(); ++i)
    {
      uint32_t account_index;
      if (!epee::string_tools::get_xtype_from_string(account_index, local_args[i]))
      {
        fail_msg_writer() << tr("failed to parse index: ") << local_args[i];
        return true;
      }
      account_indices.insert(account_index);
    }
    try
    {
      m_wallet->set_account_tag(account_indices, tag);
      print_accounts(tag);
    }
    catch (const std::exception& e)
    {
      fail_msg_writer() << e.what();
    }
  }
  else if (command == "untag" && local_args.size() >= 1)
  {
    std::set<uint32_t> account_indices;
    for (size_t i = 0; i < local_args.size(); ++i)
    {
      uint32_t account_index;
      if (!epee::string_tools::get_xtype_from_string(account_index, local_args[i]))
      {
        fail_msg_writer() << tr("failed to parse index: ") << local_args[i];
        return true;
      }
      account_indices.insert(account_index);
    }
    try
    {
      m_wallet->set_account_tag(account_indices, "");
      print_accounts();
    }
    catch (const std::exception& e)
    {
      fail_msg_writer() << e.what();
    }
  }
  else if (command == "tag_description" && local_args.size() >= 1)
  {
    const std::string tag = local_args[0];
    std::string description;
    if (local_args.size() > 1)
    {
      local_args.erase(local_args.begin());
      description = tools::join(" ", local_args);
    }
    try
    {
      m_wallet->set_account_tag_description(tag, description);
      print_accounts(tag);
    }
    catch (const std::exception& e)
    {
      fail_msg_writer() << e.what();
    }
  }
  else
  {
    PRINT_USAGE(USAGE_ACCOUNT);
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::print_accounts()
{
  const std::pair<std::map<std::string, std::string>, std::vector<std::string>>& account_tags = m_wallet->get_account_tags();
  size_t num_untagged_accounts = m_wallet->get_num_subaddress_accounts();
  for (const auto& p : account_tags.first)
  {
    const std::string& tag = p.first;
    print_accounts(tag);
    num_untagged_accounts -= std::count(account_tags.second.begin(), account_tags.second.end(), tag);
    success_msg_writer() << "";
  }

  if (num_untagged_accounts > 0)
    print_accounts("");

  if (num_untagged_accounts < m_wallet->get_num_subaddress_accounts())
    success_msg_writer() << tr("\nGrand total:\n  Balance: ") << print_money(m_wallet->balance_all(false)) << tr(", unlocked balance: ") << print_money(m_wallet->unlocked_balance_all(false));
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::print_accounts(const std::string& tag)
{
  const std::pair<std::map<std::string, std::string>, std::vector<std::string>>& account_tags = m_wallet->get_account_tags();
  if (tag.empty())
  {
    success_msg_writer() << tr("Untagged accounts:");
  }
  else
  {
    if (account_tags.first.count(tag) == 0)
    {
      fail_msg_writer() << boost::format(tr("Tag %s is unregistered.")) % tag;
      return;
    }
    success_msg_writer() << tr("Accounts with tag: ") << tag;
    success_msg_writer() << tr("Tag's description: ") << account_tags.first.find(tag)->second;
  }
  success_msg_writer() << boost::format("  %15s %21s %21s %21s %21s") % tr("Address") % tr("Balance") % tr("Unlocked balance") % tr("Batched Amount") % tr("Label");
  uint64_t total_balance = 0, total_unlocked_balance = 0;
  for (uint32_t account_index = 0; account_index < m_wallet->get_num_subaddress_accounts(); ++account_index)
  {
    std::string address_str = m_wallet->get_subaddress_as_str({account_index, 0}).substr(0, 6);
    if (account_tags.second[account_index] != tag)
      continue;
    success_msg_writer() << boost::format(tr(" %c%8u %6s %21s %21s %21s %21s"))
      % (m_current_subaddress_account == account_index ? '*' : ' ')
      % account_index
      % address_str
      % print_money(m_wallet->balance(account_index, false))
      % print_money(m_wallet->unlocked_balance(account_index, false))
      % print_money(m_wallet->get_batched_amount(address_str))
      % m_wallet->get_subaddress_label({account_index, 0});
    total_balance += m_wallet->balance(account_index, false);
    total_unlocked_balance += m_wallet->unlocked_balance(account_index, false);
  }
  success_msg_writer() << tr("----------------------------------------------------------------------------------");
  success_msg_writer() << boost::format(tr("%15s %21s %21s")) % "Total" % print_money(total_balance) % print_money(total_unlocked_balance);
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::print_address(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  // Usage:
  //  address
  //  address new <label text with white spaces allowed>
  //  address all
  //  address <index_min> [<index_max>]
  //  address label <index> <label text with white spaces allowed>
  //  address device [<index>]

  std::vector<std::string> local_args = args;
  tools::wallet2::transfer_container transfers;
  m_wallet->get_transfers(transfers);

  auto print_address_sub = [this, &transfers](uint32_t index)
  {
    bool used = std::find_if(
      transfers.begin(), transfers.end(),
      [this, &index](const wallet::transfer_details& td) {
        return td.m_subaddr_index == cryptonote::subaddress_index{ m_current_subaddress_account, index };
      }) != transfers.end();
    success_msg_writer() << index << "  " << m_wallet->get_subaddress_as_str({m_current_subaddress_account, index}) << "  " << (index == 0 ? tr("Primary address") : m_wallet->get_subaddress_label({m_current_subaddress_account, index})) << " " << (used ? tr("(used)") : "");
  };

  uint32_t index = 0;
  if (local_args.empty())
  {
    print_address_sub(index);
  }
  else if (local_args.size() == 1 && local_args[0] == "all")
  {
    local_args.erase(local_args.begin());
    for (; index < m_wallet->get_num_subaddresses(m_current_subaddress_account); ++index)
      print_address_sub(index);
  }
  else if (local_args[0] == "new")
  {
    local_args.erase(local_args.begin());
    std::string label;
    if (local_args.size() > 0)
      label = tools::join(" ", local_args);
    if (label.empty())
      label = tr("(Untitled address)");
    m_wallet->add_subaddress(m_current_subaddress_account, label);
    print_address_sub(m_wallet->get_num_subaddresses(m_current_subaddress_account) - 1);
    m_wallet->device_show_address(m_current_subaddress_account, m_wallet->get_num_subaddresses(m_current_subaddress_account) - 1, std::nullopt);
  }
  else if (local_args.size() >= 2 && local_args[0] == "label")
  {
    if (!epee::string_tools::get_xtype_from_string(index, local_args[1]))
    {
      fail_msg_writer() << tr("failed to parse index: ") << local_args[1];
      return true;
    }
    if (index >= m_wallet->get_num_subaddresses(m_current_subaddress_account))
    {
      fail_msg_writer() << tr("specify an index between 0 and ") << (m_wallet->get_num_subaddresses(m_current_subaddress_account) - 1);
      return true;
    }
    local_args.erase(local_args.begin());
    local_args.erase(local_args.begin());
    std::string label = tools::join(" ", local_args);
    m_wallet->set_subaddress_label({m_current_subaddress_account, index}, label);
    print_address_sub(index);
  }
  else if (local_args.size() <= 2 && epee::string_tools::get_xtype_from_string(index, local_args[0]))
  {
    local_args.erase(local_args.begin());
    uint32_t index_min = index;
    uint32_t index_max = index_min;
    if (local_args.size() > 0)
    {
      if (!epee::string_tools::get_xtype_from_string(index_max, local_args[0]))
      {
        fail_msg_writer() << tr("failed to parse index: ") << local_args[0];
        return true;
      }
      local_args.erase(local_args.begin());
    }
    if (index_max < index_min)
      std::swap(index_min, index_max);
    if (index_min >= m_wallet->get_num_subaddresses(m_current_subaddress_account))
    {
      fail_msg_writer() << tr("<index_min> is already out of bound");
      return true;
    }
    if (index_max >= m_wallet->get_num_subaddresses(m_current_subaddress_account))
    {
      message_writer() << tr("<index_max> exceeds the bound");
      index_max = m_wallet->get_num_subaddresses(m_current_subaddress_account) - 1;
    }
    for (index = index_min; index <= index_max; ++index)
      print_address_sub(index);
  }
  else if (local_args[0] == "device")
  {
    index = 0;
    local_args.erase(local_args.begin());
    if (local_args.size() > 0)
    {
      if (!epee::string_tools::get_xtype_from_string(index, local_args[0]))
      {
        fail_msg_writer() << tr("failed to parse index: ") << local_args[0];
        return true;
      }
      if (index >= m_wallet->get_num_subaddresses(m_current_subaddress_account))
      {
        fail_msg_writer() << tr("<index> is out of bounds");
        return true;
      }
    }

    print_address_sub(index);
    m_wallet->device_show_address(m_current_subaddress_account, index, std::nullopt);
  }
  else
  {
    PRINT_USAGE(USAGE_ADDRESS);
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::print_integrated_address(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  crypto::hash8 payment_id;
  bool display_on_device = false;
  std::vector<std::string> local_args = args;

  if (local_args.size() > 0 && local_args[0] == "device")
  {
    local_args.erase(local_args.begin());
    display_on_device = true;
  }

  auto device_show_integrated = [this, display_on_device](crypto::hash8 payment_id)
  {
    if (display_on_device)
    {
      m_wallet->device_show_address(m_current_subaddress_account, 0, payment_id);
    }
  };

  if (local_args.size() > 1)
  {
    PRINT_USAGE(USAGE_INTEGRATED_ADDRESS);
    return true;
  }
  if (local_args.size() == 0)
  {
    if (m_current_subaddress_account != 0)
    {
      fail_msg_writer() << tr("Integrated addresses can only be created for account 0");
      return true;
    }
    payment_id = crypto::rand<crypto::hash8>();
    success_msg_writer() << tr("Random payment ID: ") << payment_id;
    success_msg_writer() << tr("Matching integrated address: ") << m_wallet->get_account().get_public_integrated_address_str(payment_id, m_wallet->nettype());
    device_show_integrated(payment_id);
    return true;
  }
  if(tools::hex_to_type(local_args.back(), payment_id))
  {
    if (m_current_subaddress_account != 0)
    {
      fail_msg_writer() << tr("Integrated addresses can only be created for account 0");
      return true;
    }
    success_msg_writer() << m_wallet->get_account().get_public_integrated_address_str(payment_id, m_wallet->nettype());
    device_show_integrated(payment_id);
    return true;
  }
  else {
    address_parse_info info;
    if(get_account_address_from_str(info, m_wallet->nettype(), local_args.back()))
    {
      if (info.has_payment_id)
      {
        success_msg_writer() << boost::format(tr("Integrated address: %s, payment ID: %s")) %
          get_account_address_as_str(m_wallet->nettype(), false, info.address) % tools::type_to_hex(info.payment_id);
        device_show_integrated(info.payment_id);
      }
      else
      {
        success_msg_writer() << (info.is_subaddress ? tr("Subaddress: ") : tr("Standard address: ")) << get_account_address_as_str(m_wallet->nettype(), info.is_subaddress, info.address);
      }
      return true;
    }
  }
  fail_msg_writer() << tr("failed to parse payment ID or address");
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::address_book(const std::vector<std::string> &args/* = std::vector<std::string>()*/)
{
  if (args.size() == 0)
  {
  }
  else if (args.size() == 1 || (args[0] != "add" && args[0] != "delete"))
  {
    PRINT_USAGE(USAGE_ADDRESS_BOOK);
    return true;
  }
  else if (args[0] == "add")
  {
    cryptonote::address_parse_info info;
    if(!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), args[1]))
    {
      fail_msg_writer() << tr("failed to parse address");
      return true;
    }
    size_t description_start = 2;
    std::string description;
    for (size_t i = description_start; i < args.size(); ++i)
    {
      if (i > description_start)
        description += " ";
      description += args[i];
    }
    m_wallet->add_address_book_row(info.address, info.has_payment_id ? &info.payment_id : NULL, description, info.is_subaddress);
  }
  else
  {
    size_t row_id;
    if(!epee::string_tools::get_xtype_from_string(row_id, args[1]))
    {
      fail_msg_writer() << tr("failed to parse index");
      return true;
    }
    m_wallet->delete_address_book_row(row_id);
  }
  auto address_book = m_wallet->get_address_book();
  if (address_book.empty())
  {
    success_msg_writer() << tr("Address book is empty.");
  }
  else
  {
    for (size_t i = 0; i < address_book.size(); ++i) {
      auto& row = address_book[i];
      success_msg_writer() << tr("Index: ") << i;
      std::string address;
      if (row.m_has_payment_id)
        address = cryptonote::get_account_integrated_address_as_str(m_wallet->nettype(), row.m_address, row.m_payment_id);
      else
        address = get_account_address_as_str(m_wallet->nettype(), row.m_is_subaddress, row.m_address);
      success_msg_writer() << tr("Address: ") << address;
      success_msg_writer() << tr("Description: ") << row.m_description << "\n";
    }
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::set_tx_note(const std::vector<std::string> &args)
{
  if (args.size() == 0)
  {
    PRINT_USAGE(USAGE_SET_TX_NOTE);
    return true;
  }

  crypto::hash txid;
  if (!tools::hex_to_type(args.front(), txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  std::string note = "";
  for (size_t n = 1; n < args.size(); ++n)
  {
    if (n > 1)
      note += " ";
    note += args[n];
  }
  m_wallet->set_tx_note(txid, note);

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::get_tx_note(const std::vector<std::string> &args)
{
  if (args.size() != 1)
  {
    PRINT_USAGE(USAGE_GET_TX_NOTE);
    return true;
  }

  crypto::hash txid;
  if (!tools::hex_to_type(args.front(), txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  std::string note = m_wallet->get_tx_note(txid);
  if (note.empty())
    success_msg_writer() << "no note found";
  else
    success_msg_writer() << "note found: " << note;

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::set_description(const std::vector<std::string> &args)
{
  // 0 arguments allowed, for setting the description to empty string

  std::string description = "";
  for (size_t n = 0; n < args.size(); ++n)
  {
    if (n > 0)
      description += " ";
    description += args[n];
  }
  m_wallet->set_description(description);

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::get_description(const std::vector<std::string> &args)
{
  if (args.size() != 0)
  {
    PRINT_USAGE(USAGE_GET_DESCRIPTION);
    return true;
  }

  std::string description = m_wallet->get_description();
  if (description.empty())
    success_msg_writer() << tr("no description found");
  else
    success_msg_writer() << tr("description found: ") << description;

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::status(const std::vector<std::string> &args)
{
  uint64_t local_height = m_wallet->get_blockchain_current_height();
  rpc::version_t version;
  bool ssl = false;
  if (!m_wallet->check_connection(&version, &ssl))
  {
    success_msg_writer() << "Refreshed " << local_height << "/?, no daemon connected";
    return true;
  }

  std::string err;
  uint64_t bc_height = get_daemon_blockchain_height(err);
  if (err.empty())
  {
    bool synced = local_height == bc_height;
    success_msg_writer() << "Refreshed " << local_height << "/" << bc_height << ", " << (synced ? "synced" : "syncing")
        << ", daemon RPC v" << version.first << '.' << version.second << ", " << (ssl ? "SSL" : "no SSL");
  }
  else
  {
    fail_msg_writer() << "Refreshed " << local_height << "/?, daemon connection error";
  }
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::wallet_info(const std::vector<std::string> &args)
{
  bool ready;
  uint32_t threshold, total;
  std::string description = m_wallet->get_description();
  if (description.empty())
  {
    description = "<Not set>";
  }
  message_writer() << tr("Filename: ") << m_wallet->get_wallet_file();
  message_writer() << tr("Description: ") << description;
  message_writer() << tr("Address: ") << m_wallet->get_account().get_public_address_str(m_wallet->nettype());
  std::string type;
  if (m_wallet->watch_only())
    type = tr("Watch only");
  else if (m_wallet->multisig(&ready, &threshold, &total))
    type = (boost::format(tr("%u/%u multisig%s")) % threshold % total % (ready ? "" : " (not yet finalized)")).str();
  else
    type = tr("Normal");
  message_writer() << tr("Type: ") << type;
  message_writer() << tr("Network type: ") << (
    m_wallet->nettype() == cryptonote::network_type::TESTNET ? tr("Testnet") :
    m_wallet->nettype() == cryptonote::network_type::DEVNET ? tr("Devnet") : tr("Mainnet"));
  return true;
}

bool simple_wallet::sign_string(std::string_view value, const subaddress_index& index)
{
  if (m_wallet->key_on_device())
    fail_msg_writer() << tr("command not supported by HW wallet");
  else if (m_wallet->watch_only())
    fail_msg_writer() << tr("wallet is watch-only and cannot sign");
  else if (m_wallet->multisig())
    fail_msg_writer() << tr("This wallet is multisig and cannot sign");
  else
  {
    SCOPED_WALLET_UNLOCK();

    std::string addr = get_account_address_as_str(m_wallet->nettype(), !index.is_zero(), m_wallet->get_subaddress(index));
    std::string signature = m_wallet->sign(value, index);
    // Print the string directly if it's ascii without control characters, up to 100 bytes, and
    // doesn't contain any doubled, leading, or trailing spaces (because we can't feed those back
    // into verify_value in the cli wallet).
    bool printable = value.size() <= 100 && !tools::starts_with(value, " ") && !tools::ends_with(value, " ") && value.find("  ") == std::string::npos &&
        std::all_of(value.begin(), value.end(), [](char x) { return x >= ' ' && x <= '~'; });

    success_msg_writer()
        << "Address:   " << addr << "\n"
        << "Value:     " << (printable ? std::string{value} : "(" + std::to_string(value.size()) + " bytes)") << "\n"
        << "Signature: " << signature;
  }
  return true;
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::sign(const std::vector<std::string> &args)
{
  if (args.size() != 1 && args.size() != 2)
  {
    PRINT_USAGE(USAGE_SIGN);
    return true;
  }

  subaddress_index index{0, 0};
  if (args.size() == 2)
  {
    auto pieces = tools::split(args[0], ",");
    if (pieces.size() != 2 || !tools::parse_int(pieces[0], index.major) || !tools::parse_int(pieces[1], index.minor))
    {
      fail_msg_writer() << tr("Invalid subaddress index format");
      return true;
    }
  }

  const fs::path filename = fs::u8path(args.back());
  std::string data;
  if (!tools::slurp_file(filename, data))
  {
    fail_msg_writer() << tr("failed to read file ") << filename.u8string();
    return true;
  }

  return sign_string(data, index);
}

bool simple_wallet::verify_string(std::string_view value, std::string_view address, std::string_view signature)
{
  cryptonote::address_parse_info info;
  if(!cryptonote::get_account_address_from_str(info, m_wallet->nettype(), address))
    fail_msg_writer() << tr("failed to parse address");
  else if (!m_wallet->verify(value, info.address, signature))
    fail_msg_writer() << tr("Bad signature from ") << address;
  else
    success_msg_writer(true) << tr("Good signature from ") << address;

  return true;
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::verify(const std::vector<std::string> &args)
{
  if (args.size() != 3)
  {
    PRINT_USAGE(USAGE_VERIFY);
    return true;
  }
  fs::path filename = fs::u8path(args[0]);
  std::string data;
  if (!tools::slurp_file(filename, data))
  {
    fail_msg_writer() << tr("failed to read file ") << filename.u8string();
    return true;
  }
  return verify_string(data, args[1], args[2]);
}

bool simple_wallet::sign_value(const std::vector<std::string> &args)
{
  if (args.size() < 1)
  {
    PRINT_USAGE(USAGE_SIGN_VALUE);
    return true;
  }

  auto begin = args.begin(), end = args.end();

  subaddress_index index{0, 0};
  if (args[0].find(',') != std::string::npos && args[0].find_first_not_of(",0123456789") == std::string::npos)
  {
    // First argument is a x,y account/subaddress string, so consume it.
    auto pieces = tools::split(args[0], ",");
    if (pieces.size() != 2 || !tools::parse_int(pieces[0], index.major) || !tools::parse_int(pieces[1], index.minor))
    {
      fail_msg_writer() << tr("Invalid subaddress index format");
      return true;
    }
    begin++;
  }

  if (begin == end)
  {
    PRINT_USAGE(USAGE_SIGN_VALUE);
    return true;
  }

  // Argument parsing has split it up on spaces, so rejoin it.  This will break if you have multiple
  // sequential spaces or tabs or something, but in that case you should be using the `sign` (file)
  // command.
  std::string value = tools::join(" ", begin, end);
  return sign_string(value, index);
}

bool simple_wallet::verify_value(const std::vector<std::string> &args)
{
  if (args.size() < 3)
  {
    PRINT_USAGE(USAGE_VERIFY_VALUE);
    return true;
  }
  return verify_string(tools::join(" ", args.begin()+2, args.end()), args[0], args[1]);
}

//----------------------------------------------------------------------------------------------------
bool simple_wallet::export_key_images(const std::vector<std::string> &args)
{
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return true;
  }
  if (args.size() != 1 && args.size() != 2)
  {
    PRINT_USAGE(USAGE_EXPORT_KEY_IMAGES);
    return true;
  }
  if (m_wallet->watch_only())
  {
    fail_msg_writer() << tr("wallet is watch-only and cannot export key images");
    return true;
  }

  fs::path filename = fs::u8path(args[0]);
  if (m_wallet->confirm_export_overwrite() && !check_file_overwrite(filename))
    return true;

  SCOPED_WALLET_UNLOCK();

  try
  {
    /// whether to export requested key images only
    bool requested_only = (args.size() == 2 && args[1] == "requested-only");
    if (!m_wallet->export_key_images_to_file(filename, requested_only))
    {
      fail_msg_writer() << tr("failed to save file ") << filename.u8string();
      return true;
    }
  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Error exporting key images: " << e.what());
    fail_msg_writer() << "Error exporting key images: " << e.what();
    return true;
  }

  success_msg_writer() << tr("Signed key images exported to ") << filename.u8string();
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::import_key_images(const std::vector<std::string> &args)
{
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return true;
  }
  if (!m_wallet->is_trusted_daemon())
  {
    fail_msg_writer() << tr("this command requires a trusted daemon. Enable with --trusted-daemon");
    return true;
  }

  if (args.size() != 1)
  {
    PRINT_USAGE(USAGE_IMPORT_KEY_IMAGES);
    return true;
  }

  const fs::path filename = fs::u8path(args[0]);
  LOCK_IDLE_SCOPE();
  try
  {
    uint64_t spent = 0, unspent = 0;
    uint64_t height = m_wallet->import_key_images_from_file(filename, spent, unspent);
    success_msg_writer() << "Signed key images imported to height " << height << ", "
        << print_money(spent) << " spent, " << print_money(unspent) << " unspent";
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << "Failed to import key images: " << e.what();
    return true;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::hw_key_images_sync(const std::vector<std::string> &args)
{
  if (!m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command only supported by HW wallet");
    return true;
  }
  if (!m_wallet->get_account().get_device().has_ki_cold_sync())
  {
    fail_msg_writer() << tr("hw wallet does not support cold KI sync");
    return true;
  }

  LOCK_IDLE_SCOPE();
  key_images_sync_intern();
  return true;
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::key_images_sync_intern(){
  try
  {
    message_writer(epee::console_color_white, false) << tr("Please confirm the key image sync on the device");

    uint64_t spent = 0, unspent = 0;
    uint64_t height = m_wallet->cold_key_image_sync(spent, unspent);
    if (height > 0)
    {
      success_msg_writer() << tr("Key images synchronized to height ") << height;
      if (!m_wallet->is_trusted_daemon())
      {
        message_writer() << tr("Running untrusted daemon, cannot determine which transaction output is spent. Use a trusted daemon with --trusted-daemon and run rescan_spent");
      } else
      {
        success_msg_writer() << print_money(spent) << tr(" spent, ") << print_money(unspent) << tr(" unspent");
      }
    }
    else {
      fail_msg_writer() << tr("Failed to import key images");
    }
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("Failed to import key images: ") << e.what();
  }
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::hw_reconnect(const std::vector<std::string> &args)
{
  if (!m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command only supported by HW wallet");
    return true;
  }

  LOCK_IDLE_SCOPE();
  try
  {
    bool r = m_wallet->reconnect_device();
    if (!r){
      fail_msg_writer() << tr("Failed to reconnect device");
    }
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << tr("Failed to reconnect device: ") << tr(e.what());
    return true;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::export_outputs(const std::vector<std::string> &args)
{
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return true;
  }

  if (args.size() >= 3 || args.empty())
  {
    PRINT_USAGE(USAGE_EXPORT_OUTPUTS);
    return true;
  }

  int filename_index = 0;
  bool all           = false;
  if (args.size() == 2 && args[0] == "all")
  {
    filename_index++;
    all = true;
  }

  const fs::path filename = fs::u8path(args[filename_index]);
  if (m_wallet->confirm_export_overwrite() && !check_file_overwrite(filename))
    return true;

  SCOPED_WALLET_UNLOCK();

  try
  {
    std::string data = m_wallet->export_outputs_to_str(all);
    bool r = tools::dump_file(filename, data);
    if (!r)
    {
      fail_msg_writer() << tr("failed to save file ") << filename.u8string();
      return true;
    }
  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Error exporting outputs: " << e.what());
    fail_msg_writer() << "Error exporting outputs: " << e.what();
    return true;
  }

  success_msg_writer() << tr("Outputs exported to ") << filename.u8string();
  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::import_outputs(const std::vector<std::string> &args)
{
  if (m_wallet->key_on_device())
  {
    fail_msg_writer() << tr("command not supported by HW wallet");
    return true;
  }
  if (args.size() != 1)
  {
    PRINT_USAGE(USAGE_IMPORT_OUTPUTS);
    return true;
  }
  const fs::path filename = fs::u8path(args[0]);

  std::string data;
  bool r = tools::slurp_file(filename, data);
  if (!r)
  {
    fail_msg_writer() << tr("failed to read file ") << filename.u8string();
    return true;
  }

  try
  {
    SCOPED_WALLET_UNLOCK();
    size_t n_outputs = m_wallet->import_outputs_from_str(data);
    success_msg_writer() << boost::lexical_cast<std::string>(n_outputs) << " outputs imported";
  }
  catch (const std::exception &e)
  {
    fail_msg_writer() << "Failed to import outputs " << filename.u8string() << ": " << e.what();
    return true;
  }

  return true;
}
//----------------------------------------------------------------------------------------------------
bool simple_wallet::show_transfer(const std::vector<std::string> &args)
{
  if (args.size() != 1)
  {
    PRINT_USAGE(USAGE_SHOW_TRANSFER);
    return true;
  }

  crypto::hash txid;
  if (!tools::hex_to_type(args.front(), txid))
  {
    fail_msg_writer() << tr("failed to parse txid");
    return true;
  }

  const uint64_t last_block_height = m_wallet->get_blockchain_current_height();

  std::list<std::pair<crypto::hash, tools::wallet2::payment_details>> payments;
  m_wallet->get_payments(payments, 0, (uint64_t)-1, m_current_subaddress_account);
  for (std::list<std::pair<crypto::hash, tools::wallet2::payment_details>>::const_iterator i = payments.begin(); i != payments.end(); ++i) {
    const tools::wallet2::payment_details &pd = i->second;
    if (pd.m_tx_hash == txid) {
      std::string payment_id = tools::type_to_hex(i->first);
      if (payment_id.substr(16).find_first_not_of('0') == std::string::npos)
        payment_id = payment_id.substr(0,16);
      success_msg_writer() << "Incoming transaction found";
      success_msg_writer() << "txid: " << txid;
      if (pd.m_block_height == 0 && pd.m_unmined_blink)
        success_msg_writer() << "Height: blink (not yet mined)";
      else
        success_msg_writer() << "Height: " << pd.m_block_height;
      success_msg_writer() << "Timestamp: " << tools::get_human_readable_timestamp(pd.m_timestamp);
      success_msg_writer() << "Amount: " << print_money(pd.m_amount);
      success_msg_writer() << "Payment ID: " << payment_id;
      if (pd.m_unlock_time < MAX_BLOCK_NUMBER)
      {
        uint64_t bh = std::max(pd.m_unlock_time, pd.m_block_height + DEFAULT_TX_SPENDABLE_AGE);
        uint64_t suggested_threshold = 0;
        if (!pd.m_unmined_blink)
        {
          uint64_t last_block_reward = m_wallet->get_last_block_reward();
          suggested_threshold = last_block_reward ? (pd.m_amount + last_block_reward - 1) / last_block_reward : 0;
        }
        if (bh >= last_block_height)
          success_msg_writer() << "Locked: " << (bh - last_block_height) << " blocks to unlock";
        else if (suggested_threshold > 0)
          success_msg_writer() << std::to_string(last_block_height - bh) << " confirmations (" << suggested_threshold << " suggested threshold)";
        else if (!pd.m_unmined_blink)
          success_msg_writer() << std::to_string(last_block_height - bh) << " confirmations";
      }
      else
      {
        uint64_t current_time = static_cast<uint64_t>(time(NULL));
        uint64_t threshold = current_time + tools::to_seconds(LOCKED_TX_ALLOWED_DELTA_BLOCKS * TARGET_BLOCK_TIME);
        if (threshold >= pd.m_unlock_time)
          success_msg_writer() << "unlocked for " << tools::get_human_readable_timespan(std::chrono::seconds(threshold - pd.m_unlock_time));
        else
          success_msg_writer() << "locked for " << tools::get_human_readable_timespan(std::chrono::seconds(pd.m_unlock_time - threshold));
      }
      success_msg_writer() << "Checkpointed: " << (pd.m_unmined_blink ? "Blink" : pd.m_block_height <= m_wallet->get_immutable_height() ? "Yes" : pd.m_was_blink ? "Blink" : "No");
      success_msg_writer() << "Address index: " << pd.m_subaddr_index.minor;
      success_msg_writer() << "Note: " << m_wallet->get_tx_note(txid);
      return true;
    }
  }

  std::list<std::pair<crypto::hash, tools::wallet2::confirmed_transfer_details>> payments_out;
  m_wallet->get_payments_out(payments_out, 0, (uint64_t)-1, m_current_subaddress_account);
  for (std::list<std::pair<crypto::hash, tools::wallet2::confirmed_transfer_details>>::const_iterator i = payments_out.begin(); i != payments_out.end(); ++i) {
    if (i->first == txid)
    {
      const tools::wallet2::confirmed_transfer_details &pd = i->second;
      uint64_t change = pd.m_change == (uint64_t)-1 ? 0 : pd.m_change; // change may not be known
      uint64_t fee = pd.m_amount_in - pd.m_amount_out;
      std::string dests;
      for (const auto &d: pd.m_dests) {
        if (!dests.empty())
          dests += ", ";
        dests +=  d.address(m_wallet->nettype(), pd.m_payment_id) + ": " + print_money(d.amount);
      }
      std::string payment_id = tools::type_to_hex(i->second.m_payment_id);
      if (payment_id.substr(16).find_first_not_of('0') == std::string::npos)
        payment_id = payment_id.substr(0,16);
      success_msg_writer() << "Outgoing transaction found";
      success_msg_writer() << "txid: " << txid;
      success_msg_writer() << "Height: " << pd.m_block_height;
      success_msg_writer() << "Timestamp: " << tools::get_human_readable_timestamp(pd.m_timestamp);
      success_msg_writer() << "Amount: " << print_money(pd.m_amount_in - change - fee);
      success_msg_writer() << "Payment ID: " << payment_id;
      success_msg_writer() << "Change: " << print_money(change);
      success_msg_writer() << "Fee: " << print_money(fee);
      success_msg_writer() << "Destinations: " << dests;
      if (pd.m_unlock_time < MAX_BLOCK_NUMBER)
      {
        uint64_t bh = std::max(pd.m_unlock_time, pd.m_block_height + DEFAULT_TX_SPENDABLE_AGE);
        if (bh >= last_block_height)
          success_msg_writer() << "Locked: " << (bh - last_block_height) << " blocks to unlock";
        else
          success_msg_writer() << std::to_string(last_block_height - bh) << " confirmations";
      }
      else
      {
        uint64_t current_time = static_cast<uint64_t>(time(NULL));
        uint64_t threshold = current_time + tools::to_seconds(LOCKED_TX_ALLOWED_DELTA_BLOCKS * TARGET_BLOCK_TIME);
        if (threshold >= pd.m_unlock_time)
          success_msg_writer() << "unlocked for " << tools::get_human_readable_timespan(std::chrono::seconds(threshold - pd.m_unlock_time));
        else
          success_msg_writer() << "locked for " << tools::get_human_readable_timespan(std::chrono::seconds(pd.m_unlock_time - threshold));
      }
      success_msg_writer() << "Note: " << m_wallet->get_tx_note(txid);
      return true;
    }
  }

  try
  {
    std::list<std::pair<crypto::hash, tools::wallet2::pool_payment_details>> pool_payments;
    m_wallet->get_unconfirmed_payments(pool_payments, m_current_subaddress_account);
    for (std::list<std::pair<crypto::hash, tools::wallet2::pool_payment_details>>::const_iterator i = pool_payments.begin(); i != pool_payments.end(); ++i) {
      const tools::wallet2::payment_details &pd = i->second.m_pd;
      if (pd.m_tx_hash == txid)
      {
        std::string payment_id = tools::type_to_hex(i->first);
        if (payment_id.substr(16).find_first_not_of('0') == std::string::npos)
          payment_id = payment_id.substr(0,16);
        success_msg_writer() << "Unconfirmed incoming transaction found in the txpool";
        success_msg_writer() << "txid: " << txid;
        success_msg_writer() << "Timestamp: " << tools::get_human_readable_timestamp(pd.m_timestamp);
        success_msg_writer() << "Amount: " << print_money(pd.m_amount);
        success_msg_writer() << "Payment ID: " << payment_id;
        success_msg_writer() << "Address index: " << pd.m_subaddr_index.minor;
        success_msg_writer() << "Note: " << m_wallet->get_tx_note(txid);
        if (i->second.m_double_spend_seen)
          success_msg_writer() << tr("Double spend seen on the network: this transaction may or may not end up being mined");
        return true;
      }
    }
  }
  catch (...)
  {
    fail_msg_writer() << "Failed to get pool state";
  }

  std::list<std::pair<crypto::hash, tools::wallet2::unconfirmed_transfer_details>> upayments;
  m_wallet->get_unconfirmed_payments_out(upayments, m_current_subaddress_account);
  for (std::list<std::pair<crypto::hash, tools::wallet2::unconfirmed_transfer_details>>::const_iterator i = upayments.begin(); i != upayments.end(); ++i) {
    if (i->first == txid)
    {
      const tools::wallet2::unconfirmed_transfer_details &pd = i->second;
      uint64_t amount = pd.m_amount_in;
      uint64_t fee = amount - pd.m_amount_out;
      std::string payment_id = tools::type_to_hex(i->second.m_payment_id);
      if (payment_id.substr(16).find_first_not_of('0') == std::string::npos)
        payment_id = payment_id.substr(0,16);
      bool is_failed = pd.m_state == tools::wallet2::unconfirmed_transfer_details::failed;

      success_msg_writer() << (is_failed ? "Failed" : "Pending") << " outgoing transaction found";
      success_msg_writer() << "txid: " << txid;
      success_msg_writer() << "Timestamp: " << tools::get_human_readable_timestamp(pd.m_timestamp);
      success_msg_writer() << "Amount: " << print_money(amount - pd.m_change - fee);
      success_msg_writer() << "Payment ID: " << payment_id;
      success_msg_writer() << "Change: " << print_money(pd.m_change);
      success_msg_writer() << "Fee: " << print_money(fee);
      success_msg_writer() << "Note: " << m_wallet->get_tx_note(txid);
      return true;
    }
  }

  fail_msg_writer() << tr("Transaction ID not found");
  return true;
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::interrupt()
{
  if (m_in_manual_refresh.load(std::memory_order_relaxed))
  {
    m_wallet->stop();
  }
  else
  {
    stop();
  }
}
//----------------------------------------------------------------------------------------------------
void simple_wallet::commit_or_save(std::vector<tools::wallet2::pending_tx>& ptx_vector, bool do_not_relay, bool blink)
{
  size_t i = 0;
  std::string msg_buf;
  msg_buf.reserve(128);

  while (!ptx_vector.empty())
  {
    msg_buf.clear();
    auto & ptx = ptx_vector.back();
    const crypto::hash txid = get_transaction_hash(ptx.tx);
    if (do_not_relay)
    {
      std::string blob;
      tx_to_blob(ptx.tx, blob);
      const std::string blob_hex = oxenc::to_hex(blob);
      fs::path filename = fs::u8path("raw_oxen_tx");
      if (ptx_vector.size() > 1) filename += "_" + std::to_string(i++);
      bool success = tools::dump_file(filename, blob_hex);

      if (success) msg_buf += tr("Transaction successfully saved to ");
      else         msg_buf += tr("Failed to save transaction to ");

      msg_buf += filename.u8string();
      msg_buf += tr(", txid <");
      msg_buf += tools::type_to_hex(txid);
      msg_buf += ">";

      if (success) success_msg_writer(true) << msg_buf;
      else         fail_msg_writer()        << msg_buf;
    }
    else
    {
      m_wallet->commit_tx(ptx, blink);
      msg_buf += tr("Transaction successfully submitted, transaction <");
      msg_buf += tools::type_to_hex(txid);
      msg_buf += ">\n";
      msg_buf += tr("You can check its status by using the `show_transfers` command.");
      success_msg_writer(true) << msg_buf;
    }
    // if no exception, remove element from vector
    ptx_vector.pop_back();
  }
}
//----------------------------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
  TRY_ENTRY();

  setlocale(LC_CTYPE, "");

  auto opt_size = command_line::boost_option_sizes();

  po::options_description desc_params(wallet_args::tr("Wallet options"), opt_size.first, opt_size.second);
  po::options_description hidden_params("Hidden");
  tools::wallet2::init_options(desc_params, hidden_params);
  command_line::add_arg(desc_params, arg_wallet_file);
  command_line::add_arg(desc_params, arg_generate_new_wallet);
  command_line::add_arg(desc_params, arg_generate_from_device);
  command_line::add_arg(desc_params, arg_generate_from_view_key);
  command_line::add_arg(desc_params, arg_generate_from_spend_key);
  command_line::add_arg(desc_params, arg_generate_from_keys);
  command_line::add_arg(desc_params, arg_generate_from_multisig_keys);
  command_line::add_arg(desc_params, arg_generate_from_json);
  command_line::add_arg(desc_params, arg_mnemonic_language);
  // Positional argument
  command_line::add_arg(hidden_params, arg_command);

  command_line::add_arg(desc_params, arg_restore_deterministic_wallet );
  command_line::add_arg(desc_params, arg_restore_multisig_wallet );
  command_line::add_arg(desc_params, arg_non_deterministic );
  command_line::add_arg(desc_params, arg_electrum_seed );
  command_line::add_arg(desc_params, arg_allow_mismatched_daemon_version);
  command_line::add_arg(desc_params, arg_restore_height);
  command_line::add_arg(desc_params, arg_restore_date);
  command_line::add_arg(desc_params, arg_do_not_relay);
  command_line::add_arg(desc_params, arg_create_address_file);
  command_line::add_arg(desc_params, arg_create_hwdev_txt);
  command_line::add_arg(desc_params, arg_subaddress_lookahead);
  command_line::add_arg(desc_params, arg_use_english_language_names);

  po::positional_options_description positional_options;
  positional_options.add(arg_command.name, -1);

  auto [vm, should_terminate] = wallet_args::main(
   argc, argv,
   "oxen-wallet-cli [--wallet-file=<filename>|--generate-new-wallet=<filename>] [<COMMAND>]",
    sw::tr("This is the command line Oxen wallet. It needs to connect to a Oxen\ndaemon to work correctly.\n\nWARNING: Do not reuse your Oxen keys on a contentious fork, doing so will harm your privacy.\n Only consider reusing your key on a contentious fork if the fork has key reuse mitigations built in."),
    desc_params,
    hidden_params,
    positional_options,
    [](const std::string &s, bool emphasis){ tools::scoped_message_writer(emphasis ? epee::console_color_white : epee::console_color_default, true) << s; },
    "oxen-wallet-cli.log"
  );

  if (!vm)
  {
    return 1;
  }

  if (should_terminate)
  {
    return 0;
  }

  cryptonote::simple_wallet w;
  const bool r = w.init(*vm);
  CHECK_AND_ASSERT_MES(r, 1, sw::tr("Failed to initialize wallet"));

  std::vector<std::string> command = command_line::get_arg(*vm, arg_command);
  if (!command.empty())
  {
    bool success = w.process_command_and_log(command);
    w.stop();
    w.deinit();
    return success ? 0 : 1;
  }

  tools::signal_handler::install([&w](int type) {
    if (tools::password_container::is_prompting.load())
    {
      // must be prompting for password so return and let the signal stop prompt
      return;
    }
#ifdef WIN32
    if (type == CTRL_C_EVENT)
#else
    if (type == SIGINT)
#endif
    {
      // if we're pressing ^C when refreshing, just stop refreshing
      w.interrupt();
    }
    else
    {
      w.stop();
    }
  });
  w.run();

  w.deinit();
  return 0;
  CATCH_ENTRY_L0("main", 1);
}

#ifdef WALLET_ENABLE_MMS
#include "simplewallet-mms.inl"
#endif
