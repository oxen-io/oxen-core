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
#include <boost/format.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/algorithm/string.hpp>
#include <cstdint>
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include <chrono>
#include <exception>

#include "wallet_rpc_server_error_codes.h"
#include "wallet_rpc_server.h"
#include "wallet/wallet_args.h"
#include "common/command_line.h"
#include "common/i18n.h"
#include "common/signal_handler.h"
#include "cryptonote_config.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/account.h"
#include "multisig/multisig.h"
#include "epee/misc_language.h"
#include "epee/string_coding.h"
#include "epee/string_tools.h"
#include "crypto/hash.h"
#include "mnemonics/electrum-words.h"
#include "rpc/rpc_args.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "daemonizer/daemonizer.h"
#include "cryptonote_core/oxen_name_system.h"
#include "serialization/boost_std_variant.h"

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "wallet.rpc"

namespace rpc = cryptonote::rpc;
using namespace tools::wallet_rpc;

namespace
{
  constexpr auto DEFAULT_AUTO_REFRESH_PERIOD = 20s;

  const command_line::arg_descriptor<uint16_t, true> arg_rpc_bind_port = {"rpc-bind-port", "Sets bind port for server"};
  const command_line::arg_descriptor<bool> arg_disable_rpc_login = {"disable-rpc-login", "Disable HTTP authentication for RPC connections served by this process"};
  const command_line::arg_descriptor<bool> arg_restricted = {"restricted-rpc", "Restricts to view-only commands", false};
  const command_line::arg_descriptor<std::string> arg_wallet_dir = {"wallet-dir", "Directory for newly created wallets"};
  const command_line::arg_descriptor<bool> arg_prompt_for_password = {"prompt-for-password", "Prompts for password when not provided", false};

  constexpr const char default_rpc_username[] = "oxen";

  std::optional<tools::password_container> password_prompter(const char *prompt, bool verify)
  {
    auto pwd_container = tools::password_container::prompt(verify, prompt);
    if (!pwd_container)
    {
      MERROR("failed to read wallet password");
    }
    return pwd_container;
  }

  using rpc_func_data = std::pair<
    bool, // restricted
    std::string(*)( // function to invoke
      epee::serialization::portable_storage& ps,
      epee::serialization::storage_entry id,
      std::optional<epee::serialization::storage_entry> params,
      tools::wallet_rpc_server& server)>;

  template <typename RPC, std::enable_if_t<std::is_base_of_v<RPC_COMMAND, RPC>, int> = 0>
  void register_rpc_command(std::unordered_map<std::string, rpc_func_data>& regs)
  {
    using Request = typename RPC::request;
    using Response = typename RPC::response;
    /// check that wallet_rpc_server.invoke(Request) returns a Response; the code below
    /// will fail anyway if this isn't satisfied, but that compilation failure might be more cryptic.
    using invoke_return_type = decltype(std::declval<tools::wallet_rpc_server>().invoke(std::declval<Request&&>()));
    static_assert(std::is_same<Response, invoke_return_type>::value,
        "Unable to register RPC command: wallet_rpc_server::invoke(Request) is not defined or does not return a Response");
    rpc_func_data invoke = {
      std::is_base_of_v<RESTRICTED, RPC>,
      []( epee::serialization::portable_storage& ps,
          epee::serialization::storage_entry id,
          std::optional<epee::serialization::storage_entry> params,
          tools::wallet_rpc_server& server) {
        Request req{};
        if (params) {
          if (auto* section = std::get_if<epee::serialization::section>(&*params)) {
            if (!req.load(ps, section))
              throw tools::wallet_rpc_server::parse_error{"Failed to parse JSON parameters"};
          }
          else
            throw std::runtime_error{"only top-level JSON object values are currently supported"};
        }
        epee::json_rpc::response<Response> r{"2.0", server.invoke(std::move(req)), std::move(id)};
        std::string response;
        epee::serialization::store_t_to_json(r, response);
        if (response.capacity() > response.size())
          response += '\n';
        return response;
      }
    };

    for (const auto& name : RPC::names())
      regs.emplace(name, invoke);
  }


  template <typename... RPC>
  std::unordered_map<std::string, rpc_func_data> register_rpc_commands(tools::type_list<RPC...>) {
    std::unordered_map<std::string, rpc_func_data> regs;

    (register_rpc_command<RPC>(regs), ...);

    return regs;
  }

  const auto rpc_commands = register_rpc_commands(wallet_rpc_types{});

  // Thrown with a code and message to return a json_rpc error.
  class wallet_rpc_error : public std::runtime_error {
  public:
    int16_t code;
    std::string message;

    wallet_rpc_error(int16_t code, std::string message)
      : runtime_error{"Wallet rpc error: " + message + " (" + std::to_string(code) + ")"},
        code{code},
        message{std::move(message)}
    {}
  };

  uint32_t convert_priority(uint32_t priority)
  {
    // NOTE: Map all priorites to blink for backwards compatibility purposes
    // and leaving priority 'unimportant' or '1' as the only other alternative.
    uint32_t result = priority;
    if (result != tools::tx_priority_unimportant)
      result = tools::tx_priority_blink;
    return result;
  }

} // anon namespace

namespace tools
{
  const char* wallet_rpc_server::tr(const char* str)
  {
    return i18n_translate(str, "tools::wallet_rpc_server");
  }

  //------------------------------------------------------------------------------------------------------------------------------
  wallet_rpc_server::wallet_rpc_server(boost::program_options::variables_map vm)
  : rpc_login_file()
  , m_stop(false)
  , m_restricted(false)
  , m_vm(std::move(vm))
  {
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::create_rpc_endpoints(uWS::App& http)
  {
    http.post("/json_rpc", [this](HttpResponse* res, HttpRequest* req) {
      if (m_login && !check_auth(*req, *res))
        return;
      handle_json_rpc_request(*res, *req);
    });

    // Fallback to send a 404 for anything else:
    http.any("/*", [this](HttpResponse* res, HttpRequest* req) {
      if (m_login && !check_auth(*req, *res))
        return;
      MINFO("Invalid HTTP request for " << req->getMethod() << " " << req->getUrl());
      error_response(*res, HTTP_NOT_FOUND);
    });
  }

  void wallet_rpc_server::handle_json_rpc_request(HttpResponse& res, HttpRequest& req)
  {
    std::vector<std::pair<std::string, std::string>> extra_headers;
    handle_cors(req, extra_headers);

    res.onAborted([] {});
    res.onData([this, &res, extra_headers=std::move(extra_headers), buffer=""s](std::string_view d, bool done) mutable {
      if (!done) {
        buffer += d;
        return;
      }

      std::string_view body;
      if (buffer.empty())
        body = d; // bypass copying the string_view to a string
      else
        body = (buffer += d);

      epee::serialization::portable_storage ps;
      if(!ps.load_from_json(body))
        return jsonrpc_error_response(res, -32700, "Parse error");

      epee::serialization::storage_entry id{std::string{}};
      ps.get_value("id", id, nullptr);

      std::string method;
      if(!ps.get_value("method", method, nullptr))
      {
        MINFO("Invalid JSON RPC request from " << get_remote_address(res) << ": no 'method' in request");
        return jsonrpc_error_response(res, -32600, "Invalid Request", id);
      }

      auto it = rpc_commands.find(method);
      if (it == rpc_commands.end())
      {
        MINFO("Invalid JSON RPC request from " << get_remote_address(res) << ": method '" << method << "' is invalid");
        return jsonrpc_error_response(res, -32601, "Method not found", id);
      }
      MDEBUG("Incoming JSON RPC request for " << method << " from " << get_remote_address(res));

      const auto& [restricted, invoke_ptr] = it->second;

      // If it's a restricted command and we're in restricted mode then deny it
      if (restricted && m_restricted) {
        MWARNING("JSON RPC request for restricted command " << method << " in restricted mode from " << get_remote_address(res));
        return jsonrpc_error_response(res, error_code::DENIED, method + " is not available in restricted mode.");
      }

      // Try to load "params" into a generic epee value; if it fails (because there is no "params")
      // then clear it and pass a null optionsl.
      auto params = std::make_optional<epee::serialization::storage_entry>();
      if (!ps.get_value("params", *params, nullptr))
        params.reset();

      std::string result;
      wallet_rpc_error json_error{-32603, "Internal error"};

      try {
        result = invoke_ptr(ps, std::move(id), std::move(params), *this);
        json_error.code = 0;
      } catch (const parse_error& e) {
        json_error = {-32602, "Invalid params"}; // Reserved json code/message value for specifically this failure
      } catch (const wallet_rpc_error& e) {
        json_error = e;
      } catch (const tools::error::no_connection_to_daemon& e) {
        json_error = {error_code::NO_DAEMON_CONNECTION, e.what()};
      } catch (const tools::error::daemon_busy& e) {
        json_error = {error_code::DAEMON_IS_BUSY, e.what()};
      } catch (const tools::error::zero_destination& e) {
        json_error = {error_code::ZERO_DESTINATION, e.what()};
      } catch (const tools::error::not_enough_money& e) {
        json_error = {error_code::NOT_ENOUGH_MONEY, e.what()};
      } catch (const tools::error::not_enough_unlocked_money& e) {
        json_error = {error_code::NOT_ENOUGH_UNLOCKED_MONEY, e.what()};
      } catch (const tools::error::tx_not_possible& e) {
        json_error = {error_code::TX_NOT_POSSIBLE, (boost::format(tr("Transaction not possible. Available only %s, transaction amount %s = %s + %s (fee)")) %
            cryptonote::print_money(e.available()) %
            cryptonote::print_money(e.tx_amount() + e.fee())  %
            cryptonote::print_money(e.tx_amount()) %
            cryptonote::print_money(e.fee())).str()};
      } catch (const tools::error::not_enough_outs_to_mix& e) {
        json_error = {error_code::NOT_ENOUGH_OUTS_TO_MIX, e.what() + std::string(" Please use sweep_dust.")};
      } catch (const error::file_exists& e) {
        json_error = {error_code::WALLET_ALREADY_EXISTS, "Cannot create wallet. Already exists."};
      } catch (const error::invalid_password& e) {
        json_error = {error_code::INVALID_PASSWORD, "Invalid password."};
      } catch (const error::account_index_outofbound& e) {
        json_error = {error_code::ACCOUNT_INDEX_OUT_OF_BOUNDS, e.what()};
      } catch (const error::address_index_outofbound& e) {
        json_error = {error_code::ADDRESS_INDEX_OUT_OF_BOUNDS, e.what()};
      } catch (const error::signature_check_failed& e) {
        json_error = {error_code::WRONG_SIGNATURE, e.what()};
      } catch (const error::tx_blink_rejected& e) {
        json_error = {error_code::BLINK_FAILED, e.what()};
      } catch (const std::exception& e) {
        json_error = {error_code::UNKNOWN_ERROR, e.what()};
      } catch (...) {
        // leave it as unknown error
      }

      if (json_error.code != 0)
        return jsonrpc_error_response(res, json_error.code, std::move(json_error.message));

      res.writeHeader("Server", server_header());
      res.writeHeader("Content-Type", "application/json");
      for (const auto& [name, value] : extra_headers)
        res.writeHeader(name, value);
      if (closing()) res.writeHeader("Connection", "close");

      res.end(result);
      if (closing()) res.close();
    });
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::run_loop()
  {
    // We start 1-2 threads here:
    // - the uWS thread that handles all requests.
    // - a long poll thread (optional).
    // then this parent thread handles injecting refresh jobs (either on a timer, or because of long
    // polling detecting a change) into the uWS thread loop, and shutting down on a signal.
    std::promise<std::pair<uWS::Loop*, std::vector<us_listen_socket_t*>>> loop_promise;
    auto loop_future = loop_promise.get_future();

    // Start uWS in a thread, then join it.

    std::thread uws_thread{[this, &loop_promise] {
      uWS::App http;
      try {
        create_rpc_endpoints(http);
      } catch (...) {
        loop_promise.set_exception(std::current_exception());
      }


      bool bad = false;
      int good = 0;
      std::vector<us_listen_socket_t*> listening;
      try {
        for (const auto& [addr, port, required] : m_bind)
          http.listen(addr, port, [&listening, req=required, &good, &bad](us_listen_socket_t* sock) {
            listening.push_back(sock);
            if (sock != nullptr) good++;
            else if (req) bad = true;
          });

        if (!good || bad) {
          std::ostringstream error;
          error << "RPC HTTP server failed to bind; ";
          if (listening.empty()) error << "no valid bind address(es) given";
          else {
            error << "tried to bind to:";
            for (const auto& [addr, port, required] : m_bind)
              error << ' ' << addr << ':' << port;
          }
          throw std::runtime_error{error.str()};
        }
      } catch (...) {
        loop_promise.set_exception(std::current_exception());
        return;
      }
      loop_promise.set_value(std::make_pair(uWS::Loop::get(), std::move(listening)));

      http.run();
    }};

    // Wait for startup:
    auto [loop, sockets] = loop_future.get();
    m_loop = loop;
    m_listen_socks = std::move(sockets);

    if (m_wallet)
      start_long_poll_thread();

    // Used to prevent queuing up multiple refreshes at once
    std::atomic<bool> refreshing = false;

    // Now we just hang around and twiddle our thumbs until we're told to quit.  (And once in a
    // while we inject a wallet refresh into the uWS loop).
    while (!m_stop.load(std::memory_order_relaxed))
    {
      bool refresh_now = !refreshing && m_wallet && (
          (m_auto_refresh_period > 0s && std::chrono::steady_clock::now() > m_last_auto_refresh_time + m_auto_refresh_period)
          || m_long_poll_new_changes);

      if (refresh_now)
      {
        refreshing = true;

        // Queue the refresh to run in the uWS thread loop
        loop_defer([this, &refreshing] {
          m_long_poll_new_changes = false; // Always consume the change, if we miss one due to thread race, not the end of the world.

          try {
            if (m_wallet) m_wallet->refresh(m_wallet->is_trusted_daemon());
          } catch (const std::exception& ex) {
            LOG_ERROR("Exception while refreshing: " << ex.what());
          }

          m_last_auto_refresh_time = std::chrono::steady_clock::now();
          refreshing = false;
        });
      }

      std::this_thread::sleep_for(250ms);
    }

    MGINFO("Stopping wallet rpc server");
    MINFO("Shutting down listening HTTP RPC sockets");
    // Stopped: close the sockets, cancel the long poll, and rejoin the threads
    for (auto* s : m_listen_socks)
      us_listen_socket_close(/*ssl=*/false, s);
    m_closing = true;

    stop_long_poll_thread();

    MDEBUG("Joining uws thread");
    uws_thread.join();

    MGINFO("Storing wallet...");
    if (m_wallet)
      m_wallet->store();
    MGINFO("Wallet stopped.");
  }
  void wallet_rpc_server::start_long_poll_thread()
  {
    assert(m_wallet);
    if (m_long_poll_thread.joinable() || m_long_poll_disabled)
    {
      MDEBUG("Not starting long poll thread: " << (m_long_poll_thread.joinable() ? "already running" : "long polling disabled"));
      return;
    }
    MINFO("Starting long poll thread");
    m_long_poll_thread = std::thread{[this] {
      for (;;)
      {
        if (m_long_poll_disabled) return;
        if (m_auto_refresh_period == 0s)
        {
          std::this_thread::sleep_for(100ms);
          continue;
        }

        try
        {
          if (m_wallet->long_poll_pool_state())
            m_long_poll_new_changes = true;
        }
        catch (...)
        {
          // NOTE: Don't care about error, non fatal.
        }
      }
    }};
  }
  void wallet_rpc_server::stop_long_poll_thread()
  {
    assert(m_wallet);
    if (!m_long_poll_thread.joinable())
    {
      MDEBUG("Not stopping long poll thread: not running");
      return;
    }
    MINFO("Stopping long poll thread");
    m_wallet->cancel_long_poll();
    // Store this to revert it afterwards to its original state
    bool disabled_state = m_long_poll_disabled;
    m_long_poll_disabled = true;
    m_long_poll_thread.join();
    m_long_poll_disabled = disabled_state;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  bool wallet_rpc_server::init()
  {
    cryptonote::rpc_args rpc_config;
    try {
      rpc_config = cryptonote::rpc_args::process(m_vm);
    } catch (const std::exception& e) {
      MERROR("Failed to process rpc arguments: " << e.what());
      return false;
    }

    const uint16_t port = command_line::get_arg(m_vm, arg_rpc_bind_port);
    if (!port)
    {
      MERROR("Invalid port " << port << " specified");
      return false;
    }

    if (!rpc_config.bind_ip || !rpc_config.bind_ip->empty())
      m_bind.emplace_back(rpc_config.bind_ip.value_or("127.0.0.1"), port, rpc_config.require_ipv4);
    if (rpc_config.use_ipv6 && (!rpc_config.bind_ipv6_address || !rpc_config.bind_ipv6_address->empty()))
      m_bind.emplace_back(rpc_config.bind_ipv6_address.value_or("::1"), port, true);

    const bool disable_auth = command_line::get_arg(m_vm, arg_disable_rpc_login);

    m_restricted = command_line::get_arg(m_vm, arg_restricted);

    m_server_header = "oxen-wallet-rpc/"s + (m_restricted ? std::to_string(OXEN_VERSION[0]) : std::string{OXEN_VERSION_STR});

    m_cors = {rpc_config.access_control_origins.begin(), rpc_config.access_control_origins.end()};

    if (!command_line::is_arg_defaulted(m_vm, arg_wallet_dir))
    {
      if (!command_line::is_arg_defaulted(m_vm, wallet_args::arg_wallet_file()))
      {
        MERROR(arg_wallet_dir.name << " and " << wallet_args::arg_wallet_file().name << " are incompatible, use only one of them");
        return false;
      }
      m_wallet_dir = fs::u8path(command_line::get_arg(m_vm, arg_wallet_dir));
      if (!m_wallet_dir.empty())
      {
        std::error_code ec;
        if (fs::create_directories(m_wallet_dir, ec))
          fs::permissions(m_wallet_dir, fs::perms::owner_all, ec);
        else if (ec)
        {
          LOG_ERROR(tr("Failed to create directory ") << m_wallet_dir << ": " << ec.message());
          return false;
        }
      }
    }

    if (disable_auth)
    {
      if (rpc_config.login)
      {
        const cryptonote::rpc_args::descriptors arg{};
        LOG_ERROR(tr("Cannot specify --") << arg_disable_rpc_login.name << tr(" and --") << arg.rpc_login.name);
        return false;
      }
      m_login = std::nullopt;
    }
    else // auth enabled
    {
      if (!rpc_config.login)
      {
        std::array<std::uint8_t, 16> rand_128bit{{}};
        crypto::rand(rand_128bit.size(), rand_128bit.data());
        m_login.emplace(
          default_rpc_username,
          epee::string_encoding::base64_encode(rand_128bit.data(), rand_128bit.size())
        );

        std::string temp = "oxen-wallet-rpc." + std::to_string(port) + ".login";
        rpc_login_file = tools::private_file::create(temp);
        if (!rpc_login_file.handle())
        {
          LOG_ERROR(tr("Failed to create file ") << temp << tr(". Check permissions or remove file"));
          return false;
        }
        std::fputs(m_login->username.c_str(), rpc_login_file.handle());
        std::fputc(':', rpc_login_file.handle());
        const auto& password = m_login->password.password();
        std::fwrite(password.data(), 1, password.size(), rpc_login_file.handle());
        std::fputc('\n', rpc_login_file.handle());
        std::fflush(rpc_login_file.handle());
        if (std::ferror(rpc_login_file.handle()))
        {
          LOG_ERROR(tr("Error writing to file ") << temp);
          return false;
        }
        LOG_PRINT_L0(tr("RPC username/password is stored in file ") << temp);
      }
      else // chosen user/pass
      {
        m_login = rpc_config.login;
      }
      assert(bool(m_login));
    } // end auth enabled

    m_auto_refresh_period = DEFAULT_AUTO_REFRESH_PERIOD;
    m_last_auto_refresh_time = std::chrono::steady_clock::time_point::min();
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::require_open()
  {
    if (!m_wallet)
      throw wallet_rpc_error{error_code::NOT_OPEN, "No wallet file"};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::close_wallet(bool save_current)
  {
    if (m_wallet)
    {
      LOG_PRINT_L0(tools::wallet_rpc_server::tr("Closing wallet..."));
      stop_long_poll_thread();
      if (save_current)
      {
        LOG_PRINT_L0(tools::wallet_rpc_server::tr("Saving wallet..."));
        m_wallet->store();
        LOG_PRINT_L0(tools::wallet_rpc_server::tr("Successfully saved"));
      }
      m_wallet->deinit();
      m_wallet.reset();
      LOG_PRINT_L0(tools::wallet_rpc_server::tr("Successfully closed"));
    }
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_BALANCE::response wallet_rpc_server::invoke(GET_BALANCE::request&& req)
  {
    require_open();
    GET_BALANCE::response res{};
    {
      res.balance = req.all_accounts ? m_wallet->balance_all(req.strict) : m_wallet->balance(req.account_index, req.strict);
      res.unlocked_balance = req.all_accounts ? m_wallet->unlocked_balance_all(req.strict, &res.blocks_to_unlock, &res.time_to_unlock) : m_wallet->unlocked_balance(req.account_index, req.strict, &res.blocks_to_unlock, &res.time_to_unlock);
      res.multisig_import_needed = m_wallet->multisig() && m_wallet->has_multisig_partial_key_images();
      std::map<uint32_t, std::map<uint32_t, uint64_t>> balance_per_subaddress_per_account;
      std::map<uint32_t, std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>>> unlocked_balance_per_subaddress_per_account;
      if (req.all_accounts)
      {
        for (uint32_t account_index = 0; account_index < m_wallet->get_num_subaddress_accounts(); ++account_index)
        {
          balance_per_subaddress_per_account[account_index] = m_wallet->balance_per_subaddress(account_index, req.strict);
          unlocked_balance_per_subaddress_per_account[account_index] = m_wallet->unlocked_balance_per_subaddress(account_index, req.strict);
        }
      }
      else
      {
        balance_per_subaddress_per_account[req.account_index] = m_wallet->balance_per_subaddress(req.account_index, req.strict);
        unlocked_balance_per_subaddress_per_account[req.account_index] = m_wallet->unlocked_balance_per_subaddress(req.account_index, req.strict);
      }
      std::vector<wallet::transfer_details> transfers;
      m_wallet->get_transfers(transfers);
      for (const auto& p : balance_per_subaddress_per_account)
      {
        uint32_t account_index = p.first;
        std::map<uint32_t, uint64_t> balance_per_subaddress = p.second;
        std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> unlocked_balance_per_subaddress = unlocked_balance_per_subaddress_per_account[account_index];
        std::set<uint32_t> address_indices;
        if (!req.all_accounts && !req.address_indices.empty())
        {
          address_indices = req.address_indices;
        }
        else
        {
          for (const auto& i : balance_per_subaddress)
            address_indices.insert(i.first);
        }
        for (uint32_t i : address_indices)
        {
          wallet_rpc::GET_BALANCE::per_subaddress_info info{};
          info.account_index = account_index;
          info.address_index = i;
          cryptonote::subaddress_index index = {info.account_index, info.address_index};
          info.address = m_wallet->get_subaddress_as_str(index);
          info.balance = balance_per_subaddress[i];
          info.unlocked_balance = unlocked_balance_per_subaddress[i].first;
          info.blocks_to_unlock = unlocked_balance_per_subaddress[i].second.first;
          info.time_to_unlock = unlocked_balance_per_subaddress[i].second.second;
          info.label = m_wallet->get_subaddress_label(index);
          info.num_unspent_outputs = std::count_if(transfers.begin(), transfers.end(), [&](const wallet::transfer_details& td) { return !td.m_spent && td.m_subaddr_index == index; });
          res.per_subaddress.emplace_back(std::move(info));
        }
      }
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_ADDRESS::response wallet_rpc_server::invoke(GET_ADDRESS::request&& req)
  {
    require_open();
    GET_ADDRESS::response res{};
    {
      THROW_WALLET_EXCEPTION_IF(req.account_index >= m_wallet->get_num_subaddress_accounts(), error::account_index_outofbound);
      res.addresses.clear();
      std::vector<uint32_t> req_address_index;
      if (req.address_index.empty())
      {
        for (uint32_t i = 0; i < m_wallet->get_num_subaddresses(req.account_index); ++i)
          req_address_index.push_back(i);
      }
      else
      {
        req_address_index = req.address_index;
      }
      tools::wallet2::transfer_container transfers;
      m_wallet->get_transfers(transfers);
      for (uint32_t i : req_address_index)
      {
        THROW_WALLET_EXCEPTION_IF(i >= m_wallet->get_num_subaddresses(req.account_index), error::address_index_outofbound);
        res.addresses.resize(res.addresses.size() + 1);
        auto& info = res.addresses.back();
        const cryptonote::subaddress_index index = {req.account_index, i};
        info.address = m_wallet->get_subaddress_as_str(index);
        info.label = m_wallet->get_subaddress_label(index);
        info.address_index = index.minor;
        info.used = std::find_if(transfers.begin(), transfers.end(), [&](const wallet::transfer_details& td) { return td.m_subaddr_index == index; }) != transfers.end();
      }
      res.address = m_wallet->get_subaddress_as_str({req.account_index, 0});
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_ADDRESS_INDEX::response wallet_rpc_server::invoke(GET_ADDRESS_INDEX::request&& req)
  {
    require_open();
    GET_ADDRESS_INDEX::response res{};
    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, m_wallet->nettype(), req.address))
      throw wallet_rpc_error{error_code::WRONG_ADDRESS, "Invalid address"};
    auto index = m_wallet->get_subaddress_index(info.address);
    if (!index)
      throw wallet_rpc_error{error_code::WRONG_ADDRESS, "Address doesn't belong to the wallet"};
    res.index = *index;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  CREATE_ADDRESS::response wallet_rpc_server::invoke(CREATE_ADDRESS::request&& req)
  {
    require_open();
    CREATE_ADDRESS::response res{};
    {
      if (req.count < 1 || req.count > 64)
        throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Count must be between 1 and 64."};

      std::vector<std::string> addresses;
      std::vector<uint32_t>    address_indices;

      addresses.reserve(req.count);
      address_indices.reserve(req.count);

      for (uint32_t i = 0; i < req.count; i++) {
        m_wallet->add_subaddress(req.account_index, req.label);
        uint32_t new_address_index = m_wallet->get_num_subaddresses(req.account_index) - 1;
        address_indices.push_back(new_address_index);
        addresses.push_back(m_wallet->get_subaddress_as_str({req.account_index, new_address_index}));
      }

      res.address = addresses[0];
      res.address_index = address_indices[0];
      res.addresses = addresses;
      res.address_indices = address_indices;
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  LABEL_ADDRESS::response wallet_rpc_server::invoke(LABEL_ADDRESS::request&& req)
  {
    require_open();
    LABEL_ADDRESS::response res{};
    {
      m_wallet->set_subaddress_label(req.index, req.label);
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_ACCOUNTS::response wallet_rpc_server::invoke(GET_ACCOUNTS::request&& req)
  {
    require_open();
    GET_ACCOUNTS::response res{};
    {
      res.total_balance = 0;
      res.total_unlocked_balance = 0;
      const std::pair<std::map<std::string, std::string>, std::vector<std::string>> account_tags = m_wallet->get_account_tags();
      if (!req.tag.empty() && account_tags.first.count(req.tag) == 0)
        throw wallet_rpc_error{
          error_code::UNKNOWN_ERROR,
          (boost::format(tr("Tag %s is unregistered.")) % req.tag).str()};
      for (cryptonote::subaddress_index subaddr_index = {0,0};
          subaddr_index.major < m_wallet->get_num_subaddress_accounts();
          ++subaddr_index.major)
      {
        if (!req.tag.empty() && req.tag != account_tags.second[subaddr_index.major])
          continue;
        wallet_rpc::GET_ACCOUNTS::subaddress_account_info info;
        info.account_index = subaddr_index.major;
        info.base_address = m_wallet->get_subaddress_as_str(subaddr_index);
        info.balance = m_wallet->balance(subaddr_index.major, req.strict_balances);
        info.unlocked_balance = m_wallet->unlocked_balance(subaddr_index.major, req.strict_balances);
        info.label = m_wallet->get_subaddress_label(subaddr_index);
        info.tag = account_tags.second[subaddr_index.major];
        res.subaddress_accounts.push_back(info);
        res.total_balance += info.balance;
        res.total_unlocked_balance += info.unlocked_balance;
      }
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  CREATE_ACCOUNT::response wallet_rpc_server::invoke(CREATE_ACCOUNT::request&& req)
  {
    require_open();
    CREATE_ACCOUNT::response res{};
    {
      m_wallet->add_subaddress_account(req.label);
      res.account_index = m_wallet->get_num_subaddress_accounts() - 1;
      res.address = m_wallet->get_subaddress_as_str({res.account_index, 0});
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  LABEL_ACCOUNT::response wallet_rpc_server::invoke(LABEL_ACCOUNT::request&& req)
  {
    require_open();
    LABEL_ACCOUNT::response res{};
    {
      m_wallet->set_subaddress_label({req.account_index, 0}, req.label);
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_ACCOUNT_TAGS::response wallet_rpc_server::invoke(GET_ACCOUNT_TAGS::request&& req)
  {
    require_open();
    GET_ACCOUNT_TAGS::response res{};
    const std::pair<std::map<std::string, std::string>, std::vector<std::string>> account_tags = m_wallet->get_account_tags();
    for (const auto& p : account_tags.first)
    {
      res.account_tags.resize(res.account_tags.size() + 1);
      auto& info = res.account_tags.back();
      info.tag = p.first;
      info.label = p.second;
      for (size_t i = 0; i < account_tags.second.size(); ++i)
      {
        if (account_tags.second[i] == info.tag)
          info.accounts.push_back(i);
      }
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  TAG_ACCOUNTS::response wallet_rpc_server::invoke(TAG_ACCOUNTS::request&& req)
  {
    require_open();
    TAG_ACCOUNTS::response res{};
    {
      m_wallet->set_account_tag(req.accounts, req.tag);
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  UNTAG_ACCOUNTS::response wallet_rpc_server::invoke(UNTAG_ACCOUNTS::request&& req)
  {
    require_open();
    UNTAG_ACCOUNTS::response res{};
    {
      m_wallet->set_account_tag(req.accounts, "");
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SET_ACCOUNT_TAG_DESCRIPTION::response wallet_rpc_server::invoke(SET_ACCOUNT_TAG_DESCRIPTION::request&& req)
  {
    require_open();
    SET_ACCOUNT_TAG_DESCRIPTION::response res{};
    {
      m_wallet->set_account_tag_description(req.tag, req.description);
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_HEIGHT::response wallet_rpc_server::invoke(GET_HEIGHT::request&& req)
  {
    require_open();
    GET_HEIGHT::response res{};
    {
      res.height           = m_wallet->get_blockchain_current_height();
      res.immutable_height = m_wallet->get_immutable_height();
    }
    return res;
  }

  static cryptonote::address_parse_info extract_account_addr(
      cryptonote::network_type nettype,
      std::string_view addr_or_url)
  {
    cryptonote::address_parse_info info;
    if (!get_account_address_from_str_or_url(info, nettype, addr_or_url,
          [](const std::string_view url, const std::vector<std::string> &addresses, bool dnssec_valid) {
            if (!dnssec_valid)
              throw wallet_rpc_error{error_code::WRONG_ADDRESS, "Invalid DNSSEC for "s + std::string{url}};
            if (addresses.empty())
              throw wallet_rpc_error{error_code::WRONG_ADDRESS, "No Oxen address found at "s + std::string{url}};
            return addresses[0];
          }))
      throw wallet_rpc_error{error_code::WRONG_ADDRESS, "Invalid address: "s + std::string{addr_or_url}};
    return info;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  void wallet_rpc_server::validate_transfer(const std::list<wallet::transfer_destination>& destinations, const std::string& payment_id, std::vector<cryptonote::tx_destination_entry>& dsts, std::vector<uint8_t>& extra, bool at_least_one_destination)
  {
    crypto::hash8 integrated_payment_id = crypto::null_hash8;
    std::string extra_nonce;
    for (auto it = destinations.begin(); it != destinations.end(); it++)
    {
      cryptonote::address_parse_info info = extract_account_addr(m_wallet->nettype(), it->address);

      cryptonote::tx_destination_entry de;
      de.original = it->address;
      de.addr = info.address;
      de.is_subaddress = info.is_subaddress;
      de.amount = it->amount;
      de.is_integrated = info.has_payment_id;
      dsts.push_back(de);

      if (info.has_payment_id)
      {
        if (!payment_id.empty() || integrated_payment_id != crypto::null_hash8)
          throw wallet_rpc_error{error_code::WRONG_PAYMENT_ID, "A single payment id is allowed per transaction"};
        integrated_payment_id = info.payment_id;
        cryptonote::set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, integrated_payment_id);

        /* Append Payment ID data into extra */
        if (!cryptonote::add_extra_nonce_to_tx_extra(extra, extra_nonce))
          throw wallet_rpc_error{error_code::WRONG_PAYMENT_ID, "Something went wrong with integrated payment_id."};
      }
    }

    if (at_least_one_destination && dsts.empty())
      throw wallet_rpc_error{error_code::ZERO_DESTINATION, "No destinations for this transfer"};

    if (!payment_id.empty())
      throw wallet_rpc_error{error_code::WRONG_PAYMENT_ID, "Standalone payment IDs are obsolete. Use subaddresses or integrated addresses instead"};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  static std::string ptx_to_string(const wallet::pending_tx &ptx)
  {
    std::ostringstream oss;
    boost::archive::portable_binary_oarchive ar(oss);
    try
    {
      ar << ptx;
    }
    catch (...)
    {
      return "";
    }
    return oxenmq::to_hex(oss.str());
  }
  //------------------------------------------------------------------------------------------------------------------------------
  template<typename T> static bool is_error_value(const T &val) { return false; }
  static bool is_error_value(const std::string &s) { return s.empty(); }
  //------------------------------------------------------------------------------------------------------------------------------
  template<typename T, typename V>
  static bool fill(T &where, V s)
  {
    if (is_error_value(s)) return false;
    where = std::move(s);
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  template<typename T, typename V>
  static bool fill(std::list<T> &where, V s)
  {
    if (is_error_value(s)) return false;
    where.emplace_back(std::move(s));
    return true;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  static uint64_t total_amount(const wallet::pending_tx &ptx)
  {
    uint64_t amount = 0;
    for (const auto &dest: ptx.dests) amount += dest.amount;
    return amount;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  template<typename Ts, typename Tu>
  void wallet_rpc_server::fill_response(std::vector<wallet::pending_tx> &ptx_vector,
      bool get_tx_key, Ts& tx_key, Tu &amount, Tu &fee, std::string &multisig_txset, std::string &unsigned_txset, bool do_not_relay, bool blink,
      Ts &tx_hash, bool get_tx_hex, Ts &tx_blob, bool get_tx_metadata, Ts &tx_metadata)
  {
    for (const auto & ptx : ptx_vector)
    {
      if (get_tx_key)
      {
        epee::wipeable_string s = epee::to_hex::wipeable_string(ptx.tx_key);
        for (const crypto::secret_key& additional_tx_key : ptx.additional_tx_keys)
          s += epee::to_hex::wipeable_string(additional_tx_key);
        fill(tx_key, std::string(s.data(), s.size()));
      }
      // Compute amount leaving wallet in tx. By convention dests does not include change outputs
      fill(amount, total_amount(ptx));
      fill(fee, ptx.fee);
    }

    if (m_wallet->multisig())
    {
      multisig_txset = oxenmq::to_hex(m_wallet->save_multisig_tx(ptx_vector));
      if (multisig_txset.empty())
        throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to save multisig tx set after creation"};
    }
    else
    {
      if (m_wallet->watch_only()){
        unsigned_txset = oxenmq::to_hex(m_wallet->dump_tx_to_str(ptx_vector));
        if (unsigned_txset.empty())
          throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to save unsigned tx set after creation"};
      }
      else if (!do_not_relay)
        m_wallet->commit_tx(ptx_vector, blink);

      // populate response with tx hashes
      for (auto & ptx : ptx_vector)
      {
        bool r = fill(tx_hash, tools::type_to_hex(cryptonote::get_transaction_hash(ptx.tx)));
        r = r && (!get_tx_hex || fill(tx_blob, oxenmq::to_hex(tx_to_blob(ptx.tx))));
        r = r && (!get_tx_metadata || fill(tx_metadata, ptx_to_string(ptx)));
        if (!r)
          throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to save tx info"};
      }
    }
  }
  //------------------------------------------------------------------------------------------------------------------------------
  TRANSFER::response wallet_rpc_server::invoke(TRANSFER::request&& req)
  {
    require_open();
    TRANSFER::response res{};

    std::vector<cryptonote::tx_destination_entry> dsts;
    std::vector<uint8_t> extra;

    LOG_PRINT_L3("on_transfer starts");
    require_open();

    // validate the transfer requested and populate dsts & extra
    validate_transfer(req.destinations, req.payment_id, dsts, extra, true);

    {
      uint32_t priority = convert_priority(req.priority);
      std::optional<uint8_t> hf_version = m_wallet->get_hard_fork_version();
      if (!hf_version)
        throw wallet_rpc_error{error_code::HF_QUERY_FAILED, tools::ERR_MSG_NETWORK_VERSION_QUERY_FAILED};
      cryptonote::oxen_construct_tx_params tx_params = tools::wallet2::construct_params(*hf_version, cryptonote::txtype::standard, priority);
      std::vector<wallet2::pending_tx> ptx_vector = m_wallet->create_transactions_2(dsts, CRYPTONOTE_DEFAULT_TX_MIXIN, req.unlock_time, priority, extra, req.account_index, req.subaddr_indices, tx_params);

      if (ptx_vector.empty())
        throw wallet_rpc_error{error_code::TX_NOT_POSSIBLE, "No transaction created"};

      // reject proposed transactions if there are more than one.  see on_transfer_split below.
      if (ptx_vector.size() != 1)
        throw wallet_rpc_error{error_code::TX_TOO_LARGE, "Transaction would be too large.  try /transfer_split."};

      fill_response(ptx_vector, req.get_tx_key, res.tx_key, res.amount, res.fee, res.multisig_txset, res.unsigned_txset, req.do_not_relay, priority == tx_priority_blink,
          res.tx_hash, req.get_tx_hex, res.tx_blob, req.get_tx_metadata, res.tx_metadata);
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  TRANSFER_SPLIT::response wallet_rpc_server::invoke(TRANSFER_SPLIT::request&& req)
  {
    require_open();
    TRANSFER_SPLIT::response res{};

    std::vector<cryptonote::tx_destination_entry> dsts;
    std::vector<uint8_t> extra;

    require_open();

    // validate the transfer requested and populate dsts & extra; RPC_TRANSFER::request and RPC_TRANSFER_SPLIT::request are identical types.
    validate_transfer(req.destinations, req.payment_id, dsts, extra, true);

    {
      uint32_t priority = convert_priority(req.priority);
      std::optional<uint8_t> hf_version = m_wallet->get_hard_fork_version();
      if (!hf_version)
        throw wallet_rpc_error{error_code::HF_QUERY_FAILED, tools::ERR_MSG_NETWORK_VERSION_QUERY_FAILED};

      cryptonote::oxen_construct_tx_params tx_params = tools::wallet2::construct_params(*hf_version, cryptonote::txtype::standard, priority);
      LOG_PRINT_L2("on_transfer_split calling create_transactions_2");
      std::vector<wallet2::pending_tx> ptx_vector = m_wallet->create_transactions_2(dsts, CRYPTONOTE_DEFAULT_TX_MIXIN, req.unlock_time, priority, extra, req.account_index, req.subaddr_indices, tx_params);
      LOG_PRINT_L2("on_transfer_split called create_transactions_2");

      if (ptx_vector.empty())
        throw wallet_rpc_error{error_code::TX_NOT_POSSIBLE, "No transaction created"};

      fill_response(ptx_vector, req.get_tx_keys, res.tx_key_list, res.amount_list, res.fee_list, res.multisig_txset, res.unsigned_txset, req.do_not_relay, priority == tx_priority_blink,
          res.tx_hash_list, req.get_tx_hex, res.tx_blob_list, req.get_tx_metadata, res.tx_metadata_list);
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SIGN_TRANSFER::response wallet_rpc_server::invoke(SIGN_TRANSFER::request&& req)
  {
    require_open();
    SIGN_TRANSFER::response res{};
    if (m_wallet->key_on_device())
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "command not supported by HW wallet"};
    if(m_wallet->watch_only())
      throw wallet_rpc_error{error_code::WATCH_ONLY, "command not supported by watch-only wallet"};

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.unsigned_txset, blob))
      throw wallet_rpc_error{error_code::BAD_HEX, "Failed to parse hex."};

    wallet::unsigned_tx_set exported_txs;
    if(!m_wallet->parse_unsigned_tx_from_str(blob, exported_txs))
      throw wallet_rpc_error{error_code::BAD_UNSIGNED_TX_DATA, "cannot load unsigned_txset"};

    std::vector<wallet::pending_tx> ptxs;
    {
      wallet::signed_tx_set signed_txs;
      std::string ciphertext = m_wallet->sign_tx_dump_to_str(exported_txs, ptxs, signed_txs);
      if (ciphertext.empty())
        throw wallet_rpc_error{error_code::SIGN_UNSIGNED, "Failed to sign unsigned tx"};

      res.signed_txset = oxenmq::to_hex(ciphertext);
    }

    for (auto &ptx: ptxs)
    {
      res.tx_hash_list.push_back(tools::type_to_hex(cryptonote::get_transaction_hash(ptx.tx)));
      if (req.get_tx_keys)
      {
        res.tx_key_list.push_back(tools::type_to_hex(ptx.tx_key));
        for (const crypto::secret_key& additional_tx_key : ptx.additional_tx_keys)
          res.tx_key_list.back() += tools::type_to_hex(additional_tx_key);
      }
    }

    if (req.export_raw)
    {
      for (auto &ptx: ptxs)
      {
        res.tx_raw_list.push_back(oxenmq::to_hex(cryptonote::tx_to_blob(ptx.tx)));
      }
    }

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  DESCRIBE_TRANSFER::response wallet_rpc_server::invoke(DESCRIBE_TRANSFER::request&& req)
  {
    require_open();
    DESCRIBE_TRANSFER::response res{};
    if (m_wallet->key_on_device())
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "command not supported by HW wallet"};
    if(m_wallet->watch_only())
      throw wallet_rpc_error{error_code::WATCH_ONLY, "command not supported by watch-only wallet"};
    if(req.unsigned_txset.empty() && req.multisig_txset.empty())
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "no txset provided"};

    std::vector <wallet::tx_construction_data> tx_constructions;
    if (!req.unsigned_txset.empty()) {
      try {
        wallet::unsigned_tx_set exported_txs;
        cryptonote::blobdata blob;
        if (!epee::string_tools::parse_hexstr_to_binbuff(req.unsigned_txset, blob))
          throw wallet_rpc_error{error_code::BAD_HEX, "Failed to parse hex."};
        if (!m_wallet->parse_unsigned_tx_from_str(blob, exported_txs))
          throw wallet_rpc_error{error_code::BAD_UNSIGNED_TX_DATA, "cannot load unsigned_txset"};
        tx_constructions = exported_txs.txes;
      }
      catch (const std::exception &e) {
        throw wallet_rpc_error{error_code::BAD_UNSIGNED_TX_DATA, "failed to parse unsigned transfers: " + std::string(e.what())};
      }
    } else if (!req.multisig_txset.empty()) {
      try {
        wallet::multisig_tx_set exported_txs;
        cryptonote::blobdata blob;
        if (!epee::string_tools::parse_hexstr_to_binbuff(req.multisig_txset, blob))
          throw wallet_rpc_error{error_code::BAD_HEX, "Failed to parse hex."};
        if (!m_wallet->parse_multisig_tx_from_str(blob, exported_txs))
          throw wallet_rpc_error{error_code::BAD_MULTISIG_TX_DATA, "cannot load multisig_txset"};

        for (size_t n = 0; n < exported_txs.m_ptx.size(); ++n) {
          tx_constructions.push_back(exported_txs.m_ptx[n].construction_data);
        }
      }
      catch (const std::exception &e) {
        throw wallet_rpc_error{error_code::BAD_MULTISIG_TX_DATA, "failed to parse multisig transfers: " + std::string(e.what())};
      }
    }

    try
    {
      // gather info to ask the user
      std::unordered_map<cryptonote::account_public_address, std::pair<std::string, uint64_t>> dests;
      int first_known_non_zero_change_index = -1;
      for (size_t n = 0; n < tx_constructions.size(); ++n)
      {
        const auto &cd = tx_constructions[n];
        res.desc.push_back({0, 0, std::numeric_limits<uint32_t>::max(), 0, {}, "", 0, "", 0, 0, ""});
        wallet_rpc::DESCRIBE_TRANSFER::transfer_description &desc = res.desc.back();

        std::vector<cryptonote::tx_extra_field> tx_extra_fields;
        bool has_encrypted_payment_id = false;
        crypto::hash8 payment_id8 = crypto::null_hash8;
        if (cryptonote::parse_tx_extra(cd.extra, tx_extra_fields))
        {
          cryptonote::tx_extra_nonce extra_nonce;
          if (find_tx_extra_field_by_type(tx_extra_fields, extra_nonce))
          {
            crypto::hash payment_id;
            if(cryptonote::get_encrypted_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id8))
            {
              if (payment_id8 != crypto::null_hash8)
              {
                desc.payment_id = tools::type_to_hex(payment_id8);
                has_encrypted_payment_id = true;
              }
            }
            else if (cryptonote::get_payment_id_from_tx_extra_nonce(extra_nonce.nonce, payment_id))
            {
              desc.payment_id = tools::type_to_hex(payment_id);
            }
          }
        }

        for (size_t s = 0; s < cd.sources.size(); ++s)
        {
          desc.amount_in += cd.sources[s].amount;
          size_t ring_size = cd.sources[s].outputs.size();
          if (ring_size < desc.ring_size)
            desc.ring_size = ring_size;
        }
        for (size_t d = 0; d < cd.splitted_dsts.size(); ++d)
        {
          const cryptonote::tx_destination_entry &entry = cd.splitted_dsts[d];
          std::string address = cryptonote::get_account_address_as_str(m_wallet->nettype(), entry.is_subaddress, entry.addr);
          if (has_encrypted_payment_id && !entry.is_subaddress && address != entry.original)
            address = cryptonote::get_account_integrated_address_as_str(m_wallet->nettype(), entry.addr, payment_id8);
          auto i = dests.find(entry.addr);
          if (i == dests.end())
            dests.insert(std::make_pair(entry.addr, std::make_pair(address, entry.amount)));
          else
            i->second.second += entry.amount;
          desc.amount_out += entry.amount;
        }
        if (cd.change_dts.amount > 0)
        {
          auto it = dests.find(cd.change_dts.addr);
          if (it == dests.end())
            throw wallet_rpc_error{error_code::BAD_UNSIGNED_TX_DATA, "Claimed change does not go to a paid address"};
          if (it->second.second < cd.change_dts.amount)
            throw wallet_rpc_error{error_code::BAD_UNSIGNED_TX_DATA, "Claimed change is larger than payment to the change address"};
          if (cd.change_dts.amount > 0)
          {
            if (first_known_non_zero_change_index == -1)
              first_known_non_zero_change_index = n;
            const auto &cdn = tx_constructions[first_known_non_zero_change_index];
            if (memcmp(&cd.change_dts.addr, &cdn.change_dts.addr, sizeof(cd.change_dts.addr)))
              throw wallet_rpc_error{error_code::BAD_UNSIGNED_TX_DATA, "Change goes to more than one address"};
          }
          desc.change_amount += cd.change_dts.amount;
          it->second.second -= cd.change_dts.amount;
          if (it->second.second == 0)
            dests.erase(cd.change_dts.addr);
        }

        size_t n_dummy_outputs = 0;
        for (auto i = dests.begin(); i != dests.end(); )
        {
          if (i->second.second > 0)
          {
            desc.recipients.push_back({i->second.first, i->second.second});
          }
          else
            ++desc.dummy_outputs;
          ++i;
        }

        if (desc.change_amount > 0)
        {
          const auto &cd0 = tx_constructions[0];
          desc.change_address = get_account_address_as_str(m_wallet->nettype(), cd0.subaddr_account > 0, cd0.change_dts.addr);
        }

        desc.fee = desc.amount_in - desc.amount_out;
        desc.unlock_time = cd.unlock_time;
        desc.extra = epee::to_hex::string({cd.extra.data(), cd.extra.size()});
      }
    }
    catch (const wallet_rpc_error& e)
    {
      throw;
    }
    catch (const std::exception &e)
    {
      throw wallet_rpc_error{error_code::BAD_UNSIGNED_TX_DATA, "failed to parse unsigned transfers"};
    }

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SUBMIT_TRANSFER::response wallet_rpc_server::invoke(SUBMIT_TRANSFER::request&& req)
  {
    require_open();
    SUBMIT_TRANSFER::response res{};
    if (m_wallet->key_on_device())
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "command not supported by HW wallet"};

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.tx_data_hex, blob))
      throw wallet_rpc_error{error_code::BAD_HEX, "Failed to parse hex."};

    std::vector<wallet::pending_tx> ptx_vector;
    if (!m_wallet->parse_tx_from_str(blob, ptx_vector, nullptr))
      throw wallet_rpc_error{error_code::BAD_SIGNED_TX_DATA, "Failed to parse signed tx data."};

    try
    {
      for (auto &ptx: ptx_vector)
      {
        m_wallet->commit_tx(ptx);
        res.tx_hash_list.push_back(tools::type_to_hex(cryptonote::get_transaction_hash(ptx.tx)));
      }
    }
    catch (const std::exception &e)
    {
      throw wallet_rpc_error{error_code::SIGNED_SUBMISSION, "Failed to submit signed tx: "s + e.what()};
    }

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SWEEP_DUST::response wallet_rpc_server::invoke(SWEEP_DUST::request&& req)
  {
    require_open();
    SWEEP_DUST::response res{};

    std::vector<wallet2::pending_tx> ptx_vector = m_wallet->create_unmixable_sweep_transactions();

    fill_response(ptx_vector, req.get_tx_keys, res.tx_key_list, res.amount_list, res.fee_list, res.multisig_txset, res.unsigned_txset, req.do_not_relay, false /*blink*/,
          res.tx_hash_list, req.get_tx_hex, res.tx_blob_list, req.get_tx_metadata, res.tx_metadata_list);

    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SWEEP_ALL::response wallet_rpc_server::invoke(SWEEP_ALL::request&& req)
  {
    std::vector<cryptonote::tx_destination_entry> dsts;
    std::vector<uint8_t> extra;

    require_open();
    SWEEP_ALL::response res{};

    // validate the transfer requested and populate dsts & extra
    std::list<wallet::transfer_destination> destination;
    destination.emplace_back();
    destination.back().amount = 0;
    destination.back().address = req.address;
    validate_transfer(destination, req.payment_id, dsts, extra, true);

    if (req.outputs < 1)
      throw wallet_rpc_error{error_code::TX_NOT_POSSIBLE, "Amount of outputs should be greater than 0."};

    std::set<uint32_t> subaddr_indices;
    if (req.subaddr_indices_all)
    {
      for (uint32_t i = 0; i < m_wallet->get_num_subaddresses(req.account_index); ++i)
        subaddr_indices.insert(i);
    }
    else
    {
      subaddr_indices = std::move(req.subaddr_indices);
    }

    {
      uint32_t priority = convert_priority(req.priority);
      std::vector<wallet2::pending_tx> ptx_vector = m_wallet->create_transactions_all(req.below_amount, dsts[0].addr, dsts[0].is_subaddress, req.outputs, CRYPTONOTE_DEFAULT_TX_MIXIN, req.unlock_time, priority, extra, req.account_index, subaddr_indices);

      fill_response(ptx_vector, req.get_tx_keys, res.tx_key_list, res.amount_list, res.fee_list, res.multisig_txset, res.unsigned_txset, req.do_not_relay, priority == tx_priority_blink,
            res.tx_hash_list, req.get_tx_hex, res.tx_blob_list, req.get_tx_metadata, res.tx_metadata_list);
    }
    return res;
  }
//------------------------------------------------------------------------------------------------------------------------------
  SWEEP_SINGLE::response wallet_rpc_server::invoke(SWEEP_SINGLE::request&& req)
  {
    std::vector<cryptonote::tx_destination_entry> dsts;
    std::vector<uint8_t> extra;

    require_open();
    SWEEP_SINGLE::response res{};

    if (req.outputs < 1)
      throw wallet_rpc_error{error_code::TX_NOT_POSSIBLE, "Amount of outputs should be greater than 0."};

    // validate the transfer requested and populate dsts & extra
    std::list<wallet::transfer_destination> destination;
    destination.emplace_back();
    destination.back().amount = 0;
    destination.back().address = req.address;
    validate_transfer(destination, req.payment_id, dsts, extra, true);

    crypto::key_image ki;
    if (!tools::hex_to_type(req.key_image, ki))
      throw wallet_rpc_error{error_code::WRONG_KEY_IMAGE, "failed to parse key image"};

    {
      uint32_t priority = convert_priority(req.priority);
      std::vector<wallet2::pending_tx> ptx_vector = m_wallet->create_transactions_single(ki, dsts[0].addr, dsts[0].is_subaddress, req.outputs, CRYPTONOTE_DEFAULT_TX_MIXIN, req.unlock_time, priority, extra);

      if (ptx_vector.empty())
        throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "No outputs found"};
      if (ptx_vector.size() > 1)
        throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Multiple transactions are created, which is not supposed to happen"};
      const wallet2::pending_tx &ptx = ptx_vector[0];
      if (ptx.selected_transfers.size() > 1)
        throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "The transaction uses multiple inputs, which is not supposed to happen"};

      fill_response(ptx_vector, req.get_tx_key, res.tx_key, res.amount, res.fee, res.multisig_txset, res.unsigned_txset, req.do_not_relay, priority == tx_priority_blink,
          res.tx_hash, req.get_tx_hex, res.tx_blob, req.get_tx_metadata, res.tx_metadata);
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  RELAY_TX::response wallet_rpc_server::invoke(RELAY_TX::request&& req)
  {
    require_open();
    RELAY_TX::response res{};

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.hex, blob))
      throw wallet_rpc_error{error_code::BAD_HEX, "Failed to parse hex."};

    wallet::pending_tx ptx;
    try
    {
      std::istringstream iss(blob);
      boost::archive::portable_binary_iarchive ar(iss);
      ar >> ptx;
    }
    catch (...)
    {
      throw wallet_rpc_error{error_code::BAD_TX_METADATA, "Failed to parse tx metadata."};
    }

    try
    {
      m_wallet->commit_tx(ptx, req.blink);
    }
    catch(const std::exception &e)
    {
      throw wallet_rpc_error{error_code::GENERIC_TRANSFER_ERROR, "Failed to commit tx."};
    }

    res.tx_hash = tools::type_to_hex(cryptonote::get_transaction_hash(ptx.tx));

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  MAKE_INTEGRATED_ADDRESS::response wallet_rpc_server::invoke(MAKE_INTEGRATED_ADDRESS::request&& req)
  {
    require_open();
    MAKE_INTEGRATED_ADDRESS::response res{};
    {
      crypto::hash8 payment_id;
      if (req.payment_id.empty())
      {
        payment_id = crypto::rand<crypto::hash8>();
      }
      else
      {
        if (!tools::hex_to_type(req.payment_id,payment_id))
          throw wallet_rpc_error{error_code::WRONG_PAYMENT_ID, "Invalid payment ID"};
      }

      if (req.standard_address.empty())
      {
        res.integrated_address = m_wallet->get_integrated_address_as_str(payment_id);
      }
      else
      {
        cryptonote::address_parse_info info;
        if(!get_account_address_from_str(info, m_wallet->nettype(), req.standard_address))
          throw wallet_rpc_error{error_code::WRONG_ADDRESS, "Invalid address"};
        if (info.is_subaddress)
          throw wallet_rpc_error{error_code::WRONG_ADDRESS, "Subaddress shouldn't be used"};
        if (info.has_payment_id)
          throw wallet_rpc_error{error_code::WRONG_ADDRESS, "Already integrated address"};
        if (req.payment_id.empty())
          throw wallet_rpc_error{error_code::WRONG_PAYMENT_ID, "Payment ID shouldn't be left unspecified"};
        res.integrated_address = get_account_integrated_address_as_str(m_wallet->nettype(), info.address, payment_id);
      }
      res.payment_id = tools::type_to_hex(payment_id);
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SPLIT_INTEGRATED_ADDRESS::response wallet_rpc_server::invoke(SPLIT_INTEGRATED_ADDRESS::request&& req)
  {
    require_open();
    SPLIT_INTEGRATED_ADDRESS::response res{};
    {
      cryptonote::address_parse_info info;

      if(!get_account_address_from_str(info, m_wallet->nettype(), req.integrated_address))
        throw wallet_rpc_error{error_code::WRONG_ADDRESS, "Invalid address"};
      if(!info.has_payment_id)
        throw wallet_rpc_error{error_code::WRONG_ADDRESS, "Address is not an integrated address"};
      res.standard_address = get_account_address_as_str(m_wallet->nettype(), info.is_subaddress, info.address);
      res.payment_id = tools::type_to_hex(info.payment_id);
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  STORE::response wallet_rpc_server::invoke(STORE::request&& req)
  {
    require_open();
    m_wallet->store();
    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_PAYMENTS::response wallet_rpc_server::invoke(GET_PAYMENTS::request&& req)
  {
    require_open();
    GET_PAYMENTS::response res{};
    crypto::hash payment_id;
    crypto::hash8 payment_id8;
    cryptonote::blobdata payment_id_blob;
    if(!epee::string_tools::parse_hexstr_to_binbuff(req.payment_id, payment_id_blob))
      throw wallet_rpc_error{error_code::WRONG_PAYMENT_ID, "Payment ID has invalid format"};

    {
      if(sizeof(payment_id) == payment_id_blob.size())
      {
        payment_id = *reinterpret_cast<const crypto::hash*>(payment_id_blob.data());
      }
      else if(sizeof(payment_id8) == payment_id_blob.size())
      {
        payment_id8 = *reinterpret_cast<const crypto::hash8*>(payment_id_blob.data());
        memcpy(payment_id.data, payment_id8.data, 8);
        memset(payment_id.data + 8, 0, 24);
      }
      else
        throw wallet_rpc_error{error_code::WRONG_PAYMENT_ID, "Payment ID has invalid size: " + req.payment_id};
    }

    std::list<wallet2::payment_details> payment_list;
    m_wallet->get_payments(payment_id, payment_list);
    for (auto& payment : payment_list)
    {
      wallet_rpc::payment_details& rpc_payment = res.payments.emplace_back();
      rpc_payment.payment_id   = req.payment_id;
      rpc_payment.tx_hash      = tools::type_to_hex(payment.m_tx_hash);
      rpc_payment.amount       = payment.m_amount;
      rpc_payment.block_height = payment.m_block_height;
      rpc_payment.unlock_time  = payment.m_unlock_time;
      rpc_payment.locked       = !m_wallet->is_transfer_unlocked(payment.m_unlock_time, payment.m_block_height, payment.m_unmined_blink);
      rpc_payment.subaddr_index = payment.m_subaddr_index;
      rpc_payment.address      = m_wallet->get_subaddress_as_str(payment.m_subaddr_index);
    }

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_BULK_PAYMENTS::response wallet_rpc_server::invoke(GET_BULK_PAYMENTS::request&& req)
  {
    require_open();
    GET_BULK_PAYMENTS::response res{};

    /* If the payment ID list is empty, we get payments to any payment ID (or lack thereof) */
    if (req.payment_ids.empty())
    {
      std::list<std::pair<crypto::hash,wallet2::payment_details>> payment_list;
      m_wallet->get_payments(payment_list, req.min_block_height);

      for (auto & payment : payment_list)
      {
        wallet_rpc::payment_details& rpc_payment = res.payments.emplace_back();
        rpc_payment.payment_id   = tools::type_to_hex(payment.first);
        rpc_payment.tx_hash      = tools::type_to_hex(payment.second.m_tx_hash);
        rpc_payment.amount       = payment.second.m_amount;
        rpc_payment.block_height = payment.second.m_block_height;
        rpc_payment.unlock_time  = payment.second.m_unlock_time;
        rpc_payment.subaddr_index = payment.second.m_subaddr_index;
        rpc_payment.address      = m_wallet->get_subaddress_as_str(payment.second.m_subaddr_index);
        rpc_payment.locked       = !m_wallet->is_transfer_unlocked(payment.second.m_unlock_time, payment.second.m_block_height, payment.second.m_unmined_blink);
      }

      return res;
    }

    for (auto & payment_id_str : req.payment_ids)
    {
      crypto::hash payment_id;
      crypto::hash8 payment_id8;
      cryptonote::blobdata payment_id_blob;

      // TODO - should the whole thing fail because of one bad id?
      bool r;
      if (payment_id_str.size() == 2 * sizeof(payment_id))
      {
        r = tools::hex_to_type(payment_id_str, payment_id);
      }
      else if (payment_id_str.size() == 2 * sizeof(payment_id8))
      {
        r = tools::hex_to_type(payment_id_str, payment_id8);
        if (r)
        {
          memcpy(payment_id.data, payment_id8.data, 8);
          memset(payment_id.data + 8, 0, 24);
        }
      }
      else
        throw wallet_rpc_error{error_code::WRONG_PAYMENT_ID, "Payment ID has invalid size: " + payment_id_str};

      if(!r)
        throw wallet_rpc_error{error_code::WRONG_PAYMENT_ID, "Payment ID has invalid format: " + payment_id_str};

      std::list<wallet2::payment_details> payment_list;
      m_wallet->get_payments(payment_id, payment_list, req.min_block_height);

      for (auto & payment : payment_list)
      {
        wallet_rpc::payment_details& rpc_payment = res.payments.emplace_back();
        rpc_payment.payment_id   = payment_id_str;
        rpc_payment.tx_hash      = tools::type_to_hex(payment.m_tx_hash);
        rpc_payment.amount       = payment.m_amount;
        rpc_payment.block_height = payment.m_block_height;
        rpc_payment.unlock_time  = payment.m_unlock_time;
        rpc_payment.subaddr_index = payment.m_subaddr_index;
        rpc_payment.address      = m_wallet->get_subaddress_as_str(payment.m_subaddr_index);
        rpc_payment.locked       = !m_wallet->is_transfer_unlocked(payment.m_unlock_time, payment.m_block_height, payment.m_unmined_blink);
      }
    }

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  INCOMING_TRANSFERS::response wallet_rpc_server::invoke(INCOMING_TRANSFERS::request&& req)
  {
    require_open();
    INCOMING_TRANSFERS::response res{};
    if(req.transfer_type.compare("all") != 0 && req.transfer_type.compare("available") != 0 && req.transfer_type.compare("unavailable") != 0)
      throw wallet_rpc_error{error_code::TRANSFER_TYPE, "Transfer type must be one of: all, available, or unavailable"};

    bool filter = false;
    bool available = false;
    if (req.transfer_type.compare("available") == 0)
    {
      filter = true;
      available = true;
    }
    else if (req.transfer_type.compare("unavailable") == 0)
    {
      filter = true;
      available = false;
    }

    wallet2::transfer_container transfers;
    m_wallet->get_transfers(transfers);

    for (const auto& td : transfers)
    {
      if (!filter || available != td.m_spent)
      {
        if (req.account_index != td.m_subaddr_index.major || (!req.subaddr_indices.empty() && req.subaddr_indices.count(td.m_subaddr_index.minor) == 0))
          continue;
        wallet_rpc::transfer_details& rpc_transfers = res.transfers.emplace_back();
        rpc_transfers.amount       = td.amount();
        rpc_transfers.spent        = td.m_spent;
        rpc_transfers.global_index = td.m_global_output_index;
        rpc_transfers.tx_hash      = tools::type_to_hex(td.m_txid);
        rpc_transfers.subaddr_index = {td.m_subaddr_index.major, td.m_subaddr_index.minor};
        rpc_transfers.key_image    = td.m_key_image_known ? tools::type_to_hex(td.m_key_image) : "";
        rpc_transfers.block_height = td.m_block_height;
        rpc_transfers.frozen       = td.m_frozen;
        rpc_transfers.unlocked     = m_wallet->is_transfer_unlocked(td);
      }
    }

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  QUERY_KEY::response wallet_rpc_server::invoke(QUERY_KEY::request&& req)
  {
      require_open();
      QUERY_KEY::response res{};

      if (req.key_type.compare("mnemonic") == 0)
      {
        epee::wipeable_string seed;
        bool ready;
        if (m_wallet->multisig(&ready))
        {
          if (!ready)
            throw wallet_rpc_error{error_code::NOT_MULTISIG, "This wallet is multisig, but not yet finalized"};
          if (!m_wallet->get_multisig_seed(seed))
            throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to get multisig seed."};
        }
        else
        {
          if (m_wallet->watch_only())
            throw wallet_rpc_error{error_code::WATCH_ONLY, "The wallet is watch-only. Cannot retrieve seed."};
          if (!m_wallet->is_deterministic())
            throw wallet_rpc_error{error_code::NON_DETERMINISTIC, "The wallet is non-deterministic. Cannot display seed."};
          if (!m_wallet->get_seed(seed))
            throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to get seed."};
        }
        res.key = std::string(seed.data(), seed.size()); // send to the network, then wipe RAM :D
      }
      else if(req.key_type.compare("view_key") == 0)
      {
          epee::wipeable_string key = epee::to_hex::wipeable_string(m_wallet->get_account().get_keys().m_view_secret_key);
          res.key = std::string(key.data(), key.size());
      }
      else if(req.key_type.compare("spend_key") == 0)
      {
          if (m_wallet->watch_only())
            throw wallet_rpc_error{error_code::WATCH_ONLY, "The wallet is watch-only. Cannot retrieve spend key."};
          epee::wipeable_string key = epee::to_hex::wipeable_string(m_wallet->get_account().get_keys().m_spend_secret_key);
          res.key = std::string(key.data(), key.size());
      }
      else
        throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "key_type " + req.key_type + " not found"};

      return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  RESCAN_BLOCKCHAIN::response wallet_rpc_server::invoke(RESCAN_BLOCKCHAIN::request&& req)
  {
    require_open();
    m_wallet->rescan_blockchain(req.hard);
    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SIGN::response wallet_rpc_server::invoke(SIGN::request&& req)
  {
    require_open();
    if (m_wallet->watch_only())
      throw wallet_rpc_error{error_code::WATCH_ONLY, "Unable to sign a value using a watch-only wallet."};

    SIGN::response res{};

    res.signature = m_wallet->sign(req.data, {req.account_index, req.address_index});
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  VERIFY::response wallet_rpc_server::invoke(VERIFY::request&& req)
  {
    require_open();
    VERIFY::response res{};

    cryptonote::address_parse_info info = extract_account_addr(m_wallet->nettype(), req.address);

    res.good = m_wallet->verify(req.data, info.address, req.signature);
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  STOP_WALLET::response wallet_rpc_server::invoke(STOP_WALLET::request&& req)
  {
    m_stop = true;
    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SET_TX_NOTES::response wallet_rpc_server::invoke(SET_TX_NOTES::request&& req)
  {
    require_open();

    if (req.txids.size() != req.notes.size())
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Different amount of txids and notes"};

    std::list<crypto::hash> txids;
    std::list<std::string>::const_iterator i = req.txids.begin();
    while (i != req.txids.end())
    {
      cryptonote::blobdata txid_blob;
      if(!epee::string_tools::parse_hexstr_to_binbuff(*i++, txid_blob) || txid_blob.size() != sizeof(crypto::hash))
        throw wallet_rpc_error{error_code::WRONG_TXID, "TX ID has invalid format"};

      crypto::hash txid = *reinterpret_cast<const crypto::hash*>(txid_blob.data());
      txids.push_back(txid);
    }

    std::list<crypto::hash>::const_iterator il = txids.begin();
    std::list<std::string>::const_iterator in = req.notes.begin();
    while (il != txids.end())
    {
      m_wallet->set_tx_note(*il++, *in++);
    }

    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_TX_NOTES::response wallet_rpc_server::invoke(GET_TX_NOTES::request&& req)
  {
    require_open();
    GET_TX_NOTES::response res{};

    std::list<crypto::hash> txids;
    std::list<std::string>::const_iterator i = req.txids.begin();
    while (i != req.txids.end())
    {
      cryptonote::blobdata txid_blob;
      if(!epee::string_tools::parse_hexstr_to_binbuff(*i++, txid_blob) || txid_blob.size() != sizeof(crypto::hash))
        throw wallet_rpc_error{error_code::WRONG_TXID, "TX ID has invalid format"};

      crypto::hash txid = *reinterpret_cast<const crypto::hash*>(txid_blob.data());
      txids.push_back(txid);
    }

    std::list<crypto::hash>::const_iterator il = txids.begin();
    while (il != txids.end())
    {
      res.notes.push_back(m_wallet->get_tx_note(*il++));
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SET_ATTRIBUTE::response wallet_rpc_server::invoke(SET_ATTRIBUTE::request&& req)
  {
    require_open();
    m_wallet->set_attribute(req.key, req.value);
    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_ATTRIBUTE::response wallet_rpc_server::invoke(GET_ATTRIBUTE::request&& req)
  {
    require_open();
    GET_ATTRIBUTE::response res{};

    if (!m_wallet->get_attribute(req.key, res.value))
      throw wallet_rpc_error{error_code::ATTRIBUTE_NOT_FOUND, "Attribute not found."};
    return res;
  }
  GET_TX_KEY::response wallet_rpc_server::invoke(GET_TX_KEY::request&& req)
  {
    require_open();
    GET_TX_KEY::response res{};

    crypto::hash txid;
    if (!tools::hex_to_type(req.txid, txid))
      throw wallet_rpc_error{error_code::WRONG_TXID, "TX ID has invalid format"};

    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    if (!m_wallet->get_tx_key(txid, tx_key, additional_tx_keys))
      throw wallet_rpc_error{error_code::NO_TXKEY, "No tx secret key is stored for this tx"};

    epee::wipeable_string s;
    s += epee::to_hex::wipeable_string(tx_key);
    for (size_t i = 0; i < additional_tx_keys.size(); ++i)
      s += epee::to_hex::wipeable_string(additional_tx_keys[i]);
    res.tx_key = std::string(s.data(), s.size());
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  CHECK_TX_KEY::response wallet_rpc_server::invoke(CHECK_TX_KEY::request&& req)
  {
    require_open();
    CHECK_TX_KEY::response res{};

    crypto::hash txid;
    if (!tools::hex_to_type(req.txid, txid))
      throw wallet_rpc_error{error_code::WRONG_TXID, "TX ID has invalid format"};

    epee::wipeable_string tx_key_str = req.tx_key;
    if (tx_key_str.size() < 64 || tx_key_str.size() % 64)
      throw wallet_rpc_error{error_code::WRONG_KEY, "Tx key has invalid format"};
    const char *data = tx_key_str.data();
    crypto::secret_key tx_key;
    if (!epee::wipeable_string(data, 64).hex_to_pod(unwrap(unwrap(tx_key))))
      throw wallet_rpc_error{error_code::WRONG_KEY, "Tx key has invalid format"};
    size_t offset = 64;
    std::vector<crypto::secret_key> additional_tx_keys;
    while (offset < tx_key_str.size())
    {
      additional_tx_keys.resize(additional_tx_keys.size() + 1);
      if (!epee::wipeable_string(data + offset, 64).hex_to_pod(unwrap(unwrap(additional_tx_keys.back()))))
        throw wallet_rpc_error{error_code::WRONG_KEY, "Tx key has invalid format"};
      offset += 64;
    }

    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, m_wallet->nettype(), req.address))
      throw wallet_rpc_error{error_code::WRONG_ADDRESS, "Invalid address"};

    m_wallet->check_tx_key(txid, tx_key, additional_tx_keys, info.address, res.received, res.in_pool, res.confirmations);
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_TX_PROOF::response wallet_rpc_server::invoke(GET_TX_PROOF::request&& req)
  {
    require_open();
    GET_TX_PROOF::response res{};

    crypto::hash txid;
    if (!tools::hex_to_type(req.txid, txid))
      throw wallet_rpc_error{error_code::WRONG_TXID, "TX ID has invalid format"};

    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, m_wallet->nettype(), req.address))
      throw wallet_rpc_error{error_code::WRONG_ADDRESS, "Invalid address"};

    res.signature = m_wallet->get_tx_proof(txid, info.address, info.is_subaddress, req.message);
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  CHECK_TX_PROOF::response wallet_rpc_server::invoke(CHECK_TX_PROOF::request&& req)
  {
    require_open();
    CHECK_TX_PROOF::response res{};

    crypto::hash txid;
    if (!tools::hex_to_type(req.txid, txid))
      throw wallet_rpc_error{error_code::WRONG_TXID, "TX ID has invalid format"};

    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, m_wallet->nettype(), req.address))
      throw wallet_rpc_error{error_code::WRONG_ADDRESS, "Invalid address"};

    {
      res.good = m_wallet->check_tx_proof(txid, info.address, info.is_subaddress, req.message, req.signature, res.received, res.in_pool, res.confirmations);
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_SPEND_PROOF::response wallet_rpc_server::invoke(GET_SPEND_PROOF::request&& req)
  {
    require_open();
    GET_SPEND_PROOF::response res{};

    crypto::hash txid;
    if (!tools::hex_to_type(req.txid, txid))
      throw wallet_rpc_error{error_code::WRONG_TXID, "TX ID has invalid format"};

    res.signature = m_wallet->get_spend_proof(txid, req.message);
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  CHECK_SPEND_PROOF::response wallet_rpc_server::invoke(CHECK_SPEND_PROOF::request&& req)
  {
    require_open();
    CHECK_SPEND_PROOF::response res{};

    crypto::hash txid;
    if (!tools::hex_to_type(req.txid, txid))
      throw wallet_rpc_error{error_code::WRONG_TXID, "TX ID has invalid format"};

    res.good = m_wallet->check_spend_proof(txid, req.message, req.signature);
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_RESERVE_PROOF::response wallet_rpc_server::invoke(GET_RESERVE_PROOF::request&& req)
  {
    require_open();
    GET_RESERVE_PROOF::response res{};

    std::optional<std::pair<uint32_t, uint64_t>> account_minreserve;
    if (!req.all)
    {
      if (req.account_index >= m_wallet->get_num_subaddress_accounts())
        throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Account index is out of bound"};
      account_minreserve = std::make_pair(req.account_index, req.amount);
    }

    res.signature = m_wallet->get_reserve_proof(account_minreserve, req.message);
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  CHECK_RESERVE_PROOF::response wallet_rpc_server::invoke(CHECK_RESERVE_PROOF::request&& req)
  {
    require_open();
    CHECK_RESERVE_PROOF::response res{};

    cryptonote::address_parse_info info;
    if (!get_account_address_from_str(info, m_wallet->nettype(), req.address))
      throw wallet_rpc_error{error_code::WRONG_ADDRESS, "Invalid address"};
    if (info.is_subaddress)
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Address must not be a subaddress"};

    res.good = m_wallet->check_reserve_proof(info.address, req.message, req.signature, res.total, res.spent);
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_TRANSFERS::response wallet_rpc_server::invoke(GET_TRANSFERS::request&& req)
  {
    require_open();
    GET_TRANSFERS::response res{};

    wallet2::get_transfers_args_t args = {};
    args.in               = req.in;
    args.out              = req.out;
    args.pending          = req.pending;
    args.failed           = req.failed;
    args.pool             = req.pool;
    args.stake            = req.stake;
    args.filter_by_height = req.filter_by_height;
    args.min_height       = req.min_height;
    args.max_height       = req.max_height;
    args.subaddr_indices  = req.subaddr_indices;
    args.account_index    = req.account_index;
    args.all_accounts     = req.all_accounts;

    std::vector<wallet::transfer_view> transfers;
    m_wallet->get_transfers(args, transfers);

    for (wallet::transfer_view& entry : transfers)
    {
      // TODO(oxen): This discrepancy between having to use pay_type if type is
      // empty and type if pay type is neither is super unintuitive.
      if (entry.pay_type == wallet::pay_type::in ||
          entry.pay_type == wallet::pay_type::miner ||
          entry.pay_type == wallet::pay_type::governance ||
          entry.pay_type == wallet::pay_type::service_node)
      {
        res.in.push_back(std::move(entry));
      }
      else if (entry.pay_type == wallet::pay_type::out || entry.pay_type == wallet::pay_type::stake)
      {
        res.out.push_back(std::move(entry));
      }
      else if (entry.type == "pending")
      {
        res.pending.push_back(std::move(entry));
      }
      else if (entry.type == "failed")
      {
        res.failed.push_back(std::move(entry));
      }
      else if (entry.type == "pool")
      {
        res.pool.push_back(std::move(entry));
      }
    }

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_TRANSFERS_CSV::response wallet_rpc_server::invoke(GET_TRANSFERS_CSV::request&& req)
  {
    require_open();
    GET_TRANSFERS_CSV::response res{};

    wallet2::get_transfers_args_t args;
    args.in = req.in;
    args.out = req.out;
    args.stake = req.stake;
    args.pending = req.pending;
    args.failed = req.failed;
    args.pool = req.pool;
    args.coinbase = req.coinbase;
    args.filter_by_height = req.filter_by_height;
    args.min_height = req.min_height;
    args.max_height = req.max_height;
    args.subaddr_indices = req.subaddr_indices;
    args.account_index = req.account_index;
    args.all_accounts = req.all_accounts;

    std::vector<wallet::transfer_view> transfers;
    m_wallet->get_transfers(args, transfers);

    const bool formatting = false;
    res.csv = m_wallet->transfers_to_csv(transfers, formatting);

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_TRANSFER_BY_TXID::response wallet_rpc_server::invoke(GET_TRANSFER_BY_TXID::request&& req)
  {
    require_open();
    GET_TRANSFER_BY_TXID::response res{};

    crypto::hash txid;
    cryptonote::blobdata txid_blob;
    if(!epee::string_tools::parse_hexstr_to_binbuff(req.txid, txid_blob))
      throw wallet_rpc_error{error_code::WRONG_TXID, "Transaction ID has invalid format"};

    if(sizeof(txid) == txid_blob.size())
    {
      txid = *reinterpret_cast<const crypto::hash*>(txid_blob.data());
    }
    else
      throw wallet_rpc_error{error_code::WRONG_TXID, "Transaction ID has invalid size: " + req.txid};

    if (req.account_index >= m_wallet->get_num_subaddress_accounts())
      throw wallet_rpc_error{error_code::ACCOUNT_INDEX_OUT_OF_BOUNDS, "Account index is out of bound"};

    std::list<std::pair<crypto::hash, tools::wallet2::payment_details>> payments;
    m_wallet->get_payments(payments, 0, (uint64_t)-1, req.account_index);
    for (std::list<std::pair<crypto::hash, tools::wallet2::payment_details>>::const_iterator i = payments.begin(); i != payments.end(); ++i) {
      if (i->second.m_tx_hash == txid)
      {
        res.transfers.push_back(m_wallet->make_transfer_view(i->second.m_tx_hash, i->first, i->second));
      }
    }

    std::list<std::pair<crypto::hash, tools::wallet2::confirmed_transfer_details>> payments_out;
    m_wallet->get_payments_out(payments_out, 0, (uint64_t)-1, req.account_index);
    for (std::list<std::pair<crypto::hash, tools::wallet2::confirmed_transfer_details>>::const_iterator i = payments_out.begin(); i != payments_out.end(); ++i) {
      if (i->first == txid)
      {
        res.transfers.push_back(m_wallet->make_transfer_view(i->first, i->second));
      }
    }

    std::list<std::pair<crypto::hash, tools::wallet2::unconfirmed_transfer_details>> upayments;
    m_wallet->get_unconfirmed_payments_out(upayments, req.account_index);
    for (std::list<std::pair<crypto::hash, tools::wallet2::unconfirmed_transfer_details>>::const_iterator i = upayments.begin(); i != upayments.end(); ++i) {
      if (i->first == txid)
      {
        res.transfers.push_back(m_wallet->make_transfer_view(i->first, i->second));
      }
    }

    std::list<std::pair<crypto::hash, tools::wallet2::pool_payment_details>> pool_payments;
    m_wallet->get_unconfirmed_payments(pool_payments, req.account_index);
    for (std::list<std::pair<crypto::hash, tools::wallet2::pool_payment_details>>::const_iterator i = pool_payments.begin(); i != pool_payments.end(); ++i) {
      if (i->second.m_pd.m_tx_hash == txid)
      {
        res.transfers.push_back(m_wallet->make_transfer_view(i->first, i->second));
      }
    }

    if (!res.transfers.empty())
    {
      res.transfer = res.transfers.front(); // backward compat
      return res;
    }

    throw wallet_rpc_error{error_code::WRONG_TXID, "Transaction not found."};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  EXPORT_OUTPUTS::response wallet_rpc_server::invoke(EXPORT_OUTPUTS::request&& req)
  {
    require_open();
    EXPORT_OUTPUTS::response res{};
    if (m_wallet->key_on_device())
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "command not supported by HW wallet"};

    res.outputs_data_hex = oxenmq::to_hex(m_wallet->export_outputs_to_str(req.all));

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  IMPORT_OUTPUTS::response wallet_rpc_server::invoke(IMPORT_OUTPUTS::request&& req)
  {
    require_open();
    IMPORT_OUTPUTS::response res{};
    if (m_wallet->key_on_device())
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "command not supported by HW wallet"};

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.outputs_data_hex, blob))
      throw wallet_rpc_error{error_code::BAD_HEX, "Failed to parse hex."};

    res.num_imported = m_wallet->import_outputs_from_str(blob);

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  EXPORT_KEY_IMAGES::response wallet_rpc_server::invoke(EXPORT_KEY_IMAGES::request&& req)
  {
    require_open();
    EXPORT_KEY_IMAGES::response res{};
    {
      std::pair<size_t, std::vector<std::pair<crypto::key_image, crypto::signature>>> ski = m_wallet->export_key_images(req.requested_only);
      res.offset = ski.first;
      res.signed_key_images.resize(ski.second.size());
      for (size_t n = 0; n < ski.second.size(); ++n)
      {
         res.signed_key_images[n].key_image = tools::type_to_hex(ski.second[n].first);
         res.signed_key_images[n].signature = tools::type_to_hex(ski.second[n].second);
      }
    }

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  IMPORT_KEY_IMAGES::response wallet_rpc_server::invoke(IMPORT_KEY_IMAGES::request&& req)
  {
    require_open();
    IMPORT_KEY_IMAGES::response res{};
    if (!m_wallet->is_trusted_daemon())
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "This command requires a trusted daemon."};
    {
      std::vector<std::pair<crypto::key_image, crypto::signature>> ski;
      ski.resize(req.signed_key_images.size());
      for (size_t n = 0; n < ski.size(); ++n)
      {
        if (!tools::hex_to_type(req.signed_key_images[n].key_image, ski[n].first))
          throw wallet_rpc_error{error_code::WRONG_KEY_IMAGE, "failed to parse key image"};

        if (!tools::hex_to_type(req.signed_key_images[n].signature, ski[n].second))
          throw wallet_rpc_error{error_code::WRONG_SIGNATURE, "failed to parse signature"};
      }
      uint64_t spent = 0, unspent = 0;
      uint64_t height = m_wallet->import_key_images(ski, req.offset, spent, unspent);
      res.spent = spent;
      res.unspent = unspent;
      res.height = height;
    }

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  MAKE_URI::response wallet_rpc_server::invoke(MAKE_URI::request&& req)
  {
    require_open();
    MAKE_URI::response res{};
    std::string error;
    res.uri = m_wallet->make_uri(req.address, req.payment_id, req.amount, req.tx_description, req.recipient_name, error);
    if (res.uri.empty())
      throw wallet_rpc_error{error_code::WRONG_URI, std::string("Cannot make URI from supplied parameters: ") + error};

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  PARSE_URI::response wallet_rpc_server::invoke(PARSE_URI::request&& req)
  {
    require_open();
    PARSE_URI::response res{};
    std::string error;
    if (!m_wallet->parse_uri(req.uri, res.uri.address, res.uri.payment_id, res.uri.amount, res.uri.tx_description, res.uri.recipient_name, res.unknown_parameters, error))
      throw wallet_rpc_error{error_code::WRONG_URI, "Error parsing URI: " + error};
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_ADDRESS_BOOK_ENTRY::response wallet_rpc_server::invoke(GET_ADDRESS_BOOK_ENTRY::request&& req)
  {
    require_open();
    GET_ADDRESS_BOOK_ENTRY::response res{};
    const auto ab = m_wallet->get_address_book();
    if (req.entries.empty())
    {
      uint64_t idx = 0;
      for (const auto &entry: ab)
      {
        std::string address;
        if (entry.m_has_payment_id)
          address = cryptonote::get_account_integrated_address_as_str(m_wallet->nettype(), entry.m_address, entry.m_payment_id);
        else
          address = get_account_address_as_str(m_wallet->nettype(), entry.m_is_subaddress, entry.m_address);
        res.entries.push_back(wallet_rpc::GET_ADDRESS_BOOK_ENTRY::entry{idx++, address, entry.m_description});
      }
    }
    else
    {
      for (uint64_t idx: req.entries)
      {
        if (idx >= ab.size())
          throw wallet_rpc_error{error_code::WRONG_INDEX, "Index out of range: " + std::to_string(idx)};
        const auto &entry = ab[idx];
        std::string address;
        if (entry.m_has_payment_id)
          address = cryptonote::get_account_integrated_address_as_str(m_wallet->nettype(), entry.m_address, entry.m_payment_id);
        else
          address = get_account_address_as_str(m_wallet->nettype(), entry.m_is_subaddress, entry.m_address);
        res.entries.push_back(wallet_rpc::GET_ADDRESS_BOOK_ENTRY::entry{idx, address, entry.m_description});
      }
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  ADD_ADDRESS_BOOK_ENTRY::response wallet_rpc_server::invoke(ADD_ADDRESS_BOOK_ENTRY::request&& req)
  {
    require_open();
    ADD_ADDRESS_BOOK_ENTRY::response res{};

    cryptonote::address_parse_info info = extract_account_addr(m_wallet->nettype(), req.address);

    if (!m_wallet->add_address_book_row(info.address, info.has_payment_id ? &info.payment_id : NULL, req.description, info.is_subaddress))
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to add address book entry"};
    res.index = m_wallet->get_address_book().size() - 1;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  EDIT_ADDRESS_BOOK_ENTRY::response wallet_rpc_server::invoke(EDIT_ADDRESS_BOOK_ENTRY::request&& req)
  {
    require_open();

    const auto ab = m_wallet->get_address_book();
    if (req.index >= ab.size())
      throw wallet_rpc_error{error_code::WRONG_INDEX, "Index out of range: " + std::to_string(req.index)};

    tools::wallet2::address_book_row entry = ab[req.index];

    if (req.set_address)
    {
      cryptonote::address_parse_info info = extract_account_addr(m_wallet->nettype(), req.address);
      entry.m_address = info.address;
      entry.m_is_subaddress = info.is_subaddress;
      if (info.has_payment_id)
        entry.m_payment_id = info.payment_id;
    }

    if (req.set_description)
      entry.m_description = req.description;

    if (!m_wallet->set_address_book_row(req.index, entry.m_address, req.set_address && entry.m_has_payment_id ? &entry.m_payment_id : NULL, entry.m_description, entry.m_is_subaddress))
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to edit address book entry"};
    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  DELETE_ADDRESS_BOOK_ENTRY::response wallet_rpc_server::invoke(DELETE_ADDRESS_BOOK_ENTRY::request&& req)
  {
    require_open();

    const auto ab = m_wallet->get_address_book();
    if (req.index >= ab.size())
      throw wallet_rpc_error{error_code::WRONG_INDEX, "Index out of range: " + std::to_string(req.index)};
    if (!m_wallet->delete_address_book_row(req.index))
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to delete address book entry"};
    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  REFRESH::response wallet_rpc_server::invoke(REFRESH::request&& req)
  {
    require_open();
    REFRESH::response res{};
    m_wallet->refresh(m_wallet->is_trusted_daemon(), req.start_height, res.blocks_fetched, res.received_money);
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  AUTO_REFRESH::response wallet_rpc_server::invoke(AUTO_REFRESH::request&& req)
  {
    m_auto_refresh_period = req.enable ? req.period ? std::chrono::seconds{req.period} : DEFAULT_AUTO_REFRESH_PERIOD : 0s;
    MINFO("Auto refresh now " << (m_auto_refresh_period != 0s ? std::to_string(std::chrono::duration<float>(m_auto_refresh_period).count()) + " seconds" : std::string("disabled")));
    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  RESCAN_SPENT::response wallet_rpc_server::invoke(RESCAN_SPENT::request&& req)
  {
    require_open();
    m_wallet->rescan_spent();
    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  START_MINING::response wallet_rpc_server::invoke(START_MINING::request&& req)
  {
    require_open();
    if (!m_wallet->is_trusted_daemon())
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "This command requires a trusted daemon."};

    size_t max_mining_threads_count = (std::max)(tools::get_max_concurrency(), static_cast<unsigned>(2));
    if (req.threads_count < 1 || max_mining_threads_count < req.threads_count)
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "The specified number of threads is inappropriate."};

    rpc::START_MINING::request daemon_req{}; 
    daemon_req.miner_address = m_wallet->get_account().get_public_address_str(m_wallet->nettype());
    daemon_req.threads_count = req.threads_count;

    rpc::START_MINING::response daemon_res{};
    bool r = m_wallet->invoke_http<rpc::START_MINING>(daemon_req, daemon_res);
    if (!r || daemon_res.status != rpc::STATUS_OK)
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Couldn't start mining due to unknown error."};
    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  STOP_MINING::response wallet_rpc_server::invoke(STOP_MINING::request&& req)
  {
    require_open();
    rpc::STOP_MINING::response daemon_res{};
    bool r = m_wallet->invoke_http<rpc::STOP_MINING>({}, daemon_res);
    if (!r || daemon_res.status != rpc::STATUS_OK)
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Couldn't stop mining due to unknown error."};
    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_LANGUAGES::response wallet_rpc_server::invoke(GET_LANGUAGES::request&& req)
  {
    GET_LANGUAGES::response res{};
    crypto::ElectrumWords::get_language_list(res.languages, true);
    crypto::ElectrumWords::get_language_list(res.languages_local, false);
    return res;
  }

namespace {
  namespace po = boost::program_options;
  // Gross hack because wallet2 only takes password via a po::variables_map because it's just great
  // like that.
  po::variables_map password_arg_hack(const std::string& password, po::variables_map vm)
  {
    po::options_description desc("dummy");
    const command_line::arg_descriptor<std::string, true> arg_password = {"password", "password"};
    const char *argv[3];
    int argc = 3;
    argv[0] = "wallet-rpc";
    argv[1] = "--password";
    argv[2] = password.c_str();
    command_line::add_arg(desc, arg_password);
    po::store(po::parse_command_line(argc, argv, desc), vm);
    return vm;
  }
}

  //------------------------------------------------------------------------------------------------------------------------------
  CREATE_WALLET::response wallet_rpc_server::invoke(CREATE_WALLET::request&& req)
  {
    if (m_wallet_dir.empty())
      throw wallet_rpc_error{error_code::NO_WALLET_DIR, "No wallet dir configured"};

    const char *ptr = strchr(req.filename.c_str(), '/');
#ifdef _WIN32
    if (!ptr)
      ptr = strchr(req.filename.c_str(), '\\');
    if (!ptr)
      ptr = strchr(req.filename.c_str(), ':');
#endif
    if (ptr)
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Invalid filename"};
    fs::path wallet_file = req.filename.empty() ? fs::path{} : m_wallet_dir / fs::u8path(req.filename);
    if (!req.hardware_wallet)
    {
      std::vector<std::string> languages;
      crypto::ElectrumWords::get_language_list(languages, false);
      std::vector<std::string>::iterator it;

      it = std::find(languages.begin(), languages.end(), req.language);
      if (it == languages.end())
      {
        crypto::ElectrumWords::get_language_list(languages, true);
        it = std::find(languages.begin(), languages.end(), req.language);
      }
      if (it == languages.end())
        throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Unknown language: " + req.language};
    }
    auto vm2 = password_arg_hack(req.password, m_vm);
    std::unique_ptr<tools::wallet2> wal = tools::wallet2::make_new(vm2, true, nullptr).first;
    if (!wal)
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to create wallet"};

    if (!req.hardware_wallet)
      wal->set_seed_language(req.language);

    rpc::GET_HEIGHT::request hreq{};
    rpc::GET_HEIGHT::response hres{};
    hres.height = 0;
    bool r = wal->invoke_http<rpc::GET_HEIGHT>(hreq, hres);
    if (r)
      wal->set_refresh_from_block_height(hres.height);

    if (req.hardware_wallet)
      wal->restore_from_device(wallet_file, req.password, req.device_name.empty() ? "Ledger" : req.device_name);
    else
      wal->generate(wallet_file, req.password);

    close_wallet(true);
    m_wallet = std::move(wal);
    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  OPEN_WALLET::response wallet_rpc_server::invoke(OPEN_WALLET::request&& req)
  {
    if (m_wallet_dir.empty())
      throw wallet_rpc_error{error_code::NO_WALLET_DIR, "No wallet dir configured"};

    const char *ptr = strchr(req.filename.c_str(), '/');
#ifdef _WIN32
    if (!ptr)
      ptr = strchr(req.filename.c_str(), '\\');
    if (!ptr)
      ptr = strchr(req.filename.c_str(), ':');
#endif
    if (ptr)
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Invalid filename"};

    close_wallet(req.autosave_current);

    fs::path wallet_file = m_wallet_dir / fs::u8path(req.filename);
    auto vm2 = password_arg_hack(req.password, m_vm);
    std::unique_ptr<tools::wallet2> wal = tools::wallet2::make_from_file(vm2, true, wallet_file, nullptr).first;
    if (!wal)
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to open wallet"};

    m_wallet = std::move(wal);
    start_long_poll_thread();

    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  CLOSE_WALLET::response wallet_rpc_server::invoke(CLOSE_WALLET::request&& req)
  {
    require_open();
    close_wallet(req.autosave_current);
    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  CHANGE_WALLET_PASSWORD::response wallet_rpc_server::invoke(CHANGE_WALLET_PASSWORD::request&& req)
  {
    require_open();
    if (m_wallet->verify_password(req.old_password))
    {
      m_wallet->change_password(m_wallet->get_wallet_file(), req.old_password, req.new_password);
      LOG_PRINT_L0("Wallet password changed.");
    }
    else
      throw wallet_rpc_error{error_code::INVALID_PASSWORD, "Invalid original password."};
    return {};
  }

  static fs::path get_wallet_path(fs::path dir, fs::path filename)
  {
    if (filename.has_parent_path())
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Invalid filename"};
    auto wallet_file = filename.empty() ? filename : dir / filename;
    // check if wallet file already exists
    if (std::error_code ec; !wallet_file.empty() && fs::exists(wallet_file, ec))
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Wallet already exists."};
    return wallet_file;
  }

  //------------------------------------------------------------------------------------------------------------------------------
  GENERATE_FROM_KEYS::response wallet_rpc_server::invoke(GENERATE_FROM_KEYS::request&& req)
  {
    if (m_wallet_dir.empty())
      throw wallet_rpc_error{error_code::NO_WALLET_DIR, "No wallet dir configured"};

    // early check for mandatory fields
    if (req.viewkey.empty())
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "field 'viewkey' is mandatory. Please provide a view key you want to restore from."};
    if (req.address.empty())
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "field 'address' is mandatory. Please provide a public address."};

    GENERATE_FROM_KEYS::response res{};

    auto wallet_file = get_wallet_path(m_wallet_dir, fs::u8path(req.filename));

    auto vm2 = password_arg_hack(req.password, m_vm);
    auto rc = tools::wallet2::make_new(vm2, true, nullptr);
    std::unique_ptr<wallet2> wal;
    wal = std::move(rc.first);
    if (!wal)
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to create wallet"};

    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, wal->nettype(), req.address))
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to parse public address"};

    epee::wipeable_string password = rc.second.password();
    epee::wipeable_string viewkey_string = req.viewkey;
    crypto::secret_key viewkey;
    if (!viewkey_string.hex_to_pod(unwrap(unwrap(viewkey))))
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to parse view key secret key"};

    close_wallet(req.autosave_current);

    {
      if (!req.spendkey.empty())
      {
        epee::wipeable_string spendkey_string = req.spendkey;
        crypto::secret_key spendkey;
        if (!spendkey_string.hex_to_pod(unwrap(unwrap(spendkey))))
          throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to parse spend key secret key"};
        wal->generate(wallet_file, std::move(rc.second).password(), info.address, spendkey, viewkey, false);
        res.info = "Wallet has been generated successfully.";
      }
      else
      {
        wal->generate(wallet_file, std::move(rc.second).password(), info.address, viewkey, false);
        res.info = "Watch-only wallet has been generated successfully.";
      }
      MINFO("Wallet has been generated.\n");
    }

    if (!wal)
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to generate wallet"};

    // set blockheight if given
    wal->set_refresh_from_block_height(req.restore_height);
    wal->rewrite(wallet_file, password);

    m_wallet = std::move(wal);
    res.address = m_wallet->get_account().get_public_address_str(m_wallet->nettype());
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  RESTORE_DETERMINISTIC_WALLET::response wallet_rpc_server::invoke(RESTORE_DETERMINISTIC_WALLET::request&& req)
  {
    if (m_wallet_dir.empty())
      throw wallet_rpc_error{error_code::NO_WALLET_DIR, "No wallet dir configured"};

    // early check for mandatory fields
    if (req.seed.empty())
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "field 'seed' is mandatory. Please provide a seed you want to restore from."};

    RESTORE_DETERMINISTIC_WALLET::response res{};

    auto wallet_file = get_wallet_path(m_wallet_dir, fs::u8path(req.filename));

    crypto::secret_key recovery_key;
    std::string old_language;

    // check the given seed
    {
      if (!crypto::ElectrumWords::words_to_bytes(req.seed, recovery_key, old_language))
        throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Electrum-style word list failed verification"};
    }
    close_wallet(req.autosave_current);

    // process seed_offset if given
    {
      if (!req.seed_offset.empty())
      {
        recovery_key = cryptonote::decrypt_key(recovery_key, req.seed_offset);
      }
    }

    auto vm2 = password_arg_hack(req.password, m_vm);
    auto rc = tools::wallet2::make_new(vm2, true, nullptr);
    std::unique_ptr<wallet2> wal;
    wal = std::move(rc.first);
    if (!wal)
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to create wallet"};

    epee::wipeable_string password = rc.second.password();

    bool was_deprecated_wallet = ((old_language == crypto::ElectrumWords::old_language_name) ||
                                  crypto::ElectrumWords::get_is_old_style_seed(req.seed));

    std::string mnemonic_language = old_language;
    if (was_deprecated_wallet)
    {
      // The user had used an older version of the wallet with old style mnemonics.
      res.was_deprecated = true;
    }

    if (old_language == crypto::ElectrumWords::old_language_name)
    {
      if (req.language.empty())
        throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Wallet was using the old seed language. You need to specify a new seed language."};
      std::vector<std::string> language_list;
      std::vector<std::string> language_list_en;
      crypto::ElectrumWords::get_language_list(language_list);
      crypto::ElectrumWords::get_language_list(language_list_en, true);
      if (std::find(language_list.begin(), language_list.end(), req.language) == language_list.end() &&
          std::find(language_list_en.begin(), language_list_en.end(), req.language) == language_list_en.end())
        throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Wallet was using the old seed language, and the specified new seed language is invalid."};
      mnemonic_language = req.language;
    }

    wal->set_seed_language(mnemonic_language);

    crypto::secret_key recovery_val = wal->generate(wallet_file, std::move(rc.second).password(), recovery_key, true, false, false);
    MINFO("Wallet has been restored.\n");

    // // Convert the secret key back to seed
    epee::wipeable_string electrum_words;
    if (!crypto::ElectrumWords::bytes_to_words(recovery_val, electrum_words, mnemonic_language))
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to encode seed"};
    res.seed = std::string(electrum_words.data(), electrum_words.size());

    if (!wal)
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Failed to generate wallet"};

    // set blockheight if given
    wal->set_refresh_from_block_height(req.restore_height);
    wal->rewrite(wallet_file, password);

    m_wallet = std::move(wal);
    res.address = m_wallet->get_account().get_public_address_str(m_wallet->nettype());
    res.info = "Wallet has been restored successfully.";
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  IS_MULTISIG::response wallet_rpc_server::invoke(IS_MULTISIG::request&& req)
  {
    require_open();
    IS_MULTISIG::response res{};
    res.multisig = m_wallet->multisig(&res.ready, &res.threshold, &res.total);
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  PREPARE_MULTISIG::response wallet_rpc_server::invoke(PREPARE_MULTISIG::request&& req)
  {
    require_open();
    PREPARE_MULTISIG::response res{};
    if (m_wallet->multisig())
      throw wallet_rpc_error{error_code::ALREADY_MULTISIG, "This wallet is already multisig"};
    if (m_wallet->watch_only())
      throw wallet_rpc_error{error_code::WATCH_ONLY, "wallet is watch-only and cannot be made multisig"};

    res.multisig_info = m_wallet->get_multisig_info();
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  MAKE_MULTISIG::response wallet_rpc_server::invoke(MAKE_MULTISIG::request&& req)
  {
    require_open();
    MAKE_MULTISIG::response res{};
    if (m_wallet->multisig())
      throw wallet_rpc_error{error_code::ALREADY_MULTISIG, "This wallet is already multisig"};
    if (m_wallet->watch_only())
      throw wallet_rpc_error{error_code::WATCH_ONLY, "wallet is watch-only and cannot be made multisig"};

    res.multisig_info = m_wallet->make_multisig(req.password, req.multisig_info, req.threshold);
    res.address = m_wallet->get_account().get_public_address_str(m_wallet->nettype());

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  EXPORT_MULTISIG::response wallet_rpc_server::invoke(EXPORT_MULTISIG::request&& req)
  {
    require_open();
    EXPORT_MULTISIG::response res{};
    bool ready;
    if (!m_wallet->multisig(&ready))
      throw wallet_rpc_error{error_code::NOT_MULTISIG, "This wallet is not multisig"};
    if (!ready)
      throw wallet_rpc_error{error_code::NOT_MULTISIG, "This wallet is multisig, but not yet finalized"};

    cryptonote::blobdata info;
    info = m_wallet->export_multisig();

    res.info = oxenmq::to_hex(info);

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  IMPORT_MULTISIG::response wallet_rpc_server::invoke(IMPORT_MULTISIG::request&& req)
  {
    require_open();
    IMPORT_MULTISIG::response res{};
    bool ready;
    uint32_t threshold, total;
    if (!m_wallet->multisig(&ready, &threshold, &total))
      throw wallet_rpc_error{error_code::NOT_MULTISIG, "This wallet is not multisig"};
    if (!ready)
      throw wallet_rpc_error{error_code::NOT_MULTISIG, "This wallet is multisig, but not yet finalized"};

    if (req.info.size() < threshold - 1)
      throw wallet_rpc_error{error_code::THRESHOLD_NOT_REACHED, "Needs multisig export info from more participants"};

    std::vector<cryptonote::blobdata> info;
    info.resize(req.info.size());
    for (size_t n = 0; n < info.size(); ++n)
    {
      if (!epee::string_tools::parse_hexstr_to_binbuff(req.info[n], info[n]))
        throw wallet_rpc_error{error_code::BAD_HEX, "Failed to parse hex."};
    }

    res.n_outputs = m_wallet->import_multisig(info);

    if (m_wallet->is_trusted_daemon())
    {
      try
      {
        m_wallet->rescan_spent();
      }
      catch (...) {}
    }

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  FINALIZE_MULTISIG::response wallet_rpc_server::invoke(FINALIZE_MULTISIG::request&& req)
  {
    require_open();
    FINALIZE_MULTISIG::response res{};
    bool ready;
    uint32_t threshold, total;
    if (!m_wallet->multisig(&ready, &threshold, &total))
      throw wallet_rpc_error{error_code::NOT_MULTISIG, "This wallet is not multisig"};
    if (ready)
      throw wallet_rpc_error{error_code::ALREADY_MULTISIG, "This wallet is multisig, and already finalized"};

    if (req.multisig_info.size() < 1 || req.multisig_info.size() > total)
      throw wallet_rpc_error{error_code::THRESHOLD_NOT_REACHED, "Needs multisig info from more participants"};

    if (!m_wallet->finalize_multisig(req.password, req.multisig_info))
      throw wallet_rpc_error{error_code::UNKNOWN_ERROR, "Error calling finalize_multisig"};
    res.address = m_wallet->get_account().get_public_address_str(m_wallet->nettype());

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  EXCHANGE_MULTISIG_KEYS::response wallet_rpc_server::invoke(EXCHANGE_MULTISIG_KEYS::request&& req)
  {
    require_open();
    EXCHANGE_MULTISIG_KEYS::response res{};
    bool ready;
    uint32_t threshold, total;
    if (!m_wallet->multisig(&ready, &threshold, &total))
      throw wallet_rpc_error{error_code::NOT_MULTISIG, "This wallet is not multisig"};

    if (ready)
      throw wallet_rpc_error{error_code::ALREADY_MULTISIG, "This wallet is multisig, and already finalized"};

    if (req.multisig_info.size() < 1 || req.multisig_info.size() > total)
      throw wallet_rpc_error{error_code::THRESHOLD_NOT_REACHED, "Needs multisig info from more participants"};

    {
      res.multisig_info = m_wallet->exchange_multisig_keys(req.password, req.multisig_info);
      if (res.multisig_info.empty())
      {
        res.address = m_wallet->get_account().get_public_address_str(m_wallet->nettype());
      }
    }
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SIGN_MULTISIG::response wallet_rpc_server::invoke(SIGN_MULTISIG::request&& req)
  {
    require_open();
    SIGN_MULTISIG::response res{};
    bool ready;
    uint32_t threshold, total;
    if (!m_wallet->multisig(&ready, &threshold, &total))
      throw wallet_rpc_error{error_code::NOT_MULTISIG, "This wallet is not multisig"};
    if (!ready)
      throw wallet_rpc_error{error_code::NOT_MULTISIG, "This wallet is multisig, but not yet finalized"};

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.tx_data_hex, blob))
      throw wallet_rpc_error{error_code::BAD_HEX, "Failed to parse hex."};

    wallet::multisig_tx_set txs;
    bool r = m_wallet->load_multisig_tx(blob, txs, nullptr);
    if (!r)
      throw wallet_rpc_error{error_code::BAD_MULTISIG_TX_DATA, "Failed to parse multisig tx data."};

    std::vector<crypto::hash> txids;
    try
    {
      bool r = m_wallet->sign_multisig_tx(txs, txids);
      if (!r)
        throw wallet_rpc_error{error_code::MULTISIG_SIGNATURE, "Failed to sign multisig tx"};
    }
    catch (const std::exception &e)
    {
      throw wallet_rpc_error{error_code::MULTISIG_SIGNATURE, "Failed to sign multisig tx: "s + e.what()};
    }

    res.tx_data_hex = oxenmq::to_hex(m_wallet->save_multisig_tx(txs));
    if (!txids.empty())
    {
      for (const crypto::hash &txid: txids)
        res.tx_hash_list.push_back(tools::type_to_hex(txid));
    }

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SUBMIT_MULTISIG::response wallet_rpc_server::invoke(SUBMIT_MULTISIG::request&& req)
  {
    require_open();
    SUBMIT_MULTISIG::response res{};
    bool ready;
    uint32_t threshold, total;
    if (!m_wallet->multisig(&ready, &threshold, &total))
      throw wallet_rpc_error{error_code::NOT_MULTISIG, "This wallet is not multisig"};
    if (!ready)
      throw wallet_rpc_error{error_code::NOT_MULTISIG, "This wallet is multisig, but not yet finalized"};

    cryptonote::blobdata blob;
    if (!epee::string_tools::parse_hexstr_to_binbuff(req.tx_data_hex, blob))
      throw wallet_rpc_error{error_code::BAD_HEX, "Failed to parse hex."};

    tools::wallet2::multisig_tx_set txs;
    bool r = m_wallet->load_multisig_tx(blob, txs, nullptr);
    if (!r)
      throw wallet_rpc_error{error_code::BAD_MULTISIG_TX_DATA, "Failed to parse multisig tx data."};

    if (txs.m_signers.size() < threshold)
      throw wallet_rpc_error{error_code::THRESHOLD_NOT_REACHED, "Not enough signers signed this transaction."};

    try
    {
      for (auto &ptx: txs.m_ptx)
      {
        m_wallet->commit_tx(ptx);
        res.tx_hash_list.push_back(tools::type_to_hex(cryptonote::get_transaction_hash(ptx.tx)));
      }
    }
    catch (const std::exception &e)
    {
      throw wallet_rpc_error{error_code::MULTISIG_SUBMISSION, std::string("Failed to submit multisig tx: ") + e.what()};
    }

    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  VALIDATE_ADDRESS::response wallet_rpc_server::invoke(VALIDATE_ADDRESS::request&& req)
  {
    VALIDATE_ADDRESS::response res{};
    cryptonote::address_parse_info info;
    const struct { cryptonote::network_type type; const char *stype; } net_types[] = {
      { cryptonote::MAINNET, "mainnet" },
      { cryptonote::TESTNET, "testnet" },
      { cryptonote::DEVNET, "devnet" },
    };
    if (!req.any_net_type && !m_wallet)
      require_open();

    for (const auto &net_type: net_types)
    {
      if (!req.any_net_type && (!m_wallet || net_type.type != m_wallet->nettype()))
        continue;
      if (req.allow_openalias)
      {
        res.valid = false;
        try {
          info = extract_account_addr(net_type.type, req.address);
          res.valid = true;
        } catch (...) {}

        if (res.valid)
          res.openalias_address = info.as_str(net_type.type);
      }
      else
      {
        res.valid = cryptonote::get_account_address_from_str(info, net_type.type, req.address);
      }
      if (res.valid)
      {
        res.integrated = info.has_payment_id;
        res.subaddress = info.is_subaddress;
        res.nettype = net_type.stype;
        return res;
      }
    }

    res.valid = false;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SET_DAEMON::response wallet_rpc_server::invoke(SET_DAEMON::request&& req)
  {
    require_open();

    if (!m_wallet->set_daemon(req.address, std::nullopt, req.proxy, req.trusted))
      throw wallet_rpc_error{error_code::NO_DAEMON_CONNECTION, std::string("Unable to set daemon")};

    m_wallet->m_http_client.set_https_client_cert(req.ssl_certificate_path, req.ssl_private_key_path);
    m_wallet->m_http_client.set_insecure_https(req.ssl_allow_any_cert);
    m_wallet->m_http_client.set_https_cainfo(req.ssl_ca_file);

    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SET_LOG_LEVEL::response wallet_rpc_server::invoke(SET_LOG_LEVEL::request&& req)
  {
    if (req.level < 0 || req.level > 4)
      throw wallet_rpc_error{error_code::INVALID_LOG_LEVEL, "Error: log level not valid"};
    mlog_set_log_level(req.level);
    return {};
  }
  //------------------------------------------------------------------------------------------------------------------------------
  SET_LOG_CATEGORIES::response wallet_rpc_server::invoke(SET_LOG_CATEGORIES::request&& req)
  {
    mlog_set_log(req.categories.c_str());
    SET_LOG_CATEGORIES::response res{};
    res.categories = mlog_get_categories();
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------
  GET_VERSION::response wallet_rpc_server::invoke(GET_VERSION::request&& req)
  {
    GET_VERSION::response res{};
    res.version = WALLET_RPC_VERSION;
    return res;
  }
  //------------------------------------------------------------------------------------------------------------------------------

  //
  // Oxen
  //
  STAKE::response wallet_rpc_server::invoke(STAKE::request&& req)
  {
    require_open();
    STAKE::response res{};

    crypto::public_key snode_key             = {};
    cryptonote::address_parse_info addr_info = {};
    if (!cryptonote::get_account_address_from_str(addr_info, m_wallet->nettype(), req.destination))
      throw wallet_rpc_error{error_code::WRONG_ADDRESS, std::string("Unparsable address given: ") + req.destination};

    if (!tools::hex_to_type(req.service_node_key, snode_key))
      throw wallet_rpc_error{error_code::WRONG_KEY, std::string("Unparsable service node key given: ") + req.service_node_key};

    tools::wallet2::stake_result stake_result = m_wallet->create_stake_tx(snode_key, req.amount, 0 /*amount_fraction*/, req.priority, req.subaddr_indices);
    if (stake_result.status != tools::wallet2::stake_result_status::success)
      throw wallet_rpc_error{error_code::TX_NOT_POSSIBLE, stake_result.msg};

    std::vector<tools::wallet2::pending_tx> ptx_vector = {stake_result.ptx};

    fill_response(ptx_vector, req.get_tx_key, res.tx_key, res.amount, res.fee, res.multisig_txset, res.unsigned_txset, req.do_not_relay, false /*blink*/,
          res.tx_hash, req.get_tx_hex, res.tx_blob, req.get_tx_metadata, res.tx_metadata);

    return res;
  }

  REGISTER_SERVICE_NODE::response wallet_rpc_server::invoke(REGISTER_SERVICE_NODE::request&& req)
  {
    require_open();
    REGISTER_SERVICE_NODE::response res{};

    std::vector<std::string> args;
    boost::split(args, req.register_service_node_str, boost::is_any_of(" "));

    if (args.size() > 0)
    {
      if (args[0] == "register_service_node")
        args.erase(args.begin());
    }

    // NOTE(oxen): Pre-emptively set subaddr_account to 0. We don't support onwards from Infinite Staking which is when this call was implemented.
    tools::wallet2::register_service_node_result register_result = m_wallet->create_register_service_node_tx(args, 0 /*subaddr_account*/);
    if (register_result.status != tools::wallet2::register_service_node_result_status::success)
      throw wallet_rpc_error{error_code::TX_NOT_POSSIBLE, register_result.msg};

    std::vector<tools::wallet2::pending_tx> ptx_vector = {register_result.ptx};
    fill_response(ptx_vector, req.get_tx_key, res.tx_key, res.amount, res.fee, res.multisig_txset, res.unsigned_txset, req.do_not_relay, false /*blink*/,
          res.tx_hash, req.get_tx_hex, res.tx_blob, req.get_tx_metadata, res.tx_metadata);

    return res;
  }

  CAN_REQUEST_STAKE_UNLOCK::response wallet_rpc_server::invoke(CAN_REQUEST_STAKE_UNLOCK::request&& req)
  {
    require_open();
    CAN_REQUEST_STAKE_UNLOCK::response res{};

    crypto::public_key snode_key             = {};
    if (!tools::hex_to_type(req.service_node_key, snode_key))
      throw wallet_rpc_error{error_code::WRONG_KEY, std::string("Unparsable service node key given: ") + req.service_node_key};

    tools::wallet2::request_stake_unlock_result unlock_result = m_wallet->can_request_stake_unlock(snode_key);
    res.can_unlock = unlock_result.success;
    res.msg        = unlock_result.msg;
    return res;
  }

  // TODO(oxen): Deprecate this and make it return the TX as hex? Then just transfer it as normal? But these have no fees and or amount .. so maybe not?
  REQUEST_STAKE_UNLOCK::response wallet_rpc_server::invoke(REQUEST_STAKE_UNLOCK::request&& req)
  {
    require_open();
    REQUEST_STAKE_UNLOCK::response res{};

    crypto::public_key snode_key             = {};
    if (!tools::hex_to_type(req.service_node_key, snode_key))
      throw wallet_rpc_error{error_code::WRONG_KEY, std::string("Unparsable service node key given: ") + req.service_node_key};

    tools::wallet2::request_stake_unlock_result unlock_result = m_wallet->can_request_stake_unlock(snode_key);
    if (unlock_result.success)
    {
      try
      {
        m_wallet->commit_tx(unlock_result.ptx);
      }
      catch(const std::exception &e)
      {
        throw wallet_rpc_error{error_code::GENERIC_TRANSFER_ERROR, "Failed to commit tx."};
      }
    }
    else
      throw wallet_rpc_error{error_code::GENERIC_TRANSFER_ERROR, "Cannot request stake unlock: " + unlock_result.msg};

    res.unlocked = unlock_result.success;
    res.msg      = unlock_result.msg;
    return res;
  }

  LNS_BUY_MAPPING::response wallet_rpc_server::invoke(LNS_BUY_MAPPING::request&& req)
  {
    require_open();
    LNS_BUY_MAPPING::response res{};

    std::string reason;
    auto type = m_wallet->lns_validate_type(req.type, lns::lns_tx_type::buy, &reason);
    if (!type)
      throw wallet_rpc_error{error_code::TX_NOT_POSSIBLE, "Invalid LNS buy type: " + reason};

    std::vector<wallet2::pending_tx> ptx_vector = m_wallet->lns_create_buy_mapping_tx(*type,
                                                                                      req.owner.size() ? &req.owner : nullptr,
                                                                                      req.backup_owner.size() ? &req.backup_owner : nullptr,
                                                                                      req.name,
                                                                                      req.value,
                                                                                      &reason,
                                                                                      req.priority,
                                                                                      req.account_index,
                                                                                      req.subaddr_indices);
    if (ptx_vector.empty())
      throw wallet_rpc_error{error_code::TX_NOT_POSSIBLE, "Failed to create LNS transaction: " + reason};

    //Save the LNS record to the wallet cache
    std::string name_hash_str = lns::name_to_base64_hash(req.name);
    tools::wallet2::lns_detail detail = {
      *type,
      req.name,
      name_hash_str};
    m_wallet->set_lns_cache_record(detail);

    fill_response(         ptx_vector,
                           req.get_tx_key,
                           res.tx_key,
                           res.amount,
                           res.fee,
                           res.multisig_txset,
                           res.unsigned_txset,
                           req.do_not_relay,
                           false /*blink*/,
                           res.tx_hash,
                           req.get_tx_hex,
                           res.tx_blob,
                           req.get_tx_metadata,
                           res.tx_metadata);

    return res;
  }

  LNS_RENEW_MAPPING::response wallet_rpc_server::invoke(LNS_RENEW_MAPPING::request&& req)
  {
    require_open();
    LNS_RENEW_MAPPING::response res{};

    std::string reason;
    auto type = m_wallet->lns_validate_type(req.type, lns::lns_tx_type::renew, &reason);
    if (!type)
      throw wallet_rpc_error{error_code::TX_NOT_POSSIBLE, "Invalid LNS renewal type: " + reason};

    std::vector<wallet2::pending_tx> ptx_vector = m_wallet->lns_create_renewal_tx(
        *type, req.name, &reason, req.priority, req.account_index, req.subaddr_indices);

    if (ptx_vector.empty())
      throw wallet_rpc_error{error_code::TX_NOT_POSSIBLE, "Failed to create LNS renewal transaction: " + reason};

    fill_response(         ptx_vector,
                           req.get_tx_key,
                           res.tx_key,
                           res.amount,
                           res.fee,
                           res.multisig_txset,
                           res.unsigned_txset,
                           req.do_not_relay,
                           false /*blink*/,
                           res.tx_hash,
                           req.get_tx_hex,
                           res.tx_blob,
                           req.get_tx_metadata,
                           res.tx_metadata);

    return res;
  }

  LNS_UPDATE_MAPPING::response wallet_rpc_server::invoke(LNS_UPDATE_MAPPING::request&& req)
  {
    require_open();
    LNS_UPDATE_MAPPING::response res{};

    std::string reason;
    auto type = m_wallet->lns_validate_type(req.type, lns::lns_tx_type::update, &reason);
    if (!type)
      throw wallet_rpc_error{error_code::TX_NOT_POSSIBLE, "Invalid LNS update type: " + reason};

    std::vector<wallet2::pending_tx> ptx_vector =
        m_wallet->lns_create_update_mapping_tx(*type,
                                               req.name,
                                               req.value.empty()        ? nullptr : &req.value,
                                               req.owner.empty()        ? nullptr : &req.owner,
                                               req.backup_owner.empty() ? nullptr : &req.backup_owner,
                                               req.signature.empty()    ? nullptr : &req.signature,
                                               &reason,
                                               req.priority,
                                               req.account_index,
                                               req.subaddr_indices);

    if (ptx_vector.empty())
      throw wallet_rpc_error{error_code::TX_NOT_POSSIBLE, "Failed to create LNS update transaction: " + reason};

    // Save the updated LNS record to the wallet cache
    std::string name_hash_str = lns::name_to_base64_hash(req.name);
    m_wallet->delete_lns_cache_record(name_hash_str);
    tools::wallet2::lns_detail detail = {
      *type,
      req.name,
      name_hash_str};
    m_wallet->set_lns_cache_record(detail);

    fill_response(         ptx_vector,
                           req.get_tx_key,
                           res.tx_key,
                           res.amount,
                           res.fee,
                           res.multisig_txset,
                           res.unsigned_txset,
                           req.do_not_relay,
                           false /*blink*/,
                           res.tx_hash,
                           req.get_tx_hex,
                           res.tx_blob,
                           req.get_tx_metadata,
                           res.tx_metadata);

    return res;
  }

  LNS_MAKE_UPDATE_SIGNATURE::response wallet_rpc_server::invoke(LNS_MAKE_UPDATE_SIGNATURE::request&& req)
  {
    require_open();
    LNS_MAKE_UPDATE_SIGNATURE::response res{};

    std::string reason;
    lns::mapping_type type;
    std::optional<uint8_t> hf_version = m_wallet->get_hard_fork_version();
    if (!hf_version) throw wallet_rpc_error{error_code::HF_QUERY_FAILED, tools::ERR_MSG_NETWORK_VERSION_QUERY_FAILED};
    if (!lns::validate_mapping_type(req.type, *hf_version, lns::lns_tx_type::update, &type, &reason))
      throw wallet_rpc_error{error_code::WRONG_LNS_TYPE, "Wrong lns type given=" + reason};

    lns::generic_signature signature;
    if (!m_wallet->lns_make_update_mapping_signature(type,
                                                     req.name,
                                                     req.encrypted_value.size() ? &req.encrypted_value : nullptr,
                                                     req.owner.size() ? &req.owner : nullptr,
                                                     req.backup_owner.size() ? &req.backup_owner : nullptr,
                                                     signature,
                                                     req.account_index,
                                                     &reason))
      throw wallet_rpc_error{error_code::TX_NOT_POSSIBLE, "Failed to create signature for LNS update transaction: " + reason};

    res.signature = tools::type_to_hex(signature.ed25519);
    return res;
  }

  LNS_HASH_NAME::response wallet_rpc_server::invoke(LNS_HASH_NAME::request&& req)
  {
    require_open();
    LNS_HASH_NAME::response res{};

    std::string reason;
    lns::mapping_type type;
    std::optional<uint8_t> hf_version = m_wallet->get_hard_fork_version();
    if (!hf_version) throw wallet_rpc_error{error_code::HF_QUERY_FAILED, tools::ERR_MSG_NETWORK_VERSION_QUERY_FAILED};
    if (!lns::validate_mapping_type(req.type, *hf_version, lns::lns_tx_type::lookup, &type, &reason))
      throw wallet_rpc_error{error_code::WRONG_LNS_TYPE, "Wrong lns type given=" + reason};

    if (!lns::validate_lns_name(type, req.name, &reason))
      throw wallet_rpc_error{error_code::LNS_BAD_NAME, "Bad lns name given=" + reason};

    res.name = lns::name_to_base64_hash(req.name);
    return res;
  }

  LNS_KNOWN_NAMES::response wallet_rpc_server::invoke(LNS_KNOWN_NAMES::request&& req)
  {
    require_open();
    LNS_KNOWN_NAMES::response res{};

    std::vector<lns::mapping_type> entry_types;
    auto cache = m_wallet->get_lns_cache();
    res.known_names.reserve(cache.size());
    entry_types.reserve(cache.size());
    for (auto& [name, details] : m_wallet->get_lns_cache())
    {
      auto& entry = res.known_names.emplace_back();
      auto& type = entry_types.emplace_back(details.type);
      if (type > lns::mapping_type::lokinet && type <= lns::mapping_type::lokinet_10years)
        type = lns::mapping_type::lokinet;
      entry.type = lns::mapping_type_str(type);
      entry.hashed = details.hashed_name;
      entry.name = details.name;
    }

    auto nettype = m_wallet->nettype();
    rpc::LNS_NAMES_TO_OWNERS::request lookup_req{};
    lookup_req.include_expired = req.include_expired;

    uint64_t curr_height = req.include_expired ? m_wallet->get_blockchain_current_height() : 0;

    // Query oxend for the full record info
    for (auto it = res.known_names.begin(); it != res.known_names.end(); )
    {
      const size_t num_entries = std::distance(it, res.known_names.end());
      const auto end = num_entries < rpc::LNS_NAMES_TO_OWNERS::MAX_REQUEST_ENTRIES
          ? res.known_names.end()
          : it + rpc::LNS_NAMES_TO_OWNERS::MAX_REQUEST_ENTRIES;
      lookup_req.entries.clear();
      lookup_req.entries.reserve(std::distance(it, end));
      for (auto it2 = it; it2 != end; it2++)
      {
        auto& e = lookup_req.entries.emplace_back();
        e.name_hash = it2->hashed;
        e.types.push_back(static_cast<uint16_t>(entry_types[std::distance(res.known_names.begin(), it2)]));
      }

      if (auto [success, records] = m_wallet->lns_names_to_owners(lookup_req); success)
      {
        size_t type_offset = std::distance(res.known_names.begin(), it);
        for (auto& rec : records)
        {
          if (rec.entry_index >= num_entries)
          {
            MWARNING("Got back invalid entry_index " << rec.entry_index << " for a request for " << num_entries << " entries");
            continue;
          }

          auto& res_e = *(it + rec.entry_index);
          res_e.owner = std::move(rec.owner);
          res_e.backup_owner = std::move(rec.backup_owner);
          res_e.encrypted_value = std::move(rec.encrypted_value);
          res_e.update_height = rec.update_height;
          res_e.expiration_height = rec.expiration_height;
          if (req.include_expired && res_e.expiration_height)
            res_e.expired = *res_e.expiration_height < curr_height;
          res_e.txid = std::move(rec.txid);

          if (req.decrypt && !res_e.encrypted_value.empty() && oxenmq::is_hex(res_e.encrypted_value))
          {
            lns::mapping_value value;
            const auto type = entry_types[type_offset + rec.entry_index];
            std::string errmsg;
            if (lns::mapping_value::validate_encrypted(type, oxenmq::from_hex(res_e.encrypted_value), &value, &errmsg)
                && value.decrypt(res_e.name, type))
              res_e.value = value.to_readable_value(nettype, type);
            else
              MWARNING("Failed to decrypt LNS value for " << res_e.name << (errmsg.empty() ? ""s : ": " + errmsg));
          }
        }
      }

      it = end;
    }

    // Erase anything we didn't get a response for (it will have update_height of 0)
    res.known_names.erase(std::remove_if(res.known_names.begin(), res.known_names.end(),
          [](const auto& n) { return n.update_height == 0; }),
        res.known_names.end());

    // Now sort whatever we got back
    std::sort(res.known_names.begin(), res.known_names.end(),
        [](const auto& a, const auto& b) { return std::make_pair(a.name, a.type) < std::make_pair(b.name, b.type); });

    return res;
  }

  LNS_ADD_KNOWN_NAMES::response wallet_rpc_server::invoke(LNS_ADD_KNOWN_NAMES::request&& req)
  {
    require_open();

    std::optional<uint8_t> hf_version = m_wallet->get_hard_fork_version();
    if (!hf_version) throw wallet_rpc_error{error_code::HF_QUERY_FAILED, tools::ERR_MSG_NETWORK_VERSION_QUERY_FAILED};

    std::string reason;
    for (auto& rec : req.names)
    {
      lns::mapping_type type;
      if (!lns::validate_mapping_type(rec.type, *hf_version, lns::lns_tx_type::lookup, &type, &reason))
        throw wallet_rpc_error{error_code::WRONG_LNS_TYPE, "Invalid LNS type: " + reason};

      auto name = tools::lowercase_ascii_string(rec.name);
      if (!lns::validate_lns_name(type, name, &reason))
        throw wallet_rpc_error{error_code::LNS_BAD_NAME, "Invalid LNS name '" + name + "': " + reason};

      m_wallet->set_lns_cache_record({type, name, lns::name_to_base64_hash(name)});
    }

    return {};
  }

  LNS_DECRYPT_VALUE::response wallet_rpc_server::invoke(LNS_DECRYPT_VALUE::request&& req)
  {
    require_open();
    LNS_DECRYPT_VALUE::response res{};

    // ---------------------------------------------------------------------------------------------
    //
    // Validate encrypted value
    //
    // ---------------------------------------------------------------------------------------------
    if (req.encrypted_value.size() % 2 != 0)
      throw wallet_rpc_error{error_code::LNS_VALUE_LENGTH_NOT_EVEN, "Value length not divisible by 2, length=" + std::to_string(req.encrypted_value.size())};

    if (req.encrypted_value.size() >= (lns::mapping_value::BUFFER_SIZE * 2))
      throw wallet_rpc_error{error_code::LNS_VALUE_TOO_LONG, "Value too long to decrypt=" + req.encrypted_value};

    if (!oxenmq::is_hex(req.encrypted_value))
      throw wallet_rpc_error{error_code::LNS_VALUE_NOT_HEX, "Value is not hex=" + req.encrypted_value};

    // ---------------------------------------------------------------------------------------------
    //
    // Validate type and name
    //
    // ---------------------------------------------------------------------------------------------
    std::string reason;
    lns::mapping_type type = {};

    std::optional<uint8_t> hf_version = m_wallet->get_hard_fork_version();
    if (!hf_version) throw wallet_rpc_error{error_code::HF_QUERY_FAILED, tools::ERR_MSG_NETWORK_VERSION_QUERY_FAILED};
    {
      if (!lns::validate_mapping_type(req.type, *hf_version, lns::lns_tx_type::lookup, &type, &reason))
        throw wallet_rpc_error{error_code::WRONG_LNS_TYPE, "Invalid LNS type: " + reason};

      if (!lns::validate_lns_name(type, req.name, &reason))
        throw wallet_rpc_error{error_code::LNS_BAD_NAME, "Invalid LNS name '" + req.name + "': " + reason};
    }

    // ---------------------------------------------------------------------------------------------
    //
    // Decrypt value
    //
    // ---------------------------------------------------------------------------------------------
    lns::mapping_value value = {};
    value.len = req.encrypted_value.size() / 2;
    value.encrypted = true;
    oxenmq::from_hex(req.encrypted_value.begin(), req.encrypted_value.end(), value.buffer.begin());

    if (!value.decrypt(req.name, type))
      throw wallet_rpc_error{error_code::LNS_VALUE_NOT_HEX, "Value decryption failure"};

    res.value = value.to_readable_value(m_wallet->nettype(), type);
    return res;
  }

  LNS_ENCRYPT_VALUE::response wallet_rpc_server::invoke(LNS_ENCRYPT_VALUE::request&& req)
  {
    require_open();

    if (req.value.size() > lns::mapping_value::BUFFER_SIZE)
      throw wallet_rpc_error{error_code::LNS_VALUE_TOO_LONG, "LNS value '" + req.value + "' is too long"};

    std::string reason;
    std::optional<uint8_t> hf_version = m_wallet->get_hard_fork_version();
    if (!hf_version) throw wallet_rpc_error{error_code::HF_QUERY_FAILED, tools::ERR_MSG_NETWORK_VERSION_QUERY_FAILED};

    lns::mapping_type type;
    if (!lns::validate_mapping_type(req.type, *hf_version, lns::lns_tx_type::lookup, &type, &reason))
      throw wallet_rpc_error{error_code::WRONG_LNS_TYPE, "Wrong lns type given=" + reason};

    if (!lns::validate_lns_name(type, req.name, &reason))
      throw wallet_rpc_error{error_code::LNS_BAD_NAME, "Invalid LNS name '" + req.name + "': " + reason};

    lns::mapping_value value;
    if (!lns::mapping_value::validate(m_wallet->nettype(), type, req.value, &value, &reason))
      throw wallet_rpc_error{error_code::LNS_BAD_VALUE, "Invalid LNS value '" + req.value + "': " + reason};

    bool old_argon2 = type == lns::mapping_type::session && *hf_version < cryptonote::network_version_16_pulse;
    if (!value.encrypt(req.name, nullptr, old_argon2))
      throw wallet_rpc_error{error_code::LNS_VALUE_ENCRYPT_FAILED, "Value encryption failure"};

    return {oxenmq::to_hex(value.to_view())};
  }

  std::unique_ptr<tools::wallet2> wallet_rpc_server::load_wallet()
  {
    std::unique_ptr<tools::wallet2> wal;
    {
      const bool testnet = tools::wallet2::has_testnet_option(m_vm);
      const bool devnet = tools::wallet2::has_devnet_option(m_vm);
      if (testnet && devnet)
        throw std::logic_error{tr("Can't specify more than one of --testnet and --devnet")};

      const auto arg_wallet_file = wallet_args::arg_wallet_file();
      const auto arg_from_json = wallet_args::arg_generate_from_json();

      const auto wallet_file = command_line::get_arg(m_vm, arg_wallet_file);
      const auto from_json = command_line::get_arg(m_vm, arg_from_json);
      const auto wallet_dir = command_line::get_arg(m_vm, arg_wallet_dir);
      const auto prompt_for_password = command_line::get_arg(m_vm, arg_prompt_for_password);
      const auto password_prompt = prompt_for_password ? password_prompter : nullptr;

      if(!wallet_file.empty() && !from_json.empty())
        throw std::logic_error{tr("Can't specify more than one of --wallet-file and --generate-from-json")};

      if (!wallet_dir.empty())
        return nullptr;

      if (wallet_file.empty() && from_json.empty())
        throw std::logic_error{tr("Must specify --wallet-file or --generate-from-json or --wallet-dir")};

      LOG_PRINT_L0(tools::wallet_rpc_server::tr("Loading wallet..."));
      if(!wallet_file.empty())
        wal = tools::wallet2::make_from_file(m_vm, true, wallet_file, password_prompt).first;
      else
        wal = tools::wallet2::make_from_json(m_vm, true, from_json, password_prompt).first;

      if (!wal) // safety check (the above should throw on error)
        throw std::runtime_error{"Failed to create wallet: (unknown reason)"};

      bool quit = false;
      tools::signal_handler::install([&wal, &quit](int) {
        assert(wal);
        quit = true;
        wal->stop();
      });

      wal->refresh(wal->is_trusted_daemon());
      // if we ^C during potentially length load/refresh, there's no server loop yet
      if (quit)
      {
        MINFO(tools::wallet_rpc_server::tr("Saving wallet..."));
        wal->store();
        MINFO(tools::wallet_rpc_server::tr("Successfully saved"));
        throw std::runtime_error{tr("Wallet loading cancelled before initial refresh completed")};
      }
      MINFO(tools::wallet_rpc_server::tr("Successfully loaded"));
    }
    return wal;
  }

  bool wallet_rpc_server::run(bool)
  {
    std::unique_ptr<tools::wallet2> wal;
    try
    {
      wal = load_wallet();
    }
    catch (const std::exception& e)
    {
      LOG_ERROR(tr("Wallet initialization failed: ") << e.what());
      return false;
    }

    m_long_poll_disabled = tools::wallet2::has_disable_rpc_long_poll(m_vm);
    if (wal) m_wallet = std::move(wal);
    bool r = init();
    CHECK_AND_ASSERT_MES(r, false, tools::wallet_rpc_server::tr("Failed to initialize wallet RPC server"));
    tools::signal_handler::install([this](int) {
      MWARNING("Shutting down...");
      m_stop = true;
    });

    LOG_PRINT_L0(tools::wallet_rpc_server::tr("Starting wallet RPC server"));
    try
    {
      run_loop();
    }
    catch (const std::exception &e)
    {
      LOG_ERROR(tools::wallet_rpc_server::tr("Failed to run wallet: ") << e.what());
      return false;
    }
    LOG_PRINT_L0(tools::wallet_rpc_server::tr("Stopped wallet RPC server"));
    try
    {
      close_wallet(true);
    }
    catch (const std::exception& e)
    {
      LOG_ERROR(tools::wallet_rpc_server::tr("Failed to save wallet: ") << e.what());
      return false;
    }
    return true;
  }

  void wallet_rpc_server::stop()
  {
    m_stop = true;
  }

}

int main(int argc, char **argv)
{
  TRY_ENTRY();

  namespace po = boost::program_options;

  const auto arg_wallet_file = wallet_args::arg_wallet_file();
  const auto arg_from_json = wallet_args::arg_generate_from_json();

  auto opt_size = command_line::boost_option_sizes();

  po::options_description desc_params(wallet_args::tr("Wallet options"), opt_size.first, opt_size.second);
  po::options_description hidden_params("Hidden");
  tools::wallet2::init_options(desc_params, hidden_params);
  command_line::add_arg(desc_params, arg_rpc_bind_port);
  command_line::add_arg(desc_params, arg_disable_rpc_login);
  command_line::add_arg(desc_params, arg_restricted);
  cryptonote::rpc_args::init_options(desc_params, hidden_params);
  command_line::add_arg(desc_params, arg_wallet_file);
  command_line::add_arg(desc_params, arg_from_json);
  command_line::add_arg(desc_params, arg_wallet_dir);
  command_line::add_arg(desc_params, arg_prompt_for_password);

  daemonizer::init_options(hidden_params, desc_params);

  auto [vm, should_terminate] = wallet_args::main(
    argc, argv,
    "oxen-wallet-rpc [--wallet-file=<file>|--generate-from-json=<file>|--wallet-dir=<directory>] [--rpc-bind-port=<port>]",
    tools::wallet_rpc_server::tr("This is the RPC oxen wallet. It needs to connect to a oxen\ndaemon to work correctly."),
    desc_params, hidden_params,
    po::positional_options_description(),
    [](const std::string &s, bool emphasis){ epee::set_console_color(emphasis ? epee::console_color_white : epee::console_color_default, emphasis); std::cout << s << std::endl; if (emphasis) epee::reset_console_color(); },
    "oxen-wallet-rpc.log",
    true
  );
  if (!vm)
    return 1;
  if (should_terminate)
    return 0;

  return daemonizer::daemonize<tools::wallet_rpc_server>("Wallet RPC Daemon", argc, const_cast<const char**>(argv), std::move(*vm))
      ? 0 : 1;

  CATCH_ENTRY_L0("main", 1);
}
