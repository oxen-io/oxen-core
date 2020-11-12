// Copyright (c) 2018-2020, The Loki Project
// Copyright (c) 2014-2019, The Monero Project
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

#include <boost/asio/ip/address.hpp>
#include <memory>
#include <stdexcept>
#include <lokimq/lokimq.h>
#include <utility>

#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_core.h"
#include "epee/misc_log_ex.h"
#if defined(PER_BLOCK_CHECKPOINT)
#include "blocks/blocks.h"
#endif
#include "rpc/daemon_handler.h"
#include "rpc/rpc_args.h"
#include "rpc/http_server.h"
#include "rpc/lmq_server.h"
#include "cryptonote_protocol/quorumnet.h"

#include "common/password.h"
#include "common/signal_handler.h"
#include "daemon/command_server.h"
#include "daemon/command_line_args.h"
#include "net/parse.h"
#include "version.h"

#include "command_server.h"
#include "daemon.h"

#include <functional>

#ifdef ENABLE_SYSTEMD
extern "C" {
#  include <systemd/sd-daemon.h>
}
#endif

using namespace std::literals;

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize {

std::pair<std::string, uint16_t> parse_ip_port(std::string_view ip_port, const std::string& argname)
{
  std::pair<std::string, uint16_t> result;
  auto& [ip, port] = result;

  if (auto colon = ip_port.rfind(":"); colon != std::string::npos && tools::parse_int(ip_port.substr(colon+1), port))
    ip_port.remove_suffix(ip_port.size() - colon);
  else
    throw std::runtime_error{"Invalid IP/port value specified to " + argname + ": " + std::string(ip_port)};

  if (!ip_port.empty() && ip_port.front() == '[' && ip_port.back() == ']') {
    ip_port.remove_prefix(1);
    ip_port.remove_suffix(1);
  }

  std::string ip_str{ip_port};
  boost::system::error_code ec;
  auto addr =
#if BOOST_VERSION >= 106600
    boost::asio::ip::make_address
#else
    boost::asio::ip::address::from_string
#endif
    (ip_str, ec);
  if (ec)
    throw std::runtime_error{"Invalid IP address specified: " + ip_str};

  ip = addr.to_string();

  return result;
}

daemon::daemon(boost::program_options::variables_map vm_) :
    vm{std::move(vm_)},
    core{std::make_unique<cryptonote::core>()},
    protocol{std::make_unique<protocol_handler>(*core, command_line::get_arg(vm, cryptonote::arg_offline))},
    p2p{std::make_unique<node_server>(*protocol)},
    rpc{std::make_unique<cryptonote::rpc::core_rpc_server>(*core, *p2p)}
{
  MGINFO_BLUE("Initializing daemon objects...");

  MGINFO("- cryptonote protocol");
  if (!protocol->init(vm))
    throw std::runtime_error("Failed to initialize cryptonote protocol.");

  MGINFO("- p2p");
  if (!p2p->init(vm))
    throw std::runtime_error("Failed to initialize p2p server.");

  // Handle circular dependencies
  protocol->set_p2p_endpoint(p2p.get());
  core->set_cryptonote_protocol(protocol.get());

  auto rpc_config = cryptonote::rpc_args::process(vm);
  bool new_rpc_options = !is_arg_defaulted(vm, cryptonote::rpc::http_server::arg_rpc_admin)
    || !is_arg_defaulted(vm, cryptonote::rpc::http_server::arg_rpc_public);
  // TODO: Remove these options, perhaps starting in loki 9.0
  bool deprecated_rpc_options = !is_arg_defaulted(vm, cryptonote::rpc::http_server::arg_rpc_bind_port)
    || !is_arg_defaulted(vm, cryptonote::rpc::http_server::arg_rpc_restricted_bind_port)
    || !is_arg_defaulted(vm, cryptonote::rpc::http_server::arg_restricted_rpc)
    || !is_arg_defaulted(vm, cryptonote::rpc::http_server::arg_public_node)
    || rpc_config.bind_ip.has_value()
    || rpc_config.bind_ipv6_address.has_value()
    || rpc_config.use_ipv6;

  constexpr std::string_view deprecated_option_names = "--rpc-bind-ip/--rpc-bind-port/--rpc-restricted-bind-port/--restricted-rpc/--public-node/--rpc-use-ipv6"sv;

  if (new_rpc_options && deprecated_rpc_options)
    throw std::runtime_error{"Failed to initialize rpc settings: --rpc-public/--rpc-admin cannot be combined with deprecated " + std::string{deprecated_option_names} + " options"};

  // bind ip, listen addr, required
  std::vector<std::tuple<std::string, uint16_t, bool>> rpc_listen_admin, rpc_listen_public;
  if (deprecated_rpc_options)
  {
    MGINFO_RED(deprecated_option_names << " options are deprecated and will be removed from a future lokid version; use --rpc-public/--rpc-admin instead");

    // These old options from Monero are really janky: --restricted-rpc turns the main port
    // restricted, but then we also have --rpc-restricted-bind-port but both are stuck with
    // --rpc-bind-ip, and then half of the options get parsed here but the IP option used to get
    // parsed in the http_server code.
    auto restricted = command_line::get_arg(vm, cryptonote::rpc::http_server::arg_restricted_rpc);
    auto main_rpc_port = command_line::get_arg(vm, cryptonote::rpc::http_server::arg_rpc_bind_port);
    auto restricted_rpc_port = command_line::get_arg(vm, cryptonote::rpc::http_server::arg_rpc_restricted_bind_port);

    if (main_rpc_port == 0) {
      if (restricted && restricted_rpc_port != 0)
        std::swap(main_rpc_port, restricted_rpc_port);
      else if (command_line::get_arg(vm, cryptonote::arg_testnet_on))
        main_rpc_port = config::testnet::RPC_DEFAULT_PORT;
      else if (command_line::get_arg(vm, cryptonote::arg_devnet_on))
        main_rpc_port = config::devnet::RPC_DEFAULT_PORT;
      else
        main_rpc_port = config::RPC_DEFAULT_PORT;
    }
    if (main_rpc_port && main_rpc_port == restricted_rpc_port)
      restricted = true;

    std::vector<uint16_t> public_ports;
    if (restricted)
      public_ports.push_back(main_rpc_port);
    if (restricted_rpc_port && restricted_rpc_port != main_rpc_port)
      public_ports.push_back(restricted_rpc_port);

    for (uint16_t port : public_ports) {
      rpc_listen_public.emplace_back(rpc_config.bind_ip.value_or("127.0.0.1"), main_rpc_port, rpc_config.require_ipv4);
      if (rpc_config.bind_ipv6_address || rpc_config.use_ipv6)
        rpc_listen_public.emplace_back(rpc_config.bind_ipv6_address.value_or("::1"), main_rpc_port, true);
    }

    if (!restricted && main_rpc_port) {
      rpc_listen_admin.emplace_back(rpc_config.bind_ip.value_or("127.0.0.1"), main_rpc_port, rpc_config.require_ipv4);
      if (rpc_config.bind_ipv6_address || rpc_config.use_ipv6)
        rpc_listen_public.emplace_back(rpc_config.bind_ipv6_address.value_or("::1"), main_rpc_port, true);
    }
  }
  else
  { // no deprecated options

    for (auto& bind : command_line::get_arg(vm, cryptonote::rpc::http_server::arg_rpc_admin)) {
      if (bind == "none") continue;
      auto [ip, port] = parse_ip_port(bind, "--rpc-admin");
      bool ipv4 = ip.find(':') == std::string::npos;
      // If using the default admin setting then don't require the bind to IPv6 localhost, or the
      // IPv4 localhost bind if --rpc-ignore-ipv4 is given.
      bool required = !command_line::is_arg_defaulted(vm, cryptonote::rpc::http_server::arg_rpc_admin)
        || (ipv4 && rpc_config.require_ipv4);
      rpc_listen_admin.emplace_back(std::move(ip), port, required);
    }
    for (auto& bind : command_line::get_arg(vm, cryptonote::rpc::http_server::arg_rpc_public)) {
      // Much simpler, since this is default empty: everything specified is required.
      auto [ip, port] = parse_ip_port(bind, "--rpc-public");
      rpc_listen_public.emplace_back(std::move(ip), port, true);
    }
  }

  if (!rpc_listen_admin.empty())
  {
    MGINFO("- admin HTTP RPC server");
    http_rpc_admin.emplace(*rpc, rpc_config, false /*not restricted*/, std::move(rpc_listen_admin));
  }

  if (!rpc_listen_public.empty())
  {
    MGINFO("- public HTTP RPC server");
    http_rpc_public.emplace(*rpc, rpc_config, true /*restricted*/, std::move(rpc_listen_public));
  }

  MGINFO_BLUE("Done daemon object initialization");
}

daemon::~daemon()
{
  MGINFO_BLUE("Deinitializing daemon objects...");

  if (http_rpc_public) {
    MGINFO("- public HTTP RPC server");
    http_rpc_public.reset();
  }
  if (http_rpc_admin) {
    MGINFO("- admin HTTP RPC server");
    http_rpc_admin.reset();
  }

  MGINFO("- p2p");
  try {
    p2p->deinit();
  } catch (const std::exception& e) {
    MERROR("Failed to deinitialize p2p: " << e.what());
  }

  MGINFO("- core");
  try {
    core->deinit();
    core->set_cryptonote_protocol(nullptr);
  } catch (const std::exception& e) {
    MERROR("Failed to deinitialize core: " << e.what());
  }

  MGINFO("- cryptonote protocol");
  try {
    protocol->deinit();
    protocol->set_p2p_endpoint(nullptr);
  } catch (const std::exception& e) {
    MERROR("Failed to stop cryptonote protocol: " << e.what());
  }
  MGINFO_BLUE("Deinitialization complete");
}

void daemon::init_options(boost::program_options::options_description& option_spec, boost::program_options::options_description& hidden)
{
  static bool called = false;
  if (called)
    throw std::logic_error("daemon::init_options must only be called once");
  else
    called = true;
  cryptonote::core::init_options(option_spec);
  node_server::init_options(option_spec);
  cryptonote::rpc::core_rpc_server::init_options(option_spec, hidden);
  cryptonote::rpc::http_server::init_options(option_spec, hidden);
  cryptonote::rpc::init_lmq_options(option_spec);
  quorumnet::init_core_callbacks();
}

bool daemon::run(bool interactive)
{
  if (!core)
    throw std::runtime_error{"Can't run stopped daemon"};

  std::atomic<bool> stop_sig(false), shutdown(false);
  std::thread stop_thread{[&stop_sig, &shutdown, this] {
    while (!stop_sig)
      epee::misc_utils::sleep_no_w(100);
    if (shutdown)
      stop();
  }};

  LOKI_DEFER
  {
    stop_sig = true;
    stop_thread.join();
  };

  tools::signal_handler::install([&stop_sig, &shutdown](int) { stop_sig = true; shutdown = true; });

  try
  {
    MGINFO_BLUE("Starting up lokid services...");
    cryptonote::GetCheckpointsCallback get_checkpoints;
#if defined(PER_BLOCK_CHECKPOINT)
    get_checkpoints = blocks::GetCheckpointsData;
#endif
    MGINFO("Starting core");
    if (!core->init(vm, nullptr, get_checkpoints))
      throw std::runtime_error("Failed to start core");

    MGINFO("Starting LokiMQ");
    lmq_rpc = std::make_unique<cryptonote::rpc::lmq_rpc>(*core, *rpc, vm);
    core->start_lokimq();

    if (http_rpc_admin) {
      MGINFO("Starting admin HTTP RPC server");
      http_rpc_admin->start();
    }
    if (http_rpc_public) {
      MGINFO("Starting public HTTP RPC server");
      http_rpc_public->start();
    }

    MGINFO("Starting RPC daemon handler");
    cryptonote::rpc::DaemonHandler rpc_daemon_handler(*core, *p2p);

    std::unique_ptr<daemonize::command_server> rpc_commands;
    if (interactive)
    {
      MGINFO("Starting command-line processor");
      rpc_commands = std::make_unique<daemonize::command_server>(*rpc);
      rpc_commands->start_handling([this] { stop(); });
    }

    MGINFO_GREEN("Starting up main network");

#ifdef ENABLE_SYSTEMD
    sd_notify(0, ("READY=1\nSTATUS=" + core->get_status_string()).c_str());
#endif

    p2p->run(); // blocks until p2p goes down
    MGINFO_YELLOW("Main network stopped");

    if (rpc_commands)
    {
      MGINFO("Stopping RPC command processor");
      rpc_commands->stop_handling();
    }

    if (http_rpc_public) {
      MGINFO("Stopping public HTTP RPC server...");
      http_rpc_public->shutdown();
    }
    if (http_rpc_admin) {
      MGINFO("Stopping admin HTTP RPC server...");
      http_rpc_admin->shutdown();
    }

    MGINFO("Node stopped.");
    return true;
  }
  catch (std::exception const& ex)
  {
    MFATAL(ex.what());
    return false;
  }
  catch (...)
  {
    MFATAL("Unknown exception occured!");
    return false;
  }
}

void daemon::stop()
{
  if (!core)
    throw std::logic_error{"Can't send stop signal to a stopped daemon"};

  p2p->send_stop_signal(); // Make p2p stop so that `run()` above continues with tear down
}

} // namespace daemonize
