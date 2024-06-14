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

#include <fmt/color.h>
#include <oxenmq/oxenmq.h>

#include <boost/asio/ip/address.hpp>
#include <memory>
#include <stdexcept>
#include <utility>
#include <common/exception.h>

#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_core.h"
#include "epee/misc_log_ex.h"
#if defined(PER_BLOCK_CHECKPOINT)
#include "blocks/blocks.h"
#endif
#include <functional>

#include "command_line_args.h"
#include "command_server.h"
#include "common/password.h"
#include "common/signal_handler.h"
#include "cryptonote_core/uptime_proof.h"
#include "cryptonote_protocol/quorumnet.h"
#include "daemon.h"
#include "net/parse.h"
#include "rpc/common/rpc_args.h"
#include "rpc/http_server.h"
#include "rpc/omq_server.h"
#include "version.h"

#ifdef ENABLE_SYSTEMD
extern "C" {
#include <systemd/sd-daemon.h>
}
#endif

using namespace std::literals;

namespace daemonize {

namespace log = oxen::log;
static auto logcat = log::Cat("daemon");

std::pair<std::string, uint16_t> parse_ip_port(
        std::string_view ip_port, const std::string& argname) {
    std::pair<std::string, uint16_t> result;
    auto& [ip, port] = result;

    if (auto colon = ip_port.rfind(":");
        colon != std::string::npos && tools::parse_int(ip_port.substr(colon + 1), port))
        ip_port.remove_suffix(ip_port.size() - colon);
    else
        throw oxen::runtime_error{
                "Invalid IP/port value specified to " + argname + ": " + std::string(ip_port)};

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
        throw oxen::runtime_error{"Invalid IP address specified: " + ip_str};

    ip = addr.to_string();

    return result;
}

daemon::daemon(boost::program_options::variables_map vm_) :
        vm{std::move(vm_)},
        core{std::make_unique<cryptonote::core>()},
        protocol{std::make_unique<protocol_handler>(
                *core, command_line::get_arg(vm, cryptonote::arg_offline))},
        p2p{std::make_unique<node_server>(*protocol)},
        rpc{std::make_unique<cryptonote::rpc::core_rpc_server>(*core, *p2p)} {
    log::info(logcat, fg(fmt::terminal_color::blue), "Initializing daemon objects...");

    log::info(logcat, "- cryptonote protocol");
    if (!protocol->init(vm))
        throw oxen::runtime_error("Failed to initialize cryptonote protocol.");

    log::info(logcat, "- p2p");
    if (!p2p->init(vm))
        throw oxen::runtime_error("Failed to initialize p2p server.");

    // Handle circular dependencies
    protocol->set_p2p_endpoint(p2p.get());
    core->set_cryptonote_protocol(protocol.get());

    auto rpc_config = cryptonote::rpc_args::process(vm);
    bool new_rpc_options = !is_arg_defaulted(vm, cryptonote::rpc::http_server::arg_rpc_admin) ||
                           !is_arg_defaulted(vm, cryptonote::rpc::http_server::arg_rpc_public);
    // TODO: Remove these options, perhaps starting in oxen 9.0
    bool deprecated_rpc_options =
            !is_arg_defaulted(vm, cryptonote::rpc::http_server::arg_rpc_bind_port) ||
            !is_arg_defaulted(vm, cryptonote::rpc::http_server::arg_rpc_restricted_bind_port) ||
            !is_arg_defaulted(vm, cryptonote::rpc::http_server::arg_restricted_rpc) ||
            !is_arg_defaulted(vm, cryptonote::rpc::http_server::arg_public_node) ||
            rpc_config.bind_ip.has_value() || rpc_config.bind_ipv6_address.has_value() ||
            rpc_config.use_ipv6;

    constexpr std::string_view deprecated_option_names =
            "--rpc-bind-ip/--rpc-bind-port/--rpc-restricted-bind-port/--restricted-rpc/--public-node/--rpc-use-ipv6"sv;

    if (new_rpc_options && deprecated_rpc_options)
        throw oxen::runtime_error{
                "Failed to initialize rpc settings: --rpc-public/--rpc-admin cannot be combined "
                "with deprecated " +
                std::string{deprecated_option_names} + " options"};

    // bind ip, listen addr, required
    std::vector<std::tuple<std::string, uint16_t, bool>> rpc_listen_admin, rpc_listen_public;
    if (deprecated_rpc_options) {
        log::info(
                logcat,
                fg(fmt::terminal_color::red),
                "{} options are deprecated and will be removed from a future oxend version; use "
                "--rpc-public/--rpc-admin instead",
                deprecated_option_names);

        // These old options from Monero are really janky: --restricted-rpc turns the main port
        // restricted, but then we also have --rpc-restricted-bind-port but both are stuck with
        // --rpc-bind-ip, and then half of the options get parsed here but the IP option used to get
        // parsed in the http_server code.
        auto restricted =
                command_line::get_arg(vm, cryptonote::rpc::http_server::arg_restricted_rpc);
        auto main_rpc_port =
                command_line::get_arg(vm, cryptonote::rpc::http_server::arg_rpc_bind_port);
        auto restricted_rpc_port = command_line::get_arg(
                vm, cryptonote::rpc::http_server::arg_rpc_restricted_bind_port);

        if (main_rpc_port == 0) {
            if (restricted && restricted_rpc_port != 0)
                std::swap(main_rpc_port, restricted_rpc_port);
            else if (command_line::get_arg(vm, cryptonote::arg_testnet_on))
                main_rpc_port = cryptonote::config::testnet::RPC_DEFAULT_PORT;
            else if (command_line::get_arg(vm, cryptonote::arg_devnet_on))
                main_rpc_port = cryptonote::config::devnet::RPC_DEFAULT_PORT;
            else
                main_rpc_port = cryptonote::config::RPC_DEFAULT_PORT;
        }
        if (main_rpc_port && main_rpc_port == restricted_rpc_port)
            restricted = true;

        std::vector<uint16_t> public_ports;
        if (restricted)
            public_ports.push_back(main_rpc_port);
        if (restricted_rpc_port && restricted_rpc_port != main_rpc_port)
            public_ports.push_back(restricted_rpc_port);

        for (uint16_t port : public_ports) {
            rpc_listen_public.emplace_back(
                    rpc_config.bind_ip.value_or("127.0.0.1"),
                    main_rpc_port,
                    rpc_config.require_ipv4);
            if (rpc_config.bind_ipv6_address || rpc_config.use_ipv6)
                rpc_listen_public.emplace_back(
                        rpc_config.bind_ipv6_address.value_or("::1"), main_rpc_port, true);
        }

        if (!restricted && main_rpc_port) {
            rpc_listen_admin.emplace_back(
                    rpc_config.bind_ip.value_or("127.0.0.1"),
                    main_rpc_port,
                    rpc_config.require_ipv4);
            if (rpc_config.bind_ipv6_address || rpc_config.use_ipv6)
                rpc_listen_public.emplace_back(
                        rpc_config.bind_ipv6_address.value_or("::1"), main_rpc_port, true);
        }
    } else {  // no deprecated options

        for (auto& bind : command_line::get_arg(vm, cryptonote::rpc::http_server::arg_rpc_admin)) {
            if (bind == "none")
                continue;
            auto [ip, port] = parse_ip_port(bind, "--rpc-admin");
            bool ipv4 = ip.find(':') == std::string::npos;
            // If using the default admin setting then don't require the bind to IPv6 localhost, or
            // the IPv4 localhost bind if --rpc-ignore-ipv4 is given.
            bool required = !command_line::is_arg_defaulted(
                                    vm, cryptonote::rpc::http_server::arg_rpc_admin) ||
                            (ipv4 && rpc_config.require_ipv4);
            rpc_listen_admin.emplace_back(std::move(ip), port, required);
        }
        for (auto& bind : command_line::get_arg(vm, cryptonote::rpc::http_server::arg_rpc_public)) {
            // Much simpler, since this is default empty: everything specified is required.
            auto [ip, port] = parse_ip_port(bind, "--rpc-public");
            rpc_listen_public.emplace_back(std::move(ip), port, true);
        }
    }

    if (!rpc_listen_admin.empty()) {
        log::info(logcat, "- admin HTTP RPC server");
        http_rpc_admin.emplace(
                *rpc, rpc_config, false /*not restricted*/, std::move(rpc_listen_admin));
    }

    if (!rpc_listen_public.empty()) {
        log::info(logcat, "- public HTTP RPC server");
        http_rpc_public.emplace(
                *rpc, rpc_config, true /*restricted*/, std::move(rpc_listen_public));
    }

    log::info(logcat, fg(fmt::terminal_color::blue), "Done daemon object initialization");
}

daemon::~daemon() {
    log::info(logcat, fg(fmt::terminal_color::blue), "Deinitializing daemon objects...");

    if (http_rpc_public) {
        log::info(logcat, "- public HTTP RPC server");
        http_rpc_public.reset();
    }
    if (http_rpc_admin) {
        log::info(logcat, "- admin HTTP RPC server");
        http_rpc_admin.reset();
    }

    log::info(logcat, "- p2p");
    try {
        p2p->deinit();
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to deinitialize p2p: {}", e.what());
    }

    log::info(logcat, "- core");
    try {
        core->deinit();
        core->set_cryptonote_protocol(nullptr);
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to deinitialize core: {}", e.what());
    }

    log::info(logcat, "- cryptonote protocol");
    try {
        protocol->deinit();
        protocol->set_p2p_endpoint(nullptr);
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to stop cryptonote protocol: {}", e.what());
    }
    log::info(logcat, fg(fmt::terminal_color::blue), "Deinitialization complete");
}

void daemon::init_options(
        boost::program_options::options_description& option_spec,
        boost::program_options::options_description& hidden) {
    static bool called = false;
    if (called)
        throw oxen::logic_error("daemon::init_options must only be called once");
    else
        called = true;
    cryptonote::core::init_options(option_spec);
    node_server::init_options(option_spec, hidden);
    cryptonote::rpc::core_rpc_server::init_options(option_spec, hidden);
    cryptonote::rpc::http_server::init_options(option_spec, hidden);
    cryptonote::rpc::init_omq_options(option_spec);
    quorumnet::init_core_callbacks();
}

bool daemon::run(bool interactive) {
    if (!core)
        throw oxen::runtime_error{"Can't run stopped daemon"};

    std::atomic<bool> stop_sig(false), shutdown(false);
    std::thread stop_thread{[&stop_sig, &shutdown, this] {
        while (!stop_sig)
            std::this_thread::sleep_for(100ms);
        if (shutdown)
            stop();
    }};

    OXEN_DEFER {
        stop_sig = true;
        stop_thread.join();
    };

    tools::signal_handler::install([&stop_sig, &shutdown](int) {
        stop_sig = true;
        shutdown = true;
    });

    try {
        log::info(logcat, fg(fmt::terminal_color::blue), "Starting up oxend services...");
        cryptonote::GetCheckpointsCallback get_checkpoints;
#if defined(PER_BLOCK_CHECKPOINT)
        get_checkpoints = blocks::GetCheckpointsData;
#endif
        log::info(logcat, "Starting core");
        if (!core->init(vm, nullptr, get_checkpoints))
            throw oxen::runtime_error("Failed to start core");

        log::info(logcat, "Starting OxenMQ");
        omq_rpc = std::make_unique<cryptonote::rpc::omq_rpc>(*core, *rpc, vm);
        core->start_oxenmq();

        if (http_rpc_admin) {
            log::info(logcat, "Starting admin HTTP RPC server");
            http_rpc_admin->start();
        }
        if (http_rpc_public) {
            log::info(logcat, "Starting public HTTP RPC server");
            http_rpc_public->start();
        }

        std::optional<daemonize::command_server> rpc_commands;
        if (interactive) {
            log::info(logcat, "Starting command-line processor");
            auto& omq = core->get_omq();

            std::promise<void> p;
            auto conn = omq.connect_inproc(
                    [&p](oxenmq::ConnectionID) { p.set_value(); },
                    [&p](oxenmq::ConnectionID, std::string_view err) {
                        try {
                            throw oxen::runtime_error{
                                    "Internal oxend RPC connection failed: " + std::string{err}};
                        } catch (...) {
                            p.set_exception(std::current_exception());
                        }
                    });
            p.get_future().get();

            rpc_commands.emplace(omq, std::move(conn));
            rpc_commands->start_handling([this] { stop(); });
        }

        log::info(logcat, fg(fmt::terminal_color::green), "Starting up main network");

#ifdef ENABLE_SYSTEMD
        sd_notify(0, ("READY=1\nSTATUS=" + core->get_status_string()).c_str());
#endif

        p2p->run();  // blocks until p2p goes down
        log::info(logcat, fg(fmt::terminal_color::yellow), "Main network stopped");

        if (rpc_commands) {
            log::info(logcat, "Stopping RPC command processor");
            rpc_commands->stop_handling();
            rpc_commands.reset();
        }

        if (http_rpc_public) {
            log::info(logcat, "Stopping public HTTP RPC server...");
            http_rpc_public->shutdown();
        }
        if (http_rpc_admin) {
            log::info(logcat, "Stopping admin HTTP RPC server...");
            http_rpc_admin->shutdown();
        }

        log::info(logcat, "Node stopped.");
        return true;
    } catch (std::exception const& ex) {
        log::error(logcat, "An exception occurred: {}", ex.what());
        return false;
    } catch (...) {
        log::error(logcat, "Unknown exception occurred!");
        return false;
    }
}

void daemon::stop() {
    if (!core)
        throw oxen::logic_error{"Can't send stop signal to a stopped daemon"};

    p2p->send_stop_signal();  // Make p2p stop so that `run()` above continues with tear down
}

}  // namespace daemonize
