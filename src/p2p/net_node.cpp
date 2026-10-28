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

// IP blocking adapted from Boolberry

#include <fmt/color.h>
#include <fmt/core.h>
#include <fmt/std.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <random>
#include <tuple>
#include <vector>

#include "common/command_line.h"
#include "common/file.h"
#include "common/periodic_task.h"
#include "common/string_util.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/connection_context.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_core.h"
#include "epee/net/net_utils_base.h"
#include "epee/storages/levin_abstract_invoke2.h"
#include "net/error.h"
#include "net/parse.h"
#include "net_node.h"
#include "networks.h"
#include "p2p_protocol_defs.h"
#include "version.h"

#define MIN_WANTED_SEED_NODES 12

namespace nodetool {
static auto logcat = log::Cat("net.p2p");

using epee::connection_id_t;

const command_line::arg_descriptor<std::string> arg_p2p_bind_ip = {
        "p2p-bind-ip", "Interface for p2p network protocol (IPv4)", "0.0.0.0"};
const command_line::arg_descriptor<std::string> arg_p2p_bind_ipv6_address = {
        "p2p-bind-ipv6-address", "Interface for p2p network protocol (IPv6)", "::"};
const command_line::arg_descriptor<uint16_t> arg_p2p_bind_port{
        "p2p-bind-port",
        "Port for p2p network protocol (IPv4)",
        [](cryptonote::network_type nettype) { return get_config(nettype).P2P_DEFAULT_PORT; }};
const command_line::arg_descriptor<uint16_t> arg_p2p_bind_port_ipv6{
        "p2p-bind-port-ipv6",
        "Port for p2p network protocol (IPv6)",
        [](cryptonote::network_type nettype) { return get_config(nettype).P2P_DEFAULT_PORT; }};

const command_line::arg_descriptor<uint32_t> arg_p2p_external_port = {
        "p2p-external-port",
        "External port for p2p network protocol (if port forwarding used with NAT)",
        0};
const command_line::arg_flag arg_p2p_allow_local_ip = {
        "allow-local-ip", "Allow local ip add to peer list, mostly in debug purposes"};
const command_line::arg_descriptor<std::vector<std::string>> arg_p2p_add_peer = {
        "add-peer", "Manually add peer to local peerlist"};
const command_line::arg_descriptor<std::vector<std::string>> arg_p2p_add_priority_node = {
        "add-priority-node",
        "Specify list of peers to connect to and attempt to keep the connection open"};
const command_line::arg_descriptor<std::vector<std::string>> arg_p2p_add_exclusive_node = {
        "add-exclusive-node",
        "Specify list of peers to connect to only."
        " If this option is given the options add-priority-node and seed-node are ignored"};
const command_line::arg_descriptor<std::vector<std::string>> arg_p2p_seed_node = {
        "seed-node", "Connect to a node to retrieve peer addresses, and disconnect"};
const command_line::arg_flag arg_p2p_hide_my_port{
        "hide-my-port", "Do not announce yourself as peerlist candidate"};
const command_line::arg_flag arg_no_sync{
        "no-sync", "Don't synchronize the blockchain with other peers"};

const command_line::arg_flag arg_no_igd = {"no-igd", "Deprecated option; ignored"};
const command_line::arg_descriptor<std::string> arg_igd = {"igd", "Deprecated option; ignored", ""};
const command_line::arg_flag arg_p2p_use_ipv6{"p2p-use-ipv6", "Enable IPv6 for p2p"};
const command_line::arg_flag arg_p2p_ignore_ipv4{
        "p2p-ignore-ipv4", "Ignore unsuccessful IPv4 bind for p2p"};
const command_line::arg_descriptor<int64_t> arg_out_peers = {
        "out-peers", "set max number of out peers", -1};
const command_line::arg_descriptor<int64_t> arg_in_peers = {
        "in-peers", "set max number of in peers", -1};
const command_line::arg_descriptor<int> arg_tos_flag = {"tos-flag", "set TOS flag", -1};

const command_line::arg_descriptor<int64_t> arg_limit_rate_up = {
        "limit-rate-up", "set limit-rate-up [kB/s]", cryptonote::p2p::DEFAULT_LIMIT_RATE_UP};
const command_line::arg_descriptor<int64_t> arg_limit_rate_down = {
        "limit-rate-down", "set limit-rate-down [kB/s]", cryptonote::p2p::DEFAULT_LIMIT_RATE_DOWN};
const command_line::arg_descriptor<int64_t> arg_limit_rate = {
        "limit-rate", "set limit-rate [kB/s]", -1};

static bool append_net_address(
        std::vector<oxen::quic::Address>& seed_nodes,
        std::string_view addr,
        uint16_t default_port);
//-----------------------------------------------------------------------------------
void node_server::init_options(
        boost::program_options::options_description& desc,
        boost::program_options::options_description& hidden) {
    command_line::add_arg(desc, arg_p2p_bind_ip);
    command_line::add_arg(desc, arg_p2p_bind_ipv6_address);
    command_line::add_arg(desc, arg_p2p_bind_port);
    command_line::add_arg(desc, arg_p2p_bind_port_ipv6);
    command_line::add_arg(desc, arg_p2p_use_ipv6);
    command_line::add_arg(desc, arg_p2p_ignore_ipv4);
    command_line::add_arg(desc, arg_p2p_external_port);
    command_line::add_arg(desc, arg_p2p_allow_local_ip);
    command_line::add_arg(desc, arg_p2p_add_peer);
    command_line::add_arg(desc, arg_p2p_add_priority_node);
    command_line::add_arg(desc, arg_p2p_add_exclusive_node);
    command_line::add_arg(desc, arg_p2p_seed_node);
    command_line::add_arg(desc, arg_p2p_hide_my_port);
    command_line::add_arg(desc, arg_no_sync);
    command_line::add_arg(hidden, arg_no_igd);
    command_line::add_arg(hidden, arg_igd);
    command_line::add_arg(desc, arg_out_peers);
    command_line::add_arg(desc, arg_in_peers);
    command_line::add_arg(desc, arg_tos_flag);
    command_line::add_arg(desc, arg_limit_rate_up);
    command_line::add_arg(desc, arg_limit_rate_down);
    command_line::add_arg(desc, arg_limit_rate);
}

fs::path node_server::get_peerlist_file() const {
    fs::path p2p_filename = cryptonote::P2P_NET_DATA_FILENAME;
    if (m_nettype == cryptonote::network_type::STAGENET)
        // Kludge for stagenet reboot
        p2p_filename += u8".v4";
    return m_config_folder / p2p_filename;
}

//-----------------------------------------------------------------------------------
bool node_server::init_config() try {
    auto storage = peerlist_storage::open(get_peerlist_file());
    if (storage)
        m_peerlist_storage = std::move(*storage);

    m_first_connection_maker_call = true;

    return true;
} catch (const std::exception& e) {
    log::error(logcat, "Exception in node_server::init_config: {}", e.what());
    return false;
}
//-----------------------------------------------------------------------------------
void node_server::for_each_connection(
        std::function<bool(cryptonote_connection_context&, peerid_type)> f) {
    m_network.m_net_server.get_config_object().foreach_connection(
            [&](p2p_connection_context& cntx) { return f(cntx, cntx.peer_id); });
}
//-----------------------------------------------------------------------------------
bool node_server::for_connection(
        const connection_id_t& connection_id,
        std::function<bool(cryptonote_connection_context&, peerid_type)> f) {
    return m_network.m_net_server.get_config_object().for_connection(
            connection_id, [&](p2p_connection_context& cntx) { return f(cntx, cntx.peer_id); });
}
//-----------------------------------------------------------------------------------
bool node_server::is_remote_host_allowed(
        const oxen::quic::Address& address, time_t* t) {
    std::unique_lock lock{m_blocked_hosts_lock};

    const time_t now = time(nullptr);

    // look in the hosts list
    auto it = m_blocked_hosts.find(address.host());
    if (it != m_blocked_hosts.end()) {
        if (now >= it->second) {
            m_blocked_hosts.erase(it);
            log::info(
                    logcat,
                    fg(fmt::terminal_color::cyan),
                    "Host {} unblocked.",
                    address.host());
            it = m_blocked_hosts.end();
        } else {
            if (t)
                *t = it->second - now;
            return false;
        }
    }

    // manually loop in subnets
    if (address.is_ipv4()) {
        const auto ip = address.to_ipv4();
        for (auto it = m_blocked_subnets.begin(); it != m_blocked_subnets.end();) {
            if (now >= it->second) {
                log::info(logcat, fg(fmt::terminal_color::cyan), "Subnet {} unblocked", it->first);
                it = m_blocked_subnets.erase(it);
                continue;
            }
            if (it->first.contains(ip)) {
                if (t)
                    *t = it->second - now;
                return false;
            }
            ++it;
        }
    }

    // not found in hosts or subnets, allowed
    return true;
}
//-----------------------------------------------------------------------------------
bool node_server::block_host(
        const oxen::quic::Address& addr, time_t seconds) {
    const time_t now = time(nullptr);

    std::unique_lock lock{m_blocked_hosts_lock};
    time_t limit;
    if (now > std::numeric_limits<time_t>::max() - seconds)
        limit = std::numeric_limits<time_t>::max();
    else
        limit = now + seconds;
    m_blocked_hosts[addr.host()] = limit;

    // drop any connection to that address
    std::vector<connection_id_t> conns;
    auto& net_config = m_network.m_net_server.get_config_object();
    net_config.foreach_connection([&](const p2p_connection_context& cntxt) {
        if (net::same_host(cntxt.m_remote_address, addr))
            conns.push_back(cntxt.m_connection_id);
        return true;
    });
    for (const auto& c : conns)
        net_config.close(c);

    log::info(logcat, fg(fmt::terminal_color::cyan), "Host {} blocked", addr.host());
    return true;
}
//-----------------------------------------------------------------------------------
bool node_server::unblock_host(
        const oxen::quic::Address& address) {
    std::unique_lock lock{m_blocked_hosts_lock};
    auto i = m_blocked_hosts.find(address.host());
    if (i == m_blocked_hosts.end())
        return false;
    m_blocked_hosts.erase(i);
    log::info(logcat, fg(fmt::terminal_color::cyan), "Host {} unblocked", address.host());
    return true;
}
//-----------------------------------------------------------------------------------
bool node_server::block_subnet(
        const oxen::quic::ipv4_range& subnet, time_t seconds) {
    const time_t now = time(nullptr);

    std::unique_lock lock{m_blocked_hosts_lock};
    time_t limit;
    if (now > std::numeric_limits<time_t>::max() - seconds)
        limit = std::numeric_limits<time_t>::max();
    else
        limit = now + seconds;
    m_blocked_subnets[subnet] = limit;

    // drop any connection to that subnet
    std::vector<connection_id_t> conns;
    auto& net_config = m_network.m_net_server.get_config_object();
    net_config.foreach_connection([&](const p2p_connection_context& cntxt) {
        if (cntxt.m_remote_address.is_ipv4() && subnet.contains(cntxt.m_remote_address.to_ipv4()))
            conns.push_back(cntxt.m_connection_id);
        return true;
    });
    for (const auto& c : conns)
        net_config.close(c);

    log::info(logcat, fg(fmt::terminal_color::cyan), "Subnet {} blocked.", subnet);
    return true;
}
//-----------------------------------------------------------------------------------
bool node_server::unblock_subnet(const oxen::quic::ipv4_range& subnet) {
    std::unique_lock lock{m_blocked_hosts_lock};
    auto i = m_blocked_subnets.find(subnet);
    if (i == m_blocked_subnets.end())
        return false;
    m_blocked_subnets.erase(i);
    log::info(logcat, fg(fmt::terminal_color::cyan), "Subnet {} unblocked.", subnet);
    return true;
}
//-----------------------------------------------------------------------------------
bool node_server::add_host_fail(
        const oxen::quic::Address& address) {
    std::lock_guard lock{m_host_fails_score_lock};
    uint64_t fails = ++m_host_fails_score[address.host()];
    log::debug(logcat, "Host {} fail score={}", address.host(), fails);
    if (fails > cryptonote::p2p::IP_FAILS_BEFORE_BLOCK) {
        auto it = m_host_fails_score.find(address.host());
        if (it == m_host_fails_score.end()) {
            log::error(logcat, "internal error");
            return false;
        }
        it->second = cryptonote::p2p::IP_FAILS_BEFORE_BLOCK / 2;
        block_host(address);
    }
    return true;
}
//-----------------------------------------------------------------------------------
bool node_server::handle_command_line(
        const boost::program_options::variables_map& vm) {

    m_nettype = command_line::get_network(vm);

    m_network.m_bind_ip = command_line::get_arg(vm, arg_p2p_bind_ip);
    m_network.m_bind_ipv6_address = command_line::get_arg(vm, arg_p2p_bind_ipv6_address);
    m_network.m_port = command_line::get_arg(vm, arg_p2p_bind_port);
    m_network.m_port_ipv6 = command_line::get_arg(vm, arg_p2p_bind_port_ipv6);
    m_external_port = command_line::get_arg(vm, arg_p2p_external_port);
    m_allow_local_ip = command_line::get_arg(vm, arg_p2p_allow_local_ip);
    m_offline = command_line::get_arg(vm, cryptonote::arg_offline);
    m_use_ipv6 = command_line::get_arg(vm, arg_p2p_use_ipv6);
    m_require_ipv4 = !command_line::get_arg(vm, arg_p2p_ignore_ipv4);

    if (command_line::has_arg(vm, arg_p2p_add_peer)) {
        std::vector<std::string> perrs = command_line::get_arg(vm, arg_p2p_add_peer);
        for (const std::string& pr_str : perrs) {
            nodetool::peerlist_entry pe{};
            pe.id = crypto::rand<uint64_t>();
            const uint16_t default_port = cryptonote::get_config(m_nettype).P2P_DEFAULT_PORT;
            expect<oxen::quic::Address> adr =
                    net::get_network_address(pr_str, default_port);
            if (adr) {
                pe.adr = std::move(*adr);
                m_command_line_peers.push_back(std::move(pe));
                continue;
            }
            if (adr != net::error::unsupported_address) {
                log::error(logcat, "Bad address (\"{}\"): {}", pr_str, adr.error().message());
                return false;
            }

            std::vector<oxen::quic::Address> resolved_addrs;
            bool r = append_net_address(resolved_addrs, pr_str, default_port);
            if (!r) {
                log::error(logcat, "Failed to parse or resolve address from string: {}", pr_str);
                return false;
            }
            for (const oxen::quic::Address& addr : resolved_addrs) {
                pe.id = crypto::rand<uint64_t>();
                pe.adr = addr;
                m_command_line_peers.push_back(pe);
            }
        }
    }

    if (command_line::has_arg(vm, arg_p2p_add_exclusive_node)) {
        if (!parse_peers_and_add_to_container(vm, arg_p2p_add_exclusive_node, m_exclusive_peers))
            return false;
    }

    if (command_line::has_arg(vm, arg_p2p_add_priority_node)) {
        if (!parse_peers_and_add_to_container(vm, arg_p2p_add_priority_node, m_priority_peers))
            return false;
    }

    if (command_line::has_arg(vm, arg_p2p_seed_node)) {
        std::unique_lock lock{m_seed_nodes_mutex};

        if (!parse_peers_and_add_to_container(vm, arg_p2p_seed_node, m_seed_nodes))
            return false;
    }

    if (command_line::get_arg(vm, arg_p2p_hide_my_port))
        m_hide_my_port = true;

    if (command_line::get_arg(vm, arg_no_sync))
        m_payload_handler.set_no_sync(true);

    if (!set_max_out_peers(command_line::get_arg(vm, arg_out_peers)))
        return false;
    else
        m_payload_handler.set_max_out_peers(
                m_network.m_config.m_net_config.max_out_connection_count);

    if (!set_max_in_peers(command_line::get_arg(vm, arg_in_peers)))
        return false;

    if (!set_tos_flag(vm, command_line::get_arg(vm, arg_tos_flag)))
        return false;

    if (!set_rate_up_limit(vm, command_line::get_arg(vm, arg_limit_rate_up)))
        return false;

    if (!set_rate_down_limit(vm, command_line::get_arg(vm, arg_limit_rate_down)))
        return false;

    if (!set_rate_limit(vm, command_line::get_arg(vm, arg_limit_rate)))
        return false;

    return true;
}
//-----------------------------------------------------------------------------------
static bool append_net_address(
        std::vector<oxen::quic::Address>& seed_nodes,
        std::string_view addr,
        uint16_t default_port) {
    using namespace boost::asio;

    bool has_colon = addr.find_last_of(':') != std::string::npos;
    bool has_dot = addr.find_last_of('.') != std::string::npos;
    bool has_square_bracket = addr.find('[') != std::string::npos;

    std::string host, port;
    // IPv6 will have colons regardless.  IPv6 and IPv4 address:port will have a colon but also
    // either a . or a [ as IPv6 addresses specified as address:port are to be specified as
    // "[addr:addr:...:addr]:port" One may also specify an IPv6 address as simply
    // "[addr:addr:...:addr]" without the port; in that case the square braces will be stripped
    // here.
    if ((has_colon && has_dot) || has_square_bracket) {
        std::tie(host, port) = net::get_network_address_host_and_port(addr);
    } else {
        host = addr;
        port = std::to_string(default_port);
    }

    log::info(logcat, "Resolving node address: host={}, port={}", host, port);

    io_service io_srv;
    ip::tcp::resolver resolver(io_srv);
    boost::system::error_code ec;
    ip::tcp::resolver::results_type result = resolver.resolve(host, port, boost::asio::ip::tcp::resolver::canonical_name, ec);
    if (ec) {
        log::error(logcat, "Failed to resolve host name '{}': {}:{}", host, ec.message(), ec.value());
        return false;
    }

    for (const ip::tcp::endpoint& endpoint : result) {
        const auto& na = seed_nodes.emplace_back(endpoint.data());
        log::info(logcat, "Added node: {}", na.to_string());
    }
    return true;
}

//-----------------------------------------------------------------------------------
bool node_server::init(const boost::program_options::variables_map& vm) {
    bool res = handle_command_line(vm);
    if (!res) {
        log::error(logcat, "Failed to handle command line");
        return false;
    }

    static_cast<std::array<unsigned char, 16>&>(m_network_id) = get_config(m_nettype).NETWORK_ID;

    m_config_folder = tools::utf8_path(command_line::get_arg(vm, cryptonote::arg_data_dir));
    if (m_network.m_port != cryptonote::get_config(m_nettype).P2P_DEFAULT_PORT)
        m_config_folder /= std::to_string(m_network.m_port);

    res = init_config();
    if (!res) {
        log::error(logcat, "Failed to init config.");
        return false;
    }

    res = m_network.m_peerlist.init(m_peerlist_storage.take(), m_allow_local_ip);
    if (!res) {
        log::error(logcat, "Failed to init peerlist.");
        return false;
    }

    for (const auto& p : m_command_line_peers)
        m_network.m_peerlist.append_with_peer_white(p);

    // only in case if we really sure that we have external visible ip
    m_have_address = true;

    // configure self

    m_network.m_net_server.set_threads_prefix("P2P");

    // from here onwards, it's online stuff
    if (m_offline)
        return res;

    // try to bind
    auto& net_server = m_network.m_net_server;
    net_server.get_config_object().set_handler(this);
    net_server.get_config_object().m_invoke_timeout =
            std::chrono::milliseconds{cryptonote::p2p::DEFAULT_INVOKE_TIMEOUT};

    if (!m_network.m_bind_ip.empty()) {
        std::string ipv6_addr;
        uint16_t ipv6_port = 0;
        net_server.set_connection_filter(this);
        log::info(logcat, "Binding (IPv4) on {}:{}", m_network.m_bind_ip, m_network.m_port);
        if (!m_network.m_bind_ipv6_address.empty() && m_use_ipv6) {
            ipv6_addr = m_network.m_bind_ipv6_address;
            ipv6_port = m_network.m_port_ipv6;
            log::info(
                    logcat,
                    "Binding (IPv6) on {}:{}",
                    m_network.m_bind_ipv6_address,
                    m_network.m_port_ipv6);
        }
        try {
            res = net_server.init_server(
                    m_network.m_port,
                    m_network.m_bind_ip,
                    ipv6_port,
                    ipv6_addr,
                    m_use_ipv6,
                    m_require_ipv4);
            if (!res) {
                log::error(logcat, "Failed to bind server");
                return false;
            }
        } catch (const std::exception& e) {
            log::error(logcat, "{}", e.what());
            res = false;
        }
    }

    m_listening_port = net_server.get_binded_port();
    log::info(
            logcat,
            fg(fmt::terminal_color::green),
            "Net service bound (IPv4) to {}:{}",
            m_network.m_bind_ip,
            m_listening_port);
    if (m_use_ipv6) {
        m_listening_port_ipv6 = net_server.get_binded_port_ipv6();
        log::info(
                logcat,
                fg(fmt::terminal_color::green),
                "Net service bound (IPv6) to {}:{}",
                m_network.m_bind_ipv6_address,
                m_listening_port_ipv6);
    }
    if (m_external_port)
        log::debug(logcat, "External port defined as {}", m_external_port);

    return res;
}
//-----------------------------------------------------------------------------------
cryptonote::protocol_handler& node_server::get_payload_object() {
    return m_payload_handler;
}
//-----------------------------------------------------------------------------------
static void log_detailed_peer_stats(std::unordered_map<peerid_type, peer_stats>& peer_stats_map, std::mutex& peer_stats_map_mutex) {
    if (log::get_level(logcat) > log::Level::debug)
      return;
    std::unique_lock lock{peer_stats_map_mutex};
    for (const auto& [peer_id, stats] : peer_stats_map) {
        log::debug(globallogcat, "Peer ID: {}\n\tConnections: {} total, {} failed\n\tLast Connected: {}\n\tTotal Connection Time: {} seconds",
            peer_id, stats.total_connections, stats.failed_connections, stats.last_connected_timestamp, stats.total_connection_time);
    }
}
//-----------------------------------------------------------------------------------
bool node_server::run() {
    // creating thread to log number of connections
    mPeersLoggerThread.emplace([&]() {
        log::debug(logcat, "Thread monitor number of peers - start");
        while (!is_closing && !m_network.m_net_server.is_stop_signal_sent()) {
            m_network.m_current_number_of_in_peers = get_incoming_connections_count();
            std::this_thread::sleep_for(1s);
        }
        log::debug(logcat, "Thread monitor number of peers - done");
    });  // lambda

    m_network.m_net_server.add_idle_handler([this] { return idle_worker(); }, 1s);
    m_network.m_net_server.add_idle_handler([this] { return m_payload_handler.on_idle(); }, 1s);

    // here you can set worker threads count
    int thrds_count = 10;
    // go to loop
    log::info(logcat, "Run net_service loop( {} threads)...", thrds_count);
    if (!m_network.m_net_server.run_server(thrds_count, true)) {
        log::error(logcat, "Failed to run net tcp server!");
    }

    log::info(logcat, "net_service loop stopped.");
    log_detailed_peer_stats(peer_stats_map, peer_stats_map_mutex);
    return true;
}
//-----------------------------------------------------------------------------------
static void update_peer_stats(
    std::unordered_map<peerid_type, peer_stats>& peer_stats_map, 
    std::mutex& peer_stats_map_mutex, 
    const peerid_type peer_id, 
    uint64_t connection_time
) {
    std::unique_lock lock{peer_stats_map_mutex};
    auto& stats = peer_stats_map[peer_id];
    stats.total_connections++;
    stats.total_connection_time += connection_time;
    stats.last_connected_timestamp = time(nullptr);
}
//-----------------------------------------------------------------------------------
static void update_peer_failed_connection(
    std::unordered_map<peerid_type, peer_stats>& peer_stats_map,
    std::mutex& peer_stats_map_mutex,
    const peerid_type peer_id
) {
    std::unique_lock lock{peer_stats_map_mutex};
    auto& stats = peer_stats_map[peer_id];
    stats.failed_connections++;
    stats.last_connected_timestamp = time(nullptr);
}
//-----------------------------------------------------------------------------------
static double calculate_peer_score(
    std::unordered_map<peerid_type, peer_stats>& peer_stats_map, 
    std::mutex& peer_stats_map_mutex, 
    const peerid_type peer_id) {
    std::unique_lock lock{peer_stats_map_mutex};
    constexpr double NEUTRAL_SCORE = 100.0;
    constexpr double MAX_CONNECTION_DURATION_FACTOR = 500.0;
    constexpr time_t RECENT_DISCONNECT_PENALTY_TIMEFRAME = 60 * 5; // 5 mins
    constexpr double RECENT_DISCONNECT_PENALTY = 500.0;
    constexpr double MIN_EXPECTED_UPTIME = 60; // 1 min
    constexpr double LOW_UPTIME_PENALTY = 100.0;
    constexpr double RECENT_ACTIVITY_CAP = 100.0;

    auto it = peer_stats_map.find(peer_id);
    if (it == peer_stats_map.end()) {
        return NEUTRAL_SCORE;
    }

    const peer_stats& stats = it->second;

    // Connection Duration Factor will return a score that is from [0, 500] depending on how many
    // minutes the node has been online 
    double connection_duration_factor = stats.total_connection_time / 60.0;
    connection_duration_factor = std::min(connection_duration_factor, MAX_CONNECTION_DURATION_FACTOR);

    double successful_connections = 0.0;
    if (stats.total_connections > stats.failed_connections) {
      successful_connections = stats.total_connections - stats.failed_connections;
    }

    // Success Rate will return a [0,1] percentage of how frequently the connection has succeeded vs total connections
    double success_rate = (stats.total_connections > 0)
                              ? successful_connections /
                                stats.total_connections
                              : 0.0;

    // Recent Activity factor will return a linearly growing score up until a cap based on how long since we last connected. 
    // This will be subtracted from the score to penalise people we havent seen in a long time
    double recent_activity_factor = static_cast<double>(time(nullptr) - stats.last_connected_timestamp) / 3600.0;
    recent_activity_factor = std::min(recent_activity_factor, RECENT_ACTIVITY_CAP);

    // Penalize peers who were recently disconnected, this will be subtracted if we connected to them 
    // in the last 5 mins. The list should only show people we are currently not connected to so we assume 
    // they had to have disconnected.
    double recent_disconnect_penalty = 0.0;
    if (stats.last_connected_timestamp > 0 &&
        (time(nullptr) - stats.last_connected_timestamp) <= RECENT_DISCONNECT_PENALTY_TIMEFRAME) {
        recent_disconnect_penalty = RECENT_DISCONNECT_PENALTY;
    }

    // We expect the node to have a minumum expected uptime, so we look at their average connection time
    // and if this is less than 20 mins per connection then we give them a penalty
    double average_uptime = (successful_connections > 0)
                                ? stats.total_connection_time / successful_connections
                                : 0.0;

    double low_uptime_penalty = 0.0;
    if (average_uptime < MIN_EXPECTED_UPTIME) {
        low_uptime_penalty = LOW_UPTIME_PENALTY;
    }

    double score = connection_duration_factor * success_rate
                      - recent_activity_factor
                      - recent_disconnect_penalty
                      - low_uptime_penalty;

    return score;
}
//-----------------------------------------------------------------------------------
static std::optional<std::pair<peerid_type, size_t>> select_best_peer(
      std::unordered_map<peerid_type, peer_stats>& peer_stats_map, 
      std::mutex& peer_stats_map_mutex, 
      const std::vector<std::pair<peerid_type, size_t>>& candidate_peers
    ) {
    // Create a local copy of the candidate peers to shuffle
    std::vector<std::pair<peerid_type, size_t>> shuffled_peers = candidate_peers;

    // Shuffle the peers
    std::random_device rd;
    std::mt19937 gen(rd());
    std::shuffle(shuffled_peers.begin(), shuffled_peers.end(), gen);

    double highest_score = -std::numeric_limits<double>::max();
    std::optional<std::pair<peerid_type, size_t>> best_peer;

    for (const auto& peer : shuffled_peers) {
        double score = calculate_peer_score(peer_stats_map, peer_stats_map_mutex, peer.first);
        log::debug(logcat, "Peer {} has score {}", peer.first, score);

        if (score > highest_score) {
            highest_score = score;
            best_peer = peer;
        }
    }

    if (best_peer) {
        log::info(logcat, "Selected best peer: {} with score {}", best_peer->first, highest_score);
    } else {
        log::warning(logcat, "No valid peers found during selection");
    }

    return best_peer;
}
//-----------------------------------------------------------------------------------
uint64_t node_server::get_public_connections_count() {
    return m_network.m_net_server.get_config_object().get_connections_count();
}
//-----------------------------------------------------------------------------------
bool node_server::deinit() {
    kill();

    if (!m_offline)
        m_network.m_net_server.deinit_server();
    return store_config();
}
//-----------------------------------------------------------------------------------
bool node_server::store_config() try {
    std::error_code ec;
    if (fs::create_directories(m_config_folder); ec) {
        log::warning(logcat, "Failed to create data directory {}", m_config_folder);
        return false;
    }

    peerlist_types active{};
    m_network.m_peerlist.get_peerlist(active);

    const auto state_file_path = get_peerlist_file();
    if (!m_peerlist_storage.store(state_file_path, active)) {
        log::warning(logcat, "Failed to save config to file {}", state_file_path);
        return false;
    }
    return true;
} catch (const std::exception& e) {
    log::error(logcat, "Exception in node_server::store_config: {}", e.what());
    return false;
}
//-----------------------------------------------------------------------------------
bool node_server::send_stop_signal() {
    log::debug(logcat, "[node] sending stop signal");
    m_network.m_net_server.send_stop_signal();
    log::debug(logcat, "[node] Stop signal sent");

    std::list<connection_id_t> connection_ids;
    auto& net_config = m_network.m_net_server.get_config_object();
    net_config.foreach_connection([&](const p2p_connection_context& cntxt) {
        connection_ids.push_back(cntxt.m_connection_id);
        return true;
    });
    for (const auto& connection_id : connection_ids)
        net_config.close(connection_id);
    m_payload_handler.stop();
    return true;
}
//-----------------------------------------------------------------------------------
void node_server::do_handshake_with_peer(
        const connection_id_t& connection_id,
        bool anchor,
        bool just_take_peerlist,
        std::function<void(p2p_connection_context*)> done) {
    using request_t = typename COMMAND_HANDSHAKE::request;
    using response_t = typename COMMAND_HANDSHAKE::response;

    request_t arg{};
    get_local_node_data(arg.node_data);
    m_payload_handler.get_payload_sync_data(arg.payload_data);

    // The levin layer can fail an invoke both by calling back with an error and by returning
    // false, so this makes sure `done` is called only once.
    auto finished = std::make_shared<std::atomic<bool>>(false);
    auto finish = [finished, done = std::move(done)](p2p_connection_context* context) {
        if (!finished->exchange(true))
            done(context);
    };

    bool r = epee::net_utils::async_invoke_remote_command2<response_t>(
            connection_id,
            COMMAND_HANDSHAKE::ID,
            arg,
            m_network.m_net_server.get_config_object(),
            [this, anchor, just_take_peerlist, finish](
                    int code, response_t&& rsp, p2p_connection_context& context) {
                bool timeout = false;
                const bool ok = [&] {
                    if (code < 0) {
                        log::warning(
                                logcat,
                                "{}COMMAND_HANDSHAKE invoke failed. ({},{})",
                                context,
                                code,
                                epee::levin::get_err_descr(code));
                        timeout = code == LEVIN_ERROR_CONNECTION_TIMEDOUT ||
                                  code == LEVIN_ERROR_CONNECTION_DESTROYED;
                        return false;
                    }

                    if (rsp.node_data.network_id != m_network_id) {
                        log::warning(
                                logcat,
                                "{}COMMAND_HANDSHAKE Failed, wrong network! ({}), closing "
                                "connection.",
                                context,
                                boost::lexical_cast<std::string>(rsp.node_data.network_id));
                        return false;
                    }

                    if (!handle_remote_peerlist(rsp.local_peerlist_new, context)) {
                        log::warning(
                                logcat,
                                "{}COMMAND_HANDSHAKE: failed to handle_remote_peerlist(...), "
                                "closing connection.",
                                context);
                        add_host_fail(context.m_remote_address);
                        return false;
                    }

                    if (just_take_peerlist) {
                        log::debug(logcat, "{} COMMAND_HANDSHAKE(AND CLOSE) INVOKED OK", context);
                        return true;
                    }

                    if (!m_payload_handler.process_payload_sync_data(
                                std::move(rsp.payload_data), context, true)) {
                        log::warning(
                                logcat,
                                "{}COMMAND_HANDSHAKE invoked, but process_payload_sync_data "
                                "returned false, dropping connection.",
                                context);
                        return false;
                    }

                    context.peer_id = rsp.node_data.peer_id;
                    m_network.m_peerlist.set_peer_just_seen(
                            rsp.node_data.peer_id, context.m_remote_address, context.m_history);

                    if (rsp.node_data.peer_id == m_network.m_config.m_peer_id) {
                        log::debug(
                                logcat, "{}Connection to self detected, dropping connection", context);
                        return false;
                    }
                    context.m_anchor = anchor;
                    log::info(logcat, "{}New connection handshaked", context);
                    log::debug(logcat, "{} COMMAND_HANDSHAKE INVOKED OK", context);
                    return true;
                }();

                if (!ok) {
                    log::warning(logcat, "{}COMMAND_HANDSHAKE Failed", context);
                    update_peer_failed_connection(
                            peer_stats_map, peer_stats_map_mutex, context.peer_id);
                    // A timed out or destroyed connection has already been closed
                    if (!timeout)
                        m_network.m_net_server.get_config_object().close(context.m_connection_id);
                }
                finish(ok ? &context : nullptr);
            },
            std::chrono::milliseconds{cryptonote::p2p::DEFAULT_HANDSHAKE_INVOKE_TIMEOUT});

    if (!r) {
        log::warning(logcat, "COMMAND_HANDSHAKE invoke could not be sent");
        m_network.m_net_server.get_config_object().close(connection_id);
        finish(nullptr);
    }
}
//-----------------------------------------------------------------------------------
bool node_server::do_peer_timed_sync(
        const epee::net_utils::connection_context_base& context_, peerid_type /*peer_id*/) {
    using request_t = typename COMMAND_TIMED_SYNC::request;
    using response_t = typename COMMAND_TIMED_SYNC::response;
    request_t arg{};
    m_payload_handler.get_payload_sync_data(arg.payload_data);

    bool r = epee::net_utils::async_invoke_remote_command2<response_t>(
            context_.m_connection_id,
            COMMAND_TIMED_SYNC::ID,
            arg,
            m_network.m_net_server.get_config_object(),
            [this](int code, response_t&& rsp, p2p_connection_context& context) {
                context.m_in_timedsync = false;
                if (code < 0) {
                    log::warning(
                            logcat,
                            "{}COMMAND_TIMED_SYNC invoke failed. ({}, {})",
                            context,
                            code,
                            epee::levin::get_err_descr(code));
                    return;
                }

                if (!handle_remote_peerlist(rsp.local_peerlist_new, context)) {
                    log::warning(
                            logcat,
                            "{}COMMAND_TIMED_SYNC: failed to handle_remote_peerlist(...), closing "
                            "connection.",
                            context);
                    m_network.m_net_server.get_config_object().close(context.m_connection_id);
                    add_host_fail(context.m_remote_address);
                }
                if (!context.m_is_income)
                    m_network.m_peerlist.set_peer_just_seen(
                            context.peer_id, context.m_remote_address, rsp.payload_data.history);
                if (!m_payload_handler.process_payload_sync_data(
                            std::move(rsp.payload_data), context, false)) {
                    m_network.m_net_server.get_config_object().close(context.m_connection_id);
                }
            });

    if (!r) {
        log::warning(logcat, "{}COMMAND_TIMED_SYNC Failed", context_);
        return false;
    }
    return true;
}

//-----------------------------------------------------------------------------------
size_t node_server::get_random_exp_index(
        const size_t size, const double rate) {
    if (size <= 1)
        return 0;

    // (See net_node.h)

    crypto::random_device rng;
    const double u = std::uniform_real_distribution{}(rng);
    // For non-truncated exponential we could use: -1/rate * log(1-u), (or
    // std::exponential_distribution) but then we'd have to repeat until we got a value < size,
    // which is technically unbounded computational time.  Instead we mutate the calculation like
    // this, which gives us exponential, but truncated to [0, size), without looping:
    const size_t res =
            static_cast<size_t>(-1.0 / rate * std::log(1.0 - u * (1.0 - std::exp(-rate * size))));

    log::debug(logcat, "Random connection index={} (size={})", res, size);
    return res;
}
//-----------------------------------------------------------------------------------
template <typename Entry>
bool node_server::is_peer_used(const Entry& peer) {
    if (m_network.m_config.m_peer_id == peer.id)
        return true;  // dont make connections to ourself

    if (is_connect_pending(peer.adr))
        return true;

    bool used = false;
    m_network.m_net_server.get_config_object().foreach_connection(
            [&](const p2p_connection_context& cntxt) {
                if (cntxt.peer_id == peer.id ||
                    (!cntxt.m_is_income && peer.adr == cntxt.m_remote_address)) {
                    used = true;
                    return false;  // stop enumerating
                }
                return true;
            });
    return used;
}
//-----------------------------------------------------------------------------------
bool node_server::is_addr_connected(
        const oxen::quic::Address& peer) {
    bool connected = false;
    m_network.m_net_server.get_config_object().foreach_connection(
            [&](const p2p_connection_context& cntxt) {
                if (!cntxt.m_is_income && peer == cntxt.m_remote_address) {
                    connected = true;
                    return false;  // stop enumerating
                }
                return true;
            });

    return connected;
}

static std::string format_stamp_ago(int64_t stamp) {
    if (stamp)
        return tools::friendly_duration(
                std::chrono::system_clock::now() - std::chrono::system_clock::from_time_t(stamp));
    return "never"s;
}

bool node_server::connect_and_handshake(
        const oxen::quic::Address& na,
        PeerType peer_type,
        bool just_take_peerlist,
        uint64_t last_seen_stamp,
        uint64_t first_seen_stamp,
        std::function<void(bool success)> done) {
    {
        std::lock_guard lock{m_pending_connects_mutex};
        if (!m_pending_connects.insert(na).second)
            return false;
    }

    log::debug(
            logcat,
            "Connecting to {}(peer_type={}, last_seen: {})...",
            na.to_string(),
            peer_type,
            format_stamp_ago(last_seen_stamp));

    const std::string_view priority = is_priority_node(na) ? "[priority] " : "";
    auto finish = [this, na, done = std::move(done)](bool success) {
        {
            std::lock_guard lock{m_pending_connects_mutex};
            m_pending_connects.erase(na);
        }
        if (!success)
            record_addr_failed(na);
        if (done)
            done(success);
    };

    bool started = m_network.m_net_server.connect_async(
            na.host(),
            std::to_string(na.port()),
            m_network.m_config.m_net_config.connection_timeout.count(),
            [this, na, priority, peer_type, just_take_peerlist, first_seen_stamp, finish](
                    const typename net_server::t_connection_context& con,
                    const boost::system::error_code& ec) {
                if (ec) {
                    log::info(logcat, "{}Connect failed to {}", priority, na.to_string());
                    finish(false);
                    return false;
                }
                do_handshake_with_peer(
                        con.m_connection_id,
                        peer_type == PeerType::anchor,
                        just_take_peerlist,
                        [this, na, priority, just_take_peerlist, first_seen_stamp, finish](
                                p2p_connection_context* context) {
                            if (!context) {
                                log::info(
                                        logcat,
                                        "{}Failed to HANDSHAKE with peer {}",
                                        priority,
                                        na.to_string());
                                finish(false);
                                return;
                            }

                            if (just_take_peerlist) {
                                log::debug(logcat, "{}CONNECTION HANDSHAKED OK AND CLOSED.", *context);
                                m_network.m_net_server.get_config_object().close(
                                        context->m_connection_id);
                                finish(true);
                                return;
                            }

                            peerlist_entry pe_local{};
                            pe_local.adr = na;
                            pe_local.id = context->peer_id;
                            pe_local.last_seen = static_cast<int64_t>(time(nullptr));
                            pe_local.history = context->m_history;
                            m_network.m_peerlist.append_with_peer_white(pe_local);

                            anchor_peerlist_entry ape{};
                            ape.adr = na;
                            ape.id = context->peer_id;
                            ape.first_seen = first_seen_stamp ? first_seen_stamp : time(nullptr);
                            m_network.m_peerlist.append_with_peer_anchor(ape);

                            log::debug(logcat, "{}CONNECTION HANDSHAKED OK.", *context);
                            finish(true);
                        });
                return true;
            },
            m_network.m_bind_ip);

    if (!started) {
        log::info(logcat, "{}Connect failed to {}", priority, na.to_string());
        finish(false);
    }
    return started;
}
//-----------------------------------------------------------------------------------
bool node_server::is_connect_pending(const oxen::quic::Address& na) {
    std::lock_guard lock{m_pending_connects_mutex};
    return m_pending_connects.count(na);
}
//-----------------------------------------------------------------------------------
size_t node_server::get_outgoing_and_pending_count() {
    size_t count = 0;
    std::set<oxen::quic::Address> connected;
    m_network.m_net_server.get_config_object().foreach_connection(
            [&](const p2p_connection_context& cntxt) {
                if (!cntxt.m_is_income) {
                    ++count;
                    connected.insert(cntxt.m_remote_address);
                }
                return true;
            });
    std::lock_guard lock{m_pending_connects_mutex};
    for (const auto& addr : m_pending_connects)
        if (!connected.count(addr))
            ++count;
    return count;
}

//-----------------------------------------------------------------------------------
void node_server::record_addr_failed(
        const oxen::quic::Address& addr) {
    std::unique_lock lock{m_conn_fails_cache_lock};
    m_conn_fails_cache[addr.host()] = time(NULL);
}
//-----------------------------------------------------------------------------------
bool node_server::is_addr_recently_failed(
        const oxen::quic::Address& addr) {
    std::shared_lock lock{m_conn_fails_cache_lock};
    auto it = m_conn_fails_cache.find(addr.host());
    if (it == m_conn_fails_cache.end())
        return false;

    auto ago =
            std::chrono::system_clock::now() - std::chrono::system_clock::from_time_t(it->second);
    return ago <= cryptonote::p2p::FAILED_ADDR_FORGET;
}

static std::string peerid_to_string(peerid_type peer_id) {
    return "{:016x}"_format(peer_id);
}

//-----------------------------------------------------------------------------------
bool node_server::make_new_connection_from_anchor_peerlist(
        const std::vector<anchor_peerlist_entry>& anchor_peerlist) {
    bool started = false;
    for (const auto& pe : anchor_peerlist) {
        if (get_outgoing_and_pending_count() >= cryptonote::p2p::DEFAULT_ANCHOR_CONNECTIONS_COUNT)
            break;

        log::debug(
                logcat,
                "Considering connecting (out) to anchor peer: {} {}",
                peerid_to_string(pe.id),
                pe.adr.to_string());

        if (is_peer_used(pe)) {
            log::debug(logcat, "Peer is used");
            continue;
        }

        if (!is_remote_host_allowed(pe.adr)) {
            continue;
        }

        if (is_addr_recently_failed(pe.adr)) {
            continue;
        }

        log::debug(
                logcat,
                "Selected peer: {} {} first_seen: {}",
                peerid_to_string(pe.id),
                pe.adr.to_string(),
                format_stamp_ago(pe.first_seen));

        if (connect_and_handshake(pe.adr, PeerType::anchor, false, 0, pe.first_seen))
            started = true;
    }

    return started;
}
//-----------------------------------------------------------------------------------
std::vector<size_t> node_server::connectable_peers(
        bool use_white_list, const std::optional<cryptonote::sync_need>& need) {
    // build a set of all the addresses and peer_ids that we're connected to so that we can filter
    // them out from our potential peer selection below.
    struct {
        std::set<oxen::quic::Address> addr;
        std::unordered_set<peerid_type> peer;
    } seen;
    m_network.m_net_server.get_config_object().foreach_connection(
            [&](const p2p_connection_context& cntxt) {
                seen.addr.insert(cntxt.m_remote_address);
                seen.peer.insert(cntxt.peer_id);
                return true;
            });
    {
        std::lock_guard lock{m_pending_connects_mutex};
        seen.addr.insert(m_pending_connects.begin(), m_pending_connects.end());
    }

    std::vector<size_t> filtered;
    size_t idx = 0;
    m_network.m_peerlist.foreach (use_white_list, [&](const peerlist_entry& pe) {
        ++idx;
        // Skip peers we're already connected to:
        if (seen.peer.count(pe.id) || seen.addr.count(pe.adr))
            return true;
        // Don't include this in selection if it recently failed
        if (is_addr_recently_failed(pe.adr))
            return true;
        // An entry's chain height is long out of date, but its history isn't, so it is judged
        // against the height we are syncing to.
        if (need && (!cryptonote::history_covers(need->height, need->target, pe.history) ||
                     m_unhelpful_peers.contains(pe.adr)))
            return true;

        filtered.emplace_back(idx - 1);
        return true;
    });
    return filtered;
}
//-----------------------------------------------------------------------------------
bool node_server::make_new_connection_from_peerlist(
        bool use_white_list, const std::optional<cryptonote::sync_need>& need) {
    auto& peerlist = m_network.m_peerlist;
    std::set<size_t> tried_peers;

    for (size_t rand_count = 0; rand_count < 3 && !m_network.m_net_server.is_stop_signal_sent();
         rand_count++) {
        size_t random_index;

        std::vector<size_t> filtered = connectable_peers(use_white_list, need);

        if (filtered.empty()) {
            log::debug(
                    logcat,
                    "No available peer in {} list",
                    (use_white_list ? "white" : "gray"));
            return false;
        }

        if (use_white_list) {
            std::vector<std::pair<peerid_type, size_t>> candidate_peers;
            candidate_peers.reserve(filtered.size());
            for (size_t i = 0; i < filtered.size(); ++i) {
                peerlist_entry pe;
                if (peerlist.get_white_peer_by_index(pe, filtered[i]))
                    candidate_peers.push_back(std::make_pair(pe.id, filtered[i]));
            }
            auto maybe_best_peer = select_best_peer(peer_stats_map, peer_stats_map_mutex, candidate_peers);
            if (!maybe_best_peer)
                return false;
            random_index = maybe_best_peer->second;
        } else {
            random_index = crypto::rand_idx(filtered.size());
            random_index = filtered[random_index];
        }

        if (random_index >= (use_white_list ? peerlist.get_white_peers_count()
                                            : peerlist.get_gray_peers_count())) {
            log::error(logcat, "random_index < peers size failed!!");
            return false;
        }

        if (tried_peers.count(random_index))
            continue;

        tried_peers.insert(random_index);
        peerlist_entry pe{};
        bool r = use_white_list ? peerlist.get_white_peer_by_index(pe, random_index)
                                : peerlist.get_gray_peer_by_index(pe, random_index);
        if (!r) {
            log::error(logcat, "Failed to get random peer from peerlist(white:{})", use_white_list);
            return false;
        }

        log::debug(
                logcat,
                "Considering connecting (out) to {} list peer: {} {}",
                (use_white_list ? "white" : "gray"),
                peerid_to_string(pe.id),
                pe.adr.to_string());

        if (is_peer_used(pe)) {
            log::debug(logcat, "Peer is used");
            continue;
        }

        if (!is_remote_host_allowed(pe.adr))
            continue;

        if (is_addr_recently_failed(pe.adr))
            continue;

        log::debug(
                logcat,
                "Selected peer: {} {} [peer_list={}] last_seen: {}",
                peerid_to_string(pe.id),
                pe.adr.to_string(),
                (use_white_list ? "white" : "gray"),
                format_stamp_ago(pe.last_seen));

        if (connect_and_handshake(
                    pe.adr, use_white_list ? PeerType::white : PeerType::gray, false, pe.last_seen))
            return true;
    }
    return false;
}
//-----------------------------------------------------------------------------------
void node_server::connect_to_seed() {
    if (!m_seed_nodes_initialized) {
        std::unique_lock lock{m_seed_nodes_mutex};
        if (!m_seed_nodes_initialized) {
            const auto& netconf = cryptonote::get_config(m_nettype);
            for (const auto& full_addr : netconf.P2P_SEED_NODES) {
                log::debug(logcat, "Seed node: {}", full_addr);
                append_net_address(m_seed_nodes, full_addr, netconf.P2P_DEFAULT_PORT);
            }
            log::debug(logcat, "Number of seed nodes: {}", m_seed_nodes.size());
            if (!m_seed_nodes.empty())
                m_next_seed = crypto::rand_idx(m_seed_nodes.size());
            m_seed_nodes_initialized = true;
        }
    }

    std::shared_lock shlock{m_seed_nodes_mutex};

    if (m_seed_nodes.empty() || m_offline || !m_exclusive_peers.empty())
        return;

    // A seed is only asked for its peerlist, which any one of them can give, so they are tried one
    // at a time, in turn.
    for (const auto& seed : m_seed_nodes)
        if (is_connect_pending(seed))
            return;

    const size_t n_seeds = m_seed_nodes.size();
    for (size_t i = 0; i < n_seeds; ++i) {
        const auto& seed = m_seed_nodes[m_next_seed++ % n_seeds];
        peerlist_entry pe_seed{};
        pe_seed.adr = seed;
        if (is_peer_used(pe_seed))
            continue;
        connect_and_handshake(seed, PeerType::white, true, 0, 0, [this, n_seeds](bool success) {
            if (success)
                m_seed_failures = 0;
            else if (++m_seed_failures % n_seeds == 0)
                log::warning(
                        logcat, "Failed to connect to any of seed peers, continuing without seeds");
        });
        return;
    }
}
//-----------------------------------------------------------------------------------
auto node_server::check_sync_peers(const cryptonote::sync_need& need)
        -> sync_peers {
    m_unhelpful_peers.forget_servable(need.height);

    sync_peers peers;
    m_network.m_net_server.get_config_object().foreach_connection([&](const p2p_connection_context&
                                                                              cntxt) {
        if (cntxt.m_state == cryptonote::cryptonote_connection_context::state_before_handshake)
            return true;
        ++peers.total;
        if (cryptonote::peer_can_serve(
                    need.height, cntxt.m_remote_blockchain_height, cntxt.m_history)) {
            ++peers.able;
            return true;
        }
        // Incoming peers (often syncing nodes behind us) aren't ours to replace.
        if (cntxt.m_is_income)
            return true;
        m_unhelpful_peers.add(
                cntxt.m_remote_address, cntxt.m_remote_blockchain_height, cntxt.m_history);
        // Never an anchor (which guards against being surrounded by bad peers), nor a peer we
        // insist on, nor one still sending us blocks we asked for.
        if (!peers.droppable && !cntxt.m_anchor && cntxt.m_requested_objects.empty() &&
            !is_priority_node(cntxt.m_remote_address))
            peers.droppable = droppable_peer{
                    cntxt.m_connection_id,
                    cntxt.m_remote_address,
                    cntxt.m_remote_blockchain_height,
                    cntxt.m_history};
        return true;
    });
    return peers;
}
//-----------------------------------------------------------------------------------
bool node_server::connections_maker() {
    if (m_offline || m_network.m_net_server.is_stop_signal_sent())
        return true;

    // Nothing here waits for a connection: each attempt started counts as pending until its
    // handshake finishes, and the next run (each second) sees how it went.
    connect_to_peerlist(m_exclusive_peers);
    if (!m_exclusive_peers.empty())
        return true;

    if (!get_public_white_peers_count())
        connect_to_seed();

    connect_to_peerlist(m_priority_peers);

    // While syncing, at least half the outgoing connections' worth of peers should be able to serve
    // what the sync needs; no more than that, so that syncing nodes don't all crowd onto the peers
    // that keep the whole chain and leave the rest of the network to itself.  Until there are
    // that many, new connections go only to peers whose peerlist entries say they can serve the
    // sync (and that haven't turned out not to), white before gray, for as long as there are any
    // (only when there are none are connections made as usual, if only to learn of more peers),
    // and at the outgoing connection limit a peer that can't serve the sync is dropped to make
    // room, but only while there is a peer to replace it with.
    const auto need = m_payload_handler.get_sync_need();
    const size_t max_out = m_network.m_config.m_net_config.max_out_connection_count;
    // Whether more peers able to serve the sync are wanted and there are some left to connect to:
    // while so, nothing else is connected to.
    bool want_servable = false;
    if (need) {
        const auto peers = check_sync_peers(*need);
        if (const auto counts = std::make_pair(peers.able, peers.total);
            counts != m_sync_peers_logged) {
            log::info(
                    globallogcat,
                    "Using {}/{} peers able to serve the sync from height {}",
                    peers.able,
                    peers.total,
                    need->height);
            m_sync_peers_logged = counts;
        }
        if (peers.able < (max_out + 1) / 2) {
            for (bool white : {true, false})
                while (get_outgoing_and_pending_count() < max_out &&
                       make_new_connection_from_peerlist(white, need))
                    ;
            want_servable = !connectable_peers(true, need).empty() ||
                            !connectable_peers(false, need).empty();
            if (peers.droppable && want_servable && get_outgoing_connections_count() >= max_out) {
                log::info(
                        logcat,
                        "Dropping peer {} (height {}, history {}), which can't serve the sync from "
                        "height {}, to make room for one that can",
                        peers.droppable->address.to_string(),
                        peers.droppable->height,
                        cryptonote::describe_history(peers.droppable->history),
                        need->height);
                m_network.m_net_server.get_config_object().close(peers.droppable->connection_id);
            }
        }
    } else {
        m_unhelpful_peers.clear();
    }

    if (!want_servable) {
        // While syncing, only white (known good) peers
        const size_t expected_white_connections =
                !m_payload_handler.is_synchronized()
                        ? max_out
                        : (max_out * cryptonote::p2p::DEFAULT_WHITELIST_CONNECTIONS_PERCENT) / 100;
        const size_t conn_count = get_outgoing_and_pending_count();
        log::debug(
                logcat,
                "Expected white connections {}, connection count {}",
                expected_white_connections,
                conn_count);
        if (conn_count < expected_white_connections) {
            // start from anchor list
            while (get_outgoing_and_pending_count() <
                           cryptonote::p2p::DEFAULT_ANCHOR_CONNECTIONS_COUNT &&
                   make_expected_connections_count(
                           PeerType::anchor, cryptonote::p2p::DEFAULT_ANCHOR_CONNECTIONS_COUNT))
                ;
            // then do white list
            while (get_outgoing_and_pending_count() < expected_white_connections &&
                   make_expected_connections_count(PeerType::white, expected_white_connections))
                ;
            // then do grey list
            while (get_outgoing_and_pending_count() < max_out &&
                   make_expected_connections_count(PeerType::gray, max_out))
                ;
        } else {
            // start from grey list
            while (get_outgoing_and_pending_count() < max_out &&
                   make_expected_connections_count(PeerType::gray, max_out))
                ;
            // and then do white list
            while (get_outgoing_and_pending_count() < max_out &&
                   make_expected_connections_count(PeerType::white, max_out))
                ;
        }
    }

    // Nothing in flight and still short of connections: there was no one left to try, so ask a
    // seed for more peers.
    bool pending;
    {
        std::lock_guard lock{m_pending_connects_mutex};
        pending = !m_pending_connects.empty();
    }
    if (!pending && get_outgoing_connections_count() < max_out) {
        log::info(logcat, "Failed to connect to any, trying seeds");
        connect_to_seed();
    }

    return true;
}
//-----------------------------------------------------------------------------------
bool node_server::make_expected_connections_count(
        PeerType peer_type, size_t expected_connections) {
    if (m_offline)
        return false;

    std::vector<anchor_peerlist_entry> apl;

    if (peer_type == PeerType::anchor) {
        m_network.m_peerlist.get_and_empty_anchor_peerlist(apl);
    }

    size_t conn_count = get_outgoing_and_pending_count();
    // add new connections from white peers
    if (conn_count < expected_connections) {
        if (m_network.m_net_server.is_stop_signal_sent())
            return false;

        log::debug(
                logcat,
                "Making expected connection, type {}, {}/{} connections",
                peer_type,
                conn_count,
                expected_connections);

        if (peer_type == PeerType::anchor && !make_new_connection_from_anchor_peerlist(apl)) {
            return false;
        }

        if (peer_type == PeerType::white && !make_new_connection_from_peerlist(true)) {
            return false;
        }

        if (peer_type == PeerType::gray && !make_new_connection_from_peerlist(false)) {
            return false;
        }
    }
    return true;
}
//-----------------------------------------------------------------------------------
size_t node_server::get_public_outgoing_connections_count() {
    return get_outgoing_connections_count();
}
//-----------------------------------------------------------------------------------
size_t node_server::get_outgoing_connections_count() {
    size_t count = 0;
    m_network.m_net_server.get_config_object().foreach_connection(
            [&](const p2p_connection_context& cntxt) {
                if (!cntxt.m_is_income)
                    ++count;
                return true;
            });
    return count;
}
//-----------------------------------------------------------------------------------
size_t node_server::get_incoming_connections_count() {
    size_t count = 0;
    m_network.m_net_server.get_config_object().foreach_connection(
            [&](const p2p_connection_context& cntxt) {
                if (cntxt.m_is_income)
                    ++count;
                return true;
            });
    return count;
}
//-----------------------------------------------------------------------------------
size_t node_server::get_public_white_peers_count() {
    return m_network.m_peerlist.get_white_peers_count();
}
//-----------------------------------------------------------------------------------
size_t node_server::get_public_gray_peers_count() {
    return m_network.m_peerlist.get_gray_peers_count();
}
//-----------------------------------------------------------------------------------
void node_server::get_peerlist(
        std::vector<peerlist_entry>& gray, std::vector<peerlist_entry>& white) {
    m_network.m_peerlist.get_peerlist(gray, white);
}
//-----------------------------------------------------------------------------------
bool node_server::idle_worker() {
    m_peer_handshake_idle_maker_interval.do_call([this] { return peer_sync_idle_maker(); });
    m_connections_maker_interval.do_call([this] { return connections_maker(); });
    m_gray_peerlist_housekeeping_interval.do_call([this] { return gray_peerlist_housekeeping(); });
    m_peerlist_store_interval.do_call([this] { return store_config(); });
    m_incoming_connections_interval.do_call([this] { return check_incoming_connections(); });
    return true;
}
//-----------------------------------------------------------------------------------
bool node_server::check_incoming_connections() {
    if (m_offline)
        return true;

    if (get_incoming_connections_count() == 0) {
        if (m_hide_my_port || m_network.m_config.m_net_config.max_in_connection_count == 0) {
            log::warning(
                    globallogcat,
                    "Incoming connections disabled, enable them for full connectivity");
        } else {
            log::warning(
                    logcat,
                    fg(fmt::terminal_color::red),
                    "No incoming connections - check firewalls/routers allow port {}",
                    get_this_peer_port());
        }
    }
    return true;
}
//-----------------------------------------------------------------------------------
bool node_server::peer_sync_idle_maker() {
    // TODO: this sync code is rather dumb: every 60s we trigger a sync with every connected peer
    // all at once which results in a sudden spike of activity every 60s then not much in between.
    // This really should be spaced out, i.e. the 60s sync timing should apply per peer, not
    // globally.

    log::debug(logcat, "STARTED PEERLIST IDLE HANDSHAKE");
    typedef std::list<std::pair<epee::net_utils::connection_context_base, peerid_type>>
            local_connects_type;
    local_connects_type cncts;
    m_network.m_net_server.get_config_object().foreach_connection(
            [&](p2p_connection_context& cntxt) {
                if (cntxt.peer_id && !cntxt.m_in_timedsync) {
                    cntxt.m_in_timedsync = true;
                    cncts.push_back(local_connects_type::value_type(
                            cntxt,
                            cntxt.peer_id));  // do idle sync only with handshaked connections
                }
                return true;
            });

    std::for_each(cncts.begin(), cncts.end(), [&](const auto& vl) {
        do_peer_timed_sync(vl.first, vl.second);
    });

    log::debug(logcat, "FINISHED PEERLIST IDLE HANDSHAKE");
    return true;
}
//-----------------------------------------------------------------------------------
bool node_server::sanitize_peerlist(
        std::vector<peerlist_entry>& local_peerlist) {
    for (size_t i = 0; i < local_peerlist.size(); ++i) {
        peerlist_entry& be = local_peerlist[i];
        // Loopback, local and unspecified (0.0.0.0, ::) addresses
        if (!be.adr.is_public_ip()) {
            log::debug(logcat, "Ignoring {}", be.adr.to_string());
            std::swap(local_peerlist[i], local_peerlist[local_peerlist.size() - 1]);
            local_peerlist.resize(local_peerlist.size() - 1);
            --i;
            continue;
        }
        local_peerlist[i].last_seen = 0;
    }
    return true;
}
//-----------------------------------------------------------------------------------
bool node_server::handle_remote_peerlist(
        const std::vector<peerlist_entry>& peerlist,
        const epee::net_utils::connection_context_base& context) {
    std::vector<peerlist_entry> peerlist_ = peerlist;
    if (!sanitize_peerlist(peerlist_))
        return false;

    log::debug(logcat, "{}REMOTE PEERLIST: remote peerlist size={}", context, peerlist_.size());
    log::trace(
            logcat,
            "{}REMOTE PEERLIST: \n{}",
            context,
            "REMOTE PEERLIST: \n",
            print_peerlist_to_string(peerlist_));
    return m_network.m_peerlist.merge_peerlist(peerlist_, [this](const peerlist_entry& pe) {
        return !is_addr_recently_failed(pe.adr);
    });
}
//-----------------------------------------------------------------------------------
bool node_server::get_local_node_data(basic_node_data& node_data) {
    node_data.peer_id = m_network.m_config.m_peer_id;
    if (!m_hide_my_port)
        node_data.my_port = m_external_port ? m_external_port : m_listening_port;
    else
        node_data.my_port = 0;
    node_data.network_id = m_network_id;
    return true;
}
//-----------------------------------------------------------------------------------
int node_server::handle_get_support_flags(
        int /*command*/,
        COMMAND_REQUEST_SUPPORT_FLAGS::request& /*arg*/,
        COMMAND_REQUEST_SUPPORT_FLAGS::response& rsp,
        p2p_connection_context& /*context*/) {
    rsp.support_flags = 0;
    return 1;
}
//-----------------------------------------------------------------------------------
void node_server::request_callback(
        const epee::net_utils::connection_context_base& context) {
    m_network.m_net_server.get_config_object().request_callback(context.m_connection_id);
}
//-----------------------------------------------------------------------------------
bool node_server::relay_notify_to_list(
        int command,
        const std::span<const uint8_t> data_buff,
        std::span<const connection_id_t> connections) {
    auto& net_config = m_network.m_net_server.get_config_object();
    for (const auto& c_id : connections)
        net_config.notify(command, data_buff, c_id);
    return true;
}
//-----------------------------------------------------------------------------------
void node_server::callback(p2p_connection_context& context) {
    m_payload_handler.on_callback(context);
}
//-----------------------------------------------------------------------------------
bool node_server::invoke_notify_to_peer(
        int command,
        const std::span<const uint8_t> req_buff,
        const epee::net_utils::connection_context_base& context) {
    int res = m_network.m_net_server.get_config_object().notify(
            command, req_buff, context.m_connection_id);
    return res > 0;
}
//-----------------------------------------------------------------------------------
bool node_server::drop_connection(
        const epee::net_utils::connection_context_base& context) {
    m_network.m_net_server.get_config_object().close(context.m_connection_id);
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_callback>
bool node_server::try_ping(
        basic_node_data& node_data, p2p_connection_context& context, const t_callback& cb) {
    if (!node_data.my_port || node_data.my_port > std::numeric_limits<uint16_t>::max())
        return false;
    const auto my_port = static_cast<uint16_t>(node_data.my_port);

    if (!m_network.m_peerlist.is_host_allowed(context.m_remote_address))
        return false;

    // The peer's own listening address
    oxen::quic::Address address = context.m_remote_address;
    address.set_port(my_port);

    peerid_type pr = node_data.peer_id;
    bool r = m_network.m_net_server.connect_async(
            address.host(),
            std::to_string(my_port),
            m_network.m_config.m_net_config.ping_connection_timeout.count(),
            [cb, /*context,*/ address, pr, &context, this](
                    const typename net_server::t_connection_context& ping_context,
                    const boost::system::error_code& ec) -> bool {
                if (ec) {
                    log::warning(
                            logcat,
                            "{}back ping connect failed to {}",
                            ping_context,
                            address.to_string());
                    return false;
                }
                COMMAND_PING::request req{};
                COMMAND_PING::response rsp{};
                // vc2010 workaround
                /*std::string ip_ = ip;
                std::string port_=port;
                peerid_type pr_ = pr;
                auto cb_ = cb;*/

                // GCC 5.1.0 gives error with second use of uint64_t (peerid_type) variable.
                peerid_type pr_ = pr;

                auto& net_config = m_network.m_net_server.get_config_object();
                bool inv_call_res =
                        epee::net_utils::async_invoke_remote_command2<COMMAND_PING::response>(
                                ping_context.m_connection_id,
                                COMMAND_PING::ID,
                                req,
                                net_config,
                                [=, this](
                                        int code,
                                        const COMMAND_PING::response& rsp,
                                        p2p_connection_context& /*context*/) {
                                    if (code <= 0) {
                                        log::warning(
                                                logcat,
                                                "{}Failed to invoke COMMAND_PING to {}({}, {})",
                                                ping_context,
                                                address.to_string(),
                                                code,
                                                epee::levin::get_err_descr(code));
                                        return;
                                    }

                                    auto& net_config = m_network.m_net_server.get_config_object();
                                    if (rsp.status != COMMAND_PING::OK_RESPONSE ||
                                        pr != rsp.peer_id) {
                                        log::warning(
                                                logcat,
                                                "{}{}\" from{}, hsh_peer_id={}, rsp.peer_id={}",
                                                ping_context,
                                                "back ping invoke wrong response \"",
                                                rsp.status,
                                                address.to_string(),
                                                pr_,
                                                peerid_to_string(rsp.peer_id));
                                        net_config.close(ping_context.m_connection_id);
                                        return;
                                    }
                                    net_config.close(ping_context.m_connection_id);
                                    cb();
                                });

                if (!inv_call_res) {
                    log::warning(
                            logcat,
                            "{}{}",
                            ping_context,
                            "back ping invoke failed to ",
                            address.to_string());
                    update_peer_failed_connection(peer_stats_map, peer_stats_map_mutex, context.peer_id);
                    net_config.close(ping_context.m_connection_id);
                    return false;
                }
                return true;
            },
            m_network.m_bind_ip);
    if (!r) {
        log::warning(logcat, "{}Failed to call connect_async, network error.", context);
    }
    return r;
}
//-----------------------------------------------------------------------------------
int node_server::handle_timed_sync(
        int command,
        typename COMMAND_TIMED_SYNC::request& arg,
        typename COMMAND_TIMED_SYNC::response& rsp,
        p2p_connection_context& context) {
    if (!m_payload_handler.process_payload_sync_data(std::move(arg.payload_data), context, false)) {
        log::warning(
                logcat, "{}Failed to process_payload_sync_data(), dropping connection", context);
        drop_connection(context);
        return 1;
    }

    // fill response
    std::vector<peerlist_entry> local_peerlist_new;
    m_network.m_peerlist.get_peerlist_head(
            local_peerlist_new, true, cryptonote::p2p::DEFAULT_PEERS_IN_HANDSHAKE);

    // only include out peers we did not already send
    rsp.local_peerlist_new.reserve(local_peerlist_new.size());
    for (auto& pe : local_peerlist_new) {
        if (!context.sent_addresses.insert(pe.adr).second)
            continue;
        rsp.local_peerlist_new.push_back(std::move(pe));
    }
    m_payload_handler.get_payload_sync_data(rsp.payload_data);

    log::debug(logcat, "{}COMMAND_TIMED_SYNC", context);
    return 1;
}
//-----------------------------------------------------------------------------------
int node_server::handle_handshake(
        int /*command*/,
        typename COMMAND_HANDSHAKE::request& arg,
        typename COMMAND_HANDSHAKE::response& rsp,
        p2p_connection_context& context) {
    if (arg.node_data.network_id != m_network_id) {

        log::info(
                logcat,
                "{}{}",
                context,
                "WRONG NETWORK AGENT CONNECTED! id=",
                boost::lexical_cast<std::string>(arg.node_data.network_id));
        drop_connection(context);
        add_host_fail(context.m_remote_address);
        return 1;
    }

    if (!context.m_is_income) {
        log::warning(logcat, "{}COMMAND_HANDSHAKE came not from incoming connection", context);
        drop_connection(context);
        add_host_fail(context.m_remote_address);
        return 1;
    }

    if (context.peer_id) {
        log::warning(
                logcat,
                "{}COMMAND_HANDSHAKE came, but seems that connection already have associated "
                "peer_id (double COMMAND_HANDSHAKE?)",
                context);
        drop_connection(context);
        return 1;
    }

    if (arg.node_data.peer_id == m_network.m_config.m_peer_id) {
        log::debug(logcat, "{}Connection to self detected, dropping connection", context);
        drop_connection(context);
        return 1;
    }

    if (m_network.m_current_number_of_in_peers >=
        m_network.m_config.m_net_config.max_in_connection_count)  // in peers limit
    {
        log::warning(
                logcat,
                "{}COMMAND_HANDSHAKE came, but already have max incoming connections, so dropping "
                "this one.",
                context);
        drop_connection(context);
        return 1;
    }

    if (!m_payload_handler.process_payload_sync_data(std::move(arg.payload_data), context, true)) {
        log::warning(
                logcat,
                "{}COMMAND_HANDSHAKE came, but process_payload_sync_data returned false, dropping "
                "connection.",
                context);
        drop_connection(context);
        return 1;
    }

    if (has_too_many_connections(context.m_remote_address)) {
        log::info(
                logcat,
                "CONNECTION FROM {} REFUSED, too many connections from the same address",
                context.m_remote_address.host());
        drop_connection(context);
        return 1;
    }

    // associate peer_id with this connection
    context.peer_id = arg.node_data.peer_id;
    context.m_in_timedsync = false;

    if (arg.node_data.my_port) {
        peerid_type peer_id_l = arg.node_data.peer_id;
        // try_ping only calls back after checking that this fits in a uint16_t
        auto port_l = static_cast<uint16_t>(arg.node_data.my_port);
        // try ping to be sure that we can add this peer to peer_list
        try_ping(arg.node_data, context, [peer_id_l, port_l, context, this]() {
            // called only(!) if success pinged, update local peerlist
            peerlist_entry pe;
            pe.adr = context.m_remote_address;
            pe.adr.set_port(port_l);
            time_t last_seen;
            time(&last_seen);
            pe.last_seen = static_cast<int64_t>(last_seen);
            pe.id = peer_id_l;
            pe.history = context.m_history;
            m_network.m_peerlist.append_with_peer_white(pe);
            log::debug(
                    logcat,
                    "{}PING SUCCESS {}:{}",
                    context,
                    context.m_remote_address.host(),
                    port_l);
        });
    }

    // fill response
    m_network.m_peerlist.get_peerlist_head(rsp.local_peerlist_new, true);
    for (const auto& e : rsp.local_peerlist_new)
        context.sent_addresses.insert(e.adr);
    get_local_node_data(rsp.node_data);
    m_payload_handler.get_payload_sync_data(rsp.payload_data);
    log::debug(logcat, "{}COMMAND_HANDSHAKE", context);
    return 1;
}
//-----------------------------------------------------------------------------------
int node_server::handle_ping(
        int /*command*/,
        COMMAND_PING::request& /*arg*/,
        COMMAND_PING::response& rsp,
        p2p_connection_context& context) {
    log::debug(logcat, "{}COMMAND_PING", context);
    rsp.status = COMMAND_PING::OK_RESPONSE;
    rsp.peer_id = m_network.m_config.m_peer_id;
    return 1;
}
//-----------------------------------------------------------------------------------
bool node_server::log_peerlist() {
    std::vector<peerlist_entry> pl_white;
    std::vector<peerlist_entry> pl_gray;
    m_network.m_peerlist.get_peerlist(pl_gray, pl_white);
    log::info(
            logcat,
            "\nPeerlist white:\n{}\nPeerlist gray:\n{}",
            print_peerlist_to_string(pl_white),
            print_peerlist_to_string(pl_gray));
    return true;
}
//-----------------------------------------------------------------------------------
bool node_server::log_connections() {
    log::info(logcat, "Connections: \r\n{}", print_connections_container());
    return true;
}
//-----------------------------------------------------------------------------------
std::string node_server::print_connections_container() {

    std::stringstream ss;
    m_network.m_net_server.get_config_object().foreach_connection(
            [&](const p2p_connection_context& cntxt) {
                ss << cntxt.m_remote_address.to_string() << " \t\tpeer_id "
                   << peerid_to_string(cntxt.peer_id) << " \t\tconn_id " << cntxt.m_connection_id
                   << (cntxt.m_is_income ? " INC" : " OUT") << std::endl;
                return true;
            });
    return ss.str();
}
//-----------------------------------------------------------------------------------
void node_server::on_connection_new(p2p_connection_context& context) {
    log::info(logcat, "[{}] NEW CONNECTION", epee::net_utils::print_connection_context(context));
}
//-----------------------------------------------------------------------------------
void node_server::on_connection_close(p2p_connection_context& context) {
    const auto connection_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - context.m_started).count();
    update_peer_stats(peer_stats_map, peer_stats_map_mutex, context.peer_id, connection_time);
    if (!m_network.m_net_server.is_stop_signal_sent() && !context.m_is_income)
        m_network.m_peerlist.remove_from_peer_anchor(context.m_remote_address);

    m_payload_handler.on_connection_close(context);

    log::info(logcat, "[{}] CLOSE CONNECTION", epee::net_utils::print_connection_context(context));
}

bool node_server::is_priority_node(
        const oxen::quic::Address& na) {
    return (std::find(m_priority_peers.begin(), m_priority_peers.end(), na) !=
            m_priority_peers.end()) ||
           (std::find(m_exclusive_peers.begin(), m_exclusive_peers.end(), na) !=
            m_exclusive_peers.end());
}

template <class Container>
void node_server::connect_to_peerlist(const Container& peers) {
    for (const oxen::quic::Address& na : peers) {
        if (get_outgoing_and_pending_count() >=
            m_network.m_config.m_net_config.max_out_connection_count)
            return;

        if (is_addr_connected(na))
            continue;

        connect_and_handshake(na, PeerType::white, false);
    }
}

template <class Container>
bool node_server::parse_peers_and_add_to_container(
        const boost::program_options::variables_map& vm,
        const command_line::arg_descriptor<std::vector<std::string>>& arg,
        Container& container) {
    std::vector<std::string> perrs = command_line::get_arg(vm, arg);

    const uint16_t default_port = cryptonote::get_config(m_nettype).P2P_DEFAULT_PORT;
    for (const std::string& pr_str : perrs) {
        expect<oxen::quic::Address> adr =
                net::get_network_address(pr_str, default_port);
        if (adr) {
            container.push_back(std::move(*adr));
            continue;
        }
        std::vector<oxen::quic::Address> resolved_addrs;
        bool r = append_net_address(resolved_addrs, pr_str, default_port);
        if (!r) {
            log::error(logcat, "Failed to parse or resolve address from string: {}", pr_str);
            return false;
        }
        for (const oxen::quic::Address& addr : resolved_addrs) {
            container.push_back(addr);
        }
    }

    return true;
}

bool node_server::set_max_out_peers(int64_t max) {
    if (max == -1)
        max = cryptonote::p2p::DEFAULT_CONNECTIONS_COUNT_OUT;
    m_network.m_config.m_net_config.max_out_connection_count = max;
    return true;
}

bool node_server::set_max_in_peers(int64_t max) {
    if (max == -1)
        max = cryptonote::p2p::DEFAULT_CONNECTIONS_COUNT_IN;
    m_network.m_config.m_net_config.max_in_connection_count = max;
    return true;
}

void node_server::change_max_out_public_peers(size_t count) {
    auto& net_config = m_network.m_net_server.get_config_object();
    const auto current = net_config.get_out_connections_count();
    m_network.m_config.m_net_config.max_out_connection_count = count;
    if (current > count)
        net_config.del_out_connections(current - count);
    m_payload_handler.set_max_out_peers(count);
}

uint32_t node_server::get_max_out_public_peers() const {
    return m_network.m_config.m_net_config.max_out_connection_count;
}

void node_server::change_max_in_public_peers(size_t count) {
    auto& net_config = m_network.m_net_server.get_config_object();
    const auto current = net_config.get_in_connections_count();
    m_network.m_config.m_net_config.max_in_connection_count = count;
    if (current > count)
        net_config.del_in_connections(current - count);
}

uint32_t node_server::get_max_in_public_peers() const {
    return m_network.m_config.m_net_config.max_in_connection_count;
}

bool node_server::set_tos_flag(
        const boost::program_options::variables_map& /*vm*/, int flag) {
    if (flag == -1) {
        return true;
    }
    epee::net_utils::connection<
            epee::levin::async_protocol_handler<p2p_connection_context>>::set_tos_flag(flag);
    log::debug(logcat, "Set ToS flag  {}", flag);
    return true;
}

bool node_server::set_rate_up_limit(
        const boost::program_options::variables_map& /*vm*/, int64_t limit) {
    this->islimitup = (limit != -1) && (limit != cryptonote::p2p::DEFAULT_LIMIT_RATE_UP);

    if (limit == -1) {
        limit = cryptonote::p2p::DEFAULT_LIMIT_RATE_UP;
    }

    epee::net_utils::connection<
            epee::levin::async_protocol_handler<p2p_connection_context>>::set_rate_up_limit(limit);
    log::info(logcat, "Set limit-up to {} kB/s", limit);
    return true;
}

bool node_server::set_rate_down_limit(
        const boost::program_options::variables_map& /*vm*/, int64_t limit) {
    this->islimitdown = (limit != -1) && (limit != cryptonote::p2p::DEFAULT_LIMIT_RATE_DOWN);
    if (limit == -1) {
        limit = cryptonote::p2p::DEFAULT_LIMIT_RATE_DOWN;
    }
    epee::net_utils::connection<epee::levin::async_protocol_handler<p2p_connection_context>>::
            set_rate_down_limit(limit);
    log::info(logcat, "Set limit-down to {} kB/s", limit);
    return true;
}

bool node_server::set_rate_limit(
        const boost::program_options::variables_map& /*vm*/, int64_t limit) {
    int64_t limit_up = 0;
    int64_t limit_down = 0;

    if (limit == -1) {
        limit_up = cryptonote::p2p::DEFAULT_LIMIT_RATE_UP;
        limit_down = cryptonote::p2p::DEFAULT_LIMIT_RATE_DOWN;
    } else {
        limit_up = limit;
        limit_down = limit;
    }
    if (!this->islimitup) {
        epee::net_utils::connection<epee::levin::async_protocol_handler<p2p_connection_context>>::
                set_rate_up_limit(limit_up);
        log::info(logcat, "Set limit-up to {} kB/s", limit_up);
    }
    if (!this->islimitdown) {
        epee::net_utils::connection<epee::levin::async_protocol_handler<p2p_connection_context>>::
                set_rate_down_limit(limit_down);
        log::info(logcat, "Set limit-down to {} kB/s", limit_down);
    }

    return true;
}

bool node_server::has_too_many_connections(
        const oxen::quic::Address& address) {
    const size_t max_connections = m_nettype == cryptonote::network_type::MAINNET ? 1 : 20;
    size_t count = 0;

    m_network.m_net_server.get_config_object().foreach_connection(
            [&](const p2p_connection_context& cntxt) {
                if (cntxt.m_is_income && net::same_host(cntxt.m_remote_address, address)) {
                    count++;

                    if (count > max_connections) {
                        return false;
                    }
                }

                return true;
            });

    return count > max_connections;
}

bool node_server::gray_peerlist_housekeeping() {
    if (m_offline)
        return true;
    if (!m_exclusive_peers.empty())
        return true;
    if (m_payload_handler.needs_new_sync_connections())
        return true;

    if (m_network.m_net_server.is_stop_signal_sent())
        return false;

    peerlist_entry pe{};
    if (!m_network.m_peerlist.get_random_gray_peer(pe))
        return true;

    connect_and_handshake(pe.adr, PeerType::gray, true, pe.last_seen, 0, [this, pe](bool success) {
        if (!success) {
            m_network.m_peerlist.remove_from_peer_gray(pe);
            log::debug(
                    logcat,
                    "PEER EVICTED FROM GRAY PEER LIST: address: {} Peer ID: {}",
                    pe.adr.host(),
                    peerid_to_string(pe.id));
        } else {
            m_network.m_peerlist.set_peer_just_seen(pe.id, pe.adr, pe.history);
            log::debug(
                    logcat,
                    "PEER PROMOTED TO WHITE PEER LIST IP address: {} Peer ID: {}",
                    pe.adr.host(),
                    peerid_to_string(pe.id));
        }
    });
    return true;
}

}  // namespace nodetool
