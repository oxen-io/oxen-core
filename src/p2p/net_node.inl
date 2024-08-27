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
#include <boost/uuid/uuid_io.hpp>
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
#include "common/pruning.h"
#include "common/string_util.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/connection_context.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_core.h"
#include "epee/misc_log_ex.h"
#include "epee/net/local_ip.h"
#include "epee/storages/levin_abstract_invoke2.h"
#include "epee/string_tools.h"
#include "net/error.h"
#include "net/parse.h"
#include "net_node.h"
#include "p2p_protocol_defs.h"
#include "version.h"

#define NET_MAKE_IP(b1, b2, b3, b4) \
    ((LPARAM)(((DWORD)(b1) << 24) + ((DWORD)(b2) << 16) + ((DWORD)(b3) << 8) + ((DWORD)(b4))))

#define MIN_WANTED_SEED_NODES 12

namespace nodetool {
static auto logcat = log::Cat("net.p2p");

template <class t_payload_net_handler>
node_server<t_payload_net_handler>::~node_server() {
    // tcp server uses io_service in destructor, and every zone uses
    // io_service from public zone.
    for (auto current = m_network_zones.begin(); current != m_network_zones.end(); /* below */) {
        if (current->first != epee::net_utils::zone::public_)
            current = m_network_zones.erase(current);
        else
            ++current;
    }
}
//-----------------------------------------------------------------------------------
inline bool append_net_address(
        std::vector<epee::net_utils::network_address>& seed_nodes,
        std::string const& addr,
        uint16_t default_port);
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
void node_server<t_payload_net_handler>::init_options(
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
    command_line::add_arg(desc, arg_tx_proxy);
    command_line::add_arg(desc, arg_anonymous_inbound);
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

template <class t_payload_net_handler>
fs::path node_server<t_payload_net_handler>::get_peerlist_file() const {
    fs::path p2p_filename = cryptonote::P2P_NET_DATA_FILENAME;
    if (m_nettype == cryptonote::network_type::STAGENET)
        // Kludge for stagenet reboot
        p2p_filename += u8".v2";
    return m_config_folder / p2p_filename;
}

//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::init_config() {
    TRY_ENTRY();
    auto storage = peerlist_storage::open(get_peerlist_file());
    if (storage)
        m_peerlist_storage = std::move(*storage);

    m_first_connection_maker_call = true;

    CATCH_ENTRY("node_server::init_config", false);
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
void node_server<t_payload_net_handler>::for_each_connection(
        std::function<bool(typename t_payload_net_handler::connection_context&, peerid_type)> f) {
    for (auto& zone : m_network_zones) {
        zone.second.m_net_server.get_config_object().foreach_connection(
                [&](p2p_connection_context& cntx) { return f(cntx, cntx.peer_id); });
    }
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::for_connection(
        const boost::uuids::uuid& connection_id,
        std::function<bool(typename t_payload_net_handler::connection_context&, peerid_type)> f) {
    for (auto& zone : m_network_zones) {
        const bool result = zone.second.m_net_server.get_config_object().for_connection(
                connection_id, [&](p2p_connection_context& cntx) { return f(cntx, cntx.peer_id); });
        if (result)
            return true;
    }
    return false;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::is_remote_host_allowed(
        const epee::net_utils::network_address& address, time_t* t) {
    std::unique_lock lock{m_blocked_hosts_lock};

    const time_t now = time(nullptr);

    // look in the hosts list
    auto it = m_blocked_hosts.find(address.host_str());
    if (it != m_blocked_hosts.end()) {
        if (now >= it->second) {
            m_blocked_hosts.erase(it);
            log::info(
                    logcat,
                    fg(fmt::terminal_color::cyan),
                    "Host {} unblocked.",
                    address.host_str());
            it = m_blocked_hosts.end();
        } else {
            if (t)
                *t = it->second - now;
            return false;
        }
    }

    // manually loop in subnets
    if (address.get_type_id() == epee::net_utils::address_type::ipv4) {
        auto ipv4_address = address.template as<epee::net_utils::ipv4_network_address>();
        std::map<epee::net_utils::ipv4_network_subnet, time_t>::iterator it;
        for (it = m_blocked_subnets.begin(); it != m_blocked_subnets.end();) {
            if (now >= it->second) {
                it = m_blocked_subnets.erase(it);
                log::info(
                        logcat,
                        fg(fmt::terminal_color::cyan),
                        "Subnet {} unblocked",
                        it->first.host_str());
                continue;
            }
            if (it->first.matches(ipv4_address)) {
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
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::block_host(
        const epee::net_utils::network_address& addr, time_t seconds) {
    if (!addr.is_blockable())
        return false;

    const time_t now = time(nullptr);

    std::unique_lock lock{m_blocked_hosts_lock};
    time_t limit;
    if (now > std::numeric_limits<time_t>::max() - seconds)
        limit = std::numeric_limits<time_t>::max();
    else
        limit = now + seconds;
    m_blocked_hosts[addr.host_str()] = limit;

    // drop any connection to that address. This should only have to look into
    // the zone related to the connection, but really make sure everything is
    // swept ...
    std::vector<boost::uuids::uuid> conns;
    for (auto& zone : m_network_zones) {
        zone.second.m_net_server.get_config_object().foreach_connection(
                [&](const p2p_connection_context& cntxt) {
                    if (cntxt.m_remote_address.is_same_host(addr)) {
                        conns.push_back(cntxt.m_connection_id);
                    }
                    return true;
                });
        for (const auto& c : conns)
            zone.second.m_net_server.get_config_object().close(c);

        conns.clear();
    }

    log::info(logcat, fg(fmt::terminal_color::cyan), "Host {} blocked", addr.host_str());
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::unblock_host(
        const epee::net_utils::network_address& address) {
    std::unique_lock lock{m_blocked_hosts_lock};
    auto i = m_blocked_hosts.find(address.host_str());
    if (i == m_blocked_hosts.end())
        return false;
    m_blocked_hosts.erase(i);
    log::info(logcat, fg(fmt::terminal_color::cyan), "Host {} unblocked", address.host_str());
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::block_subnet(
        const epee::net_utils::ipv4_network_subnet& subnet, time_t seconds) {
    const time_t now = time(nullptr);

    std::unique_lock lock{m_blocked_hosts_lock};
    time_t limit;
    if (now > std::numeric_limits<time_t>::max() - seconds)
        limit = std::numeric_limits<time_t>::max();
    else
        limit = now + seconds;
    m_blocked_subnets[subnet] = limit;

    // drop any connection to that subnet. This should only have to look into
    // the zone related to the connection, but really make sure everything is
    // swept ...
    std::vector<boost::uuids::uuid> conns;
    for (auto& zone : m_network_zones) {
        zone.second.m_net_server.get_config_object().foreach_connection(
                [&](const p2p_connection_context& cntxt) {
                    if (cntxt.m_remote_address.get_type_id() !=
                        epee::net_utils::ipv4_network_address::get_type_id())
                        return true;
                    auto ipv4_address =
                            cntxt.m_remote_address
                                    .template as<epee::net_utils::ipv4_network_address>();
                    if (subnet.matches(ipv4_address)) {
                        conns.push_back(cntxt.m_connection_id);
                    }
                    return true;
                });
        for (const auto& c : conns)
            zone.second.m_net_server.get_config_object().close(c);

        conns.clear();
    }

    log::info(logcat, fg(fmt::terminal_color::cyan), "Subnet {} blocked.", subnet.host_str());
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::unblock_subnet(
        const epee::net_utils::ipv4_network_subnet& subnet) {
    std::unique_lock lock{m_blocked_hosts_lock};
    auto i = m_blocked_subnets.find(subnet);
    if (i == m_blocked_subnets.end())
        return false;
    m_blocked_subnets.erase(i);
    log::info(logcat, fg(fmt::terminal_color::cyan), "Subnet {}", subnet.host_str());
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::add_host_fail(
        const epee::net_utils::network_address& address) {
    if (!address.is_blockable())
        return false;

    std::lock_guard lock{m_host_fails_score_lock};
    uint64_t fails = ++m_host_fails_score[address.host_str()];
    log::debug(logcat, "Host {} fail score={}", address.host_str(), fails);
    if (fails > cryptonote::p2p::IP_FAILS_BEFORE_BLOCK) {
        auto it = m_host_fails_score.find(address.host_str());
        CHECK_AND_ASSERT_MES(it != m_host_fails_score.end(), false, "internal error");
        it->second = cryptonote::p2p::IP_FAILS_BEFORE_BLOCK / 2;
        block_host(address);
    }
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::handle_command_line(
        const boost::program_options::variables_map& vm) {

    m_nettype = command_line::get_network(vm);

    network_zone& public_zone = m_network_zones[epee::net_utils::zone::public_];
    public_zone.m_connect = &public_connect;
    public_zone.m_bind_ip = command_line::get_arg(vm, arg_p2p_bind_ip);
    public_zone.m_bind_ipv6_address = command_line::get_arg(vm, arg_p2p_bind_ipv6_address);
    public_zone.m_port = "{}"_format(command_line::get_arg(vm, arg_p2p_bind_port));
    public_zone.m_port_ipv6 = "{}"_format(command_line::get_arg(vm, arg_p2p_bind_port_ipv6));
    public_zone.m_can_pingback = true;
    m_external_port = command_line::get_arg(vm, arg_p2p_external_port);
    m_allow_local_ip = command_line::get_arg(vm, arg_p2p_allow_local_ip);
    m_offline = command_line::get_arg(vm, cryptonote::arg_offline);
    m_use_ipv6 = command_line::get_arg(vm, arg_p2p_use_ipv6);
    m_require_ipv4 = !command_line::get_arg(vm, arg_p2p_ignore_ipv4);
    public_zone.m_notifier = cryptonote::levin::notify{
            public_zone.m_net_server.get_io_service(),
            public_zone.m_net_server.get_config_shared(),
            {},
            true};

    if (command_line::has_arg(vm, arg_p2p_add_peer)) {
        std::vector<std::string> perrs = command_line::get_arg(vm, arg_p2p_add_peer);
        for (const std::string& pr_str : perrs) {
            nodetool::peerlist_entry pe{};
            pe.id = crypto::rand<uint64_t>();
            const uint16_t default_port = cryptonote::get_config(m_nettype).P2P_DEFAULT_PORT;
            expect<epee::net_utils::network_address> adr =
                    net::get_network_address(pr_str, default_port);
            if (adr) {
                add_zone(adr->get_zone());
                pe.adr = std::move(*adr);
                m_command_line_peers.push_back(std::move(pe));
                continue;
            }
            CHECK_AND_ASSERT_MES(
                    adr == net::error::unsupported_address,
                    false,
                    "Bad address (\"{}\"): {}",
                    pr_str,
                    adr.error().message());

            std::vector<epee::net_utils::network_address> resolved_addrs;
            bool r = append_net_address(resolved_addrs, pr_str, default_port);
            CHECK_AND_ASSERT_MES(
                    r, false, "Failed to parse or resolve address from string: {}", pr_str);
            for (const epee::net_utils::network_address& addr : resolved_addrs) {
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

    if (!set_max_out_peers(public_zone, command_line::get_arg(vm, arg_out_peers)))
        return false;
    else
        m_payload_handler.set_max_out_peers(
                public_zone.m_config.m_net_config.max_out_connection_count);

    if (!set_max_in_peers(public_zone, command_line::get_arg(vm, arg_in_peers)))
        return false;

    if (!set_tos_flag(vm, command_line::get_arg(vm, arg_tos_flag)))
        return false;

    if (!set_rate_up_limit(vm, command_line::get_arg(vm, arg_limit_rate_up)))
        return false;

    if (!set_rate_down_limit(vm, command_line::get_arg(vm, arg_limit_rate_down)))
        return false;

    if (!set_rate_limit(vm, command_line::get_arg(vm, arg_limit_rate)))
        return false;

    epee::shared_sv noise;
    auto proxies = get_proxies(vm);
    if (!proxies)
        return false;

    for (auto& proxy : *proxies) {
        network_zone& zone = add_zone(proxy.zone);
        if (zone.m_connect != nullptr) {
            log::error(logcat, "Listed --{} twice", arg_tx_proxy.name);
            return false;
        }
        zone.m_connect = &socks_connect;
        zone.m_proxy_address = std::move(proxy.address);

        if (!set_max_out_peers(zone, proxy.max_connections))
            return false;

        epee::shared_sv this_noise;
        if (proxy.noise) {
            static_assert(
                    sizeof(epee::levin::bucket_head2) < cryptonote::NOISE_BYTES,
                    "noise bytes too small");
            if (noise.view.empty())
                noise = epee::shared_sv{epee::levin::make_noise_notify(cryptonote::NOISE_BYTES)};

            this_noise = noise;
        }

        zone.m_notifier = cryptonote::levin::notify{
                zone.m_net_server.get_io_service(),
                zone.m_net_server.get_config_shared(),
                std::move(this_noise),
                false};
    }

    for (const auto& zone : m_network_zones) {
        if (zone.second.m_connect == nullptr) {
            log::error(
                    logcat, "Set outgoing peer for zone but did not set --{}", arg_tx_proxy.name);
            return false;
        }
    }

    auto inbounds = get_anonymous_inbounds(vm);
    if (!inbounds)
        return false;

    const std::size_t tx_relay_zones = m_network_zones.size();
    for (auto& inbound : *inbounds) {
        network_zone& zone = add_zone(inbound.our_address.get_zone());

        if (!zone.m_bind_ip.empty()) {
            log::error(logcat, "Listed--{} twice", arg_anonymous_inbound.name);
            return false;
        }

        if (zone.m_connect == nullptr && tx_relay_zones <= 1) {
            log::error(
                    logcat,
                    "Listed --{} without listing any --{}. The latter is necessary for sending "
                    "local txes over anonymity networks",
                    arg_anonymous_inbound.name,
                    arg_tx_proxy.name);
            return false;
        }

        zone.m_bind_ip = std::move(inbound.local_ip);
        zone.m_port = std::move(inbound.local_port);
        zone.m_net_server.set_default_remote(std::move(inbound.default_remote));
        zone.m_our_address = std::move(inbound.our_address);

        if (!set_max_in_peers(zone, inbound.max_connections))
            return false;
    }

    return true;
}
//-----------------------------------------------------------------------------------
inline bool append_net_address(
        std::vector<epee::net_utils::network_address>& seed_nodes,
        std::string const& addr,
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
    ip::tcp::resolver::query query(
            host, port, boost::asio::ip::tcp::resolver::query::canonical_name);
    boost::system::error_code ec;
    ip::tcp::resolver::iterator i = resolver.resolve(query, ec);
    CHECK_AND_ASSERT_MES(
            !ec, false, "Failed to resolve host name '{}': {}:{}", host, ec.message(), ec.value());

    ip::tcp::resolver::iterator iend;
    for (; i != iend; ++i) {
        ip::tcp::endpoint endpoint = *i;
        if (endpoint.address().is_v4()) {
            epee::net_utils::network_address na{epee::net_utils::ipv4_network_address{
                    boost::asio::detail::socket_ops::host_to_network_long(
                            endpoint.address().to_v4().to_ulong()),
                    endpoint.port()}};
            seed_nodes.push_back(na);
            log::info(logcat, "Added node: {}", na.str());
        } else {
            epee::net_utils::network_address na{epee::net_utils::ipv6_network_address{
                    endpoint.address().to_v6(), endpoint.port()}};
            seed_nodes.push_back(na);
            log::info(logcat, "Added node: {}", na.str());
        }
    }
    return true;
}

//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
std::set<std::string> node_server<t_payload_net_handler>::get_seed_nodes(
        cryptonote::network_type nettype) const {
    std::set<std::string> full_addrs;
    if (nettype == cryptonote::network_type::TESTNET) {
        full_addrs.insert("144.76.164.202:38156");  // public-eu.optf.ngo
    } else if (nettype == cryptonote::network_type::DEVNET) {
        full_addrs.insert("144.76.164.202:38856");
    } else if (nettype == cryptonote::network_type::STAGENET) {
        full_addrs.insert("104.243.40.38:11218");  // angus.oxen.io
    } else if (nettype == cryptonote::network_type::MAINNET) {
        full_addrs.insert("116.203.196.12:22022");  // Hetzner seed node
        full_addrs.insert("185.150.191.32:22022");  // Jason's seed node
        full_addrs.insert("199.127.60.6:22022");    // Oxen Foundation server "holstein"
        full_addrs.insert("23.88.6.250:22022");     // Official Session open group server
        full_addrs.insert("104.194.8.115:22000");   // Oxen Foundation server "brahman"
    }
    // LOCALDEV and FAKECHAIN don't have seed nodes
    return full_addrs;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
std::set<std::string> node_server<t_payload_net_handler>::get_seed_nodes() {
    if (!m_exclusive_peers.empty() || m_offline)
        return {};
    return get_seed_nodes(m_nettype);
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
typename node_server<t_payload_net_handler>::network_zone&
node_server<t_payload_net_handler>::add_zone(const epee::net_utils::zone zone) {
    const auto zone_ = m_network_zones.lower_bound(zone);
    if (zone_ != m_network_zones.end() && zone_->first == zone)
        return zone_->second;

    network_zone& public_zone = m_network_zones[epee::net_utils::zone::public_];
    return m_network_zones
            .emplace_hint(
                    zone_,
                    std::piecewise_construct,
                    std::make_tuple(zone),
                    std::tie(public_zone.m_net_server.get_io_service()))
            ->second;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::init(const boost::program_options::variables_map& vm) {
    bool res = handle_command_line(vm);
    CHECK_AND_ASSERT_MES(res, false, "Failed to handle command line");

    memcpy(&m_network_id, &get_config(m_nettype).NETWORK_ID, 16);

    m_config_folder = fs::path{
            tools::convert_sv<char8_t>(command_line::get_arg(vm, cryptonote::arg_data_dir))};
    network_zone& public_zone = m_network_zones.at(epee::net_utils::zone::public_);

    if (public_zone.m_port != std::to_string(cryptonote::get_config(m_nettype).P2P_DEFAULT_PORT))
        m_config_folder /= public_zone.m_port;

    res = init_config();
    CHECK_AND_ASSERT_MES(res, false, "Failed to init config.");

    for (auto& zone : m_network_zones) {
        res = zone.second.m_peerlist.init(
                m_peerlist_storage.take_zone(zone.first), m_allow_local_ip);
        CHECK_AND_ASSERT_MES(res, false, "Failed to init peerlist.");
    }

    for (const auto& p : m_command_line_peers)
        m_network_zones.at(p.adr.get_zone()).m_peerlist.append_with_peer_white(p);

    // all peers are now setup
    if constexpr (cryptonote::PRUNING_DEBUG_SPOOF_SEED) {
        for (auto& zone : m_network_zones) {
            std::list<peerlist_entry> plw;
            while (zone.second.m_peerlist.get_white_peers_count()) {
                plw.push_back(peerlist_entry());
                zone.second.m_peerlist.get_white_peer_by_index(plw.back(), 0);
                zone.second.m_peerlist.remove_from_peer_white(plw.back());
            }
            for (auto& e : plw)
                zone.second.m_peerlist.append_with_peer_white(e);

            std::list<peerlist_entry> plg;
            while (zone.second.m_peerlist.get_gray_peers_count()) {
                plg.push_back(peerlist_entry());
                zone.second.m_peerlist.get_gray_peer_by_index(plg.back(), 0);
                zone.second.m_peerlist.remove_from_peer_gray(plg.back());
            }
            for (auto& e : plg)
                zone.second.m_peerlist.append_with_peer_gray(e);
        }
    }

    // only in case if we really sure that we have external visible ip
    m_have_address = true;

    // configure self

    public_zone.m_net_server.set_threads_prefix(
            "P2P");  // all zones use these threads/asio::io_service

    // from here onwards, it's online stuff
    if (m_offline)
        return res;

    // try to bind
    for (auto& zone : m_network_zones) {
        zone.second.m_net_server.get_config_object().set_handler(this);
        zone.second.m_net_server.get_config_object().m_invoke_timeout =
                std::chrono::milliseconds{cryptonote::p2p::DEFAULT_INVOKE_TIMEOUT};

        if (!zone.second.m_bind_ip.empty()) {
            std::string ipv6_addr = "";
            std::string ipv6_port = "";
            zone.second.m_net_server.set_connection_filter(this);
            log::info(logcat, "Binding (IPv4) on {}:{}", zone.second.m_bind_ip, zone.second.m_port);
            if (!zone.second.m_bind_ipv6_address.empty() && m_use_ipv6) {
                ipv6_addr = zone.second.m_bind_ipv6_address;
                ipv6_port = zone.second.m_port_ipv6;
                log::info(
                        logcat,
                        "Binding (IPv6) on {}:{}",
                        zone.second.m_bind_ipv6_address,
                        zone.second.m_port_ipv6);
            }
            try {
                res = zone.second.m_net_server.init_server(
                        zone.second.m_port,
                        zone.second.m_bind_ip,
                        ipv6_port,
                        ipv6_addr,
                        m_use_ipv6,
                        m_require_ipv4);
                CHECK_AND_ASSERT_MES(res, false, "Failed to bind server");
            } catch (const std::exception& e) {
                log::error(logcat, "{}", e.what());
                res = false;
            }
        }
    }

    m_listening_port = public_zone.m_net_server.get_binded_port();
    log::info(
            logcat,
            fg(fmt::terminal_color::green),
            "Net service bound (IPv4) to {}:{}",
            public_zone.m_bind_ip,
            m_listening_port);
    if (m_use_ipv6) {
        m_listening_port_ipv6 = public_zone.m_net_server.get_binded_port_ipv6();
        log::info(
                logcat,
                fg(fmt::terminal_color::green),
                "Net service bound (IPv6) to {}:{}",
                public_zone.m_bind_ipv6_address,
                m_listening_port_ipv6);
    }
    if (m_external_port)
        log::debug(logcat, "External port defined as {}", m_external_port);

    return res;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
typename node_server<t_payload_net_handler>::payload_net_handler&
node_server<t_payload_net_handler>::get_payload_object() {
    return m_payload_handler;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::run() {
    // creating thread to log number of connections
    mPeersLoggerThread.emplace([&]() {
        log::debug(logcat, "Thread monitor number of peers - start");
        const network_zone& public_zone = m_network_zones.at(epee::net_utils::zone::public_);
        while (!is_closing &&
               !public_zone.m_net_server.is_stop_signal_sent()) {  // main loop of thread
            // number_of_peers = m_net_server.get_config_object().get_connections_count();
            for (auto& zone : m_network_zones) {
                unsigned int number_of_in_peers = 0;
                unsigned int number_of_out_peers = 0;
                zone.second.m_net_server.get_config_object().foreach_connection(
                        [&](const p2p_connection_context& cntxt) {
                            if (cntxt.m_is_income) {
                                ++number_of_in_peers;
                            } else {
                                // If this is a new (<10s) connection and we're still in before
                                // handshake mode then don't count it yet: it is probably a back
                                // ping connection that will be closed soon.
                                if (!(cntxt.m_state ==
                                              p2p_connection_context::state_before_handshake &&
                                      std::chrono::steady_clock::now() < cntxt.m_started + 10s))
                                    ++number_of_out_peers;
                            }
                            return true;
                        });  // lambda
                zone.second.m_current_number_of_in_peers = number_of_in_peers;
                zone.second.m_current_number_of_out_peers = number_of_out_peers;
            }
            std::this_thread::sleep_for(1s);
        }  // main loop of thread
        log::debug(logcat, "Thread monitor number of peers - done");
    });  // lambda

    network_zone& public_zone = m_network_zones.at(epee::net_utils::zone::public_);
    public_zone.m_net_server.add_idle_handler([this] { return idle_worker(); }, 1s);
    public_zone.m_net_server.add_idle_handler([this] { return m_payload_handler.on_idle(); }, 1s);

    // here you can set worker threads count
    int thrds_count = 10;
    // go to loop
    log::info(logcat, "Run net_service loop( {} threads)...", thrds_count);
    if (!public_zone.m_net_server.run_server(thrds_count, true)) {
        log::error(logcat, "Failed to run net tcp server!");
    }

    log::info(logcat, "net_service loop stopped.");
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
uint64_t node_server<t_payload_net_handler>::get_public_connections_count() {
    auto public_zone = m_network_zones.find(epee::net_utils::zone::public_);
    if (public_zone == m_network_zones.end())
        return 0;
    return public_zone->second.m_net_server.get_config_object().get_connections_count();
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::deinit() {
    kill();

    if (!m_offline) {
        for (auto& zone : m_network_zones)
            zone.second.m_net_server.deinit_server();
    }
    return store_config();
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::store_config() {
    TRY_ENTRY();

    std::error_code ec;
    if (fs::create_directories(m_config_folder); ec) {
        log::warning(logcat, "Failed to create data directory {}", m_config_folder);
        return false;
    }

    peerlist_types active{};
    for (auto& zone : m_network_zones)
        zone.second.m_peerlist.get_peerlist(active);

    const auto state_file_path = get_peerlist_file();
    if (!m_peerlist_storage.store(state_file_path, active)) {
        log::warning(logcat, "Failed to save config to file {}", state_file_path);
        return false;
    }
    CATCH_ENTRY("node_server::store", false);
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::send_stop_signal() {
    log::debug(logcat, "[node] sending stop signal");
    for (auto& zone : m_network_zones)
        zone.second.m_net_server.send_stop_signal();
    log::debug(logcat, "[node] Stop signal sent");

    for (auto& zone : m_network_zones) {
        std::list<boost::uuids::uuid> connection_ids;
        zone.second.m_net_server.get_config_object().foreach_connection(
                [&](const p2p_connection_context& cntxt) {
                    connection_ids.push_back(cntxt.m_connection_id);
                    return true;
                });
        for (const auto& connection_id : connection_ids)
            zone.second.m_net_server.get_config_object().close(connection_id);
    }
    m_payload_handler.stop();
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::do_handshake_with_peer(
        peerid_type& pi, p2p_connection_context& context_, bool just_take_peerlist) {
    network_zone& zone = m_network_zones.at(context_.m_remote_address.get_zone());

    using request_t = typename COMMAND_HANDSHAKE::request;
    using response_t = typename COMMAND_HANDSHAKE::response;

    request_t arg{};
    response_t rsp{};
    get_local_node_data(arg.node_data, zone);
    m_payload_handler.get_payload_sync_data(arg.payload_data);

    std::promise<void> ev;
    std::atomic<bool> hsh_result(false);
    bool timeout = false;

    bool r = epee::net_utils::async_invoke_remote_command2<response_t>(
            context_.m_connection_id,
            COMMAND_HANDSHAKE::ID,
            arg,
            zone.m_net_server.get_config_object(),
            [this, &pi, &ev, &hsh_result, &just_take_peerlist, &context_, &timeout](
                    int code, response_t&& rsp, p2p_connection_context& context) {
                OXEN_DEFER {
                    ev.set_value();
                };

                if (code < 0) {
                    log::warning(
                            logcat,
                            "{}COMMAND_HANDSHAKE invoke failed. ({},{})",
                            context,
                            code,
                            epee::levin::get_err_descr(code));
                    if (code == LEVIN_ERROR_CONNECTION_TIMEDOUT ||
                        code == LEVIN_ERROR_CONNECTION_DESTROYED)
                        timeout = true;
                    return;
                }

                if (rsp.node_data.network_id != m_network_id) {
                    log::warning(
                            logcat,
                            "{}COMMAND_HANDSHAKE Failed, wrong network! ({}), closing connection.",
                            context,
                            boost::lexical_cast<std::string>(rsp.node_data.network_id));
                    return;
                }

                if (!handle_remote_peerlist(rsp.local_peerlist_new, context)) {
                    log::warning(
                            logcat,
                            "{}COMMAND_HANDSHAKE: failed to handle_remote_peerlist(...), closing "
                            "connection.",
                            context);
                    add_host_fail(context.m_remote_address);
                    return;
                }
                hsh_result = true;
                if (!just_take_peerlist) {
                    if (!m_payload_handler.process_payload_sync_data(
                                std::move(rsp.payload_data), context, true)) {
                        log::warning(
                                logcat,
                                "{}COMMAND_HANDSHAKE invoked, but process_payload_sync_data "
                                "returned false, dropping connection.",
                                context);
                        hsh_result = false;
                        return;
                    }

                    pi = context.peer_id = rsp.node_data.peer_id;
                    network_zone& zone = m_network_zones.at(context.m_remote_address.get_zone());
                    zone.m_peerlist.set_peer_just_seen(
                            rsp.node_data.peer_id,
                            context.m_remote_address,
                            context.m_pruning_seed);

                    // move
                    if (rsp.node_data.peer_id == zone.m_config.m_peer_id) {
                        log::debug(
                                logcat,
                                "{}Connection to self detected, dropping connection",
                                context);
                        hsh_result = false;
                        return;
                    }
                    log::info(
                            logcat,
                            "{}New connection handshaked, pruning seed {}",
                            context,
                            epee::string_tools::to_string_hex(context.m_pruning_seed));
                    log::debug(logcat, "{} COMMAND_HANDSHAKE INVOKED OK", context);
                } else {
                    log::debug(logcat, "{} COMMAND_HANDSHAKE(AND CLOSE) INVOKED OK", context);
                }
                context_ = context;
            },
            std::chrono::milliseconds{cryptonote::p2p::DEFAULT_HANDSHAKE_INVOKE_TIMEOUT});

    if (r) {
        ev.get_future().wait();
    }

    if (!hsh_result) {
        log::warning(logcat, "{}COMMAND_HANDSHAKE Failed", context_);
        if (!timeout)
            zone.m_net_server.get_config_object().close(context_.m_connection_id);
    }

    return hsh_result;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::do_peer_timed_sync(
        const epee::net_utils::connection_context_base& context_, peerid_type /*peer_id*/) {
    using request_t = typename COMMAND_TIMED_SYNC::request;
    using response_t = typename COMMAND_TIMED_SYNC::response;
    request_t arg{};
    m_payload_handler.get_payload_sync_data(arg.payload_data);

    network_zone& zone = m_network_zones.at(context_.m_remote_address.get_zone());
    bool r = epee::net_utils::async_invoke_remote_command2<response_t>(
            context_.m_connection_id,
            COMMAND_TIMED_SYNC::ID,
            arg,
            zone.m_net_server.get_config_object(),
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
                    m_network_zones.at(context.m_remote_address.get_zone())
                            .m_net_server.get_config_object()
                            .close(context.m_connection_id);
                    add_host_fail(context.m_remote_address);
                }
                if (!context.m_is_income)
                    m_network_zones.at(context.m_remote_address.get_zone())
                            .m_peerlist.set_peer_just_seen(
                                    context.peer_id,
                                    context.m_remote_address,
                                    context.m_pruning_seed);
                if (!m_payload_handler.process_payload_sync_data(
                            std::move(rsp.payload_data), context, false)) {
                    m_network_zones.at(context.m_remote_address.get_zone())
                            .m_net_server.get_config_object()
                            .close(context.m_connection_id);
                }
            });

    if (!r) {
        log::warning(logcat, "{}COMMAND_TIMED_SYNC Failed", context_);
        return false;
    }
    return true;
}

//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
size_t node_server<t_payload_net_handler>::get_random_exp_index(const size_t size, const double rate) {
    if (size <= 1)
        return 0;

    // (See net_node.h)

    crypto::random_device rng;
    const double u = std::uniform_real_distribution{}(rng);
    // For non-truncated exponential we could use: -1/rate * log(1-u), (or
    // std::exponential_distribution) but then we'd have to repeat until we got a value < size,
    // which is technically unbounded computational time.  Instead we mutate the calculation like
    // this, which gives us exponential, but truncated to [0, size), without looping:
    const size_t res = static_cast<size_t>(
            -1.0 / rate * std::log(1.0 - u * (1.0 - std::exp(-rate * size))));

    log::debug(logcat, "Random connection index={} (size={})", res, size);
    return res;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::is_peer_used(const peerlist_entry& peer) {
    for (const auto& zone : m_network_zones)
        if (zone.second.m_config.m_peer_id == peer.id)
            return true;  // dont make connections to ourself

    bool used = false;
    for (auto& zone : m_network_zones) {
        zone.second.m_net_server.get_config_object().foreach_connection(
                [&](const p2p_connection_context& cntxt) {
                    if (cntxt.peer_id == peer.id ||
                        (!cntxt.m_is_income && peer.adr == cntxt.m_remote_address)) {
                        used = true;
                        return false;  // stop enumerating
                    }
                    return true;
                });

        if (used)
            return true;
    }
    return false;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::is_peer_used(const anchor_peerlist_entry& peer) {
    for (auto& zone : m_network_zones) {
        if (zone.second.m_config.m_peer_id == peer.id) {
            return true;  // dont make connections to ourself
        }
        bool used = false;
        zone.second.m_net_server.get_config_object().foreach_connection(
                [&](const p2p_connection_context& cntxt) {
                    if (cntxt.peer_id == peer.id ||
                        (!cntxt.m_is_income && peer.adr == cntxt.m_remote_address)) {
                        used = true;
                        return false;  // stop enumerating
                    }
                    return true;
                });
        if (used)
            return true;
    }
    return false;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::is_addr_connected(
        const epee::net_utils::network_address& peer) {
    const auto zone = m_network_zones.find(peer.get_zone());
    if (zone == m_network_zones.end())
        return false;

    bool connected = false;
    zone->second.m_net_server.get_config_object().foreach_connection(
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

template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::try_to_connect_and_handshake_with_new_peer(
        const epee::net_utils::network_address& na,
        bool just_take_peerlist,
        uint64_t last_seen_stamp,
        PeerType peer_type,
        uint64_t first_seen_stamp) {
    network_zone& zone = m_network_zones.at(na.get_zone());
    if (zone.m_connect == nullptr)  // outgoing connections in zone not possible
        return false;

    if (zone.m_current_number_of_out_peers ==
        zone.m_config.m_net_config.max_out_connection_count)  // out peers limit
    {
        return false;
    } else if (
            zone.m_current_number_of_out_peers >
            zone.m_config.m_net_config.max_out_connection_count) {
        zone.m_net_server.get_config_object().del_out_connections(1);
        --(zone.m_current_number_of_out_peers);  // atomic variable, update time = 1s
        return false;
    }

    log::debug(
            logcat,
            "Connecting to {}(peer_type={}, last_seen: {})...",
            na.str(),
            peer_type,
            format_stamp_ago(last_seen_stamp));

    auto con = zone.m_connect(zone, na);
    if (!con) {
        if (is_priority_node(na))
            log::info(logcat, "[priority] Connect failed to {}", na.str());
        else
            log::info(logcat, "Connect failed to {}", na.str());
        record_addr_failed(na);
        return false;
    }

    con->m_anchor = peer_type == PeerType::anchor;
    peerid_type pi{};
    bool res = do_handshake_with_peer(pi, *con, just_take_peerlist);

    if (!res) {
        if (is_priority_node(na))
            log::info(logcat, "{}[priority] Failed to HANDSHAKE with peer {}", *con, na.str());
        else
            log::info(logcat, "{} Failed to HANDSHAKE with peer {}", *con, na.str());
        record_addr_failed(na);
        return false;
    }

    if (just_take_peerlist) {
        zone.m_net_server.get_config_object().close(con->m_connection_id);
        log::debug(logcat, "{}CONNECTION HANDSHAKED OK AND CLOSED.", *con);
        return true;
    }

    peerlist_entry pe_local{};
    pe_local.adr = na;
    pe_local.id = pi;
    time_t last_seen;
    time(&last_seen);
    pe_local.last_seen = static_cast<int64_t>(last_seen);
    pe_local.pruning_seed = con->m_pruning_seed;
    zone.m_peerlist.append_with_peer_white(pe_local);
    // update last seen and push it to peerlist manager

    anchor_peerlist_entry ape{};
    ape.adr = na;
    ape.id = pi;
    ape.first_seen = first_seen_stamp ? first_seen_stamp : time(nullptr);

    zone.m_peerlist.append_with_peer_anchor(ape);
    zone.m_notifier.new_out_connection();

    log::debug(logcat, "{}CONNECTION HANDSHAKED OK.", *con);
    return true;
}

template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::check_connection_and_handshake_with_peer(
        const epee::net_utils::network_address& na, uint64_t last_seen_stamp) {
    network_zone& zone = m_network_zones.at(na.get_zone());
    if (zone.m_connect == nullptr)
        return false;

    log::info(
            logcat,
            "Connecting to {}(last_seen: {})...",
            na.str(),
            format_stamp_ago(last_seen_stamp));

    auto con = zone.m_connect(zone, na);
    if (!con) {
        if (is_priority_node(na))
            log::info(
                    logcat, "{}[priority]Connect failed to {}", p2p_connection_context{}, na.str());
        else
            log::info(logcat, "{}Connect failed to {}", p2p_connection_context{}, na.str());
        record_addr_failed(na);

        return false;
    }

    con->m_anchor = false;
    peerid_type pi{};
    const bool res = do_handshake_with_peer(pi, *con, true);
    if (!res) {
        if (is_priority_node(na))
            log::info(logcat, "{}[priority] Failed to HANDSHAKE with peer {}", *con, na.str());
        else
            log::info(logcat, "{} Failed to HANDSHAKE with peer {}", *con, na.str());
        record_addr_failed(na);
        return false;
    }

    zone.m_net_server.get_config_object().close(con->m_connection_id);

    log::debug(logcat, "{}CONNECTION HANDSHAKED OK AND CLOSED.", *con);

    return true;
}

//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
void node_server<t_payload_net_handler>::record_addr_failed(
        const epee::net_utils::network_address& addr) {
    std::unique_lock lock{m_conn_fails_cache_lock};
    m_conn_fails_cache[addr.host_str()] = time(NULL);
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::is_addr_recently_failed(
        const epee::net_utils::network_address& addr) {
    std::shared_lock lock{m_conn_fails_cache_lock};
    auto it = m_conn_fails_cache.find(addr.host_str());
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
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::make_new_connection_from_anchor_peerlist(
        const std::vector<anchor_peerlist_entry>& anchor_peerlist) {
    for (const auto& pe : anchor_peerlist) {
        log::debug(
                logcat,
                "Considering connecting (out) to anchor peer: {} {}",
                peerid_to_string(pe.id),
                pe.adr.str());

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
                pe.adr.str(),
                format_stamp_ago(pe.first_seen));

        if (!try_to_connect_and_handshake_with_new_peer(
                    pe.adr, false, 0, PeerType::anchor, pe.first_seen)) {
            log::debug(logcat, "Handshake failed");
            continue;
        }

        return true;
    }

    return false;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::make_new_connection_from_peerlist(
        network_zone& zone, bool use_white_list) {

    std::set<size_t> tried_peers;

    constexpr auto ipv4_type_id = epee::net_utils::ipv4_network_address::get_type_id();

    for (size_t rand_count = 0; rand_count < 3 && !zone.m_net_server.is_stop_signal_sent();
         rand_count++) {
        size_t random_index;
        const uint32_t next_needed_pruning_stripe =
                m_payload_handler.get_next_needed_pruning_stripe().second;

        // build a set of all the /16s, IPs, peer_ids that we're connected to so that we can prefer
        // and/or filter them out from our potential peer selection below.
        struct {
            std::unordered_set<uint32_t> net;
            std::set<epee::net_utils::network_address> addr;
            std::unordered_set<peerid_type> peer;
        } seen;
        if (&zone == &m_network_zones.at(epee::net_utils::zone::public_))
            zone.m_net_server.get_config_object().foreach_connection(
                    [&](const p2p_connection_context& cntxt) {
                        if (cntxt.m_remote_address.get_type_id() == ipv4_type_id) {
                            seen.net.insert(
                                    cntxt.m_remote_address
                                            .template as<
                                                    const epee::net_utils::ipv4_network_address>()
                                            .ip() &
                                    0x0000ffff);
                        }
                        seen.addr.insert(cntxt.m_remote_address);
                        seen.peer.insert(cntxt.peer_id);
                        return true;
                    });

        std::deque<std::pair<size_t, bool>> filtered;  // {index, is_duplicate_slash16_network}
        size_t idx = 0;
        zone.m_peerlist.foreach (
                use_white_list,
                [this, &seen, &filtered, &idx, next_needed_pruning_stripe](
                        const peerlist_entry& pe) {
                    // Skip peers we're already connected to:
                    if (seen.peer.count(pe.id) || seen.addr.count(pe.adr))
                        return true;
                    // Don't include this in selection if it recently failed
                    if (is_addr_recently_failed(pe.adr))
                        return true;

                    const bool have_net16 =
                            pe.adr.get_type_id() == ipv4_type_id &&
                            seen.net.count(
                                    pe.adr.template as<
                                                  const epee::net_utils::ipv4_network_address>()
                                            .ip() &
                                    0x0000ffff);

                    if (next_needed_pruning_stripe == 0 || pe.pruning_seed == 0)
                        filtered.emplace_back(idx, have_net16);
                    else if (
                            next_needed_pruning_stripe ==
                            tools::get_pruning_stripe(pe.pruning_seed))
                        filtered.emplace_front(idx, have_net16);
                    ++idx;
                    return true;
                });

        if (filtered.empty()) {
            log::debug(
                    logcat,
                    "No available peer in {} list filtered by {}",
                    (use_white_list ? "white" : "gray"),
                    next_needed_pruning_stripe);
            return false;
        }

        // Partition our filtered list to move all peers with /16s to which we are already to the
        // end of the peer list where they are much less likely to be selected:
        std::stable_partition(filtered.begin(), filtered.end(), [](const auto& idx_dupenet) {
            return !idx_dupenet.second;
        });

        if (use_white_list) {
            // if using the white list, we bias towards peers we've been using recently
            random_index = get_random_exp_index(filtered.size());
            std::lock_guard lock{m_used_stripe_peers_mutex};
            if (next_needed_pruning_stripe > 0 &&
                next_needed_pruning_stripe <= (1ul << cryptonote::PRUNING_LOG_STRIPES) &&
                !m_used_stripe_peers[next_needed_pruning_stripe - 1].empty()) {
                const auto na = m_used_stripe_peers[next_needed_pruning_stripe - 1].front();
                m_used_stripe_peers[next_needed_pruning_stripe - 1].pop_front();
                for (size_t i = 0; i < filtered.size(); ++i) {
                    peerlist_entry pe;
                    if (zone.m_peerlist.get_white_peer_by_index(pe, filtered[i].first) && pe.adr == na) {
                        log::debug(
                                logcat,
                                "Reusing stripe {} peer {}",
                                next_needed_pruning_stripe,
                                pe.adr.str());
                        random_index = i;
                        break;
                    }
                }
            }
        } else
            random_index = crypto::rand_idx(filtered.size());

        CHECK_AND_ASSERT_MES(
                random_index < filtered.size(), false, "random_index < filtered.size() failed!!");
        random_index = filtered[random_index].first;
        CHECK_AND_ASSERT_MES(
                random_index < (use_white_list ? zone.m_peerlist.get_white_peers_count()
                                               : zone.m_peerlist.get_gray_peers_count()),
                false,
                "random_index < peers size failed!!");

        if (tried_peers.count(random_index))
            continue;

        tried_peers.insert(random_index);
        peerlist_entry pe{};
        bool r = use_white_list ? zone.m_peerlist.get_white_peer_by_index(pe, random_index)
                                : zone.m_peerlist.get_gray_peer_by_index(pe, random_index);
        CHECK_AND_ASSERT_MES(
                r, false, "Failed to get random peer from peerlist(white:{})", use_white_list);

        log::debug(
                logcat,
                "Considering connecting (out) to {} list peer: {} {}, pruning seed {} (stripe {} "
                "needed)",
                (use_white_list ? "white" : "gray"),
                peerid_to_string(pe.id),
                pe.adr.str(),
                epee::string_tools::to_string_hex(pe.pruning_seed),
                next_needed_pruning_stripe);

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
                "Selected peer: {} {}, pruning seed {} [peer_list={}] last_seen: {}",
                peerid_to_string(pe.id),
                pe.adr.str(),
                epee::string_tools::to_string_hex(pe.pruning_seed),
                (use_white_list ? "white" : "gray"),
                format_stamp_ago(pe.last_seen));

        if (!try_to_connect_and_handshake_with_new_peer(
                    pe.adr,
                    false,
                    pe.last_seen,
                    use_white_list ? PeerType::white : PeerType::gray)) {
            log::debug(logcat, "Handshake failed");
            continue;
        }

        return true;
    }
    return false;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::connect_to_seed() {
    if (!m_seed_nodes_initialized) {
        std::unique_lock lock{m_seed_nodes_mutex};
        if (!m_seed_nodes_initialized) {
            for (const auto& full_addr : get_seed_nodes()) {
                log::debug(logcat, "Seed node: {}", full_addr);
                append_net_address(
                        m_seed_nodes,
                        full_addr,
                        cryptonote::get_config(m_nettype).P2P_DEFAULT_PORT);
            }
            log::debug(logcat, "Number of seed nodes: {}", m_seed_nodes.size());
            m_seed_nodes_initialized = true;
        }
    }

    std::shared_lock shlock{m_seed_nodes_mutex};

    if (m_seed_nodes.empty() || m_offline || !m_exclusive_peers.empty())
        return true;

    size_t try_count = 0;
    bool is_connected_to_at_least_one_seed_node = false;
    size_t current_index = crypto::rand_idx(m_seed_nodes.size());
    const net_server& server = m_network_zones.at(epee::net_utils::zone::public_).m_net_server;
    while (true) {
        if (server.is_stop_signal_sent())
            return false;

        peerlist_entry pe_seed{};
        pe_seed.adr = m_seed_nodes[current_index];
        if (is_peer_used(pe_seed))
            is_connected_to_at_least_one_seed_node = true;
        else if (try_to_connect_and_handshake_with_new_peer(m_seed_nodes[current_index], true))
            break;
        if (++try_count > m_seed_nodes.size()) {
            if (!m_fallback_seed_nodes_added.test_and_set()) {
                log::warning(
                        logcat, "Failed to connect to any of seed peers, trying fallback seeds");
                current_index = m_seed_nodes.size() - 1;
                {
                    shlock.unlock();
                    {
                        std::unique_lock lock{m_seed_nodes_mutex};
                        for (const auto& peer : get_seed_nodes(m_nettype)) {
                            log::debug(logcat, "Fallback seed node: {}", peer);
                            append_net_address(
                                    m_seed_nodes,
                                    peer,
                                    cryptonote::get_config(m_nettype).P2P_DEFAULT_PORT);
                        }
                    }
                    shlock.lock();
                }
                if (current_index == m_seed_nodes.size() - 1) {
                    log::warning(logcat, "No fallback seeds, continuing without seeds");
                    break;
                }
                // continue for another few cycles
            } else {
                if (!is_connected_to_at_least_one_seed_node)
                    log::warning(
                            logcat,
                            "Failed to connect to any of seed peers, continuing without seeds");
                break;
            }
        }
        if (++current_index >= m_seed_nodes.size())
            current_index = 0;
    }
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::connections_maker() {
    using zone_type = epee::net_utils::zone;

    if (m_offline)
        return true;
    if (!connect_to_peerlist(m_exclusive_peers))
        return false;

    if (!m_exclusive_peers.empty())
        return true;

    // Only have seeds in the public zone right now.

    size_t start_conn_count = get_public_outgoing_connections_count();
    if (!get_public_white_peers_count() && !connect_to_seed()) {
        return false;
    }

    if (!connect_to_peerlist(m_priority_peers))
        return false;

    for (auto& zone : m_network_zones) {
        size_t base_expected_white_connections =
                (zone.second.m_config.m_net_config.max_out_connection_count *
                 cryptonote::p2p::DEFAULT_WHITELIST_CONNECTIONS_PERCENT) /
                100;

        size_t conn_count = get_outgoing_connections_count(zone.second);
        while (conn_count < zone.second.m_config.m_net_config.max_out_connection_count) {
            const size_t expected_white_connections =
                    m_payload_handler.get_next_needed_pruning_stripe().second
                            ? zone.second.m_config.m_net_config.max_out_connection_count
                            : base_expected_white_connections;
            if (conn_count < expected_white_connections) {
                // start from anchor list
                while (get_outgoing_connections_count(zone.second) <
                               cryptonote::p2p::DEFAULT_ANCHOR_CONNECTIONS_COUNT &&
                       make_expected_connections_count(
                               zone.second,
                               PeerType::anchor,
                               cryptonote::p2p::DEFAULT_ANCHOR_CONNECTIONS_COUNT))
                    ;
                // then do white list
                while (get_outgoing_connections_count(zone.second) < expected_white_connections &&
                       make_expected_connections_count(
                               zone.second, PeerType::white, expected_white_connections))
                    ;
                // then do grey list
                while (get_outgoing_connections_count(zone.second) <
                               zone.second.m_config.m_net_config.max_out_connection_count &&
                       make_expected_connections_count(
                               zone.second,
                               PeerType::gray,
                               zone.second.m_config.m_net_config.max_out_connection_count))
                    ;
            } else {
                // start from grey list
                while (get_outgoing_connections_count(zone.second) <
                               zone.second.m_config.m_net_config.max_out_connection_count &&
                       make_expected_connections_count(
                               zone.second,
                               PeerType::gray,
                               zone.second.m_config.m_net_config.max_out_connection_count))
                    ;
                // and then do white list
                while (get_outgoing_connections_count(zone.second) <
                               zone.second.m_config.m_net_config.max_out_connection_count &&
                       make_expected_connections_count(
                               zone.second,
                               PeerType::white,
                               zone.second.m_config.m_net_config.max_out_connection_count))
                    ;
            }
            if (zone.second.m_net_server.is_stop_signal_sent())
                return false;
            size_t new_conn_count = get_outgoing_connections_count(zone.second);
            if (new_conn_count <= conn_count) {
                // we did not make any connection, sleep a bit to avoid a busy loop in case we don't
                // have any peers to try, then break so we will try seeds to get more peers
                std::this_thread::sleep_for(1s);
                break;
            }
            conn_count = new_conn_count;
        }
    }

    if (start_conn_count == get_public_outgoing_connections_count() &&
        start_conn_count < m_network_zones.at(zone_type::public_)
                                   .m_config.m_net_config.max_out_connection_count) {
        log::info(logcat, "Failed to connect to any, trying seeds");
        if (!connect_to_seed())
            return false;
    }

    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::make_expected_connections_count(
        network_zone& zone, PeerType peer_type, size_t expected_connections) {
    if (m_offline)
        return false;

    std::vector<anchor_peerlist_entry> apl;

    if (peer_type == PeerType::anchor) {
        zone.m_peerlist.get_and_empty_anchor_peerlist(apl);
    }

    size_t conn_count = get_outgoing_connections_count(zone);
    // add new connections from white peers
    if (conn_count < expected_connections) {
        if (zone.m_net_server.is_stop_signal_sent())
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

        if (peer_type == PeerType::white && !make_new_connection_from_peerlist(zone, true)) {
            return false;
        }

        if (peer_type == PeerType::gray && !make_new_connection_from_peerlist(zone, false)) {
            return false;
        }
    }
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
size_t node_server<t_payload_net_handler>::get_public_outgoing_connections_count() {
    auto public_zone = m_network_zones.find(epee::net_utils::zone::public_);
    if (public_zone == m_network_zones.end())
        return 0;
    return get_outgoing_connections_count(public_zone->second);
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
size_t node_server<t_payload_net_handler>::get_incoming_connections_count(network_zone& zone) {
    size_t count = 0;
    zone.m_net_server.get_config_object().foreach_connection(
            [&](const p2p_connection_context& cntxt) {
                if (cntxt.m_is_income)
                    ++count;
                return true;
            });
    return count;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
size_t node_server<t_payload_net_handler>::get_outgoing_connections_count(network_zone& zone) {
    size_t count = 0;
    zone.m_net_server.get_config_object().foreach_connection(
            [&](const p2p_connection_context& cntxt) {
                if (!cntxt.m_is_income)
                    ++count;
                return true;
            });
    return count;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
size_t node_server<t_payload_net_handler>::get_outgoing_connections_count() {
    size_t count = 0;
    for (auto& zone : m_network_zones)
        count += get_outgoing_connections_count(zone.second);
    return count;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
size_t node_server<t_payload_net_handler>::get_incoming_connections_count() {
    size_t count = 0;
    for (auto& zone : m_network_zones) {
        zone.second.m_net_server.get_config_object().foreach_connection(
                [&](const p2p_connection_context& cntxt) {
                    if (cntxt.m_is_income)
                        ++count;
                    return true;
                });
    }
    return count;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
size_t node_server<t_payload_net_handler>::get_public_white_peers_count() {
    auto public_zone = m_network_zones.find(epee::net_utils::zone::public_);
    if (public_zone == m_network_zones.end())
        return 0;
    return public_zone->second.m_peerlist.get_white_peers_count();
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
size_t node_server<t_payload_net_handler>::get_public_gray_peers_count() {
    auto public_zone = m_network_zones.find(epee::net_utils::zone::public_);
    if (public_zone == m_network_zones.end())
        return 0;
    return public_zone->second.m_peerlist.get_gray_peers_count();
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
void node_server<t_payload_net_handler>::get_public_peerlist(
        std::vector<peerlist_entry>& gray, std::vector<peerlist_entry>& white) {
    auto public_zone = m_network_zones.find(epee::net_utils::zone::public_);
    if (public_zone != m_network_zones.end())
        public_zone->second.m_peerlist.get_peerlist(gray, white);
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
void node_server<t_payload_net_handler>::get_peerlist(
        std::vector<peerlist_entry>& gray, std::vector<peerlist_entry>& white) {
    for (auto& zone : m_network_zones) {
        zone.second.m_peerlist.get_peerlist(gray, white);  // appends
    }
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::idle_worker() {
    m_peer_handshake_idle_maker_interval.do_call([this] { return peer_sync_idle_maker(); });
    m_connections_maker_interval.do_call([this] { return connections_maker(); });
    m_gray_peerlist_housekeeping_interval.do_call([this] { return gray_peerlist_housekeeping(); });
    m_peerlist_store_interval.do_call([this] { return store_config(); });
    m_incoming_connections_interval.do_call([this] { return check_incoming_connections(); });
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::check_incoming_connections() {
    if (m_offline)
        return true;

    const auto public_zone = m_network_zones.find(epee::net_utils::zone::public_);
    if (public_zone != m_network_zones.end() &&
        get_incoming_connections_count(public_zone->second) == 0) {
        if (m_hide_my_port ||
            public_zone->second.m_config.m_net_config.max_in_connection_count == 0) {
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
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::peer_sync_idle_maker() {
    // TODO: this sync code is rather dumb: every 60s we trigger a sync with every connected peer
    // all at once which results in a sudden spike of activity every 60s then not much in between.
    // This really should be spaced out, i.e. the 60s sync timing should apply per peer, not
    // globally.

    log::debug(logcat, "STARTED PEERLIST IDLE HANDSHAKE");
    typedef std::list<std::pair<epee::net_utils::connection_context_base, peerid_type>>
            local_connects_type;
    local_connects_type cncts;
    for (auto& zone : m_network_zones) {
        zone.second.m_net_server.get_config_object().foreach_connection(
                [&](p2p_connection_context& cntxt) {
                    if (cntxt.peer_id && !cntxt.m_in_timedsync) {
                        cntxt.m_in_timedsync = true;
                        cncts.push_back(local_connects_type::value_type(
                                cntxt,
                                cntxt.peer_id));  // do idle sync only with handshaked connections
                    }
                    return true;
                });
    }

    std::for_each(cncts.begin(), cncts.end(), [&](const auto& vl) {
        do_peer_timed_sync(vl.first, vl.second);
    });

    log::debug(logcat, "FINISHED PEERLIST IDLE HANDSHAKE");
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::sanitize_peerlist(
        std::vector<peerlist_entry>& local_peerlist) {
    for (size_t i = 0; i < local_peerlist.size(); ++i) {
        bool ignore = false;
        peerlist_entry& be = local_peerlist[i];
        epee::net_utils::network_address& na = be.adr;
        if (na.is_loopback() || na.is_local()) {
            ignore = true;
        } else if (be.adr.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id()) {
            const epee::net_utils::ipv4_network_address& ipv4 =
                    na.as<const epee::net_utils::ipv4_network_address>();
            if (ipv4.ip() == 0)
                ignore = true;
        }
        if (be.pruning_seed &&
            (be.pruning_seed < tools::make_pruning_seed(1, cryptonote::PRUNING_LOG_STRIPES) ||
             be.pruning_seed > tools::make_pruning_seed(
                                       1ul << cryptonote::PRUNING_LOG_STRIPES,
                                       cryptonote::PRUNING_LOG_STRIPES)))
            ignore = true;
        if (ignore) {
            log::debug(logcat, "Ignoring {}", be.adr.str());
            std::swap(local_peerlist[i], local_peerlist[local_peerlist.size() - 1]);
            local_peerlist.resize(local_peerlist.size() - 1);
            --i;
            continue;
        }
        local_peerlist[i].last_seen = 0;

        if constexpr (cryptonote::PRUNING_DEBUG_SPOOF_SEED)
            be.pruning_seed = tools::make_pruning_seed(
                    1 + (be.adr.as<epee::net_utils::ipv4_network_address>().ip()) %
                                    (1ul << cryptonote::PRUNING_LOG_STRIPES),
                    cryptonote::PRUNING_LOG_STRIPES);
    }
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::handle_remote_peerlist(
        const std::vector<peerlist_entry>& peerlist,
        const epee::net_utils::connection_context_base& context) {
    std::vector<peerlist_entry> peerlist_ = peerlist;
    if (!sanitize_peerlist(peerlist_))
        return false;

    const epee::net_utils::zone zone = context.m_remote_address.get_zone();
    for (const auto& peer : peerlist_) {
        if (peer.adr.get_zone() != zone) {
            log::warning(logcat, "{} sent peerlist from another zone, dropping", context);
            return false;
        }
    }

    log::debug(logcat, "{}REMOTE PEERLIST: remote peerlist size={}", context, peerlist_.size());
    log::trace(
            logcat,
            "{}REMOTE PEERLIST: \n{}",
            context,
            "REMOTE PEERLIST: \n",
            print_peerlist_to_string(peerlist_));
    return m_network_zones.at(context.m_remote_address.get_zone())
            .m_peerlist.merge_peerlist(peerlist_, [this](const peerlist_entry& pe) {
                return !is_addr_recently_failed(pe.adr);
            });
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::get_local_node_data(
        basic_node_data& node_data, const network_zone& zone) {
    node_data.peer_id = zone.m_config.m_peer_id;
    if (!m_hide_my_port && zone.m_can_pingback)
        node_data.my_port = m_external_port ? m_external_port : m_listening_port;
    else
        node_data.my_port = 0;
    node_data.network_id = m_network_id;
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
int node_server<t_payload_net_handler>::handle_get_support_flags(
        int /*command*/,
        COMMAND_REQUEST_SUPPORT_FLAGS::request& /*arg*/,
        COMMAND_REQUEST_SUPPORT_FLAGS::response& rsp,
        p2p_connection_context& /*context*/) {
    rsp.support_flags = 0;
    return 1;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
void node_server<t_payload_net_handler>::request_callback(
        const epee::net_utils::connection_context_base& context) {
    m_network_zones.at(context.m_remote_address.get_zone())
            .m_net_server.get_config_object()
            .request_callback(context.m_connection_id);
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::relay_notify_to_list(
        int command,
        const epee::span<const uint8_t> data_buff,
        std::vector<std::pair<epee::net_utils::zone, boost::uuids::uuid>> connections) {
    std::sort(connections.begin(), connections.end());
    auto zone = m_network_zones.begin();
    for (const auto& c_id : connections) {
        for (;;) {
            if (zone == m_network_zones.end()) {
                log::warning(logcat, "Unable to relay all messages, zone not available");
                return false;
            }
            if (c_id.first <= zone->first)
                break;

            ++zone;
        }
        if (zone->first == c_id.first)
            zone->second.m_net_server.get_config_object().notify(command, data_buff, c_id.second);
    }
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
epee::net_utils::zone node_server<t_payload_net_handler>::send_txs(
        std::vector<std::string> txs,
        const epee::net_utils::zone origin,
        const boost::uuids::uuid& source,
        const bool pad_txs) {
    namespace enet = epee::net_utils;

    const auto send = [&txs, &source, pad_txs](std::pair<const enet::zone, network_zone>& network) {
        if (network.second.m_notifier.send_txs(
                    std::move(txs), source, (pad_txs || network.first != enet::zone::public_)))
            return network.first;
        return enet::zone::invalid;
    };

    if (m_network_zones.empty())
        return enet::zone::invalid;

    if (origin != enet::zone::invalid)
        return send(*m_network_zones.begin());  // send all txs received via p2p over public network

    if (m_network_zones.size() <= 2)
        return send(*m_network_zones.rbegin());  // see static asserts below; sends over anonymity
                                                 // network iff enabled

    /* These checks are to ensure that i2p is highest priority if multiple
       zones are selected. Make sure to update logic if the values cannot be
       in the same relative order. `m_network_zones` must be sorted map too. */
    static_assert(
            std::is_same<std::underlying_type<enet::zone>::type, std::uint8_t>{},
            "expected uint8_t zone");
    static_assert(unsigned(enet::zone::invalid) == 0, "invalid expected to be 0");
    static_assert(unsigned(enet::zone::public_) == 1, "public_ expected to be 1");
    static_assert(unsigned(enet::zone::i2p) == 2, "i2p expected to be 2");
    static_assert(unsigned(enet::zone::tor) == 3, "tor expected to be 3");

    // check for anonymity networks with noise and connections
    for (auto network = ++m_network_zones.begin(); network != m_network_zones.end(); ++network) {
        if (enet::zone::tor < network->first)
            break;  // unknown network

        const auto status = network->second.m_notifier.get_status();
        if (status.has_noise && status.connections_filled)
            return send(*network);
    }

    // use the anonymity network with outbound support
    for (auto network = ++m_network_zones.begin(); network != m_network_zones.end(); ++network) {
        if (enet::zone::tor < network->first)
            break;  // unknown network

        if (network->second.m_connect)
            return send(*network);
    }

    // configuration should not allow this scenario
    return enet::zone::invalid;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
void node_server<t_payload_net_handler>::callback(p2p_connection_context& context) {
    m_payload_handler.on_callback(context);
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::invoke_notify_to_peer(
        int command,
        const epee::span<const uint8_t> req_buff,
        const epee::net_utils::connection_context_base& context) {
    if (is_filtered_command(context.m_remote_address, command))
        return false;

    network_zone& zone = m_network_zones.at(context.m_remote_address.get_zone());
    int res = zone.m_net_server.get_config_object().notify(
            command, req_buff, context.m_connection_id);
    return res > 0;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::invoke_command_to_peer(
        int command,
        const epee::span<const uint8_t> req_buff,
        std::string& resp_buff,
        const epee::net_utils::connection_context_base& context) {
    if (is_filtered_command(context.m_remote_address, command))
        return false;

    network_zone& zone = m_network_zones.at(context.m_remote_address.get_zone());
    int res = zone.m_net_server.get_config_object().invoke(
            command, req_buff, resp_buff, context.m_connection_id);
    return res > 0;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::drop_connection(
        const epee::net_utils::connection_context_base& context) {
    m_network_zones.at(context.m_remote_address.get_zone())
            .m_net_server.get_config_object()
            .close(context.m_connection_id);
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
template <class t_callback>
bool node_server<t_payload_net_handler>::try_ping(
        basic_node_data& node_data, p2p_connection_context& context, const t_callback& cb) {
    if (!node_data.my_port)
        return false;

    bool address_ok =
            (context.m_remote_address.get_type_id() ==
                     epee::net_utils::ipv4_network_address::get_type_id() ||
             context.m_remote_address.get_type_id() ==
                     epee::net_utils::ipv6_network_address::get_type_id());
    CHECK_AND_ASSERT_MES(address_ok, false, "Only IPv4 or IPv6 addresses are supported here");

    const epee::net_utils::network_address na = context.m_remote_address;
    std::string ip;
    std::optional<uint32_t> ipv4_addr;
    boost::asio::ip::address_v6 ipv6_addr;
    if (na.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id()) {
        ipv4_addr = na.as<const epee::net_utils::ipv4_network_address>().ip();
        ip = epee::string_tools::get_ip_string_from_int32(*ipv4_addr);
    } else {
        ipv6_addr = na.as<const epee::net_utils::ipv6_network_address>().ip();
        ip = ipv6_addr.to_string();
    }
    network_zone& zone = m_network_zones.at(na.get_zone());

    if (!zone.m_peerlist.is_host_allowed(context.m_remote_address))
        return false;

    std::string port = std::to_string(node_data.my_port);

    epee::net_utils::network_address address;
    if (ipv4_addr) {
        address = epee::net_utils::network_address{
                epee::net_utils::ipv4_network_address(*ipv4_addr, node_data.my_port)};
    } else {
        address = epee::net_utils::network_address{
                epee::net_utils::ipv6_network_address(ipv6_addr, node_data.my_port)};
    }
    peerid_type pr = node_data.peer_id;
    bool r = zone.m_net_server.connect_async(
            ip,
            port,
            zone.m_config.m_net_config.ping_connection_timeout.count(),
            [cb, /*context,*/ address, pr, this](
                    const typename net_server::t_connection_context& ping_context,
                    const boost::system::error_code& ec) -> bool {
                if (ec) {
                    log::warning(
                            logcat,
                            "{}back ping connect failed to {}",
                            ping_context,
                            address.str());
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

                network_zone& zone = m_network_zones.at(address.get_zone());

                bool inv_call_res =
                        epee::net_utils::async_invoke_remote_command2<COMMAND_PING::response>(
                                ping_context.m_connection_id,
                                COMMAND_PING::ID,
                                req,
                                zone.m_net_server.get_config_object(),
                                [=, this](
                                        int code,
                                        const COMMAND_PING::response& rsp,
                                        p2p_connection_context& /*context*/) {
                                    if (code <= 0) {
                                        log::warning(
                                                logcat,
                                                "{}Failed to invoke COMMAND_PING to {}({}, {})",
                                                ping_context,
                                                address.str(),
                                                code,
                                                epee::levin::get_err_descr(code));
                                        return;
                                    }

                                    network_zone& zone = m_network_zones.at(address.get_zone());
                                    if (rsp.status != COMMAND_PING::OK_RESPONSE ||
                                        pr != rsp.peer_id) {
                                        log::warning(
                                                logcat,
                                                "{}{}\" from{}, hsh_peer_id={}, rsp.peer_id={}",
                                                ping_context,
                                                "back ping invoke wrong response \"",
                                                rsp.status,
                                                address.str(),
                                                pr_,
                                                peerid_to_string(rsp.peer_id));
                                        zone.m_net_server.get_config_object().close(
                                                ping_context.m_connection_id);
                                        return;
                                    }
                                    zone.m_net_server.get_config_object().close(
                                            ping_context.m_connection_id);
                                    cb();
                                });

                if (!inv_call_res) {
                    log::warning(
                            logcat,
                            "{}{}",
                            ping_context,
                            "back ping invoke failed to ",
                            address.str());
                    zone.m_net_server.get_config_object().close(ping_context.m_connection_id);
                    return false;
                }
                return true;
            },
            zone.m_bind_ip);
    if (!r) {
        log::warning(logcat, "{}Failed to call connect_async, network error.", context);
    }
    return r;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
int node_server<t_payload_net_handler>::handle_timed_sync(
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
    const epee::net_utils::zone zone_type = context.m_remote_address.get_zone();
    network_zone& zone = m_network_zones.at(zone_type);

    std::vector<peerlist_entry> local_peerlist_new;
    zone.m_peerlist.get_peerlist_head(
            local_peerlist_new, true, cryptonote::p2p::DEFAULT_PEERS_IN_HANDSHAKE);

    // only include out peers we did not already send
    rsp.local_peerlist_new.reserve(local_peerlist_new.size());
    for (auto& pe : local_peerlist_new) {
        if (!context.sent_addresses.insert(pe.adr).second)
            continue;
        rsp.local_peerlist_new.push_back(std::move(pe));
    }
    m_payload_handler.get_payload_sync_data(rsp.payload_data);

    /* Tor/I2P nodes receiving connections via forwarding (from tor/i2p daemon)
    do not know the address of the connecting peer. This is relayed to them,
    iff the node has setup an inbound hidden service. The other peer will have
    to use the random peer_id value to link the two. My initial thought is that
    the inbound peer should leave the other side marked as `<unknown tor host>`,
    etc., because someone could give faulty addresses over Tor/I2P to get the
    real peer with that identity banned/blacklisted. */

    if (!context.m_is_income && zone.m_our_address.get_zone() == zone_type)
        rsp.local_peerlist_new.push_back(
                peerlist_entry{zone.m_our_address, zone.m_config.m_peer_id, std::time(nullptr)});

    log::debug(logcat, "{}COMMAND_TIMED_SYNC", context);
    return 1;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
int node_server<t_payload_net_handler>::handle_handshake(
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

    network_zone& zone = m_network_zones.at(context.m_remote_address.get_zone());

    // test only the remote end's zone, otherwise an attacker could connect to you on clearnet
    // and pass in a tor connection's peer id, and deduce the two are the same if you reject it
    if (arg.node_data.peer_id == zone.m_config.m_peer_id) {
        log::debug(logcat, "{}Connection to self detected, dropping connection", context);
        drop_connection(context);
        return 1;
    }

    if (zone.m_current_number_of_in_peers >=
        zone.m_config.m_net_config.max_in_connection_count)  // in peers limit
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
                context.m_remote_address.host_str());
        drop_connection(context);
        return 1;
    }

    // associate peer_id with this connection
    context.peer_id = arg.node_data.peer_id;
    context.m_in_timedsync = false;

    if (arg.node_data.my_port && zone.m_can_pingback) {
        peerid_type peer_id_l = arg.node_data.peer_id;
        uint32_t port_l = arg.node_data.my_port;
        // try ping to be sure that we can add this peer to peer_list
        try_ping(arg.node_data, context, [peer_id_l, port_l, context, this]() {
            CHECK_AND_ASSERT_MES(
                    (context.m_remote_address.get_type_id() ==
                             epee::net_utils::ipv4_network_address::get_type_id() ||
                     context.m_remote_address.get_type_id() ==
                             epee::net_utils::ipv6_network_address::get_type_id()),
                    /*void*/,
                    "Only IPv4 or IPv6 addresses are supported here");
            // called only(!) if success pinged, update local peerlist
            peerlist_entry pe;
            const epee::net_utils::network_address na = context.m_remote_address;
            if (context.m_remote_address.get_type_id() ==
                epee::net_utils::ipv4_network_address::get_type_id()) {
                pe.adr = epee::net_utils::ipv4_network_address(
                        na.as<epee::net_utils::ipv4_network_address>().ip(), port_l);
            } else {
                pe.adr = epee::net_utils::ipv6_network_address(
                        na.as<epee::net_utils::ipv6_network_address>().ip(), port_l);
            }
            time_t last_seen;
            time(&last_seen);
            pe.last_seen = static_cast<int64_t>(last_seen);
            pe.id = peer_id_l;
            pe.pruning_seed = context.m_pruning_seed;
            this->m_network_zones.at(context.m_remote_address.get_zone())
                    .m_peerlist.append_with_peer_white(pe);
            log::debug(
                    logcat,
                    "{}PING SUCCESS {}:{}",
                    context,
                    context.m_remote_address.host_str(),
                    port_l);
        });
    }

    // fill response
    zone.m_peerlist.get_peerlist_head(rsp.local_peerlist_new, true);
    for (const auto& e : rsp.local_peerlist_new)
        context.sent_addresses.insert(e.adr);
    get_local_node_data(rsp.node_data, zone);
    m_payload_handler.get_payload_sync_data(rsp.payload_data);
    log::debug(logcat, "{}COMMAND_HANDSHAKE", context);
    return 1;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
int node_server<t_payload_net_handler>::handle_ping(
        int /*command*/,
        COMMAND_PING::request& /*arg*/,
        COMMAND_PING::response& rsp,
        p2p_connection_context& context) {
    log::debug(logcat, "{}COMMAND_PING", context);
    rsp.status = COMMAND_PING::OK_RESPONSE;
    rsp.peer_id = m_network_zones.at(context.m_remote_address.get_zone()).m_config.m_peer_id;
    return 1;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::log_peerlist() {
    std::vector<peerlist_entry> pl_white;
    std::vector<peerlist_entry> pl_gray;
    for (auto& zone : m_network_zones)
        zone.second.m_peerlist.get_peerlist(pl_gray, pl_white);
    log::info(
            logcat,
            "\nPeerlist white:\n{}\nPeerlist gray:\n{}",
            print_peerlist_to_string(pl_white),
            print_peerlist_to_string(pl_gray));
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::log_connections() {
    log::info(logcat, "Connections: \r\n{}", print_connections_container());
    return true;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
std::string node_server<t_payload_net_handler>::print_connections_container() {

    std::stringstream ss;
    for (auto& zone : m_network_zones) {
        zone.second.m_net_server.get_config_object().foreach_connection(
                [&](const p2p_connection_context& cntxt) {
                    ss << cntxt.m_remote_address.str() << " \t\tpeer_id "
                       << peerid_to_string(cntxt.peer_id) << " \t\tconn_id "
                       << cntxt.m_connection_id << (cntxt.m_is_income ? " INC" : " OUT")
                       << std::endl;
                    return true;
                });
    }
    std::string s = ss.str();
    return s;
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
void node_server<t_payload_net_handler>::on_connection_new(p2p_connection_context& context) {
    log::info(logcat, "[{}] NEW CONNECTION", epee::net_utils::print_connection_context(context));
}
//-----------------------------------------------------------------------------------
template <class t_payload_net_handler>
void node_server<t_payload_net_handler>::on_connection_close(p2p_connection_context& context) {
    network_zone& zone = m_network_zones.at(context.m_remote_address.get_zone());
    if (!zone.m_net_server.is_stop_signal_sent() && !context.m_is_income) {
        epee::net_utils::network_address na{};
        na = context.m_remote_address;

        zone.m_peerlist.remove_from_peer_anchor(na);
    }

    m_payload_handler.on_connection_close(context);

    log::info(logcat, "[{}] CLOSE CONNECTION", epee::net_utils::print_connection_context(context));
}

template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::is_priority_node(
        const epee::net_utils::network_address& na) {
    return (std::find(m_priority_peers.begin(), m_priority_peers.end(), na) !=
            m_priority_peers.end()) ||
           (std::find(m_exclusive_peers.begin(), m_exclusive_peers.end(), na) !=
            m_exclusive_peers.end());
}

template <class t_payload_net_handler>
template <class Container>
bool node_server<t_payload_net_handler>::connect_to_peerlist(const Container& peers) {
    const network_zone& public_zone = m_network_zones.at(epee::net_utils::zone::public_);
    for (const epee::net_utils::network_address& na : peers) {
        if (public_zone.m_net_server.is_stop_signal_sent())
            return false;

        if (is_addr_connected(na))
            continue;

        try_to_connect_and_handshake_with_new_peer(na);
    }

    return true;
}

template <class t_payload_net_handler>
template <class Container>
bool node_server<t_payload_net_handler>::parse_peers_and_add_to_container(
        const boost::program_options::variables_map& vm,
        const command_line::arg_descriptor<std::vector<std::string>>& arg,
        Container& container) {
    std::vector<std::string> perrs = command_line::get_arg(vm, arg);

    for (const std::string& pr_str : perrs) {
        const uint16_t default_port = cryptonote::get_config(m_nettype).P2P_DEFAULT_PORT;
        expect<epee::net_utils::network_address> adr =
                net::get_network_address(pr_str, default_port);
        if (adr) {
            add_zone(adr->get_zone());
            container.push_back(std::move(*adr));
            continue;
        }
        std::vector<epee::net_utils::network_address> resolved_addrs;
        bool r = append_net_address(resolved_addrs, pr_str, default_port);
        CHECK_AND_ASSERT_MES(
                r, false, "Failed to parse or resolve address from string: {}", pr_str);
        for (const epee::net_utils::network_address& addr : resolved_addrs) {
            container.push_back(addr);
        }
    }

    return true;
}

template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::set_max_out_peers(network_zone& zone, int64_t max) {
    if (max == -1)
        max = cryptonote::p2p::DEFAULT_CONNECTIONS_COUNT_OUT;
    zone.m_config.m_net_config.max_out_connection_count = max;
    return true;
}

template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::set_max_in_peers(network_zone& zone, int64_t max) {
    if (max == -1)
        max = cryptonote::p2p::DEFAULT_CONNECTIONS_COUNT_IN;
    zone.m_config.m_net_config.max_in_connection_count = max;
    return true;
}

template <class t_payload_net_handler>
void node_server<t_payload_net_handler>::change_max_out_public_peers(size_t count) {
    auto public_zone = m_network_zones.find(epee::net_utils::zone::public_);
    if (public_zone != m_network_zones.end()) {
        const auto current =
                public_zone->second.m_net_server.get_config_object().get_out_connections_count();
        public_zone->second.m_config.m_net_config.max_out_connection_count = count;
        if (current > count)
            public_zone->second.m_net_server.get_config_object().del_out_connections(
                    current - count);
        m_payload_handler.set_max_out_peers(count);
    }
}

template <class t_payload_net_handler>
uint32_t node_server<t_payload_net_handler>::get_max_out_public_peers() const {
    const auto public_zone = m_network_zones.find(epee::net_utils::zone::public_);
    if (public_zone == m_network_zones.end())
        return 0;
    return public_zone->second.m_config.m_net_config.max_out_connection_count;
}

template <class t_payload_net_handler>
void node_server<t_payload_net_handler>::change_max_in_public_peers(size_t count) {
    auto public_zone = m_network_zones.find(epee::net_utils::zone::public_);
    if (public_zone != m_network_zones.end()) {
        const auto current =
                public_zone->second.m_net_server.get_config_object().get_in_connections_count();
        public_zone->second.m_config.m_net_config.max_in_connection_count = count;
        if (current > count)
            public_zone->second.m_net_server.get_config_object().del_in_connections(
                    current - count);
    }
}

template <class t_payload_net_handler>
uint32_t node_server<t_payload_net_handler>::get_max_in_public_peers() const {
    const auto public_zone = m_network_zones.find(epee::net_utils::zone::public_);
    if (public_zone == m_network_zones.end())
        return 0;
    return public_zone->second.m_config.m_net_config.max_in_connection_count;
}

template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::set_tos_flag(
        const boost::program_options::variables_map& /*vm*/, int flag) {
    if (flag == -1) {
        return true;
    }
    epee::net_utils::connection<
            epee::levin::async_protocol_handler<p2p_connection_context>>::set_tos_flag(flag);
    log::debug(logcat, "Set ToS flag  {}", flag);
    return true;
}

template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::set_rate_up_limit(
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

template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::set_rate_down_limit(
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

template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::set_rate_limit(
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

template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::has_too_many_connections(
        const epee::net_utils::network_address& address) {
    if (address.get_zone() != epee::net_utils::zone::public_)
        return false;  // Unable to determine how many connections from host

    const size_t max_connections = m_nettype == cryptonote::network_type::MAINNET ? 1 : 20;
    size_t count = 0;

    m_network_zones.at(epee::net_utils::zone::public_)
            .m_net_server.get_config_object()
            .foreach_connection([&](const p2p_connection_context& cntxt) {
                if (cntxt.m_is_income && cntxt.m_remote_address.is_same_host(address)) {
                    count++;

                    if (count > max_connections) {
                        return false;
                    }
                }

                return true;
            });

    return count > max_connections;
}

template <class t_payload_net_handler>
bool node_server<t_payload_net_handler>::gray_peerlist_housekeeping() {
    if (m_offline)
        return true;
    if (!m_exclusive_peers.empty())
        return true;
    if (m_payload_handler.needs_new_sync_connections())
        return true;

    for (auto& zone : m_network_zones) {
        if (zone.second.m_net_server.is_stop_signal_sent())
            return false;

        if (zone.second.m_connect == nullptr)
            continue;

        peerlist_entry pe{};
        if (!zone.second.m_peerlist.get_random_gray_peer(pe))
            continue;

        if (!check_connection_and_handshake_with_peer(pe.adr, pe.last_seen)) {
            zone.second.m_peerlist.remove_from_peer_gray(pe);
            log::debug(
                    logcat,
                    "PEER EVICTED FROM GRAY PEER LIST: address: {} Peer ID: {}",
                    pe.adr.host_str(),
                    peerid_to_string(pe.id));
        } else {
            zone.second.m_peerlist.set_peer_just_seen(pe.id, pe.adr, pe.pruning_seed);
            log::debug(
                    logcat,
                    "PEER PROMOTED TO WHITE PEER LIST IP address: {} Peer ID: {}",
                    pe.adr.host_str(),
                    peerid_to_string(pe.id));
        }
    }
    return true;
}

template <class t_payload_net_handler>
void node_server<t_payload_net_handler>::add_used_stripe_peer(
        const typename t_payload_net_handler::connection_context& context) {
    const uint32_t stripe = tools::get_pruning_stripe(context.m_pruning_seed);
    if (stripe == 0 || stripe > (1ul << cryptonote::PRUNING_LOG_STRIPES))
        return;
    const uint32_t index = stripe - 1;
    std::lock_guard lock{m_used_stripe_peers_mutex};
    log::info(logcat, "adding stripe {} peer: {}", stripe, context.m_remote_address.str());
    std::remove_if(
            m_used_stripe_peers[index].begin(),
            m_used_stripe_peers[index].end(),
            [&context](const epee::net_utils::network_address& na) {
                return context.m_remote_address == na;
            });
    m_used_stripe_peers[index].push_back(context.m_remote_address);
}

template <class t_payload_net_handler>
void node_server<t_payload_net_handler>::remove_used_stripe_peer(
        const typename t_payload_net_handler::connection_context& context) {
    const uint32_t stripe = tools::get_pruning_stripe(context.m_pruning_seed);
    if (stripe == 0 || stripe > (1ul << cryptonote::PRUNING_LOG_STRIPES))
        return;
    const uint32_t index = stripe - 1;
    std::lock_guard lock{m_used_stripe_peers_mutex};
    log::info(logcat, "removing stripe {} peer: {}", stripe, context.m_remote_address.str());
    std::remove_if(
            m_used_stripe_peers[index].begin(),
            m_used_stripe_peers[index].end(),
            [&context](const epee::net_utils::network_address& na) {
                return context.m_remote_address == na;
            });
}

template <class t_payload_net_handler>
void node_server<t_payload_net_handler>::clear_used_stripe_peers() {
    std::lock_guard lock{m_used_stripe_peers_mutex};
    log::info(logcat, "clearing used stripe peers");
    for (auto& e : m_used_stripe_peers)
        e.clear();
}

template <typename t_payload_net_handler>
std::optional<p2p_connection_context_t<typename t_payload_net_handler::connection_context>>
node_server<t_payload_net_handler>::socks_connect(
        network_zone& zone, const epee::net_utils::network_address& remote) {
    auto result = socks_connect_internal(
            zone.m_net_server.get_stop_signal(),
            zone.m_net_server.get_io_service(),
            zone.m_proxy_address,
            remote);
    if (result)  // if no error
    {
        p2p_connection_context context{};
        if (zone.m_net_server.add_connection(context, std::move(*result), remote))
            return {std::move(context)};
    }
    return std::nullopt;
}

template <typename t_payload_net_handler>
std::optional<p2p_connection_context_t<typename t_payload_net_handler::connection_context>>
node_server<t_payload_net_handler>::public_connect(
        network_zone& zone, epee::net_utils::network_address const& na) {
    bool is_ipv4 = na.get_type_id() == epee::net_utils::ipv4_network_address::get_type_id();
    bool is_ipv6 = na.get_type_id() == epee::net_utils::ipv6_network_address::get_type_id();
    CHECK_AND_ASSERT_MES(
            is_ipv4 || is_ipv6, std::nullopt, "Only IPv4 or IPv6 addresses are supported here");

    std::string address;
    std::string port;

    if (is_ipv4) {
        const epee::net_utils::ipv4_network_address& ipv4 =
                na.as<const epee::net_utils::ipv4_network_address>();
        address = epee::string_tools::get_ip_string_from_int32(ipv4.ip());
        port = std::to_string(ipv4.port());
    } else {
        const epee::net_utils::ipv6_network_address& ipv6 =
                na.as<const epee::net_utils::ipv6_network_address>();
        address = ipv6.ip().to_string();
        port = std::to_string(ipv6.port());
    }

    typename net_server::t_connection_context con{};
    const bool res = zone.m_net_server.connect(
            address,
            port,
            zone.m_config.m_net_config.connection_timeout.count(),
            con,
            zone.m_bind_ip);

    if (res)
        return {std::move(con)};
    return std::nullopt;
}
}  // namespace nodetool
