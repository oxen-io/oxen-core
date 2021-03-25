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

#include <boost/endian/conversion.hpp>
#include <future>
#include <optional>
#include <chrono>
#include <utility>
#include <string_view>

#include "common/command_line.h"
#include "common/string_util.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "net_node.h"
#include "epee/net/net_utils_base.h"
#include "net/socks.h"
#include "net/parse.h"
#include "net/tor_address.h"
#include "net/i2p_address.h"
#include "p2p/p2p_protocol_defs.h"
#include "epee/string_tools.h"

namespace
{
    constexpr const std::chrono::milliseconds future_poll_interval = 500ms;
    constexpr const std::chrono::seconds socks_connect_timeout{P2P_DEFAULT_SOCKS_CONNECT_TIMEOUT};

    std::int64_t get_max_connections(const std::string_view value) noexcept
    {
        // -1 is default, 0 is error
        if (value.empty())
            return -1;

        std::uint32_t out = 0;
        if (tools::parse_int(value, out))
            return out;
        return 0;
    }

    template<typename T>
    epee::net_utils::network_address get_address(std::string_view value)
    {
        expect<T> address = T::make(value);
        if (!address)
        {
            MERROR(
                "Failed to parse " << epee::net_utils::zone_to_string(T::get_zone()) << " address \"" << value << "\": " << address.error().message()
            );
            return {};
        }
        return {std::move(*address)};
    }

    bool start_socks(std::shared_ptr<net::socks::client> client, const boost::asio::ip::tcp::endpoint& proxy, const epee::net_utils::network_address& remote)
    {
        CHECK_AND_ASSERT_MES(client != nullptr, false, "Unexpected null client");

        bool set = false;
        switch (remote.get_type_id())
        {
        case net::tor_address::get_type_id():
            set = client->set_connect_command(remote.as<net::tor_address>());
            break;
        case net::i2p_address::get_type_id():
            set = client->set_connect_command(remote.as<net::i2p_address>());
            break;
        default:
            MERROR("Unsupported network address in socks_connect");
            return false;
        }

        const bool sent =
            set && net::socks::client::connect_and_send(std::move(client), proxy);
        CHECK_AND_ASSERT_MES(sent, false, "Unexpected failure to init socks client");
        return true;
    }
}

namespace nodetool
{
    const command_line::arg_descriptor<std::string> arg_p2p_bind_ip        = {"p2p-bind-ip", "Interface for p2p network protocol (IPv4)", "0.0.0.0"};
    const command_line::arg_descriptor<std::string> arg_p2p_bind_ipv6_address        = {"p2p-bind-ipv6-address", "Interface for p2p network protocol (IPv6)", "::"};
    const command_line::arg_descriptor<std::string, false, true, 2> arg_p2p_bind_port = {
        "p2p-bind-port"
      , "Port for p2p network protocol (IPv4)"
      , std::to_string(config::P2P_DEFAULT_PORT)
      , {{ &cryptonote::arg_testnet_on, &cryptonote::arg_devnet_on }}
      , [](std::array<bool, 2> testnet_devnet, bool defaulted, std::string val)->std::string {
          if (testnet_devnet[0] && defaulted)
            return std::to_string(config::testnet::P2P_DEFAULT_PORT);
          else if (testnet_devnet[1] && defaulted)
            return std::to_string(config::devnet::P2P_DEFAULT_PORT);
          return val;
        }
      };
    const command_line::arg_descriptor<std::string, false, true, 2> arg_p2p_bind_port_ipv6 = {
        "p2p-bind-port-ipv6"
      , "Port for p2p network protocol (IPv6)"
      , std::to_string(config::P2P_DEFAULT_PORT)
      , {{ &cryptonote::arg_testnet_on, &cryptonote::arg_devnet_on }}
      , [](std::array<bool, 2> testnet_devnet, bool defaulted, std::string val)->std::string {
          if (testnet_devnet[0] && defaulted)
            return std::to_string(config::testnet::P2P_DEFAULT_PORT);
          else if (testnet_devnet[1] && defaulted)
            return std::to_string(config::devnet::P2P_DEFAULT_PORT);
          return val;
        }
      };

    const command_line::arg_descriptor<uint32_t>    arg_p2p_external_port  = {"p2p-external-port", "External port for p2p network protocol (if port forwarding used with NAT)", 0};
    const command_line::arg_descriptor<bool>        arg_p2p_allow_local_ip = {"allow-local-ip", "Allow local ip add to peer list, mostly in debug purposes"};
    const command_line::arg_descriptor<std::vector<std::string> > arg_p2p_add_peer   = {"add-peer", "Manually add peer to local peerlist"};
    const command_line::arg_descriptor<std::vector<std::string> > arg_p2p_add_priority_node   = {"add-priority-node", "Specify list of peers to connect to and attempt to keep the connection open"};
    const command_line::arg_descriptor<std::vector<std::string> > arg_p2p_add_exclusive_node   = {"add-exclusive-node", "Specify list of peers to connect to only."
                                                                                                  " If this option is given the options add-priority-node and seed-node are ignored"};
    const command_line::arg_descriptor<std::vector<std::string> > arg_p2p_seed_node   = {"seed-node", "Connect to a node to retrieve peer addresses, and disconnect"};
    const command_line::arg_descriptor<std::vector<std::string> > arg_tx_proxy = {"tx-proxy", "Send local txes through proxy: <network-type>,<socks-ip:port>[,max_connections][,disable_noise] i.e. \"tor,127.0.0.1:9050,100,disable_noise\""};
    const command_line::arg_descriptor<std::vector<std::string> > arg_anonymous_inbound = {"anonymous-inbound", "<hidden-service-address>,<[bind-ip:]port>[,max_connections] i.e. \"x.onion,127.0.0.1:18083,100\""};
    const command_line::arg_descriptor<bool> arg_p2p_hide_my_port   =    {"hide-my-port", "Do not announce yourself as peerlist candidate", false, true};
    const command_line::arg_descriptor<bool> arg_no_sync = {"no-sync", "Don't synchronize the blockchain with other peers", false};

    const command_line::arg_descriptor<bool>        arg_no_igd  = {"no-igd", "Backwards compatibility option (this is now the default)"};
    const command_line::arg_descriptor<std::string> arg_igd = {"igd", "UPnP port mapping (disabled, enabled, delayed)", "disabled"};
    const command_line::arg_descriptor<bool>        arg_p2p_use_ipv6  = {"p2p-use-ipv6", "Enable IPv6 for p2p", false};
    const command_line::arg_descriptor<bool>        arg_p2p_ignore_ipv4  = {"p2p-ignore-ipv4", "Ignore unsuccessful IPv4 bind for p2p", false};
    const command_line::arg_descriptor<int64_t>     arg_out_peers = {"out-peers", "set max number of out peers", -1};
    const command_line::arg_descriptor<int64_t>     arg_in_peers = {"in-peers", "set max number of in peers", -1};
    const command_line::arg_descriptor<int> arg_tos_flag = {"tos-flag", "set TOS flag", -1};

    const command_line::arg_descriptor<int64_t> arg_limit_rate_up = {"limit-rate-up", "set limit-rate-up [kB/s]", P2P_DEFAULT_LIMIT_RATE_UP};
    const command_line::arg_descriptor<int64_t> arg_limit_rate_down = {"limit-rate-down", "set limit-rate-down [kB/s]", P2P_DEFAULT_LIMIT_RATE_DOWN};
    const command_line::arg_descriptor<int64_t> arg_limit_rate = {"limit-rate", "set limit-rate [kB/s]", -1};

    std::optional<std::vector<proxy>> get_proxies(boost::program_options::variables_map const& vm)
    {
        namespace ip = boost::asio::ip;

        std::vector<proxy> proxies{};

        const std::vector<std::string> args = command_line::get_arg(vm, arg_tx_proxy);
        proxies.reserve(args.size());

        for (std::string_view arg : args)
        {
            auto& set_proxy = proxies.emplace_back();

            auto pieces = tools::split(arg, ","sv);
            CHECK_AND_ASSERT_MES(pieces.size() >= 1 && !pieces[0].empty(), std::nullopt, "No network type for --" << arg_tx_proxy.name);
            CHECK_AND_ASSERT_MES(pieces.size() >= 2 && !pieces[1].empty(), std::nullopt, "No ipv4:port given for --" << arg_tx_proxy.name);
            auto& zone = pieces[0];
            auto& proxy = pieces[1];
            auto it = pieces.begin() + 2;
            if (it != pieces.end() && *it == "disable_noise"sv)
            {
                set_proxy.noise = false;
                ++it;
            }
            if (it != pieces.end())
            {
                set_proxy.max_connections = get_max_connections(*it);
                if (set_proxy.max_connections == 0)
                {
                    MERROR("Invalid max connections given to --" << arg_tx_proxy.name);
                    return std::nullopt;
                }
                ++it;
            }
            if (it != pieces.end())
            {
                MERROR("Too many ',' characters given to --" << arg_tx_proxy.name);
                return std::nullopt;
            }

            switch (epee::net_utils::zone_from_string(zone))
            {
            case epee::net_utils::zone::tor:
                set_proxy.zone = epee::net_utils::zone::tor;
                break;
            case epee::net_utils::zone::i2p:
                set_proxy.zone = epee::net_utils::zone::i2p;
                break;
            default:
                MERROR("Invalid network for --" << arg_tx_proxy.name);
                return std::nullopt;
            }

            std::uint32_t ip = 0;
            std::uint16_t port = 0;
            if (!epee::string_tools::parse_peer_from_string(ip, port, proxy) || port == 0)
            {
                MERROR("Invalid ipv4:port given for --" << arg_tx_proxy.name);
                return std::nullopt;
            }
            set_proxy.address = ip::tcp::endpoint{ip::address_v4{boost::endian::native_to_big(ip)}, port};
        }

        return proxies;
    }

    std::optional<std::vector<anonymous_inbound>> get_anonymous_inbounds(boost::program_options::variables_map const& vm)
    {
        std::vector<anonymous_inbound> inbounds{};

        const std::vector<std::string> args = command_line::get_arg(vm, arg_anonymous_inbound);
        inbounds.reserve(args.size());

        for (std::string_view arg : args)
        {
            auto& set_inbound = inbounds.emplace_back();

            auto pieces = tools::split(arg, ","sv);
            CHECK_AND_ASSERT_MES(pieces.size() >= 1 && !pieces[0].empty(), std::nullopt, "No inbound address for --" << arg_anonymous_inbound.name);
            CHECK_AND_ASSERT_MES(pieces.size() >= 2 && !pieces[1].empty(), std::nullopt, "No local ipv4:port given for --" << arg_anonymous_inbound.name);
            auto& address = pieces[0];
            auto& bind = pieces[1];

            const std::size_t colon = bind.find_first_of(':');
            CHECK_AND_ASSERT_MES(colon < bind.size(), std::nullopt, "No local port given for --" << arg_anonymous_inbound.name);

            if (pieces.size() >= 3)
            {
                set_inbound.max_connections = get_max_connections(pieces[2]);
                if (set_inbound.max_connections == 0)
                {
                    MERROR("Invalid max connections given to --" << arg_tx_proxy.name);
                    return std::nullopt;
                }
            }

            expect<epee::net_utils::network_address> our_address = net::get_network_address(address, 0);
            switch (our_address ? our_address->get_type_id() : epee::net_utils::address_type::invalid)
            {
            case net::tor_address::get_type_id():
                set_inbound.our_address = std::move(*our_address);
                set_inbound.default_remote = net::tor_address::unknown();
                break;
            case net::i2p_address::get_type_id():
                set_inbound.our_address = std::move(*our_address);
                set_inbound.default_remote = net::i2p_address::unknown();
                break;
            default:
                MERROR("Invalid inbound address (" << address << ") for --" << arg_anonymous_inbound.name << ": " << (our_address ? "invalid type" : our_address.error().message()));
                return std::nullopt;
            }

            // get_address returns default constructed address on error
            if (set_inbound.our_address == epee::net_utils::network_address{})
                return std::nullopt;

            std::uint32_t ip = 0;
            std::uint16_t port = 0;
            if (!epee::string_tools::parse_peer_from_string(ip, port, bind))
            {
                MERROR("Invalid ipv4:port given for --" << arg_anonymous_inbound.name);
                return std::nullopt;
            }
            set_inbound.local_ip = bind.substr(0, colon);
            set_inbound.local_port = bind.substr(colon + 1);
        }

        return inbounds;
    }

    bool is_filtered_command(const epee::net_utils::network_address& address, int command)
    {
        switch (command)
        {
        case nodetool::COMMAND_HANDSHAKE_T<cryptonote::CORE_SYNC_DATA>::ID:
        case nodetool::COMMAND_TIMED_SYNC_T<cryptonote::CORE_SYNC_DATA>::ID:
        case cryptonote::NOTIFY_NEW_TRANSACTIONS::ID:
            return false;
        default:
            break;
        }

        if (address.get_zone() == epee::net_utils::zone::public_)
            return false;

        MWARNING("Filtered command (#" << command << ") to/from " << address.str());
        return true;
    }

    std::optional<boost::asio::ip::tcp::socket>
    socks_connect_internal(const std::atomic<bool>& stop_signal, boost::asio::io_service& service, const boost::asio::ip::tcp::endpoint& proxy, const epee::net_utils::network_address& remote)
    {
        using socket_type = net::socks::client::stream_type::socket;
        using client_result = std::pair<boost::system::error_code, socket_type>;

        struct notify
        {
            std::promise<client_result> socks_promise;

            void operator()(boost::system::error_code error, socket_type&& sock)
            {
                socks_promise.set_value(std::make_pair(error, std::move(sock)));
            }
        };

        std::future<client_result> socks_result{};
        {
            std::promise<client_result> socks_promise{};
            socks_result = socks_promise.get_future();

            auto client = net::socks::make_connect_client(
                boost::asio::ip::tcp::socket{service}, net::socks::version::v4a, notify{std::move(socks_promise)}
             );
            if (!start_socks(std::move(client), proxy, remote))
                return std::nullopt;
        }

        const auto start = std::chrono::steady_clock::now();
        while (socks_result.wait_for(future_poll_interval) == std::future_status::timeout)
        {
            if (socks_connect_timeout < std::chrono::steady_clock::now() - start)
            {
                MERROR("Timeout on socks connect (" << proxy << " to " << remote.str() << ")");
                return std::nullopt;
            }

            if (stop_signal)
                return std::nullopt;
        }

        try
        {
            auto result = socks_result.get();
            if (!result.first)
                return {std::move(result.second)};

            MERROR("Failed to make socks connection to " << remote.str() << " (via " << proxy << "): " << result.first.message());
        }
        catch (const std::future_error&)
        {}

        return std::nullopt;
    }
}
