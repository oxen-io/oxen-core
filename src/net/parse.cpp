// Copyright (c) 2019, The Monero Project
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

#include "parse.h"

#include <boost/version.hpp>

#include "common/string_util.h"
#include "net/error.h"
#include "net/ipv4_address.h"

namespace net {
std::pair<std::string_view, std::string_view> get_network_address_host_and_port(
        std::string_view address) {
    std::pair<std::string_view, std::string_view> result;
    auto& [host, port] = result;
    // require ipv6 address format "[addr:addr:addr:...:addr]:port"
    if (address.find(']') != std::string_view::npos) {
        host = address.substr(1, address.rfind(']') - 1);
        if ((host.size() + 2) < address.size()) {
            port = address.substr(address.rfind(':') + 1);
        }
    } else {
        host = address.substr(0, address.rfind(':'));
        if (host.size() < address.size()) {
            port = address.substr(host.size() + 1);
        }
    }
    return result;
}

expect<epee::net_utils::network_address> get_network_address(
        std::string_view address, const std::uint16_t default_port) {
    bool ipv6 = false;

    auto [host_str, port_str] = get_network_address_host_and_port(address);

    if (host_str.empty())
        return make_error_code(net::error::invalid_host);

    boost::system::error_code ec;
#if BOOST_VERSION >= 106600
    auto v6 = boost::asio::ip::make_address_v6(host_str, ec);
#else
    auto v6 = boost::asio::ip::address_v6::from_string(std::string{host_str}, ec);
#endif
    ipv6 = !ec;

    std::uint16_t port = default_port;
    if (port_str.size()) {
        if (!tools::parse_int(port_str, port))
            return make_error_code(net::error::invalid_port);
    }

    if (ipv6)
        return {epee::net_utils::ipv6_network_address{v6, port}};

    try {
        return {ipv4_address{oxen::quic::ipv4{std::string{host_str}}, port}};
    } catch (const std::invalid_argument&) {
        return make_error_code(net::error::unsupported_address);
    }
}
}  // namespace net
