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

#pragma once

#include <common/exception.h>

#include <boost/mpl/bool.hpp>

#include "common/ipv4.h"
#include "epee/net/net_utils_base.h"
#include "net/ipv4_address.h"
#include "p2p/p2p_protocol_defs.h"

BOOST_CLASS_VERSION(nodetool::peerlist_entry, 6)

namespace boost::serialization {
template <class T, class Archive>
inline void do_serialize(boost::mpl::false_, Archive& a, epee::net_utils::network_address& na) {
    T addr{};
    a & addr;
    na = std::move(addr);
}

template <class T, class Archive>
inline void do_serialize(
        boost::mpl::true_, Archive& a, const epee::net_utils::network_address& na) {
    a & na.as<T>();
}

template <class Archive, class ver_type>
inline void serialize(Archive& a, epee::net_utils::network_address& na, const ver_type ver) {
    static constexpr const typename Archive::is_saving is_saving{};

    uint8_t type;
    if (is_saving)
        type = uint8_t(na.get_type_id());
    a & type;
    switch (epee::net_utils::address_type(type)) {
        case net::ipv4_address::get_type_id():
            do_serialize<net::ipv4_address>(is_saving, a, na);
            break;
        case epee::net_utils::ipv6_network_address::get_type_id():
            do_serialize<epee::net_utils::ipv6_network_address>(is_saving, a, na);
            break;
        case epee::net_utils::address_type::invalid:
        default: throw oxen::traced<std::runtime_error>("Unsupported network address type");
    }
}
template <class Archive, class ver_type>
inline void serialize(Archive& a, net::ipv4_address& na, const ver_type ver) {
    uint32_t ip = tools::ipv4_to_legacy_int(na.ip());
    uint16_t port{na.port()};
    a & ip;
    a & port;
    if (!typename Archive::is_saving())
        na = net::ipv4_address{tools::ipv4_from_legacy_int(ip), port};
}

template <class Archive, class ver_type>
inline void serialize(Archive& a, boost::asio::ip::address_v6& v6, const ver_type ver) {
    if (typename Archive::is_saving()) {
        auto bytes = v6.to_bytes();
        for (auto& e : bytes)
            a & e;
    } else {
        boost::asio::ip::address_v6::bytes_type bytes;
        for (auto& e : bytes)
            a & e;
        v6 = boost::asio::ip::address_v6(bytes);
    }
}

template <class Archive, class ver_type>
inline void serialize(Archive& a, epee::net_utils::ipv6_network_address& na, const ver_type ver) {
    boost::asio::ip::address_v6 ip{na.ip()};
    uint16_t port{na.port()};
    a & ip;
    a & port;
    if (!typename Archive::is_saving())
        na = epee::net_utils::ipv6_network_address{ip, port};
}

template <class Archive, class ver_type>
inline void serialize(Archive& a, nodetool::peerlist_entry& pl, const ver_type ver) {
    a & pl.adr;
    a & pl.id;
    a & pl.last_seen;
    // Versions 1 to 3 had an (always unused) pruning seed, and version 2 an unused rpc port too,
    // which are only ever read: anything saved now is the current version.
    //
    // ver can be a boost::serialization::version_type, whose boost::operators comparisons with an
    // integer (other than <) recurse forever, so it is compared as a plain integer.
    const unsigned version = ver;
    if (version >= 1 && version < 4) {
        uint32_t pruning_seed = 0;
        a & pruning_seed;
    }
    if (version == 2) {
        uint16_t rpc_port = 0;
        a & rpc_port;
    }
    if (version == 5) {
        // Version 5 could not tell a peer that never said what it keeps from one keeping every
        // block: both were 0.
        uint64_t history = 0;
        a & history;
        if (history)
            pl.history = history;
        else
            pl.history.reset();
    } else if (version >= 6) {
        // As a flag and a value, rather than through boost/serialization/optional.hpp, which only
        // handles std::optional in newer Boost versions than some builds have.
        bool has_history = pl.history.has_value();
        a & has_history;
        if (has_history) {
            uint64_t history = pl.history.value_or(0);
            a & history;
            pl.history = history;
        } else {
            pl.history.reset();
        }
    }
}

template <class Archive, class ver_type>
inline void serialize(Archive& a, nodetool::anchor_peerlist_entry& pl, const ver_type ver) {
    a & pl.adr;
    a & pl.id;
    a & pl.first_seen;
}
}  // namespace boost::serialization
