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

#include <array>
#include <boost/serialization/version.hpp>
#include <cstring>
#include <span>
#include <stdexcept>

#include "common/ipv4.h"
#include "net/address.h"
#include "p2p/p2p_protocol_defs.h"

BOOST_CLASS_VERSION(nodetool::peerlist_entry, 6)

namespace nodetool::detail {
// The p2pstate file has an address's IP and port inside nested objects, and boost archives write
// class info for each class at its first appearance; these mirror the classes that the address was
// serialized through (an IPv4 address; an IPv6 address holding a boost::asio address_v6) to keep
// the file's format.
struct legacy_ipv4 {
    uint32_t ip;  // see tools::ipv4_to_legacy_int
    uint16_t port;
};
struct legacy_ipv6_bytes {
    std::array<uint8_t, 16> bytes;
};
struct legacy_ipv6 {
    legacy_ipv6_bytes ip;
    uint16_t port;
};
}  // namespace nodetool::detail

namespace boost::serialization {
template <class Archive>
void serialize(Archive& a, nodetool::detail::legacy_ipv4& v, const unsigned int) {
    a & v.ip;
    a & v.port;
}
template <class Archive>
void serialize(Archive& a, nodetool::detail::legacy_ipv6_bytes& v, const unsigned int) {
    for (auto& b : v.bytes)
        a & b;
}
template <class Archive>
void serialize(Archive& a, nodetool::detail::legacy_ipv6& v, const unsigned int) {
    a & v.ip;
    a & v.port;
}

template <class Archive>
void serialize(Archive& a, oxen::quic::Address& addr, const unsigned int) {
    constexpr bool saving = Archive::is_saving::value;

    uint8_t type = saving ? static_cast<uint8_t>(net::type_of(addr)) : 0;
    a & type;
    switch (net::address_type{type}) {
        case net::address_type::ipv4: {
            nodetool::detail::legacy_ipv4 v{};
            if (saving)
                v = {tools::ipv4_to_legacy_int(addr.to_ipv4()), addr.port()};
            a & v;
            if (!saving)
                addr = oxen::quic::Address{tools::ipv4_from_legacy_int(v.ip), v.port};
            break;
        }
        case net::address_type::ipv6: {
            nodetool::detail::legacy_ipv6 v{};
            if (saving) {
                std::memcpy(v.ip.bytes.data(), addr.in6().sin6_addr.s6_addr, v.ip.bytes.size());
                v.port = addr.port();
            }
            a & v;
            if (!saving)
                addr = oxen::quic::Address{oxen::quic::ipv6{std::span{v.ip.bytes}}, v.port};
            break;
        }
        default: throw std::runtime_error("Unsupported network address type");
    }
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
