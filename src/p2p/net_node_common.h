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

#include <oxen/quic/ip.hpp>
#include <span>
#include <utility>
#include <vector>

#include "cryptonote_basic/connection_context.h"
#include "epee/net/net_utils_base.h"
#include "p2p_protocol_defs.h"

namespace nodetool {

using cryptonote::cryptonote_connection_context;
using epee::connection_id_t;

struct i_p2p_endpoint {
    virtual bool relay_notify_to_list(
            int command,
            const std::span<const uint8_t> data_buff,
            std::span<const connection_id_t> connections) = 0;
    // Safe to call from any thread.
    virtual bool invoke_notify_to_peer(
            int command, const std::span<const uint8_t> req_buff, const connection_id_t& id) = 0;
    virtual bool drop_connection(const epee::net_utils::connection_context_base& context) = 0;
    virtual void request_callback(const epee::net_utils::connection_context_base& context) = 0;
    // Calls `f` with the connection's context on the thread that handles the connection's
    // messages, after what is already queued there, unless the connection has closed by then.
    // Safe to call from any thread.
    virtual void call_on_connection(
            const connection_id_t& id, std::function<void(cryptonote_connection_context&)> f) = 0;
    virtual uint64_t get_public_connections_count() = 0;
    virtual void for_each_connection(
            std::function<bool(cryptonote_connection_context&, peerid_type)> f) = 0;
    virtual bool for_connection(
            const connection_id_t&,
            std::function<bool(cryptonote_connection_context&, peerid_type)> f) = 0;
    virtual bool block_host(const oxen::quic::Address& address, time_t seconds = 0) = 0;
    virtual bool unblock_host(const oxen::quic::Address& address) = 0;
    virtual std::map<std::string, time_t> get_blocked_hosts() = 0;
    virtual std::map<oxen::quic::ipv4_range, time_t> get_blocked_subnets() = 0;
    virtual bool add_host_fail(const oxen::quic::Address& address) = 0;
};

struct p2p_endpoint_stub : public i_p2p_endpoint {
    virtual bool relay_notify_to_list(
            int command,
            const std::span<const uint8_t> data_buff,
            std::span<const connection_id_t> connections) {
        return false;
    }
    virtual bool invoke_notify_to_peer(
            int command, const std::span<const uint8_t> req_buff, const connection_id_t& id) {
        return true;
    }
    virtual bool drop_connection(const epee::net_utils::connection_context_base& context) {
        return false;
    }
    virtual void request_callback(const epee::net_utils::connection_context_base& context) {}
    virtual void call_on_connection(
            const connection_id_t& id, std::function<void(cryptonote_connection_context&)> f) {}
    virtual void for_each_connection(
            std::function<bool(cryptonote_connection_context&, peerid_type)> f) {}
    virtual bool for_connection(
            const connection_id_t&,
            std::function<bool(cryptonote_connection_context&, peerid_type)> f) {
        return false;
    }

    virtual uint64_t get_public_connections_count() { return false; }
    virtual bool block_host(const oxen::quic::Address& address, time_t seconds) { return true; }
    virtual bool unblock_host(const oxen::quic::Address& address) { return true; }
    virtual std::map<std::string, time_t> get_blocked_hosts() {
        return std::map<std::string, time_t>();
    }
    virtual std::map<oxen::quic::ipv4_range, time_t> get_blocked_subnets() { return {}; }
    virtual bool add_host_fail(const oxen::quic::Address& address) { return true; }
};
}  // namespace nodetool
