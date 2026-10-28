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
#include <atomic>
#include <chrono>
#include <concepts>
#include <map>
#include <optional>
#include <oxen/quic/address.hpp>
#include <unordered_set>
#include <vector>

#include "common/format.h"
#include "connection_id.h"
#include "crypto/hash.h"
#include "fmt/format.h"

using namespace std::literals;

namespace cryptonote {

struct cryptonote_connection_context {
    cryptonote_connection_context() = default;
    cryptonote_connection_context(
            connection_id_t connection_id,
            const oxen::quic::Address& remote_address,
            bool is_income) :
            m_connection_id{connection_id},
            m_remote_address{remote_address},
            m_is_income{is_income} {}

    const connection_id_t m_connection_id{};
    const oxen::quic::Address m_remote_address{};
    const bool m_is_income = false;
    std::chrono::steady_clock::time_point m_started = std::chrono::steady_clock::now();
    std::chrono::steady_clock::time_point m_last_recv =
            std::chrono::steady_clock::time_point::min();
    std::chrono::steady_clock::time_point m_last_send =
            std::chrono::steady_clock::time_point::min();
    uint64_t m_recv_cnt = 0;
    uint64_t m_send_cnt = 0;
    double m_current_speed_down = 0;
    double m_current_speed_up = 0;
    double m_max_speed_down = 0;
    double m_max_speed_up = 0;

    enum state {
        state_before_handshake = 0,  // default state
        state_synchronizing,
        state_standby,
        state_normal
    };

    state m_state{state_before_handshake};
    std::vector<crypto::hash> m_needed_objects;
    std::unordered_set<crypto::hash> m_requested_objects;
    // True while a NOTIFY_REQUEST_CHAIN to the peer awaits its response.
    bool m_chain_requested{false};

    // True if a request to the peer (for the chain, or for blocks or txes) awaits its response,
    // which is what carries the sync with this peer on: until it arrives, another request would
    // leave two outstanding.
    bool request_outstanding() const { return m_chain_requested || !m_requested_objects.empty(); }
    std::map<uint64_t, std::pair<crypto::hash, bool>>
            m_blink_state;  // HEIGHT => {CHECKSUM, NEEDED}
    bool m_need_blink_sync{false};
    uint64_t m_remote_blockchain_height{0};
    // The peer's advertised history (see CORE_SYNC_DATA::history): 0 if it has every block;
    // nullopt until its sync data has said (or if it never does).
    std::optional<uint64_t> m_history;
    uint64_t m_last_response_height{0};
    std::optional<std::chrono::steady_clock::time_point> m_last_request_time;
    crypto::hash m_last_known_hash{};
    bool m_anchor{false};
    // size_t m_score{0};  TODO: add score calculations
};

constexpr std::string_view get_protocol_state_string(cryptonote_connection_context::state s) {
    switch (s) {
        case cryptonote_connection_context::state_before_handshake: return "before_handshake"sv;
        case cryptonote_connection_context::state_synchronizing: return "synchronizing"sv;
        case cryptonote_connection_context::state_standby: return "standby"sv;
        case cryptonote_connection_context::state_normal: return "normal"sv;
        default: return "unknown"sv;
    }
}

constexpr char get_protocol_state_char(cryptonote_connection_context::state s) {
    switch (s) {
        case cryptonote_connection_context::state_before_handshake: return 'h';
        case cryptonote_connection_context::state_synchronizing: return 's';
        case cryptonote_connection_context::state_standby: return 'w';
        case cryptonote_connection_context::state_normal: return 'n';
        default: return 'u';
    }
}

}  // namespace cryptonote

// Formats a connection (as the prefix of a log message about it) as e.g. "[1.2.3.4:22022 OUT]"
template <std::derived_from<cryptonote::cryptonote_connection_context> T, typename Char>
struct fmt::formatter<T, Char> : fmt::formatter<std::string_view> {
    auto format(const cryptonote::cryptonote_connection_context& c, format_context& ctx) const {
        return formatter<std::string_view>::format(
                fmt::format(
                        "[{} {}]", c.m_remote_address.to_string(), c.m_is_income ? "INC" : "OUT"),
                ctx);
    }
};
