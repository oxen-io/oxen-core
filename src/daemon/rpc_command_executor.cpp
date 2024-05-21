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

#include "daemon/rpc_command_executor.h"

#include <fmt/chrono.h>
#include <fmt/core.h>
#include <oxenc/base32z.h>
#include <oxenc/variant.h>
#include <oxenmq/connections.h>

#include <chrono>
#include <ctime>
#include <exception>
#include <fstream>
#include <iterator>
#include <numeric>
#include <stack>
#include <string>
#include <type_traits>

#include "checkpoints/checkpoints.h"
#include "common/hex.h"
#include "common/median.h"
#include "common/password.h"
#include "common/pruning.h"
#include "common/scoped_message_writer.h"
#include "common/string_util.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_config.h"
#include "cryptonote_core/service_node_rules.h"
#include "epee/int-util.h"
#include "epee/string_tools.h"
#include "oxen_economy.h"
#include "rpc/core_rpc_server_commands_defs.h"

using namespace cryptonote::rpc;
using cryptonote::hf;

using nlohmann::json;

namespace daemonize {

namespace {
    enum class input_line_result {
        yes,
        no,
        cancel,
        back,
    };

    template <typename... Args>
    std::string input_line(Args&&... prompt) {
        rdln::suspend_readline pause_readline;
        (std::cout << ... << prompt) << std::flush;
        std::string result;
        std::getline(std::cin, result);

        return result;
    }

    input_line_result input_line_ask(std::string_view msg) {
        auto input = input_line(msg, " (Y/Yes/N/No/B/Back/C/Cancel): ");

        if (command_line::is_yes(input))
            return input_line_result::yes;
        if (command_line::is_no(input))
            return input_line_result::no;
        if (command_line::is_back(input))
            return input_line_result::back;
        return input_line_result::cancel;
    }

    std::pair<input_line_result, std::string> input_line_value(
            std::string_view msg,
            bool back = true,
            const std::string& extra_opt = "",
            const std::string& default_ = "") {
        std::string_view end = ""sv;
        if (msg.back() == '\n') {
            end = "\n"sv;
            msg.remove_suffix(1);
        }
        auto input = input_line(
                msg,
                (back ? " (B/Back/C/Cancel" : " (C/Cancel") + extra_opt + ")" +
                        (!default_.empty() ? " [" + default_ + "]" : "") + ": ",
                end);

        return {back && command_line::is_back(input) ? input_line_result::back
                : command_line::is_cancel(input)     ? input_line_result::cancel
                                                     : input_line_result::yes,
                input.empty() ? default_ : input};
    }

    void print_block_header(block_header_response const& header) {
        tools::success_msg_writer(
                R"(timestamp: {} ({})
previous hash: {}
nonce: {}
is orphan: {}
height: {}
depth: {}
hash: {}
difficulty: {}
cumulative_difficulty: {}
POW hash: {}
block size: {}
block weight: {}
long term weight: {}
num txes: {}
reward: {}
coinbase payouts: {}
service node winner: {}
miner tx hash: {})",
                header.timestamp,
                tools::get_human_readable_timestamp(header.timestamp),
                header.prev_hash,
                header.nonce,
                header.orphan_status,
                header.height,
                header.depth,
                header.hash,
                header.difficulty,
                header.cumulative_difficulty,
                header.pow_hash.value_or("N/A"),
                header.block_size,
                header.block_weight,
                header.long_term_weight,
                header.num_txes,
                cryptonote::print_money(header.reward),
                cryptonote::print_money(header.coinbase_payouts),
                header.service_node_winner,
                header.miner_tx_hash);
    }

    template <typename Rep, typename Period>
    std::string get_human_time_ago(
            std::chrono::duration<Rep, Period> ago_dur, bool abbreviate = false) {
        auto ago = std::chrono::duration_cast<std::chrono::seconds>(ago_dur);
        if (ago == 0s)
            return "now";
        auto dt = ago > 0s ? ago : -ago;
        std::string s;
        if (dt < 90s)
            s = std::to_string(dt.count()) + (abbreviate ? "sec"
                                              : dt == 1s ? " second"
                                                         : " seconds");
        else if (dt < 90min)
            s = "{:.1f}{:s}"_format(dt.count() / 60.0, abbreviate ? "min" : " minutes");
        else if (dt < 36h)
            s = "{:.1f}{:s}"_format(dt.count() / 3600.0, abbreviate ? "hr" : " hours");
        else
            s = "{:.1f} days"_format(dt.count() / 86400.0);
        if (abbreviate) {
            if (ago < 0s)
                s += " (in fut.)";
        } else {
            s += ' ';
            s += (ago < 0s ? "in the future" : "ago");
        }
        return s;
    }

    std::string get_human_time_ago(std::time_t t, std::time_t now, bool abbreviate = false) {
        return get_human_time_ago(std::chrono::seconds{now - t}, abbreviate);
    }

    bool print_peer(std::string_view prefix, const json& peer, bool pruned_only) {
        auto pruning_seed = peer.value<uint64_t>("pruning_seed", 0);
        if (pruned_only && pruning_seed == 0)
            return false;

        time_t now = std::time(nullptr);
        time_t last_seen = peer.value<time_t>("last_seen", 0);

        tools::msg_writer(
                "{:<10} {:016x}    {:<30} {}",
                prefix,
                peer["id"].get<uint64_t>(),
                "{}:{}"_format(peer["host"].get<std::string_view>(), peer["port"].get<uint16_t>()),
                last_seen == 0 ? "never" : get_human_time_ago(last_seen, now));
        return true;
    }

    template <typename... Args>
    void print_peers(std::string_view prefix, const json& peers, size_t& limit, Args&&... args) {
        if (limit > 0)
            tools::msg_writer(
                    "{:<10} {:<16}    {:<30} {}", "Type", "Peer id", "Remote address", "Last seen");
        for (auto it = peers.begin(); it != peers.end() && limit > 0; it++)
            if (print_peer(prefix, *it, std::forward<Args>(args)...))
                limit--;
    }

}  // namespace

rpc_command_executor::rpc_command_executor(
        std::string http_url, const std::optional<tools::login>& login) :
        m_rpc{std::in_place_type<cryptonote::rpc::http_client>, http_url} {
    if (login)
        var::get<cryptonote::rpc::http_client>(m_rpc).set_auth(
                login->username, std::string{login->password.password().view()});
}

rpc_command_executor::rpc_command_executor(oxenmq::OxenMQ& omq, oxenmq::ConnectionID conn) :
        m_rpc{std::move(conn)}, m_omq{&omq} {}

template <typename Callback>
static auto try_running(Callback code, std::string_view error_prefix)
        -> std::optional<decltype(code())> {
    try {
        return code();
    } catch (const std::exception& e) {
        tools::fail_msg_writer("{}: {}", error_prefix, e.what());
        return std::nullopt;
    }
}

json rpc_command_executor::invoke(
        std::string_view method,
        bool public_method,
        std::optional<json> params,
        bool check_status_ok) {

    json result;

    if (auto* rpc_client = std::get_if<cryptonote::rpc::http_client>(&m_rpc)) {
        result = rpc_client->json_rpc(method, std::move(params));
    } else {
        assert(m_omq);
        auto conn = var::get<oxenmq::ConnectionID>(m_rpc);
        auto endpoint = (public_method ? "rpc." : "admin.") + std::string{method};
        std::promise<json> result_p;
        m_omq->request(
                conn,
                endpoint,
                [&result_p](bool success, auto data) {
                    try {
                        if (!success)
                            throw std::runtime_error{"Request timed out"};
                        if (data.size() >= 2 && data[0] == "200")
                            result_p.set_value(json::parse(data[1]));
                        else
                            throw std::runtime_error{
                                    "RPC method failed: " +
                                    (data.empty() ? "empty response" : tools::join(" ", data))};
                    } catch (...) {
                        result_p.set_exception(std::current_exception());
                    }
                },
                params ? params->dump() : "{}");

        result = result_p.get_future().get();
    }

    if (check_status_ok) {
        if (auto it = result.find("status");
            it == result.end() || it->get<std::string_view>() != cryptonote::rpc::STATUS_OK)
            throw std::runtime_error{
                    "Received status " +
                    (it == result.end() ? "(empty)" : it->get_ref<const std::string&>()) +
                    " != OK"};
    }

    return result;
}

bool rpc_command_executor::print_checkpoints(
        std::optional<uint64_t> start_height, std::optional<uint64_t> end_height, bool print_json) {

    uint32_t count = 0;
    if (!start_height && !end_height)
        count = GET_CHECKPOINTS::NUM_CHECKPOINTS_TO_QUERY_BY_DEFAULT;
    else if (!start_height || !end_height)
        count = 1;
    // Otherwise, both start/end are set so get all the checkpoints between start and end

    auto maybe_checkpoints = try_running(
            [&] {
                json params{{"count", count}};
                if (start_height)
                    params["start_height"] = *start_height;
                if (end_height)
                    params["end_height"] = *end_height;
                return invoke<GET_CHECKPOINTS>(std::move(params));
            },
            "Failed to query blockchain checkpoints");
    if (!maybe_checkpoints)
        return false;

    auto checkpoints = *maybe_checkpoints;

    std::string entry;
    auto entry_append = std::back_inserter(entry);
    if (print_json)
        entry.append(checkpoints.dump());
    else {
        for (size_t i = 0; i < checkpoints.size(); i++) {
            auto& cp = checkpoints[i];
            fmt::format_to(
                    entry_append,
                    "[{}] Type: {} Height: {} Hash: {}\n",
                    i,
                    cp["type"].get<std::string_view>(),
                    cp["height"].get<int64_t>(),
                    cp["block_hash"].get<std::string_view>());
        }
        if (entry.empty())
            entry.append("No Checkpoints");
    }

    tools::success_msg_writer() + entry;
    return true;
}

bool rpc_command_executor::print_sn_state_changes(
        uint64_t start_height, std::optional<uint64_t> end_height) {
    auto maybe_sn_state = try_running(
            [&] {
                json params{{"start_height", start_height}};
                if (end_height)
                    params["end_height"] = *end_height;
                return invoke<GET_SN_STATE_CHANGES>(std::move(params));
            },
            "Failed to query service node state changes");
    if (!maybe_sn_state)
        return false;

    auto sn_state_changes = *maybe_sn_state;

    auto writer = tools::success_msg_writer();

    writer.append(
            "Service Node State Changes (blocks {}-{})\n",
            sn_state_changes["start_height"].get<std::string_view>(),
            sn_state_changes["end_height"].get<std::string_view>());
    writer.append(
            " Recommissions:       {}",
            sn_state_changes["total_recommission"].get<std::string_view>());
    writer.append(
            " Unlocks:             {}", sn_state_changes["total_unlock"].get<std::string_view>());
    writer.append(
            " Decommissions:       {}",
            sn_state_changes["total_decommission"].get<std::string_view>());
    writer.append(
            " Deregistrations:     {}",
            sn_state_changes["total_deregister"].get<std::string_view>());
    writer.append(
            " IP change penalties: {}",
            sn_state_changes["total_ip_change_penalty"].get<std::string_view>());

    return true;
}

bool rpc_command_executor::print_peer_list(bool white, bool gray, size_t limit, bool pruned_only) {
    auto maybe_pl =
            try_running([this] { return invoke<GET_PEER_LIST>(); }, "Failed to retrieve peer list");
    if (!maybe_pl)
        return false;
    auto& pl = *maybe_pl;

    if (!limit)
        limit = std::numeric_limits<size_t>::max();
    if (white) {
        tools::success_msg_writer("{} whitelist peers:", pl["white_list"].size());
        print_peers("white", pl["white_list"], limit, pruned_only);
    }
    if (gray) {
        tools::success_msg_writer("{} graylist peers:", pl["gray_list"].size());
        print_peers("gray", pl["gray_list"], limit, pruned_only);
    }

    return true;
}

bool rpc_command_executor::print_peer_list_stats() {
    auto maybe_info =
            try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
    if (!maybe_info)
        return false;
    auto& info = *maybe_info;

    auto wls = info.find("white_peerlist_size");
    auto gls = info.find("grey_peerlist_size");
    if (wls == info.end() || gls == info.end()) {
        tools::fail_msg_writer("Failed to retrieve whitelist info");
        return false;
    }

    tools::msg_writer(
            "White list size: {}/{} ({:.1f}%)\nGray list size: {}/{} ({:.1f}%)",
            wls->get<int>(),
            cryptonote::p2p::LOCAL_WHITE_PEERLIST_LIMIT,
            wls->get<int>() * 100.0 / cryptonote::p2p::LOCAL_WHITE_PEERLIST_LIMIT,
            gls->get<int>(),
            cryptonote::p2p::LOCAL_GRAY_PEERLIST_LIMIT,
            gls->get<int>() * 100.0 / cryptonote::p2p::LOCAL_GRAY_PEERLIST_LIMIT);

    return true;
}

bool rpc_command_executor::save_blockchain() {
    return invoke_simple<SAVE_BC>("Couldn't save blockchain", "Blockchain saved");
}

bool rpc_command_executor::show_difficulty() {
    auto maybe_info =
            try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
    if (!maybe_info)
        return false;
    auto& info = *maybe_info;

    auto msg = tools::success_msg_writer(
            "HEIGHT: {}, HASH: {}",
            info["height"].get<uint64_t>(),
            info["top_block_hash"].get<std::string_view>());
    if (info.value("pulse", false))
        msg += ", PULSE";
    else
        msg.append(
                ", DIFF: {}, CUM_DIFF: {}, HR: {} H/s",
                info["difficulty"].get<uint64_t>(),
                info["cumulative_difficulty"].get<uint64_t>(),
                info["difficulty"].get<uint64_t>() / info["target"].get<uint64_t>());

    return true;
}

static std::string get_mining_speed(uint64_t hr) {
    if (hr >= 1e9)
        return "{:.2f} GH/s"_format(hr * 1e-9);
    if (hr >= 1e6)
        return "{:.2f} MH/s"_format(hr * 1e-6);
    if (hr >= 1e3)
        return "{:.2f} kH/s"_format(hr * 1e-3);
    return "{:d} H/s"_format(hr);
}

static tools::scoped_message_writer& print_fork_extra_info(
        tools::scoped_message_writer& msg,
        uint64_t t,
        uint64_t now,
        std::chrono::seconds block_time) {
    double blocks_per_day = 24h / block_time;

    if (t == now)
        return msg += " (forking now)";
    if (t < now)
        return msg;
    uint64_t dblocks = t - now;
    if (dblocks > blocks_per_day * 30)
        return msg;
    msg.append(" (next fork in ");
    if (dblocks <= 30)
        return msg.append("{} blocks)", dblocks);
    if (dblocks <= blocks_per_day / 2)
        return msg.append("{:.1f} hours)", dblocks / blocks_per_day * 24);
    return msg.append("{:.1f} days)", dblocks / blocks_per_day);
}

static float get_sync_percentage(uint64_t height, uint64_t target_height) {
    target_height = target_height ? target_height < height ? height : target_height : height;
    float pc = 100.0f * height / target_height;
    if (height < target_height && pc > 99.9f)
        return 99.9f;  // to avoid 100% when not fully synced
    return pc;
}

bool rpc_command_executor::show_status() {
    auto maybe_info =
            try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
    if (!maybe_info)
        return false;
    auto& info = *maybe_info;

    auto maybe_hf = try_running(
            [this] { return invoke<HARD_FORK_INFO>(); }, "Failed to retrieve hard fork info");
    if (!maybe_hf)
        return false;
    auto& hfinfo = *maybe_hf;
    bool has_mining_info = false, mining_active = false;
    long mining_hashrate = 0;

    bool mining_busy = false;
    bool restricted_response = false;
    if (auto it = info.find("start_time");
        it != info.end() &&
        it->get<uint64_t>() > 0)  // This will only be non-null if we were recognized as admin
                                  // (which we need for mining info)
    {
        restricted_response = true;
        if (auto maybe_mining_info = try_running(
                    [this] { return invoke<MINING_STATUS>(false); },
                    "Failed to retrieve mining info")) {
            has_mining_info = true;
            auto& mres = *maybe_mining_info;
            if (mres["status"] == STATUS_BUSY)
                mining_busy = true;
            else if (mres["status"] != STATUS_OK) {
                tools::fail_msg_writer("Failed to retrieve mining info");
                return false;
            } else {
                mining_active = mres["active"].get<bool>();
                if (mining_active)
                    mining_hashrate = mres["speed"].get<long>();
            }
        } else {
            return false;
        }
    }

    std::string my_sn_key;
    int64_t my_decomm_remaining = 0;
    uint64_t my_sn_last_uptime = 0;
    bool my_sn_registered = false, my_sn_staked = false, my_sn_active = false;
    uint16_t my_reason_all = 0, my_reason_any = 0;
    if (info["service_node"].get<bool>()) {
        auto maybe_service_keys = try_running(
                [this] { return invoke<GET_SERVICE_KEYS>(json{}); },
                "Failed to retrieve service node keys");
        if (!maybe_service_keys)
            return false;

        my_sn_key = (*maybe_service_keys)["service_node_pubkey"];

        auto maybe_sns = try_running(
                [&] {
                    return invoke<GET_SERVICE_NODES>(
                            json{{"service_node_pubkeys", json::array({my_sn_key})}});
                },
                "Failed to retrieve service node info");
        if (maybe_sns) {
            if (auto it = maybe_sns->find("service_node_states");
                it != maybe_sns->end() && it->is_array() && it->size() > 0) {
                auto& state = it->front();
                my_sn_registered = true;
                my_sn_staked = state["total_contributed"].get<uint64_t>() >=
                               state["staking_requirement"].get<uint64_t>();
                my_sn_active = state["active"].get<bool>();
                my_decomm_remaining = state["earned_downtime_blocks"].get<uint64_t>();
                my_sn_last_uptime = state["last_uptime_proof"].get<uint64_t>();
                my_reason_all = state["last_decommission_reason_consensus_all"].get<uint16_t>();
                my_reason_any = state["last_decommission_reason_consensus_any"].get<uint16_t>();
            }
        }
    }

    uint64_t height = info["height"].get<uint64_t>();
    uint64_t net_height = std::max(info["target_height"].get<uint64_t>(), height);

    auto msg = tools::success_msg_writer("Height: {}", height);
    if (height != net_height)
        msg.append("/{} ({:.1f}%)", net_height, get_sync_percentage(height, net_height));

    auto net = info["nettype"].get<std::string_view>();
    if (net == "testnet")
        msg += " ON TESTNET";
    else if (net == "devnet")
        msg += " ON DEVNET";

    if (height < net_height)
        msg += ", syncing";

    auto hf_version = hfinfo["version"].get<cryptonote::hf>();
    if (hf_version < cryptonote::feature::PULSE && !has_mining_info)
        msg += ", mining info unavailable";
    if (has_mining_info && !mining_busy && mining_active)
        msg.append(", mining at {}", get_mining_speed(mining_hashrate));

    if (hf_version < cryptonote::feature::PULSE)
        msg.append(
                ", net hash {}",
                get_mining_speed(
                        info["difficulty"].get<uint64_t>() / info["target"].get<uint64_t>()));

    msg.append(
            ", v{}(net v{})",
            info["version"].get<std::string_view>(),
            static_cast<int>(hf_version));
    auto earliest = hfinfo.value("earliest_height", uint64_t{0});
    if (earliest)
        print_fork_extra_info(msg, earliest, net_height, 1s * info["target"].get<uint64_t>());

    std::time_t now = std::time(nullptr);

    if (restricted_response) {
        std::chrono::seconds uptime{now - info["start_time"].get<std::time_t>()};
        msg.append(
                ", {}(out)+{}(in) connections, uptime {}",
                info["outgoing_connections_count"].get<int>(),
                info["incoming_connections_count"].get<int>(),
                tools::friendly_duration(uptime));
    }

    if (!my_sn_key.empty()) {
        msg.flush().append("SN: {} ", my_sn_key);
        if (!my_sn_registered)
            msg += "not registered";
        else if (!my_sn_staked)
            msg += "awaiting";
        else if (my_sn_active)
            msg += "active";
        else
            msg.append("DECOMMISSIONED ({} blocks credit)", my_decomm_remaining);

        auto last_ss_ping = info["last_storage_server_ping"].get<uint64_t>();
        auto last_lokinet_ping = info["last_lokinet_ping"].get<uint64_t>();

        msg.append(
                ", proof: {}, last pings: {} (storage), {} (lokinet)",
                my_sn_last_uptime ? get_human_time_ago(my_sn_last_uptime, now) : "(never)",
                last_ss_ping > 0 ? get_human_time_ago(last_ss_ping, now, true /*abbreviate*/)
                                 : "NOT RECEIVED",
                last_lokinet_ping > 0
                        ? get_human_time_ago(last_lokinet_ping, now, true /*abbreviate*/)
                        : "NOT RECEIVED");

        if (my_sn_registered && my_sn_staked && !my_sn_active && (my_reason_all | my_reason_any)) {
            msg.flush().append("Decomm reasons: ");
            if (auto reasons = cryptonote::readable_reasons(my_reason_all); !reasons.empty())
                msg.append("{}", fmt::join(reasons, ", "));
            if (auto reasons = cryptonote::readable_reasons(my_reason_any & ~my_reason_all);
                !reasons.empty()) {
                for (auto& r : reasons)
                    r += "(some)";
                msg.append("{}{}", my_reason_all ? ", " : "", fmt::join(reasons, ", "));
            }
        }
    }

    return true;
}

bool rpc_command_executor::mining_status() {
    auto maybe_mining_info = try_running(
            [this] { return invoke<MINING_STATUS>(false); }, "Failed to retrieve mining info");
    if (!maybe_mining_info)
        return false;

    bool mining_busy = false;
    auto& mres = *maybe_mining_info;
    if (mres["status"] == STATUS_BUSY)
        mining_busy = true;
    else if (mres["status"] != STATUS_OK) {
        tools::fail_msg_writer("Failed to retrieve mining info");
        return false;
    }
    bool active = mres["active"].get<bool>();
    long speed = mres["speed"].get<long>();
    if (mining_busy || !active)
        tools::msg_writer("Not currently mining");
    else {
        tools::msg_writer(
                "Mining at {} with {} threads",
                get_mining_speed(speed),
                mres["threads_count"].get<int>());
        tools::msg_writer("Mining address: {}", mres["address"].get<std::string_view>());
    }
    tools::msg_writer("PoW algorithm: {}", mres["pow_algorithm"].get<std::string_view>());

    return true;
}

static const char* get_address_type_name(epee::net_utils::address_type address_type) {
    switch (address_type) {
        default:
        case epee::net_utils::address_type::invalid: return "invalid";
        case epee::net_utils::address_type::ipv4: return "IPv4";
        case epee::net_utils::address_type::ipv6: return "IPv6";
        case epee::net_utils::address_type::i2p: return "I2P";
        case epee::net_utils::address_type::tor: return "Tor";
    }
}

bool rpc_command_executor::print_connections() {
    auto maybe_conns = try_running(
            [this] { return invoke<GET_CONNECTIONS>(); }, "Failed to retrieve connection info");
    if (!maybe_conns)
        return false;
    auto& conns = *maybe_conns;

    constexpr auto hdr_fmt = "{:<30}{:<8}{:<20}{:<30}{:<25}{:<20}{:<12s}{:<14s}{:<10s}{:<13s}"sv;
    constexpr auto row_fmt =
            "{:<30}{:<8}{:<20}{:<30}{:<25}{:<20}{:<12.1f}{:<14.1f}{:<10.1f}{:<13.1f}{}{}"sv;
    tools::msg_writer(
            hdr_fmt,
            "Remote Host",
            "Type",
            "Peer id",
            "Recv/Sent (inactive,sec)",
            "State",
            "Livetime(sec)",
            "Down (kB/sec)",
            "Down(now)",
            "Up (kB/s)",
            "Up(now)");

    for (auto& info : conns) {
        tools::msg_writer(
                row_fmt,
                "{} {}:{}"_format(
                        info["incoming"].get<bool>() ? "INC" : "OUT",
                        info["ip"].get<std::string_view>(),
                        info["port"].get<uint16_t>()),
                get_address_type_name(info["address_type"].get<epee::net_utils::address_type>()),
                info["peer_id"].get<std::string_view>(),
                "{}({}/{})"_format(
                        info["recv_count"].get<uint64_t>(),
                        tools::friendly_duration(1ms * info["recv_idle_ms"].get<int64_t>()),
                        tools::friendly_duration(1ms * info["send_idle_ms"].get<int64_t>())),
                info["state"].get<std::string_view>(),
                tools::friendly_duration(1ms * info["live_ms"].get<int64_t>()),
                info["avg_download"].get<uint64_t>() / 1000.,
                info["current_download"].get<uint64_t>() / 1000.,
                info["avg_upload"].get<uint64_t>() / 1000.,
                info["current_upload"].get<uint64_t>() / 1000.,
                info.value("localhost", false) ? "[LOCALHOST]" : "",
                info.value("local_ip", false) ? "[LAN]" : "");
    }

    return true;
}

bool rpc_command_executor::print_net_stats() {
    auto maybe_stats = try_running(
            [this] { return invoke<GET_NET_STATS>(); }, "Failed to retrieve net statistics");
    auto maybe_limit = try_running(
            [this] { return invoke<GET_LIMIT>(); }, "Failed to retrieve bandwidth limits");
    if (!maybe_stats || !maybe_limit)
        return false;
    auto& stats = *maybe_stats;
    auto& limit = *maybe_limit;
    auto uptime = time(nullptr) - stats["start_time"].get<std::time_t>();

    for (bool in : {true, false}) {
        auto bytes = stats[in ? "total_bytes_in" : "total_bytes_out"].get<uint64_t>();
        double average = uptime > 0 ? bytes / (double)uptime : 0.0;
        uint64_t lim = limit[in ? "limit_down" : "limit_up"].get<uint64_t>() *
                       1024;  // convert to bytes, as limits are always kB/s
        tools::success_msg_writer(
                "{} {} in {} packets, average {}/s = {:.2f}% of the limit of {}/s",
                in ? "Received" : "Sent",
                tools::get_human_readable_bytes(bytes),
                stats[in ? "total_packets_in" : "total_packets_out"].get<uint64_t>(),
                tools::get_human_readable_bytes(average),
                average / lim * 100.0,
                tools::get_human_readable_bytes(lim));
    }

    return true;
}

bool rpc_command_executor::print_blockchain_info(
        int64_t start_block_index, uint64_t end_block_index) {
    // negative: relative to the end
    if (start_block_index < 0) {
        auto maybe_info =
                try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
        if (!maybe_info)
            return false;
        auto& info = *maybe_info;

        if (start_block_index < 0 && -start_block_index >= info["height"].get<int64_t>()) {
            tools::fail_msg_writer("start offset is larger than blockchain height");
            return false;
        }

        start_block_index += info["height"].get<int64_t>();
        end_block_index += start_block_index - 1;
    }

    auto maybe_block_headers = try_running(
            [this, start_block_index, end_block_index] {
                return invoke<GET_BLOCK_HEADERS_RANGE>(
                        json{{"start_height", start_block_index},
                             {"end_height", end_block_index},
                             {"fill_pow_hash", false}});
            },
            "Failed to retrieve block headers");
    if (!maybe_block_headers)
        return false;
    auto& block_headers = *maybe_block_headers;

    auto writer = tools::msg_writer("\n");
    for (auto& header : block_headers["headers"]) {
        writer.flush().append(
                "height: {}, timestamp: {} ({}), size: {}, weight: {} (long term {}), "
                "transactions: {}\n"
                "major version: {}, minor version: {}\n"
                "block id: {}, previous block id: {}\n"
                "difficulty: {}, nonce {}, reward {}\n",
                header["height"].get<int64_t>(),
                header["timestamp"].get<int64_t>(),
                tools::get_human_readable_timestamp(header["timestamp"].get<uint64_t>()),
                header["block_size"].get<int64_t>(),
                header["block_weight"].get<int64_t>(),
                header["long_term_weight"].get<int64_t>(),
                header["num_txes"].get<int64_t>(),
                header["major_version"].get<int64_t>(),
                header["minor_version"].get<int64_t>(),
                header["hash"].get<std::string_view>(),
                header["prev_hash"].get<std::string_view>(),
                header["difficulty"].get<uint64_t>(),
                header["nonce"].get<int64_t>(),
                cryptonote::print_money(header["reward"].get<uint64_t>()));
    }

    return true;
}

bool rpc_command_executor::print_quorum_state(
        std::optional<uint64_t> start_height, std::optional<uint64_t> end_height) {
    auto maybe_quorums = try_running(
            [this, start_height, end_height] {
                json params;
                if (start_height)
                    params["start_height"] = *start_height;
                if (end_height)
                    params["end_height"] = *end_height;
                return invoke<GET_QUORUM_STATE>(std::move(params));
            },
            "Failed to retrieve quorum state");

    if (!maybe_quorums)
        return false;
    auto& quorums = *maybe_quorums;

    tools::success_msg_writer("{{\n\"quorums\": {}\n}}", quorums["quorums"].dump(2));
    return true;
}

bool rpc_command_executor::set_log_level(int8_t level) {
    if (!invoke<SET_LOG_LEVEL>(json{{"level", level}}))
        return false;

    tools::success_msg_writer("Log level is now {:d}", level);

    return true;
}

bool rpc_command_executor::set_log_categories(std::string categories) {
    // auto maybe_categories = try_running([this, &categories] { return
    // invoke<SET_LOG_CATEGORIES>(json{{"categories", std::move(categories)}}); }, "Failed to set
    // log categories"); if (!maybe_categories) return false;
    // auto& categories_response = *maybe_categories;
    auto categories_response =
            make_request<SET_LOG_CATEGORIES>(json{{"categories", std::move(categories)}});

    tools::success_msg_writer(
            "Log categories are now {}", categories_response["categories"].get<std::string_view>());

    return true;
}

bool rpc_command_executor::print_height() {
    if (auto height = try_running(
                [this] { return invoke<GET_HEIGHT>().at("height").get<int>(); },
                "Failed to retrieve height")) {
        tools::success_msg_writer("{}", *height);
        return true;
    }
    return false;
}

bool rpc_command_executor::print_block_by_hash(const crypto::hash& block_hash, bool include_hex) {
    auto maybe_block = try_running(
            [this, &block_hash] {
                return invoke<GET_BLOCK>(
                        json{{"hash", tools::type_to_hex(block_hash)}, {"fill_pow_hash", true}});
            },
            "Block retrieval failed");
    if (!maybe_block)
        return false;
    auto& block = *maybe_block;

    if (include_hex)
        tools::success_msg_writer() + block["blob"].get<std::string_view>() + "\n";
    print_block_header(block["block_header"]);
    tools::success_msg_writer() + block["json"].get<std::string_view>() + "\n";

    return true;
}

bool rpc_command_executor::print_block_by_height(uint64_t height, bool include_hex) {
    auto maybe_block = try_running(
            [this, height] {
                return invoke<GET_BLOCK>(json{{"height", height}, {"fill_pow_hash", true}});
            },
            "Block retrieval failed");
    if (!maybe_block)
        return false;
    auto& block = *maybe_block;

    if (include_hex)
        tools::success_msg_writer("{}\n", block["blob"].get<std::string_view>());
    print_block_header(block["block_header"]);
    tools::success_msg_writer("{}\n", block["json"].get<std::string_view>());

    return true;
}

bool rpc_command_executor::print_transaction(
        const crypto::hash& transaction_hash,
        bool include_metadata,
        bool include_hex,
        bool include_json) {

    auto maybe_tx = try_running(
            [this, &transaction_hash] {
                return invoke<GET_TRANSACTIONS>(
                        json{{"tx_hashes", json::array({tools::type_to_hex(transaction_hash)})},
                             {"split", true}});
            },
            "Transaction retrieval failed");
    if (!maybe_tx)
        return false;

    auto& txi = *maybe_tx;
    auto txs = txi["txs"];
    if (txs.size() != 1) {
        tools::fail_msg_writer("Transaction wasn't found: {}\n", transaction_hash);
        return true;
    }

    auto tx = txs.front();
    auto prunable_hash = tx.value<std::string_view>("prunable_hash", ""sv);
    auto prunable_hex = tx.value<std::string_view>("prunable", ""sv);
    bool pruned = !prunable_hash.empty() && prunable_hex.empty();

    bool in_pool = tx["in_pool"].get<bool>();
    if (in_pool)
        tools::success_msg_writer("Found in pool");
    else
        tools::success_msg_writer(
                "Found in blockchain at height {}{}",
                tx["block_height"].get<uint64_t>(),
                pruned ? " (pruned)" : "");

    auto pruned_hex = tx["pruned"].get<std::string_view>();  // Always included with req.split=true

    std::optional<cryptonote::transaction> t;
    if (include_metadata || include_json) {
        if (oxenc::is_hex(pruned_hex) && oxenc::is_hex(prunable_hex)) {
            std::string blob = oxenc::from_hex(pruned_hex);
            if (!prunable_hex.empty())
                blob += oxenc::from_hex(prunable_hex);

            bool parsed =
                    pruned ? cryptonote::parse_and_validate_tx_base_from_blob(blob, t.emplace())
                           : cryptonote::parse_and_validate_tx_from_blob(blob, t.emplace());
            if (!parsed) {
                tools::fail_msg_writer("Failed to parse transaction data");
                t.reset();
            }
        }
    }

    // Print metadata if requested
    if (include_metadata) {
        if (!in_pool) {
            auto ts = tx["block_timestamp"].get<std::time_t>();
            tools::msg_writer(
                    "Block timestamp: {} ({})", ts, tools::get_human_readable_timestamp(ts));
        }
        tools::msg_writer("Size: {}", tx["size"].get<int>());
        if (t)
            tools::msg_writer("Weight: {}", cryptonote::get_transaction_weight(*t));
    }

    // Print raw hex if requested
    if (include_hex)
        tools::success_msg_writer("{}{}\n", pruned_hex, prunable_hex);

    // Print json if requested
    if (include_json && t)
        tools::success_msg_writer("{}\n", cryptonote::obj_to_json_str(*t));

    return true;
}

bool rpc_command_executor::is_key_image_spent(const std::vector<crypto::key_image>& ki) {

    auto maybe_spent = try_running(
            [this, &ki] {
                auto kis = json::array();
                for (auto& k : ki)
                    kis.push_back(tools::type_to_hex(k));
                return invoke<IS_KEY_IMAGE_SPENT>(json{{"key_images", std::move(kis)}});
            },
            "Failed to retrieve key image status");
    if (!maybe_spent)
        return false;
    auto& spent_status = (*maybe_spent)["spent_status"];

    if (spent_status.size() != ki.size()) {
        tools::fail_msg_writer("key image status could not be determined\n");
        return false;
    }

    for (size_t i = 0; i < ki.size(); i++) {
        int status = spent_status[i].get<int>();
        tools::success_msg_writer(
                "{}: {}",
                ki[i],
                status == 0   ? "unspent"
                : status == 1 ? "spent"
                : status == 2 ? "spent (in pool)"
                              : "unknown");
    }
    return true;
}

static void print_pool(const json& txs) {
    if (txs.empty()) {
        tools::msg_writer("Pool is empty\n");
        return;
    }
    const time_t now = time(nullptr);
    auto msg = tools::msg_writer("{} Transactions:\n", txs.size());
    for (auto& tx : txs) {
        std::vector<std::string_view> status;
        if (tx.value("blink", false))
            status.push_back("blink"sv);
        status.push_back(tx["relayed"].get<bool>() ? "relayed"sv : "not relayed"sv);
        if (tx.value("do_not_relay", false))
            status.push_back("do not relay"sv);
        if (tx.value("double_spend_seen", false))
            status.push_back("double spend"sv);
        if (tx.value("kept_by_block", false))
            status.push_back("from popped block"sv);

        msg.flush().append("{}:\n", tx["tx_hash"].get_ref<const std::string&>());
        msg.append("    size/weight: {}/{}\n", tx["size"].get<int>(), tx["weight"].get<int>());
        msg.append(
                "    fee: {} ({}/byte)\n",
                cryptonote::print_money(tx["fee"].get<uint64_t>()),
                cryptonote::print_money(tx["fee"].get<double>() / tx["weight"].get<double>()));
        msg.append(
                "    received: {} ({})\n",
                tx["received_timestamp"].get<std::time_t>(),
                get_human_time_ago(tx["received_timestamp"].get<std::time_t>(), now));
        msg.append("    status: {}\n", fmt::join(status, ", "));
        msg.append(
                "    top required block: {} ({})\n",
                tx["max_used_height"].get<uint64_t>(),
                tx["max_used_block"].get<std::string_view>());
        if (tx.count("last_failed_height"))
            msg.append(
                    "    last failed block: {} ({})\n",
                    tx["last_failed_height"].get<uint64_t>(),
                    tx["last_failed_block"].get<std::string_view>());
        if (auto extra = tx.find("extra"); extra != tx.end()) {
            msg.append("    transaction extra: ");
            for (auto line : tools::split(extra->dump(2), "\n", true))
                msg.append("      {}\n", line);
        }
        msg.append("\n");
    }
}

bool rpc_command_executor::print_transaction_pool(bool long_format) {
    json args{{"memory_pool", true}};
    if (long_format)
        args["tx_extra"] = true;
    auto maybe_pool = try_running(
            [this, &args] { return invoke<GET_TRANSACTIONS>(args); },
            "Failed to retrieve transaction pool details");
    if (!maybe_pool)
        return false;
    auto& pool = *maybe_pool;

    print_pool(pool["txs"]);

    if (long_format && !pool["mempool_key_images"].empty()) {
        auto msg = tools::msg_writer("\nSpent key images:");
        for (const auto& [key, tx_hashes] : pool["mempool_key_images"].items()) {
            msg.flush().append("key image: {}\n", key);
            if (tx_hashes.size() == 1)
                msg.append("  tx: {}\n", tx_hashes.front().get<std::string_view>());
            else if (tx_hashes.empty())
                msg.append("  WARNING: spent key image has no txs associated!\n");
            else {
                msg.append("  NOTE: key image for multiple transactions ({}):\n", tx_hashes.size());
                for (const auto& txid : tx_hashes)
                    msg.append("    - {}\n", txid.get<std::string_view>());
            }
        }
        if (pool["txs"].empty())
            msg.flush().append(
                    "WARNING: Inconsistent pool state - key images but no no transactions");
    }

    return true;
}

bool rpc_command_executor::print_transaction_pool_stats() {

    auto full_reward_zone = try_running(
            [this] { return invoke<GET_INFO>().at("block_size_limit").get<uint64_t>() / 2; },
            "Failed to retrieve node info");
    if (!full_reward_zone)
        return false;

    auto maybe_stats = try_running(
            [this] {
                return invoke<GET_TRANSACTION_POOL_STATS>(json{{"include_unrelayed", true}});
            },
            "Failed to retrieve transaction pool statistics");
    if (!maybe_stats)
        return false;
    auto& pstats = maybe_stats->at("pool_stats");

    size_t n_transactions = pstats["txs_total"].get<int>();
    const uint64_t now = time(NULL);
    auto bytes_total = pstats["bytes_total"].get<uint64_t>();
    size_t avg_bytes = n_transactions ? bytes_total / n_transactions : 0;

    std::string backlog_message = "no backlog";
    if (bytes_total > *full_reward_zone) {
        uint64_t backlog = (bytes_total + *full_reward_zone - 1) / *full_reward_zone;
        backlog_message = "estimated {} block ({} minutes) backlog"_format(
                backlog, (backlog * cryptonote::TARGET_BLOCK_TIME / 1min));
    }

    uint64_t fee_total = pstats["fee_total"].get<uint64_t>();
    std::time_t oldest = pstats["oldest"].get<std::time_t>();
    tools::msg_writer(
            "{} tx(s), {} bytes total (min {}, max {}, avg {}, median {})\n"
            "fees {} (avg {} per tx, {} per byte)\n"
            "{} double spends, {} not relayed, {} failing, {} older than 10 minutes (oldest {}), "
            "{}",
            n_transactions,
            bytes_total,
            pstats["bytes_min"].get<uint64_t>(),
            pstats["bytes_max"].get<uint64_t>(),
            avg_bytes,
            pstats["bytes_med"].get<uint64_t>(),
            cryptonote::print_money(fee_total),
            cryptonote::print_money(n_transactions ? fee_total / n_transactions : 0),
            cryptonote::print_money(bytes_total ? fee_total / bytes_total : 0),
            pstats["num_double_spends"].get<uint64_t>(),
            pstats["num_not_relayed"].get<uint64_t>(),
            pstats["num_failing"].get<uint64_t>(),
            pstats["num_10m"].get<uint64_t>(),
            oldest == 0 ? "-" : get_human_time_ago(oldest, now),
            backlog_message);

    auto histo = pstats["histo"].get<std::vector<std::pair<uint64_t, uint64_t>>>();
    if (n_transactions > 1 && !histo.empty()) {
        std::array<uint64_t, 11> times;
        bool last_is_gt = false;
        if (auto it = pstats.find("histo_98pc"); it != pstats.end()) {
            auto histo98 = it->get<uint64_t>();
            for (size_t i = 0; i < 11; i++)
                times[i] = i * histo98 / 9;
            last_is_gt = true;
        } else {
            auto histo_max = pstats["histo_max"].get<uint64_t>();
            for (size_t i = 0; i < 11; i++)
                times[i] = i * histo_max / 10;
        }

        constexpr auto hist_fmt = "{:>10} - {:<14} {:>7} {:>11}"sv;
        tools::msg_writer("{:^23}     {:>7} {:>11}", "Age", "Txes", "Bytes");
        for (size_t i = 0; i < 10; i++)
            tools::msg_writer(
                    hist_fmt,
                    get_human_time_ago(times[i] * 1s, true),
                    (last_is_gt && i == 10 ? ""
                                           : get_human_time_ago(times[i + 1] * 1s, true) + " ago"),
                    histo[i].first,
                    histo[i].second);
    }
    tools::msg_writer();

    return true;
}

bool rpc_command_executor::start_mining(
        const cryptonote::account_public_address& address,
        int num_threads,
        int num_blocks,
        cryptonote::network_type nettype) {
    json args{
            {"num_blocks", num_blocks},
            {"threads_count", num_threads},
            {"miner_address", cryptonote::get_account_address_as_str(nettype, false, address)}};
    if (!try_running(
                [this, &args] { return invoke<START_MINING>(args); }, "Unable to start mining"))
        return false;

    tools::success_msg_writer(
            "Mining started with {} thread(s).{}",
            std::max(num_threads, 1),
            num_blocks ? " Will stop after {} blocks"_format(num_blocks) : "");
    return true;
}

bool rpc_command_executor::stop_mining() {
    return invoke_simple<STOP_MINING>("Couldn't stop mining", "Mining stopped");
}

bool rpc_command_executor::stop_daemon() {
    return invoke_simple<STOP_DAEMON>("Couldn't stop daemon", "Stop signal sent");
}

bool rpc_command_executor::get_limit() {
    auto maybe_limit = try_running(
            [this] { return invoke<GET_LIMIT>(); }, "Failed to retrieve current traffic limits");
    if (!maybe_limit)
        return false;
    auto& limit = *maybe_limit;

    tools::msg_writer(
            "Current limits are {} kiB/s down, {} kiB/s up",
            limit["limit_down"].get<uint64_t>(),
            limit["limit_up"].get<uint64_t>());
    return true;
}

bool rpc_command_executor::set_limit(int64_t limit_down, int64_t limit_up) {
    json args{{"limit_down", limit_down}, {"limit_up", limit_up}};
    auto maybe_limit = try_running(
            [this, &args] { return invoke<SET_LIMIT>(args); }, "Failed to set traffic limits");
    if (!maybe_limit)
        return false;
    auto& limit = *maybe_limit;

    tools::success_msg_writer(
            "New limits are {} kiB/s down, {} kiB/s up",
            limit["limit_down"].get<uint64_t>(),
            limit["limit_up"].get<uint64_t>());
    return true;
}

bool rpc_command_executor::out_peers(bool set, uint32_t limit) {
    auto maybe_out_peers = try_running(
            [this, set, limit] {
                return invoke<OUT_PEERS>(json{{"set", set}, {"out_peers", limit}});
            },
            "Failed to set max out peers");
    if (!maybe_out_peers)
        return false;
    auto& out_peers = *maybe_out_peers;

    const std::string s = out_peers["out_peers"] == (uint32_t)-1
                                ? "unlimited"
                                : out_peers["out_peers"].get<std::string>();
    tools::msg_writer().append("Max number of out peers set to {}\n", s);

    return true;
}

bool rpc_command_executor::in_peers(bool set, uint32_t limit) {
    auto maybe_in_peers = try_running(
            [this, set, limit] {
                return invoke<IN_PEERS>(json{{"set", set}, {"in_peers", limit}});
            },
            "Failed to set max in peers");
    if (!maybe_in_peers)
        return false;
    auto& in_peers = *maybe_in_peers;

    const std::string s = in_peers["in_peers"] == (uint32_t)-1
                                ? "unlimited"
                                : in_peers["in_peers"].get<std::string>();
    tools::msg_writer().append("Max number of in peers set to {}\n", s);

    return true;
}

bool rpc_command_executor::print_bans() {
    auto maybe_bans =
            try_running([this] { return invoke<GET_BANS>(); }, "Failed to retrieve ban list");
    if (!maybe_bans)
        return false;
    auto bans = *maybe_bans;

    if (!bans.empty()) {
        for (auto i = bans.begin(); i != bans.end(); ++i) {
            tools::msg_writer(
                    "{} banned for {} seconds",
                    (*i)["host"].get<std::string_view>(),
                    (*i)["seconds"].get<int64_t>());
        }
    } else
        tools::msg_writer("No IPs are banned");

    return true;
}

bool rpc_command_executor::ban(const std::string& address, time_t seconds, bool clear_ban) {
    auto maybe_banned = try_running(
            [this, &address, seconds, clear_ban] {
                return invoke<SET_BANS>(
                        json{{"host", std::move(address)},
                             {"ip", 0},
                             {"seconds", seconds},
                             {"ban", !clear_ban}});
            },
            clear_ban ? "Failed to clear ban" : "Failed to set ban");
    if (!maybe_banned)
        return false;

    return true;
}

bool rpc_command_executor::unban(const std::string& address) {
    return ban(std::move(address), 0, true);
}

bool rpc_command_executor::banned(const std::string& address) {
    auto maybe_banned = try_running(
            [this, &address] {
                return invoke<BANNED>(json{{"address", std::move(address)}});
            },
            "Failed to retrieve ban information");
    if (!maybe_banned)
        return false;
    auto& banned_response = *maybe_banned;

    if (banned_response["banned"].get<bool>())
        tools::msg_writer(
                "{} is banned for {} seconds",
                address,
                banned_response["seconds"].get<std::string_view>());
    else
        tools::msg_writer("{} is not banned", address);

    return true;
}

bool rpc_command_executor::flush_txpool(std::string txid) {
    std::vector<std::string> txids{};
    if (!txid.empty())
        txids.push_back(std::move(txid));

    if (!invoke<FLUSH_TRANSACTION_POOL>(json{{txids, std::move(txids)}})) {
        tools::fail_msg_writer("Failed to flush tx pool");
        return false;
    }

    tools::success_msg_writer("Pool successfully flushed");
    return true;
}

bool rpc_command_executor::output_histogram(
        const std::vector<uint64_t>& amounts, uint64_t min_count, uint64_t max_count) {
    auto maybe_histogram = try_running(
            [this, &amounts, min_count, max_count] {
                return invoke<GET_OUTPUT_HISTOGRAM>(
                        json{{"amounts", amounts},
                             {"min_count", min_count},
                             {"max_count", max_count},
                             {"unlocked", false},
                             {"recent_cutoff", 0}});
            },
            "Failed to retrieve output histogram");
    if (!maybe_histogram)
        return false;
    std::vector<GET_OUTPUT_HISTOGRAM::entry> histogram = (*maybe_histogram)["histogram"];
    std::sort(histogram.begin(), histogram.end(), [](const auto& e1, const auto& e2) -> bool {
        return e1.total_instances < e2.total_instances;
    });
    for (const auto& e : histogram)
        tools::msg_writer("{}  {}", e.total_instances, cryptonote::print_money(e.amount));

    return true;
}

bool rpc_command_executor::print_coinbase_tx_sum(uint64_t height, uint64_t count) {
    auto maybe_coinbase = try_running(
            [this, &height, &count] {
                return invoke<GET_COINBASE_TX_SUM>(json{{"height", height}, {"count", count}});
            },
            "Failed to retrieve coinbase info");
    if (!maybe_coinbase)
        return false;
    auto& coinbase = *maybe_coinbase;

    tools::msg_writer(
            "Sum of coinbase transactions between block heights [{}, {}) is {} consisting of {} in "
            "emissions and {} in fees",
            height,
            height + count,
            cryptonote::print_money(
                    coinbase["emission_amount"].get<int64_t>() +
                    coinbase["fee_amount"].get<int64_t>()),
            cryptonote::print_money(coinbase["emission_amount"]),
            cryptonote::print_money(coinbase["fee_amount"]));
    return true;
}

bool rpc_command_executor::alt_chain_info(
        const std::string& tip, size_t above, uint64_t last_blocks) {
    auto height = try_running(
            [this] { return invoke<GET_INFO>().at("height").get<uint64_t>(); },
            "Failed to retrieve node info");
    if (!height)
        return false;

    auto maybe_chains = try_running(
            [this] { return invoke<GET_ALTERNATE_CHAINS>(); }, "Failed to retrieve node info");
    if (!maybe_chains)
        return false;

    std::vector<GET_ALTERNATE_CHAINS::chain_info> chains = (*maybe_chains)["chains"];
    if (tip.empty()) {
        std::sort(chains.begin(), chains.end(), [](const auto& info0, auto& info1) {
            return info0.height < info1.height;
        });
        std::vector<size_t> display;
        for (size_t i = 0; i < chains.size(); ++i) {
            const auto& chain = chains[i];
            if (chain.length <= above)
                continue;
            const uint64_t start_height = (chain.height - chain.length + 1);
            if (last_blocks > 0 && *height - 1 - start_height >= last_blocks)
                continue;
            display.push_back(i);
        }
        tools::msg_writer("{} alternate chains found:", display.size());
        for (const size_t idx : display) {
            const auto& chain = chains[idx];
            const uint64_t start_height = (chain.height - chain.length + 1);
            tools::msg_writer(
                    "{} blocks long, from height {} ({} deep), diff {}: {}",
                    chain.length,
                    start_height,
                    *height - start_height - 1,
                    chain.difficulty,
                    chain.block_hash);
        }
    } else {
        const uint64_t now = time(NULL);
        const auto i = std::find_if(
                chains.begin(), chains.end(), [&tip](GET_ALTERNATE_CHAINS::chain_info& info) {
                    return info.block_hash == tip;
                });
        if (i != chains.end()) {
            const auto& chain = *i;
            tools::success_msg_writer("Found alternate chain with tip {}", tip);
            uint64_t start_height = (chain.height - chain.length + 1);
            auto msg = tools::msg_writer(
                    "{} blocks long, from height {} ({} deep), diff {}:",
                    chain.length,
                    start_height,
                    *height - start_height - 1,
                    chain.difficulty);
            for (const std::string& block_id : chain.block_hashes)
                msg.append("\n  {}", block_id);
            msg.append("\nChain parent on main chain: {}", chain.main_chain_parent_block);
            msg.flush();

            std::vector<std::string> hashes{chain.block_hashes};
            hashes.push_back(chain.main_chain_parent_block);
            auto maybe_headers = try_running(
                    [&] {
                        return invoke<GET_BLOCK_HEADER_BY_HASH>(
                                json{{"hashes", hashes}, {"fill_pow_hash", false}});
                    },
                    "Failed to query block header by hash");
            if (!maybe_headers)
                return false;
            auto headers = *maybe_headers;

            if (headers["block_headers"].size() != chain.length + 1) {
                tools::fail_msg_writer("Failed to get block header info for alt chain");
                return true;
            }
            uint64_t t0 = std::numeric_limits<uint64_t>::max(),
                     t1 = std::numeric_limits<uint64_t>::min();
            for (const auto& block_header : headers["block_headers"]) {
                const uint64_t ts = block_header.get<uint64_t>();
                t0 = std::min(t0, ts);
                t1 = std::max(t1, ts);
            }
            const uint64_t dt = t1 - t0;
            const uint64_t age = std::max(dt, t0 < now ? now - t0 : 0);
            tools::msg_writer(
                    "Age: {}", tools::get_human_readable_timespan(std::chrono::seconds(age)));
            if (chain.length > 1) {
                tools::msg_writer(
                        "Time span: {}",
                        tools::get_human_readable_timespan(std::chrono::seconds(dt)));
                cryptonote::difficulty_type start_difficulty =
                        headers["block_headers"].back()["difficulty"];
                if (start_difficulty > 0)
                    tools::msg_writer(
                            "Approximately {:.2f}% of network hash rate",
                            100.0 * tools::to_seconds(cryptonote::TARGET_BLOCK_TIME) *
                                    chain.length / dt);
                else
                    tools::fail_msg_writer("Bad cumulative difficulty reported by dameon");
            }
        } else
            tools::fail_msg_writer(
                    "Block hash {} is not the tip of any known alternate chain", tip);
    }
    return true;
}

bool rpc_command_executor::print_blockchain_dynamic_stats(uint64_t nblocks) {
    auto maybe_info =
            try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
    if (!maybe_info)
        return false;
    auto& info = *maybe_info;

    auto maybe_hf = try_running(
            [this] { return invoke<HARD_FORK_INFO>(); }, "Failed to retrieve hard fork info");
    if (!maybe_hf)
        return false;
    auto& hfinfo = *maybe_hf;

    auto maybe_fees = try_running(
            [this] { return invoke<GET_BASE_FEE_ESTIMATE>(json{}); },
            "Failed to retrieve current fee info");
    if (!maybe_fees)
        return false;
    auto& feres = *maybe_fees;

    auto height = info["height"].get<uint64_t>();
    tools::msg_writer(
            "Height: {}, diff {}, cum. diff {}, target {} sec, dyn fee {}/{} + {}/out",
            height,
            info["difficulty"].get<uint64_t>(),
            info["cumulative_difficulty"].get<uint64_t>(),
            info["target"].get<int>(),
            cryptonote::print_money(feres["fee_per_byte"]),
            hfinfo["enabled"].get<bool>() ? "byte" : "kB",
            cryptonote::print_money(feres["fee_per_output"]));

    if (nblocks > 0) {
        if (nblocks > height)
            nblocks = height;

        auto maybe_block_headers = try_running(
                [this, height, nblocks] {
                    return invoke<GET_BLOCK_HEADERS_RANGE>(
                            json{{"start_height", height - nblocks},
                                 {"end_height", height - 1},
                                 {"fill_pow_hash", false}});
                },
                "Failed to retrieve block headers");
        if (!maybe_block_headers)
            return false;
        auto& block_headers = *maybe_block_headers;

        double avgdiff = 0;
        double avgnumtxes = 0;
        double avgreward = 0;
        std::vector<uint64_t> weights;
        weights.reserve(nblocks);
        uint64_t earliest = std::numeric_limits<uint64_t>::max(), latest = 0;
        std::map<unsigned, std::pair<unsigned, unsigned>>
                versions;  // version -> {majorcount, minorcount}
        for (const auto& bhr : block_headers["headers"]) {
            avgdiff += bhr["difficulty"].get<double>();
            avgnumtxes += bhr["num_txes"].get<double>();
            avgreward += bhr["reward"].get<double>();
            weights.push_back(bhr["block_weight"].get<uint64_t>());
            versions[bhr["major_version"]].first++;
            versions[bhr["minor_version"]].second++;
            earliest = std::min(earliest, bhr["timestamp"].get<uint64_t>());
            latest = std::max(latest, bhr["timestamp"].get<uint64_t>());
        }
        avgdiff /= nblocks;
        avgnumtxes /= nblocks;
        avgreward /= nblocks;
        uint64_t median_block_weight = tools::median(std::move(weights));
        tools::msg_writer(
                "Last {}: avg. diff {}, {} avg sec/block, avg num txes {}, avg. reward {}, median "
                "block weight {}",
                nblocks,
                (uint64_t)avgdiff,
                (latest - earliest) / nblocks,
                avgnumtxes,
                cryptonote::print_money(avgreward),
                median_block_weight);

        auto msg = tools::msg_writer("Block versions (major/minor): ");
        bool first = true;
        for (auto& v : versions) {
            if (first)
                first = false;
            else
                msg.append("; ");
            msg.append("v{} ({}/{})", v.first, v.second.first, v.second.second);
        }
    }
    return true;
}

bool rpc_command_executor::relay_tx(const std::string& txid) {
    auto maybe_relay = try_running(
            [&] {
                return invoke<RELAY_TX>(json{{"txid", txid}});
            },
            "Failed to relay tx");
    if (!maybe_relay)
        return false;

    tools::success_msg_writer("Transaction successfully relayed");
    return true;
}

bool rpc_command_executor::sync_info() {
    auto maybe_sync =
            try_running([this] { return invoke<SYNC_INFO>(); }, "Failed to retrieve sync info");
    if (!maybe_sync)
        return false;
    auto& sync = *maybe_sync;

    uint64_t height = sync["height"].get<uint64_t>();
    uint64_t target = std::max(sync.value("target_height", height), height);
    auto msg = tools::success_msg_writer(
            "Height: {}, target: {} ({}%)", height, target, 100.0 * height / target);
    auto& spans = sync["spans"];
    auto& peers = sync["peers"];
    uint64_t current_download = 0;
    for (const auto& p : peers)
        current_download += p["current_download"].get<uint64_t>();
    msg.append("\nDownloading at {:.1f} kB/s", current_download / 1000.0);
    if (auto nnps = sync.value("next_needed_pruning_seed", 0))
        msg.append("\nNext needed pruning seed: {}", nnps);

    msg.append("\n{} peers", peers.size());
    for (const auto& [cid, p] : peers.items()) {
        std::string address = "{}:{}"_format(p["ip"].get<std::string>(), p["port"].get<uint16_t>());
        uint64_t nblocks = 0, size = 0;
        for (const auto& s : spans) {
            if (s["connection_id"] == cid) {
                nblocks += s["nblocks"].get<uint64_t>();
                size += s["size"].get<uint64_t>();
            }
        }
        msg.append(
                "\n{:<24s}  {}  {:<16s}  {}  {:.1f} kB/s, {} blocks / {:.2f} MB queued",
                address,
                p["peer_id"].get<std::string_view>(),
                p["state"].get<std::string_view>(),
                p["height"].get<uint64_t>(),
                p["current_download"].get<uint64_t>() / 1000.0,
                nblocks,
                size / 1'000'000.0);
    }

    uint64_t total_size = 0;
    for (const auto& s : spans)
        total_size += s["size"].get<uint64_t>();
    msg.append("\n{} spans, {:.2f} MB", spans.size(), total_size / 1'000'000.0);
    if (auto overview = sync["overview"].get<std::string_view>(); overview != "[]"sv)
        msg.append("\n{}", overview);
    for (const auto& s : spans) {
        auto& c = peers[s["connection_id"].get_ref<const std::string&>()];
        std::string address = "(unknown)";
        if (c.is_object())
            address = "{}:{}"_format(c["ip"].get<std::string_view>(), c["port"].get<uint16_t>());
        auto size = s["size"].get<uint64_t>();
        auto start = s["start_block_height"].get<uint64_t>();
        auto nblocks = s["nblocks"].get<uint64_t>();
        msg.append("\n{:<24s}  {} ({} - {}", address, nblocks, start, start + nblocks - 1);
        if (size == 0)
            msg.append(")  -");
        else
            msg.append(
                    ", {:.1f} kB)  {} kB/s ({})",
                    size / 1000.0,
                    s["rate"].get<uint64_t>() / 1000.0,
                    s["speed"].get<uint64_t>() / 100.0);
    }

    return true;
}

static std::string to_string_rounded(double d, int precision) {
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(precision) << d;
    return ss.str();
}

template <typename E, typename EPrinter>
void print_votes(std::ostream& o, const json& elem, const std::string& key, EPrinter eprint) {
    std::vector<E> voted, missed;
    if (auto it = elem.find(key); it != elem.end()) {
        (*it)["voted"].get_to(voted);
        (*it)["missed"].get_to(missed);
    }
    if (voted.empty() && missed.empty())
        o << "(Awaiting votes from service node)";
    else {
        o << voted.size() << " voted";
        if (!voted.empty())
            o << " [" << tools::join_transform(" ", voted, eprint) << "]";
        if (missed.empty())
            o << ", none missed.";
        else
            o << ", " << missed.size() << " MISSED VOTES ["
              << tools::join_transform(" ", missed, eprint) << "]";
    }
}

static void append_printable_service_node_list_entry(
        cryptonote::network_type nettype,
        bool detailed_view,
        uint64_t blockchain_height,
        uint64_t entry_index,
        const json& entry,
        std::string& buffer) {
    const char indent1[] = "  ";
    const char indent2[] = "    ";
    const char indent3[] = "      ";
    bool is_funded = entry["funded"].get<bool>();

    std::ostringstream stream;

    // Print Funding Status
    {
        stream << indent1 << "[" << entry_index << "] "
               << "Service Node: " << entry["service_node_pubkey"].get<std::string_view>() << " ";
        if (auto e = entry.find("service_node_version"); e != entry.end())
            stream << "v" << tools::join(".", entry["service_node_version"].get<std::vector<int>>())
                   << "\n";
        else
            stream << "v(unknown)\n";

        if (detailed_view) {
            stream << indent2 << "Total Contributed/Staking Requirement: "
                   << cryptonote::print_money(entry["total_contributed"].get<uint64_t>()) << "/"
                   << cryptonote::print_money(entry["staking_requirement"].get<uint64_t>()) << "\n";
            if (auto it = entry.find("total_reserved"); it != entry.end())
                stream << indent2
                       << "Total Reserved: " << cryptonote::print_money(it->get<uint64_t>())
                       << "\n";
        }
    }

    // Print expiry information
    uint64_t const now = time(nullptr);
    {
        auto expiry_height = entry["requested_unlock_height"].get<uint64_t>();

        stream << indent2
               << "Registration: Hardfork Version: " << entry["registration_hf_version"].get<int>()
               << "; Height: " << entry["registration_height"].get<uint64_t>() << "; Expiry: ";
        if (expiry_height == service_nodes::KEY_IMAGE_AWAITING_UNLOCK_HEIGHT)
            stream << "Staking Infinitely (stake unlock not requested)\n";
        else {
            uint64_t delta_height =
                    (blockchain_height >= expiry_height) ? 0 : expiry_height - blockchain_height;
            auto expiry_epoch_time =
                    now + (delta_height * tools::to_seconds(cryptonote::TARGET_BLOCK_TIME));
            stream << expiry_height << " (in " << delta_height << ") blocks\n";

            stream << indent2 << "Expiry Date (estimated): "
                   << "{:%Y-%m-%d %I:%M:%S %p} UTC"_format(fmt::gmtime(expiry_epoch_time)) << " ("
                   << get_human_time_ago(expiry_epoch_time, now) << ")\n";
        }
    }

    if (detailed_view && is_funded)  // Print reward status
    {
        stream << indent2 << "Last Reward (Or Penalty) At (Height/TX Index): "
               << entry["last_reward_block_height"].get<uint64_t>() << "/"
               << entry["last_reward_transaction_index"].get<uint64_t>() << "\n";
    }

    if (detailed_view)  // Print operator information
    {
        // MERGEFIX: figure out what this *should* do and check the corresponding RPC method
        stream << indent2
               << "Operator Fee: " << to_string_rounded(entry["operator_fee"].get<int>() / 1000., 3)
               << "%\n";
        stream << indent2
               << "Operator Address: " << entry["operator_address"].get<std::string_view>() << "\n";
        // stream << indent2 << "Operator Cut (\% Of Reward): " <<
        // to_string_rounded((entry.portions_for_operator /
        // (double)cryptonote::old::STAKING_PORTIONS) * 100.0, 2) << "%\n"; stream << indent2 <<
        // "Operator Address: " << entry.operator_address << "\n";
    }

    if (is_funded)  // Print service node tests
    {
        auto proof_time = entry.value("last_uptime_proof", uint64_t{0});
        epee::console_colors uptime_proof_color =
                proof_time ? epee::console_color_red : epee::console_color_green;

        stream << indent2 << "Last Uptime Proof Received: "
               << (proof_time == 0 ? "(Awaiting confirmation from network)"
                                   : get_human_time_ago(proof_time, time(nullptr)));

        //
        // NOTE: Node Identification
        //
        stream << "\n";
        stream << indent2 << "IP Address & Ports: ";
        if (entry.value("public_ip", "0.0.0.0"s) == "0.0.0.0")
            stream << "(Awaiting confirmation from network)";
        else
            stream << entry["public_ip"].get<std::string_view>() << " :"
                   << entry["storage_port"].get<uint16_t>()
                   << " (storage https), :" << entry["storage_lmq_port"].get<uint16_t>()
                   << " (storage omq), :" << entry["quorumnet_port"].get<uint16_t>()
                   << " (quorumnet)";

        stream << "\n";
        if (detailed_view) {
            auto ed_pk = entry.value("pubkey_ed25519", ""sv);
            stream << indent2 << "Auxiliary Public Keys:\n"
                   << indent3 << (ed_pk.empty() ? "(not yet received)"sv : ed_pk) << " (Ed25519)\n"
                   << indent3
                   << (ed_pk.empty() ? "(not yet received)"s
                                     : oxenc::to_base32z(oxenc::from_hex(ed_pk)) + ".snode")
                   << " (Lokinet)\n"
                   << indent3 << entry.value("pubkey_x25519", "(not yet received)"sv)
                   << " (X25519)\n";
        }

        //
        // NOTE: Storage Server Test
        //
        auto print_reachable = [&stream, &now](const json& j, const std::string& prefix) {
            auto first_unreachable = j.value<time_t>(prefix + "_first_unreachable", 0),
                 last_unreachable = j.value<time_t>(prefix + "_last_unreachable", 0),
                 last_reachable = j.value<time_t>(prefix + "_last_reachable", 0);

            if (first_unreachable == 0) {
                if (last_reachable == 0)
                    stream << "Not yet tested";
                else {
                    stream << "Yes (last tested " << get_human_time_ago(last_reachable, now);
                    if (last_unreachable)
                        stream << "; last failure " << get_human_time_ago(last_unreachable, now);
                    stream << ")";
                }
            } else {
                stream << "NO";
                if (!j.value(prefix + "_reachable", false))
                    stream << " - FAILING!";
                stream << " (last tested " << get_human_time_ago(last_unreachable, now)
                       << "; failing since " << get_human_time_ago(first_unreachable, now);
                if (last_reachable)
                    stream << "; last good " << get_human_time_ago(last_reachable, now);
                stream << ")";
            }
            stream << '\n';
        };
        stream << indent2 << "Storage Server Reachable: ";
        print_reachable(entry, "storage_server");
        stream << indent2 << "Lokinet Reachable: ";
        print_reachable(entry, "lokinet");

        //
        // NOTE: Component Versions
        //
        auto show_component_version = [](const json& j, std::string_view name) {
            if (!j.is_array() || j.front().get<int>() == 0)
                return "("s + std::string{name} + " ping not yet received)"s;
            return tools::join(".", j.get<std::array<int, 3>>());
        };
        stream << indent2 << "Storage Server / Lokinet Router versions: "
               << show_component_version(entry["storage_server_version"], "Storage Server") << " / "
               << show_component_version(entry["storage_server_version"], "Lokinet") << "\n";

        //
        // NOTE: Print Voting History
        //
        stream << indent2 << "Checkpoints votes: ";
        print_votes<uint64_t>(
                stream, entry, "checkpoint_votes", [](uint64_t height) { return height; });

        stream << '\n' << indent2 << "Pulse blocks: ";
        print_votes<std::pair<uint64_t, uint8_t>>(
                stream, entry, "pulse_votes", [](const auto& val) {
                    if (val.second)
                        return "{} {}"_format(val.first, val.second);
                    return "{}"_format(val.first);
                });

        auto print_pass_fail = [&stream, &entry](const std::string& key) {
            std::pair<int, int> val;
            auto& [success, fail] = val;
            if (auto it = entry.find(key); it != entry.end())
                it->get_to(val);

            if (!success && !fail)
                stream << "(Awaiting test data)";
            else {
                stream << success << " passes, ";
                if (fail)
                    stream << fail << " FAILURES";
                else
                    stream << "no failures";
            }
        };

        stream << '\n' << indent2 << "Quorumnet tests: ";
        print_pass_fail("quorumnet_tests");

        stream << '\n' << indent2 << "Timesync tests: ";
        print_pass_fail("timesync_tests");
        stream << '\n';
    }

    if (detailed_view)  // Print contributors
    {
        auto n_contributors = entry["contributors"].size();
        stream << indent2 << "Contributors (" << n_contributors << "):\n";
        for (auto& contributor : entry["contributors"]) {
            stream << indent3 << contributor["address"].get<std::string_view>();
            auto amount = contributor["amount"].get<uint64_t>();
            auto reserved = contributor.value("reserved", amount);
            stream << " (" << cryptonote::print_money(amount, true);
            if (reserved != amount)
                stream << " / " << cryptonote::print_money(reserved, true);
            if (!is_funded || n_contributors > 1) {
                auto required = entry["staking_requirement"].get<uint64_t>();
                stream << " = " << std::round(reserved / (double)required * 10000.) / 100. << "%";
            }
            stream << ")\n";
        }
    }

    //
    // NOTE: Overall status
    //
    if (entry["active"].get<bool>()) {
        stream << indent2 << "Current Status: ACTIVE\n";
        auto downtime = entry["earned_downtime_blocks"].get<uint64_t>();
        stream << indent2 << "Downtime Credits: " << downtime << " blocks"
               << " (about " << to_string_rounded(downtime / (double)cryptonote::BLOCKS_PER_HOUR, 2)
               << " hours)";
        if (downtime < service_nodes::DECOMMISSION_MINIMUM)
            stream << " (Note: " << service_nodes::DECOMMISSION_MINIMUM
                   << " blocks required to enable deregistration delay)";
    } else if (is_funded) {
        stream << indent2 << "Current Status: DECOMMISSIONED";
        auto reason_all = entry["last_decommission_reason_consensus_all"].get<uint16_t>();
        auto reason_any = entry["last_decommission_reason_consensus_any"].get<uint16_t>();
        if (reason_any)
            stream << " - ";
        if (auto reasons = cryptonote::readable_reasons(reason_all); !reasons.empty())
            stream << tools::join(", ", reasons);
        // Add any "any" reasons that aren't in all with a (some) qualifier
        if (auto reasons = cryptonote::readable_reasons(reason_any & ~reason_all);
            !reasons.empty()) {
            for (auto& r : reasons)
                r += "(some)";
            stream << (reason_all ? ", " : "") << tools::join(", ", reasons);
        }
        stream << "\n";
        stream << indent2 << "Remaining Decommission Time Until DEREGISTRATION: "
               << entry["earned_downtime_blocks"].get<uint64_t>() << " blocks";
    } else {
        stream << indent2 << "Current Status: awaiting contributions\n";
    }
    stream << "\n";

    buffer.append(stream.str());
}

bool rpc_command_executor::print_sn(const std::vector<std::string>& args, bool self) {
    std::vector<std::string> pubkeys;

    bool detailed_view = false;
    for (auto& arg : args) {
        if (arg == "+json")
            tools::fail_msg_writer("+json is no longer supported");
        else if (arg == "+detail")
            detailed_view = true;
        else if (self) {
            tools::fail_msg_writer("print_sn_status takes no pubkey arguments");
            return false;
        } else
            pubkeys.push_back(arg);
    }

    auto maybe_info =
            try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
    if (!maybe_info)
        return false;
    auto& info = *maybe_info;

    cryptonote::network_type nettype =
            info.value("mainnet", false)   ? cryptonote::network_type::MAINNET
            : info.value("devnet", false)  ? cryptonote::network_type::DEVNET
            : info.value("testnet", false) ? cryptonote::network_type::TESTNET
                                           : cryptonote::network_type::UNDEFINED;
    uint64_t curr_height = info["height"].get<uint64_t>();

    std::vector<json> awaiting;
    std::vector<json> registered;

    std::string my_sn_pk;
    if (!self) {
        auto maybe_sns = try_running(
                [&] {
                    return invoke<GET_SERVICE_NODES>(json{{"service_node_pubkeys", pubkeys}});
                },
                "Failed to retrieve service node data");
        if (!maybe_sns)
            return false;

        for (auto& entry : (*maybe_sns)["service_node_states"]) {
            if (entry["total_contributed"].get<uint64_t>() ==
                entry["staking_requirement"].get<uint64_t>())
                registered.push_back(std::move(entry));
            else
                awaiting.push_back(std::move(entry));
        }
    } else {
        auto maybe_sn = try_running(
                [&] { return invoke<GET_SERVICE_NODE_STATUS>(); },
                "Failed to retrieve service node status");
        if (!maybe_sn)
            return false;
        auto& sn = (*maybe_sn)["service_node_state"];
        my_sn_pk = sn["service_node_pubkey"];
        if (sn.find("registration_height") != sn.end()) {
            if (sn["total_contributed"].get<uint64_t>() ==
                sn["staking_requirement"].get<uint64_t>())
                registered.push_back(std::move(sn));
            else
                awaiting.push_back(std::move(sn));
        }
    }

    if (awaiting.size() == 0 && registered.size() == 0) {
        if (pubkeys.size() > 0)
            tools::msg_writer(
                    "No service node is currently known on the network: {}",
                    fmt::join(pubkeys, ", "));
        else if (self)
            tools::msg_writer(
                    "Service node {} is not currently registered on the network", my_sn_pk);
        else
            tools::msg_writer("No service nodes are currently known on the network");

        return true;
    }

    std::sort(awaiting.begin(), awaiting.end(), [](const json& a, const json& b) {
        auto a_res = a.find("total_reserved");
        auto b_res = b.find("total_reserved");
        uint64_t total_a = (a_res == a.end() ? a["total_contributed"] : *a_res).get<uint64_t>();
        uint64_t total_b = (b_res == b.end() ? b["total_contributed"] : *b_res).get<uint64_t>();
        uint64_t a_remaining = a["staking_requirement"].get<uint64_t>() - total_a;
        uint64_t b_remaining = b["staking_requirement"].get<uint64_t>() - total_b;

        if (b_remaining == a_remaining)
            return b["portions_for_operator"].get<uint64_t>() <
                   a["portions_for_operator"].get<uint64_t>();

        return b_remaining < a_remaining;
    });

    std::sort(registered.begin(), registered.end(), [](const json& a, const json& b) {
        return std::make_tuple(
                       a["last_reward_block_height"].get<uint64_t>(),
                       a["last_reward_transaction_index"].get<uint64_t>(),
                       a["service_node_pubkey"].get<std::string_view>()) <
               std::make_tuple(
                       b["last_reward_block_height"].get<uint64_t>(),
                       b["last_reward_transaction_index"].get<uint64_t>(),
                       b["service_node_pubkey"].get<std::string_view>());
    });

    std::string awaiting_print_data;
    std::string registered_print_data;
    for (size_t i = 0; i < awaiting.size(); i++) {
        if (i > 0)
            awaiting_print_data += '\n';
        append_printable_service_node_list_entry(
                nettype, detailed_view, curr_height, i, awaiting[i], awaiting_print_data);
    }

    for (size_t i = 0; i < registered.size(); i++) {
        if (i > 0)
            registered_print_data += '\n';
        append_printable_service_node_list_entry(
                nettype, detailed_view, curr_height, i, registered[i], registered_print_data);
    }

    if (awaiting.size() > 0)
        tools::msg_writer(
                "Service Node Awaiting State [{}]\n{}", awaiting.size(), awaiting_print_data);

    if (registered.size() > 0)
        tools::msg_writer(
                "Service Node Registration State [{}]\n{}",
                registered.size(),
                registered_print_data);

    return true;
}

bool rpc_command_executor::flush_cache(bool bad_txs, bool bad_blocks) {
    if (!invoke<FLUSH_CACHE>(
                json{{"bad_txs", bad_txs}, {"bad_blocks", bad_blocks}}, "Failed to flush TX cache"))
        return false;
    return true;
}

bool rpc_command_executor::claim_rewards(const std::string& address) {
    auto maybe_withdrawal_response = try_running(
            [this, address] {
                return invoke<BLS_REWARDS_REQUEST>(json{{"address", address}});
            },
            "Failed to get withdrawal rewards");
    if (!maybe_withdrawal_response)
        return false;
    auto& withdrawal_response = *maybe_withdrawal_response;

    tools::msg_writer(
            "Address: {0:s}\n Amount: {1:d}\n Height: {2:d}\n Signature: {3:s}\n"
            " Link to claim rewards: "
            "https://oxen-eth-webpage.vercel.app/"
            "?amount={1:d}&address={0:s}&height={2:d}&sig={3:s}\n",
            withdrawal_response["address"].get<std::string_view>(),
            withdrawal_response["amount"].get<uint64_t>(),
            withdrawal_response["height"].get<uint64_t>(),
            withdrawal_response["signature"].get<std::string_view>());
    return true;
}

bool rpc_command_executor::print_sn_status(std::vector<std::string> args) {
    return print_sn(std::move(args), true);
}

bool rpc_command_executor::print_sr(uint64_t height) {
    auto maybe_staking_requirement = try_running(
            [this, height] {
                return invoke<GET_STAKING_REQUIREMENT>(json{{"height", height}});
            },
            "Failed to retrieve staking requirements");
    if (!maybe_staking_requirement)
        return false;
    auto& staking_requirement = *maybe_staking_requirement;

    tools::success_msg_writer(
            "Staking Requirement: {}",
            cryptonote::print_money(staking_requirement["staking_requirement"]));
    return true;
}

bool rpc_command_executor::pop_blocks(uint64_t num_blocks) {
    auto maybe_pop_blocks = try_running(
            [this, num_blocks] {
                return invoke<POP_BLOCKS>(json{{"nblocks", num_blocks}});
            },
            "Failed to pop blocks");
    if (!maybe_pop_blocks)
        return false;
    auto& pop_blocks = *maybe_pop_blocks;

    tools::success_msg_writer("new height: {}", pop_blocks["height"].get<int64_t>());
    return true;
}

bool rpc_command_executor::print_sn_key() {

    auto maybe_service_keys = try_running(
            [this] { return invoke<GET_SERVICE_KEYS>(json{}); },
            "Failed to retrieve service node keys");
    if (!maybe_service_keys)
        return false;

    auto my_sn_keys = *maybe_service_keys;

    tools::success_msg_writer(
            "Service Node Public Key: {}\n"
            "     Ed25519 Public Key: {}\n"
            "      X25519 Public Key: {}",
            my_sn_keys["service_node_pubkey"].get<std::string_view>(),
            my_sn_keys["service_node_ed25519_pubkey"].get<std::string_view>(),
            my_sn_keys["service_node_x25519_pubkey"].get<std::string_view>());
    return true;
}

namespace {

    // Returns an error message on invalid, nullopt if good
    std::optional<std::string_view> is_invalid_staking_address(
            std::string_view addr, const cryptonote::network_type nettype) {
        cryptonote::address_parse_info info;
        bool valid = get_account_address_from_str(info, nettype, addr);
        if (!valid)
            return "Invalid OXEN address"sv;
        if (info.is_subaddress)
            return "Staking from subaddresses is not supported"sv;
        if (info.has_payment_id)
            return "Staking with a payment id/integrated address is not supported"sv;
        return std::nullopt;
    }

    std::string highlight_money(uint64_t amount) {
        return "\x1b[36;1m{}\x1b[0m"_format(cryptonote::format_money(amount));
    };

}  // namespace

bool rpc_command_executor::prepare_registration(bool force_registration) {
    auto maybe_info =
            try_running([this] { return invoke<GET_INFO>(); }, "Failed to retrieve node info");
    if (!maybe_info)
        return false;
    auto& info = *maybe_info;

    // Check if the daemon was started in Service Node or not
    if (!info.value("service_node", false)) {
        tools::fail_msg_writer(
                "Unable to prepare registration: this daemon is not running in --service-node "
                "mode");
        return false;
    }

    auto maybe_hf = try_running(
            [this] { return invoke<HARD_FORK_INFO>(); }, "Failed to retrieve hard fork info");
    if (!maybe_hf)
        return false;
    auto& hfinfo = *maybe_hf;
    auto hf_version = hfinfo["version"].get<cryptonote::hf>();
    if (hf_version < hf::hf19_reward_batching) {
        tools::fail_msg_writer("Error: this command only supports HF19+");
        return false;
    }

    auto maybe_keys = try_running(
            [this] { return invoke<GET_SERVICE_KEYS>(); }, "Failed to retrieve service node keys");
    if (!maybe_keys)
        return false;
    auto& snode_keys = *maybe_keys;

    // TODO sean use the feature flag instead
    if (hf_version > hf::hf20) {
        tools::success_msg_writer(
                "Service Node Pubkey: {}\n"
                "Service Node Signature: {}\n",
                snode_keys.value<std::string>("service_node_pubkey", ""),
                snode_keys.value<std::string>(
                        "service_node_signature",
                        ""));  // Assuming 'service_node_signature' is the key for signature
        return true;
    }

    if (!info.value("devnet", false))  // Devnet doesn't run storage-server / lokinet
    {
        auto now = std::chrono::system_clock::now();
        auto last_lokinet_ping_timet = info.value<std::time_t>("last_lokinet_ping", 0);
        if (auto last_lokinet_ping =
                    std::chrono::system_clock::from_time_t(last_lokinet_ping_timet);
            last_lokinet_ping < now - 1min && !force_registration) {
            tools::fail_msg_writer(
                    "Unable to prepare registration: this daemon has not received a ping from "
                    "lokinet {}",
                    last_lokinet_ping_timet == 0
                            ? "yet"
                            : "since " + get_human_time_ago(now - last_lokinet_ping));
            return false;
        }
        auto last_ss_ping_timet = info.value<std::time_t>("last_storage_server_ping", 0);
        if (auto last_storage_server_ping =
                    std::chrono::system_clock::from_time_t(last_ss_ping_timet);
            last_storage_server_ping < now - 1min && !force_registration) {
            tools::fail_msg_writer(
                    "Unable to prepare registration: this daemon has not received a ping from the "
                    "storage server {}",
                    last_ss_ping_timet == 0
                            ? "yet"
                            : "since " + get_human_time_ago(now - last_storage_server_ping));
            return false;
        }
    }

    uint64_t block_height =
            std::max(info["height"].get<uint64_t>(), info["target_height"].get<uint64_t>());
    cryptonote::network_type const nettype =
            info.value("mainnet", false)   ? cryptonote::network_type::MAINNET
            : info.value("devnet", false)  ? cryptonote::network_type::DEVNET
            : info.value("testnet", false) ? cryptonote::network_type::TESTNET
            : info["nettype"].get<std::string_view>() == "fakechain"
                    ? cryptonote::network_type::FAKECHAIN
                    : cryptonote::network_type::UNDEFINED;

    // Query the latest block we've synced and check that the timestamp is sensible, issue a warning
    // if not
    {
        auto const& maybe_header = try_running(
                [this] {
                    return invoke<GET_LAST_BLOCK_HEADER>()
                            .at("block_header")
                            .get<block_header_response>();
                },
                "Get latest block failed, unable to check sync status");
        if (!maybe_header)
            return false;

        auto const& header = *maybe_header;

        const auto now = std::chrono::system_clock::now();
        const auto block_ts = std::chrono::system_clock::from_time_t(header.timestamp);

        if (now - block_ts >= 10min) {
            tools::fail_msg_writer(
                    "The last block this Service Node knows about was at least {}\n"
                    "Your node is possibly desynced from the network or still syncing to the "
                    "network.\n\n"
                    "Registering this node may result in a deregistration due to being out of date "
                    "with the network\n",
                    get_human_time_ago(now - block_ts));
        }

        if (auto synced_height = header.height; block_height >= synced_height) {
            uint64_t delta = block_height - header.height;
            if (delta > 5) {
                tools::fail_msg_writer(
                        "The last block this Service Node synced is {} blocks away from the "
                        "longest chain we know about.\n\n"
                        "Registering this node may result in a deregistration due to being out of "
                        "date with the network\n",
                        delta);
            }
        }
    }

    const uint64_t staking_requirement =
            service_nodes::get_staking_requirement(nettype, hf_version);

    fmt::print(
            "\n\n\x1b[33;1m"
            "Oxen Service Node Registration\n"
            "------------------------------\n"
            "Service Node Pubkey: \x1b[32;1m{}\x1b[33;1m\n"
            "Staking requirement: {} from up to {} contributors\n\n",
            snode_keys.value<std::string>("service_node_pubkey", ""),
            highlight_money(staking_requirement),
            oxen::MAX_CONTRIBUTORS_HF19);

    enum struct register_step {
        ask_address,
        ask_amount,
        get_operator_fee,
        summary_info,
        final_summary,
        cancelled_by_user,
    };

    struct prepare_registration_state {
        register_step prev_step = register_step::ask_address;
        uint16_t operator_fee = cryptonote::STAKING_FEE_BASIS;
        uint64_t total_reserved_contributions = 0;
        std::vector<std::pair<std::string, uint64_t>> contributions;
    };

    prepare_registration_state state{};
    std::stack<prepare_registration_state> state_stack;
    state_stack.push(state);

    bool finished = false;
    bool go_back = false;
    auto step = register_step::ask_address;

    auto next_step = [&](register_step next) {
        state.prev_step = step;
        step = next;
        state_stack.push(state);
        std::cout << std::endl;
    };
    auto check_cancel_back = [&](input_line_result result) -> bool {
        switch (result) {
            case input_line_result::cancel: step = register_step::cancelled_by_user; return true;
            case input_line_result::back: go_back = true; return true;
            default: return false;
        }
    };

    while (!finished) {
        if (go_back) {
            step = state.prev_step;
            state_stack.pop();
            state = state_stack.top();
            go_back = false;
            std::cout << std::endl;
        }

        switch (step) {
            case register_step::ask_address: {
                bool is_operator = state.contributions.empty();
                std::string prompt;
                if (is_operator)
                    prompt = "\n\nEnter the OXEN address of the the Service Node operator\n";
                else
                    prompt = fmt::format(
                            "\n\nThis service node requires an additional stake of {}.\n\n"
                            "To add a reserved contribution spot enter the contributor's OXEN "
                            "address now.\n"
                            "Leave this blank to leave the remaining stake open to public "
                            "contributors.\n",
                            highlight_money(
                                    staking_requirement - state.total_reserved_contributions));
                auto [result, address_str] = input_line_value(prompt, /*back=*/!is_operator);

                if (check_cancel_back(result))
                    break;

                if (!is_operator && address_str.empty())
                    next_step(register_step::get_operator_fee);
                else if (auto bad = is_invalid_staking_address(address_str, nettype))
                    tools::fail_msg_writer("{}\n", *bad);
                else if (std::any_of(
                                 state.contributions.begin(),
                                 state.contributions.end(),
                                 [a = address_str](auto& b) { return b.first == a; }))
                    tools::fail_msg_writer(
                            "Invalid OXEN address: you cannot provide the same address twice\n");
                else {
                    state.contributions.emplace_back(std::move(address_str), 0);
                    next_step(register_step::ask_amount);
                }
                break;
            }

            case register_step::ask_amount: {
                bool is_operator = state.total_reserved_contributions == 0;
                uint64_t amount_left = staking_requirement - state.total_reserved_contributions;
                uint64_t min_contribution = is_operator ? oxen::MINIMUM_OPERATOR_CONTRIBUTION(
                                                                  staking_requirement)
                                                        : service_nodes::get_min_node_contribution(
                                                                  hf_version,
                                                                  staking_requirement,
                                                                  state.total_reserved_contributions,
                                                                  state.contributions.size() - 1 /* -1 because we already added this address to the list */);

                auto [result, contribution_str] = input_line_value(
                        fmt::format(
                                "\n\nThe {} must stake between {} and {}.\n\n"
                                "How much OXEN does {} want to stake?",
                                is_operator ? "operator" : "next contributor",
                                highlight_money(min_contribution),
                                highlight_money(amount_left),
                                is_operator
                                        ? "the operator"
                                        : "contributor {}"_format(state.contributions.size() - 1)),
                        true,
                        "/\x1b[36;1mmax\x1b[0m/\x1b[36;1mmin\x1b[0m",
                        "max");

                if (check_cancel_back(result))
                    break;

                uint64_t contribution;
                if (contribution_str == "max") {
                    fmt::print("Using maximum contribution ({})\n", highlight_money(amount_left));
                    contribution = amount_left;
                } else if (contribution_str == "min") {
                    fmt::print(
                            "Using minimum contribution ({})\n", highlight_money(min_contribution));
                    contribution = min_contribution;
                } else if (auto c = cryptonote::parse_amount(contribution_str))
                    contribution = *c;
                else {
                    tools::fail_msg_writer("Invalid amount.\n");
                    break;
                }

                if (contribution > amount_left) {
                    tools::fail_msg_writer(
                            "Invalid amount: The contribution exceeds the remaining staking "
                            "requirement ({}).\n",
                            highlight_money(amount_left));
                    break;
                } else if (contribution < min_contribution) {
                    tools::fail_msg_writer(
                            "Invalid amount: The contribution does not meet the minimum staking "
                            "requirement ({}).\n",
                            highlight_money(min_contribution));
                    break;
                }

                state.contributions.back().second = contribution;
                state.total_reserved_contributions += contribution;

                next_step(
                        state.total_reserved_contributions < staking_requirement
                                ? register_step::ask_address
                                : register_step::get_operator_fee);
                break;
            }

            case register_step::get_operator_fee: {
                if (state.contributions.size() == 1 &&
                    state.total_reserved_contributions == staking_requirement) {
                    // Solo node, don't need to ask the fee
                    state.operator_fee = cryptonote::STAKING_FEE_BASIS;
                    step = register_step::summary_info;  // Not next_step() because we have no state
                                                         // to unwind
                } else {
                    auto [result, operator_fee_str] = input_line_value(R"(


This service node has multiple contributors and thus requires an operator fee
percentage.  This percentage is removed from the block reward and assigned to
the operator, then the remaining reward is split among contributors (including
the operator) proportionally to their contribution.

Enter the operator fee as a percentage [0.00-100.00])");

                    if (check_cancel_back(result))
                        break;

                    try {
                        state.operator_fee =
                                service_nodes::percent_to_basis_points(operator_fee_str);
                        next_step(register_step::summary_info);
                    } catch (const std::exception& e) {
                        tools::fail_msg_writer().append(
                                "Invalid value: {}. Fee must be between 0 and 100%",
                                operator_fee_str);
                    }
                }
                break;
            }

            case register_step::summary_info: {
                uint64_t open_spots = oxen::MAX_CONTRIBUTORS_HF19 - state.contributions.size();
                const uint64_t amount_left =
                        staking_requirement - state.total_reserved_contributions;
                fmt::print(
                        "Total reserved contributions: {}\n",
                        highlight_money(state.total_reserved_contributions));
                if (amount_left == 0) {
                    // Not calling next_step here because we have no state change to push
                    step = register_step::final_summary;
                    std::cout << std::endl;
                    break;
                }

                fmt::print(
                        R"(
The total reserved amount ({}) is less than the required full stake ({}).
The remaining stake ({}) will be open to contribution from {}.
The Service Node will not activate until the entire stake has been contributed.

)",
                        highlight_money(state.total_reserved_contributions),
                        highlight_money(staking_requirement),
                        highlight_money(amount_left),
                        open_spots > 1 ? "1-{} public contributors"_format(open_spots)
                                       : "1 public contributor");

                auto result = input_line_ask("Is this acceptable?");
                if (result == input_line_result::no)
                    result = input_line_result::cancel;
                if (check_cancel_back(result))
                    break;

                next_step(register_step::final_summary);
                break;
            }

            case register_step::final_summary: {
                const uint64_t amount_left =
                        staking_requirement - state.total_reserved_contributions;

                std::cout << "\nRegistration Summary:\n\n";

                std::cout << "Service Node Pubkey: \x1b[32;1m" << snode_keys["service_node_pubkey"]
                          << "\x1b[0m\n"
                          << std::endl;

                if (amount_left > 0 || state.contributions.size() > 1)
                    fmt::print(
                            "Operator fee (as % of Service Node rewards): \x1b[33;1m{}%\x1b[0m\n\n",
                            state.operator_fee * 100.0 / (double)cryptonote::STAKING_FEE_BASIS);

                constexpr auto row = "{:^14}  {:^13}  {:>17}  {:>8}\n"sv;
                fmt::print(row, "Contributor", "Address", "Contribution", "Contr. %");
                fmt::print(row, "_____________", "_____________", "_________________", "________");
                fmt::print("\n");

                for (size_t i = 0; i < state.contributions.size(); ++i) {
                    const auto& [addr, amount] = state.contributions[i];
                    fmt::print(
                            row,
                            (i == 0) ? "Operator" : "Contributor " + std::to_string(i),
                            addr.substr(0, 9) + ".." + addr.substr(addr.size() - 2),
                            cryptonote::print_money(amount),
                            "{:.2f}%"_format(amount * 100.0 / staking_requirement));
                }

                if (amount_left > 0) {
                    size_t open_spots = oxen::MAX_CONTRIBUTORS_HF19 - state.contributions.size();
                    for (size_t i = 0; i < open_spots; i++)
                        fmt::print(
                                row,
                                "(open)",
                                "(any)",
                                i == 0 && open_spots == 1 ? cryptonote::print_money(amount_left)
                                : i == 0                  ? ">=" + cryptonote::print_money(
                                                          (amount_left + open_spots - 1) /
                                                          open_spots)
                                         : "",
                                i == 0 && open_spots == 1
                                        ? "{:.2f}%"_format(
                                                  amount_left * 100.0 / staking_requirement)
                                : i == 0 ? ">={:.2f}%"_format(
                                                   amount_left * 100.0 / staking_requirement /
                                                   open_spots)
                                         : "");
                }

                auto result = input_line_ask("\nIs the staking information above correct?");
                if (result == input_line_result::no)
                    result = input_line_result::cancel;
                if (check_cancel_back(result))
                    break;

                finished = true;
                break;
            }

            case register_step::cancelled_by_user: {
                tools::fail_msg_writer("Registration preparation cancelled.\n");
                return true;
            }
        }
    }

    // <operator_fee> <address> <amount> [<address> <amount> [...]]]
    std::vector<std::string> args;
    args.reserve(1 + 2 * state.contributions.size());
    args.push_back(std::to_string(state.operator_fee));
    for (const auto& [addr, portion] : state.contributions) {
        args.push_back(addr);
        args.push_back(std::to_string(portion));
    }

    {
        auto maybe_registration = try_running(
                [this, staking_requirement, &args] {
                    return invoke<GET_SERVICE_NODE_REGISTRATION_CMD_RAW>(
                            json{{"staking_requirement", staking_requirement},
                                 {"args", args},
                                 {"make_friendly", true}});
                },
                "Failed to validate registration arguments; check the addresses and registration "
                "parameters and that the Daemon is running with the '--service-node' flag");
        if (!maybe_registration)
            return false;
        auto& registration = *maybe_registration;

        tools::success_msg_writer(
                "\n\n{}\n\n", registration["registration_cmd"].get<std::string_view>());
        return true;
    }

    return false;
}

bool rpc_command_executor::prune_blockchain() {
    tools::fail_msg_writer("Blockchain pruning is not supported in Oxen yet");
    return true;
}

bool rpc_command_executor::check_blockchain_pruning() {
    auto maybe_pruning = try_running(
            [this] {
                return invoke<PRUNE_BLOCKCHAIN>(json{{"check", true}});
            },
            "Failed to check blockchain pruning status");
    if (!maybe_pruning)
        return false;
    auto& pruning = *maybe_pruning;

    tools::success_msg_writer("Blockchain {} pruned", pruning["pruning_seed"] ? "is" : "is not");
    return true;
}

bool rpc_command_executor::version() {
    auto version = try_running(
            [this] { return invoke<GET_INFO>().at("version").get<std::string>(); },
            "Failed to retrieve node info");
    if (!version)
        return false;
    tools::success_msg_writer() + *version;
    return true;
}

bool rpc_command_executor::test_trigger_uptime_proof() {
    return invoke<TEST_TRIGGER_UPTIME_PROOF>(json{{}}, "Failed to trigger uptime proof");
}

}  // namespace daemonize
