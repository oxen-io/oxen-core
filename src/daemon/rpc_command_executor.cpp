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

#include "epee/string_tools.h"
#include "common/password.h"
#include "common/scoped_message_writer.h"
#include "common/pruning.h"
#include "common/hex.h"
#include "daemon/rpc_command_executor.h"
#include "epee/int-util.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "cryptonote_core/service_node_rules.h"
#include "cryptonote_basic/hardfork.h"
#include "checkpoints/checkpoints.h"
#include <boost/format.hpp>

#include "common/loki_integration_test_hooks.h"

#include <fstream>
#include <ctime>
#include <string>
#include <numeric>
#include <stack>

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "daemon"

using namespace cryptonote::rpc;

namespace daemonize {

namespace {
  enum class input_line_result { yes, no, cancel, back, };

  std::string input_line(std::string const &prompt)
  {
    std::cout << prompt << std::flush;
    std::string result;
#if defined (LOKI_ENABLE_INTEGRATION_TEST_HOOKS)
    integration_test::write_buffered_stdout();
    result = integration_test::read_from_pipe();
#else
    rdln::suspend_readline pause_readline;
    std::cin >> result;
#endif

    return result;
  }

  input_line_result input_line_yes_no_back_cancel(char const *msg)
  {
    std::string prompt = std::string(msg);
    prompt += " (Y/Yes/N/No/B/Back/C/Cancel): ";
    std::string input = input_line(prompt);

    if (command_line::is_yes(input))  return input_line_result::yes;
    if (command_line::is_no(input))   return input_line_result::no;
    if (command_line::is_back(input)) return input_line_result::back;
    return input_line_result::cancel;
  }

  input_line_result input_line_yes_no_cancel(char const *msg)
  {
    std::string prompt = msg;
    prompt += " (Y/Yes/N/No/C/Cancel): ";
    std::string input = input_line(prompt);

    if (command_line::is_yes(input)) return input_line_result::yes;
    if (command_line::is_no(input))  return input_line_result::no;
    return input_line_result::cancel;
  }


  input_line_result input_line_back_cancel_get_input(char const *msg, std::string &input)
  {
    std::string prompt = msg;
    prompt += " (B/Back/C/Cancel): ";
    input   = input_line(prompt);

    if (command_line::is_back(input))   return input_line_result::back;
    if (command_line::is_cancel(input)) return input_line_result::cancel;
    return input_line_result::yes;
  }

  const char *get_address_type_name(epee::net_utils::address_type address_type)
  {
    switch (address_type)
    {
      default:
      case epee::net_utils::address_type::invalid: return "invalid";
      case epee::net_utils::address_type::ipv4: return "IPv4";
      case epee::net_utils::address_type::ipv6: return "IPv6";
      case epee::net_utils::address_type::i2p: return "I2P";
      case epee::net_utils::address_type::tor: return "Tor";
    }
  }

  void print_peer(std::string const & prefix, GET_PEER_LIST::peer const & peer, bool pruned_only, bool publicrpc_only)
  {
    if (pruned_only && peer.pruning_seed == 0)
      return;
    if (publicrpc_only && peer.rpc_port == 0)
      return;

    time_t now = std::time(nullptr);
    time_t last_seen = static_cast<time_t>(peer.last_seen);

    std::string elapsed = peer.last_seen == 0 ? "never" : epee::misc_utils::get_time_interval_string(now - last_seen);
    std::string id_str = epee::string_tools::pad_string(epee::string_tools::to_string_hex(peer.id), 16, '0', true);
    std::string addr_str = peer.host + ":" + std::to_string(peer.port);
    std::string rpc_port = peer.rpc_port ? std::to_string(peer.rpc_port) : "-";
    std::string pruning_seed = epee::string_tools::to_string_hex(peer.pruning_seed);
    tools::msg_writer() << boost::format("%-10s %-25s %-25s %-5s %-4s %s") % prefix % id_str % addr_str % rpc_port % pruning_seed % elapsed;
  }

  void print_block_header(block_header_response const & header)
  {
    tools::success_msg_writer()
      << "timestamp: " << header.timestamp << " (" << tools::get_human_readable_timestamp(header.timestamp) << ")" << "\n"
      << "previous hash: " << header.prev_hash << "\n"
      << "nonce: " << header.nonce << "\n"
      << "is orphan: " << header.orphan_status << "\n"
      << "height: " << header.height << "\n"
      << "depth: " << header.depth << "\n"
      << "hash: " << header.hash << "\n"
      << "difficulty: " << header.difficulty << "\n"
      << "cumulative_difficulty: " << header.cumulative_difficulty << "\n"
      << "POW hash: " << header.pow_hash.value_or("N/A") << "\n"
      << "block size: " << header.block_size << "\n"
      << "block weight: " << header.block_weight << "\n"
      << "long term weight: " << header.long_term_weight << "\n"
      << "num txes: " << header.num_txes << "\n"
      << "reward: " << cryptonote::print_money(header.reward) << "\n"
      << "miner reward: " << cryptonote::print_money(header.miner_reward) << "\n"
      << "service node winner: " << header.service_node_winner << "\n"
      << "miner tx hash: " << header.miner_tx_hash;
  }

  std::string get_human_time_ago(time_t t, time_t now, bool abbreviate = false)
  {
    if (t == now)
      return "now";
    time_t dt = t > now ? t - now : now - t;
    std::string s;
    if (dt < 90)
      s = std::to_string(dt) + (abbreviate ? "sec" : dt == 1 ? " second" : " seconds");
    else if (dt < 90 * 60)
      s = (boost::format(abbreviate ? "%.1fmin" : "%.1f minutes") % ((float)dt/60)).str();
    else if (dt < 36 * 3600)
      s = (boost::format(abbreviate ? "%.1fhr" : "%.1f hours") % ((float)dt/3600)).str();
    else
      s = (boost::format("%.1f days") % ((float)dt/(3600*24))).str();
    if (abbreviate) {
        if (t > now)
            return s + " (in fut.)";
        return s;
    }
    return s + " " + (t > now ? "in the future" : "ago");
  }

  char const *get_date_time(time_t t)
  {
    static char buf[128];
    buf[0] = 0;

    struct tm tm;
    epee::misc_utils::get_gmt_time(t, tm);
    strftime(buf, sizeof(buf), "%Y-%m-%d %I:%M:%S %p UTC", &tm);
    return buf;
  }

  std::string get_time_hms(time_t t)
  {
    unsigned int hours, minutes, seconds;
    char buffer[24];
    hours = t / 3600;
    t %= 3600;
    minutes = t / 60;
    t %= 60;
    seconds = t;
    snprintf(buffer, sizeof(buffer), "%02u:%02u:%02u", hours, minutes, seconds);
    return std::string(buffer);
  }
}

rpc_command_executor::rpc_command_executor(
    std::string remote_url,
    const std::optional<tools::login>& login
  )
{
  m_rpc_client.emplace(remote_url);
  if (login)
    m_rpc_client->set_auth(login->username, std::string{login->password.password().view()});
}

bool rpc_command_executor::print_checkpoints(uint64_t start_height, uint64_t end_height, bool print_json)
{
  GET_CHECKPOINTS::request  req{start_height, end_height};
  if (req.start_height == GET_CHECKPOINTS::HEIGHT_SENTINEL_VALUE &&
      req.end_height   == GET_CHECKPOINTS::HEIGHT_SENTINEL_VALUE)
  {
    req.count = GET_CHECKPOINTS::NUM_CHECKPOINTS_TO_QUERY_BY_DEFAULT;
  }
  else if (req.start_height == GET_CHECKPOINTS::HEIGHT_SENTINEL_VALUE ||
           req.end_height   == GET_CHECKPOINTS::HEIGHT_SENTINEL_VALUE)
  {
    req.count = 1;
  }
  // Otherwise, neither heights are set to HEIGHT_SENTINEL_VALUE, so get all the checkpoints between start and end

  GET_CHECKPOINTS::response res{};
  if (!invoke<GET_CHECKPOINTS>(std::move(req), res, "Failed to query blockchain checkpoints"))
    return false;

  std::string entry;
  if (print_json) entry.append("{\n\"checkpoints\": [");
  for (size_t i = 0; i < res.checkpoints.size(); i++)
  {
    GET_CHECKPOINTS::checkpoint_serialized &checkpoint = res.checkpoints[i];
    if (print_json)
    {
      entry.append("\n");
      entry.append(epee::serialization::store_t_to_json(checkpoint));
      entry.append(",\n");
    }
    else
    {
      entry.append("[");
      entry.append(std::to_string(i));
      entry.append("]");

      entry.append(" Type: ");
      entry.append(checkpoint.type);

      entry.append(" Height: ");
      entry.append(std::to_string(checkpoint.height));

      entry.append(" Hash: ");
      entry.append(checkpoint.block_hash);
      entry.append("\n");
    }
  }

  if (print_json)
  {
    entry.append("]\n}");
  }
  else
  {
    if (entry.empty())
      entry.append("No Checkpoints");
  }

  tools::success_msg_writer() << entry;
  return true;
}

bool rpc_command_executor::print_sn_state_changes(uint64_t start_height, uint64_t end_height)
{
  GET_SN_STATE_CHANGES::request  req{};
  GET_SN_STATE_CHANGES::response res{};

  req.start_height = start_height;
  req.end_height   = end_height;

  if (!invoke<GET_SN_STATE_CHANGES>(std::move(req), res, "Failed to query service nodes state changes"))
    return false;

  std::stringstream output;

  output << "Service Node State Changes (blocks " << res.start_height << "-" << res.end_height << ")" << std::endl;
  output << " Recommissions:\t\t" << res.total_recommission << std::endl;
  output << " Unlocks:\t\t" << res.total_unlock << std::endl;
  output << " Decommissions:\t\t" << res.total_decommission << std::endl;
  output << " Deregistrations:\t" << res.total_deregister << std::endl;
  output << " IP change penalties:\t" << res.total_ip_change_penalty << std::endl;

  tools::success_msg_writer() << output.str();
  return true;
}

bool rpc_command_executor::print_peer_list(bool white, bool gray, size_t limit, bool pruned_only, bool publicrpc_only) {
  GET_PEER_LIST::response res{};

  if (!invoke<GET_PEER_LIST>({}, res, "Couldn't retrieve peer list"))
    return false;

  if (white)
  {
    auto peer = res.white_list.cbegin();
    const auto end = limit ? peer + std::min(limit, res.white_list.size()) : res.white_list.cend();
    for (; peer != end; ++peer)
    {
      print_peer("white", *peer, pruned_only, publicrpc_only);
    }
  }

  if (gray)
  {
    auto peer = res.gray_list.cbegin();
    const auto end = limit ? peer + std::min(limit, res.gray_list.size()) : res.gray_list.cend();
    for (; peer != end; ++peer)
    {
      print_peer("gray", *peer, pruned_only, publicrpc_only);
    }
  }

  return true;
}

bool rpc_command_executor::print_peer_list_stats() {
  GET_PEER_LIST::response res{};

  if (!invoke<GET_PEER_LIST>({}, res, "Couldn't retrieve peer list"))
    return false;

  tools::msg_writer()
    << "White list size: " << res.white_list.size() << "/" << P2P_LOCAL_WHITE_PEERLIST_LIMIT << " (" << res.white_list.size() *  100.0 / P2P_LOCAL_WHITE_PEERLIST_LIMIT << "%)" << std::endl
    << "Gray list size: " << res.gray_list.size() << "/" << P2P_LOCAL_GRAY_PEERLIST_LIMIT << " (" << res.gray_list.size() *  100.0 / P2P_LOCAL_GRAY_PEERLIST_LIMIT << "%)";

  return true;
}

bool rpc_command_executor::save_blockchain() {
  SAVE_BC::response res{};

  if (!invoke<SAVE_BC>({}, res, "Couldn't save blockchain"))
    return false;

  tools::success_msg_writer() << "Blockchain saved";

  return true;
}

bool rpc_command_executor::show_hash_rate() {
  SET_LOG_HASH_RATE::request req{};
  SET_LOG_HASH_RATE::response res{};
  req.visible = true;

  if (!invoke<SET_LOG_HASH_RATE>(std::move(req), res, "Couldn't enable hash rate logging"))
    return false;

  tools::success_msg_writer() << "Hash rate logging is on";

  return true;
}

bool rpc_command_executor::hide_hash_rate() {
  SET_LOG_HASH_RATE::request req{};
  SET_LOG_HASH_RATE::response res{};
  req.visible = false;

  if (!invoke<SET_LOG_HASH_RATE>(std::move(req), res, "Couldn't disable hash rate logging"))
    return false;

  tools::success_msg_writer() << "Hash rate logging is off";

  return true;
}

bool rpc_command_executor::show_difficulty() {
  GET_INFO::response res{};
  if (!invoke<GET_INFO>({}, res, "Failed to get node info"))
    return false;

  tools::success_msg_writer() <<   "BH: " << res.height
                              << ", TH: " << res.top_block_hash
                              << ", DIFF: " << res.difficulty
                              << ", CUM_DIFF: " << res.cumulative_difficulty
                              << ", HR: " << res.difficulty / res.target << " H/s";

  return true;
}

static std::string get_mining_speed(uint64_t hr)
{
  if (hr>1e9) return (boost::format("%.2f GH/s") % (hr/1e9)).str();
  if (hr>1e6) return (boost::format("%.2f MH/s") % (hr/1e6)).str();
  if (hr>1e3) return (boost::format("%.2f kH/s") % (hr/1e3)).str();
  return (boost::format("%.0f H/s") % hr).str();
}

static std::ostream& print_fork_extra_info(std::ostream& o, uint64_t t, uint64_t now, uint64_t block_time)
{
  uint64_t blocks_per_day = 86400 / block_time;

  if (t == now)
    return o << " (forking now)";
  if (t < now)
    return o;
  uint64_t dblocks = t - now;
  if (dblocks > blocks_per_day * 30)
    return o;
  o << " (next fork in ";
  if (dblocks <= 30)
    return o << dblocks << " blocks)";
  if (dblocks <= blocks_per_day / 2)
    return o << boost::format("%.1f hours)") % (dblocks / (float)blocks_per_day * 24);
  return o << boost::format("%.1f days)") % (dblocks / (float)blocks_per_day);
}

static float get_sync_percentage(uint64_t height, uint64_t target_height)
{
  target_height = target_height ? target_height < height ? height : target_height : height;
  float pc = 100.0f * height / target_height;
  if (height < target_height && pc > 99.9f)
    return 99.9f; // to avoid 100% when not fully synced
  return pc;
}
static float get_sync_percentage(const GET_INFO::response &ires)
{
  return get_sync_percentage(ires.height, ires.target_height);
}

bool rpc_command_executor::show_status() {
  GET_INFO::response ires{};
  HARD_FORK_INFO::request hfreq{};
  HARD_FORK_INFO::response hfres{};
  MINING_STATUS::response mres{};
  bool has_mining_info = false;

  hfreq.version = 0;
  bool mining_busy = false;
  if (!invoke<GET_INFO>({}, ires, "Failed to get node info") ||
      !invoke<HARD_FORK_INFO>(std::move(hfreq), hfres, "Failed to retrieve hard fork info"))
    return false;
  if (ires.start_time) // This will only be non-null if we were recognized as admin (which we need for mining info)
  {
    has_mining_info = invoke<MINING_STATUS>({}, mres, "Failed to retrieve mining info", false);
    if (has_mining_info) {
      if (mres.status == STATUS_BUSY)
        mining_busy = true;
      else if (mres.status != STATUS_OK) {
        tools::fail_msg_writer() << "Failed to retrieve mining info";
        return false;
      }
    }
  }

  std::string my_sn_key;
  int64_t my_decomm_remaining = 0;
  uint64_t my_sn_last_uptime = 0;
  bool my_sn_registered = false, my_sn_staked = false, my_sn_active = false;
  if (ires.service_node && *ires.service_node) {
    GET_SERVICE_KEYS::response res{};

    if (!invoke<GET_SERVICE_KEYS>({}, res, "Failed to retrieve service node keys"))
      return false;

    my_sn_key = std::move(res.service_node_pubkey);
    GET_SERVICE_NODES::request sn_req{};
    GET_SERVICE_NODES::response sn_res{};

    sn_req.service_node_pubkeys.push_back(my_sn_key);
    if (invoke<GET_SERVICE_NODES>(std::move(sn_req), sn_res, "") && sn_res.service_node_states.size() == 1)
    {
      auto &entry = sn_res.service_node_states.front();
      my_sn_registered = true;
      my_sn_staked = entry.total_contributed >= entry.staking_requirement;
      my_sn_active = entry.active;
      my_decomm_remaining = entry.earned_downtime_blocks;
      my_sn_last_uptime = entry.last_uptime_proof;
    }
  }

  uint64_t net_height = ires.target_height > ires.height ? ires.target_height : ires.height;
  std::string bootstrap_msg;

  std::ostringstream str;
  str << "Height: " << ires.height;
  if (ires.height != net_height)
      str << "/" << net_height << " (" << boost::format("%.1f") % get_sync_percentage(ires) << "%)";

  if (ires.testnet)     str << " ON TESTNET";
  else if (ires.devnet) str << " ON DEVNET";

  if (ires.height < ires.target_height)
    str << ", syncing";

  if (ires.was_bootstrap_ever_used && *ires.was_bootstrap_ever_used && ires.bootstrap_daemon_address)
  {
    str << ", bootstrap " << *ires.bootstrap_daemon_address;
    if (ires.untrusted)
      str << boost::format(", local height: %llu (%.1f%%)") % *ires.height_without_bootstrap % get_sync_percentage(*ires.height_without_bootstrap, net_height);
    else
      str << " was used";
  }

  if (hfres.version < HF_VERSION_PULSE && !has_mining_info)
    str << ", mining info unavailable";
  if (has_mining_info && !mining_busy && mres.active)
    str << ", mining at " << get_mining_speed(mres.speed);

  if (hfres.version < HF_VERSION_PULSE)
    str << ", net hash " << get_mining_speed(ires.difficulty / ires.target);

  str << ", v" << (ires.version.empty() ? "?.?.?" : ires.version);
  str << "(net v" << +hfres.version << ')';
  print_fork_extra_info(str, hfres.earliest_height, net_height, ires.target);

  str << ", " << (
    hfres.state == cryptonote::HardFork::Ready ? "up to date" :
    hfres.state == cryptonote::HardFork::UpdateNeeded ? "update needed" :
    "out of date, likely forked");

  // restricted RPC does not disclose these:
  if (ires.outgoing_connections_count && ires.incoming_connections_count && ires.start_time)
  {
    std::time_t uptime = std::time(nullptr) - *ires.start_time;
    str << ", " << *ires.outgoing_connections_count << "(out)+" << *ires.incoming_connections_count << "(in) connections"
      << ", uptime "
      << (uptime / (24*60*60)) << 'd'
      << (uptime / (60*60)) % 24 << 'h'
      << (uptime / 60) % 60 << 'm'
      << uptime % 60 << 's';
  }

  tools::success_msg_writer() << str.str();

  if (!my_sn_key.empty()) {
    str.str("");
    str << "SN: " << my_sn_key << ' ';
    if (!my_sn_registered)
      str << "not registered";
    else
      str << (!my_sn_staked ? "awaiting" : my_sn_active ? "active" : "DECOMMISSIONED (" + std::to_string(my_decomm_remaining) + " blocks credit)")
        << ", proof: " << (my_sn_last_uptime ? get_human_time_ago(my_sn_last_uptime, time(nullptr)) : "(never)");
    str << ", last pings: ";
    if (*ires.last_storage_server_ping > 0)
        str << get_human_time_ago(*ires.last_storage_server_ping, time(nullptr), true /*abbreviate*/);
    else
        str << "NOT RECEIVED";
    str << " (storage), ";

    if (*ires.last_lokinet_ping > 0)
        str << get_human_time_ago(*ires.last_lokinet_ping, time(nullptr), true /*abbreviate*/);
    else
        str << "NOT RECEIVED";
    str << " (lokinet)";

    tools::success_msg_writer() << str.str();
  }

  return true;
}

bool rpc_command_executor::mining_status() {
  MINING_STATUS::response mres{};

  if (!invoke<MINING_STATUS>({}, mres, "Failed to retrieve mining info", false))
    return false;

  bool mining_busy = false;
  if (mres.status == STATUS_BUSY)
  {
    mining_busy = true;
  }
  else if (mres.status != STATUS_OK)
  {
    tools::fail_msg_writer() << "Failed to retrieve mining info";
    return false;
  }

  if (mining_busy || !mres.active)
  {
    tools::msg_writer() << "Not currently mining";
  }
  else
  {
    tools::msg_writer() << "Mining at " << get_mining_speed(mres.speed) << " with " << mres.threads_count << " threads";
  }

  tools::msg_writer() << "PoW algorithm: " << mres.pow_algorithm;
  if (mres.active)
  {
    tools::msg_writer() << "Mining address: " << mres.address;
  }

  if (!mining_busy && mres.active && mres.speed > 0 && mres.block_target > 0 && mres.difficulty > 0)
  {
    uint64_t daily = 86400 / (double)mres.difficulty * mres.speed * mres.block_reward;
    tools::msg_writer() << "Expected: " << cryptonote::print_money(daily) << " LOKI daily, " << cryptonote::print_money(7*daily) << " weekly";
  }

  return true;
}

bool rpc_command_executor::print_connections() {
  GET_CONNECTIONS::response res{};

  if (!invoke<GET_CONNECTIONS>({}, res, "Failed to retrieve connection info"))
    return false;

  tools::msg_writer() << std::setw(30) << std::left << "Remote Host"
      << std::setw(8) << "Type"
      << std::setw(20) << "Peer id"
      << std::setw(20) << "Support Flags"
      << std::setw(30) << "Recv/Sent (inactive,sec)"
      << std::setw(25) << "State"
      << std::setw(20) << "Livetime(sec)"
      << std::setw(12) << "Down (kB/s)"
      << std::setw(14) << "Down(now)"
      << std::setw(10) << "Up (kB/s)"
      << std::setw(13) << "Up(now)"
      << std::endl;

  for (auto & info : res.connections)
  {
    std::string address = info.incoming ? "INC " : "OUT ";
    address += info.ip + ":" + info.port;
    //std::string in_out = info.incoming ? "INC " : "OUT ";
    tools::msg_writer()
     //<< std::setw(30) << std::left << in_out
     << std::setw(30) << std::left << address
     << std::setw(8) << (get_address_type_name((epee::net_utils::address_type)info.address_type))
     << std::setw(20) << info.peer_id
     << std::setw(20) << info.support_flags
     << std::setw(30) << std::to_string(info.recv_count) + "("  + std::to_string(tools::to_seconds(info.recv_idle_time)) + ")/" + std::to_string(info.send_count) + "(" + std::to_string(tools::to_seconds(info.send_idle_time)) + ")"
     << std::setw(25) << info.state
     << std::setw(20) << std::to_string(tools::to_seconds(info.live_time))
     << std::setw(12) << info.avg_download
     << std::setw(14) << info.current_download
     << std::setw(10) << info.avg_upload
     << std::setw(13) << info.current_upload

     << std::left << (info.localhost ? "[LOCALHOST]" : "")
     << std::left << (info.local_ip ? "[LAN]" : "");
    //tools::msg_writer() << boost::format("%-25s peer_id: %-25s %s") % address % info.peer_id % in_out;

  }

  return true;
}

bool rpc_command_executor::print_net_stats()
{
  GET_NET_STATS::response net_stats_res{};
  GET_LIMIT::response limit_res{};

  if (!invoke<GET_NET_STATS>({}, net_stats_res, "Unable to retrieve net statistics") ||
      !invoke<GET_LIMIT>({}, limit_res, "Unable to retrieve bandwidth limits"))
    return false;

  uint64_t seconds = (uint64_t)time(NULL) - net_stats_res.start_time;
  uint64_t average = seconds > 0 ? net_stats_res.total_bytes_in / seconds : 0;
  uint64_t limit = limit_res.limit_down * 1024;   // convert to bytes, as limits are always kB/s
  double percent = (double)average / (double)limit * 100.0;
  tools::success_msg_writer() << boost::format("Received %u bytes (%s) in %u packets, average %s/s = %.2f%% of the limit of %s/s")
    % net_stats_res.total_bytes_in
    % tools::get_human_readable_bytes(net_stats_res.total_bytes_in)
    % net_stats_res.total_packets_in
    % tools::get_human_readable_bytes(average)
    % percent
    % tools::get_human_readable_bytes(limit);

  average = seconds > 0 ? net_stats_res.total_bytes_out / seconds : 0;
  limit = limit_res.limit_up * 1024;
  percent = (double)average / (double)limit * 100.0;
  tools::success_msg_writer() << boost::format("Sent %u bytes (%s) in %u packets, average %s/s = %.2f%% of the limit of %s/s")
    % net_stats_res.total_bytes_out
    % tools::get_human_readable_bytes(net_stats_res.total_bytes_out)
    % net_stats_res.total_packets_out
    % tools::get_human_readable_bytes(average)
    % percent
    % tools::get_human_readable_bytes(limit);

  return true;
}

bool rpc_command_executor::print_blockchain_info(int64_t start_block_index, uint64_t end_block_index) {
  GET_BLOCK_HEADERS_RANGE::request req{};
  GET_BLOCK_HEADERS_RANGE::response res{};

  // negative: relative to the end
  if (start_block_index < 0)
  {
    GET_INFO::response ires;
    if (!invoke<GET_INFO>(GET_INFO::request{}, ires, "Failed to query daemon info"))
        return false;

    if (start_block_index < 0 && (uint64_t)-start_block_index >= ires.height)
    {
      tools::fail_msg_writer() << "start offset is larger than blockchain height";
      return false;
    }

    start_block_index = ires.height + start_block_index;
    end_block_index = start_block_index + end_block_index - 1;
  }

  req.start_height = start_block_index;
  req.end_height = end_block_index;
  req.fill_pow_hash = false;

  if (!invoke<GET_BLOCK_HEADERS_RANGE>(std::move(req), res, "Failed to retrieve block headers"))
    return false;

  bool first = true;
  for (auto & header : res.headers)
  {
    if (first)
      first = false;
    else
      tools::msg_writer() << "\n";

    tools::msg_writer()
      << "height: " << header.height << ", timestamp: " << header.timestamp << " (" << tools::get_human_readable_timestamp(header.timestamp) << ")"
      << ", size: " << header.block_size << ", weight: " << header.block_weight << " (long term " << header.long_term_weight << "), transactions: " << header.num_txes
      << "\nmajor version: " << (unsigned)header.major_version << ", minor version: " << (unsigned)header.minor_version
      << "\nblock id: " << header.hash << ", previous block id: " << header.prev_hash
      << "\ndifficulty: " << header.difficulty << ", nonce " << header.nonce << ", reward " << cryptonote::print_money(header.reward) << "\n";
  }

  return true;
}

bool rpc_command_executor::print_quorum_state(uint64_t start_height, uint64_t end_height)
{
  GET_QUORUM_STATE::request req{};
  GET_QUORUM_STATE::response res{};

  req.start_height = start_height;
  req.end_height   = end_height;
  req.quorum_type  = GET_QUORUM_STATE::ALL_QUORUMS_SENTINEL_VALUE;

  if (!invoke<GET_QUORUM_STATE>(std::move(req), res, "Failed to retrieve quorum state"))
    return false;

  std::string output;
  output.append("{\n\"quorums\": [");
  for (GET_QUORUM_STATE::quorum_for_height const &quorum : res.quorums)
  {
    output.append("\n");
    output.append(epee::serialization::store_t_to_json(quorum));
    output.append(",\n");
  }
  output.append("]\n}");
  tools::success_msg_writer() << output;
  return true;
}


bool rpc_command_executor::set_log_level(int8_t level) {
  SET_LOG_LEVEL::response res{};
  if (!invoke<SET_LOG_LEVEL>({level}, res, "Failed to set log level"))
    return false;

  tools::success_msg_writer() << "Log level is now " << std::to_string(level);

  return true;
}

bool rpc_command_executor::set_log_categories(std::string categories) {
  SET_LOG_CATEGORIES::response res{};

  if (!invoke<SET_LOG_CATEGORIES>({std::move(categories)}, res, "Failed to set log categories"))
    return false;

  tools::success_msg_writer() << "Log categories are now " << res.categories;

  return true;
}

bool rpc_command_executor::print_height() {
  GET_HEIGHT::response res{};

  if (!invoke<GET_HEIGHT>({}, res, "Failed to retrieve height"))
    return false;

  tools::success_msg_writer() << res.height;

  return true;
}

bool rpc_command_executor::print_block(GET_BLOCK::request&& req, bool include_hex) {
  req.fill_pow_hash = true;
  GET_BLOCK::response res{};

  if (!invoke<GET_BLOCK>(std::move(req), res, "Block retrieval failed"))
    return false;

  if (include_hex)
    tools::success_msg_writer() << res.blob << std::endl;
  print_block_header(res.block_header);
  tools::success_msg_writer() << res.json << "\n";

  return true;
}

bool rpc_command_executor::print_block_by_hash(const crypto::hash& block_hash, bool include_hex) {
  GET_BLOCK::request req{};
  req.hash = tools::type_to_hex(block_hash);
  return print_block(std::move(req), include_hex);
}

bool rpc_command_executor::print_block_by_height(uint64_t height, bool include_hex) {
  GET_BLOCK::request req{};
  req.height = height;
  return print_block(std::move(req), include_hex);
}

bool rpc_command_executor::print_transaction(const crypto::hash& transaction_hash,
  bool include_metadata,
  bool include_hex,
  bool include_json) {
  GET_TRANSACTIONS::request req{};
  GET_TRANSACTIONS::response res{};

  req.txs_hashes.push_back(tools::type_to_hex(transaction_hash));
  req.split = true;
  if (!invoke<GET_TRANSACTIONS>(std::move(req), res, "Transaction retrieval failed"))
    return false;

  if (1 == res.txs.size())
  {
    auto& tx = res.txs.front();
    bool pruned = tx.prunable_hash && !tx.prunable_as_hex;

    if (tx.in_pool)
      tools::success_msg_writer() << "Found in pool";
    else
      tools::success_msg_writer() << "Found in blockchain at height " << tx.block_height << (pruned ? " (pruned)" : "");

    const std::string &pruned_as_hex = *tx.pruned_as_hex; // Always included with req.split=true

    std::optional<cryptonote::transaction> t;
    if (include_metadata || include_json)
    {
      if (lokimq::is_hex(pruned_as_hex) && (!tx.prunable_as_hex || lokimq::is_hex(*tx.prunable_as_hex)))
      {
        std::string blob = lokimq::from_hex(pruned_as_hex);
        if (tx.prunable_as_hex)
          blob += lokimq::from_hex(*tx.prunable_as_hex);

        bool parsed = pruned
          ? cryptonote::parse_and_validate_tx_base_from_blob(blob, t.emplace())
          : cryptonote::parse_and_validate_tx_from_blob(blob, t.emplace());
        if (!parsed)
        {
          tools::fail_msg_writer() << "Failed to parse transaction data";
          t.reset();
        }
      }
    }

    // Print metadata if requested
    if (include_metadata)
    {
      if (!tx.in_pool)
        tools::msg_writer() << "Block timestamp: " << tx.block_timestamp << " (" << tools::get_human_readable_timestamp(tx.block_timestamp) << ")";
      tools::msg_writer() << "Size: " << tx.size;
      if (t)
        tools::msg_writer() << "Weight: " << cryptonote::get_transaction_weight(*t);
    }

    // Print raw hex if requested
    if (include_hex)
      tools::success_msg_writer() << pruned_as_hex << (tx.prunable_as_hex ? *tx.prunable_as_hex : "") << '\n';

    // Print json if requested
    if (include_json && t)
      tools::success_msg_writer() << cryptonote::obj_to_json_str(*t) << '\n';
  }
  else
    tools::fail_msg_writer() << "Transaction wasn't found: " << transaction_hash << std::endl;

  return true;
}

bool rpc_command_executor::is_key_image_spent(const crypto::key_image &ki) {
  IS_KEY_IMAGE_SPENT::response res{};
  if (!invoke<IS_KEY_IMAGE_SPENT>({{tools::type_to_hex(ki)}}, res, "Failed to retrieve key image status"))
    return false;

  if (1 == res.spent_status.size())
  {
    // first as hex
    tools::success_msg_writer() << ki << ": " << (res.spent_status.front() ? "spent" : "unspent") << (res.spent_status.front() == IS_KEY_IMAGE_SPENT::SPENT_IN_POOL ? " (in pool)" : "");
    return true;
  }

  tools::fail_msg_writer() << "key image status could not be determined" << std::endl;
  return false;
}

static void print_pool(const std::vector<cryptonote::rpc::tx_info> &transactions, bool include_json) {
  if (transactions.empty())
  {
    tools::msg_writer() << "Pool is empty" << std::endl;
    return;
  }
  const time_t now = time(NULL);
  tools::msg_writer() << "Transactions:";
  for (auto &tx_info : transactions)
  {
    auto w = tools::msg_writer();
    w << "id: " << tx_info.id_hash << "\n";
    if (include_json) w << tx_info.tx_json << "\n";
    w << "blob_size: " << tx_info.blob_size << "\n"
      << "weight: " << tx_info.weight << "\n"
      << "fee: " << cryptonote::print_money(tx_info.fee) << "\n"
      /// NB(Loki): in v13 we have min_fee = per_out*outs + per_byte*bytes, only the total fee/byte matters for
      /// the purpose of building a block template from the pool, so we still print the overall fee / byte here.
      /// (we can't back out the individual per_out and per_byte that got used anyway).
      << "fee/byte: " << cryptonote::print_money(tx_info.fee / (double)tx_info.weight) << "\n"
      << "receive_time: " << tx_info.receive_time << " (" << get_human_time_ago(tx_info.receive_time, now) << ")\n"
      << "relayed: " << (tx_info.relayed ? std::to_string(tx_info.last_relayed_time) + " (" + get_human_time_ago(tx_info.last_relayed_time, now) + ")" : "no") << "\n"
      << std::boolalpha
      << "do_not_relay: " << tx_info.do_not_relay << "\n"
      << "blink: " << tx_info.blink << "\n"
      << "kept_by_block: " << tx_info.kept_by_block << "\n"
      << "double_spend_seen: " << tx_info.double_spend_seen << "\n"
      << std::noboolalpha
      << "max_used_block_height: " << tx_info.max_used_block_height << "\n"
      << "max_used_block_id: " << tx_info.max_used_block_id_hash << "\n"
      << "last_failed_height: " << tx_info.last_failed_height << "\n"
      << "last_failed_id: " << tx_info.last_failed_id_hash << "\n";
  }
}

bool rpc_command_executor::print_transaction_pool_long() {
  GET_TRANSACTION_POOL::response res{};

  if (!invoke<GET_TRANSACTION_POOL>({}, res, "Failed to retrieve transaction pool details"))
    return false;

  print_pool(res.transactions, true);

  if (res.spent_key_images.empty())
  {
    if (! res.transactions.empty())
      tools::msg_writer() << "WARNING: Inconsistent pool state - no spent key images";
  }
  else
  {
    tools::msg_writer() << ""; // one newline
    tools::msg_writer() << "Spent key images: ";
    for (const auto& kinfo : res.spent_key_images)
    {
      tools::msg_writer() << "key image: " << kinfo.id_hash;
      if (kinfo.txs_hashes.size() == 1)
      {
        tools::msg_writer() << "  tx: " << kinfo.txs_hashes[0];
      }
      else if (kinfo.txs_hashes.size() == 0)
      {
        tools::msg_writer() << "  WARNING: spent key image has no txs associated";
      }
      else
      {
        tools::msg_writer() << "  NOTE: key image for multiple txs: " << kinfo.txs_hashes.size();
        for (const std::string& tx_id : kinfo.txs_hashes)
        {
          tools::msg_writer() << "  tx: " << tx_id;
        }
      }
    }
    if (res.transactions.empty())
    {
      tools::msg_writer() << "WARNING: Inconsistent pool state - no transactions";
    }
  }

  return true;
}

bool rpc_command_executor::print_transaction_pool_short() {
  GET_TRANSACTION_POOL::request req{};
  GET_TRANSACTION_POOL::response res{};

  if (!invoke<GET_TRANSACTION_POOL>({}, res, "Failed to retrieve transaction pool details"))
    return false;

  print_pool(res.transactions, false);

  return true;
}

bool rpc_command_executor::print_transaction_pool_stats() {
  GET_TRANSACTION_POOL_STATS::response res{};
  GET_INFO::response ires{};

  if (!invoke<GET_TRANSACTION_POOL_STATS>({}, res, "Failed to retreive transaction pool statistics") ||
      !invoke<GET_INFO>({}, ires, "Failed to retrieve node info"))
    return false;

  size_t n_transactions = res.pool_stats.txs_total;
  const uint64_t now = time(NULL);
  size_t avg_bytes = n_transactions ? res.pool_stats.bytes_total / n_transactions : 0;

  std::string backlog_message;
  const uint64_t full_reward_zone = ires.block_weight_limit / 2;
  if (res.pool_stats.bytes_total <= full_reward_zone)
  {
    backlog_message = "no backlog";
  }
  else
  {
    uint64_t backlog = (res.pool_stats.bytes_total + full_reward_zone - 1) / full_reward_zone;
    backlog_message = (boost::format("estimated %u block (%u minutes) backlog") % backlog % (backlog * TARGET_BLOCK_TIME / 1min)).str();
  }

  tools::msg_writer() << n_transactions << " tx(es), " << res.pool_stats.bytes_total << " bytes total (min " << res.pool_stats.bytes_min << ", max " << res.pool_stats.bytes_max << ", avg " << avg_bytes << ", median " << res.pool_stats.bytes_med << ")" << std::endl
      << "fees " << cryptonote::print_money(res.pool_stats.fee_total) << " (avg " << cryptonote::print_money(n_transactions ? res.pool_stats.fee_total / n_transactions : 0) << " per tx" << ", " << cryptonote::print_money(res.pool_stats.bytes_total ? res.pool_stats.fee_total / res.pool_stats.bytes_total : 0) << " per byte)" << std::endl
      << res.pool_stats.num_double_spends << " double spends, " << res.pool_stats.num_not_relayed << " not relayed, " << res.pool_stats.num_failing << " failing, " << res.pool_stats.num_10m << " older than 10 minutes (oldest " << (res.pool_stats.oldest == 0 ? "-" : get_human_time_ago(res.pool_stats.oldest, now)) << "), " << backlog_message;

  if (n_transactions > 1 && res.pool_stats.histo.size())
  {
    std::vector<uint64_t> times;
    uint64_t numer;
    size_t i, n = res.pool_stats.histo.size(), denom;
    times.resize(n);
    if (res.pool_stats.histo_98pc)
    {
      numer = res.pool_stats.histo_98pc;
      denom = n-1;
      for (i=0; i<denom; i++)
        times[i] = i * numer / denom;
      times[i] = now - res.pool_stats.oldest;
    } else
    {
      numer = now - res.pool_stats.oldest;
      denom = n;
      for (i=0; i<denom; i++)
        times[i] = i * numer / denom;
    }
    tools::msg_writer() << "   Age      Txes       Bytes";
    for (i=0; i<n; i++)
    {
      tools::msg_writer() << get_time_hms(times[i]) << std::setw(8) << res.pool_stats.histo[i].txs << std::setw(12) << res.pool_stats.histo[i].bytes;
    }
  }
  tools::msg_writer();

  return true;
}

bool rpc_command_executor::start_mining(const cryptonote::account_public_address& address, uint64_t num_threads, uint32_t num_blocks, cryptonote::network_type nettype) {
  START_MINING::request req{};
  START_MINING::response res{};
  req.num_blocks    = num_blocks;
  req.miner_address = cryptonote::get_account_address_as_str(nettype, false, address);
  req.threads_count = num_threads;

  if (!invoke<START_MINING>(std::move(req), res, "Unable to start mining"))
    return false;

  std::stringstream stream;
  stream << "Mining started";
  if (num_threads) stream << " with " << num_threads << " thread(s).";
  else             stream << ", auto detecting the number of threads to use.";

  if (num_blocks) stream << " Mining for " << num_blocks << " blocks before stopping or until manually stopped.";
  tools::success_msg_writer() << stream.str();
  return true;
}

bool rpc_command_executor::stop_mining() {
  STOP_MINING::response res{};

  if (!invoke<STOP_MINING>({}, res, "Unable to stop mining"))
    return false;

  tools::success_msg_writer() << "Mining stopped";
  return true;
}

bool rpc_command_executor::stop_daemon()
{
  STOP_DAEMON::response res{};

  if (!invoke<STOP_DAEMON>({}, res, "Failed to stop daemon"))
    return false;

  tools::success_msg_writer() << "Stop signal sent";

  return true;
}

bool rpc_command_executor::print_status()
{
  if (!m_rpc_client)
  {
    tools::fail_msg_writer() << "print_status makes no sense in interactive mode";
    return false;
  }

  // Make a request to get_height because it is public and relatively simple
  GET_HEIGHT::response res;
  if (invoke<GET_HEIGHT>({}, res, "lokid is NOT running")) {
    tools::success_msg_writer() << "lokid is running (height: " << res.height << ")";
    return true;
  }
  return false;
}

bool rpc_command_executor::get_limit(bool up, bool down)
{
  GET_LIMIT::response res{};

  if (!invoke<GET_LIMIT>({}, res, "Failed to retrieve current bandwidth limits"))
    return false;

  if (down)
    tools::msg_writer() << "limit-down is " << res.limit_down << " kB/s";
  if (up)
    tools::msg_writer() << "limit-up is " << res.limit_up << " kB/s";
  return true;
}

bool rpc_command_executor::set_limit(int64_t limit_down, int64_t limit_up)
{
  SET_LIMIT::response res{};
  if (!invoke<SET_LIMIT>({limit_down, limit_up}, res, "Failed to set bandwidth limits"))
    return false;

  tools::msg_writer() << "Set limit-down to " << res.limit_down << " kB/s";
  tools::msg_writer() << "Set limit-up to " << res.limit_up << " kB/s";
  return true;
}


bool rpc_command_executor::out_peers(bool set, uint32_t limit)
{
    OUT_PEERS::request req{set, limit};
	OUT_PEERS::response res{};
    if (!invoke<OUT_PEERS>(std::move(req), res, "Failed to set max out peers"))
      return false;

	const std::string s = res.out_peers == (uint32_t)-1 ? "unlimited" : std::to_string(res.out_peers);
	tools::msg_writer() << "Max number of out peers set to " << s << std::endl;

	return true;
}

bool rpc_command_executor::in_peers(bool set, uint32_t limit)
{
    IN_PEERS::request req{set, limit};
	IN_PEERS::response res{};
    if (!invoke<IN_PEERS>(std::move(req), res, "Failed to set max in peers"))
      return false;

	const std::string s = res.in_peers == (uint32_t)-1 ? "unlimited" : std::to_string(res.in_peers);
	tools::msg_writer() << "Max number of in peers set to " << s << std::endl;

	return true;
}

bool rpc_command_executor::hard_fork_info(uint8_t version)
{
    HARD_FORK_INFO::response res{};
    if (!invoke<HARD_FORK_INFO>({version}, res, "Failed to retrieve hard fork info"))
      return false;

    version = version > 0 ? version : res.voting;
    tools::msg_writer() << "version " << (uint32_t)version << " " << (res.enabled ? "enabled" : "not enabled") <<
        ", " << res.votes << "/" << res.window << " votes, threshold " << res.threshold;
    tools::msg_writer() << "current version " << (uint32_t)res.version << ", voting for version " << (uint32_t)res.voting;

    return true;
}

bool rpc_command_executor::print_bans()
{
    GETBANS::response res{};

    if (!invoke<GETBANS>({}, res, "Failed to retrieve ban list"))
      return false;

    if (!res.bans.empty())
    {
        for (auto i = res.bans.begin(); i != res.bans.end(); ++i)
        {
            tools::msg_writer() << i->host << " banned for " << i->seconds << " seconds";
        }
    }
    else 
        tools::msg_writer() << "No IPs are banned";

    return true;
}

bool rpc_command_executor::ban(const std::string &address, time_t seconds, bool clear_ban)
{
    SETBANS::request req{};
    SETBANS::response res{};

    req.bans.emplace_back();
    auto& ban = req.bans.back();
    ban.host = address;
    ban.ip = 0;
    ban.ban = !clear_ban;
    ban.seconds = seconds;

    if (!invoke<SETBANS>(std::move(req), res, clear_ban ? "Failed to clear ban" : "Failed to set ban"))
      return false;

    // TODO(doyle): Work around because integration tests break when using
    // mlog_set_categories(""), so emit the block message using msg writer
    // instead of the logging system.
#if defined(LOKI_ENABLE_INTEGRATION_TEST_HOOKS)
    tools::success_msg_writer() << "Host " << address << (clear_ban ? " unblocked." : " blocked.");
#endif

    return true;
}

bool rpc_command_executor::unban(const std::string &address)
{
    return ban(std::move(address), 0, true);
}

bool rpc_command_executor::banned(const std::string &address)
{
    BANNED::request req{};
    BANNED::response res{};

    req.address = address;

    if (!invoke<BANNED>({address}, res, "Failed to retrieve ban information"))
      return false;

    if (res.banned)
      tools::msg_writer() << address << " is banned for " << res.seconds << " seconds";
    else
      tools::msg_writer() << address << " is not banned";

    return true;
}

bool rpc_command_executor::flush_txpool(std::string txid)
{
    FLUSH_TRANSACTION_POOL::request req{};
    FLUSH_TRANSACTION_POOL::response res{};

    if (!txid.empty())
      req.txids.push_back(std::move(txid));

    if (!invoke<FLUSH_TRANSACTION_POOL>(std::move(req), res, "Failed to flush tx pool"))
      return false;

    tools::success_msg_writer() << "Pool successfully flushed";
    return true;
}

bool rpc_command_executor::output_histogram(const std::vector<uint64_t> &amounts, uint64_t min_count, uint64_t max_count)
{
    GET_OUTPUT_HISTOGRAM::request req{};
    GET_OUTPUT_HISTOGRAM::response res{};

    req.amounts = amounts;
    req.min_count = min_count;
    req.max_count = max_count;
    req.unlocked = false;
    req.recent_cutoff = 0;

    if (!invoke<GET_OUTPUT_HISTOGRAM>(std::move(req), res, "Failed to retrieve output histogram"))
      return false;

    std::sort(res.histogram.begin(), res.histogram.end(),
        [](const auto& e1, const auto& e2)->bool { return e1.total_instances < e2.total_instances; });
    for (const auto &e: res.histogram)
    {
        tools::msg_writer() << e.total_instances << "  " << cryptonote::print_money(e.amount);
    }

    return true;
}

bool rpc_command_executor::print_coinbase_tx_sum(uint64_t height, uint64_t count)
{
  GET_COINBASE_TX_SUM::response res{};
  if (!invoke<GET_COINBASE_TX_SUM>({height, count}, res, "Failed to retrieve coinbase info"))
    return false;

  tools::msg_writer() << "Sum of coinbase transactions between block heights ["
    << height << ", " << (height + count) << ") is "
    << cryptonote::print_money(res.emission_amount + res.fee_amount) << " "
    << "consisting of " << cryptonote::print_money(res.emission_amount)
    << " in emissions, and " << cryptonote::print_money(res.fee_amount) << " in fees";
  return true;
}

bool rpc_command_executor::alt_chain_info(const std::string &tip, size_t above, uint64_t last_blocks)
{
  GET_INFO::response ires{};
  GET_ALTERNATE_CHAINS::response res{};

  if (!invoke<GET_INFO>({}, ires, "Failed to retrieve node info") ||
      !invoke<GET_ALTERNATE_CHAINS>({}, res, "Failed to retrieve alt chain data"))
    return false;

  if (tip.empty())
  {
    auto chains = res.chains;
    std::sort(chains.begin(), chains.end(), [](const GET_ALTERNATE_CHAINS::chain_info &info0, GET_ALTERNATE_CHAINS::chain_info &info1){ return info0.height < info1.height; });
    std::vector<size_t> display;
    for (size_t i = 0; i < chains.size(); ++i)
    {
      const auto &chain = chains[i];
      if (chain.length <= above)
        continue;
      const uint64_t start_height = (chain.height - chain.length + 1);
      if (last_blocks > 0 && ires.height - 1 - start_height >= last_blocks)
        continue;
      display.push_back(i);
    }
    tools::msg_writer() << display.size() << " alternate chains found:";
    for (const size_t idx: display)
    {
      const auto &chain = chains[idx];
      const uint64_t start_height = (chain.height - chain.length + 1);
      tools::msg_writer() << chain.length << " blocks long, from height " << start_height << " (" << (ires.height - start_height - 1)
          << " deep), diff " << chain.difficulty << ": " << chain.block_hash;
    }
  }
  else
  {
    const uint64_t now = time(NULL);
    const auto i = std::find_if(res.chains.begin(), res.chains.end(), [&tip](GET_ALTERNATE_CHAINS::chain_info &info){ return info.block_hash == tip; });
    if (i != res.chains.end())
    {
      const auto &chain = *i;
      tools::success_msg_writer() << "Found alternate chain with tip " << tip;
      uint64_t start_height = (chain.height - chain.length + 1);
      tools::msg_writer() << chain.length << " blocks long, from height " << start_height << " (" << (ires.height - start_height - 1)
          << " deep), diff " << chain.difficulty << ":";
      for (const std::string &block_id: chain.block_hashes)
        tools::msg_writer() << "  " << block_id;
      tools::msg_writer() << "Chain parent on main chain: " << chain.main_chain_parent_block;
      GET_BLOCK_HEADER_BY_HASH::request bhreq{};
      GET_BLOCK_HEADER_BY_HASH::response bhres{};
      bhreq.hashes = chain.block_hashes;
      bhreq.hashes.push_back(chain.main_chain_parent_block);
      bhreq.fill_pow_hash = false;
      if (!invoke<GET_BLOCK_HEADER_BY_HASH>(std::move(bhreq), bhres, "Failed to query block header by hash"))
        return false;

      if (bhres.block_headers.size() != chain.length + 1)
      {
        tools::fail_msg_writer() << "Failed to get block header info for alt chain";
        return true;
      }
      uint64_t t0 = bhres.block_headers.front().timestamp, t1 = t0;
      for (const block_header_response &block_header: bhres.block_headers)
      {
        t0 = std::min<uint64_t>(t0, block_header.timestamp);
        t1 = std::max<uint64_t>(t1, block_header.timestamp);
      }
      const uint64_t dt = t1 - t0;
      const uint64_t age = std::max(dt, t0 < now ? now - t0 : 0);
      tools::msg_writer() << "Age: " << tools::get_human_readable_timespan(std::chrono::seconds(age));
      if (chain.length > 1)
      {
        tools::msg_writer() << "Time span: " << tools::get_human_readable_timespan(std::chrono::seconds(dt));
        cryptonote::difficulty_type start_difficulty = bhres.block_headers.back().difficulty;
        if (start_difficulty > 0)
          tools::msg_writer() << "Approximated " << 100.f * tools::to_seconds(TARGET_BLOCK_TIME) * chain.length / dt << "% of network hash rate";
        else
          tools::fail_msg_writer() << "Bad cmumulative difficulty reported by dameon";
      }
    }
    else
      tools::fail_msg_writer() << "Block hash " << tip << " is not the tip of any known alternate chain";
  }
  return true;
}

bool rpc_command_executor::print_blockchain_dynamic_stats(uint64_t nblocks)
{
  GET_INFO::response ires{};
  GET_BASE_FEE_ESTIMATE::response feres{};
  HARD_FORK_INFO::response hfres{};

  if (!invoke<GET_INFO>({}, ires, "Failed to retrieve node info") ||
      !invoke<GET_BASE_FEE_ESTIMATE>({}, feres, "Failed to retrieve current fee info") ||
      !invoke<HARD_FORK_INFO>({HF_VERSION_PER_BYTE_FEE}, hfres, "Failed to retrieve hard fork info"))
    return false;

  tools::msg_writer() << "Height: " << ires.height << ", diff " << ires.difficulty << ", cum. diff " << ires.cumulative_difficulty
      << ", target " << ires.target << " sec" << ", dyn fee " << cryptonote::print_money(feres.fee_per_byte) << "/" << (hfres.enabled ? "byte" : "kB")
      << " + " << cryptonote::print_money(feres.fee_per_output) << "/out";

  if (nblocks > 0)
  {
    if (nblocks > ires.height)
      nblocks = ires.height;

    GET_BLOCK_HEADERS_RANGE::request bhreq{};
    GET_BLOCK_HEADERS_RANGE::response bhres{};

    bhreq.start_height = ires.height - nblocks;
    bhreq.end_height = ires.height - 1;
    bhreq.fill_pow_hash = false;
    if (!invoke<GET_BLOCK_HEADERS_RANGE>(std::move(bhreq), bhres, "Failed to retrieve block headers"))
      return false;

    double avgdiff = 0;
    double avgnumtxes = 0;
    double avgreward = 0;
    std::vector<uint64_t> weights;
    weights.reserve(nblocks);
    uint64_t earliest = std::numeric_limits<uint64_t>::max(), latest = 0;
    std::map<unsigned, std::pair<unsigned, unsigned>> versions; // version -> {majorcount, minorcount}
    for (const auto &bhr: bhres.headers)
    {
      avgdiff += bhr.difficulty;
      avgnumtxes += bhr.num_txes;
      avgreward += bhr.reward;
      weights.push_back(bhr.block_weight);
      versions[bhr.major_version].first++;
      versions[bhr.minor_version].second++;
      earliest = std::min(earliest, bhr.timestamp);
      latest = std::max(latest, bhr.timestamp);
    }
    avgdiff /= nblocks;
    avgnumtxes /= nblocks;
    avgreward /= nblocks;
    uint64_t median_block_weight = epee::misc_utils::median(weights);
    tools::msg_writer() << "Last " << nblocks << ": avg. diff " << (uint64_t)avgdiff << ", " << (latest - earliest) / nblocks << " avg sec/block, avg num txes " << avgnumtxes
        << ", avg. reward " << cryptonote::print_money(avgreward) << ", median block weight " << median_block_weight;

    std::ostringstream s;
    bool first = true;
    for (auto& v : versions)
    {
      if (first) first = false;
      else s << "; ";
      s << "v" << v.first << " (" << v.second.first << "/" << v.second.second << ")";
    }
    tools::msg_writer() << "Block versions (major/minor): " << s.str();
  }
  return true;
}

bool rpc_command_executor::relay_tx(const std::string &txid)
{
    RELAY_TX::response res{};
    if (!invoke<RELAY_TX>({{txid}}, res, "Failed to relay tx"))
      return false;

    tools::success_msg_writer() << "Transaction successfully relayed";
    return true;
}

bool rpc_command_executor::sync_info()
{
    SYNC_INFO::response res{};

    if (!invoke<SYNC_INFO>({}, res, "Failed to retrieve synchronization info"))
      return false;

    uint64_t target = res.target_height < res.height ? res.height : res.target_height;
    tools::success_msg_writer() << "Height: " << res.height << ", target: " << target << " (" << (100.0 * res.height / target) << "%)";
    uint64_t current_download = 0;
    for (const auto &p: res.peers)
      current_download += p.info.current_download;
    tools::success_msg_writer() << "Downloading at " << current_download << " kB/s";
    if (res.next_needed_pruning_seed)
      tools::success_msg_writer() << "Next needed pruning seed: " << res.next_needed_pruning_seed;

    tools::success_msg_writer() << std::to_string(res.peers.size()) << " peers";
    for (const auto &p: res.peers)
    {
      std::string address = epee::string_tools::pad_string(p.info.address, 24);
      uint64_t nblocks = 0, size = 0;
      for (const auto &s: res.spans)
        if (s.connection_id == p.info.connection_id)
          nblocks += s.nblocks, size += s.size;
      tools::success_msg_writer() << address << "  " << p.info.peer_id << "  " <<
          epee::string_tools::pad_string(p.info.state, 16) << "  " <<
          epee::string_tools::pad_string(epee::string_tools::to_string_hex(p.info.pruning_seed), 8) << "  " << p.info.height << "  "  <<
          p.info.current_download << " kB/s, " << nblocks << " blocks / " << size/1e6 << " MB queued";
    }

    uint64_t total_size = 0;
    for (const auto &s: res.spans)
      total_size += s.size;
    tools::success_msg_writer() << std::to_string(res.spans.size()) << " spans, " << total_size/1e6 << " MB";
    tools::success_msg_writer() << res.overview;
    for (const auto &s: res.spans)
    {
      std::string address = epee::string_tools::pad_string(s.remote_address, 24);
      std::string pruning_seed = epee::string_tools::to_string_hex(tools::get_pruning_seed(s.start_block_height, std::numeric_limits<uint64_t>::max(), CRYPTONOTE_PRUNING_LOG_STRIPES));
      if (s.size == 0)
      {
        tools::success_msg_writer() << address << "  " << s.nblocks << "/" << pruning_seed << " (" << s.start_block_height << " - " << (s.start_block_height + s.nblocks - 1) << ")  -";
      }
      else
      {
        tools::success_msg_writer() << address << "  " << s.nblocks << "/" << pruning_seed << " (" << s.start_block_height << " - " << (s.start_block_height + s.nblocks - 1) << ", " << (uint64_t)(s.size/1e3) << " kB)  " << (unsigned)(s.rate/1e3) << " kB/s (" << s.speed/100.0f << ")";
      }
    }

    return true;
}

static std::string to_string_rounded(double d, int precision) {
  std::ostringstream ss;
  ss << std::fixed << std::setprecision(precision) << d;
  return ss.str();
}

static void print_vote_history(std::ostringstream &stream, std::vector<service_nodes::participation_entry> const &votes)
{
  if (votes.empty())
    stream << "(Awaiting votes from service node)";

  // NOTE: Votes were stored in a ring buffer and copied naiively into the vote
  // array so they may be out of order. Find the smallest entry (by height) and
  // print starting from that entry.
  auto it       = std::min_element(votes.begin(), votes.end(), [](const auto &a, const auto &b) { return a.height < b.height; });
  size_t offset = std::distance(votes.begin(), it);

  for (size_t i = 0; i < votes.size(); i++)
  {
    service_nodes::participation_entry const &entry = votes[(offset + i) % votes.size()];
    if (entry.is_pulse)
    {
      stream << "[" << entry.height << ", ";
      stream << +entry.pulse.round << ", ";
      stream << (entry.voted ? "Yes" : "No") << "]";
    }
    else
    {
      stream << "[" << entry.height << ", " << (entry.voted ? "Yes" : "No") << "]";
    }
    if (i < (votes.size() - 1)) stream << ",";
    stream << " ";
  }
}

template <class participationEntry>
static void print_participation_history(std::ostringstream &stream, std::vector<participationEntry> const &votes)
{
  if (votes.empty())
    stream << "(Awaiting votes from service node)";

  for (size_t i = 0; i < votes.size(); i++)
  {
    participationEntry const &entry = votes[i];
    stream << "["<< (entry.pass() ? "Yes" : "No") << "]";
    if (i < (votes.size() - 1)) stream << ",";
    stream << " ";
  }
}

static void append_printable_service_node_list_entry(cryptonote::network_type nettype, bool detailed_view, uint64_t blockchain_height, uint64_t entry_index, GET_SERVICE_NODES::response::entry const &entry, std::string &buffer)
{
  const char indent1[] = "    ";
  const char indent2[] = "        ";
  const char indent3[] = "            ";
  bool is_registered = entry.total_contributed >= entry.staking_requirement;

  std::ostringstream stream;

  // Print Funding Status
  {
    stream << indent1 << "[" << entry_index << "] " << "Service Node: " << entry.service_node_pubkey << " ";
    stream << "v" << tools::join(".", entry.service_node_version) << "\n";

    if (detailed_view)
    {
      stream << indent2 << "Total Contributed/Staking Requirement: " << cryptonote::print_money(entry.total_contributed) << "/" << cryptonote::print_money(entry.staking_requirement) << "\n";
      stream << indent2 << "Total Reserved: " << cryptonote::print_money(entry.total_reserved) << "\n";
    }
  }

  // Print expiry information
  uint64_t const now = time(nullptr);
  {
    uint64_t expiry_height = 0;
    if (entry.registration_hf_version >= cryptonote::network_version_11_infinite_staking)
    {
      expiry_height = entry.requested_unlock_height;
    }
    else if (entry.registration_hf_version >= cryptonote::network_version_10_bulletproofs)
    {
        expiry_height = entry.registration_height + service_nodes::staking_num_lock_blocks(nettype);
        expiry_height += STAKING_REQUIREMENT_LOCK_BLOCKS_EXCESS;
    }
    else
    {
        expiry_height = entry.registration_height + service_nodes::staking_num_lock_blocks(nettype);
    }

    stream << indent2 << "Registration: Hardfork Version: " << entry.registration_hf_version << "; Height: " << entry.registration_height << "; Expiry: ";
    if (expiry_height == service_nodes::KEY_IMAGE_AWAITING_UNLOCK_HEIGHT)
    {
        stream << "Staking Infinitely (stake unlock not requested)\n";
    }
    else
    {
      uint64_t delta_height      = (blockchain_height >= expiry_height) ? 0 : expiry_height - blockchain_height;
      uint64_t expiry_epoch_time = now + (delta_height * tools::to_seconds(TARGET_BLOCK_TIME));
      stream << expiry_height << " (in " << delta_height << ") blocks\n";
      stream << indent2 << "Expiry Date (estimated): " << get_date_time(expiry_epoch_time) << " (" << get_human_time_ago(expiry_epoch_time, now) << ")\n";
    }
  }

  if (detailed_view && is_registered) // Print reward status
  {
    stream << indent2 << "Last Reward (Or Penalty) At (Height/TX Index): " << entry.last_reward_block_height << "/" << entry.last_reward_transaction_index << "\n";
  }

  if (detailed_view) // Print operator information
  {
    stream << indent2 << "Operator Cut (\% Of Reward): " << to_string_rounded((entry.portions_for_operator / (double)STAKING_PORTIONS) * 100.0, 2) << "%\n";
    stream << indent2 << "Operator Address: " << entry.operator_address << "\n";
  }

  if (is_registered) // Print service node tests
  {
    epee::console_colors uptime_proof_color = (entry.last_uptime_proof == 0) ? epee::console_color_red : epee::console_color_green;

    stream << indent2;
    if (entry.last_uptime_proof == 0)
    {
      stream << "Last Uptime Proof Received: (Awaiting confirmation from network)";
    }
    else
    {
      stream << "Last Uptime Proof Received: " << get_human_time_ago(entry.last_uptime_proof, time(nullptr));
    }

    //
    // NOTE: Node Identification
    //
    stream << "\n";
    stream << indent2 << "IP Address & Ports: ";
    if (entry.public_ip == "0.0.0.0")
      stream << "(Awaiting confirmation from network)";
    else
      stream << entry.public_ip << " :" << entry.storage_port << " (storage), :" << entry.storage_lmq_port
             << " (storage lmq), :" << entry.quorumnet_port << " (quorumnet)";

    stream << "\n";
    if (detailed_view)
      stream << indent2 << "Auxiliary Public Keys:\n"
             << indent3 << (entry.pubkey_ed25519.empty() ? "(not yet received)" : entry.pubkey_ed25519) << " (Ed25519)\n"
             << indent3 << (entry.pubkey_x25519.empty()  ? "(not yet received)" : entry.pubkey_x25519)  << " (X25519)\n";

    //
    // NOTE: Storage Server Test
    //
    stream << indent2 << "Storage Server Reachable: " << (entry.storage_server_reachable ? "Yes" : "No") << " (";
    if (entry.storage_server_reachable_timestamp == 0)
      stream << "Awaiting first test";
    else
      stream << "Last checked: " << get_human_time_ago(entry.storage_server_reachable_timestamp, now);
    stream << ")\n";

    //
    // NOTE: Node Credits
    //
    stream << indent2;
    if (entry.active) {
      stream << "Downtime Credits: " << entry.earned_downtime_blocks << " blocks";
      stream << " (about " << to_string_rounded(entry.earned_downtime_blocks / (double) BLOCKS_EXPECTED_IN_HOURS(1), 2)  << " hours)";
      if (entry.earned_downtime_blocks < service_nodes::DECOMMISSION_MINIMUM)
        stream << " (Note: " << service_nodes::DECOMMISSION_MINIMUM << " blocks required to enable deregistration delay)";
    } else {
      stream << "Current Status: DECOMMISSIONED\n";
      stream << indent2 << "Remaining Decommission Time Until DEREGISTRATION: " << entry.earned_downtime_blocks << " blocks";
    }
    stream << "\n";

    //
    // NOTE: Print Voting History
    //
    stream << indent2 <<  "Checkpoint Participation [Height, Voted]\n" << indent3;
    print_vote_history(stream, entry.checkpoint_participation);

    stream << "\n\n" << indent2 << "Pulse Participation [Height, Round, Voted]\n" << indent3;
    print_vote_history(stream, entry.pulse_participation);

    stream << "\n\n" << indent2 << "Timestamp Participation [in_sync]\n" << indent3;
    print_participation_history(stream, entry.timestamp_participation);

    stream << "\n\n" << indent2 << "Timesync Response [responded]\n" << indent3;
    print_participation_history(stream, entry.timesync_status);
  }

  stream << "\n";
  if (detailed_view) // Print contributors
  {
    for (size_t j = 0; j < entry.contributors.size(); ++j)
    {
      const auto& contributor = entry.contributors[j];
      stream << indent2 << "[" << j << "] Contributor: " << contributor.address  << "\n";
      stream << indent3 << "Amount / Reserved: " << cryptonote::print_money(contributor.amount) << "/" << cryptonote::print_money(contributor.reserved) << "\n";
    }
  }

  buffer.append(stream.str());
}

bool rpc_command_executor::print_sn(const std::vector<std::string> &args)
{
    GET_SERVICE_NODES::request req{};
    GET_SERVICE_NODES::response res{};

    bool detailed_view = false;
    for (auto& arg : args)
    {
      if (arg == "+json")
        req.include_json = true;
      else if (arg == "+detail")
        detailed_view = true;
      else
        req.service_node_pubkeys.push_back(arg);
    }

    GET_INFO::response get_info_res{};

    if (!invoke<GET_INFO>({}, get_info_res, "Failed to retrieve node info") ||
        !invoke<GET_SERVICE_NODES>(std::move(req), res, "Failed to retrieve service node data"))
      return false;

    cryptonote::network_type nettype =
      get_info_res.mainnet  ? cryptonote::MAINNET :
      get_info_res.devnet ? cryptonote::DEVNET :
      get_info_res.testnet  ? cryptonote::TESTNET :
      cryptonote::UNDEFINED;
    uint64_t curr_height = get_info_res.height;

    std::vector<const GET_SERVICE_NODES::response::entry*> unregistered;
    std::vector<const GET_SERVICE_NODES::response::entry*> registered;
    registered.reserve(res.service_node_states.size());

    for (auto &entry : res.service_node_states)
    {
      if (entry.total_contributed == entry.staking_requirement)
        registered.push_back(&entry);
      else
        unregistered.push_back(&entry);
    }

    std::sort(unregistered.begin(), unregistered.end(), [](auto *a, auto *b) {
        uint64_t a_remaining = a->staking_requirement - a->total_reserved;
        uint64_t b_remaining = b->staking_requirement - b->total_reserved;

        if (b_remaining == a_remaining)
          return b->portions_for_operator < a->portions_for_operator;

        return b_remaining < a_remaining;
    });

    std::sort(registered.begin(), registered.end(), [](auto *a, auto *b) {
        return std::make_tuple(a->last_reward_block_height, a->last_reward_transaction_index, a->service_node_pubkey)
             < std::make_tuple(b->last_reward_block_height, b->last_reward_transaction_index, b->service_node_pubkey);
    });

    if (req.include_json)
    {
      std::cout << res.as_json << std::endl;
      return true;
    }

    if (unregistered.size() == 0 && registered.size() == 0)
    {
      if (req.service_node_pubkeys.size() > 0)
      {
        int str_size = 0;
        for (const std::string &arg : req.service_node_pubkeys) str_size += (arg.size() + 2);

        std::string buffer;
        buffer.reserve(str_size);
        for (size_t i = 0; i < req.service_node_pubkeys.size(); ++i)
        {
          buffer.append(req.service_node_pubkeys[i]);
          if (i < req.service_node_pubkeys.size() - 1) buffer.append(", ");
        }

        tools::msg_writer() << "No service node is currently known on the network: " << buffer;
      }
      else
      {
        tools::msg_writer() << "No service node is currently known on the network";
      }

      return true;
    }

    std::string unregistered_print_data;
    std::string registered_print_data;
    for (size_t i = 0; i < unregistered.size(); i++)
    {
      if (i) unregistered_print_data.append("\n");
      append_printable_service_node_list_entry(nettype, detailed_view, curr_height, i, *unregistered[i], unregistered_print_data);
    }

    for (size_t i = 0; i < registered.size(); i++)
    {
      if (i) registered_print_data.append("\n");
      append_printable_service_node_list_entry(nettype, detailed_view, curr_height, i, *registered[i], registered_print_data);
    }

    if (unregistered.size() > 0)
      tools::msg_writer() << "Service Node Unregistered State [" << unregistered.size() << "]\n" << unregistered_print_data;

    if (registered.size() > 0)
      tools::msg_writer() << "Service Node Registration State [" << registered.size() << "]\n"   << registered_print_data;

    return true;
}

bool rpc_command_executor::flush_cache(bool bad_txs, bool bad_blocks)
{
  FLUSH_CACHE::response res{};
  FLUSH_CACHE::request req{};
  req.bad_txs    = bad_txs;
  req.bad_blocks = bad_blocks;
  if (!invoke<FLUSH_CACHE>(std::move(req), res, "Failed to flush TX cache"))
      return false;
  return true;
}

bool rpc_command_executor::print_sn_status(std::vector<std::string> args)
{
  if (args.size() > 1)
  {
    tools::fail_msg_writer() << "Unexpected arguments";
    return false;
  }

  GET_SERVICE_KEYS::response res{};
  if (!invoke<GET_SERVICE_KEYS>({}, res, "Failed to retrieve service node keys"))
    return false;

  args.push_back(std::move(res.service_node_pubkey));

  return print_sn(args);
}

bool rpc_command_executor::print_sr(uint64_t height)
{
  GET_STAKING_REQUIREMENT::response res{};
  if (!invoke<GET_STAKING_REQUIREMENT>({height}, res, "Failed to retrieve staking requirements"))
    return false;

  tools::success_msg_writer() << "Staking Requirement: " << cryptonote::print_money(res.staking_requirement);
  return true;
}

bool rpc_command_executor::pop_blocks(uint64_t num_blocks)
{
  POP_BLOCKS::response res{};
  if (!invoke<POP_BLOCKS>({num_blocks}, res, "Popping blocks failed"))
    return false;

  tools::success_msg_writer() << "new height: " << res.height;
  return true;
}

bool rpc_command_executor::print_sn_key()
{
  GET_SERVICE_KEYS::response res{};

  if (!invoke<GET_SERVICE_KEYS>({}, res, "Failed to retrieve service node keys"))
    return false;

  tools::success_msg_writer()
    <<   "Service Node Public Key: " << res.service_node_pubkey
    << "\n     Ed25519 Public Key: " << res.service_node_ed25519_pubkey
    << "\n      X25519 Public Key: " << res.service_node_x25519_pubkey;
  return true;
}

// Returns lowest x such that (STAKING_PORTIONS * x/amount) >= portions
static uint64_t get_amount_to_make_portions(uint64_t amount, uint64_t portions)
{
  uint64_t lo, hi, resulthi, resultlo;
  lo = mul128(amount, portions, &hi);
  if (lo > UINT64_MAX - (STAKING_PORTIONS - 1))
    hi++;
  lo += STAKING_PORTIONS-1;
  div128_64(hi, lo, STAKING_PORTIONS, &resulthi, &resultlo);
  return resultlo;
}

static uint64_t get_actual_amount(uint64_t amount, uint64_t portions)
{
  uint64_t lo, hi, resulthi, resultlo;
  lo = mul128(amount, portions, &hi);
  div128_64(hi, lo, STAKING_PORTIONS, &resulthi, &resultlo);
  return resultlo;
}

bool rpc_command_executor::prepare_registration()
{
  // RAII-style class to temporarily clear categories and restore upon destruction (i.e. upon returning).
  struct clear_log_categories {
    std::string categories;
    clear_log_categories() { categories = mlog_get_categories(); mlog_set_categories(""); }
    ~clear_log_categories() { mlog_set_categories(categories.c_str()); }
  };
  auto scoped_log_cats = std::unique_ptr<clear_log_categories>(new clear_log_categories());

  // Check if the daemon was started in Service Node or not
  GET_INFO::response res{};
  GET_SERVICE_KEYS::response kres{};
  HARD_FORK_INFO::response hf_res{};
  if (!invoke<GET_INFO>({}, res, "Failed to get node info") ||
      !invoke<HARD_FORK_INFO>({}, hf_res, "Failed to retrieve hard fork info") ||
      !invoke<GET_SERVICE_KEYS>({}, kres, "Failed to retrieve service node keys"))
    return false;

  if (!res.service_node)
  {
    tools::fail_msg_writer() << "Unable to prepare registration: this daemon is not running in --service-node mode";
    return false;
  }

  uint64_t block_height = std::max(res.height, res.target_height);
  uint8_t hf_version = hf_res.version;
#if defined(LOKI_ENABLE_INTEGRATION_TEST_HOOKS)
  cryptonote::network_type const nettype = cryptonote::FAKECHAIN;
#else
  cryptonote::network_type const nettype =
    res.mainnet  ? cryptonote::MAINNET :
    res.devnet ? cryptonote::DEVNET :
    res.testnet  ? cryptonote::TESTNET :
    res.nettype == "fakechain" ? cryptonote::FAKECHAIN :
    cryptonote::UNDEFINED;
#endif

  // Query the latest block we've synced and check that the timestamp is sensible, issue a warning if not
  {
    GET_LAST_BLOCK_HEADER::response res{};

    if (!invoke<GET_LAST_BLOCK_HEADER>({}, res, "Get latest block failed, unable to check sync status"))
      return false;

    auto const& header = res.block_header;
    uint64_t const now = time(nullptr);

    if (now >= header.timestamp)
    {
      uint64_t delta = now - header.timestamp;
      if (delta > (60 * 60))
      {
        tools::fail_msg_writer() << "The last block this Service Node knows about was at least " << get_human_time_ago(header.timestamp, now)
                                 << "\nYour node is possibly desynced from the network or still syncing to the network."
                                 << "\n\nRegistering this node may result in a deregistration due to being out of date with the network\n";
      }
    }

    if (block_height >= header.height)
    {
      uint64_t delta = block_height - header.height;
      if (delta > 15)
      {
        tools::fail_msg_writer() << "The last block this Service Node synced is " << delta << " blocks away from the longest chain we know about."
                                 << "\n\nRegistering this node may result in a deregistration due to being out of date with the network\n";
      }
    }
  }

  const uint64_t staking_requirement =
    std::max(service_nodes::get_staking_requirement(nettype, block_height, hf_version),
             service_nodes::get_staking_requirement(nettype, block_height + 30 * 24, hf_version)); // allow 1 day

  // anything less than DUST will be added to operator stake
  const uint64_t DUST = MAX_NUMBER_OF_CONTRIBUTORS;
  std::cout << "Current staking requirement: " << cryptonote::print_money(staking_requirement) << " " << cryptonote::get_unit() << std::endl;

  enum struct register_step
  {
    ask_is_solo_stake = 0,
    is_solo_stake__operator_address_to_reserve,

    is_open_stake__get_operator_fee,
    is_open_stake__do_you_want_to_reserve_other_contributors,
    is_open_stake__how_many_more_contributors,
    is_open_stake__operator_amount_to_reserve,
    is_open_stake__operator_address_to_reserve,
    is_open_stake__contributor_address_to_reserve,
    is_open_stake__contributor_amount_to_reserve,
    is_open_stake__summary_info,
    final_summary,
    cancelled_by_user,
  };

  struct prepare_registration_state
  {
    register_step            prev_step                    = register_step::ask_is_solo_stake;
    bool                     is_solo_stake;
    size_t                   num_participants             = 1;
    uint64_t                 operator_fee_portions        = STAKING_PORTIONS;
    uint64_t                 portions_remaining           = STAKING_PORTIONS;
    uint64_t                 total_reserved_contributions = 0;
    std::vector<std::string> addresses;
    std::vector<uint64_t>    contributions;
  };

  prepare_registration_state state = {};
  std::stack<prepare_registration_state> state_stack;
  state_stack.push(state);

  bool finished = false;
  register_step step = register_step::ask_is_solo_stake;
  for (input_line_result last_input_result = input_line_result::yes; !finished;)
  {
    if (last_input_result == input_line_result::back)
    {
      step = state.prev_step;
      state_stack.pop();
      state = state_stack.top();
      std::cout << std::endl;
    }

    switch(step)
    {
      case register_step::ask_is_solo_stake:
      {
        last_input_result = input_line_yes_no_cancel("Will the operator contribute the entire stake?");
        if(last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        state.is_solo_stake = (last_input_result == input_line_result::yes);
        if (state.is_solo_stake)
        {
          std::cout << std::endl;
          step = register_step::is_solo_stake__operator_address_to_reserve;
        }
        else
        {
          step = register_step::is_open_stake__get_operator_fee;
        }

        state_stack.push(state);
        continue;
      }

      case register_step::is_solo_stake__operator_address_to_reserve:
      {
        std::string address_str;
        last_input_result = input_line_back_cancel_get_input("Enter the loki address for the solo staker", address_str);
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        state.addresses.push_back(address_str); // the addresses will be validated later down the line
        state.contributions.push_back(STAKING_PORTIONS);
        state.portions_remaining = 0;
        state.total_reserved_contributions += staking_requirement;
        state.prev_step = step;
        step            = register_step::final_summary;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__get_operator_fee:
      {
        std::string operator_fee_str;
        last_input_result = input_line_back_cancel_get_input("Enter operator fee as a percentage of the total staking reward [0-100]%", operator_fee_str);

        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        if (!service_nodes::get_portions_from_percent_str(operator_fee_str, state.operator_fee_portions))
        {
          std::cout << "Invalid value: " << operator_fee_str << ". Should be between [0-100]" << std::endl;
          continue;
        }

        step = register_step::is_open_stake__do_you_want_to_reserve_other_contributors;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__do_you_want_to_reserve_other_contributors:
      {
        last_input_result = input_line_yes_no_back_cancel("Do you want to reserve portions of the stake for other specific contributors?");
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        state.prev_step = step;
        if(last_input_result == input_line_result::yes)
        {
          step = register_step::is_open_stake__how_many_more_contributors;
        }
        else
        {
          std::cout << std::endl;
          step = register_step::is_open_stake__operator_address_to_reserve;
        }

        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__how_many_more_contributors:
      {
        std::string prompt = "Number of additional contributors [1-" + std::to_string(MAX_NUMBER_OF_CONTRIBUTORS - 1) + "]";
        std::string input;
        last_input_result = input_line_back_cancel_get_input(prompt.c_str(), input);

        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        long additional_contributors = strtol(input.c_str(), NULL, 10 /*base 10*/);
        if(additional_contributors < 1 || additional_contributors > (MAX_NUMBER_OF_CONTRIBUTORS - 1))
        {
          std::cout << "Invalid value. Should be between [1-" << (MAX_NUMBER_OF_CONTRIBUTORS - 1) << "]" << std::endl;
          continue;
        }

        std::cout << std::endl;
        state.num_participants += static_cast<size_t>(additional_contributors);
        state.prev_step = step;
        step            = register_step::is_open_stake__operator_address_to_reserve;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__operator_address_to_reserve:
      {
        std::string address_str;
        last_input_result = input_line_back_cancel_get_input("Enter the loki address for the operator", address_str);
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        state.addresses.push_back(address_str); // the addresses will be validated later down the line
        state.prev_step = step;
        step            = register_step::is_open_stake__operator_amount_to_reserve;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__operator_amount_to_reserve:
      {
        uint64_t min_contribution_portions = service_nodes::get_min_node_contribution_in_portions(hf_version, staking_requirement, 0, 0);
        const uint64_t min_contribution    = get_amount_to_make_portions(staking_requirement, min_contribution_portions);
        std::cout << "Minimum amount that can be reserved: " << cryptonote::print_money(min_contribution) << " " << cryptonote::get_unit() << std::endl;

        std::string contribution_str;
        last_input_result = input_line_back_cancel_get_input("How much loki does the operator want to reserve in the stake?", contribution_str);
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        uint64_t contribution;
        if(!cryptonote::parse_amount(contribution, contribution_str))
        {
          std::cout << "Invalid amount." << std::endl;
          continue;
        }

        uint64_t portions = service_nodes::get_portions_to_make_amount(staking_requirement, contribution);
        if(portions < min_contribution_portions)
        {
          std::cout << "The operator needs to contribute at least 25% of the stake requirement (" << cryptonote::print_money(min_contribution) << " " << cryptonote::get_unit() << "). Aborted." << std::endl;
          continue;
        }

        if(portions > state.portions_remaining)
        {
          std::cout << "The operator contribution is higher than the staking requirement. Any excess contribution will be locked for the staking duration, but won't yield any additional reward." << std::endl;
          portions = state.portions_remaining;
        }

        state.contributions.push_back(portions);
        state.portions_remaining -= portions;
        state.total_reserved_contributions += get_actual_amount(staking_requirement, portions);
        state.prev_step = step;

        if (state.num_participants > 1)
        {
          step = register_step::is_open_stake__contributor_address_to_reserve;
        }
        else
        {
          step = register_step::is_open_stake__summary_info;
        }

        std::cout << std::endl;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__contributor_address_to_reserve:
      {
        std::string const prompt = "Enter the loki address for contributor " + std::to_string(state.contributions.size() + 1);
        std::string address_str;
        last_input_result = input_line_back_cancel_get_input(prompt.c_str(), address_str);
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        // the addresses will be validated later down the line
        state.addresses.push_back(address_str);
        state.prev_step = step;
        step            = register_step::is_open_stake__contributor_amount_to_reserve;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__contributor_amount_to_reserve:
      {
        const uint64_t amount_left         = staking_requirement - state.total_reserved_contributions;
        uint64_t min_contribution_portions = service_nodes::get_min_node_contribution_in_portions(hf_version, staking_requirement, state.total_reserved_contributions, state.contributions.size());
        const uint64_t min_contribution    = service_nodes::portions_to_amount(staking_requirement, min_contribution_portions);

        std::cout << "The minimum amount possible to contribute is " << cryptonote::print_money(min_contribution) << " " << cryptonote::get_unit() << std::endl;
        std::cout << "There is " << cryptonote::print_money(amount_left) << " " << cryptonote::get_unit() << " left to meet the staking requirement." << std::endl;

        std::string contribution_str;
        std::string const prompt = "How much loki does contributor " + std::to_string(state.contributions.size() + 1) + " want to reserve in the stake?";
        last_input_result        = input_line_back_cancel_get_input(prompt.c_str(), contribution_str);
        if (last_input_result == input_line_result::back)
          continue;

        if (last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        uint64_t contribution;
        if (!cryptonote::parse_amount(contribution, contribution_str))
        {
          std::cout << "Invalid amount." << std::endl;
          continue;
        }

        uint64_t portions = service_nodes::get_portions_to_make_amount(staking_requirement, contribution);
        if (portions < min_contribution_portions)
        {
          std::cout << "The amount is too small." << std::endl;
          continue;
        }

        if (portions > state.portions_remaining)
          portions = state.portions_remaining;

        state.contributions.push_back(portions);
        state.portions_remaining -= portions;
        state.total_reserved_contributions += get_actual_amount(staking_requirement, portions);
        state.prev_step = step;

        if (state.contributions.size() == state.num_participants)
          step = register_step::is_open_stake__summary_info;
        else
          step = register_step::is_open_stake__contributor_address_to_reserve;

        std::cout << std::endl;
        state_stack.push(state);
        continue;
      }

      case register_step::is_open_stake__summary_info:
      {
        const uint64_t amount_left = staking_requirement - state.total_reserved_contributions;
        std::cout << "Total staking contributions reserved: " << cryptonote::print_money(state.total_reserved_contributions) << " " << cryptonote::get_unit() << std::endl;
        if (amount_left > DUST)
        {
          std::cout << "Your total reservations do not equal the staking requirement." << std::endl;
          std::cout << "You will leave the remaining portion of " << cryptonote::print_money(amount_left) << " " << cryptonote::get_unit() << " open to contributions from anyone, and the Service Node will not activate until the full staking requirement is filled." << std::endl;

          last_input_result = input_line_yes_no_back_cancel("Is this ok?\n");
          if(last_input_result == input_line_result::no || last_input_result == input_line_result::cancel)
          {
            step = register_step::cancelled_by_user;
            continue;
          }

          if(last_input_result == input_line_result::back)
            continue;

          state_stack.push(state);
          state.prev_step = step;
        }

        step = register_step::final_summary;
        continue;
      }

      case register_step::final_summary:
      {
        assert(state.addresses.size() == state.contributions.size());
        const uint64_t amount_left = staking_requirement - state.total_reserved_contributions;

        std::cout << "Summary:" << std::endl;
        std::cout << "Operating costs as % of reward: " << (state.operator_fee_portions * 100.0 / static_cast<double>(STAKING_PORTIONS)) << "%" << std::endl;
        printf("%-16s%-9s%-19s%-s\n", "Contributor", "Address", "Contribution", "Contribution(%)");
        printf("%-16s%-9s%-19s%-s\n", "___________", "_______", "____________", "_______________");

        for (size_t i = 0; i < state.num_participants; ++i)
        {
          const std::string participant_name = (i==0) ? "Operator" : "Contributor " + std::to_string(i);
          uint64_t amount = get_actual_amount(staking_requirement, state.contributions[i]);
          if (amount_left <= DUST && i == 0)
            amount += amount_left; // add dust to the operator.
          printf("%-16s%-9s%-19s%-.9f\n", participant_name.c_str(), state.addresses[i].substr(0,6).c_str(), cryptonote::print_money(amount).c_str(), (double)state.contributions[i] * 100 / (double)STAKING_PORTIONS);
        }

        if (amount_left > DUST)
        {
          printf("%-16s%-9s%-19s%-.2f\n", "(open)", "", cryptonote::print_money(amount_left).c_str(), amount_left * 100.0 / staking_requirement);
        }
        else if (amount_left > 0)
        {
          std::cout << "\nActual amounts may differ slightly from specification. This is due to\n" << std::endl;
          std::cout << "limitations on the way fractions are represented internally.\n" << std::endl;
        }

        std::cout << "\nBecause the actual requirement will depend on the time that you register, the\n";
        std::cout << "amounts shown here are used as a guide only, and the percentages will remain\n";
        std::cout << "the same." << std::endl << std::endl;

        last_input_result = input_line_yes_no_back_cancel("Do you confirm the information above is correct?");
        if(last_input_result == input_line_result::no || last_input_result == input_line_result::cancel)
        {
          step = register_step::cancelled_by_user;
          continue;
        }

        if(last_input_result == input_line_result::back)
          continue;

        finished = true;
        continue;
      }

      case register_step::cancelled_by_user:
      {
        std::cout << "Cancel requested in prepare registration. Aborting." << std::endl;
        return true;
      }
    }
  }

  // <operator cut> <address> <fraction> [<address> <fraction> [...]]]
  std::vector<std::string> args;
  args.push_back(std::to_string(state.operator_fee_portions));
  for (size_t i = 0; i < state.num_participants; ++i)
  {
    args.push_back(state.addresses[i]);
    args.push_back(std::to_string(state.contributions[i]));
  }

  for (size_t i = 0; i < state.addresses.size(); i++)
  {
    for (size_t j = 0; j < i; j++)
    {
      if (state.addresses[i] == state.addresses[j])
      {
        std::cout << "Must not provide the same address twice" << std::endl;
        return true;
      }
    }
  }

  scoped_log_cats.reset();

  {
    GET_SERVICE_NODE_REGISTRATION_CMD_RAW::request req{};
    GET_SERVICE_NODE_REGISTRATION_CMD_RAW::response res{};

    req.args = args;
    req.make_friendly = true;
    req.staking_requirement = staking_requirement;

    if (!invoke<GET_SERVICE_NODE_REGISTRATION_CMD_RAW>(std::move(req), res, "Failed to validate registration arguments; "
          "check the addresses and registration parameters and that the Daemon is running with the '--service-node' flag"))
      return false;

    tools::success_msg_writer() << res.registration_cmd;
  }

  return true;
}

bool rpc_command_executor::prune_blockchain()
{
#if 0
    PRUNE_BLOCKCHAIN::response res{};
    if (!invoke<PRUNE_BLOCKCHAIN>({false}, res, "Failed to prune blockchain"))
      return false;

    tools::success_msg_writer() << "Blockchain pruned";
#else
    tools::fail_msg_writer() << "Blockchain pruning is not supported in Loki yet";
#endif
    return true;
}

bool rpc_command_executor::check_blockchain_pruning()
{
    PRUNE_BLOCKCHAIN::response res{};
    if (!invoke<PRUNE_BLOCKCHAIN>({true}, res, "Failed to check blockchain pruning status"))
      return false;

    tools::success_msg_writer() << "Blockchain is" << (res.pruning_seed ? "" : " not") << " pruned";
    return true;
}

bool rpc_command_executor::set_bootstrap_daemon(
  const std::string &address,
  const std::string &username,
  const std::string &password)
{
    SET_BOOTSTRAP_DAEMON::request req{};
    req.address = address;
    req.username = username;
    req.password = password;

    SET_BOOTSTRAP_DAEMON::response res{};
    if (!invoke<SET_BOOTSTRAP_DAEMON>(std::move(req), res, "Failed to set bootstrap daemon to: " + address))
        return false;

    tools::success_msg_writer()
      << "Successfully set bootstrap daemon address to "
      << (!req.address.empty() ? req.address : "none");
    return true;
}

bool rpc_command_executor::version()
{
    GET_INFO::response response{};
    if (!invoke<GET_INFO>(GET_INFO::request{}, response, "Failed to query daemon info"))
        return false;
    tools::success_msg_writer() << response.version;
    return true;
}

bool rpc_command_executor::test_trigger_uptime_proof()
{
  TEST_TRIGGER_UPTIME_PROOF::request req{};
  TEST_TRIGGER_UPTIME_PROOF::response res{};
  return invoke<TEST_TRIGGER_UPTIME_PROOF>(std::move(req), res, "Failed to trigger uptime proof");
}

}// namespace daemonize
