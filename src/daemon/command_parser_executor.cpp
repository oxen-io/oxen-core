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

#include "daemon/command_parser_executor.h"

#include <forward_list>

#include "common/command_line.h"
#include "common/guts.h"
#include "common/scoped_message_writer.h"
#include "common/string_util.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "version.h"

namespace daemonize {

namespace log = oxen::log;
static auto logcat = log::Cat("daemon");

template <typename T>
constexpr bool is_std_optional = false;
template <typename T>
inline constexpr bool is_std_optional<std::optional<T>> = true;

// Consumes an argument from the given list, if present, parsing it into `var`.
// Returns false upon parse failure, true otherwise.
template <typename T>
static bool parse_if_present(std::forward_list<std::string>& list, T& var, const char* name) {
    if (list.empty())
        return true;
    bool good = false;
    if constexpr (is_std_optional<T>)
        good = epee::string_tools::get_xtype_from_string(var.emplace(), list.front());
    else
        good = epee::string_tools::get_xtype_from_string(var, list.front());
    if (good) {
        list.pop_front();
        return true;
    }

    std::cout << "unexpected " << name << " argument: " << list.front() << std::endl;
    return false;
}

bool command_parser_executor::print_checkpoints(const std::vector<std::string>& args) {
    std::optional<uint64_t> start_height, end_height;

    std::forward_list<std::string> args_list(args.begin(), args.end());
    bool print_json = !args_list.empty() && args_list.front() == "+json";
    if (print_json)
        args_list.pop_front();

    if (!parse_if_present(args_list, start_height, "start height"))
        return false;

    if (!parse_if_present(args_list, end_height, "end height"))
        return false;

    if (!args_list.empty()) {
        std::cout << "use: print_checkpoints [+json] [start height] [end height]\n"
                  << "(omit arguments to print the last "
                  << cryptonote::rpc::GET_CHECKPOINTS::NUM_CHECKPOINTS_TO_QUERY_BY_DEFAULT
                  << " checkpoints) " << std::endl;
        return false;
    }

    return m_executor.print_checkpoints(start_height, end_height, print_json);
}

bool command_parser_executor::print_sn_state_changes(const std::vector<std::string>& args) {
    uint64_t start_height;
    std::optional<uint64_t> end_height;

    if (args.empty()) {
        std::cout << "Missing first argument start_height" << std::endl;
        return false;
    }

    std::forward_list<std::string> args_list(args.begin(), args.end());
    if (!epee::string_tools::get_xtype_from_string(start_height, args_list.front())) {
        std::cout << "start_height should be a number" << std::endl;
        return false;
    }
    args_list.pop_front();

    if (!parse_if_present(args_list, end_height, "end height"))
        return false;

    if (!args_list.empty()) {
        std::cout << "use: print_sn_state_changes <start_height> [end height]"
                  << "(omit arguments to scan until the current block)" << std::endl;
        return false;
    }

    return m_executor.print_sn_state_changes(start_height, end_height);
}

bool command_parser_executor::print_peer_list(const std::vector<std::string>& args) {
    bool white = false;
    bool gray = false;
    bool pruned = false;
    size_t limit = 0;
    for (const auto& arg : args) {
        if (arg == "white")
            white = true;
        else if (arg == "gray")
            gray = true;
        else if (arg == "pruned")
            pruned = true;
        else if (tools::parse_int(arg, limit))
            /*limit already set*/;
        else {
            std::cout << "Unexpected argument: " << arg << "\n";
            return true;
        }
    }

    if (!white && !gray)
        white = gray = true;
    return m_executor.print_peer_list(white, gray, limit, pruned);
}

bool command_parser_executor::print_peer_list_stats(const std::vector<std::string>& args) {
    if (!args.empty())
        return false;

    return m_executor.print_peer_list_stats();
}

bool command_parser_executor::save_blockchain(const std::vector<std::string>& args) {
    if (!args.empty())
        return false;

    return m_executor.save_blockchain();
}

bool command_parser_executor::show_difficulty(const std::vector<std::string>& args) {
    if (!args.empty())
        return false;

    return m_executor.show_difficulty();
}

bool command_parser_executor::show_status(const std::vector<std::string>& args) {
    if (!args.empty())
        return false;

    return m_executor.show_status();
}

bool command_parser_executor::print_connections(const std::vector<std::string>& args) {
    if (!args.empty())
        return false;

    return m_executor.print_connections();
}

bool command_parser_executor::print_net_stats(const std::vector<std::string>& args) {
    if (!args.empty())
        return false;

    return m_executor.print_net_stats();
}

bool command_parser_executor::print_blockchain_info(const std::vector<std::string>& args) {
    if (!args.size()) {
        std::cout << "need block index parameter" << std::endl;
        return false;
    }
    uint64_t start_index = 0;
    uint64_t end_index = 0;
    if (args[0][0] == '-') {
        int64_t nblocks;
        if (!epee::string_tools::get_xtype_from_string(nblocks, args[0])) {
            std::cout << "wrong number of blocks" << std::endl;
            return false;
        }
        return m_executor.print_blockchain_info(nblocks, (uint64_t)-nblocks);
    }
    if (!epee::string_tools::get_xtype_from_string(start_index, args[0])) {
        std::cout << "wrong starter block index parameter" << std::endl;
        return false;
    }
    if (args.size() > 1 && !epee::string_tools::get_xtype_from_string(end_index, args[1])) {
        std::cout << "wrong end block index parameter" << std::endl;
        return false;
    }

    return m_executor.print_blockchain_info(start_index, end_index);
}

bool command_parser_executor::print_quorum_state(const std::vector<std::string>& args) {
    std::optional<uint64_t> start_height;
    std::optional<uint64_t> end_height;

    std::forward_list<std::string> args_list(args.begin(), args.end());
    if (!parse_if_present(args_list, start_height, "start height"))
        return false;

    if (!parse_if_present(args_list, end_height, "end height"))
        return false;

    if (!args_list.empty()) {
        std::cout << "use: print_quorum_state [start height] [end height]\n"
                  << "(omit arguments to print the latest quorums" << std::endl;
        return false;
    }

    return m_executor.print_quorum_state(start_height, end_height);
}

bool command_parser_executor::print_sn_key(const std::vector<std::string>& args) {
    if (!args.empty())
        return false;
    bool result = m_executor.print_sn_key();
    return result;
}

bool command_parser_executor::print_sr(const std::vector<std::string>& args) {
    if (args.size() != 1) {
        std::cout << "expected 1 argument, <height>, received: " << args.size() << std::endl;
        return false;
    }

    uint64_t height = 0;
    if (!epee::string_tools::get_xtype_from_string(height, args[0])) {
        std::cout << "wrong block height parameter" << std::endl;
        return false;
    }

    bool result = m_executor.print_sr(height);
    return result;
}

bool command_parser_executor::prepare_registration(const std::vector<std::string>& args) {
    bool force_registration = false;
    for (auto& arg : args) {
        if (arg == "+force")
            force_registration = true;
    }

    return m_executor.prepare_registration(force_registration);
}

bool command_parser_executor::prepare_eth_registration(const std::vector<std::string>& args) {
    constexpr auto usage = "Eth registration args: <operator address> [\"print\"]"sv;

    auto argc = args.size();
    if (argc < 1) {
        log::error(logcat, usage);
        return false;
    }
    if (args[0].size() != 42) {
        log::error(logcat, usage);
        return false;
    }
    const auto operator_address = std::string_view{args[0]};
    bool print = false;
    if (argc == 2 && args[1] == "print") {
        print = true;
    } else if (argc != 1) {
        log::error(logcat, usage);
        return false;
    }
    return m_executor.prepare_eth_registration(operator_address, print);
}

bool command_parser_executor::print_sn(const std::vector<std::string>& args) {
    bool result = m_executor.print_sn(args);
    return result;
}

bool command_parser_executor::print_sn_status(const std::vector<std::string>& args) {
    bool result = m_executor.print_sn_status(args);
    return result;
}

bool command_parser_executor::set_log_level(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "use: set_log [critical|error|warning|info|debug|trace] [category=LEVEL ...]"
                  << std::endl;
        return true;
    }

    return m_executor.set_log_level("{}"_format(fmt::join(args, ", ")));
}

bool command_parser_executor::print_height(const std::vector<std::string>& args) {
    if (!args.empty())
        return false;

    return m_executor.print_height();
}

bool command_parser_executor::print_block(const std::vector<std::string>& args) {
    bool include_hex = false;

    // Assumes that optional flags come after mandatory argument <transaction_hash>
    for (unsigned int i = 1; i < args.size(); ++i) {
        if (args[i] == "+hex")
            include_hex = true;
        else {
            std::cout << "unexpected argument: " << args[i] << std::endl;
            return true;
        }
    }
    if (args.empty()) {
        std::cout << "expected: print_block (<block_hash> | <block_height>) [+hex]" << std::endl;
        return false;
    }

    const std::string& arg = args.front();
    try {
        uint64_t height = boost::lexical_cast<uint64_t>(arg);
        return m_executor.print_block_by_height(height, include_hex);
    } catch (const boost::bad_lexical_cast&) {
        crypto::hash block_hash;
        if (tools::try_load_from_hex_guts(arg, block_hash))
            return m_executor.print_block_by_hash(block_hash, include_hex);
        log::error(logcat, "Invalid hash or height value: {}", arg);
    }

    return false;
}

bool command_parser_executor::print_transaction(const std::vector<std::string>& args) {
    bool include_metadata = false;
    bool include_hex = false;
    bool include_json = false;

    // Assumes that optional flags come after mandatory argument <transaction_hash>
    for (unsigned int i = 1; i < args.size(); ++i) {
        if (args[i] == "+meta")
            include_metadata = true;
        else if (args[i] == "+hex")
            include_hex = true;
        else if (args[i] == "+json")
            include_json = true;
        else {
            std::cout << "unexpected argument: " << args[i] << std::endl;
            return true;
        }
    }
    if (args.empty()) {
        std::cout << "expected: print_tx <transaction_hash> [+meta] [+hex] [+json]" << std::endl;
        return true;
    }

    const std::string& str_hash = args.front();
    crypto::hash tx_hash;
    if (tools::try_load_from_hex_guts(str_hash, tx_hash))
        m_executor.print_transaction(tx_hash, include_metadata, include_hex, include_json);
    else
        log::error(logcat, "Invalid transaction hash: {}", str_hash);

    return true;
}

bool command_parser_executor::is_key_image_spent(const std::vector<std::string>& args) {
    if (args.empty()) {
        tools::fail_msg_writer(
                "Invalid arguments.  Expected: is_key_image_spent <key_image> [<key_image> ...]\n");
        return true;
    }

    std::vector<crypto::key_image> kis;
    for (const auto& hex : args) {
        if (!tools::try_load_from_hex_guts(hex, kis.emplace_back())) {
            tools::fail_msg_writer("Invalid key image: '{}'", hex);
            return true;
        }
    }
    m_executor.is_key_image_spent(kis);

    return true;
}

bool command_parser_executor::print_transaction_pool_long(const std::vector<std::string>& args) {
    if (!args.empty())
        return false;

    return m_executor.print_transaction_pool(true);
}

bool command_parser_executor::print_transaction_pool_short(const std::vector<std::string>& args) {
    if (!args.empty())
        return false;

    return m_executor.print_transaction_pool(false);
}

bool command_parser_executor::print_transaction_pool_stats(const std::vector<std::string>& args) {
    if (!args.empty())
        return false;

    return m_executor.print_transaction_pool_stats();
}

bool command_parser_executor::start_mining(const std::vector<std::string>& args) {
    if (!args.size()) {
        std::cout << "Please specify a wallet address to mine for: "
                     "start_mining {<addr>|none} [threads={N|auto}] [num_blocks=N]"
                  << std::endl;
        return true;
    }

    std::string address = args.front();
    if (address == "none")
        ;
    else if (cryptonote::address_parse_info info;
             !cryptonote::get_account_address_from_str(
                     info, cryptonote::network_type::MAINNET, address) &&
             !cryptonote::get_account_address_from_str(
                     info, cryptonote::network_type::TESTNET, address) &&
             !cryptonote::get_account_address_from_str(
                     info, cryptonote::network_type::DEVNET, address) &&
             !cryptonote::get_account_address_from_str(
                     info, cryptonote::network_type::STAGENET, address)) {
        std::cout << "target account address has wrong format" << std::endl;
        return true;
    } else if (info.is_subaddress) {
        tools::fail_msg_writer("subaddress for mining reward is not yet supported!");
        return true;
    }

    std::string_view threads_val =
            tools::find_prefixed_value(args.begin() + 1, args.end(), "threads="sv);
    std::string_view num_blocks_val =
            tools::find_prefixed_value(args.begin() + 1, args.end(), "num_blocks="sv);

    unsigned int threads_count = 1, num_blocks = 0;
    if (threads_val.size() && !tools::parse_int(threads_val, threads_count)) {
        tools::fail_msg_writer("Failed to parse threads value {}", threads_val);
        return false;
    }

    if (num_blocks_val.size())
        tools::parse_int(num_blocks_val, num_blocks);
    m_executor.start_mining(address, threads_count, num_blocks);
    return true;
}

bool command_parser_executor::stop_mining(const std::vector<std::string>& args) {
    if (!args.empty())
        return false;

    return m_executor.stop_mining();
}

bool command_parser_executor::mining_status(const std::vector<std::string>& args) {
    return m_executor.mining_status();
}

bool command_parser_executor::stop_daemon(const std::vector<std::string>& args) {
    if (!args.empty())
        return false;

    return m_executor.stop_daemon();
}

bool command_parser_executor::set_limit(const std::vector<std::string>& args) {
    if (args.size() == 0)
        return m_executor.get_limit();

    if (args.size() > 2) {
        tools::fail_msg_writer("Too many arguments ({}): expected 0-2 values", args.size());
        return false;
    }
    int64_t limit_down;
    if (args[0] == "default")  // Accept "default" as a string because getting -1 through the cli
                               // arg parsing is a nuissance
        limit_down = -1;
    else if (!tools::parse_int(args[0], limit_down)) {
        tools::fail_msg_writer("Failed to parse '{}' as a limit", args[0]);
        return false;
    }

    int64_t limit_up;
    if (args.size() == 1)
        limit_up = limit_down;
    else if (args[1] == "default")
        limit_up = -1;
    else if (!tools::parse_int(args[1], limit_up)) {
        tools::fail_msg_writer("Failed to parse '{}' as a limit", args[1]);
        return false;
    }

    return m_executor.set_limit(limit_down, limit_up);
}

bool command_parser_executor::out_peers(const std::vector<std::string>& args) {
    bool set = false;
    uint32_t limit = 0;
    try {
        if (!args.empty()) {
            limit = std::stoi(args[0]);
            set = true;
        }
    }

    catch (const std::exception& ex) {
        log::error(logcat, "stoi exception");
        return false;
    }

    return m_executor.out_peers(set, limit);
}

bool command_parser_executor::in_peers(const std::vector<std::string>& args) {
    bool set = false;
    uint32_t limit = 0;
    try {
        if (!args.empty()) {
            limit = std::stoi(args[0]);
            set = true;
        }
    }

    catch (const std::exception& ex) {
        log::error(logcat, "stoi exception");
        return false;
    }

    return m_executor.in_peers(set, limit);
}

bool command_parser_executor::show_bans(const std::vector<std::string>& args) {
    if (!args.empty())
        return false;
    return m_executor.print_bans();
}

bool command_parser_executor::ban(const std::vector<std::string>& args) {
    if (args.size() != 1 && args.size() != 2)
        return false;
    std::string ip = args[0];
    time_t seconds = tools::to_seconds(cryptonote::p2p::IP_BLOCK_TIME);
    if (args.size() > 1) {
        try {
            seconds = std::stoi(args[1]);
        } catch (const std::exception& e) {
            return false;
        }
        if (seconds == 0) {
            return false;
        }
    }
    return m_executor.ban(ip, seconds);
}

bool command_parser_executor::unban(const std::vector<std::string>& args) {
    if (args.size() != 1)
        return false;
    std::string ip = args[0];
    return m_executor.unban(ip);
}

bool command_parser_executor::banned(const std::vector<std::string>& args) {
    if (args.size() != 1)
        return false;
    std::string address = args[0];
    return m_executor.banned(address);
}

bool command_parser_executor::flush_txpool(const std::vector<std::string>& args) {
    if (args.size() > 1)
        return false;

    std::string txid;
    if (args.size() == 1) {
        crypto::hash hash;
        if (!tools::try_load_from_hex_guts(args[0], hash)) {
            std::cout << "failed to parse tx id: " << args[0] << "\n";
            return true;
        }
        txid = args[0];
    }
    return m_executor.flush_txpool(std::move(txid));
}

bool command_parser_executor::output_histogram(const std::vector<std::string>& args) {
    std::vector<uint64_t> amounts;
    uint64_t min_count = 3;
    uint64_t max_count = 0;
    size_t n_raw = 0;

    for (size_t n = 0; n < args.size(); ++n) {
        if (args[n][0] == '@') {
            amounts.push_back(boost::lexical_cast<uint64_t>(args[n].c_str() + 1));
        } else if (n_raw == 0) {
            min_count = boost::lexical_cast<uint64_t>(args[n]);
            n_raw++;
        } else if (n_raw == 1) {
            max_count = boost::lexical_cast<uint64_t>(args[n]);
            n_raw++;
        } else {
            std::cout << "Invalid syntax: more than two non-amount parameters" << std::endl;
            return true;
        }
    }
    return m_executor.output_histogram(amounts, min_count, max_count);
}

bool command_parser_executor::print_coinbase_tx_sum(const std::vector<std::string>& args) {
    if (!args.size()) {
        std::cout << "need block height parameter" << std::endl;
        return false;
    }
    uint64_t height = 0;
    uint64_t count = 0;
    if (!epee::string_tools::get_xtype_from_string(height, args[0])) {
        std::cout << "wrong starter block height parameter" << std::endl;
        return false;
    }
    if (args.size() > 1 && !epee::string_tools::get_xtype_from_string(count, args[1])) {
        std::cout << "wrong count parameter" << std::endl;
        return false;
    }

    return m_executor.print_coinbase_tx_sum(height, count);
}

bool command_parser_executor::alt_chain_info(const std::vector<std::string>& args) {
    if (args.size() > 1) {
        std::cout << "usage: alt_chain_info [block_hash|>N|-N]" << std::endl;
        return false;
    }

    std::string tip;
    size_t above = 0;
    uint64_t last_blocks = 0;
    if (args.size() == 1) {
        if (args[0].size() > 0 && args[0][0] == '>') {
            if (!epee::string_tools::get_xtype_from_string(above, args[0].c_str() + 1)) {
                std::cout << "invalid above parameter" << std::endl;
                return false;
            }
        } else if (args[0].size() > 0 && args[0][0] == '-') {
            if (!epee::string_tools::get_xtype_from_string(last_blocks, args[0].c_str() + 1)) {
                std::cout << "invalid last_blocks parameter" << std::endl;
                return false;
            }
        } else {
            tip = args[0];
        }
    }

    return m_executor.alt_chain_info(tip, above, last_blocks);
}

bool command_parser_executor::print_blockchain_dynamic_stats(const std::vector<std::string>& args) {
    if (args.size() != 1) {
        std::cout << "Exactly one parameter is needed" << std::endl;
        return false;
    }

    uint64_t nblocks = 0;
    if (!epee::string_tools::get_xtype_from_string(nblocks, args[0]) || nblocks == 0) {
        std::cout << "wrong number of blocks" << std::endl;
        return false;
    }

    return m_executor.print_blockchain_dynamic_stats(nblocks);
}

bool command_parser_executor::relay_tx(const std::vector<std::string>& args) {
    if (args.size() != 1)
        return false;

    std::string txid;
    crypto::hash hash;
    if (!tools::try_load_from_hex_guts(args[0], hash)) {
        std::cout << "failed to parse tx id: " << args[0] << std::endl;
        return true;
    }
    txid = args[0];
    return m_executor.relay_tx(txid);
}

bool command_parser_executor::sync_info(const std::vector<std::string>& args) {
    if (args.size() != 0)
        return false;

    return m_executor.sync_info();
}

bool command_parser_executor::pop_blocks(const std::vector<std::string>& args) {
    if (args.size() != 1) {
        std::cout << "Exactly one parameter is needed" << std::endl;
        return false;
    }

    try {
        uint64_t nblocks = boost::lexical_cast<uint64_t>(args[0]);
        if (nblocks < 1) {
            std::cout << "number of blocks must be greater than 0" << std::endl;
            return false;
        }
        return m_executor.pop_blocks(nblocks);
    } catch (const boost::bad_lexical_cast&) {
        std::cout << "number of blocks must be a number greater than 0" << std::endl;
    }
    return false;
}

bool command_parser_executor::version(const std::vector<std::string>& args) {
    return m_executor.version();
}

bool command_parser_executor::prune_blockchain(const std::vector<std::string>& args) {
    if (args.size() > 1)
        return false;

    if (args.empty() || args[0] != "confirm") {
        std::cout << "Warning: pruning from within oxend will not shrink the database file size."
                  << std::endl;
        std::cout << "Instead, parts of the file will be marked as free, so the file will not grow"
                  << std::endl;
        std::cout << "until that newly free space is used up. If you want a smaller file size now,"
                  << std::endl;
        std::cout << "exit oxend and run oxen-blockchain-prune (you will temporarily need more"
                  << std::endl;
        std::cout << "disk space for the database conversion though). If you are OK with the "
                     "database"
                  << std::endl;
        std::cout << "file keeping the same size, re-run this command with the \"confirm\" "
                     "parameter."
                  << std::endl;
        return true;
    }

    return m_executor.prune_blockchain();
}

bool command_parser_executor::check_blockchain_pruning(const std::vector<std::string>& args) {
    return m_executor.check_blockchain_pruning();
}

bool command_parser_executor::flush_cache(const std::vector<std::string>& args) {
    bool bad_txs = false, bad_blocks = false;
    std::string arg;

    if (args.empty())
        goto show_list;

    for (size_t i = 0; i < args.size(); ++i) {
        arg = args[i];
        if (arg == "bad-txs")
            bad_txs = true;
        else if (arg == "bad-blocks")
            bad_blocks = true;
        else
            goto show_list;
    }
    return m_executor.flush_cache(bad_txs, bad_blocks);

show_list:
    std::cout << "Invalid cache type: " << arg << std::endl;
    std::cout << "Cache types: bad-txs bad-blocks" << std::endl;
    return true;
}

bool command_parser_executor::claim_rewards(const std::vector<std::string>& args) {
    if (args.size() != 1) {
        tools::fail_msg_writer("Invalid arguments.  Expected: claim_rewards <eth_address>\n");
        return false;
    }

    return m_executor.claim_rewards(args[0]);
}

}  // namespace daemonize
