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

#include "daemon/command_server.h"

#include <optional>

#include "cryptonote_config.h"
#include "epee/string_tools.h"
#include "version.h"

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize {

void command_server::init_commands(cryptonote::rpc::core_rpc_server* rpc_server) {
    m_command_lookup.set_handler(
            "help",
            [this](const auto& x) { return help(x); },
            "help [<command>]",
            "Show the help section or the documentation about a <command>.");
    m_command_lookup.set_handler(
            "print_height",
            [this](const auto& x) { return m_parser.print_height(x); },
            "Print the local blockchain height.");
    m_command_lookup.set_handler(
            "print_pl",
            [this](const auto& x) { return m_parser.print_peer_list(x); },
            "print_pl [white] [gray] [pruned] [<limit>]",
            "Print the current peer list.");
    m_command_lookup.set_handler(
            "print_pl_stats",
            [this](const auto& x) { return m_parser.print_peer_list_stats(x); },
            "Print the peer list statistics.");
    m_command_lookup.set_handler(
            "print_cn",
            [this](const auto& x) { return m_parser.print_connections(x); },
            "Print the current connections.");
    m_command_lookup.set_handler(
            "print_net_stats",
            [this](const auto& x) { return m_parser.print_net_stats(x); },
            "Print network statistics.");
    m_command_lookup.set_handler(
            "print_bc",
            [this](const auto& x) { return m_parser.print_blockchain_info(x); },
            "print_bc <begin_height> [<end_height>]",
            "Print the blockchain info in a given blocks range.");
    m_command_lookup.set_handler(
            "print_block",
            [this](const auto& x) { return m_parser.print_block(x); },
            "print_block <block_hash> | <block_height>",
            "Print a given block.");
    m_command_lookup.set_handler(
            "print_tx",
            [this](const auto& x) { return m_parser.print_transaction(x); },
            "print_tx <transaction_hash> [+hex] [+json]",
            "Print a given transaction.");
    m_command_lookup.set_handler(
            "print_quorum_state",
            [this](const auto& x) { return m_parser.print_quorum_state(x); },
            "print_quorum_state [start height] [end height]",
            "Print the quorum state for the range of block heights, omit the height to print the "
            "latest quorum");
    m_command_lookup.set_handler(
            "print_sn_key",
            [this](const auto& x) { return m_parser.print_sn_key(x); },
            "print_sn_key",
            "Print this daemon's service node key, if it is one and launched in service node "
            "mode.");
    m_command_lookup.set_handler(
            "print_sr",
            [this](const auto& x) { return m_parser.print_sr(x); },
            "print_sr <height>",
            "Print the staking requirement for the height.");
    m_command_lookup.set_handler(
            "prepare_registration",
            [this](const auto& x) { return m_parser.prepare_registration(x); },
            "prepare_registration [+force]",
            "Interactive prompt to prepare a service node registration command. The resulting "
            "registration command can be run in the command-line wallet to send the registration "
            "to the blockchain.");

    m_command_lookup.set_handler(
            "prepare_eth_registration",
            [this](const auto& x) { return m_parser.prepare_eth_registration(x); },
            "prepare_eth_registration <operator address> [\"print\"]",
            "Prepare a service node registration for submission to the ethereum contract.  By "
            "default this information is submitted to https://stake.getsession.org to make it easy "
            "to submit your registration to the smart contract.  If you would prefer to just print "
            "the information instead of submitting it, append the word 'print' to the command.");

    m_command_lookup.set_handler(
            "print_sn",
            [this](const auto& x) { return m_parser.print_sn(x); },
            "print_sn [<pubkey> [...]] [+json|+detail]",
            "Print service node registration info for the current height");
    m_command_lookup.set_handler(
            "print_sn_status",
            [this](const auto& x) { return m_parser.print_sn_status(x); },
            "print_sn_status [+json|+detail]",
            "Print service node registration info for this service node");
    m_command_lookup.set_handler(
            "is_key_image_spent",
            [this](const auto& x) { return m_parser.is_key_image_spent(x); },
            "is_key_image_spent <key_image> [<key_image> ...]",
            "Queries whether one or more key images have been spent on the blockchain or in the "
            "memory pool.");
    m_command_lookup.set_handler(
            "start_mining",
            [this](const auto& x) { return m_parser.start_mining(x); },
            "start_mining <addr> [threads=N] [num_blocks=B]",
            "Start mining for specified address, primarily for debug and testing purposes as Oxen "
            "is proof-of-stake. Defaults to 1 thread. When num_blocks is set, continue mining "
            "until the blockchain reaches height (current + B).");
    m_command_lookup.set_handler(
            "stop_mining",
            [this](const auto& x) { return m_parser.stop_mining(x); },
            "Stop mining.");
    m_command_lookup.set_handler(
            "mining_status",
            [this](const auto& x) { return m_parser.mining_status(x); },
            "Show current mining status.");
    m_command_lookup.set_handler(
            "print_pool",
            [this](const auto& x) { return m_parser.print_transaction_pool_long(x); },
            "Print the transaction pool using a long format.");
    m_command_lookup.set_handler(
            "print_pool_sh",
            [this](const auto& x) { return m_parser.print_transaction_pool_short(x); },
            "Print transaction pool using a short format.");
    m_command_lookup.set_handler(
            "print_pool_stats",
            [this](const auto& x) { return m_parser.print_transaction_pool_stats(x); },
            "Print the transaction pool's statistics.");
    m_command_lookup.set_handler(
            "save",
            [this](const auto& x) { return m_parser.save_blockchain(x); },
            "Save the blockchain.");
    m_command_lookup.set_handler(
            "set_log",
            [this](const auto& x) { return m_parser.set_log_level(x); },
            "set_log [LEVEL] [CATEGORY=LEVEL ...]",
            "Change the current global log level and/or category-specific log levels.  LEVEL is "
            "one of critical/error/warning/info/debug/trace.");
    m_command_lookup.set_handler(
            "diff",
            [this](const auto& x) { return m_parser.show_difficulty(x); },
            "Show the current difficulty.");
    m_command_lookup.set_handler(
            "status",
            [this](const auto& x) { return m_parser.show_status(x); },
            "Show the current status.");
    m_command_lookup.set_handler(
            "stop_daemon",
            [this](const auto& x) { return m_parser.stop_daemon(x); },
            "Stop the daemon.");
    m_command_lookup.set_handler(
            "exit", [this](const auto& x) { return m_parser.stop_daemon(x); }, "Stop the daemon.");
    m_command_lookup.set_handler(
            "limit",
            [this](const auto& x) { return m_parser.set_limit(x); },
            "limit [<kiB/s> [<kiB/s]]",
            R"(Get or set the download and/or upload limit.  If given no arguments then this
prints the current limits.  If given single value then it is applied to both
download and upload limits.  If given two values then they are the new download
and upload limits, respectively.  Limits may be 0 to leave the value unchanged,
or "default" to return the limit to its default value.)");
    m_command_lookup.set_handler(
            "out_peers",
            [this](const auto& x) { return m_parser.out_peers(x); },
            "out_peers <max_number>",
            "Set the <max_number> of out peers.");
    m_command_lookup.set_handler(
            "in_peers",
            [this](const auto& x) { return m_parser.in_peers(x); },
            "in_peers <max_number>",
            "Set the <max_number> of in peers.");
    m_command_lookup.set_handler(
            "bans",
            [this](const auto& x) { return m_parser.show_bans(x); },
            "Show the currently banned IPs.");
    m_command_lookup.set_handler(
            "ban",
            [this](const auto& x) { return m_parser.ban(x); },
            "ban <IP> [<seconds>]",
            "Ban a given <IP> for a given amount of <seconds>.");
    m_command_lookup.set_handler(
            "unban",
            [this](const auto& x) { return m_parser.unban(x); },
            "unban <address>",
            "Unban a given <IP>.");
    m_command_lookup.set_handler(
            "banned",
            [this](const auto& x) { return m_parser.banned(x); },
            "banned <address>",
            "Check whether an <address> is banned.");
    m_command_lookup.set_handler(
            "flush_txpool",
            [this](const auto& x) { return m_parser.flush_txpool(x); },
            "flush_txpool [<txid>]",
            "Flush a transaction from the tx pool by its <txid>, or the whole tx pool.");
    m_command_lookup.set_handler(
            "output_histogram",
            [this](const auto& x) { return m_parser.output_histogram(x); },
            "output_histogram [@<amount>] <min_count> [<max_count>]",
            "Print the output histogram of outputs.");
    m_command_lookup.set_handler(
            "print_coinbase_tx_sum",
            [this](const auto& x) { return m_parser.print_coinbase_tx_sum(x); },
            "print_coinbase_tx_sum <start_height> [<block_count>]",
            "Print the sum of coinbase transactions.");
    m_command_lookup.set_handler(
            "alt_chain_info",
            [this](const auto& x) { return m_parser.alt_chain_info(x); },
            "alt_chain_info [blockhash]",
            "Print the information about alternative chains.");
    m_command_lookup.set_handler(
            "bc_dyn_stats",
            [this](const auto& x) { return m_parser.print_blockchain_dynamic_stats(x); },
            "bc_dyn_stats <last_block_count>",
            "Print the information about current blockchain dynamic state.");
    // TODO(oxen): Implement
#if 0
    m_command_lookup.set_handler(
      "update"
    , [this](const auto &x) { return m_parser.update(x); }
    , "update (check|download)"
    , "Check if an update is available, optionally downloads it if there is. Updating is not yet implemented."
    );
#endif
    m_command_lookup.set_handler(
            "relay_tx",
            [this](const auto& x) { return m_parser.relay_tx(x); },
            "relay_tx <txid>",
            "Relay a given transaction by its <txid>.");
    m_command_lookup.set_handler(
            "sync_info",
            [this](const auto& x) { return m_parser.sync_info(x); },
            "Print information about the blockchain sync state.");
    m_command_lookup.set_handler(
            "pop_blocks",
            [this](const auto& x) { return m_parser.pop_blocks(x); },
            "pop_blocks <nblocks>",
            "Remove blocks from end of blockchain");
    m_command_lookup.set_handler(
            "version",
            [this](const auto& x) { return m_parser.version(x); },
            "Print version information.");
#if 0  // TODO(oxen): Pruning not supported because of Service Node List
    m_command_lookup.set_handler(
      "prune_blockchain"
    , [this](const auto &x) { return m_parser.prune_blockchain(x); }
    , "Prune the blockchain."
    );
#endif
    m_command_lookup.set_handler(
            "check_blockchain_pruning",
            [this](const auto& x) { return m_parser.check_blockchain_pruning(x); },
            "Check the blockchain pruning.");
    m_command_lookup.set_handler(
            "print_checkpoints",
            [this](const auto& x) { return m_parser.print_checkpoints(x); },
            "print_checkpoints [+json] [start height] [end height]",
            "Query the available checkpoints between the range, omit arguments to print the last "
            "60 checkpoints");
    m_command_lookup.set_handler(
            "print_sn_state_changes",
            [this](const auto& x) { return m_parser.print_sn_state_changes(x); },
            "print_sn_state_changes <start_height> [end height]",
            "Query the state changes between the range, omit the last argument to scan until the "
            "current block");
    m_command_lookup.set_handler(
            "flush_cache",
            [this](const auto& x) { return m_parser.flush_cache(x); },
            "flush_cache [bad-txs] [bad-blocks]",
            "Flush the specified cache(s).");
    m_command_lookup.set_handler(
            "claim_rewards",
            [this](const auto& x) { return m_parser.claim_rewards(x); },
            "claim_rewards ETH_ADDRESS",
            "Generates a network reward signature that allows claiming of SENT rewards");
    m_command_lookup.set_handler(
            "test_trigger_uptime_proof",
            [this](const auto&) {
                m_parser.test_trigger_uptime_proof();
                return true;
            },
            "");
}

bool command_server::start_handling(std::function<void(void)> exit_handler) {

    m_command_lookup.start_handling("", get_commands_str(), std::move(exit_handler));
    return true;
}

void command_server::stop_handling() {
    m_command_lookup.stop_handling();
}

bool command_server::help(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << get_commands_str() << std::endl;
    } else {
        std::cout << get_command_usage(args) << std::endl;
    }
    return true;
}

std::string command_server::get_commands_str() {
    std::stringstream ss;
    ss << "Oxen '" << OXEN_RELEASE_NAME << "' (v" << OXEN_VERSION_FULL << ")" << std::endl;
    ss << "Commands:\n";
    m_command_lookup.for_each([&ss](const std::string&,
                                    const std::string& usage,
                                    const std::string&) { ss << "  " << usage << "\n"; });
    return ss.str();
}

std::string command_server::get_command_usage(const std::vector<std::string>& args) {
    std::pair<std::string, std::string> documentation = m_command_lookup.get_documentation(args);
    std::stringstream ss;
    if (documentation.first.empty()) {
        ss << "Unknown command: " << args.front() << std::endl;
    } else {
        std::string usage = documentation.second.empty() ? args.front() : documentation.first;
        std::string description =
                documentation.second.empty() ? documentation.first : documentation.second;
        usage.insert(0, "  ");
        ss << "Command usage: \n" << usage << "\n\n";
        ss << "Command description:\n  ";
        for (char c : description) {
            if (c == '\n')
                ss << "\n  ";
            else
                ss << c;
        }
    }
    return ss.str();
}

}  // namespace daemonize
