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

#include "blockchain_db/blockchain_db.h"
#include "blockchain_objects.h"
#include "cryptonote_core/cryptonote_core.h"
#include "version.h"

#include <common/command_line.h>
#include <common/guts.h>
#include <common/median.h>
#include <common/exception.h>

#include <fmt/std.h>

namespace po = boost::program_options;
using namespace cryptonote;

static auto logcat = log::Cat("bcutil");

int main(int argc, char* argv[]) {
    std::set_terminate(oxen::on_terminate_handler);
    TRY_ENTRY();

    epee::string_tools::set_module_name_and_folder(argv[0]);
    tools::on_startup();

    auto opt_size = command_line::boost_option_sizes();

    po::options_description desc_cmd_only("Command line options", opt_size.first, opt_size.second);
    po::options_description desc_cmd_sett(
            "Command line options and settings options", opt_size.first, opt_size.second);
    const command_line::arg_descriptor<std::string> arg_log_level = {
            "log-level", "0-4 or categories", ""};
    const command_line::arg_descriptor<std::string> arg_txid = {
            "txid", "Get min depth for this txid", ""};
    const command_line::arg_descriptor<uint64_t> arg_height = {
            "height", "Get min depth for all txes at this height", 0};
    const command_line::arg_descriptor<bool> arg_include_coinbase = {
            "include-coinbase", "Include coinbase in the average", false};

    command_line::add_arg(desc_cmd_sett, cryptonote::arg_data_dir);
    command_line::add_arg(desc_cmd_sett, cryptonote::arg_testnet_on);
    command_line::add_arg(desc_cmd_sett, cryptonote::arg_devnet_on);
    command_line::add_arg(desc_cmd_sett, arg_log_level);
    command_line::add_arg(desc_cmd_sett, arg_txid);
    command_line::add_arg(desc_cmd_sett, arg_height);
    command_line::add_arg(desc_cmd_sett, arg_include_coinbase);
    command_line::add_arg(desc_cmd_only, command_line::arg_help);

    po::options_description desc_options("Allowed options");
    desc_options.add(desc_cmd_only).add(desc_cmd_sett);

    po::variables_map vm;
    bool r = command_line::handle_error_helper(desc_options, [&]() {
        auto parser = po::command_line_parser(argc, argv).options(desc_options);
        po::store(parser.run(), vm);
        po::notify(vm);
        return true;
    });
    if (!r)
        return 1;

    if (command_line::get_arg(vm, command_line::arg_help)) {
        std::cout << "Oxen '" << OXEN_RELEASE_NAME << "' (v" << OXEN_VERSION_FULL << ")\n\n";
        std::cout << desc_options << std::endl;
        return 1;
    }

    auto m_config_folder = command_line::get_arg(vm, cryptonote::arg_data_dir);
    auto log_file_path = m_config_folder + "oxen-blockchain-depth.log";
    log::Level log_level;
    if (auto level = oxen::logging::parse_level(command_line::get_arg(vm, arg_log_level).c_str())) {
        log_level = *level;
    } else {
        std::cerr << "Incorrect log level: " << command_line::get_arg(vm, arg_log_level).c_str()
                  << std::endl;
        throw oxen::traced<std::runtime_error>{"Incorrect log level"};
    }
    oxen::logging::init(log_file_path, log_level);
    log::warning(logcat, "Starting...");

    bool opt_testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
    bool opt_devnet = command_line::get_arg(vm, cryptonote::arg_devnet_on);
    network_type net_type = opt_testnet ? network_type::TESTNET
                          : opt_devnet  ? network_type::DEVNET
                                        : network_type::MAINNET;
    std::string opt_txid_string = command_line::get_arg(vm, arg_txid);
    uint64_t opt_height = command_line::get_arg(vm, arg_height);
    bool opt_include_coinbase = command_line::get_arg(vm, arg_include_coinbase);

    if (!opt_txid_string.empty() && opt_height) {
        std::cerr << "txid and height cannot be given at the same time" << std::endl;
        return 1;
    }
    crypto::hash opt_txid{};
    if (!opt_txid_string.empty()) {
        if (!tools::try_load_from_hex_guts(opt_txid_string, opt_txid)) {
            std::cerr << "Invalid txid" << std::endl;
            return 1;
        }
    }

    log::warning(logcat, "Initializing source blockchain (BlockchainDB)");
    blockchain_objects_t blockchain_objects = {};
    Blockchain* core_storage = &blockchain_objects.m_blockchain;
    BlockchainDB* db = new_db();
    if (db == NULL) {
        log::error(logcat, "Failed to initialize a database");
        throw oxen::traced<std::runtime_error>("Failed to initialize a database");
    }
    log::warning(logcat, "database: LMDB");

    const fs::path filename =
            tools::utf8_path(command_line::get_arg(vm, cryptonote::arg_data_dir)) /
            db->get_db_name();
    log::warning(logcat, "Loading blockchain from folder {} ...", filename);

    try {
        db->open(filename, core_storage->nettype(), DBF_RDONLY);
    } catch (const std::exception& e) {
        log::warning(logcat, "Error opening database: {}", e.what());
        return 1;
    }
    r = core_storage->init(db, nullptr /*ons_db*/, nullptr, net_type);

    CHECK_AND_ASSERT_MES(r, 1, "Failed to initialize source blockchain storage");
    log::warning(logcat, "Source blockchain storage initialized OK");

    std::vector<crypto::hash> start_txids;
    if (!opt_txid_string.empty()) {
        start_txids.push_back(opt_txid);
    } else {
        const std::string bd = db->get_block_blob_from_height(opt_height);
        cryptonote::block b;
        if (!cryptonote::parse_and_validate_block_from_blob(bd, b)) {
            log::warning(logcat, "Bad block from db");
            return 1;
        }
        for (const crypto::hash& txid : b.tx_hashes)
            start_txids.push_back(txid);
        if (opt_include_coinbase)
            start_txids.push_back(cryptonote::get_transaction_hash(b.miner_tx));
    }

    if (start_txids.empty()) {
        log::warning(logcat, "No transaction(s) to check");
        return 1;
    }

    std::vector<uint64_t> depths;
    for (const crypto::hash& start_txid : start_txids) {
        uint64_t depth = 0;
        bool coinbase = false;

        log::warning(logcat, "Checking depth for txid {}", start_txid);
        std::vector<crypto::hash> txids(1, start_txid);
        while (!coinbase) {
            log::warning(logcat, "Considering {} transaction(s) at depth {}", txids.size(), depth);
            std::vector<crypto::hash> new_txids;
            for (const crypto::hash& txid : txids) {
                std::string bd;
                if (!db->get_pruned_tx_blob(txid, bd)) {
                    log::warning(logcat, "Failed to get txid {} from db", txid);
                    return 1;
                }
                cryptonote::transaction tx;
                if (!cryptonote::parse_and_validate_tx_base_from_blob(bd, tx)) {
                    log::warning(logcat, "Bad tx: {}", txid);
                    return 1;
                }
                for (size_t ring = 0; ring < tx.vin.size(); ++ring) {
                    if (std::holds_alternative<cryptonote::txin_gen>(tx.vin[ring])) {
                        log::debug(logcat, "{} is a coinbase transaction", txid);
                        coinbase = true;
                        goto done;
                    }
                    if (auto* txin = std::get_if<cryptonote::txin_to_key>(&tx.vin[ring])) {
                        const uint64_t amount = txin->amount;
                        auto absolute_offsets =
                                cryptonote::relative_output_offsets_to_absolute(txin->key_offsets);
                        for (uint64_t offset : absolute_offsets) {
                            const output_data_t od = db->get_output_key(amount, offset);
                            const crypto::hash block_hash =
                                    db->get_block_hash_from_height(od.height);
                            bd = db->get_block_blob(block_hash);
                            cryptonote::block b;
                            if (!cryptonote::parse_and_validate_block_from_blob(bd, b)) {
                                log::warning(logcat, "Bad block from db");
                                return 1;
                            }
                            // find the tx which created this output
                            bool found = false;
                            for (size_t out = 0; out < b.miner_tx.vout.size(); ++out) {
                                if (auto* txout = std::get_if<cryptonote::txout_to_key>(
                                            &b.miner_tx.vout[out].target)) {
                                    if (txout->key == od.pubkey) {
                                        found = true;
                                        new_txids.push_back(
                                                cryptonote::get_transaction_hash(b.miner_tx));
                                        log::debug(
                                                logcat,
                                                "adding txid: {}",
                                                cryptonote::get_transaction_hash(b.miner_tx));
                                        break;
                                    }
                                } else {
                                    log::warning(
                                            logcat,
                                            "Bad vout type in txid {}",
                                            cryptonote::get_transaction_hash(b.miner_tx));
                                    return 1;
                                }
                            }
                            for (const crypto::hash& block_txid : b.tx_hashes) {
                                if (found)
                                    break;
                                if (!db->get_pruned_tx_blob(block_txid, bd)) {
                                    log::warning(
                                            logcat, "Failed to get txid {} from db", block_txid);
                                    return 1;
                                }
                                cryptonote::transaction tx2;
                                if (!cryptonote::parse_and_validate_tx_base_from_blob(bd, tx2)) {
                                    log::warning(logcat, "Bad tx: {}", block_txid);
                                    return 1;
                                }
                                for (size_t out = 0; out < tx2.vout.size(); ++out) {
                                    if (auto* txout = std::get_if<cryptonote::txout_to_key>(
                                                &tx2.vout[out].target)) {
                                        if (txout->key == od.pubkey) {
                                            found = true;
                                            new_txids.push_back(block_txid);
                                            log::debug(logcat, "adding txid: {}", block_txid);
                                            break;
                                        }
                                    } else {
                                        log::warning(
                                                logcat, "Bad vout type in txid {}", block_txid);
                                        return 1;
                                    }
                                }
                            }
                            if (!found) {
                                log::warning(logcat, "Output originating transaction not found");
                                return 1;
                            }
                        }
                    } else {
                        log::warning(logcat, "Bad vin type in txid {}", txid);
                        return 1;
                    }
                }
            }
            if (!coinbase) {
                std::swap(txids, new_txids);
                ++depth;
            }
        }
    done:
        log::warning(logcat, "Min depth for txid {}: {}", start_txid, depth);
        depths.push_back(depth);
    }

    uint64_t cumulative_depth = 0;
    for (uint64_t depth : depths)
        cumulative_depth += depth;
    log::warning(
            logcat,
            "Average min depth for {} transaction(s): {}",
            start_txids.size(),
            cumulative_depth / (float)depths.size());
    log::warning(
            logcat,
            "Median min depth for {} transaction(s): {}",
            start_txids.size(),
            tools::median(std::move(depths)));

    core_storage->deinit();
    return 0;

    CATCH_ENTRY("Depth query error", 1);
}
