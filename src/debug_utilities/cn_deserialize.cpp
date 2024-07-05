// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2018, The Loki Project
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

#include <oxenc/hex.h>

#include <cpptrace/cpptrace.hpp>

#include "common/command_line.h"
#include "common/exception.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_core/blockchain.h"
#include "oxen_economy.h"
#include "version.h"

namespace po = boost::program_options;

using namespace cryptonote;

static auto logcat = log::Cat("debugtools.deserialize");

static std::string extra_nonce_to_string(const cryptonote::tx_extra_nonce& extra_nonce) {
    if (extra_nonce.nonce.size() == 9 &&
        extra_nonce.nonce[0] == TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID)
        return "encrypted payment ID: " +
               oxenc::to_hex(extra_nonce.nonce.begin() + 1, extra_nonce.nonce.end());
    if (extra_nonce.nonce.size() == 33 && extra_nonce.nonce[0] == TX_EXTRA_NONCE_PAYMENT_ID)
        return "plaintext payment ID: " +
               oxenc::to_hex(extra_nonce.nonce.begin() + 1, extra_nonce.nonce.end());
    return oxenc::to_hex(extra_nonce.nonce);
}

struct extra_printer {
    std::string operator()(const tx_extra_padding& x) { return "padding: {} bytes"_format(x.size); }
    std::string operator()(const tx_extra_pub_key& x) { return "pub key: {}"_format(x.pub_key); }
    std::string operator()(const tx_extra_nonce& x) {
        return "nonce: {}"_format(extra_nonce_to_string(x));
    }
    std::string operator()(const tx_extra_merge_mining_tag& x) {
        return "merge mining tag: depth {}, markle root {}"_format(x.depth, x.merkle_root);
    }
    std::string operator()(const tx_extra_additional_pub_keys& x) {
        return "additional tx pubkeys: {}"_format(fmt::join(x.data, ", "));
    }
    std::string operator()(const tx_extra_mysterious_minergate& x) {
        return "minergate custom: {}"_format(oxenc::to_hex(x.data));
    }
    std::string operator()(const tx_extra_service_node_winner& x) {
        return "SN reward winner: {}"_format(x.m_service_node_key);
    }
    std::string operator()(const tx_extra_service_node_register& x) {
        return "SN registration data";
    }  // TODO: could parse this further
    std::string operator()(const tx_extra_service_node_pubkey& x) {
        return "SN pubkey: {}"_format(x.m_service_node_key);
    }
    std::string operator()(const tx_extra_service_node_contributor& x) {
        return "SN contribution";
    }  // Can't actually print the address without knowing the network type
    std::string operator()(const tx_extra_service_node_deregister_old& x) {
        return "SN deregistration (pre-HF12)";
    }
    std::string operator()(const tx_extra_tx_secret_key& x) {
        return "TX secret key: {}" + tools::hex_guts(x.key);
    }
    std::string operator()(const tx_extra_tx_key_image_proofs& x) {
        return "TX key image proofs ({})"_format(x.proofs.size());
    }
    std::string operator()(const tx_extra_tx_key_image_unlock& x) {
        return "TX key image unlock: {}"_format(x.key_image);
    }
    std::string operator()(const tx_extra_burn& x) {
        return "Transaction burned fee/payment: {}"_format(print_money(x.amount));
    }
    std::string operator()(const tx_extra_oxen_name_system& x) {
        std::string val = "ONS {}"_format(
                x.is_buying()     ? "registration"
                : x.is_updating() ? "update"
                                  : "(unknown)");
        switch (x.type) {
            case ons::mapping_type::lokinet: val += " - Lokinet (1y)"; break;
            case ons::mapping_type::lokinet_2years: val += " - Lokinet (2y)"; break;
            case ons::mapping_type::lokinet_5years: val += " - Lokinet (5y)"; break;
            case ons::mapping_type::lokinet_10years: val += " - Lokinet (10y)"; break;
            case ons::mapping_type::session: val += " - Session address"; break;
            case ons::mapping_type::wallet: val += " - Wallet address"; break;
            case ons::mapping_type::update_record_internal:
            case ons::mapping_type::_count: break;
        }
        return val;
    }
    std::string operator()(const tx_extra_service_node_state_change& x) {
        std::string_view type;
        switch (x.state) {
            case service_nodes::new_state::decommission: type = "decommission"; break;
            case service_nodes::new_state::recommission: type = "recommission"; break;
            case service_nodes::new_state::deregister: type = "deregister"; break;
            case service_nodes::new_state::ip_change_penalty: type = "ip change penalty"; break;
            case service_nodes::new_state::_count: type = "(unknown)"; break;
        }
        return "SN state change: {} for block height {}, SN index {}"_format(
                type, x.block_height, x.service_node_index);
    }
    std::string operator()(const tx_extra_ethereum_new_service_node& x) {
        std::string contributors_info;
        for (const auto& contributor : x.contributors) {
            contributors_info += fmt::format(
                    "{{address: {}, amount: {}}}, ",
                    contributor.address,
                    print_money(contributor.amount));
        }
        return "New Ethereum Service Node: version {}, bls key {}, eth address {}, sn pubkey {}, fee {}, contributors [{}] signature {}"_format(
                x.version,
                x.bls_pubkey,
                x.eth_address,
                x.service_node_pubkey,
                print_money(x.fee),
                contributors_info,
                x.signature);
    }
    std::string operator()(const tx_extra_ethereum_service_node_leave_request& x) {
        return "Ethereum Service Node Leave Request: version {}, bls key {}"_format(
                x.version, x.bls_pubkey);
    }
    std::string operator()(const tx_extra_ethereum_service_node_exit& x) {
        return "Ethereum Service Node Exit: version {}, eth address {}, amount {}, bls key {}"_format(
                x.version, x.eth_address, print_money(x.amount), x.bls_pubkey);
    }
    std::string operator()(const tx_extra_ethereum_service_node_deregister& x) {
        return "Ethereum Service Node Deregister: version {}, bls key {}"_format(
                x.version, x.bls_pubkey);
    }
};

static void print_extra_fields(const std::vector<cryptonote::tx_extra_field>& fields) {
    std::cout << "tx_extra has " << fields.size() << " field(s)\n";
    for (size_t n = 0; n < fields.size(); ++n) {
        std::cout << "- " << n << ": ";
        std::cout << var::visit(extra_printer{}, fields[n]);
        std::cout << "\n";
    }
}

constexpr static std::string_view network_type_str(network_type nettype) {
    switch (nettype) {
        case network_type::MAINNET: return "Mainnet"sv;
        case network_type::TESTNET: return "Testnet"sv;
        case network_type::DEVNET: return "Devnet"sv;
        case network_type::FAKECHAIN: return "Fakenet"sv;
        case network_type::UNDEFINED: return "Undefined Net"sv;
    }
    return "Unhandled Net"sv;
}

int main(int argc, char* argv[]) {
    std::set_terminate(oxen::on_terminate_handler);
    uint32_t default_log_level = 0;
    std::string input;

    tools::on_startup();

    po::options_description desc_cmd_only("Command line options");
    po::options_description desc_cmd_sett("Command line options and settings options");
    const command_line::arg_descriptor<uint32_t> arg_log_level = {
            "log-level", "", default_log_level};
    const command_line::arg_descriptor<std::string> arg_input = {
            "input",
            "Specify a wallet address or hex string of a Cryptonote type for decoding, supporting\n"
            " - TX Extra\n"
            " - Block\n"
            " - Transaction\n",
            ""};

    command_line::add_arg(desc_cmd_sett, arg_log_level);
    command_line::add_arg(desc_cmd_sett, arg_input);

    command_line::add_arg(desc_cmd_only, command_line::arg_help);

    po::options_description desc_options("Allowed options");
    desc_options.add(desc_cmd_only).add(desc_cmd_sett);

    po::variables_map vm;
    bool r = command_line::handle_error_helper(desc_options, [&]() {
        po::store(po::parse_command_line(argc, argv, desc_options), vm);
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

    input = command_line::get_arg(vm, arg_input);
    if (input.empty()) {
        std::cerr << "Usage: --input <hex|wallet address>" << std::endl;
        return 1;
    }

    auto log_file_path = "cn_deserialize.log";
    log::Level log_level;
    if (auto level = oxen::logging::parse_level(command_line::get_arg(vm, arg_log_level))) {
        log_level = *level;
    } else {
        std::cerr << "Incorrect log level: " << command_line::get_arg(vm, arg_log_level)
                  << std::endl;
        throw oxen::traced<std::runtime_error>{"Incorrect log level"};
    }
    oxen::logging::init(log_file_path, log_level);
    log::warning(logcat, "Starting...");

    if (oxenc::is_hex(input)) {
        auto blob = oxenc::from_hex(input);
        bool full;
        cryptonote::block block;
        cryptonote::transaction tx;
        std::vector<cryptonote::tx_extra_field> fields;
        if (cryptonote::parse_and_validate_block_from_blob(blob, block)) {
            std::cout << "Parsed block:" << std::endl;
            std::cout << cryptonote::obj_to_json_str(block) << std::endl;
        } else if (
                cryptonote::parse_and_validate_tx_from_blob(blob, tx) ||
                cryptonote::parse_and_validate_tx_base_from_blob(blob, tx)) {
            if (tx.pruned)
                std::cout << "Parsed pruned transaction:" << std::endl;
            else
                std::cout << "Parsed transaction:" << std::endl;
            std::cout << cryptonote::obj_to_json_str(tx) << std::endl;

            bool parsed = cryptonote::parse_tx_extra(tx.extra, fields);
            if (!parsed)
                std::cout << "Failed to parse tx_extra" << std::endl;

            if (!fields.empty()) {
                print_extra_fields(fields);
            } else {
                std::cout << "No fields were found in tx_extra" << std::endl;
            }
        } else if (
                ((full = cryptonote::parse_tx_extra(
                          std::vector<uint8_t>(blob.begin(), blob.end()), fields)) ||
                 true) &&
                !fields.empty()) {
            std::cout << "Parsed" << (full ? "" : " partial") << " tx_extra:" << std::endl;
            print_extra_fields(fields);
        } else {
            std::cerr << "Not a recognized CN type" << std::endl;
            return 1;
        }
    } else {
        bool addr_decoded = false;
        for (auto nettype : {network_type::MAINNET, network_type::TESTNET, network_type::DEVNET}) {
            cryptonote::address_parse_info addr_info = {};
            if (cryptonote::get_account_address_from_str(
                        addr_info, static_cast<cryptonote::network_type>(nettype), input)) {
                addr_decoded = true;
                cryptonote::account_public_address const& address = addr_info.address;
                fmt::print("Network Type: {}\n", network_type_str(nettype));
                fmt::print("Address: {}\n", input);
                fmt::print("Subaddress: {}\n", addr_info.is_subaddress ? "Yes" : "No");
                if (addr_info.has_payment_id)
                    fmt::print("Payment ID: {}\n", addr_info.payment_id);
                else
                    fmt::print("Payment ID: (none)\n");
                fmt::print("Spend Public Key: {}\n", address.m_spend_public_key);
                fmt::print("View Public Key: {}\n", address.m_view_public_key);
            }
        }

        if (!addr_decoded) {
            std::cerr << "Not a recognized CN type" << std::endl;
            return 1;
        }
    }

    return 0;
}
