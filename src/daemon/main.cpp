// Copyright (c) 2014-2020, The Monero Project
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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <cstdlib>
#include <cpptrace/cpptrace.hpp>

#include "command_server.h"
#include "common/command_line.h"
#include "common/fs.h"
#include "common/password.h"
#include "common/scoped_message_writer.h"
#include "common/util.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_core.h"
#include "daemon.h"
#include "daemon/command_line_args.h"
#include "daemonizer/daemonizer.h"
#include "epee/misc_log_ex.h"
#include "logging/oxen_logger.h"
#include "p2p/net_node.h"
#include "rpc/common/rpc_args.h"
#include "rpc/core_rpc_server.h"
#include "version.h"


namespace po = boost::program_options;

namespace Log = oxen::log;  // capital Log to avoid conflict with math.h log()

using namespace std::literals;

namespace {

auto logcat = Log::Cat("daemon");

// Some ANSI color sequences that we use here (before the log system is initialized):
constexpr auto RESET = "\033[0m";
constexpr auto RED = "\033[31;1m";
constexpr auto YELLOW = "\033[33;1m";
constexpr auto CYAN = "\033[36;1m";
}  // namespace

int main(int argc, char const* argv[]) {
    cpptrace::register_terminate_handler();
    bool logs_initialized = false;
    try {
        // TODO parse the debug options like set log level right here at start

        tools::on_startup();

        epee::string_tools::set_module_name_and_folder(argv[0]);

        auto opt_size = command_line::boost_option_sizes();

        // Build argument description
        po::options_description all_options("All", opt_size.first, opt_size.second);
        po::options_description hidden_options("Hidden");
        po::options_description visible_options("Options", opt_size.first, opt_size.second);
        po::options_description core_settings("Settings", opt_size.first, opt_size.second);
        po::positional_options_description positional_options;
        {
            // Misc Options

            command_line::add_arg(visible_options, command_line::arg_help);
            command_line::add_arg(visible_options, command_line::arg_version);
            command_line::add_arg(visible_options, daemon_args::arg_config_file);

            // Settings
            command_line::add_arg(core_settings, daemon_args::arg_log_file);
            command_line::add_arg(core_settings, daemon_args::arg_log_level);
            command_line::add_arg(core_settings, daemon_args::arg_max_log_file_size);
            command_line::add_arg(core_settings, daemon_args::arg_max_log_files);
            command_line::add_arg(core_settings, daemon_args::arg_max_concurrency);

            daemonizer::init_options(hidden_options, visible_options);
            daemonize::daemon::init_options(core_settings, hidden_options);

            // Hidden options
            command_line::add_arg(hidden_options, daemon_args::arg_command);

            visible_options.add(core_settings);
            all_options.add(visible_options);
            all_options.add(hidden_options);

            // Positional
            positional_options.add(
                    daemon_args::arg_command.name, -1);  // -1 for unlimited arguments
        }

        // Do command line parsing
        po::variables_map vm;
        bool ok = command_line::handle_error_helper(visible_options, [&]() {
            boost::program_options::store(
                    boost::program_options::command_line_parser(argc, argv)
                            .options(all_options)
                            .positional(positional_options)
                            .run(),
                    vm);

            return true;
        });
        if (!ok)
            return 1;

        if (command_line::get_arg(vm, command_line::arg_help)) {
            std::cout << CYAN << "Oxen '" << OXEN_RELEASE_NAME << "' (v" << OXEN_VERSION_FULL << ")"
                      << RESET << "\n\n";
            std::cout << "Usage: " + std::string{argv[0]} +
                                 " [options|settings] [daemon_command...]"
                      << std::endl
                      << std::endl;
            std::cout << visible_options << std::endl;
            return 0;
        }

        // Oxen Version
        if (command_line::get_arg(vm, command_line::arg_version)) {
            std::cout << CYAN << "Oxen '" << OXEN_RELEASE_NAME << "' (v" << OXEN_VERSION_FULL << ")"
                      << RESET << "\n\n";
            return 0;
        }

        std::optional<fs::path> load_config;

        if (command_line::is_arg_defaulted(vm, daemon_args::arg_config_file)) {
            // We are using the default config file, which will be in the data directory, as
            // determined *only* by the command-line arguments but *not* config file arguments,
            // unlike pretty much all other command line options (where we load from both, with cli
            // options taking precendence).  Thus it's possible that the data-dir isn't specified on
            // the command-line which means *for the purpose of loading the config file* that we use
            // `~/.oxen`, but that after we load the config file it could be something else.  (In
            // such an edge case, we simply ignore a <final-data-dir>/oxen.conf).
            auto data_dir = fs::absolute(
                    tools::utf8_path(command_line::get_arg(vm, cryptonote::arg_data_dir)));

            // --regtest should append a /regtest to the data-dir, but this is done here rather than
            // in the defaults because this is a dev-only option that we don't really want the user
            // to need to worry about.
            if (command_line::get_arg(vm, cryptonote::arg_regtest_on))
                data_dir /= "regtest";

            // We also have to worry about migrating loki.conf -> oxen.conf *and* about a potential
            // ~/.loki -> ~/.oxen migration, so build a list of possible options along with whether
            // we want to rename if we find one (the data-dir migration happens later):
            std::list<std::pair<fs::path, bool>> potential;
            if (std::error_code ec; fs::exists(data_dir, ec)) {
                potential.emplace_back(data_dir / cryptonote::CONF_FILENAME, false);
                potential.emplace_back(data_dir / cryptonote::old::CONF_FILENAME, true);
            } else if (command_line::is_arg_defaulted(vm, cryptonote::arg_data_dir)) {
                // If we weren't given an explict command-line data-dir then we also need to check
                // the legacy data directory.  (We will rename it, later, but we have to check it
                // *first* because it might have a data-dir inside it that affects the data dir
                // rename logic).
                auto old_data_dir = tools::get_depreciated_default_data_dir();
                // If we *have* a --testnet or --devnet arg then we can use it, but it's possible
                // that the config file itself will set and change that, which is why we retrieve
                // those arguments again later, after parsing the config.
                if (command_line::get_arg(vm, cryptonote::arg_testnet_on))
                    old_data_dir /= "testnet";
                else if (command_line::get_arg(vm, cryptonote::arg_devnet_on))
                    old_data_dir /= "devnet";
                else if (command_line::get_arg(vm, cryptonote::arg_regtest_on))
                    old_data_dir /= "regtest";

                potential.emplace_back(old_data_dir / cryptonote::CONF_FILENAME, false);
                potential.emplace_back(old_data_dir / cryptonote::old::CONF_FILENAME, true);
            }
            for (auto& [conf, rename] : potential) {
                if (std::error_code ec; fs::exists(conf, ec)) {
                    if (rename) {
                        fs::path renamed = conf;
                        renamed.replace_filename(cryptonote::CONF_FILENAME);
                        assert(renamed != conf);
                        if (fs::rename(conf, renamed, ec); ec) {
                            std::cerr << RED << "Failed to migrate " << conf << " -> " << renamed
                                      << ": " << ec.message() << RESET << "\n";
                            return 1;
                        }
                        if (fs::create_symlink(renamed.filename(), conf, ec); ec) {
                            std::cerr << YELLOW << "Failed to create post-migration " << conf
                                      << " -> " << renamed << " symlink: " << ec.message() << RESET
                                      << "\n";
                            // Continue anyway as this isn't fatal
                        }
                        std::cerr << CYAN << "Renamed " << conf << " -> " << renamed << RESET
                                  << "\n";
                        load_config = std::move(renamed);
                    } else {
                        load_config = std::move(conf);
                    }
                    break;
                }
            }
        } else {
            // config file explicitly given, no migration
            load_config = tools::utf8_path(command_line::get_arg(vm, daemon_args::arg_config_file));
            if (std::error_code ec; !fs::exists(*load_config, ec)) {
                std::cerr << RED << "Can't find config file " << *load_config << RESET << "\n";
                return 1;
            }
        }

        if (load_config) {
            try {
                std::ifstream cfg{*load_config};
                if (!cfg.is_open())
                    throw cpptrace::runtime_error{"Unable to open file"};
                po::store(
                        po::parse_config_file<char>(
                                cfg,
                                po::options_description{}.add(core_settings).add(hidden_options)),
                        vm);
            } catch (const std::exception& e) {
                std::cerr << RED << "Error parsing config file: " << e.what() << RESET << "\n";
                return 1;
            }
        }

        const bool testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
        const bool devnet = command_line::get_arg(vm, cryptonote::arg_devnet_on);
        const bool regtest = command_line::get_arg(vm, cryptonote::arg_regtest_on);
        if (testnet + devnet + regtest > 1) {
            std::cerr << RED
                      << "Can't specify more than one of --testnet and --devnet and --regtest"
                      << RESET << "\n";
            return 1;
        }

        // data_dir
        //   default: e.g. ~/.oxen/ or ~/.oxen/testnet
        //   if data-dir argument given:
        //     absolute path
        //     relative path: relative to cwd

        // Create data dir if it doesn't exist
        auto data_dir =
                fs::absolute(tools::utf8_path(command_line::get_arg(vm, cryptonote::arg_data_dir)));

        // --regtest should append a /regtest to the data-dir, but this is done here rather than in
        // the defaults because this is a dev-only option that we don't really want the user to need
        // to worry about.
        if (command_line::get_arg(vm, cryptonote::arg_regtest_on))
            data_dir /= "regtest";

        // Will check if the default data directory is used and if it exists.
        // Then will ensure that migration from the old data directory (.loki) has occurred if it
        // exists.
        if (command_line::is_arg_defaulted(vm, cryptonote::arg_data_dir) && !fs::exists(data_dir)) {
            auto old_data_dir = tools::get_depreciated_default_data_dir();
            if (testnet)
                old_data_dir /= "testnet";
            else if (devnet)
                old_data_dir /= "devnet";
            else if (regtest)
                old_data_dir /= "regtest";

            if (fs::is_directory(old_data_dir)) {
                std::error_code ec;
                if (fs::create_directories(data_dir.parent_path(), ec); ec) {
                    std::cerr << RED << "Data directory migration failed: cannot create "
                              << data_dir.parent_path() << ": " << ec.message() << RESET << "\n";
                    return 1;
                }
                if (fs::rename(old_data_dir, data_dir, ec); ec) {
                    std::cerr << RED << "Data directory migrate failed: could not rename "
                              << old_data_dir << " to " << data_dir << ": " << ec.message() << RESET
                              << "\n";
                    return 1;
                }
                if (fs::create_directory_symlink(data_dir, old_data_dir, ec); ec)
                    std::cerr << YELLOW << "Failed to create " << old_data_dir << " -> " << data_dir
                              << " symlink" << RESET << "\n";
                std::cerr << CYAN << "Migrated data directory from " << old_data_dir << " to "
                          << data_dir << RESET << "\n";
            }
        }

        // Create the data directory; we have to do this before initializing the logs because the
        // log likely goes inside the data dir.
        if (std::error_code ec; !fs::create_directories(data_dir, ec) && ec)
            std::cerr << YELLOW << "Failed to create data directory " << data_dir << ": "
                      << ec.message() << RESET << "\n";

        po::notify(vm);

        // log_file_path
        //   default: <data_dir>/oxen.log
        //   if log-file argument given:
        //     absolute path
        //     relative path: relative to data_dir
        Log::Level log_level;
        if (auto level = oxen::logging::parse_level(
                    command_line::get_arg(vm, daemon_args::arg_log_level).c_str())) {
            log_level = *level;
        } else {
            std::cerr << "Incorrect log level: "
                      << command_line::get_arg(vm, daemon_args::arg_log_level).c_str() << std::endl;
            throw cpptrace::runtime_error{"Incorrect log level"};
        }
        auto log_file_path = data_dir / cryptonote::LOG_FILENAME;
        if (!command_line::is_arg_defaulted(vm, daemon_args::arg_log_file))
            log_file_path = command_line::get_arg(vm, daemon_args::arg_log_file);
        if (log_file_path.is_relative())
            log_file_path = fs::absolute(data_dir / log_file_path);

        oxen::logging::init(log_file_path.string(), log_level);

        logs_initialized = true;

        if (!command_line::is_arg_defaulted(vm, daemon_args::arg_max_concurrency))
            tools::set_max_concurrency(command_line::get_arg(vm, daemon_args::arg_max_concurrency));

        // logging is now set up
        // FIXME: only print this when starting up as a daemon but not when running rpc commands
        Log::info(logcat, "Oxen '{}' (v{})", OXEN_RELEASE_NAME, OXEN_VERSION_FULL);

        // If there are positional options, we're running a daemon command
        {
            auto command = command_line::get_arg(vm, daemon_args::arg_command);

            if (command.size()) {
                auto rpc_config = cryptonote::rpc_args::process(vm);
                std::string rpc_addr;
                // TODO: remove this in oxen 9.x and only use rpc-admin
                if (!is_arg_defaulted(vm, cryptonote::rpc::http_server::arg_rpc_bind_port) ||
                    rpc_config.bind_ip.has_value()) {
                    auto rpc_port = command_line::get_arg(
                            vm, cryptonote::rpc::http_server::arg_rpc_bind_port);
                    if (rpc_port == 0)
                        rpc_port = command_line::get_arg(vm, cryptonote::arg_testnet_on)
                                         ? cryptonote::config::testnet::RPC_DEFAULT_PORT
                                 : command_line::get_arg(vm, cryptonote::arg_devnet_on)
                                         ? cryptonote::config::devnet::RPC_DEFAULT_PORT
                                         : cryptonote::config::RPC_DEFAULT_PORT;
                    rpc_addr = rpc_config.bind_ip.value_or("127.0.0.1") + ":" +
                               std::to_string(rpc_port);
                } else {
                    rpc_addr = command_line::get_arg(
                            vm, cryptonote::rpc::http_server::arg_rpc_admin)[0];
                    if (rpc_addr == "none")
                        throw cpptrace::runtime_error{
                                "Cannot invoke oxend command: --rpc-admin is disabled"};
                }

                {
                    // Throws if invalid:
                    auto [ip, port] = daemonize::parse_ip_port(rpc_addr, "--rpc-admin");
                    rpc_addr = "http://"s +
                               (ip.find(':') != std::string::npos ? "[" + ip + "]" : ip) + ":" +
                               std::to_string(port);
                }

                daemonize::command_server rpc_commands{rpc_addr, rpc_config.login};
                return rpc_commands.process_command_and_log(command) ? 0 : 1;
            }
        }

        Log::info(logcat, "Moving from main() into the daemonize now.");

        return daemonizer::daemonize<daemonize::daemon>("Oxen Daemon", argc, argv, std::move(vm))
                     ? 0
                     : 1;
    } catch (std::exception const& ex) {
        if (logs_initialized)
            Log::error(logcat, "Exception in main! {}", ex.what());
        else
            std::cerr << RED << "Exception in main! " << ex.what() << RESET << "\n";
    } catch (...) {
        if (logs_initialized)
            Log::error(logcat, "Exception in main! (unknown exception type)");
        else
            std::cerr << RED << "Exception in main! (unknown exception type)" << RESET << "\n";
    }
    return 1;
}
