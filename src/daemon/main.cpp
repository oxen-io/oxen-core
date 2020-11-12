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
#include "common/command_line.h"
#include "common/scoped_message_writer.h"
#include "common/password.h"
#include "common/util.h"
#include "common/fs.h"
#include "cryptonote_core/cryptonote_core.h"
#include "daemonizer/daemonizer.h"
#include "epee/misc_log_ex.h"
#include "p2p/net_node.h"
#include "rpc/rpc_args.h"
#include "rpc/core_rpc_server.h"
#include "daemon/command_line_args.h"
#include "version.h"

#include "command_server.h"
#include "daemon.h"

#ifdef STACK_TRACE
#include "common/stack_trace.h"
#endif // STACK_TRACE

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "daemon"

namespace po = boost::program_options;

using namespace std::literals;

int main(int argc, char const * argv[])
{
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
      positional_options.add(daemon_args::arg_command.name, -1); // -1 for unlimited arguments
    }

    // Do command line parsing
    po::variables_map vm;
    bool ok = command_line::handle_error_helper(visible_options, [&]()
    {
      boost::program_options::store(
        boost::program_options::command_line_parser(argc, argv)
          .options(all_options).positional(positional_options).run()
      , vm
      );

      return true;
    });
    if (!ok) return 1;

    if (command_line::get_arg(vm, command_line::arg_help))
    {
      std::cout << "Loki '" << LOKI_RELEASE_NAME << "' (v" << LOKI_VERSION_FULL << ")\n\n";
      std::cout << "Usage: " + std::string{argv[0]} + " [options|settings] [daemon_command...]" << std::endl << std::endl;
      std::cout << visible_options << std::endl;
      return 0;
    }

    // Loki Version
    if (command_line::get_arg(vm, command_line::arg_version))
    {
      std::cout << "Loki '" << LOKI_RELEASE_NAME << "' (v" << LOKI_VERSION_FULL << ")\n\n";
      return 0;
    }

    auto config = fs::u8path(command_line::get_arg(vm, daemon_args::arg_config_file));
    if (std::error_code ec; fs::exists(config, ec))
    {
      try
      {
        fs::ifstream cfg{config};
        if (!cfg.is_open())
          throw std::runtime_error{"Unable to open file"};
        po::store(po::parse_config_file<char>(
                    cfg,
                    po::options_description{}.add(core_settings).add(hidden_options)),
                vm);
      }
      catch (const std::exception &e)
      {
        // log system isn't initialized yet
        std::cerr << "Error parsing config file: " << e.what() << std::endl;
        throw;
      }
    }
    else if (!command_line::is_arg_defaulted(vm, daemon_args::arg_config_file))
    {
      std::cerr << "Can't find config file " << config << std::endl;
      return 1;
    }

    const bool testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
    const bool devnet = command_line::get_arg(vm, cryptonote::arg_devnet_on);
    const bool regtest = command_line::get_arg(vm, cryptonote::arg_regtest_on);
    if (testnet + devnet + regtest > 1)
    {
      std::cerr << "Can't specify more than one of --testnet and --devnet and --regtest\n";
      return 1;
    }

    // data_dir
    //   default: e.g. ~/.loki/ or ~/.loki/testnet
    //   if data-dir argument given:
    //     absolute path
    //     relative path: relative to cwd

    // Create data dir if it doesn't exist
    auto data_dir = fs::absolute(fs::u8path(command_line::get_arg(vm, cryptonote::arg_data_dir)));

    // FIXME: not sure on windows implementation default, needs further review
    //fs::path relative_path_base = daemonizer::get_relative_path_base(vm);
    fs::path relative_path_base = data_dir;

    po::notify(vm);

    // log_file_path
    //   default: <data_dir>/<CRYPTONOTE_NAME>.log
    //   if log-file argument given:
    //     absolute path
    //     relative path: relative to data_dir
    auto log_file_path = data_dir / CRYPTONOTE_NAME ".log";
    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_log_file))
      log_file_path = command_line::get_arg(vm, daemon_args::arg_log_file);
    if (log_file_path.is_relative())
      log_file_path = fs::absolute(fs::relative(log_file_path, relative_path_base));
    mlog_configure(log_file_path.string(), true, command_line::get_arg(vm, daemon_args::arg_max_log_file_size), command_line::get_arg(vm, daemon_args::arg_max_log_files));

    // Set log level
    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_log_level))
    {
      mlog_set_log(command_line::get_arg(vm, daemon_args::arg_log_level).c_str());
    }

    // after logs initialized
    tools::create_directories_if_necessary(data_dir);

#ifdef STACK_TRACE
    tools::set_stack_trace_log(log_file_path.filename().string());
#endif // STACK_TRACE

    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_max_concurrency))
      tools::set_max_concurrency(command_line::get_arg(vm, daemon_args::arg_max_concurrency));

    // logging is now set up
    // FIXME: only print this when starting up as a daemon but not when running rpc commands
    MGINFO_GREEN("Loki '" << LOKI_RELEASE_NAME << "' (v" << LOKI_VERSION_FULL << ")");

    // If there are positional options, we're running a daemon command
    {
      auto command = command_line::get_arg(vm, daemon_args::arg_command);

      if (command.size())
      {
        auto rpc_config = cryptonote::rpc_args::process(vm);
        std::string rpc_addr;
        // TODO: remove this in loki 9.x and only use rpc-admin
        if (!is_arg_defaulted(vm, cryptonote::rpc::http_server::arg_rpc_bind_port) ||
            rpc_config.bind_ip.has_value()) {
          auto rpc_port = command_line::get_arg(vm, cryptonote::rpc::http_server::arg_rpc_bind_port);
          if (rpc_port == 0)
            rpc_port =
              command_line::get_arg(vm, cryptonote::arg_testnet_on) ? config::testnet::RPC_DEFAULT_PORT :
              command_line::get_arg(vm, cryptonote::arg_devnet_on) ? config::devnet::RPC_DEFAULT_PORT :
              config::RPC_DEFAULT_PORT;
          rpc_addr = rpc_config.bind_ip.value_or("127.0.0.1") + ":" + std::to_string(rpc_port);
        } else {
          rpc_addr = command_line::get_arg(vm, cryptonote::rpc::http_server::arg_rpc_admin)[0];
          if (rpc_addr == "none")
            throw std::runtime_error{"Cannot invoke lokid command: --rpc-admin is disabled"};
        }

        {
          // Throws if invalid:
          auto [ip, port] = daemonize::parse_ip_port(rpc_addr, "--rpc-admin");
          rpc_addr = "http://"s + (ip.find(':') != std::string::npos ? "[" + ip + "]" : ip) + ":" + std::to_string(port);
        }

        daemonize::command_server rpc_commands{rpc_addr, rpc_config.login};
        return rpc_commands.process_command_and_log(command) ? 0 : 1;
      }
    }

    MINFO("Moving from main() into the daemonize now.");

    return daemonizer::daemonize<daemonize::daemon>("Loki Daemon", argc, argv, std::move(vm))
        ? 0 : 1;
  }
  catch (std::exception const & ex)
  {
    LOG_ERROR("Exception in main! " << ex.what());
  }
  catch (...)
  {
    LOG_ERROR("Exception in main!");
  }
  return 1;
}
