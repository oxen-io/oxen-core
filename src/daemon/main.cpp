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
#include "cryptonote_core/cryptonote_core.h"
#include "daemonizer/daemonizer.h"
#include "misc_log_ex.h"
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
namespace bf = boost::filesystem;

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
      daemonize::daemon::init_options(core_settings);

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

    std::string config = command_line::get_arg(vm, daemon_args::arg_config_file);
    boost::filesystem::path config_path(config);
    boost::system::error_code ec;
    if (bf::exists(config_path, ec))
    {
      try
      {
        po::store(po::parse_config_file<char>(config_path.string<std::string>().c_str(), core_settings), vm);
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
    const bool stagenet = command_line::get_arg(vm, cryptonote::arg_stagenet_on);
    const bool regtest = command_line::get_arg(vm, cryptonote::arg_regtest_on);
    if (testnet + stagenet + regtest > 1)
    {
      std::cerr << "Can't specify more than one of --tesnet and --stagenet and --regtest\n";
      return 1;
    }

    // data_dir
    //   default: e.g. ~/.loki/ or ~/.loki/testnet
    //   if data-dir argument given:
    //     absolute path
    //     relative path: relative to cwd

    // Create data dir if it doesn't exist
    boost::filesystem::path data_dir = boost::filesystem::absolute(
        command_line::get_arg(vm, cryptonote::arg_data_dir));

    // FIXME: not sure on windows implementation default, needs further review
    //bf::path relative_path_base = daemonizer::get_relative_path_base(vm);
    bf::path relative_path_base = data_dir;

    po::notify(vm);

    // log_file_path
    //   default: <data_dir>/<CRYPTONOTE_NAME>.log
    //   if log-file argument given:
    //     absolute path
    //     relative path: relative to data_dir
    bf::path log_file_path {data_dir / std::string(CRYPTONOTE_NAME ".log")};
    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_log_file))
      log_file_path = command_line::get_arg(vm, daemon_args::arg_log_file);
    if (!log_file_path.has_parent_path())
      log_file_path = bf::absolute(log_file_path, relative_path_base);
    mlog_configure(log_file_path.string(), true, command_line::get_arg(vm, daemon_args::arg_max_log_file_size), command_line::get_arg(vm, daemon_args::arg_max_log_files));

    // Set log level
    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_log_level))
    {
      mlog_set_log(command_line::get_arg(vm, daemon_args::arg_log_level).c_str());
    }

    // after logs initialized
    tools::create_directories_if_necessary(data_dir.string());

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
        const cryptonote::rpc_args::descriptors arg{};
        auto rpc_ip_str = command_line::get_arg(vm, arg.rpc_bind_ip);
        auto rpc_port = command_line::get_arg(vm, cryptonote::rpc::http_server::arg_rpc_bind_port);

        uint32_t rpc_ip;
        if (!epee::string_tools::get_ip_int32_from_string(rpc_ip, rpc_ip_str))
        {
          std::cerr << "Invalid IP: " << rpc_ip_str << std::endl;
          return 1;
        }

        const char *env_rpc_login = nullptr;
        const bool has_rpc_arg = command_line::has_arg(vm, arg.rpc_login);
        const bool use_rpc_env = !has_rpc_arg && (env_rpc_login = getenv("RPC_LOGIN")) != nullptr && strlen(env_rpc_login) > 0;
        std::optional<tools::login> login{};
        if (has_rpc_arg || use_rpc_env)
        {
          login = tools::login::parse(
            has_rpc_arg ? command_line::get_arg(vm, arg.rpc_login) : std::string(env_rpc_login), false, [](bool verify) {
              rdln::suspend_readline pause_readline;
              return tools::password_container::prompt(verify, "Daemon client password");
            }
          );
          if (!login)
          {
            std::cerr << "Failed to obtain password" << std::endl;
            return 1;
          }
        }

        daemonize::command_server rpc_commands{rpc_ip, rpc_port, std::move(login)};
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
