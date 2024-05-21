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
#include "wallet/wallet_args.h"

#include <fmt/std.h>

#include <fstream>
#include <sstream>

#include "common/file.h"
#include "common/i18n.h"
#include "common/util.h"
#include "epee/misc_log_ex.h"
#include "epee/string_tools.h"
#include "logging/oxen_logger.h"
#include "version.h"

#if defined(WIN32)
#include <crtdbg.h>
#endif

// workaround for a suspected bug in pthread/kernel on MacOS X
#ifdef __APPLE__
#define DEFAULT_MAX_CONCURRENCY 1
#else
#define DEFAULT_MAX_CONCURRENCY 0
#endif

namespace wallet_args {

namespace log = oxen::log;

static auto logcat = log::Cat("wallet.wallet2");

// Create on-demand to prevent static initialization order fiasco issues.
command_line::arg_descriptor<std::string> arg_generate_from_json() {
    return {"generate-from-json", wallet_args::tr("Generate wallet from JSON format file"), ""};
}
command_line::arg_descriptor<std::string> arg_wallet_file() {
    return {"wallet-file", wallet_args::tr("Use wallet <arg>"), ""};
}

const char* tr(const char* str) {
    return i18n_translate(str, "wallet_args");
}

std::pair<std::optional<boost::program_options::variables_map>, bool> main(
        int argc,
        char** argv,
        const char* const usage,
        const char* const notice,
        boost::program_options::options_description desc_params,
        boost::program_options::options_description hidden_params,
        const boost::program_options::positional_options_description& positional_options,
        const std::function<void(const std::string&)>& print,
        const char* default_log_name,
        bool log_to_console)

{
    namespace po = boost::program_options;
#ifdef WIN32
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

    const command_line::arg_descriptor<std::string> arg_log_level = {
            "log-level", "0-4 or categories", "warning"};
    const command_line::arg_descriptor<std::size_t> arg_max_log_file_size = {
            "max-log-file-size", "Specify maximum log file size [B]", 50};
    const command_line::arg_descriptor<std::size_t> arg_max_log_files = {
            "max-log-files",
            "Specify maximum number of rotated log files to be saved (no limit by setting to 0)",
            50};
    const command_line::arg_descriptor<uint32_t> arg_max_concurrency = {
            "max-concurrency",
            wallet_args::tr("Max number of threads to use for a parallel job"),
            DEFAULT_MAX_CONCURRENCY};
    const command_line::arg_descriptor<std::string> arg_log_file = {
            "log-file", wallet_args::tr("Specify log file"), ""};
    const command_line::arg_descriptor<std::string> arg_config_file = {
            "config-file", wallet_args::tr("Config file"), "", true};

    std::string lang = i18n_get_language();
    tools::on_startup();
#ifdef NDEBUG
    tools::disable_core_dumps();
#endif
    tools::set_strict_default_file_permissions(true);

    epee::string_tools::set_module_name_and_folder(argv[0]);

    po::options_description desc_general(wallet_args::tr("General options"));
    command_line::add_arg(desc_general, command_line::arg_help);
    command_line::add_arg(desc_general, command_line::arg_version);

    command_line::add_arg(desc_params, arg_log_file);
    command_line::add_arg(desc_params, arg_log_level);
    command_line::add_arg(desc_params, arg_max_log_file_size);
    command_line::add_arg(desc_params, arg_max_log_files);
    command_line::add_arg(desc_params, arg_max_concurrency);
    command_line::add_arg(desc_params, arg_config_file);

    i18n_set_language("translations", "oxen", lang);

    po::options_description desc_all, desc_visible;
    desc_visible.add(desc_general).add(desc_params);
    desc_all.add(desc_visible).add(hidden_params);
    po::variables_map vm;
    bool should_terminate = false;
    bool r = command_line::handle_error_helper(desc_visible, [&]() {
        auto parser = po::command_line_parser(argc, argv)
                              .options(desc_all)
                              .positional(positional_options);
        po::store(parser.run(), vm);

        bool help = command_line::get_arg(vm, command_line::arg_help);
        bool version = command_line::get_arg(vm, command_line::arg_version);
        if (help or version) {
            print("Oxen '{}' (v{})\n"_format(OXEN_RELEASE_NAME, OXEN_VERSION_FULL));

            if (help) {
                print(
                        "{}\n"_format(wallet_args::tr("This is the command line oxen wallet. It "
                                                      "needs to connect to a oxen\n"
                                                      "daemon to work correctly.")));
                print("{}\n  {}"_format(wallet_args::tr("Usage:"), usage));

                // Yuck.  Need to replace boost::po.
                std::ostringstream s;
                s << desc_visible;
                print(s.str());
            }

            should_terminate = true;
            return true;
        }

        if (command_line::has_arg(vm, arg_config_file)) {
            fs::path config{tools::convert_sv<char8_t>(command_line::get_arg(vm, arg_config_file))};
            if (std::error_code ec; fs::exists(config, ec)) {
                std::ifstream cfg{config};
                if (!cfg.is_open())
                    throw std::runtime_error{"Unable to open config file: {}"_format(config)};
                po::store(po::parse_config_file<char>(cfg, desc_params), vm);
            } else {
                log::error(logcat, "{}{}", wallet_args::tr("Can't find config file "), config);
                return false;
            }
        }

        po::notify(vm);
        return true;
    });
    if (!r)
        return {std::nullopt, true};

    if (should_terminate)
        return {std::move(vm), should_terminate};

    std::string log_path;
    if (!command_line::is_arg_defaulted(vm, arg_log_file))
        log_path = command_line::get_arg(vm, arg_log_file);
    else
        log_path = epee::string_tools::get_current_module_name() + ".log";
    log::Level log_level;
    if (auto level = oxen::logging::parse_level(command_line::get_arg(vm, arg_log_level).c_str())) {
        log_level = *level;
    } else {
        std::cerr << "Incorrect log level: " << command_line::get_arg(vm, arg_log_level).c_str()
                  << std::endl;
        throw std::runtime_error{"Incorrect log level"};
    }

    oxen::logging::init(log_path, log_level, false /*do not log to stdout.*/);

    if (notice)
        print("{}\n"_format(notice));

    if (!command_line::is_arg_defaulted(vm, arg_max_concurrency))
        tools::set_max_concurrency(command_line::get_arg(vm, arg_max_concurrency));

    print("Oxen '{}' (v{})\n"_format(OXEN_RELEASE_NAME, OXEN_VERSION_FULL));

    if (!command_line::is_arg_defaulted(vm, arg_log_level))
        log::info(logcat, "Setting log level = {}", command_line::get_arg(vm, arg_log_level));
    else {
        const char* logs = getenv("OXEN_LOGS");
        log::info(logcat, "Setting log levels = {}", (logs ? logs : "<default>"));
    }
    print("{}{}"_format(tr("Logging to: "), log_path));

    const ssize_t lockable_memory = tools::get_lockable_memory();
    if (lockable_memory >= 0 &&
        lockable_memory < 256 * 4096)  // 256 pages -> at least 256 secret keys and other such
                                       // small/medium objects
        print(tr("WARNING: You may not have a high enough lockable memory limit")
#ifdef ELPP_OS_UNIX
              + ", "s + tr("see ulimit -l")
#endif
        );

    return {std::move(vm), should_terminate};
}
}  // namespace wallet_args
