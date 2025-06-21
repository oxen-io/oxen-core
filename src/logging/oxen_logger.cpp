#include "oxen_logger.h"

#include <spdlog/sinks/rotating_file_sink.h>

#include <oxen/log.hpp>

#include "common/format.h"
#include "common/string_util.h"

oxen::log::CategoryLogger globallogcat{"global"};

namespace oxen::logging {

using namespace std::literals;

static auto logcat = log::Cat("logging");

void set_additional_log_categories(log::Level log_level) {
    switch (log_level) {
        case log::Level::critical: break;
        case log::Level::err: break;
        case log::Level::warn:
            log::set_level("net", log::Level::err);
            log::set_level("net.http", log::Level::err);
            log::set_level("net.p2p", log::Level::err);
            log::set_level("net.p2p.msg", log::Level::err);
            log::set_level("omq", log::Level::err);
            log::set_level("global", log::Level::info);
            log::set_level("verify", log::Level::err);
            log::set_level("serialization", log::Level::err);
            log::set_level("msgwriter", log::Level::info);
            log::set_level("daemon", log::Level::info);
            log::set_level("miner", log::Level::info);
            log::set_level("l2_proxy", log::Level::info);
            break;
        case log::Level::info:
            log::set_level("net", log::Level::err);
            log::set_level("net.http", log::Level::err);
            log::set_level("net.p2p", log::Level::err);
            log::set_level("net.p2p.msg", log::Level::err);
            log::set_level("omq", log::Level::warn);
            log::set_level("verify", log::Level::err);
            log::set_level("serialization", log::Level::err);
            log::set_level("blockchain", log::Level::warn);
            log::set_level("blockchain.db.lmdb", log::Level::warn);
            log::set_level("service_nodes", log::Level::warn);
            log::set_level("txpool", log::Level::warn);
            log::set_level("construct_tx", log::Level::warn);
            log::set_level("pulse", log::Level::warn);
            break;
        case log::Level::debug: break;
        case log::Level::trace: break;
        default: break;
    }
}

using strlvl = std::pair<std::string_view, log::Level>;
static constexpr std::array extra_levels = {
        strlvl{"4"sv, log::Level::trace},
        strlvl{"3"sv, log::Level::trace},
        strlvl{"2"sv, log::Level::debug},
        strlvl{"1"sv, log::Level::info},
        strlvl{"0"sv, log::Level::warn},
        strlvl{"trc"sv, log::Level::trace},
        strlvl{"dbg"sv, log::Level::debug},
        strlvl{"inf"sv, log::Level::info},
        strlvl{"wrn"sv, log::Level::warn},
        strlvl{"crt"sv, log::Level::critical},
};

static int add_compat_levels() {
    for (auto& [s, l] : extra_levels)
        log::add_level_compat_string(std::string{s}, l);
    return 42;  // Dummy value just to have a return value for static initialization
}
static int compat_levels = add_compat_levels();

void apply_categories_string(std::string_view categories) {
    log::extract_categories(categories).apply(set_additional_log_categories);
}

void init(const std::string& log_location, std::string_view log_levels, bool log_to_stdout) {
    auto cats = log::extract_categories(log_levels);
    if (cats.empty() && !log_levels.empty()) {
        std::cerr << "Invalid log level string: " << log_levels << std::endl;
        throw std::runtime_error{
                "Invalid log level or log categories string: {}"_format(log_levels)};
    }
    if (!cats.default_level)
        cats.default_level = log::Level::warn;

    cats.apply(set_additional_log_categories);
    if (log_to_stdout)
        log::add_sink(log::Type::Print, "stdout");
    if (!log_location.empty())
        set_file_sink(log_location);
}

void set_file_sink(const std::string& log_location) {
    constexpr size_t LOG_FILE_SIZE_LIMIT = 1024 * 1024 * 50;  // 50MiB
    constexpr size_t EXTRA_FILES = 1;

    // setting this to `true` can be useful for debugging on testnet
    bool rotate_on_open = false;

    try {
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                log_location, LOG_FILE_SIZE_LIMIT, EXTRA_FILES, rotate_on_open);

        log::add_sink(std::move(file_sink));
    } catch (const spdlog::spdlog_ex& ex) {
        log::error(
                logcat,
                "Failed to open {} for logging: {}.  File logging disabled.",
                log_location,
                ex.what());
        return;
    }

    log::info(logcat, "Writing logs to {}", log_location);
}

log::Level parse_level(uint8_t input) {
    switch (input) {
        case 0: return log::Level::warn;
        case 1: return log::Level::info;
        case 2: return log::Level::debug;
        default: return log::Level::trace;
    }
}

log::Level parse_level(oxenmq::LogLevel input) {
    switch (input) {
        case oxenmq::LogLevel::trace: return log::Level::trace;
        case oxenmq::LogLevel::debug: return log::Level::debug;
        case oxenmq::LogLevel::info: return log::Level::info;
        case oxenmq::LogLevel::warn: return log::Level::warn;
        case oxenmq::LogLevel::error: return log::Level::err;
        case oxenmq::LogLevel::fatal: return log::Level::critical;
    }
    return log::Level::trace;
}

}  // namespace oxen::logging
