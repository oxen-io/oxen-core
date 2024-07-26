#include "oxen_logger.h"

#include <spdlog/sinks/rotating_file_sink.h>

#include <oxen/log.hpp>

#include "common/format.h"
#include "common/string_util.h"

oxen::log::CategoryLogger globallogcat{"global"};

namespace oxen::logging {

using namespace std::literals;

static auto logcat = log::Cat("logging");

void set_additional_log_categories(log::Level& log_level) {
    switch (log_level) {
        case log::Level::critical: break;
        case log::Level::err: break;
        case log::Level::warn:
            log::set_level("net", log::Level::err);
            log::set_level("net.http", log::Level::err);
            log::set_level("net.p2p", log::Level::err);
            log::set_level("net.p2p.msg", log::Level::err);
            log::set_level("global", log::Level::info);
            log::set_level("verify", log::Level::err);
            log::set_level("serialization", log::Level::err);
            log::set_level("msgwriter", log::Level::info);
            log::set_level("daemon", log::Level::info);
            break;
        case log::Level::info:
            log::set_level("net", log::Level::err);
            log::set_level("net.http", log::Level::err);
            log::set_level("net.p2p", log::Level::err);
            log::set_level("net.p2p.msg", log::Level::err);
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

LogCats extract_categories(std::string_view categories) {
    LogCats result;
    for (auto cat : tools::split_any(categories, " ,;", true)) {
        auto pieces = tools::split_any(cat, ":=", true);
        if (pieces.size() < 1 || pieces.size() > 2) {
            log::error(
                    logcat,
                    "Invalid or unparseable log category/level '{}'; expected 'level' or "
                    "'category=level'",
                    cat);
            continue;
        }
        auto lvl = parse_level(pieces.back());
        if (!lvl) {
            log::error(logcat, "Invalid log level '{}' in log input '{}'", pieces.back(), cat);
            continue;
        }
        auto cat_name = pieces.size() == 1 ? "*"sv : pieces.front();

        if (cat_name == "*") {
            result.default_level = *lvl;
            result.cat_levels.clear();
        } else {
            result.cat_levels[std::string{pieces.front()}] = *lvl;
        }
    }

    return result;
}

void apply_categories_string(std::string_view categories) {
    extract_categories(categories).apply();
}

std::list<std::string> LogCats::apply() {
    std::list<std::string> applied;
    if (default_level) {
        log::reset_level(*default_level);
        set_additional_log_categories(*default_level);
        applied.push_back("*={}"_format(log::to_string(*default_level)));
    }

    for (const auto& [cat, lvl] : cat_levels) {
        log::set_level(cat, lvl);
        applied.push_back("{}={}"_format(cat, log::to_string(lvl)));
    }

    if (!applied.empty())
        log::info(logcat, "Applied log categories: {}", fmt::join(applied, ", "));

    return applied;
}

void init(const std::string& log_location, std::string_view log_levels, bool log_to_stdout) {
    auto cats = extract_categories(log_levels);
    if (cats.empty() && !log_levels.empty()) {
        std::cerr << "Incorrect log level string: " << log_levels << std::endl;
        throw std::runtime_error{"Invalid log level or log categories"};
    }
    if (!cats.default_level)
        cats.default_level = log::Level::warn;

    cats.apply();
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

using namespace std::literals;

using strlvl = std::pair<std::string_view, log::Level>;
static constexpr std::array logLevels = {
        strlvl{""sv, log::Level::warn},         strlvl{"4"sv, log::Level::trace},
        strlvl{"3"sv, log::Level::trace},       strlvl{"2"sv, log::Level::debug},
        strlvl{"1"sv, log::Level::info},        strlvl{"0"sv, log::Level::warn},
        strlvl{"trace"sv, log::Level::trace},   strlvl{"trc"sv, log::Level::trace},
        strlvl{"debug"sv, log::Level::debug},   strlvl{"dbg"sv, log::Level::debug},
        strlvl{"info"sv, log::Level::info},     strlvl{"inf"sv, log::Level::info},
        strlvl{"warning"sv, log::Level::warn},  strlvl{"warn"sv, log::Level::warn},
        strlvl{"wrn"sv, log::Level::warn},      strlvl{"error"sv, log::Level::err},
        strlvl{"err"sv, log::Level::err},       strlvl{"critical"sv, log::Level::critical},
        strlvl{"crit"sv, log::Level::critical}, strlvl{"crt"sv, log::Level::critical},
};

std::optional<spdlog::level::level_enum> parse_level(std::string_view input) {

    auto in = tools::lowercase_ascii_string(input);
    for (const auto& [str, lvl] : logLevels)
        if (str == in)
            return lvl;

    return std::nullopt;
}

static constexpr std::array<std::pair<uint8_t, log::Level>, 5> intLogLevels = {
        {{4, log::Level::trace},
         {3, log::Level::trace},
         {2, log::Level::debug},
         {1, log::Level::info},
         {0, log::Level::warn}}};

std::optional<spdlog::level::level_enum> parse_level(uint8_t input) {
    for (const auto& [str, lvl] : intLogLevels)
        if (str == input)
            return lvl;
    return std::nullopt;
}

static constexpr std::array<std::pair<oxenmq::LogLevel, log::Level>, 6> omqLogLevels = {
        {{oxenmq::LogLevel::trace, log::Level::trace},
         {oxenmq::LogLevel::debug, log::Level::debug},
         {oxenmq::LogLevel::info, log::Level::info},
         {oxenmq::LogLevel::warn, log::Level::warn},
         {oxenmq::LogLevel::error, log::Level::err},
         {oxenmq::LogLevel::fatal, log::Level::critical}}};

std::optional<spdlog::level::level_enum> parse_level(oxenmq::LogLevel input) {
    for (const auto& [str, lvl] : omqLogLevels)
        if (str == input)
            return lvl;
    return std::nullopt;
}

}  // namespace oxen::logging
