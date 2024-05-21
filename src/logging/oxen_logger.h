#pragma once

#include <oxenmq/oxenmq.h>

#include <oxen/log.hpp>

#define OXEN_LOG_ENABLED(LVL) logcat->should_log(spdlog::level::LVL)

// We can't just make a global "log" namespace because it conflicts with global C log()
namespace cryptonote {
namespace log = oxen::log;
}
namespace crypto {
namespace log = oxen::log;
}
namespace tools {
namespace log = oxen::log;
}
namespace service_nodes {
namespace log = oxen::log;
}
namespace nodetool {
namespace log = oxen::log;
}
namespace rct {
namespace log = oxen::log;
}

inline auto globallogcat = oxen::log::Cat("global");

namespace oxen::logging {
void init(const std::string& log_location, log::Level log_level, bool log_to_stdout = true);
void set_file_sink(const std::string& log_location);
void set_additional_log_categories(const log::Level& log_level);
void process_categories_string(const std::string& categories);

std::optional<log::Level> parse_level(std::string input);
std::optional<log::Level> parse_level(uint8_t input);
std::optional<log::Level> parse_level(oxenmq::LogLevel input);

}  // namespace oxen::logging
