#pragma once

#include <oxenmq/oxenmq.h>

#include <oxen/log.hpp>

#include "oxen/log/catlogger.hpp"

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
namespace eth {
namespace log = oxen::log;
}

extern oxen::log::CategoryLogger globallogcat;

namespace oxen::logging {
void init(const std::string& log_location, std::string_view log_level, bool log_to_stdout = true);
void set_file_sink(const std::string& log_location);
void set_additional_log_categories(log::Level log_level);

// Takes a string such as "warning, abc=info, quic=debug" and applies it to the logger.  See
// oxen::logger for the exact rules of how this works.
void apply_categories_string(std::string_view categories);

log::Level parse_level(uint8_t input);
log::Level parse_level(oxenmq::LogLevel input);

}  // namespace oxen::logging
