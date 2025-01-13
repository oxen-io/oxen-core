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
void set_additional_log_categories(const log::Level& log_level);
// Takes a string such as "warning, abc=info, quic=debug" and applies it to the logger.  String
// rules:
//
// - Categories can be separated with spaces, commas, or semicolons
// - The category name and the level can be separated with `=` or `:`
// - A bare level can be specified and is equivalent to `*=level`
// - A single `*` as the category resets all existing categories to the given level (and so means
//   that anything before the *, such as 'abc=info, *=warning', has no effect).
// - anything else sets the level of a single category.  (Note that `foo*=debug` is not special: it
//   just sets a literal category 'foo*' to a level of debug, which probably doesn't do anything).
//
// TODO: this would probably be usefully adapted into oxen-logging itself.
void apply_categories_string(std::string_view categories);

// The return value of `extract_categories`: this contains the (possible) default as well as any
// individual log categories specified by a category string.
struct LogCats {
    std::optional<log::Level> default_level;
    std::unordered_map<std::string, log::Level> cat_levels;

    // True if this object contains no parsed levels (either neither a default nor any category
    // levels)
    bool empty() const { return !default_level && cat_levels.empty(); }

    // Applies the settings in the object to the global logger.  Returns the actual setting applied
    // (i.e. not including redundant or unparseable settings).
    std::list<std::string> apply();
};

/// Given a log level string this extracts the default and individual category levels applied by the
/// string, returning them in a LogCats struct.  Only final settings are included (i.e. settings
/// overridden by a later default, or same category occuring again later, are omitted).  This is
/// used internally by apply_categories_string but can also be used directly.
[[nodiscard]] LogCats extract_categories(std::string_view categories);

std::optional<log::Level> parse_level(std::string_view input);
std::optional<log::Level> parse_level(uint8_t input);
std::optional<log::Level> parse_level(oxenmq::LogLevel input);

}  // namespace oxen::logging
