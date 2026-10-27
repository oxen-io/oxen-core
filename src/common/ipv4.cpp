#include "ipv4.h"

#include <exception>
#include <string>

#include "string_util.h"

namespace tools {

std::optional<oxen::quic::ipv4_range> parse_ipv4_range(std::string_view str, bool allow_bare_ip) {
    uint8_t mask = 32;
    if (auto slash = str.find('/'); slash != std::string_view::npos) {
        if (!parse_int(str.substr(slash + 1), mask) || mask > 32)
            return std::nullopt;
        str = str.substr(0, slash);
    } else if (!allow_bare_ip)
        return std::nullopt;

    try {
        return oxen::quic::ipv4{std::string{str}} / mask;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

}  // namespace tools
