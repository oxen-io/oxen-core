#include "systemd.h"

#include <fmt/format.h>

#ifdef ENABLE_SYSTEMD
extern "C" {
#include <systemd/sd-daemon.h>
}
#endif

namespace tools {

void systemd_extend_timeout(std::chrono::seconds more, std::string_view status) {
#ifdef ENABLE_SYSTEMD
    sd_notify(
            0,
            fmt::format(
                    "EXTEND_TIMEOUT_USEC={}\nSTATUS={}",
                    std::chrono::microseconds{more}.count(),
                    status)
                    .c_str());
#else
    (void)more;
    (void)status;
#endif
}

}  // namespace tools
