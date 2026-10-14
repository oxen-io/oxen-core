#pragma once

#include <chrono>
#include <string_view>

namespace tools {

/// Tells systemd (when oxend is running as a Type=notify service) that it is busy with something
/// that can take a while, pushing the start or stop timeout back to `more` from now, and sets the
/// service's status line to `status`.  Callers doing something long call it again (no more than
/// every 10s or so) while it continues.  Does nothing when built without systemd support, or when
/// not run by systemd.
void systemd_extend_timeout(std::chrono::seconds more, std::string_view status);

}  // namespace tools
