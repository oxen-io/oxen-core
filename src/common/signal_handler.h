#pragma once
#include <csignal>
#include <cstring>
#include <functional>
#include <mutex>

#include "logging/oxen_logger.h"
#ifdef _WIN32
#include "windows.h"
#endif

namespace tools {

/*! \brief Defines a singleton signal handler for win32 and *nix
 */
class signal_handler {
  public:
    /*! \brief installs a signal handler  */
    template <typename T>
    static bool install(T t) {
#ifdef _WIN32
        bool r = TRUE == ::SetConsoleCtrlHandler(&win_handler, TRUE);
        if (r) {
            m_handler = t;
        }
        return r;
#else
        static struct sigaction sa;
        memset(&sa, 0, sizeof(struct sigaction));
        sa.sa_handler = posix_handler;
        sa.sa_flags = 0;
        /* Only blocks SIGINT, SIGTERM and SIGPIPE */
        sigaction(SIGINT, &sa, NULL);
        signal(SIGTERM, posix_handler);
        signal(SIGPIPE, SIG_IGN);
        m_handler = t;
        return true;
#endif
    }

  private:
#if defined(WIN32)
    /*! \brief Handler for win */
    static BOOL WINAPI win_handler(DWORD type) {
        if (CTRL_C_EVENT == type || CTRL_BREAK_EVENT == type) {
            handle_signal(type);
        } else {
            log::info(
                    globallogcat,
                    fg(fmt::terminal_color::red),
                    "Got control signal {}. Exiting without saving...",
                    type);
            return FALSE;
        }
        return TRUE;
    }
#else
    /*! \brief handler for NIX */
    static void posix_handler(int type) { handle_signal(type); }
#endif

    /*! \brief calles m_handler */
    static void handle_signal(int type) {
        static std::mutex m_mutex;
        std::unique_lock lock{m_mutex};
        m_handler(type);
    }

    /*! \brief where the installed handler is stored */
    static inline std::function<void(int)> m_handler;
};

}  // namespace tools
