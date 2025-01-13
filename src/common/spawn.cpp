// Copyright (c) 2019, The Monero Project
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

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <sys/wait.h>
#endif

#include "epee/misc_log_ex.h"
#include "logging/oxen_logger.h"
#include "oxen.h"
#include "spawn.h"
#include "string_util.h"
#include "util.h"

namespace tools {

static auto logcat = log::Cat("spawn");

#ifndef _WIN32
static void closefrom(int fd) {
#if defined __FreeBSD__ || defined __OpenBSD__ || defined __NetBSD__ || defined __DragonFly__
    ::closefrom(fd);
#else
#if defined __GLIBC__
    const int sc_open_max = sysconf(_SC_OPEN_MAX);
    const int MAX_FDS = std::min(65536, sc_open_max);
#else
    const int MAX_FDS = 65536;
#endif
    while (fd < MAX_FDS) {
        close(fd);
        ++fd;
    }
#endif
}
#endif

int spawn(const fs::path& filename, const std::vector<std::string>& args, bool wait) {
#ifdef _WIN32
    std::string joined = tools::join(" ", args);
    char* commandLine = !joined.empty() ? &joined[0] : nullptr;
    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    // This .string() is wrong for non-ascii paths, but if we switch to CreateProcessW and use
    // .c_str() directly our commandLine argument will not be accepted (because it then has to be a
    // wchar_t* but out input is utf-8).  Shame on you for this garbage API, Windows.
    if (!CreateProcessA(
                filename.string().c_str(),
                commandLine,
                nullptr,
                nullptr,
                false,
                0,
                nullptr,
                nullptr,
                &si,
                &pi)) {
        log::error(logcat, "CreateProcess failed. Error code {}", GetLastError());
        return -1;
    }

    OXEN_DEFER {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    };

    if (!wait) {
        return 0;
    }

    DWORD result = WaitForSingleObject(pi.hProcess, INFINITE);
    if (result != WAIT_OBJECT_0) {
        log::error(
                logcat,
                "WaitForSingleObject failed. Result {}, error code {}",
                result,
                GetLastError());
        return -1;
    }

    DWORD exitCode;
    if (!GetExitCodeProcess(pi.hProcess, &exitCode)) {
        log::error(logcat, "GetExitCodeProcess failed. Error code {}", GetLastError());
        return -1;
    }

    log::info(logcat, "Child exited with {}", exitCode);
    return static_cast<int>(exitCode);
#else
    std::vector<char*> argv(args.size() + 1);
    for (size_t n = 0; n < args.size(); ++n)
        argv[n] = (char*)args[n].c_str();
    argv[args.size()] = NULL;

    pid_t pid = fork();
    if (pid < 0) {
        log::error(logcat, "Error forking: {}", strerror(errno));
        return -1;
    }

    // child
    if (pid == 0) {
        tools::closefrom(3);
        close(0);
        char* envp[] = {NULL};
        execve(filename.c_str(), argv.data(), envp);
        log::error(logcat, "Failed to execve: {}", strerror(errno));
        return -1;
    }

    // parent
    if (pid > 0) {
        if (!wait) {
            signal(SIGCHLD, SIG_IGN);
            return 0;
        }

        while (1) {
            int wstatus = 0;
            pid_t w = waitpid(pid, &wstatus, WUNTRACED | WCONTINUED);
            if (w < 0) {
                log::error(logcat, "Error waiting for child: {}", strerror(errno));
                return -1;
            }
            if (WIFEXITED(wstatus)) {
                log::info(logcat, "Child exited with {}", WEXITSTATUS(wstatus));
                return WEXITSTATUS(wstatus);
            }
            if (WIFSIGNALED(wstatus)) {
                log::info(logcat, "Child killed by {}", WEXITSTATUS(wstatus));
                return WEXITSTATUS(wstatus);
            }
        }
    }
    log::error(logcat, "Secret passage found");
    return -1;
#endif
}

}  // namespace tools
