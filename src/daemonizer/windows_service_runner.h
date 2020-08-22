// Copyright (c) 2014-2019, The Monero Project
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

#pragma once

#ifdef WIN32

#undef UNICODE
#undef _UNICODE

#include "daemonizer/windows_service.h"
#include <memory>
#include <string>
#include <vector>
#include <windows.h>

namespace windows {

  template <typename Application>
  class service_runner final
  {
  private:
    SERVICE_STATUS_HANDLE m_status_handle{nullptr};
    SERVICE_STATUS m_status{};
    std::mutex m_lock;
    std::string m_name;
    Application app;

    static service_runner*& get_instance() { static service_runner* instance{nullptr}; return instance; }

  public:
    template <typename... Args>
    service_runner(std::string name, Args&&... args)
        : m_name{std::move(name)}, app{std::forward<Args>(args)...}
    {
      // This limitation is crappy, but imposed on us by Windows
      auto& instance = get_instance();
      if (instance) throw std::runtime_error("Only one service_runner<T> may exist at a time");
      instance = this;

      m_status.dwServiceType = SERVICE_WIN32;
      m_status.dwCurrentState = SERVICE_STOPPED;
      m_status.dwControlsAccepted = 0;
      m_status.dwWin32ExitCode = NO_ERROR;
      m_status.dwServiceSpecificExitCode = NO_ERROR;
      m_status.dwCheckPoint = 0;
      m_status.dwWaitHint = 0;
    }

    ~service_runner() { get_instance() = nullptr; }

    // Non-copyable and non-moveable
    service_runner &operator=(service_runner&&) = delete;
    service_runner &operator=(const service_runner&) = delete;
    service_runner(service_runner&&) = delete;
    service_runner(const service_runner&) = delete;

    void run()
    {
      SERVICE_TABLE_ENTRY const table[] = {{&m_name[0], &service_main}, {0, 0}};
      StartServiceCtrlDispatcher(table);
    }
  private:

    void report_status(DWORD status)
    {
      m_status.dwCurrentState = status;
      if (status == SERVICE_RUNNING)
      {
        m_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
      }
      else if(status == SERVICE_STOP_PENDING)
      {
        m_status.dwControlsAccepted = 0;
      }
      SetServiceStatus(m_status_handle, &m_status);
    }

    static void WINAPI service_main(DWORD argc, LPSTR * argv)
    {
      get_instance()->service_main_(argc, argv);
    }

    void service_main_(DWORD argc, LPSTR * argv)
    {
      m_status_handle = RegisterServiceCtrlHandler(m_name.c_str(), &on_state_change_request);
      if (m_status_handle == nullptr) return;

      report_status(SERVICE_START_PENDING);

      report_status(SERVICE_RUNNING);

      app.run(false /*not interactive*/);

      on_state_change_request_(SERVICE_CONTROL_STOP);

      // Ensure that the service is uninstalled
      uninstall_service(m_name.c_str());
    }

    static void WINAPI on_state_change_request(DWORD control_code)
    {
      get_instance()->on_state_change_request_(control_code);
    }

    void on_state_change_request_(DWORD control_code)
    {
      switch (control_code)
      {
        case SERVICE_CONTROL_INTERROGATE:
          break;
        case SERVICE_CONTROL_SHUTDOWN:
        case SERVICE_CONTROL_STOP:
          report_status(SERVICE_STOP_PENDING);
          app.stop();
          break;
        case SERVICE_CONTROL_PAUSE:
          break;
        case SERVICE_CONTROL_CONTINUE:
          break;
        default:
          break;
      }
    }
  };
}

#endif
