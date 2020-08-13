// Copyright (c) 2006-2013, Andrey N. Sabelnikov, www.sabelnikov.net
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
// * Neither the name of the Andrey N. Sabelnikov nor the
// names of its contributors may be used to endorse or promote products
// derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER  BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#pragma once

#include "misc_log_ex.h"
#include "string_tools.h"
#include <functional>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <thread>
#include <iostream>
#include <any>
#include <unordered_map>
#ifdef __OpenBSD__
#include <stdio.h>
#endif
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

#ifdef HAVE_READLINE
  #include "readline_buffer.h"
#endif
#include "readline_suspend.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "console_handler"

namespace epee
{
  class async_stdin_reader
  {
  public:
    async_stdin_reader()
      : m_run(true)
      , m_has_read_request(false)
      , m_read_status(state_init)
    {
#ifdef HAVE_READLINE
      m_readline_buffer.start();
#endif
      m_reader_thread = std::thread([this] { reader_thread_func(); });
    }

    ~async_stdin_reader()
    {
      try { stop(); }
      catch (...) { /* ignore */ }
    }

#ifdef HAVE_READLINE
    rdln::readline_buffer& get_readline_buffer()
    {
      return m_readline_buffer;
    }
#endif

    // Not thread safe. Only one thread can call this method at once.
    bool get_line(std::string& line)
    {
      if (!start_read())
        return false;

      if (state_eos == m_read_status)
        return false;

      std::unique_lock<std::mutex> lock(m_response_mutex);
      m_response_cv.wait(lock, [this] { return m_read_status != state_init; });

      bool res = false;
      if (state_success == m_read_status)
      {
        line = m_line;
        res = true;
      }

      if (!eos() && m_read_status != state_cancelled)
        m_read_status = state_init;

      return res;
    }

    bool eos() const { return m_read_status == state_eos; }

    void stop()
    {
      if (m_run)
      {
        m_run.store(false, std::memory_order_relaxed);

#if defined(WIN32)
        ::CloseHandle(::GetStdHandle(STD_INPUT_HANDLE));
#endif

        m_request_cv.notify_one();
        m_reader_thread.join();
#ifdef HAVE_READLINE
        m_readline_buffer.stop();
#endif
      }
    }

    void cancel()
    {
      std::unique_lock<std::mutex> lock(m_response_mutex);
      m_read_status = state_cancelled;
      m_has_read_request = false;
      m_response_cv.notify_one();
    }

  private:
    bool start_read()
    {
      std::unique_lock<std::mutex> lock(m_request_mutex);
      if (!m_run.load(std::memory_order_relaxed) || m_has_read_request)
        return false;

      m_has_read_request = true;
      m_request_cv.notify_one();
      return true;
    }

    bool wait_read()
    {
      std::unique_lock<std::mutex> lock(m_request_mutex);
      m_request_cv.wait(lock, [this] { return m_has_read_request || !m_run; });

      if (m_has_read_request)
      {
        m_has_read_request = false;
        return true;
      }

      return false;
    }

    bool wait_stdin_data()
    {
#if !defined(WIN32)
      #if defined(__OpenBSD__) || defined(__ANDROID__)
      int stdin_fileno = fileno(stdin);
      #else
      int stdin_fileno = ::fileno(stdin);
      #endif

      while (m_run.load(std::memory_order_relaxed))
      {
        if (m_read_status == state_cancelled)
          return false;

        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(stdin_fileno, &read_set);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100 * 1000;

        int retval = ::select(stdin_fileno + 1, &read_set, NULL, NULL, &tv);
        if (retval < 0)
          return false;
        else if (0 < retval)
          return true;
      }
#else
      while (m_run.load(std::memory_order_relaxed))
      {
        if (m_read_status == state_cancelled)
          return false;

        int retval = ::WaitForSingleObject(::GetStdHandle(STD_INPUT_HANDLE), 100);
        switch (retval)
        {
          case WAIT_FAILED:
            return false;
          case WAIT_OBJECT_0:
            return true;
          default:
            break;
        }
      }
#endif

      return true;
    }

    void reader_thread_func()
    {
      while (true)
      {
        if (!wait_read())
          break;

        std::string line;
        bool read_ok = true;
#ifdef HAVE_READLINE
reread:
#endif
        if (wait_stdin_data())
        {
          if (m_run.load(std::memory_order_relaxed))
          {
#ifdef HAVE_READLINE
            switch (m_readline_buffer.get_line(line))
            {
            case rdln::empty:   goto eof;
            case rdln::partial: goto reread;
            case rdln::full:    break;
            }
#else
            if (m_read_status != state_cancelled)
              std::getline(std::cin, line);
#endif
            read_ok = !std::cin.eof() && !std::cin.fail();
          }
        }
        else
        {
          read_ok = false;
        }
        if (std::cin.eof()) {
#ifdef HAVE_READLINE
eof:
#endif
          m_read_status = state_eos;
          m_response_cv.notify_one();
          break;
        }
        else
        {
          std::unique_lock<std::mutex> lock(m_response_mutex);
          if (m_run.load(std::memory_order_relaxed))
          {
            m_line = std::move(line);
            m_read_status = read_ok ? state_success : state_error;
          }
          else
          {
            m_read_status = state_cancelled;
          }
          m_response_cv.notify_one();
        }
      }
    }

    enum t_state
    {
      state_init,
      state_success,
      state_error,
      state_cancelled,
      state_eos
    };

  private:
    std::thread m_reader_thread;
    std::atomic<bool> m_run;
#ifdef HAVE_READLINE
    rdln::readline_buffer m_readline_buffer;
#endif

    std::string m_line;
    bool m_has_read_request;
    t_state m_read_status;

    std::mutex m_request_mutex;
    std::mutex m_response_mutex;
    std::condition_variable m_request_cv;
    std::condition_variable m_response_cv;
  };

  class async_console_handler
  {
  public:
    async_console_handler()
    {
    }

    template<class t_server, class chain_handler>
    bool run(t_server* psrv, chain_handler ch_handler, std::function<std::string()> prompt, const std::string& usage = "")
    {
      return run(prompt, usage, [&](const std::string& cmd) { return ch_handler(psrv, cmd); }, [&] { psrv->send_stop_signal(); });
    }

    template<class chain_handler>
    bool run(chain_handler ch_handler, std::function<std::string()> prompt, const std::string& usage = "", std::function<void()> exit_handler = NULL)
    {
      return run(prompt, usage, [&](const std::optional<std::string>& cmd) { return ch_handler(cmd); }, exit_handler);
    }

    void stop()
    {
      m_running = false;
      m_stdin_reader.stop();
    }

    void cancel()
    {
      m_cancel = true;
      m_stdin_reader.cancel();
    }

    void print_prompt()
    {
      std::string prompt = m_prompt();
      if (!prompt.empty())
      {
#ifdef HAVE_READLINE
        std::string color_prompt = "\001\033[1;33m\002" + prompt;
        if (' ' != prompt.back())
          color_prompt += " ";
        color_prompt += "\001\033[0m\002";
        m_stdin_reader.get_readline_buffer().set_prompt(color_prompt);
#else
        epee::set_console_color(epee::console_color_yellow, true);
        std::cout << prompt;
        if (' ' != prompt.back())
          std::cout << ' ';
        epee::reset_console_color();
        std::cout.flush();
#endif
      }
    }

  private:
    template<typename t_cmd_handler>
    bool run(std::function<std::string()> prompt, const std::string& usage, const t_cmd_handler& cmd_handler, std::function<void()> exit_handler)
    {
      bool continue_handle = true;
      m_prompt = prompt;
      while(continue_handle)
      {
        try
        {
          if (!m_running)
          {
            break;
          }
          print_prompt();

          std::string command;
          bool get_line_ret = m_stdin_reader.get_line(command);
          if (!m_running)
            break;
          if (m_stdin_reader.eos())
          {
            MGINFO("EOF on stdin, exiting");
            std::cout << std::endl;
            break;
          }

          if (m_cancel)
          {
            MDEBUG("Input cancelled");
            cmd_handler(std::nullopt);
            m_cancel = false;
            continue;
          }
          if (!get_line_ret)
          {
            MERROR("Failed to read line.");
          }

          string_tools::trim(command);

          LOG_PRINT_L2("Read command: " << command);
          if (command.empty())
          {
            continue;
          }
          else if(0 == command.compare("exit") || 0 == command.compare("q"))
          {
            continue_handle = false;
          }
          else
          {
            cmd_handler(command);
          }
        }
        catch (const std::exception &ex)
        {
          LOG_ERROR("Exception at [console_handler], what=" << ex.what());
        }
      }
      if (exit_handler)
        exit_handler();
      return true;
    }

  private:
    async_stdin_reader m_stdin_reader;
    std::atomic<bool> m_running = {true};
    std::atomic<bool> m_cancel = {false};
    std::function<std::string()> m_prompt;
  };

  class command_handler {
  public:
    using callback = std::function<bool(const std::vector<std::string> &)>;
    using empty_callback = std::function<bool()>;
    using lookup = std::map<std::string, std::pair<callback, std::pair<std::string, std::string>>>;

    /// Go through registered commands in sorted order, call the function with three string
    /// arguments: command name, usage, and description.
    template <typename Function>
    void for_each(Function f)
    {
      for (const auto& x : m_command_handlers)
        f(x.first, x.second.second.first, x.second.second.second);
    }

    /// Returns {usage, description} for a given command.
    std::pair<std::string, std::string> get_documentation(const std::vector<std::string>& cmd)
    {
      if(cmd.empty())
        return {"", ""};
      auto it = m_command_handlers.find(cmd.front());
      if(it == m_command_handlers.end())
        return {"", ""};
      return it->second.second;
    }

    using pre_handler_callback = std::function<std::any(const std::string& cmd)>;
    using post_handler_callback = std::function<void(const std::string& cmd, bool& handler_result, std::any pre_handler_result)>;

    /// Sets a pre-handler than runs immediately before any handler set up with `set_handler`.
    /// Called with the command name.  If the handler returns a value it will be stored in a
    /// `std::any` and then passed into the `post_handler`.  Pre- and post-handlers are only invoked
    /// on valid commands.
    template <typename Callback>
    void pre_handler(Callback handler)
    {
      using Return = decltype(handler(""s));
      if constexpr (std::is_void_v<Return>)
        m_pre_handler = [f=std::move(handler)](const std::string& cmd) { f(cmd); return std::any{}; };
      else if constexpr (std::is_same_v<Return, std::any>)
        m_pre_handler = handler;
      else
        m_pre_handler = [f=std::move(handler)](const std::string& cmd) -> std::any { return f(cmd); };
    }

    /// Sets a post-handler that runs immediately after a handler set up with `set_handler`.  Takes
    /// three arguments:
    /// - the command name
    /// - a `bool&` containing the result returned by the handler (which can be modified by the post
    ///   handler to affect the callback return, if desired)
    /// - an `std::any` containing the result of the pre-handler.  (If not pre-handler was set up or
    ///   the pre-handler has a void return, the std::any will be empty).
    ///
    /// The post handler is not invoked at all if the command handler throws an exception.
    void post_handler(post_handler_callback handler)
    {
      m_post_handler = std::move(handler);
    }

    void set_handler(const std::string& cmd, callback hndlr, std::string usage = "", std::string description = "")
    {
      lookup::mapped_type & vt = m_command_handlers[cmd];
      vt.first = std::move(hndlr);
      if (description.empty())
        vt.second = {cmd, std::move(usage)};
      else
        vt.second = {std::move(usage), std::move(description)};
#ifdef HAVE_READLINE
      rdln::readline_buffer::add_completion(cmd);
#endif
    }

    /// Throws invalid_command on bad command with what() set to the command name, otherwise
    /// returns the result of the command (true generally means success, false means failure).
    struct invalid_command : std::invalid_argument { using std::invalid_argument::invalid_argument; };
    bool process_command(const std::vector<std::string>& cmd)
    {
      if(!cmd.size())
        throw invalid_command{"(empty)"};
      auto it = m_command_handlers.find(cmd.front());
      if (it == m_command_handlers.end())
        throw invalid_command{cmd.front()};

      std::any pre_result;
      if (m_pre_handler)
        pre_result = m_pre_handler(cmd.front());

      bool result = it->second.first(std::vector<std::string>{cmd.begin()+1, cmd.end()});

      if (m_post_handler)
        m_post_handler(cmd.front(), result, std::move(pre_result));

      return result;
    }

    bool process_command_and_log(const std::vector<std::string> &cmd)
    {
      try
      {
        return process_command(cmd);
      }
      catch (const invalid_command &e)
      {
        rdln::suspend_readline pause_readline;
        std::cout << "Unknown command: " << e.what() << ". Try 'help' for available commands\n";
      }
      catch (const std::exception &e)
      {
        rdln::suspend_readline pause_readline;
        std::cout << "Command errored: " << cmd.front() << ", " << e.what();
      }

      return false;
    }

    bool process_command_and_log(const std::optional<std::string>& cmd)
    {
      if (!cmd)
        return m_cancel_handler();
      std::vector<std::string> cmd_v;
      boost::split(cmd_v,*cmd,boost::is_any_of(" "), boost::token_compress_on);
      return process_command_and_log(cmd_v);
    }

    void set_cancel_handler(const empty_callback& hndlr)
    {
      m_cancel_handler = hndlr;
    }

  private:
    pre_handler_callback m_pre_handler;
    post_handler_callback m_post_handler;
    lookup m_command_handlers;
    empty_callback m_cancel_handler;
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  class console_handlers_binder : public command_handler
  {
    typedef command_handler::callback console_command_handler;
    typedef command_handler::lookup command_handlers_map;
    std::thread m_console_thread;
    async_console_handler m_console_handler;
  public:
    ~console_handlers_binder() {
      try
      {
        stop_handling();
        if (m_console_thread.joinable())
          m_console_thread.join();
      }
      catch (const std::exception &e)
      { /*ignore*/
      }
    }

    bool start_handling(std::function<std::string()> prompt, const std::string& usage_string = "", std::function<void()> exit_handler = NULL)
    {
      m_console_thread = std::thread{std::bind(&console_handlers_binder::run_handling, this, prompt, usage_string, exit_handler)};
      return true;
    }
    bool start_handling(const std::string &prompt, const std::string& usage_string = "", std::function<void()> exit_handler = NULL)
    {
      return start_handling([prompt](){ return prompt; }, usage_string, exit_handler);
    }

    void stop_handling()
    {
      m_console_handler.stop();
    }

    bool run_handling(std::function<std::string()> prompt, const std::string& usage_string, std::function<void()> exit_handler = NULL)
    {
      return m_console_handler.run([this](const auto& arg) { return process_command_and_log(arg); }, prompt, usage_string, exit_handler);
    }

    void print_prompt()
    {
      m_console_handler.print_prompt();
    }

    void cancel_input()
    {
      m_console_handler.cancel();
    }
  };
}
