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

#include <fmt/color.h>

#include <iostream>

#include "epee/misc_log_ex.h"
#include "epee/readline_suspend.h"
#include "logging/oxen_logger.h"

namespace tools {

/************************************************************************/
/*                                                                      */
/************************************************************************/
class scoped_message_writer {
  private:
    std::string m_prefix;
    std::string m_content;
    std::optional<fmt::terminal_color> m_color;
    oxen::log::Level m_log_level;

  public:
    explicit scoped_message_writer(
            std::optional<fmt::terminal_color> color = std::nullopt,
            std::string prefix = "",
            log::Level log_level = log::Level::info) :
            m_prefix{std::move(prefix)}, m_color{color}, m_log_level{log_level} {}

    scoped_message_writer(scoped_message_writer&& o) :
            m_prefix{std::move(o.m_prefix)},
            m_content{std::move(o.m_content)},
            m_color{o.m_color},
            m_log_level{o.m_log_level} {
        o.m_content.clear();
    }

    scoped_message_writer(const scoped_message_writer& rhs) = delete;
    scoped_message_writer& operator=(const scoped_message_writer& rhs) = delete;
    scoped_message_writer& operator=(scoped_message_writer&& rhs) = delete;

    /// Appends a message and returns *this (so that it can be chained).  If called with more than 1
    /// argument then the first argument is fmt::format'ed with the remaining arguments.
    template <typename... T>
    scoped_message_writer& append(fmt::format_string<T...> format, T&&... args) {
        fmt::format_to(std::back_inserter(m_content), format, std::forward<T>(args)...);
        return *this;
    }

    scoped_message_writer& append(std::string_view msg) {
        m_content.append(msg);
        return *this;
    }

    /// Same as .append(msg). (Doesn't format, just like the single-argument .append(msg)).
    scoped_message_writer& operator+=(std::string_view msg) { return append(msg); }

    /// Essentially the same as +=, but can only be used on an rvalue instance of the object, so
    /// that you can do things like: `scoped_message_writer{} + "abc"`, which feels more natural
    /// than `scoped_message_writer{} += "abc"`.
    scoped_message_writer&& operator+(std::string_view msg) && {
        append(msg);
        return std::move(*this);
    }

    /// Flushes the current message to output and resets it.  This is normally not called explicitly
    /// but rather implicitly when the object is destroyed.
    scoped_message_writer& flush();

    /// Prints the complete message on destruction.
    ~scoped_message_writer();
};

template <typename... T>
scoped_message_writer msg_writer(std::optional<fmt::terminal_color> color = std::nullopt) {
    scoped_message_writer writer{color};
    return writer;
}

template <typename... T>
scoped_message_writer msg_writer(
        std::optional<fmt::terminal_color> color, fmt::format_string<T...> format, T&&... args) {
    auto writer = msg_writer(std::move(color));
    writer.append(format, std::forward<T>(args)...);
    return writer;
}

template <typename... T>
scoped_message_writer msg_writer(fmt::format_string<T...> format, T&&... args) {
    return msg_writer(std::nullopt, format, std::forward<T>(args)...);
}

constexpr std::optional<fmt::terminal_color> success_color{fmt::terminal_color::green};
constexpr std::optional<fmt::terminal_color> fail_color{fmt::terminal_color::red};

/// Constructs and returns a scoped_message_writer for a typical success message, with or without
/// color, as specified by the first argument.  If additional arguments are provided they will be
/// passed to append(...) to set a message (or formatted message, if multiple arguments are given).
///
/// (We deduce the Bool argument here to avoid implicit conversion to bool from non-bool values).

template <std::same_as<bool> Bool>
scoped_message_writer success_msg_writer(Bool color) {
    return msg_writer(color ? success_color : std::nullopt);
}
template <std::same_as<bool> Bool, typename... T>
scoped_message_writer success_msg_writer(Bool color, fmt::format_string<T...> format, T&&... args) {
    auto writer = success_msg_writer(color);
    writer.append(format, std::forward<T>(args)...);
    return writer;
}

inline scoped_message_writer success_msg_writer() {
    return success_msg_writer(true);
}

/// Same as above, but for calling with just a message (without a bool). Color will be true.
template <typename... T>
scoped_message_writer success_msg_writer(fmt::format_string<T...> format, T&&... args) {
    return success_msg_writer(true, format, std::forward<T>(args)...);
}

/// Constructs and returns a scoped_message_writer for a typical error message.  Color will be
/// enabled and the message will be prefixed with "Error: ".  Given arguments, if any, are passed to
/// .append() and so can specify either a single unformatted string, or a format string + format
/// arguments.
inline scoped_message_writer fail_msg_writer() {
    return scoped_message_writer{fail_color, "Error: ", spdlog::level::err};
}
template <typename... T>
scoped_message_writer fail_msg_writer(fmt::format_string<T...> format, T&&... args) {
    auto writer = fail_msg_writer();
    writer.append(format, std::forward<T>(args)...);
    return writer;
}

}  // namespace tools
