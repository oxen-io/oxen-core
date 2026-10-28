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



#ifndef _NET_UTILS_BASE_H_
#define _NET_UTILS_BASE_H_

#include <oxen/quic/address.hpp>
#include <typeinfo>
#include <type_traits>
#include "../serialization/keyvalue_serialization.h"
#include <fmt/core.h>
#include <fmt/ranges.h>

namespace epee
{

struct connection_id_t : std::array<unsigned char, 16> {
    // Makes a random connection id.  *NOT* cryptographically secure random.
    static connection_id_t random();

    constexpr bool is_nil() const {
        return std::all_of(begin(), end(), [](auto x) { return x == 0; });
    }

    // Returns the id in uuid form, e.g. 00112233-4455-6677-8899-101112131415
    std::string to_string() const;
    static constexpr bool to_string_formattable = true;
};

std::ostream& operator<<(std::ostream& out, const connection_id_t& c);

namespace net_utils
{
	/************************************************************************/
	/*                                                                      */
	/************************************************************************/
	struct connection_context_base
	{
    const connection_id_t m_connection_id;
    const oxen::quic::Address m_remote_address;
    const bool     m_is_income;
    std::chrono::steady_clock::time_point m_started;
    std::chrono::steady_clock::time_point m_last_recv;
    std::chrono::steady_clock::time_point m_last_send;
    uint64_t m_recv_cnt;
    uint64_t m_send_cnt;
    double m_current_speed_down;
    double m_current_speed_up;
    double m_max_speed_down;
    double m_max_speed_up;

    connection_context_base(connection_id_t connection_id,
                            const oxen::quic::Address &remote_address, bool is_income,
                            std::chrono::steady_clock::time_point last_recv = std::chrono::steady_clock::time_point::min(),
                            std::chrono::steady_clock::time_point last_send = std::chrono::steady_clock::time_point::min(),
                            uint64_t recv_cnt = 0, uint64_t send_cnt = 0):
                                            m_connection_id(connection_id),
                                            m_remote_address(remote_address),
                                            m_is_income(is_income),
                                            m_started(std::chrono::steady_clock::now()),
                                            m_last_recv(last_recv),
                                            m_last_send(last_send),
                                            m_recv_cnt(recv_cnt),
                                            m_send_cnt(send_cnt),
                                            m_current_speed_down(0),
                                            m_current_speed_up(0),
                                            m_max_speed_down(0),
                                            m_max_speed_up(0)
    {}

    connection_context_base(): m_connection_id(),
                               m_remote_address(),
                               m_is_income(false),
                               m_started(std::chrono::steady_clock::now()),
                               m_last_recv(std::chrono::steady_clock::time_point::min()),
                               m_last_send(std::chrono::steady_clock::time_point::min()),
                               m_recv_cnt(0),
                               m_send_cnt(0),
                               m_current_speed_down(0),
                               m_current_speed_up(0),
                               m_max_speed_down(0),
                               m_max_speed_up(0)
    {}

    connection_context_base(const connection_context_base& a): connection_context_base()
    {
      set_details(a.m_connection_id, a.m_remote_address, a.m_is_income);
    }

    connection_context_base& operator=(const connection_context_base& a)
    {
      set_details(a.m_connection_id, a.m_remote_address, a.m_is_income);
      return *this;
    }
    
  private:
    void set_details(connection_id_t connection_id, const oxen::quic::Address &remote_address, bool is_income)
    {
      this->~connection_context_base();
      new(this) connection_context_base(connection_id, remote_address, is_income);
    }

	};


  //some helpers
  std::string print_connection_context(const connection_context_base& ctx);
  std::string print_connection_context_short(const connection_context_base& ctx);

  inline std::ostream& operator<<(std::ostream& os, const connection_context_base& ct)
  {
    os << "[" << epee::net_utils::print_connection_context_short(ct) << "] ";
    return os;
  }

}
}

// connection_id_t is a std::array, which fmt would otherwise also consider formattable as a range,
// making it ambiguous with its to_string formatting.
template <typename T, typename Char>
    requires std::same_as<std::remove_cv_t<T>, epee::connection_id_t>
struct fmt::is_range<T, Char> {
    static constexpr bool value = false;
};

namespace std {
template <>
struct hash<epee::connection_id_t> {
    size_t operator()(const epee::connection_id_t& id) const {
        constexpr size_t inverse_golden_ratio = sizeof(size_t) >= 8 ? 0x9e37'79b9'7f4a'7c15 : 0x9e37'79b9;

        uint64_t a, b;
        std::memcpy(&a, id.data(), 8);
        std::memcpy(&b, id.data() + 8, 8);
        auto h = hash<uint64_t>{}(a);
        return hash<uint64_t>{}(b) + inverse_golden_ratio + (h << 6) + (h >> 2);
    }
};
}  // namespace std

template <std::derived_from<epee::net_utils::connection_context_base> T, typename Char>
struct fmt::formatter<
        T,
        Char,
        // SFINAE shouldn't be needed here in C++20, but gcc-10 disagrees:
        std::enable_if_t<std::is_base_of_v<epee::net_utils::connection_context_base, T>>>
        : fmt::formatter<std::string_view> {
    auto format(
            const epee::net_utils::connection_context_base& connection_context,
            format_context& ctx) const {
        return formatter<std::string_view>::format(
                fmt::format("[{}]", epee::net_utils::print_connection_context_short(connection_context)),
                ctx);
    }
};

#endif //_NET_UTILS_BASE_H_
