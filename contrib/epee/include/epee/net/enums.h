// Copyright (c) 2018, The Monero Project
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

#include <string_view>
#include <cstdint>
#include <iosfwd>

namespace epee::net_utils
{
using namespace std::literals;
	enum class address_type : std::uint8_t
	{
		// Do not change values, this will break serialization
		invalid = 0,
		ipv4 = 1,
		ipv6 = 2,
		i2p = 3,
		tor = 4
	};

	enum class zone : std::uint8_t
	{
		invalid = 0,
		public_ = 1, // public is keyword
		i2p = 2,     // order from here changes priority of selection for origin TXes
		tor = 3
	};

    //! \return String name of address type
    constexpr std::string_view to_string(address_type a) noexcept {
      switch (a) {
        case address_type::ipv4: return "IPv4"sv;
        case address_type::ipv6: return "IPv6"sv;
        case address_type::i2p: return "I2P"sv;
        case address_type::tor: return "Tor"sv;
        default: return "invalid"sv;
      }
    }

	//! \return String name of zone or "invalid" on error.
    constexpr std::string_view to_string(zone value) noexcept {
      switch(value) {
        case zone::public_: return "public"sv;
        case zone::i2p:     return "i2p"sv;
        case zone::tor:     return "tor"sv;
        default:            return "invalid"sv;
      }
    }

	//! \return `zone` enum of `value` or `zone::invalid` on error.
    constexpr zone zone_from_string(std::string_view value) noexcept {
      if (value == "public"sv) return zone::public_;
      if (value == "i2p"sv)    return zone::i2p;
      if (value == "tor"sv)    return zone::tor;
      return zone::invalid;
    }

	// implementations in src/net_utils_base.cpp

    std::ostream& operator<<(std::ostream& o, address_type a);
    std::ostream& operator<<(std::ostream& o, zone z);

} // epee::net_utils
