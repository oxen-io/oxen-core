// Copyright (c) 2021, The Oxen Project
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

#include <string>
#include <functional>
#include <optional>

namespace tools
{

namespace net_utils
{

  struct ip_address {
    //Big Endian format. 127.0.0.1 will be saved as [127,0,0,1]
    std::array<uint8_t, 4> octets;
    uint32_t as_host32() const;
    bool is_ip_public();

    ip_address();
    ip_address(const uint8_t a, const uint8_t b, const uint8_t c, const uint8_t d);
  };

  ip_address from_big_endian( uint32_t be_uint);
  ip_address from_little_endian( uint32_t le_uint);

  struct ip_address_and_netmask {
    ip_address ip_addr;
    uint32_t netmask;
  };

  ip_address_and_netmask FromIPv4(const uint8_t a, const uint8_t b, const uint8_t c, const uint8_t d, const uint32_t netmask);

  uint32_t netmask_to_cidr(uint32_t netmask);
  uint32_t netmask_ipv4_bits(int prefix);

  bool is_ip_public(ip_address ip);
}  // namespace tools::net_utils

}  // namespace tools
