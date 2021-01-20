// Copyright (c)      2021, The Oxen Project
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

#include "common/net_utils.h"

#include "epee/misc_log_ex.h"

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "net.net"

namespace tools
{

namespace net_utils
{

ip_address from_big_endian(uint32_t be_uint)
{
  ip_address ret;
  union {
      uint32_t integer;
      std::array<uint8_t,4> bytes;
  } value { be_uint };

  ret.octets = value.bytes;
  return ret;
}

ip_address from_little_endian(uint32_t le_uint)
{
  ip_address ret;
  union {
      uint32_t integer;
      std::array<uint8_t,4> bytes;
  } value { le_uint };

  std::swap(value.bytes[0], value.bytes[3]);
  std::swap(value.bytes[1], value.bytes[2]);
  ret.octets = value.bytes;
  return ret;
}

uint32_t ip_address::as_host32() const { return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]; }

ip_address::ip_address():octets{0}{};

ip_address::ip_address(const uint8_t a, const uint8_t b, const uint8_t c, const uint8_t d)
{
  octets[0] = a;
  octets[1] = b;
  octets[2] = c;
  octets[3] = d;
}

ip_address_and_netmask FromIPv4(const uint8_t a, const uint8_t b, const uint8_t c, const uint8_t d, const uint32_t netmask)
{
  return ip_address_and_netmask{ip_address(a,b,c,d), netmask_ipv4_bits(netmask)};
}

uint32_t netmask_to_cidr(uint32_t netmask)
{
  int cidr = 0;
  while ( netmask )
  {
      cidr += ( netmask & 0x01 );
      netmask >>= 1;
  }
  return cidr;
}

uint32_t netmask_ipv4_bits(int prefix)
{
	if (prefix) {
		return ~((1 << (32 - prefix)) - 1);
	} else {
		return uint32_t{0};
	}
}


std::array bogonRanges = {FromIPv4(0, 0, 0, 0, 8),
                           FromIPv4(10, 0, 0, 0, 8),
                           FromIPv4(100, 64, 0, 0, 10),
                           FromIPv4(127, 0, 0, 0, 8),
                           FromIPv4(169, 254, 0, 0, 16),
                           FromIPv4(172, 16, 0, 0, 12),
                           FromIPv4(192, 0, 0, 0, 24),
                           FromIPv4(192, 0, 2, 0, 24),
                           FromIPv4(192, 88, 99, 0, 24),
                           FromIPv4(192, 168, 0, 0, 16),
                           FromIPv4(198, 18, 0, 0, 15),
                           FromIPv4(198, 51, 100, 0, 24),
                           FromIPv4(203, 0, 113, 0, 24),
                           FromIPv4(224, 0, 0, 0, 4),
                           FromIPv4(240, 0, 0, 0, 4)};

bool ip_address::is_ip_public()
{

  uint32_t ip = this->as_host32();
  for(const auto ipRange: bogonRanges) {
    uint32_t netstart = (ipRange.ip_addr.as_host32() & ipRange.netmask); // first ip in subnet
    uint32_t netend = (netstart | ~ipRange.netmask); // last ip in subnet
    if ((ip >= netstart) && (ip <= netend))
      return false;
  }
  return true;
}

bool is_ip_public(ip_address ip)
{
  return ip.is_ip_public();
}

}  // namespace tools::net_utils

}  // namespace tools
