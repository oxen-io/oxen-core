#pragma once

#include <oxenc/endian.h>

#include <cstdint>
#include <optional>
#include <oxen/quic/ip.hpp>
#include <string_view>

namespace tools {

/// Parses an IPv4 range in CIDR notation ("1.2.3.0/24"), or a bare IPv4 address as a /32 if
/// `allow_bare_ip` is true.  Returns nullopt if the value isn't parseable, or if the mask is
/// greater than 32.
std::optional<oxen::quic::ipv4_range> parse_ipv4_range(std::string_view str, bool allow_bare_ip);

// Several formats inherited from epee store an IPv4 address as the integer whose little-endian
// encoding is the address's network-order bytes, which is the byte-reversed value of the address's
// natural integer (1.2.3.4 is stored as 0x04030201).  These convert to and from that integer, and
// exist only so that those existing formats keep their encoding; new formats must not use them.

constexpr uint32_t ipv4_to_legacy_int(const oxen::quic::ipv4& ip) {
    uint32_t legacy = ip.addr;
    oxenc::byteswap_inplace(legacy);
    return legacy;
}

constexpr oxen::quic::ipv4 ipv4_from_legacy_int(uint32_t legacy) {
    oxenc::byteswap_inplace(legacy);
    return oxen::quic::ipv4{legacy};
}

}  // namespace tools
