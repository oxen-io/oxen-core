#pragma once

#include <cstdint>
#include <oxen/quic/address.hpp>

#include "serialization/levin_kv/fwd.h"

namespace net {

// The type ids that peer addresses are serialized with, on the p2p wire and in the p2pstate file,
// and reported as over RPC: the values must not change.
enum class address_type : uint8_t {
    invalid = 0,
    ipv4 = 1,
    ipv6 = 2,
};

address_type type_of(const oxen::quic::Address& addr);

// These look only at the IP, unlike oxen::quic::Address::is_loopback (which is false for any
// address with a 0 port).
bool is_loopback(const oxen::quic::Address& addr);
// Not publicly routable, but not loopback either.
bool is_local(const oxen::quic::Address& addr);
bool same_host(const oxen::quic::Address& a, const oxen::quic::Address& b);

}  // namespace net

// levin_kv serialization of peer addresses, in levin_kv's namespace (which the archive finds it in)
// rather than libquic's.  The format is the one existing nodes use for a peer address:
//     {"type": 1, "addr": {"m_ip": u32, "m_port": u16}}
//     {"type": 2, "addr": {"addr": 16-byte string, "m_port": u16}}
// where m_ip is the legacy, byte-reversed integer (see tools::ipv4_to_legacy_int).  An invalid
// address is written as an empty map; one of an unknown type is left as it was when read.
namespace levin_kv {
void serialize(archive& ar, oxen::quic::Address& addr);
}  // namespace levin_kv
