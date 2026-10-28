#pragma once

#include <cstdint>
#include <oxen/quic/address.hpp>

namespace epee::serialization {
class portable_storage;
struct section;
}  // namespace epee::serialization

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

// KV (portable storage) serialization of peer addresses, which epee's KV serialization finds by
// ADL.  The format is the one existing nodes use for a peer address:
//     {"type": 1, "addr": {"m_ip": u32, "m_port": u16}}
//     {"type": 2, "addr": {"addr": 16-byte string, "m_port": u16}}
// where m_ip is the legacy, byte-reversed integer (see tools::ipv4_to_legacy_int).
namespace epee::serialization {
bool kv_store(const oxen::quic::Address& addr, portable_storage& stg, section* parent);
bool kv_load(oxen::quic::Address& addr, portable_storage& stg, section* parent);
}  // namespace epee::serialization
