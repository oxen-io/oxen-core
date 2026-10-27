#include "ipv4_address.h"

#include <fmt/format.h>

#include "common/ipv4.h"
#include "epee/serialization/keyvalue_serialization.h"
#include "epee/storages/portable_storage.h"

namespace net {

namespace {
    // The p2p wire format (inherited from epee) carries the IP as a legacy integer; see
    // tools::ipv4_to_legacy_int.
    struct ipv4_serialized {
        std::uint32_t m_ip;
        std::uint16_t m_port;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(m_ip)
        KV_SERIALIZE(m_port)
        END_KV_SERIALIZE_MAP()
    };
}  // namespace

bool ipv4_address::_load(
        epee::serialization::portable_storage& src, epee::serialization::section* hparent) {
    ipv4_serialized in{};
    if (!in._load(src, hparent))
        return false;
    ip_ = tools::ipv4_from_legacy_int(in.m_ip);
    port_ = in.m_port;
    return true;
}

bool ipv4_address::store(
        epee::serialization::portable_storage& dest, epee::serialization::section* hparent) const {
    const ipv4_serialized out{tools::ipv4_to_legacy_int(ip_), port_};
    return out.store(dest, hparent);
}

std::string ipv4_address::str() const {
    return fmt::format("{}:{}", ip_.to_string(), port_);
}

}  // namespace net
