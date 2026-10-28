#include "address.h"

#include <array>
#include <cstring>
#include <oxen/log.hpp>
#include <span>

#include "common/ipv4.h"
#include "epee/serialization/keyvalue_serialization.h"
#include "epee/storages/portable_storage.h"

namespace net {

static auto logcat = oxen::log::Cat("net");

using oxen::quic::Address;

address_type type_of(const Address& addr) {
    return addr.is_ipv4() ? address_type::ipv4
         : addr.is_ipv6() ? address_type::ipv6
                          : address_type::invalid;
}

bool is_loopback(const Address& addr) {
    if (addr.is_ipv4())
        return oxen::quic::ipv4_loopback.contains(addr.to_ipv4());
    if (addr.is_ipv6())
        return addr.to_ipv6() == oxen::quic::ipv6_loopback;
    return false;
}

bool is_local(const Address& addr) {
    return !addr.is_public_ip() && !is_loopback(addr);
}

bool same_host(const Address& a, const Address& b) {
    if (a.is_ipv4() && b.is_ipv4())
        return a.to_ipv4() == b.to_ipv4();
    if (a.is_ipv6() && b.is_ipv6())
        return a.to_ipv6() == b.to_ipv6();
    return false;
}

namespace {

    struct ipv4_serialized {
        uint32_t m_ip;
        uint16_t m_port;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(m_ip)
        KV_SERIALIZE(m_port)
        END_KV_SERIALIZE_MAP()
    };

    struct ipv6_serialized {
        std::array<uint8_t, 16> addr;
        uint16_t m_port;

        BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_VAL_POD_AS_BLOB(addr)
        KV_SERIALIZE(m_port)
        END_KV_SERIALIZE_MAP()
    };

}  // namespace

}  // namespace net

namespace epee::serialization {

bool kv_store(const oxen::quic::Address& addr, portable_storage& stg, section* parent) {
    auto type = net::type_of(addr);
    if (type == net::address_type::invalid)
        return false;
    if (!stg.set_value("type", static_cast<uint8_t>(type), parent))
        return false;
    if (type == net::address_type::ipv4) {
        net::ipv4_serialized out{tools::ipv4_to_legacy_int(addr.to_ipv4()), addr.port()};
        return perform_serialize<true>(out, stg, parent, "addr");
    }
    net::ipv6_serialized out{};
    std::memcpy(out.addr.data(), addr.in6().sin6_addr.s6_addr, out.addr.size());
    out.m_port = addr.port();
    return perform_serialize<true>(out, stg, parent, "addr");
}

bool kv_load(oxen::quic::Address& addr, portable_storage& stg, section* parent) {
    uint8_t type = 0;
    if (!stg.get_value("type", type, parent))
        return false;
    switch (net::address_type{type}) {
        case net::address_type::ipv4: {
            net::ipv4_serialized in{};
            if (!perform_serialize<false>(in, stg, parent, "addr"))
                return false;
            addr = oxen::quic::Address{tools::ipv4_from_legacy_int(in.m_ip), in.m_port};
            return true;
        }
        case net::address_type::ipv6: {
            net::ipv6_serialized in{};
            if (!perform_serialize<false>(in, stg, parent, "addr"))
                return false;
            addr = oxen::quic::Address{oxen::quic::ipv6{std::span{in.addr}}, in.m_port};
            return true;
        }
        default:
            oxen::log::error(net::logcat, "Unsupported network address type: {}", +type);
            return false;
    }
}

}  // namespace epee::serialization
