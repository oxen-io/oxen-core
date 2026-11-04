#include "address.h"

#include <array>
#include <cstring>
#include <oxen/log.hpp>
#include <span>

#include "common/guts.h"
#include "common/ipv4.h"
#include "serialization/levin_kv/archive.h"

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
        uint32_t m_ip = 0;
        uint16_t m_port = 0;

        void serialize(levin_kv::archive& ar) {
            ar.value("m_ip", m_ip);
            ar.value("m_port", m_port);
        }
    };

    struct ipv6_serialized {
        std::array<uint8_t, 16> addr{};
        uint16_t m_port = 0;

        void serialize(levin_kv::archive& ar) {
            ar.value("addr", tools::byte_span(addr));
            ar.value("m_port", m_port);
        }
    };

}  // namespace

}  // namespace net

void levin_kv::serialize(archive& ar, oxen::quic::Address& addr) {
    if (!ar.loading()) {
        auto type = net::type_of(addr);
        if (type == net::address_type::invalid)
            return;
        auto type_id = static_cast<uint8_t>(type);
        ar.value("type", type_id);
        if (type == net::address_type::ipv4) {
            net::ipv4_serialized out{tools::ipv4_to_legacy_int(addr.to_ipv4()), addr.port()};
            ar.value("addr", out);
        } else {
            net::ipv6_serialized out{};
            std::memcpy(out.addr.data(), addr.in6().sin6_addr.s6_addr, out.addr.size());
            out.m_port = addr.port();
            ar.value("addr", out);
        }
        return;
    }

    uint8_t type = 0;
    if (!ar.value("type", type))
        return;
    switch (net::address_type{type}) {
        case net::address_type::ipv4: {
            net::ipv4_serialized in{};
            if (ar.value("addr", in))
                addr = oxen::quic::Address{tools::ipv4_from_legacy_int(in.m_ip), in.m_port};
            return;
        }
        case net::address_type::ipv6: {
            net::ipv6_serialized in{};
            if (ar.value("addr", in))
                addr = oxen::quic::Address{oxen::quic::ipv6{std::span{in.addr}}, in.m_port};
            return;
        }
        default: oxen::log::error(net::logcat, "Unsupported network address type: {}", +type);
    }
}
