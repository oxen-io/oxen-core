#pragma once

#include <compare>
#include <cstdint>
#include <oxen/quic/ip.hpp>
#include <string>

#include "epee/net/enums.h"

namespace epee::serialization {
class portable_storage;
struct section;
}  // namespace epee::serialization

namespace net {

/// An IPv4 address and port, as held by epee's type-erased `network_address`.
class ipv4_address {
    oxen::quic::ipv4 ip_;
    std::uint16_t port_ = 0;

  public:
    constexpr ipv4_address() noexcept = default;
    constexpr ipv4_address(const oxen::quic::ipv4& ip, std::uint16_t port) noexcept :
            ip_{ip}, port_{port} {}

    bool _load(epee::serialization::portable_storage& src, epee::serialization::section* hparent);
    bool store(epee::serialization::portable_storage& dest, epee::serialization::section* hparent)
            const;

    constexpr auto operator<=>(const ipv4_address&) const noexcept = default;
    constexpr bool operator==(const ipv4_address&) const noexcept = default;

    constexpr bool equal(const ipv4_address& rhs) const noexcept { return *this == rhs; }
    constexpr bool less(const ipv4_address& rhs) const noexcept { return *this < rhs; }
    constexpr bool is_same_host(const ipv4_address& rhs) const noexcept { return ip_ == rhs.ip_; }

    constexpr const oxen::quic::ipv4& ip() const noexcept { return ip_; }
    constexpr std::uint16_t port() const noexcept { return port_; }
    std::string str() const;
    std::string host_str() const { return ip_.to_string(); }
    constexpr bool is_loopback() const noexcept { return oxen::quic::ipv4_loopback.contains(ip_); }
    // Not publicly routable, but not loopback either (which `is_loopback()` reports).
    constexpr bool is_local() const noexcept { return !ip_.is_public() && !is_loopback(); }
    static constexpr epee::net_utils::address_type get_type_id() noexcept {
        return epee::net_utils::address_type::ipv4;
    }
    static constexpr epee::net_utils::zone get_zone() noexcept {
        return epee::net_utils::zone::public_;
    }
    static constexpr bool is_blockable() noexcept { return true; }
};

}  // namespace net
