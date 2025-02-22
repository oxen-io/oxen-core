
#include "epee/net/net_utils_base.h"

#include <random>
#include <oxenc/hex.h>

#include "epee/string_tools.h"
#include "epee/net/local_ip.h"
#include "epee/net/enums.h"

namespace epee::net_utils
{
	bool ipv4_network_address::equal(const ipv4_network_address& other) const noexcept
	{ return is_same_host(other) && port() == other.port(); }

	bool ipv4_network_address::less(const ipv4_network_address& other) const noexcept
	{ return is_same_host(other) ? port() < other.port() : ip() < other.ip(); }

	std::string ipv4_network_address::str() const
	{ return string_tools::get_ip_string_from_int32(ip()) + ":" + std::to_string(port()); }

	std::string ipv4_network_address::host_str() const { return string_tools::get_ip_string_from_int32(ip()); }
	bool ipv4_network_address::is_loopback() const { return net_utils::is_ip_loopback(ip()); }
	bool ipv4_network_address::is_local() const { return net_utils::is_ip_local(ip()); }

	bool ipv6_network_address::equal(const ipv6_network_address& other) const noexcept
	{ return is_same_host(other) && port() == other.port(); }

	bool ipv6_network_address::less(const ipv6_network_address& other) const noexcept
	{ return is_same_host(other) ? port() < other.port() : m_address < other.m_address; }

	std::string ipv6_network_address::str() const
	{ return std::string("[") + host_str() + "]:" + std::to_string(port()); }

	std::string ipv6_network_address::host_str() const { return m_address.to_string(); }
	bool ipv6_network_address::is_loopback() const { return m_address.is_loopback(); }
	bool ipv6_network_address::is_local() const { return m_address.is_link_local(); }


	bool ipv4_network_subnet::equal(const ipv4_network_subnet& other) const noexcept
	{ return is_same_host(other) && m_mask == other.m_mask; }

	bool ipv4_network_subnet::less(const ipv4_network_subnet& other) const noexcept
	{ return subnet() < other.subnet() ? true : (other.subnet() < subnet() ? false : (m_mask < other.m_mask)); }

	std::string ipv4_network_subnet::str() const
	{ return string_tools::get_ip_string_from_int32(subnet()) + "/" + std::to_string(m_mask); }

	std::string ipv4_network_subnet::host_str() const { return string_tools::get_ip_string_from_int32(subnet()) + "/" + std::to_string(m_mask); }
	bool ipv4_network_subnet::is_loopback() const { return net_utils::is_ip_loopback(subnet()); }
	bool ipv4_network_subnet::is_local() const { return net_utils::is_ip_local(subnet()); }
	bool ipv4_network_subnet::matches(const ipv4_network_address &address) const
	{
		return (address.ip() & ~(0xffffffffull << m_mask)) == subnet();
	}

	bool network_address::equal(const network_address& other) const
	{
		// clang typeid workaround
		network_address::interface const* const self_ = self.get();
		network_address::interface const* const other_self = other.self.get();
		if (self_ == other_self) return true;
		if (!self_ || !other_self) return false;
		if (typeid(*self_) != typeid(*other_self)) return false;
		return self_->equal(*other_self);
	}

	bool network_address::less(const network_address& other) const
	{
		// clang typeid workaround
		network_address::interface const* const self_ = self.get();
		network_address::interface const* const other_self = other.self.get();
		if (self_ == other_self) return false;
		if (!self_ || !other_self) return self == nullptr;
		if (typeid(*self_) != typeid(*other_self))
			return self_->get_type_id() < other_self->get_type_id();
		return self_->less(*other_self);
	}

	bool network_address::is_same_host(const network_address& other) const
	{
		// clang typeid workaround
		network_address::interface const* const self_ = self.get();
		network_address::interface const* const other_self = other.self.get();
		if (self_ == other_self) return true;
		if (!self_ || !other_self) return false;
		if (typeid(*self_) != typeid(*other_self)) return false;
		return self_->is_same_host(*other_self);
	}

  // should be here, but network_address is perverted with a circular dependency into src/net, so
  // this is in src/net/epee_network_address_hack.cpp instead.
  //KV_SERIALIZE_MAP_CODE_BEGIN(network_address)

  std::string print_connection_context(const connection_context_base& ctx)
  {
    std::stringstream ss;
    ss << ctx.m_remote_address.str() << " " << ctx.m_connection_id << (ctx.m_is_income ? " INC":" OUT");
    return ss.str();
  }

  std::string print_connection_context_short(const connection_context_base& ctx)
  {
    std::stringstream ss;
    ss << ctx.m_remote_address.str() << (ctx.m_is_income ? " INC":" OUT");
    return ss.str();
  }

  std::ostream& operator<<(std::ostream& o, address_type a)
  {
    return o << to_string(a);
  }
  std::ostream& operator<<(std::ostream& o, zone z)
  {
    return o << to_string(z);
  }
} // namespace epee::net_utils

namespace epee {

static std::mt19937_64 seed_rng() {
    std::random_device dev;
    // each dev() gives us 32 bits of random data; 256 bits ought to be plenty for what we need:
    std::seed_seq seed{{dev(), dev(), dev(), dev(), dev(), dev(), dev(), dev()}};
    std::mt19937_64 rng{seed};
    return rng;
}

connection_id_t connection_id_t::random() {
    static thread_local auto rng = seed_rng();
    uint64_t x[2];
    x[0] = rng();
    x[1] = rng();
    connection_id_t conn_id;
    static_assert(sizeof(conn_id) == sizeof(x));
    std::memcpy(conn_id.data(), &x, sizeof(x));
    return conn_id;
}

std::ostream& operator<<(std::ostream& out, const connection_id_t& c) {
    // Output in uuid form:
    // 00112233-4455-6677-8899-101112131415
    return out << oxenc::to_hex(c.begin(), c.begin() + 4) << '-'
               << oxenc::to_hex(c.begin() + 4, c.begin() + 6) << '-'
               << oxenc::to_hex(c.begin() + 6, c.begin() + 8) << '-'
               << oxenc::to_hex(c.begin() + 8, c.begin() + 10) << '-'
               << oxenc::to_hex(c.begin() + 10, c.end());
}

}  // namespace epee
