
#include "epee/net/net_utils_base.h"

#include <iterator>
#include <random>
#include <oxenc/hex.h>

#include "epee/net/enums.h"

namespace epee::net_utils
{
	bool ipv6_network_address::equal(const ipv6_network_address& other) const noexcept
	{ return is_same_host(other) && port() == other.port(); }

	bool ipv6_network_address::less(const ipv6_network_address& other) const noexcept
	{ return is_same_host(other) ? port() < other.port() : m_address < other.m_address; }

	std::string ipv6_network_address::str() const
	{ return std::string("[") + host_str() + "]:" + std::to_string(port()); }

	std::string ipv6_network_address::host_str() const { return m_address.to_string(); }
	bool ipv6_network_address::is_loopback() const { return m_address.is_loopback(); }
	bool ipv6_network_address::is_local() const { return m_address.is_link_local(); }

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

std::string connection_id_t::to_string() const {
    std::string s;
    s.reserve(36);
    auto out = std::back_inserter(s);
    oxenc::to_hex(begin(), begin() + 4, out);
    s += '-';
    oxenc::to_hex(begin() + 4, begin() + 6, out);
    s += '-';
    oxenc::to_hex(begin() + 6, begin() + 8, out);
    s += '-';
    oxenc::to_hex(begin() + 8, begin() + 10, out);
    s += '-';
    oxenc::to_hex(begin() + 10, end(), out);
    return s;
}

std::ostream& operator<<(std::ostream& out, const connection_id_t& c) {
    return out << c.to_string();
}

}  // namespace epee
