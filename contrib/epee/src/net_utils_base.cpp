
#include "epee/net/net_utils_base.h"

#include <boost/uuid/uuid_io.hpp>

#include "epee/string_tools.h"
#include "epee/int-util.h"

namespace {

    bool is_ip_loopback(uint32_t ip)
    {
      ip = SWAP32LE(ip);
      if ((ip & 0xff) == 0x7f) // 127.0.0.0/8
        return true;

      return false;
    }

    bool is_ip_local(uint32_t ip)
    {
      ip = SWAP32LE(ip);
      /*
      private network ranges:
      10.0.0.0/8
      172.16.0.0/12
      192.168.0.0/16

      carrier-grade NAT network range:
      100.64.0.0/10

      link-local addresses:
      169.254.0.0/16
      */

      // Extremely bizarrely, IPs are stored in little-endian order in epee, which is just plain
      // wrong, but we have to deal with.  (Jason)
      if ((ip & 0xff) == 0x0a) // 10.0.0.0/8
        return true;

      if ((ip & 0xf0ff) == 0x10ac) // 172.16.0.0/12 (0xf0ff looks strange because of the little endian nonsense)
        return true;

      if ((ip & 0xffff) == 0xa8c0) // 192.168.0.0/16
        return true;

      if ((ip & 0xc0ff) == 0x4064) // 100.64.0.0/10
        return true;

      if ((ip & 0xffff) == 0xfea9) // 169.254.0.0/16
        return true;

      return false;
    }
}

namespace epee { namespace net_utils
{
	bool ipv4_network_address::equal(const ipv4_network_address& other) const noexcept
	{ return is_same_host(other) && port() == other.port(); }

	bool ipv4_network_address::less(const ipv4_network_address& other) const noexcept
	{ return is_same_host(other) ? port() < other.port() : ip() < other.ip(); }

	std::string ipv4_network_address::str() const
	{ return string_tools::get_ip_string_from_int32(ip()) + ":" + std::to_string(port()); }

	std::string ipv4_network_address::host_str() const { return string_tools::get_ip_string_from_int32(ip()); }
	bool ipv4_network_address::is_loopback() const { return is_ip_loopback(ip()); }
	bool ipv4_network_address::is_local() const { return is_ip_local(ip()); }

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
	bool ipv4_network_subnet::is_loopback() const { return is_ip_loopback(subnet()); }
	bool ipv4_network_subnet::is_local() const { return is_ip_local(subnet()); }
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
}}

