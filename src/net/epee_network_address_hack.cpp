#include "epee/net/net_utils_base.h"
#include "epee/storages/portable_storage.h"
#include "i2p_address.h"
#include "logging/oxen_logger.h"
#include "tor_address.h"

// This unholy hack of defining epee implementation outside of epee is here because of Monero's lack
// of quality code review that allowed someone to add circular dependencies between src/net/ and
// epee/net_utils_base.cpp.  See the comment in epee/include/net/net_utils_base.h for the sordid
// details.
//
// TODO: epee needs to die.

namespace epee::net_utils {

static auto logcat = oxen::log::Cat("global");

KV_SERIALIZE_MAP_CODE_BEGIN(network_address)
std::uint8_t type =
        static_cast<std::uint8_t>(is_store ? this_ref.get_type_id() : address_type::invalid);
if (!epee::serialization::perform_serialize<is_store>(type, stg, parent_section, "type"))
    return false;

switch (address_type(type)) {
    case address_type::ipv4:
        return this_ref.template serialize_addr<ipv4_network_address>(stg, parent_section);
    case address_type::ipv6:
        return this_ref.template serialize_addr<ipv6_network_address>(stg, parent_section);
    case address_type::tor:
        return this_ref.template serialize_addr<net::tor_address>(stg, parent_section);
    case address_type::i2p:
        return this_ref.template serialize_addr<net::i2p_address>(stg, parent_section);
    default:
        oxen::log::error(logcat, "Unsupported network address type: {}", (unsigned)type);
        return false;
}
KV_SERIALIZE_MAP_CODE_END()

}  // namespace epee::net_utils
