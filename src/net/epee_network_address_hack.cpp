#include "epee/net/net_utils_base.h"
#include "epee/storages/portable_storage.h"
#include "ipv4_address.h"
#include "logging/oxen_logger.h"

// This epee serialization code lives outside epee because it has to know about net::ipv4_address,
// which is not part of epee.
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
        return this_ref.template serialize_addr<net::ipv4_address>(stg, parent_section);
    case address_type::ipv6:
        return this_ref.template serialize_addr<ipv6_network_address>(stg, parent_section);
    default:
        oxen::log::error(logcat, "Unsupported network address type: {}", (unsigned)type);
        return false;
}
KV_SERIALIZE_MAP_CODE_END()

}  // namespace epee::net_utils
