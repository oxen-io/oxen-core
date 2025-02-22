#include "p2p_protocol_defs.h"

#include <fmt/core.h>

#include <chrono>

#include "common/string_util.h"
#include "epee/string_tools.h"
#include "net/i2p_address.h"  // needed for serialization
#include "net/tor_address.h"  // needed for serialization

namespace nodetool {

std::string print_peerlist_to_string(const std::vector<peerlist_entry>& pl) {
    auto now = std::chrono::system_clock::now();
    std::string result;
    for (const auto& pe : pl) {
        result += "{:016x}\t{}\tpruning seed {}\tlast_seen {}"_format(
                pe.id,
                pe.adr.str(),
                pe.pruning_seed,
                pe.last_seen == 0
                        ? "never"s
                        : tools::friendly_duration(
                                  now - std::chrono::system_clock::from_time_t(pe.last_seen)));
    }
    return result;
}

KV_SERIALIZE_MAP_CODE_BEGIN(peerlist_entry)
KV_SERIALIZE(adr)
KV_SERIALIZE(id)
KV_SERIALIZE_OPT(last_seen, (int64_t)0)
KV_SERIALIZE_OPT(pruning_seed, (uint32_t)0)
// rpc_port is unused, but pass it along anyway to avoid breaking the protocol
uint16_t rpc_port = 0;
KV_SERIALIZE_VALUE(rpc_port);
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(anchor_peerlist_entry)
KV_SERIALIZE(adr)
KV_SERIALIZE(id)
KV_SERIALIZE(first_seen)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(connection_entry)
KV_SERIALIZE(adr)
KV_SERIALIZE(id)
KV_SERIALIZE(is_income)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(network_config)
KV_SERIALIZE(max_out_connection_count)
KV_SERIALIZE(max_in_connection_count)
KV_SERIALIZE(handshake_interval)
KV_SERIALIZE(packet_max_size)
KV_SERIALIZE(config_id)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(basic_node_data)
KV_SERIALIZE_VAL_POD_AS_BLOB(network_id)
KV_SERIALIZE(peer_id)
KV_SERIALIZE(my_port)
// Unused, but pass a 0 to avoid breaking the protocol
uint16_t rpc_port = 0;
KV_SERIALIZE_VALUE(rpc_port);
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(COMMAND_HANDSHAKE::request)
KV_SERIALIZE(node_data)
KV_SERIALIZE(payload_data)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(COMMAND_HANDSHAKE::response)
KV_SERIALIZE(node_data)
KV_SERIALIZE(payload_data)
KV_SERIALIZE(local_peerlist_new)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(COMMAND_TIMED_SYNC::request)
KV_SERIALIZE(payload_data)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(COMMAND_TIMED_SYNC::response)
KV_SERIALIZE(payload_data)
KV_SERIALIZE(local_peerlist_new)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(COMMAND_PING::request)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(COMMAND_PING::response)
KV_SERIALIZE(status)
KV_SERIALIZE(peer_id)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(COMMAND_REQUEST_SUPPORT_FLAGS::request)
KV_SERIALIZE_MAP_CODE_END()

KV_SERIALIZE_MAP_CODE_BEGIN(COMMAND_REQUEST_SUPPORT_FLAGS::response)
KV_SERIALIZE(support_flags)
KV_SERIALIZE_MAP_CODE_END()
}  // namespace nodetool
