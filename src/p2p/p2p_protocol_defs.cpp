#include "p2p_protocol_defs.h"

#include <fmt/core.h>

#include <chrono>

#include "common/guts.h"
#include "common/string_util.h"
#include "cryptonote_protocol/peer_history.h"
#include "serialization/levin_kv/archive.h"

namespace nodetool {

std::string print_peerlist_to_string(const std::vector<peerlist_entry>& pl) {
    auto now = std::chrono::system_clock::now();
    std::string result;
    for (const auto& pe : pl) {
        result += "{:016x}\t{}\tlast_seen {}\thistory {}\n"_format(
                pe.id,
                pe.adr.to_string(),
                pe.last_seen == 0
                        ? "never"s
                        : tools::friendly_duration(
                                  now - std::chrono::system_clock::from_time_t(pe.last_seen)),
                cryptonote::describe_history(pe.history));
    }
    return result;
}

void peerlist_entry::serialize(levin_kv::archive& ar) {
    ar.value("adr", adr);
    ar.value("id", id);
    ar.value_or("last_seen", last_seen, int64_t{0});
    // rpc_port is unused, but pass it along anyway to avoid breaking the protocol
    uint16_t rpc_port = 0;
    ar.value("rpc_port", rpc_port);
    ar.value("history", history);
}

void basic_node_data::serialize(levin_kv::archive& ar) {
    ar.value("network_id", tools::byte_span(network_id));
    ar.value("peer_id", peer_id);
    ar.value("my_port", my_port);
    // Unused, but pass a 0 to avoid breaking the protocol
    uint16_t rpc_port = 0;
    ar.value("rpc_port", rpc_port);
}

void COMMAND_HANDSHAKE::request::serialize(levin_kv::archive& ar) {
    ar.value("node_data", node_data);
    ar.value("payload_data", payload_data);
}

void COMMAND_HANDSHAKE::response::serialize(levin_kv::archive& ar) {
    ar.value("node_data", node_data);
    ar.value("payload_data", payload_data);
    ar.value("local_peerlist_new", local_peerlist_new);
}

void COMMAND_TIMED_SYNC::request::serialize(levin_kv::archive& ar) {
    ar.value("payload_data", payload_data);
}

void COMMAND_TIMED_SYNC::response::serialize(levin_kv::archive& ar) {
    ar.value("payload_data", payload_data);
    ar.value("local_peerlist_new", local_peerlist_new);
}

void COMMAND_PING::request::serialize(levin_kv::archive&) {}

void COMMAND_PING::response::serialize(levin_kv::archive& ar) {
    ar.value("status", status);
    ar.value("peer_id", peer_id);
}

void COMMAND_REQUEST_SUPPORT_FLAGS::request::serialize(levin_kv::archive&) {}

void COMMAND_REQUEST_SUPPORT_FLAGS::response::serialize(levin_kv::archive& ar) {
    ar.value("support_flags", support_flags);
}
}  // namespace nodetool
