#pragma once

#include <cassert>
#include <cstdint>
#include <string_view>

#include "common/formattable.h"

namespace cryptonote {

using namespace std::literals;

enum class txversion : uint16_t {
    v0 = 0,
    v1,
    v2_ringct,
    v3_per_output_unlock_times,
    v4_tx_types,
    _count,
};
enum class txtype : uint16_t {
    standard,
    state_change,
    key_image_unlock,
    stake,
    oxen_name_system,
    ethereum_new_service_node,
    ethereum_service_node_removal_request,
    ethereum_service_node_removal,
    ethereum_service_node_liquidated,
    _count
};

inline constexpr std::string_view to_string(txversion v) {
    switch (v) {
        case txversion::v1: return "1"sv;
        case txversion::v2_ringct: return "2_ringct"sv;
        case txversion::v3_per_output_unlock_times: return "3_per_output_unlock_times"sv;
        case txversion::v4_tx_types: return "4_tx_types"sv;
        default: assert(false); return "xx_unhandled_version"sv;
    }
}

inline constexpr std::string_view to_string(txtype type) {
    switch (type) {
        case txtype::standard: return "standard"sv;
        case txtype::state_change: return "state_change"sv;
        case txtype::key_image_unlock: return "key_image_unlock"sv;
        case txtype::stake: return "stake"sv;
        case txtype::oxen_name_system: return "oxen_name_system"sv;
        case txtype::ethereum_new_service_node: return "ethereum_new_service_node"sv;
        case txtype::ethereum_service_node_removal_request:
            return "ethereum_service_node_removal_request"sv;
        case txtype::ethereum_service_node_removal: return "ethereum_service_node_removal"sv;
        case txtype::ethereum_service_node_liquidated: return "ethereum_service_node_liquidated"sv;
        default: assert(false); return "xx_unhandled_type"sv;
    }
}

}  // namespace cryptonote

template <>
inline constexpr bool formattable::via_to_string<cryptonote::txversion> = true;
template <>
inline constexpr bool formattable::via_to_string<cryptonote::txtype> = true;
