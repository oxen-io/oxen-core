#pragma once

#include <map>
#include <random>
#include <vector>

#include "service_node_rules.h"

namespace service_nodes {
inline constexpr uint64_t MAX_ID = UNASSIGNED_SWARM_ID - 1;

using swarm_snode_map_t = std::map<swarm_id_t, std::vector<crypto::public_key>>;
struct swarm_size {
    swarm_id_t swarm_id;
    size_t size;
};
struct excess_pool_snode {
    crypto::public_key public_key;
    swarm_id_t swarm_id;
};

uint64_t get_new_swarm_id(const swarm_snode_map_t& swarm_to_snodes);

void calc_swarm_changes(swarm_snode_map_t& swarm_to_snodes, uint64_t seed);

}  // namespace service_nodes
