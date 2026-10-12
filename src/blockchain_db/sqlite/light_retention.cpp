#include "light_retention.h"

#include <cryptonote_basic/hardfork.h>
#include <cryptonote_core/service_node_rules.h>

#include <algorithm>

namespace cryptonote {

uint64_t light_retention_blocks(network_type nettype, uint64_t height) {
    auto hf15 = hard_fork_begins(nettype, hf::hf15_ons);
    if (!hf15 || height < *hf15)
        return std::max(
                LIGHT_RETENTION_BLOCKS,
                service_nodes::staking_num_lock_blocks(nettype) + LIGHT_RETENTION_LOCK_MARGIN);
    return LIGHT_RETENTION_BLOCKS;
}

}  // namespace cryptonote
