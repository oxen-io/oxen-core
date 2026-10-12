#include "history.h"

#include <common/format.h>
#include <cryptonote_basic/hardfork.h>
#include <cryptonote_core/service_node_rules.h>
#include <networks.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <stdexcept>

namespace cryptonote {

using namespace std::literals;

uint64_t history_minimum(network_type nettype, uint64_t height) {
    auto hf15 = hard_fork_begins(nettype, hf::hf15_ons);
    if (!hf15 || height < *hf15)
        return std::max(
                HISTORY_MIN_BLOCKS,
                service_nodes::staking_num_lock_blocks(nettype) + HISTORY_LOCK_MARGIN);
    return HISTORY_MIN_BLOCKS;
}

uint64_t history_window(network_type nettype, uint64_t history, uint64_t height) {
    if (history == 0)
        return 0;
    return std::max(history, history_minimum(nettype, height));
}

uint64_t parse_history(std::string_view value, network_type nettype) {
    if (value == "full"sv)
        return 0;

    uint64_t number = 0;
    auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), number);
    std::string_view unit{end, static_cast<size_t>(value.data() + value.size() - end)};
    if (ec != std::errc{} || end == value.data() || unit.size() > 1)
        throw std::invalid_argument{
                "Invalid history '{}': expected 'full', a number of blocks, or a duration such as "
                "2w, 3d or 12h"_format(value)};

    uint64_t blocks = number;
    if (!unit.empty()) {
        std::chrono::seconds per;
        switch (unit[0]) {
            case 'w': per = 7 * 24h; break;
            case 'd': per = 24h; break;
            case 'h': per = 1h; break;
            default:
                throw std::invalid_argument{
                        "Invalid history '{}': a duration's unit must be w, d or h"_format(value)};
        }
        if (number > static_cast<uint64_t>(std::chrono::seconds::max().count() / per.count()))
            throw std::invalid_argument{"Invalid history '{}': too long"_format(value)};
        blocks = get_config(nettype).BLOCKS_IN(number * per);
    }
    if (blocks < HISTORY_MIN_BLOCKS)
        throw std::invalid_argument{
                "Invalid history '{}' ({} blocks): it must be at least {} blocks"_format(
                        value, blocks, HISTORY_MIN_BLOCKS)};
    return blocks;
}

std::optional<uint64_t> history_complete_at(uint64_t history, uint64_t start, uint64_t height) {
    if (history == 0 || start == 0 || height >= start + history)
        return std::nullopt;
    return start + history;
}

}  // namespace cryptonote
