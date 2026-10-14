#include "peer_history.h"

namespace cryptonote {

void unhelpful_peers::add(
        const epee::net_utils::network_address& addr, uint64_t height, uint64_t history) {
    m_peers.insert_or_assign(addr, std::make_pair(height, history));
}

bool unhelpful_peers::contains(const epee::net_utils::network_address& addr) const {
    return m_peers.count(addr);
}

void unhelpful_peers::forget_servable(uint64_t need) {
    for (auto it = m_peers.begin(); it != m_peers.end();) {
        const auto& [height, history] = it->second;
        if (peer_can_serve(need, height, history))
            it = m_peers.erase(it);
        else
            ++it;
    }
}

}  // namespace cryptonote
