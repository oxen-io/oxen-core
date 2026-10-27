#include "accrued_history.h"

#include <common/format.h>
#include <common/guts.h>

#include <algorithm>
#include <cassert>

#include "logging/oxen_logger.h"

namespace cryptonote {

static auto logcat = oxen::log::Cat("blockchain.db.rewards");

static std::span<const unsigned char> address_bytes(const rewards_address& a) {
    return std::visit(
            [](const auto& addr) -> std::span<const unsigned char> {
                return tools::span_guts(addr);
            },
            a);
}

bool rewards_address_less::operator()(const rewards_address& a, const rewards_address& b) const {
    auto x = address_bytes(a), y = address_bytes(b);
    return std::lexicographical_compare(x.begin(), x.end(), y.begin(), y.end());
}

void accrued_history::reset(uint64_t height, const accrued_rows& rows) {
    wallets.clear();
    for (const auto& [addr, row] : rows) {
        auto& w = wallets[addr];
        w.first_height = height;
        w.ring[slot(height)] = {
                .height = height,
                .present = true,
                .payout_offset = row.payout_offset,
                .amount = row.amount,
                .lifetime_rewards = row.lifetime_rewards,
                .lifetime_locked_stakes = row.lifetime_locked_stakes,
                .lifetime_unlocked_stakes = row.lifetime_unlocked_stakes,
                .lifetime_liquidated_stakes = row.lifetime_liquidated_stakes};
    }
    min_height = current = height;
    nothing_held = false;
}

void accrued_history::advance(uint64_t height, const accrued_changes& changes) {
    if (nothing_held || height != current + 1)
        throw std::logic_error{"Internal error: rewards history at {} cannot advance to {}"_format(
                current, height)};

    const auto prev = slot(current), next = slot(height);
    for (auto& [addr, w] : wallets) {
        w.ring[next] = w.ring[prev];
        w.ring[next].height = height;
    }
    current = height;
    if (current + 1 >= REWARDS_HISTORY)
        min_height = std::max(min_height, current + 1 - REWARDS_HISTORY);

    for (const auto& [addr, row] : changes) {
        auto it = wallets.find(addr);
        if (row) {
            if (it == wallets.end())
                it = wallets.emplace(addr, wallet{.first_height = height}).first;
            auto& w = it->second;
            w.ring[next] = {
                    .height = height,
                    .present = true,
                    .payout_offset = row->payout_offset,
                    .amount = row->amount,
                    .lifetime_rewards = row->lifetime_rewards,
                    .lifetime_locked_stakes = row->lifetime_locked_stakes,
                    .lifetime_unlocked_stakes = row->lifetime_unlocked_stakes,
                    .lifetime_liquidated_stakes = row->lifetime_liquidated_stakes};
            w.removed_height.reset();
        } else if (it != wallets.end()) {
            auto& w = it->second;
            w.ring[next].present = false;
            if (!w.removed_height)
                w.removed_height = height;
        }
    }

    std::erase_if(wallets, [this](const auto& item) {
        return item.second.removed_height && *item.second.removed_height <= min_height;
    });
}

void accrued_history::rewind(uint64_t height) {
    if (!contains(height)) {
        if (height < min_height || nothing_held) {
            wallets.clear();
            min_height = current = height;
            nothing_held = true;
        }
        // (Rewinding to a height above the newest leaves it as it is.)
        return;
    }
    current = height;
    std::erase_if(
            wallets, [height](const auto& item) { return item.second.first_height > height; });
    for (auto& [addr, w] : wallets) {
        for (auto& s : w.ring)
            if (s.height != INVALID_HEIGHT && s.height > height)
                s.height = INVALID_HEIGHT;
        if (w.removed_height && *w.removed_height > height)
            w.removed_height.reset();
        // Rewound to while removed, but after a re-adding cleared the height it was removed at:
        // `height` is a conservative stand-in, which only delays dropping it.
        if (!w.removed_height && !w.ring[slot(height)].present)
            w.removed_height = height;
    }
}

accrued_lookup accrued_history::row_at(
        const rewards_address& addr, const wallet& w, uint64_t height) const {
    if (height < w.first_height)
        return {.known = true};
    const auto& s = w.ring[slot(height)];
    if (s.height != height) {
        oxen::log::error(
                logcat,
                "Internal error: rewards history slot for height {} holds height {} (held: {}-{})",
                height,
                s.height,
                min_height,
                current);
        assert(s.height == height);
        return {.known = false};
    }
    if (!s.present)
        return {.known = true};
    return {.known = true,
            .row = accrued_row{
                    .amount = s.amount,
                    .payout_offset = s.payout_offset,
                    .lifetime_locked_stakes = s.lifetime_locked_stakes,
                    .lifetime_unlocked_stakes = s.lifetime_unlocked_stakes,
                    .lifetime_liquidated_stakes = s.lifetime_liquidated_stakes,
                    .lifetime_rewards = s.lifetime_rewards}};
}

accrued_lookup accrued_history::lookup(const rewards_address& addr, uint64_t height) const {
    if (!contains(height))
        return {.known = false};
    auto it = wallets.find(addr);
    if (it == wallets.end())
        return {.known = true};
    return row_at(addr, it->second, height);
}

void accrued_history::for_each(
        uint64_t height,
        const std::function<void(const rewards_address&, const accrued_row&)>& f) const {
    if (!contains(height))
        throw std::logic_error{
                "Internal error: rewards history doesn't hold height {}"_format(height)};
    for (const auto& [addr, w] : wallets) {
        auto r = row_at(addr, w, height);
        if (!r.known)
            throw std::logic_error{
                    "Internal error: invalid rewards history slot for height {}"_format(height)};
        if (r.row)
            f(addr, *r.row);
    }
}

accrued_rows accrued_history::snapshot_rows(uint64_t height) const {
    accrued_rows rows;
    rows.reserve(wallets.size());
    for_each(height, [&rows](const auto& addr, const auto& row) { rows.emplace_back(addr, row); });
    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
        return rewards_address_less{}(a.first, b.first);
    });
    return rows;
}

}  // namespace cryptonote
