#include <gtest/gtest.h>

#include <map>

#include "blockchain_db/sqlite/accrued_history.h"

namespace cryptonote {
// Reaches into the history to break one of its invariants, as only a bug could.
struct accrued_history_test_access {
    static void set_slot_height(
            accrued_history& h, const rewards_address& addr, uint64_t slot_of, uint64_t height) {
        h.wallets.at(addr).ring[accrued_history::slot(slot_of)].height = height;
    }
    static bool has_wallet(const accrued_history& h, const rewards_address& addr) {
        return h.wallets.count(addr);
    }
};
}  // namespace cryptonote

namespace {

using cryptonote::accrued_changes;
using cryptonote::accrued_history;
using cryptonote::accrued_row;
using cryptonote::REWARDS_HISTORY;
using cryptonote::rewards_address;
using cryptonote::rewards_address_less;

rewards_address addr(uint8_t i) {
    eth::address a{};
    a.data_[0] = i;
    return a;
}

accrued_row row(int64_t amount) {
    return {.amount = amount, .lifetime_rewards = amount};
}

using state = std::map<rewards_address, accrued_row, rewards_address_less>;

// Keeps the history and a straightforward recomputation of every height's rows side by side.
struct model {
    accrued_history history;
    std::map<uint64_t, state> expected;

    explicit model(uint64_t height, const state& start = {}) {
        history.reset(height, {start.begin(), start.end()});
        expected[height] = start;
    }

    void advance(const accrued_changes& changes) {
        auto h = history.newest() + 1;
        auto next = expected.at(h - 1);
        for (const auto& [a, r] : changes) {
            if (r)
                next[a] = *r;
            else
                next.erase(a);
        }
        expected[h] = next;
        history.advance(h, changes);
    }

    void rewind(uint64_t h) {
        history.rewind(h);
        expected.erase(expected.upper_bound(h), expected.end());
    }

    void check() const {
        ASSERT_LE(history.newest() - history.oldest() + 1, REWARDS_HISTORY);
        for (auto h = history.oldest(); h <= history.newest(); h++) {
            const auto& want = expected.at(h);
            auto rows = history.snapshot_rows(h);
            EXPECT_EQ(rows, cryptonote::accrued_rows(want.begin(), want.end())) << "height " << h;
            for (uint8_t i = 0; i < 20; i++) {
                auto r = history.lookup(addr(i), h);
                EXPECT_TRUE(r.known) << "height " << h;
                auto it = want.find(addr(i));
                EXPECT_EQ(r.row, it == want.end() ? std::nullopt : std::optional{it->second})
                        << "height " << h << ", address " << int{i};
            }
        }
        EXPECT_FALSE(history.lookup(addr(0), history.newest() + 1).known);
        if (history.oldest() > 0)
            EXPECT_FALSE(history.lookup(addr(0), history.oldest() - 1).known);
    }
};

// Varied changes, which differ between `round`s for the same height
accrued_changes changes_for(uint64_t h, int round) {
    accrued_changes c;
    c[addr(h % 5)] = row(h * 100 + round);
    if (h % 3 == 0)
        c[addr(10 + h % 4)] = row(h + round);
    if (h % 4 == 1)
        c[addr((h + 2) % 5)] = std::nullopt;
    return c;
}

TEST(accrued_history, rewind_then_advance_matches_recomputation) {
    model m{100, {{addr(0), row(1)}, {addr(1), row(2)}, {addr(7), row(70)}}};
    for (uint64_t h = 101; h <= 112; h++)
        m.advance(changes_for(h, 0));
    m.check();
    EXPECT_EQ(m.history.oldest(), 112 - REWARDS_HISTORY + 1);

    m.rewind(109);
    m.check();
    for (uint64_t h = 110; h <= 111; h++)
        m.advance(changes_for(h, 1));
    m.check();
    EXPECT_EQ(m.history.newest(), 111);
    // The abandoned heights' values aren't what is now there
    EXPECT_EQ(m.history.lookup(addr(110 % 5), 110).row, row(110 * 100 + 1));
}

TEST(accrued_history, untouched_wallet_is_copied_forward) {
    model m{0, {{addr(7), row(70)}}};
    for (int i = 0; i < 20; i++)
        m.advance({{addr(1), row(i)}});
    m.check();
    for (auto h = m.history.oldest(); h <= m.history.newest(); h++)
        EXPECT_EQ(m.history.lookup(addr(7), h).row, row(70));
}

TEST(accrued_history, rewind_erases_wallet_created_in_window) {
    model m{50, {{addr(0), row(1)}}};
    m.advance({});
    m.advance({{addr(3), row(30)}});  // 52
    m.advance({});
    m.check();
    m.rewind(51);
    m.check();
    EXPECT_FALSE(m.history.lookup(addr(3), 51).row);
    m.advance({});  // 52 again, without addr(3) this time
    m.check();
    EXPECT_FALSE(m.history.lookup(addr(3), 52).row);
}

TEST(accrued_history, rewind_below_oldest_holds_nothing) {
    model m{0, {{addr(0), row(1)}}};
    for (int i = 0; i < 12; i++)
        m.advance({{addr(0), row(i)}});
    auto below = m.history.oldest() - 1;
    m.history.rewind(below);
    EXPECT_FALSE(m.history.held());
    EXPECT_FALSE(m.history.lookup(addr(0), below).known);
    EXPECT_THROW(m.history.advance(below + 1, {}), std::logic_error);
    m.history.reset(below, {{addr(0), row(5)}});
    EXPECT_EQ(m.history.lookup(addr(0), below).row, row(5));
}

TEST(accrued_history, removal_and_transition) {
    // A transition at X removes the set A and creates the set B, as a block's changes.
    const uint64_t X = 200;
    model m{X - 3, {{addr(0), row(1)}, {addr(1), row(2)}, {addr(2), row(3)}}};
    m.advance({{addr(0), row(11)}});
    m.advance({{addr(1), row(12)}});
    accrued_changes transition;
    for (uint8_t i : {0, 1, 2})
        transition[addr(i)] = std::nullopt;
    for (uint8_t i : {10, 11})
        transition[addr(i)] = row(100 + i);
    m.advance(transition);
    m.check();
    EXPECT_FALSE(m.history.lookup(addr(0), X).row);
    EXPECT_EQ(m.history.lookup(addr(0), X - 1).row, row(11));

    m.rewind(X - 1);
    m.check();
    EXPECT_EQ(m.history.lookup(addr(1), X - 1).row, row(12));
    EXPECT_FALSE(m.history.lookup(addr(10), X - 1).row);
    m.advance(transition);
    m.check();

    // Once the oldest height is past the removal, the removed wallets are gone entirely
    for (uint64_t i = 0; i < REWARDS_HISTORY; i++)
        m.advance({});
    m.check();
    for (uint8_t i : {0, 1, 2})
        EXPECT_FALSE(m.history.lookup(addr(i), m.history.oldest()).row);
}

TEST(accrued_history, removed_readded_then_rewound_into_removal) {
    using access = cryptonote::accrued_history_test_access;
    model m{0, {{addr(0), row(1)}, {addr(1), row(2)}}};
    auto tick = [&m](accrued_changes c) {
        c[addr(1)] = row(m.history.newest() + 100);
        m.advance(c);
        m.check();
    };
    tick({});                         // 1
    tick({});                         // 2
    tick({{addr(0), std::nullopt}});  // 3: removed
    tick({});                         // 4
    tick({});                         // 5
    tick({{addr(0), row(60)}});       // 6: re-added
    tick({});                         // 7

    // Back into the removed stretch: the re-adding is undone, and the wallet is removed again (so
    // still found at the heights before 3, where it had its first row).
    m.rewind(5);
    m.check();
    EXPECT_FALSE(m.history.lookup(addr(0), 5).row);
    EXPECT_EQ(m.history.lookup(addr(0), 2).row, row(1));

    tick({});                         // 6, without re-adding it this time
    tick({{addr(0), row(70)}});       // 7: re-added
    tick({});                         // 8
    tick({{addr(0), std::nullopt}});  // 9: the final removal
    EXPECT_EQ(m.history.lookup(addr(0), 8).row, row(70));

    // It stays (for the lookups below its removal) until the oldest height held is past that
    while (m.history.oldest() < 9) {
        EXPECT_TRUE(access::has_wallet(m.history, addr(0))) << "oldest " << m.history.oldest();
        tick({});
    }
    EXPECT_FALSE(access::has_wallet(m.history, addr(0)));
    m.check();
}

TEST(accrued_history, payout_offset_change) {
    // As on localdev at HF21: an OXEN row (with a payout offset) removed by the transition and
    // added again, in the same block, without one.
    auto with_offset = row(5);
    with_offset.payout_offset = 3;
    model m{20, {{addr(0), with_offset}}};
    m.advance({});
    m.advance({{addr(0), row(6)}});  // 22
    m.advance({});
    m.check();
    EXPECT_EQ(m.history.lookup(addr(0), 21).row->payout_offset, 3);
    EXPECT_EQ(m.history.lookup(addr(0), 22).row->payout_offset, std::nullopt);

    m.rewind(21);
    m.check();
    EXPECT_EQ(m.history.snapshot_rows(21).at(0).second.payout_offset, 3);
    m.advance({});
    m.check();
    EXPECT_EQ(m.history.lookup(addr(0), 22).row, with_offset);
}

TEST(accrued_history, mismatched_slot_is_unknown) {
    model m{10, {{addr(0), row(1)}}};
    m.advance({});
    m.advance({});
    cryptonote::accrued_history_test_access::set_slot_height(m.history, addr(0), 11, 3);
#ifdef NDEBUG
    EXPECT_FALSE(m.history.lookup(addr(0), 11).known);
    EXPECT_TRUE(m.history.lookup(addr(0), 12).known);
    EXPECT_THROW(m.history.snapshot_rows(11), std::logic_error);
#else
    EXPECT_DEATH(m.history.lookup(addr(0), 11), "");
#endif
}

}  // namespace
