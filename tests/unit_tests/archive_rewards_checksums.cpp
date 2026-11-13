#include <gtest/gtest.h>

#include <algorithm>
#include <tuple>

#include "blockchain_db/sqlite/rewards_db.h"
#include "blockchain_db/sqlite/snapshots.h"
#include "common/guts.h"
#include "cryptonote_basic/hardfork.h"

namespace {

using cryptonote::network_type;
using cryptonote::RewardsDB;
namespace snapshots = cryptonote::snapshots;

constexpr int64_t CSUM_MOD = 789012345678901;
constexpr int64_t CORRECT_2240K_CHECKSUM = 69'742'265'256'895'630;

// A rewards database at fixup version `version` with the compiled-in snapshot's rows at each of
// `heights` (so that only a snapshot at 2,240,000 has its correct checksum, and one at any other
// height of the checked ones fails), with each amount at the heights of `wrong_heights` one
// higher, and a delayed payment added at each of `delayed_heights`.
void make_db(
        session::sqlite::Database& sql,
        const std::vector<int64_t>& heights,
        const std::vector<int64_t>& wrong_heights = {},
        int version = 2,
        const std::vector<int64_t>& delayed_heights = {}) {
    {
        RewardsDB{network_type::MAINNET, sql};
    }
    auto conn = sql.conn();
    SQLite::Transaction tx{conn.sql};
    for (auto h : heights) {
        const int64_t error = std::ranges::count(wrong_heights, h);
        conn.prepared_exec("INSERT INTO rewards_snapshot_heights (height) VALUES (?)", h);
        for (const auto& r : snapshots::batched_payments)
            conn.prepared_exec(
                    "INSERT INTO rewards_snapshots (height, address, amount, payout_offset,"
                    " lifetime_locked_stakes, lifetime_unlocked_stakes,"
                    " lifetime_liquidated_stakes, lifetime_rewards)"
                    " VALUES (?, ?, ?, NULL, ?, ?, ?, ?)",
                    h,
                    tools::span_guts(r.addr),
                    r.amount + error,
                    r.lifetime_locked_stakes,
                    r.lifetime_unlocked_stakes,
                    r.lifetime_liquidated_stakes,
                    r.lifetime_rewards);
    }
    for (auto h : delayed_heights)
        conn.prepared_exec(
                "INSERT INTO delayed_payments (eth_address, amount, payout_height, height,"
                " block_height, block_tx_index, contributor_index)"
                " VALUES (?, 1000, ?, ?, ?, 0, 0)",
                tools::span_guts(snapshots::batched_payments[0].addr),
                h + 21'600,
                h,
                h - 4);
    conn.prepared_exec(
            "UPDATE properties SET value = ? WHERE key = 'rewards_fixup_version'", version);
    tx.commit();
}

using row = std::tuple<int64_t, std::string, int64_t, int64_t>;

std::vector<row> dump(session::sqlite::Database& sql) {
    std::vector<row> rows;
    for (auto r : sql.conn().prepared_results<int64_t, std::string, int64_t, int64_t>(
                 "SELECT height, hex(address), amount, lifetime_rewards FROM rewards_snapshots"
                 " ORDER BY height, address"))
        rows.push_back(r);
    return rows;
}

std::vector<int64_t> heights(session::sqlite::Database& sql, const std::string& table) {
    std::vector<int64_t> hs;
    for (auto h :
         sql.conn().prepared_results<int64_t>("SELECT height FROM " + table + " ORDER BY height"))
        hs.push_back(h);
    return hs;
}
std::vector<int64_t> snapshot_heights(session::sqlite::Database& sql) {
    return heights(sql, "rewards_snapshot_heights");
}
std::vector<int64_t> delayed_heights(session::sqlite::Database& sql) {
    return heights(sql, "delayed_payments");
}

std::optional<int64_t> fixup_version(session::sqlite::Database& sql) {
    return sql.conn().prepared_maybe_get<int64_t>(
            "SELECT value FROM properties WHERE key = 'rewards_fixup_version'");
}

std::optional<int64_t> checksum(session::sqlite::Database& sql, int64_t height) {
    return sql.conn().prepared_get<std::optional<int64_t>>(
            "SELECT SUM(amount % ?) FROM rewards_snapshots WHERE height = ?", CSUM_MOD, height);
}

uint64_t hf19() {
    return cryptonote::hard_fork_begins(network_type::MAINNET, cryptonote::hf::hf19_reward_batching)
            .value();
}

// Starts the rewards of `sql` as a node does, with the sqlite blockchain backend (unless
// `separate`) and keeping `history`, and runs the fixup.
struct started {
    RewardsDB rewards;
    std::optional<uint64_t> detach;

    started(session::sqlite::Database& sql,
            network_type net = network_type::MAINNET,
            bool separate = false,
            uint64_t history = 0) :
            rewards{net, sql} {
        rewards.shares_blockchain_db = !separate;
        rewards.kept_history = history;
        detach = rewards.fixup();
    }
};

// Checks that the fixup only raises the fixup version to 3, changing nothing else.
void expect_only_marked(
        session::sqlite::Database& sql,
        network_type net = network_type::MAINNET,
        bool separate = false,
        uint64_t history = 0) {
    const auto before = dump(sql);
    const auto before_heights = snapshot_heights(sql);
    const auto before_delayed = delayed_heights(sql);
    started s{sql, net, separate, history};
    EXPECT_EQ(s.detach, std::nullopt);
    EXPECT_EQ(fixup_version(sql), 3);
    EXPECT_EQ(dump(sql), before);
    EXPECT_EQ(snapshot_heights(sql), before_heights);
    EXPECT_EQ(delayed_heights(sql), before_delayed);
    EXPECT_EQ(s.rewards.height, before_heights.empty() ? 0 : before_heights.back());
}

// Checks that the fixup restores the rewards to `restored`, leaving the snapshots at `remaining`
// and the delayed payments at `delayed_remaining`, for the rescan from there, and that the recheck
// then passes.
void expect_restored(
        session::sqlite::Database& sql,
        uint64_t restored,
        const std::vector<int64_t>& remaining,
        const std::vector<int64_t>& delayed_remaining) {
    started s{sql};
    EXPECT_EQ(s.detach, restored);
    EXPECT_EQ(fixup_version(sql), 3);
    EXPECT_EQ(snapshot_heights(sql), remaining);
    EXPECT_EQ(delayed_heights(sql), delayed_remaining);
    EXPECT_EQ(s.rewards.height, restored);
    EXPECT_EQ(s.rewards.fixup(/*recheck=*/true), std::nullopt);
}

}  // namespace

TEST(ArchiveRewardsChecksums, compiled_snapshot_has_the_correct_checksum) {
    ASSERT_EQ(snapshots::height, 2'240'000);
    session::sqlite::Database sql{":memory:"};
    make_db(sql, {snapshots::height});
    EXPECT_EQ(checksum(sql, snapshots::height), CORRECT_2240K_CHECKSUM);
}

TEST(ArchiveRewardsChecksums, early_failure_above_the_compiled_snapshot) {
    session::sqlite::Database sql{":memory:"};
    make_db(sql,
            {1'850'000, 1'860'000, 2'000'000, 2'240'000, 2'241'600},
            {2'240'000},
            2,
            {1'860'000, 2'239'000, 2'241'000});
    expect_restored(sql, 2'240'000, {1'850'000, 2'240'000}, {1'860'000, 2'239'000});
    EXPECT_EQ(checksum(sql, 2'240'000), CORRECT_2240K_CHECKSUM);
}

TEST(ArchiveRewardsChecksums, early_failure_below_the_compiled_snapshot) {
    session::sqlite::Database sql{":memory:"};
    make_db(sql,
            {1'850'000, 1'860'000, 2'000'000, 2'239'080, 2'239'200},
            {},
            2,
            {1'849'000, 1'860'000, 2'239'000});
    expect_restored(sql, 1'850'000, {1'850'000}, {1'849'000});
}

TEST(ArchiveRewardsChecksums, late_failure) {
    // Snapshots between the checked heights aren't checked, so stand in for correct ones before a
    // late height that fails
    {
        session::sqlite::Database sql{":memory:"};
        make_db(sql, {1'850'000, 2'095'000, 2'100'000, 2'241'600});
        expect_restored(sql, 2'240'000, {1'850'000, 2'095'000, 2'240'000}, {});
        EXPECT_EQ(checksum(sql, 2'240'000), CORRECT_2240K_CHECKSUM);
    }
    {
        session::sqlite::Database sql{":memory:"};
        make_db(sql, {1'850'000, 2'095'000, 2'100'000, 2'239'200});
        expect_restored(sql, 2'095'000, {1'850'000, 2'095'000}, {});
    }
}

TEST(ArchiveRewardsChecksums, only_the_compiled_snapshot_height_fails) {
    session::sqlite::Database sql{":memory:"};
    make_db(sql, {1'850'000, 2'235'000, 2'240'000, 2'241'600}, {2'240'000});
    expect_restored(sql, 2'240'000, {1'850'000, 2'235'000, 2'240'000}, {});
    EXPECT_EQ(checksum(sql, 2'240'000), CORRECT_2240K_CHECKSUM);
}

TEST(ArchiveRewardsChecksums, nothing_failing_is_only_marked) {
    {
        session::sqlite::Database sql{":memory:"};
        make_db(sql, {1'850'000, 2'240'000, 2'241'600}, {2'241'600}, 2, {2'239'000, 2'241'000});
        expect_only_marked(sql);
    }
    {
        session::sqlite::Database sql{":memory:"};
        make_db(sql, {1'850'000, 2'239'200});
        expect_only_marked(sql);
    }
}

TEST(ArchiveRewardsChecksums, only_sqlite_archive_mainnet_nodes_are_checked) {
    const std::vector<int64_t> hs{1'860'000, 2'241'600};
    for (auto [net, separate, history] :
         {std::tuple{network_type::MAINNET, true, uint64_t{0}},
          std::tuple{network_type::MAINNET, false, uint64_t{10'080}},
          std::tuple{network_type::TESTNET, false, uint64_t{0}}}) {
        session::sqlite::Database sql{":memory:"};
        make_db(sql, hs, {}, 2, {1'860'000});
        expect_only_marked(sql, net, separate, history);
    }
}

TEST(ArchiveRewardsChecksums, runs_once) {
    session::sqlite::Database sql{":memory:"};
    make_db(sql, {1'860'000, 2'241'600}, {}, 3);
    expect_only_marked(sql);
}

TEST(ArchiveRewardsChecksums, older_databases_are_rescanned_from_the_start) {
    // Whatever the backend and history
    for (auto [separate, history] :
         {std::pair{false, uint64_t{0}},
          std::pair{true, uint64_t{0}},
          std::pair{false, uint64_t{10'080}}}) {
        session::sqlite::Database sql{":memory:"};
        make_db(sql, {1'850'000, 2'240'000, 2'241'600}, {}, 1, {1'860'000, 2'241'000});
        started s{sql, network_type::MAINNET, separate, history};
        EXPECT_EQ(s.detach, hf19() - 1);
        EXPECT_EQ(fixup_version(sql), 3);
        EXPECT_TRUE(snapshot_heights(sql).empty());
        EXPECT_TRUE(dump(sql).empty());
        EXPECT_TRUE(delayed_heights(sql).empty());
        EXPECT_EQ(s.rewards.height, 0);
    }
}

TEST(ArchiveRewardsChecksums, older_databases_before_hf21_or_off_mainnet_are_only_marked) {
    {
        session::sqlite::Database sql{":memory:"};
        make_db(sql, {1'840'000, 1'850'000}, {}, 1);
        expect_only_marked(sql);
    }
    {
        session::sqlite::Database sql{":memory:"};
        make_db(sql, {1'860'000, 2'241'600}, {}, 1, {1'860'000});
        expect_only_marked(sql, network_type::TESTNET);
    }
}
