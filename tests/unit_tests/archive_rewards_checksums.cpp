#include <gtest/gtest.h>

#include <algorithm>
#include <tuple>

#include "blockchain_db/sqlite/rewards_db.h"
#include "blockchain_db/sqlite/snapshots.h"
#include "common/guts.h"

namespace {

using cryptonote::network_type;
using cryptonote::RewardsDB;
namespace snapshots = cryptonote::snapshots;

constexpr int64_t CSUM_MOD = 789012345678901;
constexpr int64_t CORRECT_1890K_CHECKSUM = 22'402'200'527'873'036;

// A rewards database at fixup version `version` with the hard-coded 1,890,000 snapshot's rows at
// each of `heights` (so only a snapshot at 1,890,000 has its correct checksum), with each amount
// at the heights of `wrong_heights` one higher.
void make_db(
        session::sqlite::Database& sql,
        const std::vector<int64_t>& heights,
        const std::vector<int64_t>& wrong_heights = {},
        int version = 2) {
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

std::vector<int64_t> heights(session::sqlite::Database& sql) {
    std::vector<int64_t> hs;
    for (auto h : sql.conn().prepared_results<int64_t>(
                 "SELECT height FROM rewards_snapshot_heights ORDER BY height"))
        hs.push_back(h);
    return hs;
}

std::optional<int64_t> fixup_version(session::sqlite::Database& sql) {
    return sql.conn().prepared_maybe_get<int64_t>(
            "SELECT value FROM properties WHERE key = 'rewards_fixup_version'");
}

std::optional<int64_t> checksum(session::sqlite::Database& sql, int64_t height) {
    return sql.conn().prepared_get<std::optional<int64_t>>(
            "SELECT SUM(amount % ?) FROM rewards_snapshots WHERE height = ?", CSUM_MOD, height);
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
    const auto before_heights = heights(sql);
    started s{sql, net, separate, history};
    EXPECT_EQ(s.detach, std::nullopt);
    EXPECT_EQ(fixup_version(sql), 3);
    EXPECT_EQ(dump(sql), before);
    EXPECT_EQ(heights(sql), before_heights);
    EXPECT_EQ(s.rewards.height, before_heights.empty() ? 0 : before_heights.back());
}

}  // namespace

TEST(ArchiveRewardsChecksums, hard_coded_snapshot_has_the_correct_checksum) {
    session::sqlite::Database sql{":memory:"};
    make_db(sql, {1'890'000});
    EXPECT_EQ(checksum(sql, 1'890'000), CORRECT_1890K_CHECKSUM);
}

TEST(ArchiveRewardsChecksums, failed_checksum_rescans_from_the_hard_coded_snapshot) {
    // A 1,860,000 snapshot (which, with the 1,890,000 rows, fails its checksum) alongside a correct
    // 1,890,000 one; and a 1,890,000 one that fails its checksum
    for (auto [hs, wrong] :
         {std::pair<std::vector<int64_t>, std::vector<int64_t>>{
                  {1'850'000, 1'860'000, 1'890'000, 2'000'000, 2'239'200}, {}},
          std::pair<std::vector<int64_t>, std::vector<int64_t>>{
                  {1'850'000, 1'890'000, 2'000'000, 2'239'200}, {1'890'000}}}) {
        SCOPED_TRACE(hs.size());
        session::sqlite::Database sql{":memory:"};
        make_db(sql, hs, wrong);
        started s{sql};
        EXPECT_EQ(s.detach, 1'890'000);
        EXPECT_EQ(fixup_version(sql), 3);
        // Every snapshot from HF21 on is deleted, except a correct one at 1,890,000 (or the
        // hard-coded one loaded in place of a wrong one)
        EXPECT_EQ(heights(sql), (std::vector<int64_t>{1'850'000, 1'890'000}));
        EXPECT_EQ(checksum(sql, 1'890'000), CORRECT_1890K_CHECKSUM);
        EXPECT_EQ(s.rewards.height, 1'890'000);
        EXPECT_GT(sql.conn().prepared_get<int>("SELECT COUNT(*) FROM delayed_payments"), 0);

        // The recheck after the rescan finds every checksum correct
        EXPECT_EQ(s.rewards.fixup(/*recheck=*/true), std::nullopt);
    }
}

TEST(ArchiveRewardsChecksums, correct_checksums_are_only_marked) {
    session::sqlite::Database sql{":memory:"};
    make_db(sql, {1'850'000, 1'890'000, 2'000'000, 2'239'200}, {2'000'000, 2'239'200});
    expect_only_marked(sql);
}

TEST(ArchiveRewardsChecksums, without_the_checksum_heights_only_marked) {
    session::sqlite::Database sql{":memory:"};
    make_db(sql, {2'000'000, 2'239'200}, {2'000'000, 2'239'200});
    expect_only_marked(sql);
}

TEST(ArchiveRewardsChecksums, only_sqlite_archive_mainnet_nodes_rescan) {
    const std::vector<int64_t> hs{1'890'000, 2'239'200};
    for (auto [net, separate, history] :
         {std::tuple{network_type::MAINNET, true, uint64_t{0}},
          std::tuple{network_type::MAINNET, false, uint64_t{10'080}},
          std::tuple{network_type::TESTNET, false, uint64_t{0}}}) {
        session::sqlite::Database sql{":memory:"};
        make_db(sql, hs, hs);
        expect_only_marked(sql, net, separate, history);
    }
}

TEST(ArchiveRewardsChecksums, runs_once) {
    session::sqlite::Database sql{":memory:"};
    make_db(sql, {1'890'000, 2'239'200}, {1'890'000}, 3);
    expect_only_marked(sql);
}

TEST(ArchiveRewardsChecksums, older_databases_still_get_the_old_fixup) {
    session::sqlite::Database sql{":memory:"};
    make_db(sql, {1'860'000, 1'890'000, 2'239'200}, {}, 1);
    started s{sql, network_type::MAINNET, /*separate=*/true, /*history=*/10'080};
    EXPECT_EQ(s.detach, 1'890'000);
    EXPECT_EQ(fixup_version(sql), 2);
}
