// Copyright (c) 2021, The Oxen Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <gtest/gtest.h>

#include "blockchain_db/sqlite/light_retention.h"
#include "blockchain_db/sqlite/rewards_db.h"
#include "common/guts.h"
#include "cryptonote_core/service_node_rules.h"
#include "cryptonote_core/oxen_name_system.h"

#include "../rewards_db_test.h"

namespace {

bool has_table(session::sqlite::Database& db, std::string_view name) {
  return db.conn().table_exists(name);
}

std::optional<int64_t> int_property(session::sqlite::Database& db, std::string_view key) {
  return db.conn().prepared_maybe_get<int64_t>("SELECT value FROM properties WHERE key = ?", key);
}

}

// A sqlite.db as left by 11.4+ releases: the live values, with copies at recent and archive heights,
// the height in batch_db_info, and the fixup version in PRAGMA user_version.
TEST(SQLITE, LegacyRewardsUpgrade)
{
  session::sqlite::Database sql{":memory:"};
  sql.conn().sql.exec(R"(
CREATE TABLE batched_payments_accrued(
  address BLOB NOT NULL, amount INTEGER NOT NULL DEFAULT 0, payout_offset INTEGER,
  lifetime_locked_stakes INTEGER NOT NULL DEFAULT 0, lifetime_unlocked_stakes INTEGER NOT NULL DEFAULT 0,
  lifetime_liquidated_stakes INTEGER NOT NULL DEFAULT 0, lifetime_rewards INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(address) CHECK(amount >= 0));
CREATE TABLE batched_payments_accrued_recent(
  address BLOB NOT NULL, amount INTEGER NOT NULL DEFAULT 0, payout_offset INTEGER,
  height INTEGER NOT NULL DEFAULT 0,
  lifetime_locked_stakes INTEGER NOT NULL DEFAULT 0, lifetime_unlocked_stakes INTEGER NOT NULL DEFAULT 0,
  lifetime_liquidated_stakes INTEGER NOT NULL DEFAULT 0, lifetime_rewards INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(height, address) CHECK(amount >= 0));
CREATE TABLE batched_payments_accrued_archive(
  address BLOB NOT NULL, amount INTEGER NOT NULL DEFAULT 0, payout_offset INTEGER,
  height INTEGER NOT NULL DEFAULT 0,
  lifetime_locked_stakes INTEGER NOT NULL DEFAULT 0, lifetime_unlocked_stakes INTEGER NOT NULL DEFAULT 0,
  lifetime_liquidated_stakes INTEGER NOT NULL DEFAULT 0, lifetime_rewards INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(height, address) CHECK(amount >= 0));
CREATE TABLE batch_db_info(height INTEGER NOT NULL);
INSERT INTO batch_db_info(height) VALUES(1234);
CREATE TRIGGER make_recent AFTER UPDATE ON batch_db_info FOR EACH ROW BEGIN SELECT 1; END;
INSERT INTO batched_payments_accrued (address, amount, lifetime_rewards)
  VALUES (x'0123456789012345678901234567890123456789', 42, 42);
INSERT INTO batched_payments_accrued_recent (address, amount, height)
  VALUES (x'0123456789012345678901234567890123456789', 40, 1200),
         (x'0123456789012345678901234567890123456789', 41, 1233);
INSERT INTO batched_payments_accrued_archive (address, amount, height)
  VALUES (x'0123456789012345678901234567890123456789', 30, 1000);
PRAGMA user_version = 1;
)");

  cryptonote::RewardsDB rewardsDB(cryptonote::network_type::FAKECHAIN, sql);

  EXPECT_EQ(rewardsDB.height, 1234);
  for (auto old : {"batch_db_info", "batch_db_height", "batched_payments_accrued",
                   "batched_payments_accrued_recent", "batched_payments_accrued_archive"})
    EXPECT_FALSE(has_table(sql, old)) << old;
  EXPECT_EQ(sql.conn().prepared_get<int>(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger'"), 0);
  EXPECT_EQ(int_property(sql, "rewards_fixup_version"), 1);

  // The live values become the snapshot at their height, the archived ones snapshots at theirs,
  // and the recent ones too, but only at heights the SN list stores its state at.
  std::vector<int64_t> heights;
  for (auto h : sql.conn().prepared_results<int64_t>(
           "SELECT height FROM rewards_snapshot_heights ORDER BY height"))
    heights.push_back(h);
  EXPECT_EQ(heights, (std::vector<int64_t>{1000, 1200, 1234}));
  EXPECT_EQ(sql.conn().prepared_get<int64_t>(
                "SELECT amount FROM rewards_snapshots WHERE height = 1200"), 40);

  auto rows = rewardsDB.get_accrued_rows();
  ASSERT_EQ(rows.size(), 1);
  EXPECT_EQ(rows[0].second.amount, 42);
  EXPECT_EQ(rows[0].second.lifetime_rewards, 42);
}

// Snapshots are written at heights divisible by STATE_SNAPSHOT_INTERVAL and at archive heights;
// writing one keeps the three newest and those at archive heights the SN archive still keeps.
TEST(SQLITE, RewardsSnapshotRetention)
{
  test::RewardsDBTest rewardsDB(cryptonote::network_type::FAKECHAIN, ":memory:");
  cryptonote::block_payments payments;
  payments[eth::address{}].amount = cryptonote::reward_money::from_coin(5);
  rewardsDB.add_sn_rewards(cryptonote::hf::hf21_eth, payments, true);
  rewardsDB.publish_block();
  while (rewardsDB.height < 20'130)
    rewardsDB.publish_block();

  auto conn = rewardsDB.db.conn();
  std::vector<int64_t> heights;
  for (auto h : conn.prepared_results<int64_t>(
           "SELECT height FROM rewards_snapshot_heights ORDER BY height"))
    heights.push_back(h);
  EXPECT_EQ(heights, (std::vector<int64_t>{10'000, 20'000, 20'040, 20'100}));
  // The deleted snapshots' rows go with them
  EXPECT_EQ(conn.prepared_get<int>("SELECT COUNT(*) FROM rewards_snapshots"), 4);

  // A rewind past the in-memory heights loads a stored snapshot, deleting those above it
  EXPECT_TRUE(rewardsDB.can_restore(20'040));
  rewardsDB.blockchain_detached(20'040);
  EXPECT_EQ(rewardsDB.height, 20'040);
  ASSERT_EQ(rewardsDB.get_accrued_rows().size(), 1);
  EXPECT_EQ(conn.prepared_get<int>("SELECT COUNT(*) FROM rewards_snapshot_heights"), 3);
}

// Changes made while processing a block that isn't then added (such as an alt block's, which the
// SN list discards) never take effect, and a block's exits' delayed payments only come in through
// its add_block.
TEST(SQLITE, RewardsChangesOnlyThroughAddBlock)
{
  test::RewardsDBTest rewardsDB(cryptonote::network_type::FAKECHAIN, ":memory:");
  cryptonote::block_payments payments;
  payments[eth::address{}].amount = cryptonote::reward_money::from_coin(5);
  rewardsDB.add_sn_rewards(cryptonote::hf::hf21_eth, payments, true);
  rewardsDB.discard_pending();
  rewardsDB.publish_block();
  EXPECT_TRUE(rewardsDB.get_accrued_rows().empty());

  cryptonote::block b{};
  b.major_version = cryptonote::hf::hf9_service_nodes;
  b.miner_tx.emplace();
  b.miner_tx->vin.push_back(cryptonote::txin_gen{rewardsDB.height + 1});
  service_nodes::block_add_result block_add{};
  auto& exited = block_add.exited_stakes.emplace_back();
  exited.stake.amount = cryptonote::reward_money::from_coin(1000);
  exited.stake.block_height = 2;
  exited.payout_height = rewardsDB.height + 10;
  service_nodes::service_node_list::state_t sn_state{nullptr};
  ASSERT_TRUE(rewardsDB.add_block(b, sn_state, block_add));
  EXPECT_EQ(rewardsDB.height, 2);
  auto delayed = rewardsDB.get_delayed_payments();
  ASSERT_EQ(delayed.size(), 1);
  EXPECT_EQ(delayed.begin()->second.amount.to_coin(), 1000);
  EXPECT_EQ(rewardsDB.db.conn().prepared_get<int>("SELECT COUNT(*) FROM delayed_payments"), 1);
}

// Before HF9 the rewards follow the chain from wherever they were reset to, as the service node
// list does, and carry on from there at HF9.
TEST(SQLITE, RewardsFollowChainBeforeHF9)
{
  test::RewardsDBTest rewardsDB(cryptonote::network_type::FAKECHAIN, ":memory:");
  rewardsDB.reset_database(100);
  EXPECT_EQ(rewardsDB.height, 100);

  service_nodes::service_node_list::state_t sn_state{nullptr};
  auto add = [&](cryptonote::hf version, uint64_t height) {
    cryptonote::block b{};
    b.major_version = version;
    b.miner_tx.emplace();
    b.miner_tx->vin.push_back(cryptonote::txin_gen{height});
    return rewardsDB.add_block(b, sn_state, {});
  };
  EXPECT_TRUE(add(cryptonote::hf::hf7, 1));
  EXPECT_EQ(rewardsDB.height, 1);
  EXPECT_TRUE(add(cryptonote::hf::hf7, 2));
  EXPECT_EQ(rewardsDB.height, 2);
  EXPECT_TRUE(add(cryptonote::hf::hf9_service_nodes, 3));
  EXPECT_EQ(rewardsDB.height, 3);
  EXPECT_FALSE(add(cryptonote::hf::hf9_service_nodes, 5));
  EXPECT_EQ(rewardsDB.height, 3);
}

// The in-memory heights answer queries at, and restores to, the most recent heights.
TEST(SQLITE, RewardsHistory)
{
  test::RewardsDBTest rewardsDB(cryptonote::network_type::FAKECHAIN, ":memory:");
  eth::address a{}, b{}, never{};
  b.data_[0] = 1;
  never.data_[0] = 2;
  for (int i = 1; i <= 10; i++) {
    cryptonote::block_payments payments;
    payments[a].amount = cryptonote::reward_money::from_coin(1);
    if (i == 6)
      payments[b].amount = cryptonote::reward_money::from_coin(7);
    rewardsDB.add_sn_rewards(cryptonote::hf::hf21_eth, payments, true);
    rewardsDB.publish_block();
  }

  EXPECT_EQ(rewardsDB.get_accrued_rewards(a).amount.to_coin(), 10);
  ASSERT_TRUE(rewardsDB.get_accrued_rewards(a, 5));
  EXPECT_EQ(rewardsDB.get_accrued_rewards(a, 5)->amount.to_coin(), 5);

  // At the current height, and at a held one: an address with values; one without, which is an
  // authoritative zero, with `found` false; and, at a height not held, nothing known at all.
  for (uint64_t h : {uint64_t{10}, uint64_t{5}}) {
    auto with = rewardsDB.get_accrued_rewards(a, h);
    ASSERT_TRUE(with) << h;
    EXPECT_TRUE(with->found) << h;
    EXPECT_EQ(with->height, h);
    EXPECT_EQ(with->amount.to_coin(), h);

    auto without = rewardsDB.get_accrued_rewards(never, h);
    ASSERT_TRUE(without) << h;
    EXPECT_FALSE(without->found) << h;
    EXPECT_EQ(without->amount.to_coin(), 0);
  }
  EXPECT_FALSE(rewardsDB.get_accrued_rewards(never).found);
  EXPECT_FALSE(rewardsDB.get_accrued_rewards(a, 10 - cryptonote::REWARDS_HISTORY));
  EXPECT_FALSE(rewardsDB.get_accrued_rewards(a, 11));
  // An address that first got values within the held heights has none before then
  EXPECT_FALSE(rewardsDB.get_accrued_rewards(b, 5)->found);
  EXPECT_TRUE(rewardsDB.get_accrued_rewards(b, 6)->found);

  ASSERT_TRUE(rewardsDB.can_restore(5));
  rewardsDB.blockchain_detached(5);
  EXPECT_EQ(rewardsDB.get_accrued_rewards(a).amount.to_coin(), 5);
  EXPECT_FALSE(rewardsDB.get_accrued_rewards(b).found);
  EXPECT_FALSE(rewardsDB.get_accrued_rewards(a, 6));
}

// The legacy tables aren't STRICT, so they can hold values the current tables can't take (such as
// the TEXT addresses of pre-11.4.0 code, beside BLOB ones, as some testnet databases written by
// development builds have).  The migration says where, and leaves the legacy tables as they were.
TEST(SQLITE, LegacyRewardsUnmigratableValue)
{
  session::sqlite::Database sql{":memory:"};
  auto conn = sql.conn();
  conn.sql.exec(R"(
CREATE TABLE batched_payments_accrued(
  address BLOB NOT NULL, amount INTEGER NOT NULL DEFAULT 0, payout_offset INTEGER,
  lifetime_locked_stakes INTEGER NOT NULL DEFAULT 0, lifetime_unlocked_stakes INTEGER NOT NULL DEFAULT 0,
  lifetime_liquidated_stakes INTEGER NOT NULL DEFAULT 0, lifetime_rewards INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(address) CHECK(amount >= 0));
CREATE TABLE batched_payments_accrued_recent(
  address BLOB NOT NULL, amount INTEGER NOT NULL DEFAULT 0, payout_offset INTEGER,
  height INTEGER NOT NULL DEFAULT 0,
  lifetime_locked_stakes INTEGER NOT NULL DEFAULT 0, lifetime_unlocked_stakes INTEGER NOT NULL DEFAULT 0,
  lifetime_liquidated_stakes INTEGER NOT NULL DEFAULT 0, lifetime_rewards INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(height, address) CHECK(amount >= 0));
CREATE TABLE batch_db_info(height INTEGER NOT NULL);
INSERT INTO batch_db_info(height) VALUES(1234);
INSERT INTO batched_payments_accrued (address, amount)
  VALUES (x'0123456789012345678901234567890123456789', 42);
INSERT INTO batched_payments_accrued_recent (address, amount, height)
  VALUES (x'0123456789012345678901234567890123456789', 41, 1200),
         ('0x1111111111111111111111111111111111111111', 9, 1200),
         ('0x2222222222222222222222222222222222222222', 8, 1200);
PRAGMA user_version = 2;
)");

  try {
    cryptonote::RewardsDB rewardsDB(cryptonote::network_type::FAKECHAIN, sql);
    FAIL() << "migration should have failed";
  } catch (const std::exception& e) {
    EXPECT_NE(
        std::string_view{e.what()}.find(
            "Unable to migrate the legacy rewards table batched_payments_accrued_recent: its "
            "address column holds 2 text value(s), where only 'blob' can be migrated"),
        std::string_view::npos)
        << e.what();
  }

  // Everything the attempt did, including creating the tables it was missing, was rolled back
  for (auto table : {"batched_payments_accrued", "batched_payments_accrued_recent", "batch_db_info"})
    EXPECT_TRUE(has_table(sql, table)) << table;
  for (auto table : {"rewards_snapshots", "rewards_snapshot_heights", "batch_db_height",
                     "batched_payments_accrued_archive", "delayed_payments"})
    EXPECT_FALSE(has_table(sql, table)) << table;
  EXPECT_EQ(conn.prepared_get<int>("SELECT COUNT(*) FROM batched_payments_accrued_recent"), 3);
  EXPECT_EQ(conn.prepared_get<int>("SELECT height FROM batch_db_info"), 1234);
}

TEST(SQLITE, NewRewardsFixupVersion)
{
  session::sqlite::Database sql{":memory:"};
  // A database's user_version isn't the rewards' to take, if it already has one of its own
  sql.conn().sql.exec("PRAGMA user_version = 1");
  cryptonote::RewardsDB rewardsDB(cryptonote::network_type::FAKECHAIN, sql);
  EXPECT_EQ(int_property(sql, "rewards_fixup_version"), 2);
  EXPECT_EQ(sql.conn().prepared_get<int>("PRAGMA user_version"), 1);
}

// An ons.db (or lns.db) as left by earlier releases: tables without the ons_ prefix, and the
// settings in a single-row table.
TEST(SQLITE, LegacyONSUpgrade)
{
  session::sqlite::Database sql{":memory:"};
  crypto::ed25519_public_key pk{};
  pk.data_[0] = 0x42;
  auto owner = ons::make_ed25519_owner(pk);
  crypto::hash top_hash{};
  top_hash.data_[0] = 0x99;
  crypto::hash txid{};
  txid.data_[0] = 0x77;
  {
    auto conn = sql.conn();
    conn.sql.exec(R"(
CREATE TABLE owner(id INTEGER PRIMARY KEY AUTOINCREMENT, address BLOB NOT NULL UNIQUE);
CREATE TABLE settings(id INTEGER PRIMARY KEY NOT NULL, top_height INTEGER NOT NULL,
  top_hash VARCHAR NOT NULL, version INTEGER NOT NULL, pruned_height INTEGER NOT NULL DEFAULT 0);
CREATE TABLE mappings(id INTEGER PRIMARY KEY NOT NULL, type INTEGER NOT NULL,
  name_hash VARCHAR NOT NULL, encrypted_value BLOB NOT NULL, txid BLOB NOT NULL,
  owner_id INTEGER NOT NULL REFERENCES owner(id), backup_owner_id INTEGER REFERENCES owner(id),
  update_height INTEGER NOT NULL, expiration_height INTEGER);
CREATE INDEX owner_id_index ON mappings(owner_id);
CREATE INDEX backup_owner_index ON mappings(backup_owner_id);
CREATE UNIQUE INDEX name_type_update ON mappings (name_hash, type, update_height DESC);
CREATE INDEX mapping_type_name_exp ON mappings (type, name_hash, expiration_height DESC);
)");
    conn.prepared_exec("INSERT INTO owner (address) VALUES (?)", tools::span_guts(owner));
    conn.prepared_exec(
        "INSERT INTO settings VALUES (1, 100, ?, 2, 50)", tools::span_guts(top_hash));
    conn.prepared_exec(
        "INSERT INTO mappings VALUES (1, 0, ?, x'00112233', ?, 1, NULL, 10, NULL)",
        std::string(43, 'A') + "=",
        tools::span_guts(txid));
  }

  {
    ons::name_system_db ons;
    ASSERT_TRUE(ons.init(nullptr, cryptonote::network_type::FAKECHAIN, sql));

    for (auto old : {"owner", "mappings", "settings", "ons_settings"})
      EXPECT_FALSE(has_table(sql, old)) << old;
    EXPECT_TRUE(has_table(sql, "ons_owners"));
    EXPECT_TRUE(has_table(sql, "ons_mappings"));
    EXPECT_EQ(sql.conn().prepared_get<int>(
                  "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN "
                  "('owner_id_index', 'backup_owner_index', 'name_type_update', 'mapping_type_name_exp')"),
              0);
    EXPECT_EQ(sql.conn().prepared_get<int>(
                  "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND tbl_name = 'ons_mappings'"
                  " AND name LIKE 'ons_mappings_%'"),
              4);
    // The foreign keys follow the owner table's rename
    EXPECT_NE(sql.conn().prepared_get<std::string>(
                  "SELECT sql FROM sqlite_master WHERE name = 'ons_mappings'").find("ons_owners"),
              std::string::npos);

    EXPECT_EQ(int_property(sql, "ons_top_height"), 100);
    EXPECT_EQ(int_property(sql, "ons_version"), 2);
    EXPECT_EQ(int_property(sql, "ons_pruned_height"), 50);
    auto settings = ons.get_settings();
    ASSERT_TRUE(settings);
    EXPECT_EQ(settings.top_height, 100);
    EXPECT_EQ(settings.top_hash, top_hash);
    EXPECT_EQ(settings.version, 2);

    auto mappings = ons.get_mappings_by_owner(owner);
    ASSERT_EQ(mappings.size(), 1);
    EXPECT_EQ(mappings[0].update_height, 10);
    EXPECT_EQ(mappings[0].txid, txid);
  }
}

TEST(SQLITE, AddressModulus)
{
  cryptonote::address_parse_info wallet_address;
  cryptonote::get_account_address_from_str(wallet_address, cryptonote::network_type::TESTNET, "T6TzkJb5EiASaCkcH7idBEi1HSrpSQJE1Zq3aL65ojBMPZvqHNYPTL56i3dncGVNEYCG5QG5zrBmRiVwcg6b1cRM1SRNqbp44");

  EXPECT_EQ(wallet_address.address.modulus(10), 0);
  EXPECT_EQ(wallet_address.address.modulus(100), 90);

  EXPECT_EQ(wallet_address.address.next_payout_height(50, 100), 90);
  EXPECT_EQ(wallet_address.address.next_payout_height(100, 100), 190);
}

TEST(SQLITE, AddSNRewards)
{
  test::RewardsDBTest rewardsDB(cryptonote::network_type::FAKECHAIN, ":memory:");

  EXPECT_EQ(rewardsDB.batching_count(cryptonote::hf::hf19_reward_batching), 0);

  cryptonote::block_payments t1;

  cryptonote::address_parse_info wallet_address;

  cryptonote::get_account_address_from_str(wallet_address, cryptonote::network_type::FAKECHAIN, "LCFxT37LAogDn1jLQKf4y7aAqfi21DjovX9qyijaLYQSdrxY1U5VGcnMJMjWrD9RhjeK5Lym67wZ73uh9AujXLQ1RKmXEyL");

  t1[wallet_address.address].amount = cryptonote::reward_money::from_intermediate(16'500000001'789/2);

  EXPECT_NO_THROW(rewardsDB.add_sn_rewards(cryptonote::hf::hf19_reward_batching, t1, true));
  // Pending until the block is published
  EXPECT_EQ(rewardsDB.batching_count(cryptonote::hf::hf19_reward_batching), 0);
  rewardsDB.publish_block();
  EXPECT_EQ(rewardsDB.batching_count(cryptonote::hf::hf19_reward_batching), 1);

  std::vector<cryptonote::batch_sn_payment> p1;
  const auto expected_payout = wallet_address.address.next_payout_height(0, cryptonote::config::mainnet::config.BATCHING_INTERVAL);
  p1 = rewardsDB.get_sn_payments(expected_payout - 1);
  EXPECT_EQ(p1.size(), 0);

  std::vector<cryptonote::batch_sn_payment> p2;
  p2 = rewardsDB.get_sn_payments(expected_payout);
  EXPECT_EQ(p2.size(), 1);
  // We shouldn't get a fractional atomic OXEN amount in the payment amount:
  auto expected_amount = cryptonote::reward_money::from_coin(8'250000000);
  EXPECT_EQ(p2[0].amount, expected_amount);

  // Pay an amount less than the database expects and test for failure
  std::vector<cryptonote::batch_sn_payment> t2;
  t2.emplace_back(wallet_address.address, expected_amount - cryptonote::reward_money::from_coin(1));
  EXPECT_FALSE(rewardsDB.save_payments(expected_payout, t2));

  // Pay the amount back out and expect the database to be empty
  std::vector<cryptonote::batch_sn_payment> t3;
  t3.emplace_back(wallet_address.address, expected_amount);
  EXPECT_TRUE(rewardsDB.save_payments(expected_payout, t3));
  rewardsDB.publish_block();
  EXPECT_EQ(rewardsDB.batching_count(cryptonote::hf::hf19_reward_batching), 0);
}

TEST(SQLITE, CalculateRewards)
{
  test::RewardsDBTest rewardsDB(cryptonote::network_type::TESTNET, ":memory:");
  auto reward = cryptonote::reward_money::from_coin(200);
  auto hf_version = cryptonote::hf::hf19_reward_batching;

  // Check that a single contributor receives 100% of the block reward
  cryptonote::block_payments rewards;
  cryptonote::address_parse_info first_address{};
  cryptonote::get_account_address_from_str(first_address, cryptonote::network_type::TESTNET, "T6TzkJb5EiASaCkcH7idBEi1HSrpSQJE1Zq3aL65ojBMPZvqHNYPTL56i3dncGVNEYCG5QG5zrBmRiVwcg6b1cRM1SRNqbp44");
  {
    service_nodes::service_node_info single_contributor{};
    single_contributor.version = service_nodes::service_node_info::version_t::v7_decommission_reason;
    auto& contributor = single_contributor.contributors.emplace_back();
    single_contributor.portions_for_operator = 0;
    contributor.address = first_address.address;
    contributor.reserved = 0;
    contributor.amount = reward.to_coin();
    single_contributor.staking_requirement = contributor.amount;

    rewardsDB.add_rewards(hf_version, reward, single_contributor, rewards);
    EXPECT_EQ(rewards[first_address.address].amount.to_coin(), reward.to_coin());
  }

  // Check that 3 contributor receives their portion of the block reward
  service_nodes::service_node_info multiple_contributors{};
  multiple_contributors.version = service_nodes::service_node_info::version_t::v7_decommission_reason;
  auto& contributor1 = multiple_contributors.contributors.emplace_back();
  contributor1.address = first_address.address;
  contributor1.reserved = 0;
  contributor1.amount = 33;
  cryptonote::address_parse_info second_address{};
  cryptonote::get_account_address_from_str(second_address, cryptonote::network_type::TESTNET, "T6SjALssDNvPZnTnV7vr459SX632c4X5qjLKfHfzvS32RPuhH3vnJmP9fyiD6ZiMu4XPk8ofH95mNRDg5bUPWkmq1LGAnyP3B");
  auto& contributor2 = multiple_contributors.contributors.emplace_back();
  contributor2.address = second_address.address;
  contributor2.reserved = 0;
  contributor2.amount = 33;
  cryptonote::address_parse_info third_address{};
  cryptonote::get_account_address_from_str(third_address, cryptonote::network_type::TESTNET, "T6SkkovCyLWViVDMgeJoF7X4vFrHnKX5jXyktaoGmRuNTdoFEx1xXu1joXdmeH9mx2LLNPq998fKKcsAHwdRJWhk126SapptR");
  auto& contributor3 = multiple_contributors.contributors.emplace_back();
  contributor3.address = third_address.address;
  contributor3.reserved = 0;
  contributor3.amount = 34;
  for (const auto& c : multiple_contributors.contributors)
      multiple_contributors.staking_requirement += c.amount;

  rewards.clear();
  rewardsDB.add_rewards(hf_version, reward, multiple_contributors, rewards);

  auto& a1 = first_address.address;
  auto& a2 = second_address.address;
  auto& a3 = third_address.address;
  EXPECT_EQ(rewards[a1].amount.to_coin(), 66);
  EXPECT_EQ(rewards[a2].amount.to_coin(), 66);
  EXPECT_EQ(rewards[a3].amount.to_coin(), 68);

  // Check that 3 contributors receives their portion of the block reward when the operator takes a 10% fee
  multiple_contributors.portions_for_operator = cryptonote::old::STAKING_PORTIONS/10;
  multiple_contributors.operator_address = first_address.address;
  reward = cryptonote::reward_money::from_coin(1000);
  rewards.clear();
  rewardsDB.add_rewards(hf_version, reward, multiple_contributors, rewards);
  // Operator gets 10%, remainder split among operator and contributors:
  EXPECT_EQ(rewards[a1].amount.to_coin(), 99 + 297); // fee + share
  EXPECT_EQ(rewards[a2].amount.to_coin(), 297);
  EXPECT_EQ(rewards[a3].amount.to_coin(), 306);
}

TEST(SQLITE, LightRetentionWindow)
{
  using cryptonote::light_retention_blocks;
  using cryptonote::network_type;
  constexpr auto main = network_type::MAINNET;

  // The staking lock period (30 days of blocks) plus the margin up to the last block before HF15;
  // one week from HF15 on.
  constexpr uint64_t early_window = 21'600 + cryptonote::LIGHT_RETENTION_LOCK_MARGIN;
  EXPECT_EQ(service_nodes::staking_num_lock_blocks(main), 21'600);
  EXPECT_EQ(cryptonote::LIGHT_RETENTION_BLOCKS, 5'040);
  EXPECT_EQ(light_retention_blocks(main, 0), early_window);
  EXPECT_EQ(light_retention_blocks(main, 101'250), early_window);
  EXPECT_EQ(light_retention_blocks(main, 161'849), early_window);
  EXPECT_EQ(light_retention_blocks(main, 496'968), early_window);
  EXPECT_EQ(light_retention_blocks(main, 496'969), 5'040);
  EXPECT_EQ(light_retention_blocks(main, 2'130'531), 5'040);

  // Testnet's staking lock period is shorter than a week, and it reaches HF15 at height 6.
  for (uint64_t h : {0, 5, 6, 100'000, 1'000'000})
    EXPECT_EQ(light_retention_blocks(network_type::TESTNET, h), 5'040);
}
