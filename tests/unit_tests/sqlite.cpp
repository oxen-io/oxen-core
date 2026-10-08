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

#include "blockchain_db/sqlite/rewards_db.h"
#include "common/guts.h"
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

// A sqlite.db as left by 11.4+ releases: the height in batch_db_info, and the fixup version in
// PRAGMA user_version.
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
CREATE TABLE batch_db_info(height INTEGER NOT NULL);
INSERT INTO batch_db_info(height) VALUES(1234);
CREATE TRIGGER make_recent AFTER UPDATE ON batch_db_info FOR EACH ROW BEGIN SELECT 1; END;
INSERT INTO batched_payments_accrued (address, amount) VALUES (x'0123456789', 42);
PRAGMA user_version = 1;
)");

  cryptonote::RewardsDB rewardsDB(cryptonote::network_type::FAKECHAIN, sql);

  EXPECT_EQ(rewardsDB.height, 1234);
  EXPECT_FALSE(has_table(sql, "batch_db_info"));
  ASSERT_TRUE(has_table(sql, "batch_db_height"));
  EXPECT_EQ(sql.conn().prepared_get<int64_t>("SELECT height FROM batch_db_height WHERE id = 1"), 1234);
  EXPECT_EQ(int_property(sql, "rewards_fixup_version"), 1);

  // The retention triggers moved to the new table along with the height
  rewardsDB.update_height(1235);
  EXPECT_EQ(sql.conn().prepared_get<int>(
                "SELECT COUNT(*) FROM batched_payments_accrued_recent WHERE height = 1235"),
            1);
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

TEST(SQLITE, BatchDbHeightSingleton)
{
  test::RewardsDBTest rewardsDB(cryptonote::network_type::FAKECHAIN, ":memory:");
  auto conn = rewardsDB.db.conn();
  auto row_count = [&] { return conn.prepared_get<int>("SELECT COUNT(*) FROM batch_db_height"); };

  EXPECT_EQ(row_count(), 1);
  for (int id : {1, 2, 0, -1})
    EXPECT_THROW(
        conn.prepared_exec("INSERT INTO batch_db_height (id, height) VALUES (?, 5)", id),
        std::exception) << "id " << id;
  EXPECT_THROW(conn.prepared_exec("INSERT INTO batch_db_height (height) VALUES (5)"), std::exception);
  EXPECT_EQ(row_count(), 1);
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
  EXPECT_NO_THROW(rewardsDB.save_payments(expected_payout, t3));
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
