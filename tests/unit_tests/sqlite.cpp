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

#include "blockchain_db/sqlite/db_sqlite.h"

#include "../blockchain_sqlite_test.h"

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
  test::BlockchainSQLiteTest sqliteDB(cryptonote::network_type::FAKECHAIN, ":memory:");

  EXPECT_EQ(sqliteDB.batching_count(), 0);

  cryptonote::block_payments t1;

  cryptonote::address_parse_info wallet_address;

  cryptonote::get_account_address_from_str(wallet_address, cryptonote::network_type::FAKECHAIN, "LCFxT37LAogDn1jLQKf4y7aAqfi21DjovX9qyijaLYQSdrxY1U5VGcnMJMjWrD9RhjeK5Lym67wZ73uh9AujXLQ1RKmXEyL");

  t1[wallet_address.address] = 16500000001'789/2;

  bool success = false;
  success = sqliteDB.add_sn_rewards(t1);
  EXPECT_TRUE(success);

  EXPECT_EQ(sqliteDB.batching_count(), 1);

  std::vector<cryptonote::batch_sn_payment> p1;
  const auto expected_payout = wallet_address.address.next_payout_height(0, cryptonote::config::mainnet::config.BATCHING_INTERVAL);
  p1 = sqliteDB.get_sn_payments(expected_payout - 1);
  EXPECT_EQ(p1.size(), 0);

  std::vector<cryptonote::batch_sn_payment> p2;
  p2 = sqliteDB.get_sn_payments(expected_payout);
  EXPECT_EQ(p2.size(), 1);
  // We shouldn't get a fractional atomic OXEN amount in the payment amount:
  uint64_t expected_amount = 8250000000'000;
  EXPECT_EQ(p2[0].amount, expected_amount);

  // Pay an amount less than the database expects and test for failure
  std::vector<cryptonote::batch_sn_payment> t2;
  t2.emplace_back(wallet_address.address, expected_amount - 1000);
  EXPECT_FALSE(sqliteDB.save_payments(expected_payout, t2));

  // Pay the amount back out and expect the database to be empty
  std::vector<cryptonote::batch_sn_payment> t3;
  t3.emplace_back(wallet_address.address, expected_amount);
  success = sqliteDB.save_payments(expected_payout, t3);
  EXPECT_TRUE(success);
  EXPECT_EQ(sqliteDB.batching_count(), 0);
}

TEST(SQLITE, CalculateRewards)
{
  test::BlockchainSQLiteTest sqliteDB(cryptonote::network_type::TESTNET, ":memory:");

  cryptonote::block block;
  block.reward = 200;

  // Check that a single contributor receives 100% of the block reward
  service_nodes::service_node_info single_contributor{};
  single_contributor.portions_for_operator = 0;
  cryptonote::address_parse_info first_address{};
  cryptonote::get_account_address_from_str(first_address, cryptonote::network_type::TESTNET, "T6TzkJb5EiASaCkcH7idBEi1HSrpSQJE1Zq3aL65ojBMPZvqHNYPTL56i3dncGVNEYCG5QG5zrBmRiVwcg6b1cRM1SRNqbp44");
  single_contributor.contributors.emplace_back(0, first_address.address);
  single_contributor.contributors.back().amount = block.reward;
  auto hf_version = block.major_version;

  // Check that 3 contributor receives their portion of the block reward
  service_nodes::service_node_info multiple_contributors{};
  multiple_contributors.contributors.emplace_back(0, first_address.address);
  multiple_contributors.contributors.back().amount = 33;
  cryptonote::address_parse_info second_address{};
  cryptonote::get_account_address_from_str(second_address, cryptonote::network_type::TESTNET, "T6SjALssDNvPZnTnV7vr459SX632c4X5qjLKfHfzvS32RPuhH3vnJmP9fyiD6ZiMu4XPk8ofH95mNRDg5bUPWkmq1LGAnyP3B");
  multiple_contributors.contributors.emplace_back(0, second_address.address);
  multiple_contributors.contributors.back().amount = 33;
  cryptonote::address_parse_info third_address{};
  cryptonote::get_account_address_from_str(third_address, cryptonote::network_type::TESTNET, "T6SkkovCyLWViVDMgeJoF7X4vFrHnKX5jXyktaoGmRuNTdoFEx1xXu1joXdmeH9mx2LLNPq998fKKcsAHwdRJWhk126SapptR");
  multiple_contributors.contributors.emplace_back(0, third_address.address);
  multiple_contributors.contributors.back().amount = 34;
  cryptonote::block_payments rewards;
  sqliteDB.add_rewards(block.major_version, block.reward, multiple_contributors, rewards);

  auto& a1 = first_address.address;
  auto& a2 = second_address.address;
  auto& a3 = third_address.address;
  EXPECT_EQ(rewards[a1], 66);
  EXPECT_EQ(rewards[a2], 66);
  EXPECT_EQ(rewards[a3], 68);

  // Check that 3 contributors receives their portion of the block reward when the operator takes a 10% fee
  multiple_contributors.portions_for_operator = cryptonote::old::STAKING_PORTIONS/10;
  multiple_contributors.operator_address = first_address.address;
  block.reward = 1000;
  rewards.clear();
  sqliteDB.add_rewards(block.major_version, block.reward, multiple_contributors, rewards);
  // Operator gets 10%, remainder split among operator and contributors:
  EXPECT_EQ(rewards[a1], 99 + 297); // fee + share
  EXPECT_EQ(rewards[a2], 297);
  EXPECT_EQ(rewards[a3], 306);
}
