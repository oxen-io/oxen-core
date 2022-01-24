// Copyright (c) 2021, The Oxen Project
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

#include "db_sqlite.h"

#include <sodium.h>
#include <SQLiteCpp/SQLiteCpp.h>
#include <sqlite3.h>

#include <string>
#include <iostream>
#include <cassert>

#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/service_node_list.h"
#include "common/string_util.h"

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "blockchain.db.sqlite"

namespace cryptonote
{

BlockchainSQLite::BlockchainSQLite(cryptonote::network_type nettype, fs::path db_path)
  : db::Database(db_path, ""), m_nettype(nettype), filename(db_path.u8string())
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);
  height = 0;

  if (!db.tableExists("batched_payments") || !db.tableExists("batch_db_info")) {
    create_schema();
  }

  SQLite::Statement st{db, "SELECT height FROM batch_db_info"};
  while (st.executeStep()) {
    this->height = st.getColumn(0).getInt64();
  }
}


void BlockchainSQLite::create_schema() {
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

	db.exec(R"(
CREATE TABLE batched_payments (
    address VARCHAR NOT NULL,
    amount BIGINT NOT NULL,
    height_earned BIGINT NOT NULL,
    estimated_height_paid BIGINT NOT NULL,
    height_paid BIGINT,
    CHECK(amount > 0)
);
CREATE VIEW accrued_rewards AS
    SELECT 
        address,
        SUM(amount) as amount,
        MIN(estimated_height_paid) as height
    FROM batched_payments 
    WHERE height_paid IS NULL 
    GROUP BY address;

CREATE TABLE batch_db_info (
    height BIGINT NOT NULL
);

INSERT INTO batch_db_info (height) VALUES (0);

CREATE TRIGGER batch_payments_prune_paid
AFTER UPDATE ON batch_db_info FOR EACH ROW
BEGIN
    DELETE FROM batched_payments WHERE height_paid < (NEW.height - 10000);
END;
	)");

	MINFO("Database setup complete");
}

void BlockchainSQLite::clear_database()
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

	db.exec(R"(
DROP TABLE batched_payments;

DROP VIEW accrued_rewards;

DROP TABLE batch_db_info;
	)");

  create_schema();

	MINFO("Database reset complete");
}

bool BlockchainSQLite::update_height(uint64_t new_height)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " Called with new height: " << new_height);
  this->height = new_height;
  SQLite::Statement update_height{db,
    "UPDATE batch_db_info SET height = ?"};
  db::exec_query(update_height, static_cast<int64_t>(height));
  return true;
}

bool BlockchainSQLite::increment_height()
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " Called with height: " << this->height + 1);
  return update_height(this->height + 1);
}

bool BlockchainSQLite::decrement_height()
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " Called with height: " << this->height - 1);
  return update_height(this->height - 1);
}


bool BlockchainSQLite::add_sn_payments(std::vector<cryptonote::batch_sn_payment>& payments, uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " called on height: " << block_height);

  SQLite::Statement insert_payment{db,
    "INSERT INTO batched_payments (address, amount, height_earned, estimated_height_paid) VALUES (?, ?, ?, ?)"};

  for (auto& payment: payments) {
    const auto& conf = get_config(m_nettype);
    uint64_t next_payout_height = payment.address_info.address.next_payout_height(block_height, conf.BATCHING_INTERVAL);
    std::string address_str = cryptonote::get_account_address_as_str(m_nettype, 0, payment.address_info.address);
    MTRACE("Adding record for SN reward contributor " << address_str << "to database with amount " << static_cast<int64_t>(payment.amount));
    db::exec_query(insert_payment, address_str, static_cast<int64_t>(payment.amount), static_cast<int64_t>(block_height), static_cast<int64_t>(next_payout_height));
    insert_payment.reset();
  };

  return true;
}

std::optional<std::vector<cryptonote::batch_sn_payment>> BlockchainSQLite::get_sn_payments(uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

  if (block_height == 0)
    return std::nullopt;

  const auto& conf = get_config(m_nettype);

  SQLite::Statement select_payments{db,
    "SELECT address, amount FROM accrued_rewards WHERE height <= ? AND amount > ? ORDER BY height LIMIT ?"}; 

  select_payments.bind(1, static_cast<int64_t>(block_height));
  select_payments.bind(2, static_cast<int64_t>(conf.MIN_BATCH_PAYMENT_AMOUNT));
  select_payments.bind(3, static_cast<int64_t>(conf.LIMIT_BATCH_OUTPUTS));

  std::vector<cryptonote::batch_sn_payment> payments;

  std::string address;
  uint64_t amount;
  while (select_payments.executeStep())
  {
    address = select_payments.getColumn(0).getString();
    amount = static_cast<uint64_t>(select_payments.getColumn(1).getInt64());
    if (cryptonote::is_valid_address(address, m_nettype)) {
      payments.emplace_back(address, amount, m_nettype);
    }
    else
    {
      MERROR("Invalid address returned from batching database: " << address);
      return std::nullopt;
    }
  }

  return payments;
}

std::vector<cryptonote::batch_sn_payment> BlockchainSQLite::calculate_rewards(uint8_t hf_version, uint64_t distribution_amount, service_nodes::service_node_info sn_info)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

  // Find out how much is due for the operator
  uint64_t operator_fee = 0;
  {
    // This calculates (operator_portion / max_operator_portion) * distribution_amount but using 128 bit integer math
    uint64_t hi, lo, resulthi, resultlo;
    lo = mul128(sn_info.portions_for_operator, distribution_amount, &hi);
    div128_64(hi, lo, STAKING_PORTIONS, &resulthi, &resultlo);
    if (resulthi > 0)
      throw std::logic_error("overflow from calculating sn operator fee");
    operator_fee = resultlo;
  }
  std::vector<cryptonote::batch_sn_payment> payments;
  // Pay the operator fee to the operator
  if (operator_fee > 0)
    payments.emplace_back(sn_info.operator_address, operator_fee, m_nettype);

  // Pay the balance to all the contributors (including the operator again)
  uint64_t total_contributed_to_sn = std::accumulate(sn_info.contributors.begin(), sn_info.contributors.end(), uint64_t(0), [](auto const a, auto const b){return a + b.amount;});

  for (auto & contributor : sn_info.contributors)
  {
    // This calculates (contributor.amount / total_contributed_to_winner_sn) * (distribution_amount - operator_fee) but using 128 bit integer math
    uint64_t hi, lo, resulthi, resultlo;
    lo = mul128(contributor.amount, distribution_amount - operator_fee, &hi);
    div128_64(hi, lo, total_contributed_to_sn, &resulthi, &resultlo);
    if (resulthi > 0)
      throw std::logic_error("overflow from calculating sn contributor reward");
    if (resultlo > 0)
      payments.emplace_back(contributor.address, resultlo, m_nettype);
  }

  return payments;
}

bool BlockchainSQLite::add_block(const cryptonote::block& block, const service_nodes::service_node_list::state_t& service_nodes_state)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

  auto block_height = get_block_height(block);

  // If we receive an add_block() for the genesis block assume we are clearing the database 
  if (block_height == 0) 
  {
    clear_database();
    return true;
  }

  auto hf_version = block.major_version;
  if (hf_version < cryptonote::network_version_19)
  {
    if (height > block_height)
      clear_database();
    return update_height(block_height);
  }

  if (block_height != height + 1)
  {
    MERROR("Block height out of sync with batching database. Block height: " << block_height << " batching db height: " << height);
    return false;
  }


  // We query our own database as a source of truth to verify the blocks payments against. The calculated_rewards
  // variable contains a known good list of who should have been paid in this block 
  auto calculated_rewards = get_sn_payments(block_height);

  // We iterate through the block's coinbase payments and build a copy of our own list of the payments
  // miner_tx_vouts this will be compared against calculated_rewards and if they match we know the block is
  // paying the correct people only.
  std::vector<std::tuple<crypto::public_key, uint64_t>> miner_tx_vouts;
  for(auto & vout : block.miner_tx.vout)
    miner_tx_vouts.emplace_back(var::get<txout_to_key>(vout.target).key, vout.amount);

  bool success = false;
  try
  {
    SQLite::Transaction transaction{db};

    // Goes through the miner transactions vouts checks they are right and marks them as paid in the database
    if (!validate_batch_payment(miner_tx_vouts, *calculated_rewards, block_height, true)) {
      return false;
    }

    // Step 1: Pay out the block producer their fees
    uint64_t service_node_reward = cryptonote::service_node_reward_formula(0, block.major_version);
    if (block.reward - service_node_reward > 0)
    {
      if (block.service_node_winner_key && crypto_core_ed25519_is_valid_point(reinterpret_cast<const unsigned char *>(block.service_node_winner_key.data)))
      {
        auto service_node_winner = service_nodes_state.service_nodes_infos.find(block.service_node_winner_key);
        if (service_node_winner != service_nodes_state.service_nodes_infos.end())
        {
          std::vector<cryptonote::batch_sn_payment> block_producer_fee_payments = calculate_rewards(block.major_version, block.reward - service_node_reward, *service_node_winner->second);
          // Takes the block producer and adds its contributors to the batching database for the transaction fees
          success = add_sn_payments(block_producer_fee_payments, block_height);
          if (!success)
            return false;
          }
        }
    }

    // Step 2: Iterate over the whole service node list and pay each node 1/service_node_list fraction
    const auto payable_service_nodes = service_nodes_state.payable_service_nodes_infos(block_height);
    size_t total_service_nodes_payable = payable_service_nodes.size();
    for (const auto& [node_pubkey, node_info]: payable_service_nodes)
    {
      std::vector<cryptonote::batch_sn_payment> node_contributors;
      auto payable_service_node = service_nodes_state.service_nodes_infos.find(node_pubkey);
      if (payable_service_node == service_nodes_state.service_nodes_infos.end())
        continue;
      std::vector<cryptonote::batch_sn_payment> node_rewards = calculate_rewards(block.major_version, service_node_reward/total_service_nodes_payable, *payable_service_node->second);
      // Takes the node and adds its contributors to the batching database
      success = add_sn_payments(node_rewards, block_height);
      if (!success)
        return false;
    }
    // Step 3: Add Governance reward to the list
    if (m_nettype != cryptonote::FAKECHAIN)
    {
      std::vector<cryptonote::batch_sn_payment> governance_rewards;
      cryptonote::address_parse_info governance_wallet_address;
      cryptonote::get_account_address_from_str(governance_wallet_address, m_nettype, cryptonote::get_config(m_nettype).governance_wallet_address(hf_version));
      governance_rewards.emplace_back(governance_wallet_address.address, FOUNDATION_REWARD_HF17, m_nettype);
      success = add_sn_payments(governance_rewards, block_height);
      if (!success)
        return false;
    }
    success = increment_height();

    transaction.commit();
  }
  catch (std::exception& e)
  {
    MFATAL("Exception: " << e.what());
    return false;
  }
  return success;
}

bool BlockchainSQLite::pop_block(const cryptonote::block& block)
{
  auto block_height = get_block_height(block);

  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " called on height: " << block_height);
  if (height < block_height) {
    MDEBUG("Block above batching DB height skipping pop");
    return true;
  }
  if (cryptonote::get_block_height(block) != height)
  {
    MERROR("Block height out of sync with batching database");
    return false;

  }

  const auto& conf = get_config(m_nettype);
  auto hf_version = block.major_version;
  if (hf_version < cryptonote::network_version_19)
    return decrement_height();

  bool success = false;
  try
  {
    SQLite::Transaction transaction{db};

    // Take away the SN winners contributions from the database should just be delete from db where height = block.height
    // Deletes the unpaid SN winners that accrued rewards from this block
    SQLite::Statement delete_payment{db,
      "DELETE from batched_payments WHERE height_earned = ?"};
    db::exec_query(delete_payment, static_cast<int64_t>(block_height));

    // Marks the miner tx payments that received funds in this block as unpaid (paid_height = NULL)
    delete_block_payments(block_height);

    if (decrement_height())
      success = true;
    transaction.commit();
  }
  catch (std::exception& e)
  {
    MFATAL("Exception: " << e.what());
    return false;
  }
  return success;
}

bool BlockchainSQLite::validate_batch_payment(std::vector<std::tuple<crypto::public_key, uint64_t>> miner_tx_vouts, std::vector<cryptonote::batch_sn_payment> calculated_payments_from_batching_db, uint64_t block_height, bool save_payment)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);
  size_t length_miner_tx_vouts = miner_tx_vouts.size();
  size_t length_calculated_payments_from_batching_db = calculated_payments_from_batching_db.size();

  if (length_miner_tx_vouts != length_calculated_payments_from_batching_db)
  {
    MERROR("Length of batch paments does not match, block vouts: " << length_miner_tx_vouts << " batch size: " << length_calculated_payments_from_batching_db);
    return false;
  }

  int8_t vout_index = 0;
  uint64_t total_oxen_payout_in_our_db = std::accumulate(calculated_payments_from_batching_db.begin(),calculated_payments_from_batching_db.end(), uint64_t(0), [](auto const a, auto const b){return a + b.amount;});
  uint64_t total_oxen_payout_in_vouts = 0;
  std::vector<batch_sn_payment> finalised_payments;
  cryptonote::keypair const deterministic_keypair = cryptonote::get_deterministic_keypair_from_height(block_height);
  for(auto & vout : miner_tx_vouts)
  {
    if (std::get<1>(vout) != calculated_payments_from_batching_db[vout_index].amount)
    {
      MERROR("Service node reward amount incorrect. Should be " << cryptonote::print_money(calculated_payments_from_batching_db[vout_index].amount) << ", is: " << cryptonote::print_money(std::get<1>(vout)));
      return false;
    }
    crypto::public_key out_eph_public_key{};
    if (!cryptonote::get_deterministic_output_key(calculated_payments_from_batching_db[vout_index].address_info.address, deterministic_keypair, vout_index, out_eph_public_key))
    {
      MERROR("Failed to generate output one-time public key");
      return false;
    }
    if (tools::view_guts(std::get<0>(vout)) != tools::view_guts(out_eph_public_key))
    {
      MERROR("Output ephemeral public key does not match");
      return false;
    }
    total_oxen_payout_in_vouts += std::get<1>(vout);
    finalised_payments.emplace_back(calculated_payments_from_batching_db[vout_index].address, std::get<1>(vout), m_nettype);
    vout_index++;
  }
  if (total_oxen_payout_in_vouts != total_oxen_payout_in_our_db)
  {
    MERROR("Total service node reward amount incorrect. Should be " << cryptonote::print_money(total_oxen_payout_in_our_db) << ", is: " << cryptonote::print_money(total_oxen_payout_in_vouts));
    return false;
  }

  if (save_payment)
    return save_payments(block_height, finalised_payments);
  else
    return true;
}

bool BlockchainSQLite::save_payments(uint64_t block_height, std::vector<batch_sn_payment> paid_amounts)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

  SQLite::Statement select_sum{db,
    "SELECT sum(amount) from batched_payments WHERE address = ? AND height_paid IS NULL;"};

  SQLite::Statement update_paid{db,
    "UPDATE batched_payments SET height_paid = ? WHERE address = ? AND height_paid IS NULL;"};


  for (const auto& payment: paid_amounts)
  {
    select_sum.bind(1, payment.address);
    while (select_sum.executeStep()) {
      uint64_t amount = static_cast<uint64_t>(select_sum.getColumn(0).getInt64());
      if (amount != payment.amount)
      {
        MERROR("Invalid amounts passed in to save payments for address: " << payment.address << " received " << payment.amount << " expected " << amount);
        return false;
      }
    }
    select_sum.reset();

    db::exec_query(update_paid, static_cast<int64_t>(block_height), payment.address);
    update_paid.reset();
  };
  return true;
}

std::vector<cryptonote::batch_sn_payment> BlockchainSQLite::get_block_payments(uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " Called with height: " << block_height);

  std::vector<cryptonote::batch_sn_payment> payments_at_height;
  SQLite::Statement st{db, "SELECT address, amount FROM batched_payments WHERE height_paid = ? ORDER BY address"};
  st.bind(1, static_cast<int64_t>(block_height));
  while (st.executeStep()) {
    payments_at_height.emplace_back(st.getColumn(0).getString(), st.getColumn(1).getInt64(), m_nettype);
  }
  return payments_at_height;
}

bool BlockchainSQLite::delete_block_payments(uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " Called with height: " << block_height);
  SQLite::Statement delete_payments{db,
    "UPDATE batched_payments SET height_paid = NULL WHERE height_paid = ? ;"};
  db::exec_query(delete_payments, static_cast<int64_t>(block_height));
  return true;
}

fs::path check_if_copy_filename(std::string_view db_path)
{
  return (db_path != ":memory:") ? fs::path(std::string(db_path) + "-copy") : fs::path(std::string(db_path));
}

BlockchainSQLiteTest::BlockchainSQLiteTest(BlockchainSQLiteTest &other)
  : BlockchainSQLiteTest(other.m_nettype, check_if_copy_filename(other.filename))
{
  std::vector<std::tuple<std::string, int64_t, int64_t, int64_t, int64_t>> all_payments;
  SQLite::Statement st{other.db, "SELECT address, amount, height_earned, height_paid, estimated_height_paid FROM batched_payments"};
  while (st.executeStep())
    all_payments.emplace_back(st.getColumn(0).getString(), st.getColumn(1).getInt64(), st.getColumn(2).getInt64(), st.getColumn(3).getInt64(), st.getColumn(4).getInt64());

  SQLite::Transaction transaction{db};
    
  SQLite::Statement insert_payment{db,
    "INSERT INTO batched_payments (address, amount, height_earned, height_paid, estimated_height_paid) VALUES (?, ?, ?, ?, ?)"};

  for (auto& payment: all_payments) {
    db::exec_query(insert_payment, std::get<0>(payment), std::get<1>(payment), std::get<2>(payment), std::get<3>(payment), std::get<4>(payment));
    insert_payment.reset();
  };
  delete_block_payments(0);
  transaction.commit();

  update_height(other.height);
}

uint64_t BlockchainSQLiteTest::batching_count()
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);
  SQLite::Statement st{db, "SELECT count(*) FROM accrued_rewards"};
  uint64_t count = 0;
  while (st.executeStep()) {
    count = st.getColumn(0).getInt64();
  }
  return count;
}

std::optional<uint64_t> BlockchainSQLiteTest::retrieve_amount_by_address(const std::string& address)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);
  SQLite::Statement st{db, "SELECT amount FROM accrued_amounts WHERE address = ?"};
  st.bind(1, address);
  std::optional<uint64_t> amount = std::nullopt;
  while (st.executeStep()) {
    assert(!amount);
    amount.emplace(st.getColumn(0).getInt64());
  }
  return amount;
}

} // namespace cryptonote
