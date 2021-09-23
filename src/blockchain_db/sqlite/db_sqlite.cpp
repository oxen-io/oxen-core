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

#include <SQLiteCpp/SQLiteCpp.h>
#include <sqlite3.h>

#include <string>
#include <iostream>
#include <cassert>

#include "cryptonote_core/blockchain.h"
#include "common/string_util.h"


#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "blockchain.db.sqlite"

namespace cryptonote
{

template <typename T> constexpr bool is_cstr = false;
template <size_t N> constexpr bool is_cstr<char[N]> = true;
template <size_t N> constexpr bool is_cstr<const char[N]> = true;
template <> constexpr bool is_cstr<char*> = true;
template <> constexpr bool is_cstr<const char*> = true;

// Simple wrapper class that can be used to bind a blob through the templated binding code below.
// E.g. `exec_query(st, 100, 42, blob_binder{data})` binds the third parameter using no-copy blob
// binding of the contained data.
struct blob_binder {
    std::string_view data;
    explicit blob_binder(std::string_view d) : data{d} {}
};

// Binds a string_view as a no-copy blob at parameter index i.
void bind_blob_ref(SQLite::Statement& st, int i, std::string_view blob) {
    st.bindNoCopy(i, static_cast<const void*>(blob.data()), blob.size());
}

// Called from exec_query and similar to bind statement parameters for immediate execution.  strings
// (and c strings) use no-copy binding; user_pubkey_t values use *two* sequential binding slots for
// pubkey (first) and type (second); integer values are bound by value.  You can bind a blob (by
// reference, like strings) by passing `blob_binder{data}`.
template <typename T>
void bind_oneshot(SQLite::Statement& st, int& i, const T& val) {
    if constexpr (std::is_same_v<T, std::string> || is_cstr<T>)
        st.bindNoCopy(i++, val);
    else if constexpr (std::is_same_v<T, blob_binder>)
        bind_blob_ref(st, i++, val.data);
    else
        st.bind(i++, val);
}

// Executes a query that does not expect results.  Optionally binds parameters, if provided.
// Returns the number of affected rows; throws on error or if results are returned.
template <typename... T>
int exec_query(SQLite::Statement& st, const T&... bind) {
    int i = 1;
    (bind_oneshot(st, i, bind), ...);
    return st.exec();
}

// Same as above, but prepares a literal query on the fly for use with queries that are only used
// once.
template <typename... T>
int exec_query(SQLite::Database& db, const char* query, const T&... bind) {
    SQLite::Statement st{db, query};
    return exec_query(st, bind...);
}

constexpr std::chrono::milliseconds SQLite_busy_timeout = 3s;

BlockchainSQLite::BlockchainSQLite(const BlockchainSQLite &other) {
  filename = other.filename;

  if (filename != ":memory:") {
    filename += "-copy";
  }

  this->load_database(other.m_nettype, filename);

  std::vector<std::tuple<std::string, int64_t, int64_t>> all_payments;
  SQLite::Statement st{*other.db, "SELECT * FROM batch_sn_payments"};
  while (st.executeStep()) {
    all_payments.emplace_back(st.getColumn(0).getString(), st.getColumn(1).getInt64(), st.getColumn(2).getInt64());
  }

  std::vector<std::tuple<std::string, int64_t, int64_t, int64_t>> all_block_payments;
  SQLite::Statement block_st{*other.db, "SELECT * FROM block_payments"};
  while (block_st.executeStep()) {
    all_block_payments.emplace_back(block_st.getColumn(0).getString(), block_st.getColumn(1).getInt64(), block_st.getColumn(2).getInt64(), block_st.getColumn(2).getInt64());
  }

  SQLite::Transaction transaction{*db};
    
  SQLite::Statement insert_payment{*db,
    "INSERT INTO batch_sn_payments (address, amount, height) VALUES (?, ?, ?)"};

  SQLite::Statement insert_block_payment{*db,
    "INSERT INTO block_payments (address, amount, height, vout_index) VALUES (?, ?, ?, ?)"};

  for (auto& payment: all_payments) {
    exec_query(insert_payment, std::get<0>(payment), std::get<1>(payment), std::get<2>(payment));
    insert_payment.reset();
  };

  for (auto& payment: all_block_payments) {
    exec_query(insert_block_payment, std::get<0>(payment), std::get<1>(payment), std::get<2>(payment), std::get<3>(payment));
    insert_block_payment.reset();
  };

  transaction.commit();

  update_height(other.height);
}

void BlockchainSQLite::create_schema() {
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

	db->exec(R"(
CREATE TABLE batch_sn_payments (
    address BLOB NOT NULL PRIMARY KEY,
    amount BIGINT NOT NULL,
    height BIGINT NOT NULL,
    CHECK(amount >= 0)
);

CREATE TABLE block_payments (
    address BLOB NOT NULL,
    amount BIGINT NOT NULL,
    height BIGINT NOT NULL,
    vout_index INT NOT NULL,
    PRIMARY KEY(height, vout_index)
    CHECK(amount >= 0)
) WITHOUT ROWID;

CREATE TABLE batch_sn_info (
    height BIGINT NOT NULL
);

INSERT INTO batch_sn_info (height) VALUES (0);

CREATE TRIGGER batch_payments_delete_empty
AFTER UPDATE ON batch_sn_payments FOR EACH ROW WHEN NEW.amount = 0 
BEGIN
    DELETE FROM batch_sn_payments WHERE address = NEW.address;
END;
	)");

	MINFO("Database setup complete");
} 

void BlockchainSQLite::clear_database() {
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

	db->exec(R"(
DROP TABLE batch_sn_payments;

DROP TABLE block_payments;

DROP TABLE batch_sn_info;
	)");

  create_schema();

	MINFO("Database reset complete");
}

void BlockchainSQLite::load_database(cryptonote::network_type nettype, std::optional<fs::path> file) {
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);
  this->height = 0;
  if (db)
    throw std::runtime_error("Reloading database not supported");

  m_nettype = nettype;

  std::string fileString;
  if (file.has_value())
  {
    fileString = file->string();
    MINFO("Loading sqliteDB from file " << fileString);
  }
  else
  {
    fileString = ":memory:";
    MINFO("Loading memory-backed sqliteDB");
  }
  db = std::make_unique<SQLite::Database>(
      SQLite::Database{
      fileString, 
      SQLite::OPEN_READWRITE | SQLite::OPEN_CREATE | SQLite::OPEN_FULLMUTEX,
      SQLite_busy_timeout.count()
      });

  if (!db->tableExists("batch_sn_payments") || !db->tableExists("batch_sn_info") || !db->tableExists("block_payments")) {
    create_schema();
  }

  SQLite::Statement st{*db, "SELECT height FROM batch_sn_info"};
  while (st.executeStep()) {
    this->height = st.getColumn(0).getInt64();
  }
  filename = fileString;
}

bool BlockchainSQLite::update_height(uint64_t new_height) {
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " Called with new height: " << new_height);
  this->height = new_height;
  SQLite::Statement update_height{*db,
    "UPDATE batch_sn_info SET height = ?"};
  exec_query(update_height, static_cast<int64_t>(height));
  return true;
}

bool BlockchainSQLite::increment_height() {
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " Called with height: " << this->height + 1);
  return update_height(this->height + 1);
}

bool BlockchainSQLite::decrement_height() {
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " Called with height: " << this->height - 1);
  return update_height(this->height - 1);
}

uint64_t BlockchainSQLite::batching_count() {
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);
  SQLite::Statement st{*db, "SELECT count(*) FROM batch_sn_payments"};
  uint64_t count = 0;
  while (st.executeStep()) {
    count = st.getColumn(0).getInt64();
  }
  return count;
}

std::optional<uint64_t> BlockchainSQLite::retrieve_amount_by_address(const std::string& address) {
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);
  SQLite::Statement st{*db, "SELECT amount FROM batch_sn_payments WHERE address = ?"};
  st.bind(1, address);
  std::optional<uint64_t> amount = std::nullopt;
  while (st.executeStep()) {
    assert(!amount);
    amount.emplace(st.getColumn(0).getInt64());
  }
  return amount;
}

bool BlockchainSQLite::add_sn_payments(std::vector<cryptonote::batch_sn_payment>& payments, uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " called on height: " << block_height);
  //Assert that all the addresses in the payments vector are unique
  std::sort(payments.begin(),payments.end(),[](const cryptonote::batch_sn_payment i, const cryptonote::batch_sn_payment j){ return i.address < j.address; });
  auto uniq = std::unique( payments.begin(), payments.end(), [](const cryptonote::batch_sn_payment i, const cryptonote::batch_sn_payment j){ return i.address == j.address; } );
  if(uniq != payments.end()) {
    MWARNING("Duplicate addresses in payments list");
    return false;
  }

  SQLite::Statement insert_payment{*db,
    "INSERT INTO batch_sn_payments (address, amount, height) VALUES (?, ?, ?)"};

  SQLite::Statement update_payment{*db,
    "UPDATE batch_sn_payments SET amount = ? WHERE address = ?"};

  for (auto& payment: payments) {
    std::string address_str = cryptonote::get_account_address_as_str(m_nettype, 0, payment.address_info.address);
    auto prev_amount = retrieve_amount_by_address(address_str);
    if(prev_amount.has_value()){
      MDEBUG("Record found for SN reward contributor, adding " << address_str << "to database with amount " << static_cast<int64_t>(payment.amount));
      exec_query(update_payment, static_cast<int64_t>(*prev_amount) + static_cast<int64_t>(payment.amount), address_str);
      update_payment.reset();
    } else {
      MDEBUG("No Record found for SN reward contributor, adding " << address_str << "to database with amount " << static_cast<int64_t>(payment.amount));
      exec_query(insert_payment, address_str, static_cast<int64_t>(payment.amount), static_cast<int64_t>(block_height));
      insert_payment.reset();
    }
  };

  return true;
}

bool BlockchainSQLite::subtract_sn_payments(std::vector<cryptonote::batch_sn_payment>& payments, uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

  SQLite::Statement update_payment{*db,
    "UPDATE batch_sn_payments SET amount = ? WHERE address = ?"};

  for (auto& payment: payments) {
    std::string address_str = cryptonote::get_account_address_as_str(m_nettype, 0, payment.address_info.address);
    auto prev_amount = retrieve_amount_by_address(address_str);
    if(prev_amount.has_value()){
      if (payment.amount > *prev_amount) { 
        MDEBUG(__FILE__ << ":" << __LINE__ << "failing to pop as previous amount in database is less than the amount being subtracted");
        return false;
      }
      //update_payment.bind(*prev_amount - payment.amount, address_str);
      exec_query(update_payment, static_cast<int64_t>(*prev_amount - payment.amount), address_str);
      update_payment.reset();

    } else {
      MDEBUG(__FILE__ << ":" << __LINE__ << "failing to pop as previous amount in database does not have a value");
      return false;
    }

  };

  return true;
}

std::optional<std::vector<cryptonote::batch_sn_payment>> BlockchainSQLite::get_sn_payments(uint64_t block_height)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

  if (block_height == 0)
    return std::nullopt;

  const auto& conf = get_config(m_nettype);

  SQLite::Statement select_payments{*db,
    "SELECT address, amount FROM batch_sn_payments WHERE height <= ? AND amount > ? ORDER BY height LIMIT ?"}; 

  select_payments.bind(1, static_cast<int64_t>(block_height - conf.BATCHING_INTERVAL));
  select_payments.bind(2, static_cast<int64_t>(conf.MIN_BATCH_PAYMENT_AMOUNT));
  select_payments.bind(3, static_cast<int64_t>(conf.LIMIT_BATCH_OUTPUTS));

  std::vector<cryptonote::batch_sn_payment> payments;

  std::string address;
  uint64_t amount;
  while (select_payments.executeStep())
  {
    address = select_payments.getColumn(0).getString();
    amount = static_cast<uint64_t>(select_payments.getColumn(1).getInt64());
    if (cryptonote::is_valid_address(address, m_nettype))
      payments.emplace_back(address, amount, m_nettype);
    else
    {
      MERROR("Invalid address returned from batching database: " << address);
      return std::nullopt;
    }
  }

  return payments;
}

std::vector<cryptonote::batch_sn_payment> BlockchainSQLite::calculate_rewards(const cryptonote::block& block, std::vector<cryptonote::batch_sn_payment> contributors)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);
  uint64_t distribution_amount = block.reward;

  uint64_t total_contributed_to_winner_sn = std::accumulate(contributors.begin(), contributors.end(), uint64_t(0), [](auto const a, auto const b){return a + b.amount;});

  std::vector<cryptonote::batch_sn_payment> payments;
  for (auto & contributor : contributors)
    payments.emplace_back(contributor.address, (contributor.amount / total_contributed_to_winner_sn * distribution_amount), m_nettype);

  return payments;
}

bool BlockchainSQLite::add_block(const cryptonote::block& block, std::vector<cryptonote::batch_sn_payment> contributors)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

  auto block_height = get_block_height(block);

  // If we receive an add_block() for the genesis block assume we are clearing the database 
  if (block_height == 0) 
  {
    clear_database();
    return true;
  }

  if (block_height != height + 1)
  {
    MERROR("Block height out of sync with batching database. Block height: " << block_height << " batching db height: " << height);
    return false;
  }

  auto hf_version = block.major_version;
  if (hf_version < cryptonote::network_version_19)
  {
    return increment_height();
  }

  std::vector<std::tuple<crypto::public_key, uint64_t>> miner_tx_vouts;

  bool has_batched_governance_reward = height_has_governance_output(m_nettype, hf_version, block_height);

  auto calculated_rewards = get_sn_payments(block_height);

  for(auto & vout : block.miner_tx.vout)
    miner_tx_vouts.emplace_back(var::get<txout_to_key>(vout.target).key,vout.amount);

  bool success = false;
  try
  {
    SQLite::Transaction transaction{*db};
    if (!validate_batch_payment(miner_tx_vouts, *calculated_rewards, block_height, has_batched_governance_reward, true)) {
      return false;
    } else {
      if (!subtract_sn_payments(*calculated_rewards, block_height)) {
        return false;
      }
    }

    std::vector<cryptonote::batch_sn_payment> payments = calculate_rewards(block, contributors);

    if(increment_height())
      success = add_sn_payments(payments, block_height);
    transaction.commit();
  }
  catch (std::exception& e)
  {
    MFATAL("Exception: " << e.what());
    return false;
  }
  return success;
}


bool BlockchainSQLite::pop_block(const cryptonote::block &block, std::vector<cryptonote::batch_sn_payment> contributors)
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

  std::vector<std::tuple<crypto::public_key, uint64_t>> miner_tx_vouts;
  bool has_batched_governance_reward = height_has_governance_output(m_nettype, hf_version, block_height);
  for(auto & vout : block.miner_tx.vout)
    miner_tx_vouts.emplace_back(var::get<cryptonote::txout_to_key>(vout.target).key, vout.amount);

  std::vector<cryptonote::batch_sn_payment> payments = calculate_rewards(block, contributors);
  if (payments.size() > 0) {
    if(!subtract_sn_payments(payments, block_height)) {
      MDEBUG(__FILE__ << ":" << __LINE__ << "failing to call subtract_sn_payments function call");
      return false;
    }
  }

	auto previous_block_payments = get_block_payments(block_height);

  bool success = false;
  try
  {
    SQLite::Transaction transaction{*db};
    if (previous_block_payments.size() > 0)
    {
      if (!validate_batch_payment(miner_tx_vouts, previous_block_payments, block_height, has_batched_governance_reward, false))
      {
        MINFO(__FILE__ << ":" << __LINE__ << " failing validate_batch_payments function call");
        return false;
      } else {
        MDEBUG(__FILE__ << ":" << __LINE__ << " (" << __func__ << ") Calling add sn payments with height: " << block_height - conf.BATCHING_INTERVAL << " - debug");
        if (!add_sn_payments(previous_block_payments, block_height - conf.BATCHING_INTERVAL)) {
          MINFO(__FILE__ << ":" << __LINE__ << "failing to call add_sn_payments function call");
          return false;
        }
      }
    }

    delete_block_payments(block_height);

    if(decrement_height())
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

bool BlockchainSQLite::validate_batch_payment(std::vector<std::tuple<crypto::public_key, uint64_t>> miner_tx_vouts, std::vector<cryptonote::batch_sn_payment> calculated_payments_from_batching_db, uint64_t block_height, bool has_batched_governance_output, bool save_payment)
{
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);
  size_t length_miner_tx_vouts = miner_tx_vouts.size();
  size_t length_calculated_payments_from_batching_db = calculated_payments_from_batching_db.size();

  uint64_t batched_governance_reward = 0;
  if(has_batched_governance_output)
  {
    length_calculated_payments_from_batching_db++;
    size_t num_blocks = cryptonote::get_config(m_nettype).GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS;
    batched_governance_reward = num_blocks * FOUNDATION_REWARD_HF17;
  }
  if (length_miner_tx_vouts != length_calculated_payments_from_batching_db)
  {
    MERROR("Length of batch paments does not match, block vouts: " << length_miner_tx_vouts << " batch size: " << length_calculated_payments_from_batching_db);
    return false;
  }

  int8_t vout_index = 0;
  uint64_t total_oxen_payout_in_our_db = std::accumulate(calculated_payments_from_batching_db.begin(),calculated_payments_from_batching_db.end(), uint64_t(0), [](auto const a, auto const b){return a + b.amount;});
  uint64_t total_oxen_payout_in_vouts = 0;
  std::vector<std::tuple<std::string, int64_t, int8_t, int64_t>> finalised_payments;
  cryptonote::keypair const deterministic_keypair = cryptonote::get_deterministic_keypair_from_height(block_height);
  for(auto & vout : miner_tx_vouts)
  {
    if(has_batched_governance_output && std::get<1>(vout) == batched_governance_reward) 
    {
      total_oxen_payout_in_vouts += batched_governance_reward;
      total_oxen_payout_in_our_db += batched_governance_reward;
      vout_index++;
      continue;
    }

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
    finalised_payments.emplace_back(calculated_payments_from_batching_db[vout_index].address, static_cast<int64_t>(std::get<1>(vout)), vout_index, block_height);
    vout_index++;
  }
  if (total_oxen_payout_in_vouts != total_oxen_payout_in_our_db)
  {
    MERROR("Total service node reward amount incorrect. Should be " << cryptonote::print_money(total_oxen_payout_in_our_db) << ", is: " << cryptonote::print_money(total_oxen_payout_in_vouts));
    return false;
  }

  if (save_payment)
    return save_block_payments(finalised_payments);
  else
    return true;
}

bool BlockchainSQLite::save_block_payments(std::vector<std::tuple<std::string, int64_t, int8_t, int64_t>> finalised_payments){
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);
  SQLite::Statement insert_payment{*db,
    "INSERT INTO block_payments (address, amount, vout_index, height) VALUES (?, ?, ?, ?)"};
  for (auto& payment: finalised_payments)
  {
    exec_query(insert_payment, std::get<0>(payment), std::get<1>(payment), std::get<2>(payment), std::get<3>(payment));
    insert_payment.reset();
  };
  return true;
}

std::vector<cryptonote::batch_sn_payment> BlockchainSQLite::get_block_payments(uint64_t block_height){
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " Called with height: " << block_height);

  std::vector<cryptonote::batch_sn_payment> payments_at_height;
  SQLite::Statement st{*db, "SELECT address, amount FROM block_payments WHERE height = ? ORDER BY vout_index"};
  st.bind(1, static_cast<int64_t>(block_height));
  while (st.executeStep()) {
    payments_at_height.emplace_back(st.getColumn(0).getString(), st.getColumn(1).getInt64(), m_nettype);
  }
  return payments_at_height;
}

bool BlockchainSQLite::delete_block_payments(uint64_t block_height){
  LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " Called with height: " << block_height);
  SQLite::Statement delete_payments{*db,
    "DELETE FROM block_payments WHERE height = ?;"};
  exec_query(delete_payments, static_cast<int64_t>(block_height));
  return true;
}

} // namespace cryptonote
