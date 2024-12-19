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

#include <sqlite3.h>
#include <sodium.h>
#include <fmt/core.h>

#include <iostream>
#include <cassert>

#include "cryptonote_config.h"
#include "cryptonote_core/blockchain.h"
#include "cryptonote_core/service_node_list.h"
#include "common/string_util.h"
#include "cryptonote_basic/hardfork.h"

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "blockchain.db.sqlite"

namespace cryptonote {

  BlockchainSQLite::BlockchainSQLite(cryptonote::network_type nettype, fs::path db_path): db::Database(db_path, ""), m_nettype(nettype), filename {db_path.u8string()} {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);
    height = 0;

    if (!db.tableExists("batched_payments_accrued") || !db.tableExists("batched_payments_raw") || !db.tableExists("batch_db_info")) {
      create_schema();
    }

    upgrade_schema();

    height = prepared_get<int64_t>("SELECT height FROM batch_db_info");
  }

  void BlockchainSQLite::create_schema() {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

    auto& netconf = cryptonote::get_config(m_nettype);

    db.exec(fmt::format(R"(
      CREATE TABLE batched_payments_accrued(
        address VARCHAR NOT NULL,
        amount BIGINT NOT NULL,
        payout_offset INTEGER NOT NULL,
        PRIMARY KEY(address),
        CHECK(amount >= 0)
      );

      CREATE INDEX batched_payments_accrued_payout_offset_idx ON batched_payments_accrued(payout_offset);

      CREATE TRIGGER batch_payments_delete_empty AFTER UPDATE ON batched_payments_accrued
      FOR EACH ROW WHEN NEW.amount = 0 BEGIN
          DELETE FROM batched_payments_accrued WHERE address = NEW.address;
      END;

      CREATE TABLE batched_payments_raw(
        address VARCHAR NOT NULL,
        amount BIGINT NOT NULL,
        height_paid BIGINT NOT NULL,
        PRIMARY KEY(address, height_paid),
        CHECK(amount >= 0)
      );

      CREATE INDEX batched_payments_raw_height_idx ON batched_payments_raw(height_paid);

      CREATE TABLE batch_db_info(
        height BIGINT NOT NULL
      );

      INSERT INTO batch_db_info(height) VALUES(0);

      CREATE TRIGGER batch_payments_prune AFTER UPDATE ON batch_db_info
      FOR EACH ROW BEGIN
          DELETE FROM batched_payments_raw WHERE height_paid < (NEW.height - 10000);
      END;

      CREATE VIEW batched_payments_paid AS SELECT * FROM batched_payments_raw;

      CREATE TRIGGER make_payment INSTEAD OF INSERT ON batched_payments_paid
      FOR EACH ROW BEGIN
          UPDATE batched_payments_accrued SET amount = (amount - NEW.amount) WHERE address = NEW.address;
          SELECT RAISE(ABORT, 'Address not found') WHERE changes() = 0;
          INSERT INTO batched_payments_raw(address, amount, height_paid) VALUES(NEW.address, NEW.amount, NEW.height_paid);
      END;

      CREATE TRIGGER rollback_payment INSTEAD OF DELETE ON batched_payments_paid
      FOR EACH ROW BEGIN
          DELETE FROM batched_payments_raw WHERE address = OLD.address AND height_paid = OLD.height_paid;
          INSERT INTO batched_payments_accrued(address, payout_offset, amount) VALUES(OLD.address, OLD.height_paid % {}, OLD.amount)
              ON CONFLICT(address) DO UPDATE SET amount = (amount + excluded.amount);
      END;
    )",
    netconf.BATCHING_INTERVAL));

    MDEBUG("Database setup complete");
  }

  void BlockchainSQLite::upgrade_schema() {
    bool have_offset = false;
    SQLite::Statement msg_cols{db, "PRAGMA main.table_info(batched_payments_accrued)"};
    while (msg_cols.executeStep()) {
      auto [cid, name] = db::get<int64_t, std::string>(msg_cols);
      if (name == "payout_offset")
        have_offset = true;
    }

    if (!have_offset) {
      MINFO("Adding payout_offset to batching db");
      auto& netconf = get_config(m_nettype);
      SQLite::Transaction transaction{
        db,
        SQLite::TransactionBehavior::IMMEDIATE
      };

      db.exec(fmt::format(R"(
        ALTER TABLE batched_payments_accrued ADD COLUMN payout_offset INTEGER NOT NULL DEFAULT -1;

        CREATE INDEX batched_payments_accrued_payout_offset_idx ON batched_payments_accrued(payout_offset);

        DROP TRIGGER IF EXISTS rollback_payment;
        CREATE TRIGGER rollback_payment INSTEAD OF DELETE ON batched_payments_paid
        FOR EACH ROW BEGIN
            DELETE FROM batched_payments_raw WHERE address = OLD.address AND height_paid = OLD.height_paid;
            INSERT INTO batched_payments_accrued(address, payout_offset, amount) VALUES(OLD.address, OLD.height_paid % {}, OLD.amount)
                ON CONFLICT(address) DO UPDATE SET amount = (amount + excluded.amount);
        END;
        )", netconf.BATCHING_INTERVAL));

      auto st = prepared_st("UPDATE batched_payments_accrued SET payout_offset = ? WHERE address = ?");
      for (const auto& address : prepared_results<std::string>("SELECT address from batched_payments_accrued")) {
        cryptonote::address_parse_info addr_info{};
        cryptonote::get_account_address_from_str(addr_info, m_nettype, address);
        auto offset = static_cast<int>(addr_info.address.modulus(netconf.BATCHING_INTERVAL));
        exec_query(st, offset, address);
        st->reset();
      }

      auto count = prepared_get<int>("SELECT COUNT(*) FROM batched_payments_accrued WHERE payout_offset NOT BETWEEN 0 AND ?",
          static_cast<int>(netconf.BATCHING_INTERVAL));

      if (count != 0) {
        constexpr auto error = "Batching db update to add offsets failed: not all addresses were converted";
        MFATAL(error);
        throw std::runtime_error{error};
      }

      transaction.commit();
    }

    const auto archive_table_count = prepared_get<int64_t>("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='batched_payments_accrued_archive';");
    if(archive_table_count == 0)
    {
      MINFO("Adding archiving to batching db");
      auto& netconf = get_config(m_nettype);
      SQLite::Transaction transaction{
        db,
        SQLite::TransactionBehavior::IMMEDIATE
      };
      db.exec(fmt::format(R"(
        CREATE TABLE batched_payments_accrued_archive(
          address VARCHAR NOT NULL,
          amount BIGINT NOT NULL,
          payout_offset INTEGER NOT NULL,
          archive_height BIGINT NOT NULL,
          CHECK(amount >= 0),
          CHECK(archive_height >= 0)
        );

        CREATE INDEX batched_payments_accrued_archive_height_idx ON batched_payments_accrued_archive(archive_height);

        DROP TRIGGER IF EXISTS make_archive;
        CREATE TRIGGER make_archive AFTER UPDATE ON batch_db_info
        FOR EACH ROW WHEN (NEW.height % 100) = 0 AND NEW.height > OLD.height BEGIN
            INSERT INTO batched_payments_accrued_archive SELECT *, NEW.height FROM batched_payments_accrued;
            DELETE FROM batched_payments_accrued_archive WHERE archive_height < NEW.height - {1} AND archive_height % {0} != 0;
        END;

        DROP TRIGGER IF EXISTS clear_archive;
        CREATE TRIGGER clear_archive AFTER UPDATE ON batch_db_info
        FOR EACH ROW WHEN NEW.height < OLD.height BEGIN
            DELETE FROM batched_payments_accrued_archive WHERE archive_height >= NEW.height;
        END;
        )", netconf.STORE_LONG_TERM_STATE_INTERVAL, 500));
      transaction.commit();
    }
  }

  void BlockchainSQLite::reset_database() {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

    db.exec(R"(
      DROP TABLE IF EXISTS batched_payments_accrued;

      DROP TABLE IF EXISTS batched_payments_accrued_archive;

      DROP VIEW IF EXISTS batched_payments_paid;

      DROP TABLE IF EXISTS batched_payments_raw;

      DROP TABLE IF EXISTS batch_db_info;
    )");

    create_schema();

    upgrade_schema();

    MDEBUG("Database reset complete");
  }

  void BlockchainSQLite::update_height(uint64_t new_height) {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " Called with new height: " << new_height);
    height = new_height;
    prepared_exec(
      "UPDATE batch_db_info SET height = ?",
      static_cast<int64_t>(height));
  }

  void BlockchainSQLite::increment_height() {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " Called with height: " << height + 1);
    update_height(height + 1);
  }

  void BlockchainSQLite::decrement_height() {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " Called with height: " << height - 1);
    update_height(height - 1);
  }

  void BlockchainSQLite::blockchain_detached(uint64_t new_height)
  {
    if (height < new_height)
      return;
    int64_t revert_to_height = new_height - 1;
    auto maybe_prev_interval = prepared_maybe_get<int64_t>(
        "SELECT DISTINCT archive_height FROM batched_payments_accrued_archive WHERE archive_height <= ? ORDER BY archive_height DESC LIMIT 1",
        revert_to_height);

    if (!maybe_prev_interval)
    {
      auto fork_height = cryptonote::get_hard_fork_heights(m_nettype, hf::hf19_reward_batching);
      reset_database();
      update_height(fork_height.first.value_or(0));
      return;
    }
    const auto prev_interval = *maybe_prev_interval;

    db.exec(fmt::format(R"(
      DELETE FROM batched_payments_raw WHERE height_paid > {0};

      DELETE FROM batched_payments_accrued;

      INSERT INTO batched_payments_accrued
        SELECT address, amount, payout_offset
        FROM batched_payments_accrued_archive WHERE archive_height = {0};

      DELETE FROM batched_payments_accrued_archive WHERE archive_height >= {0};
      )", prev_interval));
    update_height(prev_interval);
    return;
  }

  // Must be called with the address_str_cache_mutex held!
  const std::string& BlockchainSQLite::get_address_str(const account_public_address& addr)
  {
    auto& address_str = address_str_cache[addr];
    if (address_str.empty())
      address_str = cryptonote::get_account_address_as_str(m_nettype, 0, addr);
    return address_str;
  }


  bool BlockchainSQLite::add_sn_rewards(const std::vector<cryptonote::batch_sn_payment>& payments) {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);
    auto insert_payment = prepared_st(
      "INSERT INTO batched_payments_accrued (address, payout_offset, amount) VALUES (?, ?, ?)"
      " ON CONFLICT (address) DO UPDATE SET amount = amount + excluded.amount");

    const auto& netconf = get_config(m_nettype);

    for (auto& payment: payments) {
      auto offset = static_cast<int>(payment.address_info.address.modulus(netconf.BATCHING_INTERVAL));
      auto amt = static_cast<int64_t>(payment.amount);
      const auto& address_str = get_address_str(payment.address_info.address);
      MTRACE(fmt::format("Adding record for SN reward contributor {} to database with amount {}",
           address_str, amt));
      db::exec_query(insert_payment, address_str, offset, amt);
      insert_payment->reset();
    }

    return true;
  }

  bool BlockchainSQLite::subtract_sn_rewards(const std::vector<cryptonote::batch_sn_payment>& payments) {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);
    auto update_payment = prepared_st(
      "UPDATE batched_payments_accrued SET amount = (amount - ?) WHERE address = ?");

    for (auto& payment: payments) {
      const auto& address_str = get_address_str(payment.address_info.address);
      auto result = db::exec_query(update_payment, static_cast<int64_t>(payment.amount), address_str);
      if (!result) {
        MERROR("tried to subtract payment from an address that doesn't exist: " << address_str);
        return false;
      }
      update_payment->reset();
    }

    return true;
  }

  std::vector<cryptonote::batch_sn_payment> BlockchainSQLite::get_sn_payments(uint64_t block_height) {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

    // <= here because we might have crap in the db that we don't clear until we actually add the HF
    // block later on.  (This is a pretty slim edge case that happened on devnet and is probably
    // virtually impossible on mainnet).
    if (m_nettype != cryptonote::network_type::FAKECHAIN && block_height <= cryptonote::get_hard_fork_heights(m_nettype, hf::hf19_reward_batching).first.value_or(0))
      return {};

    const auto& conf = get_config(m_nettype);

    auto accrued_amounts = prepared_results<std::string_view, int64_t>(
      "SELECT address, amount FROM batched_payments_accrued WHERE payout_offset = ? AND amount >= ? ORDER BY address ASC",
      static_cast<int>(block_height % conf.BATCHING_INTERVAL),
      static_cast<int64_t>(conf.MIN_BATCH_PAYMENT_AMOUNT * BATCH_REWARD_FACTOR));

    std::vector<cryptonote::batch_sn_payment> payments;

    for (auto [address, amount] : accrued_amounts) {
      auto& p = payments.emplace_back();
      p.amount = amount / BATCH_REWARD_FACTOR * BATCH_REWARD_FACTOR; /* truncate to atomic OXEN */
      [[maybe_unused]] bool addr_ok = cryptonote::get_account_address_from_str(p.address_info, m_nettype, address);
      assert(addr_ok);
    }

    return payments;
  }


  uint64_t BlockchainSQLite::get_accrued_earnings(const std::string& address) {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

    auto earnings = prepared_maybe_get<int64_t>(
        "SELECT amount FROM batched_payments_accrued WHERE address = ?",
        address);
    return static_cast<uint64_t>(earnings.value_or(0) / 1000);
  }

  std::pair<std::vector<std::string>, std::vector<uint64_t>> BlockchainSQLite::get_all_accrued_earnings() {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

    std::pair<std::vector<std::string>, std::vector<uint64_t>> result;
    auto& [addresses, amounts] = result;

    for (auto [addr, amt] : prepared_results<std::string, int64_t>(
          "SELECT address, amount FROM batched_payments_accrued")) {
      auto amount = static_cast<uint64_t>(amt / 1000);
      if (amount > 0) {
        addresses.push_back(std::move(addr));
        amounts.push_back(amount);
      }
    }

    return result;
  }

  void BlockchainSQLite::calculate_rewards(hf hf_version, uint64_t distribution_amount, const service_nodes::service_node_info& sn_info, std::vector<cryptonote::batch_sn_payment>& payments) {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

    // Find out how much is due for the operator: fee_portions/PORTIONS * reward
    assert(sn_info.portions_for_operator <= old::STAKING_PORTIONS);
    uint64_t operator_fee = mul128_div64(sn_info.portions_for_operator, distribution_amount, old::STAKING_PORTIONS);

    assert(operator_fee <= distribution_amount);

    payments.clear();
    // Pay the operator fee to the operator
    if (operator_fee > 0)
      payments.emplace_back(sn_info.operator_address, operator_fee);

    // Pay the balance to all the contributors (including the operator again)
    uint64_t total_contributed_to_sn = std::accumulate(
        sn_info.contributors.begin(),
        sn_info.contributors.end(),
        uint64_t(0),
        [](auto&& a, auto&& b) { return a + b.amount; });

    for (auto& contributor: sn_info.contributors) {
      // This calculates (contributor.amount / total_contributed_to_winner_sn) * (distribution_amount - operator_fee) but using 128 bit integer math
      uint64_t c_reward = mul128_div64(contributor.amount, distribution_amount - operator_fee, total_contributed_to_sn);
      if (c_reward > 0)
        payments.emplace_back(contributor.address, c_reward);
    }
  }

  // Calculates block rewards, then invokes either `add_sn_rewards` (if `add`) or
  // `subtract_sn_rewards` (if `!add`) to process them.
  bool BlockchainSQLite::reward_handler(
      const cryptonote::block& block,
      const service_nodes::service_node_list::state_t& service_nodes_state,
      bool add)
  {
    // The method we call do actually handle the change: either `add_sn_payments` if add is true,
    // `subtract_sn_payments` otherwise:
    bool (BlockchainSQLite::* add_or_subtract)(const std::vector<cryptonote::batch_sn_payment>&)
      = add ? &BlockchainSQLite::add_sn_rewards : &BlockchainSQLite::subtract_sn_rewards;

    // From here on we calculate everything in milli-atomic OXEN (i.e. thousanths of an atomic
    // OXEN) so that our integer math has minimal loss from integer division.
    if (block.reward > std::numeric_limits<uint64_t>::max() / BATCH_REWARD_FACTOR)
      throw std::logic_error{"Reward distribution amount is too large"};

    uint64_t block_reward = block.reward * BATCH_REWARD_FACTOR;
    uint64_t service_node_reward = cryptonote::service_node_reward_formula(0, block.major_version) * BATCH_REWARD_FACTOR;

    std::vector<cryptonote::batch_sn_payment> payments;

    // Step 1: Pay out the block producer their tx fees (note that, unlike the below, this applies
    // even if the SN isn't currently payable).
    if (block_reward < service_node_reward && m_nettype != cryptonote::network_type::FAKECHAIN)
      throw std::logic_error{"Invalid payment: block reward is too small"};

    std::lock_guard a_s_lock{address_str_cache_mutex};

    if (uint64_t tx_fees = block_reward - service_node_reward;
        tx_fees > 0
        && block.service_node_winner_key // "service_node_winner_key" tracks the pulse winner; 0 if a mined block
        && crypto_core_ed25519_is_valid_point(reinterpret_cast<const unsigned char *>(block.service_node_winner_key.data))
    ) {

      if (auto service_node_winner = service_nodes_state.service_nodes_infos.find(block.service_node_winner_key);
          service_node_winner != service_nodes_state.service_nodes_infos.end()) {
        calculate_rewards(block.major_version, tx_fees, *service_node_winner->second, payments);
        // Takes the block producer and adds its contributors to the batching database for the transaction fees
        if (!(this->*add_or_subtract)(payments))
          return false;
      }
    }

    auto block_height = get_block_height(block);

    // Step 2: Iterate over the whole service node list and pay each node 1/service_node_list fraction
    const auto payable_service_nodes = service_nodes_state.payable_service_nodes_infos(block_height, m_nettype);
    size_t total_service_nodes_payable = payable_service_nodes.size();
    for (const auto& [node_pubkey, node_info]: payable_service_nodes) {
      auto payable_service_node = service_nodes_state.service_nodes_infos.find(node_pubkey);
      if (payable_service_node == service_nodes_state.service_nodes_infos.end())
        continue;
      calculate_rewards(block.major_version, service_node_reward / total_service_nodes_payable, * payable_service_node -> second, payments);
      // Takes the node and adds its contributors to the batching database
      if (!(this->*add_or_subtract)(payments))
        return false;
    }

    // Step 3: Add Governance reward to the list
    if (m_nettype != cryptonote::network_type::FAKECHAIN) {
      if (parsed_governance_addr.first != block.major_version) {
        cryptonote::get_account_address_from_str(parsed_governance_addr.second, m_nettype,
            cryptonote::get_config(m_nettype).governance_wallet_address(block.major_version));
        parsed_governance_addr.first = block.major_version;
      }
      uint64_t foundation_reward = cryptonote::governance_reward_formula(block.major_version) * BATCH_REWARD_FACTOR;
      payments.clear();
      payments.emplace_back(parsed_governance_addr.second.address, foundation_reward);
      if (!(this->*add_or_subtract)(payments))
        return false;
    }

    return true;
  }

  bool BlockchainSQLite::add_block(const cryptonote::block& block,
    const service_nodes::service_node_list::state_t& service_nodes_state) {
    auto block_height = get_block_height(block);
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " called on height: " << block_height);

    auto hf_version = block.major_version;
    if (hf_version < hf::hf19_reward_batching) {
      update_height(block_height);
      return true;
    }

    auto fork_height = cryptonote::get_hard_fork_heights(m_nettype, hf::hf19_reward_batching);
    if (block_height == fork_height.first.value_or(0)) {
      MDEBUG("Batching of Service Node Rewards Begins");
      reset_database();
      update_height(block_height - 1);
    }

    if (block_height != height + 1) {
      MERROR(fmt::format("Block height ({}) out of sync with batching database ({})", block_height, height));
      return false;
    }

    // We query our own database as a source of truth to verify the blocks payments against. The calculated_rewards
    // variable contains a known good list of who should have been paid in this block 
    auto calculated_rewards = get_sn_payments(block_height);

    // We iterate through the block's coinbase payments and build a copy of our own list of the payments
    // miner_tx_vouts this will be compared against calculated_rewards and if they match we know the block is
    // paying the correct people only.
    std::vector<std::tuple<crypto::public_key, uint64_t>> miner_tx_vouts;
    for (auto & vout: block.miner_tx.vout)
      miner_tx_vouts.emplace_back(var::get<txout_to_key>(vout.target).key, vout.amount);

    try {
      SQLite::Transaction transaction {
        db,
        SQLite::TransactionBehavior::IMMEDIATE
      };

      // Goes through the miner transactions vouts checks they are right and marks them as paid in the database
      if (!validate_batch_payment(miner_tx_vouts, calculated_rewards, block_height)) {
        return false;
      }

      if (!reward_handler(block, service_nodes_state, /*add=*/ true))
        return false;

      increment_height();

      transaction.commit();
    } catch (std::exception& e) {
      MFATAL("Error adding reward payments: " << e.what());
      return false;
    }
    return true;
  }

  bool BlockchainSQLite::pop_block(const cryptonote::block& block,
    const service_nodes::service_node_list::state_t& service_nodes_state) {
    auto block_height = get_block_height(block);

    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " called on height: " << block_height);
    if (height < block_height) {
      MDEBUG("Block above batching DB height skipping pop");
      return true;
    }
    if (block_height != height) {
      MERROR("Block height out of sync with batching database");
      return false;
    }

    const auto& conf = get_config(m_nettype);
    auto hf_version = block.major_version;
    if (hf_version < hf::hf19_reward_batching) {
      decrement_height();
      return true;
    }

    try {
      SQLite::Transaction transaction {
        db,
        SQLite::TransactionBehavior::IMMEDIATE
      };


      if (!reward_handler(block, service_nodes_state, /*add=*/ false))
        return false;

      // Add back to the database payments that had been made in this block
      delete_block_payments(block_height);

      decrement_height();
      transaction.commit();
    } catch (std::exception& e) {
      MFATAL("Error subtracting reward payments: " << e.what());
      return false;
    }
    return true;
  }

  bool BlockchainSQLite::validate_batch_payment(
      const std::vector<std::tuple<crypto::public_key, uint64_t>>& miner_tx_vouts,
      const std::vector<cryptonote::batch_sn_payment>& calculated_payments_from_batching_db,
      uint64_t block_height) {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

    if (miner_tx_vouts.size() != calculated_payments_from_batching_db.size()) {
      MERROR(fmt::format("Length of batch payments ({}) does not match block vouts ({})", calculated_payments_from_batching_db.size(), miner_tx_vouts.size()));
      return false;
    }

    int8_t vout_index = 0;
    uint64_t total_oxen_payout_in_our_db = std::accumulate(
        calculated_payments_from_batching_db.begin(),
        calculated_payments_from_batching_db.end(),
        uint64_t(0),
        [](auto&& a, auto&& b) { return a + b.amount; });
    uint64_t total_oxen_payout_in_vouts = 0;
    std::vector<batch_sn_payment> finalised_payments;
    cryptonote::keypair
    const deterministic_keypair = cryptonote::get_deterministic_keypair_from_height(block_height);
    for (size_t vout_index = 0; vout_index < miner_tx_vouts.size(); vout_index++) {
      const auto& [pubkey, amt] = miner_tx_vouts[vout_index];
      uint64_t amount = amt * BATCH_REWARD_FACTOR;
      const auto& from_db = calculated_payments_from_batching_db[vout_index];
      if (amount != from_db.amount) {
        MERROR(fmt::format("Batched payout amount incorrect. Should be {}, not {}", from_db.amount, amount));
        return false;
      }
      crypto::public_key out_eph_public_key{};
      if (!cryptonote::get_deterministic_output_key(from_db.address_info.address, deterministic_keypair, vout_index, out_eph_public_key)) {
        MERROR("Failed to generate output one-time public key");
        return false;
      }
      if (tools::view_guts(pubkey) != tools::view_guts(out_eph_public_key)) {
        MERROR("Output ephemeral public key does not match");
        return false;
      }
      total_oxen_payout_in_vouts += amount;
      finalised_payments.emplace_back(from_db.address_info, amount);
    }
    if (total_oxen_payout_in_vouts != total_oxen_payout_in_our_db) {
      MERROR(fmt::format("Total batched payout amount incorrect. Should be {}, not {}", total_oxen_payout_in_our_db, total_oxen_payout_in_vouts));
      return false;
    }

    return save_payments(block_height, finalised_payments);
  }

  bool BlockchainSQLite::save_payments(uint64_t block_height, const std::vector<batch_sn_payment>& paid_amounts) {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__);

    auto select_sum = prepared_st(
      "SELECT amount from batched_payments_accrued WHERE address = ?");

    auto update_paid = prepared_st(
      "INSERT INTO batched_payments_paid (address, amount, height_paid) VALUES (?,?,?)");

    std::lock_guard a_s_lock{address_str_cache_mutex};

    for (const auto& payment: paid_amounts) {
      const auto& address_str = get_address_str(payment.address_info.address);
      if (auto maybe_amount = db::exec_and_maybe_get<int64_t>(select_sum, address_str))
      {
        // Truncate the thousanths amount to an atomic OXEN:
        auto amount = static_cast<uint64_t>(*maybe_amount) / BATCH_REWARD_FACTOR * BATCH_REWARD_FACTOR;

        if (amount != payment.amount) {
          MERROR(fmt::format("Invalid amounts passed in to save payments for address {}: received {}, expected {} (truncated from {})",
                address_str, payment.amount, amount, *maybe_amount));
          return false;
        }

        db::exec_query(update_paid, address_str, static_cast<int64_t>(amount), static_cast<int64_t>(block_height));
        update_paid->reset();
      }
      else {
        // This shouldn't occur: we validate payout addresses much earlier in the block validation.
        MERROR(fmt::format("Internal error: Invalid amounts passed in to save payments for address {}: that address has no accrued rewards",
              address_str));
        return false;
      }

      select_sum->reset();
    }
    return true;
  }

  std::vector<cryptonote::batch_sn_payment> BlockchainSQLite::get_block_payments(uint64_t block_height) {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " Called with height: " << block_height);

    std::vector<cryptonote::batch_sn_payment> payments_at_height;
    auto paid = prepared_results<std::string_view, int64_t>(
      "SELECT address, amount FROM batched_payments_paid WHERE height_paid = ? ORDER BY address",
      static_cast<int64_t>(block_height));

    for (auto [addr, amt] : paid) {
      auto& p = payments_at_height.emplace_back();
      p.amount = static_cast<uint64_t>(amt);
      cryptonote::get_account_address_from_str(p.address_info, m_nettype, addr);
    }

    return payments_at_height;
  }

  bool BlockchainSQLite::delete_block_payments(uint64_t block_height) {
    LOG_PRINT_L3("BlockchainDB_SQLITE::" << __func__ << " Called with height: " << block_height);
    prepared_exec(
        "DELETE FROM batched_payments_paid WHERE height_paid >= ?",
        static_cast<int64_t>(block_height));
    return true;
  }

} // namespace cryptonote
