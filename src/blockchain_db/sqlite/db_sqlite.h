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

#pragma once

#include <string>
#include <filesystem>

#include "epee/misc_log_ex.h"
#include "../../cryptonote_basic/cryptonote_format_utils.h"
#include "../../cryptonote_core/cryptonote_tx_utils.h"
#include "common/fs.h"

#include <SQLiteCpp/SQLiteCpp.h>

namespace cryptonote
{

class BlockchainSQLite
{
public:
  BlockchainSQLite() = default;
  BlockchainSQLite(const BlockchainSQLite &other);

  // Database management functions. Should be called on creation of BlockchainSQLite
  void create_schema();
  void clear_database();
  void load_database(cryptonote::network_type nettype, std::optional<fs::path> file);

  // The batching database maintains a height variable to know if it gets out of sync with the mainchain. Calling increment and decrement is the primary method of interacting with this height variable
  bool update_height(uint64_t new_height);
  bool increment_height();
  bool decrement_height();

  // Helper functions, used in testing to assess the state of the database
  uint64_t batching_count();
  std::optional<uint64_t> retrieve_amount_by_address(const std::string& address);

  // add_sn_payments -> passing an array of addresses and amounts. These will be added or subtracted to the database for each address specified. If the address does not exist it will be created.
  bool add_sn_payments(std::vector<cryptonote::batch_sn_payment>& payments, uint64_t block_height);

  // get_payments -> passing a block height will return an array of payments that should be created in a coinbase transaction on that block given the current batching DB state.
  std::optional<std::vector<cryptonote::batch_sn_payment>> get_sn_payments(uint64_t block_height);

  // calculate_rewards -> takes a list of contributors with their SN contribution amounts and will calculate how much of the block rewards should be the allocated to the contributors. The function will return a list suitable for passing to add_sn_payments
  std::vector<cryptonote::batch_sn_payment> calculate_rewards(const cryptonote::block& block, std::vector<cryptonote::batch_sn_payment> contributors);

  // add/pop_block -> takes a block that contains new block rewards to be batched and added to the database and/or batching payments that need to be subtracted from the database, in addition it takes an externally generated list of contributors for the SN winner of that block. The function will then process this block add and subtracting to the batching DB appropriately. This is the primary entry point for the blockchain to add to the batching database. Each accepted block should call this passing in the SN winners contributors at the same time.
  bool add_block(const cryptonote::block &block, std::vector<cryptonote::batch_sn_payment> contributors);
  bool pop_block(const cryptonote::block &block, std::vector<cryptonote::batch_sn_payment> contributors);

  // validate_batch_payment -> used to make sure that list of miner_tx_vouts is correct. Compares the miner_tx_vouts with a list previously extracted payments to make sure that the correct persons are being paid.
  bool validate_batch_payment(std::vector<std::tuple<crypto::public_key, uint64_t>> miner_tx_vouts, std::vector<cryptonote::batch_sn_payment> calculated_payments_from_batching_db, uint64_t block_height, bool save_payment);
  
  // these keep track of payments made to SN operators after then payment has been made. Allows for popping blocks back and knowing who got paid in those blocks.
  // passing in a list of people to be marked as paid in the paid_amounts vector, the amounts MUST reconcile with what is currently in the database 
  // else it will fail. Block height will be added to the batched_payments database as height_paid.
  bool save_payments(uint64_t block_height, std::vector<batch_sn_payment> paid_amounts);
  std::vector<cryptonote::batch_sn_payment> get_block_payments(uint64_t block_height);
  bool delete_block_payments(uint64_t block_height);

  uint64_t height;

  cryptonote::network_type m_nettype;
  std::unique_ptr<SQLite::Database> db;
  std::string filename;

private:

};

}
