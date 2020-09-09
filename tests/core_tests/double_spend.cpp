// Copyright (c) 2014-2018, The Monero Project
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
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "chaingen.h"
#include "double_spend.h"

using namespace cryptonote;


//======================================================================================================================

bool gen_double_spend_in_tx::generate(std::vector<test_event_entry>& events) const
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(20);
  gen.add_mined_money_unlock_blocks();

  uint64_t amount              = MK_COINS(10);
  cryptonote::account_base bob = gen.add_account();

  std::vector<cryptonote::tx_source_entry> sources;
  std::vector<cryptonote::tx_destination_entry> destinations;
  fill_tx_sources_and_destinations(gen.events_,
                                   gen.top().block,
                                   gen.first_miner_,
                                   bob.get_keys().m_account_address,
                                   amount,
                                   TESTS_DEFAULT_FEE,
                                   9, // nmix
                                   sources,
                                   destinations);
  sources.push_back(sources.back()); // Double spend!

  {
    cryptonote::transaction tx_1;
    loki_construct_tx_params tx_params;
    tx_params.hf_version = gen.hf_version_;
    if (!construct_tx(gen.first_miner_.get_keys(), sources, destinations, std::nullopt, std::vector<uint8_t>(), tx_1, 0, tx_params))
      return false;

    uint64_t expected_height = gen.height();
    loki_blockchain_entry entry = gen.create_next_block({tx_1}); // Double spending TX
    gen.add_tx(tx_1, false /*can_be_added_to_blockchain*/, "Can't add TX with double spending output", false /*kept_by_block*/);
    gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Can't add block with double spending tx");

    loki_register_callback(events, "check_block_and_txpool_unaffected", [expected_height](cryptonote::core &c, size_t ev_index)
    {
      DEFINE_TESTS_ERROR_CONTEXT("check_block_and_txpool_unaffected");
      uint64_t top_height;
      crypto::hash top_hash;
      c.get_blockchain_top(top_height, top_hash);
      CHECK_TEST_CONDITION(top_height == expected_height);
      CHECK_TEST_CONDITION_MSG(c.get_pool().get_transactions_count() == 0, "The double spend TX should not be added to the pool");
      return true;
    });
  }

  // NOTE: Do the same with a new transaction but this time kept by block, can't reused old transaction because we cache the bad TX hash
  {
    cryptonote::transaction tx_1;
    loki_construct_tx_params tx_params;
    tx_params.hf_version = gen.hf_version_;
    if (!construct_tx(gen.first_miner_.get_keys(), sources, destinations, std::nullopt, std::vector<uint8_t>(), tx_1, 0, tx_params))
      return false;

    uint64_t expected_height    = gen.height();
    loki_blockchain_entry entry = gen.create_next_block({tx_1}); // Double spending TX
    gen.add_tx(tx_1, false /*can_be_added_to_blockchain*/, "Can't add TX with double spending output even if kept by block", true /*kept_by_block*/);
    gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Can't add block with double spending tx");

    loki_register_callback(events, "check_block_and_txpool_unaffected_even_if_kept_by_block", [expected_height](cryptonote::core &c, size_t ev_index)
    {
      DEFINE_TESTS_ERROR_CONTEXT("check_block_and_txpool_unaffected_even_if_kept_by_block");
      uint64_t top_height;
      crypto::hash top_hash;
      c.get_blockchain_top(top_height, top_hash);
      CHECK_TEST_CONDITION(top_height == expected_height);
      CHECK_TEST_CONDITION_MSG(c.get_pool().get_transactions_count() == 0, "The double spend TX should not be added to the pool");
      return true;
    });
  }
  return true;
}

bool gen_double_spend_in_the_same_block::generate(std::vector<test_event_entry>& events) const
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(10);
  gen.add_mined_money_unlock_blocks();

  for (int kept_by_block_int = 0; kept_by_block_int < 2; kept_by_block_int++)
  {
    bool kept_by_block = static_cast<bool>(kept_by_block_int);
    if (kept_by_block)
      gen.add_event_msg("Double spending transaction kept by block should be allowed");
    else
      gen.add_event_msg("Double spending transaction kept by block false, disallowed");

    uint64_t amount                       = MK_COINS(10);
    cryptonote::account_base const &miner = gen.first_miner_;
    cryptonote::account_base bob          = gen.add_account();
    cryptonote::transaction tx_1 = gen.create_tx(miner, bob.get_keys().m_account_address, amount, TESTS_DEFAULT_FEE);
    cryptonote::transaction tx_2 = gen.create_and_add_tx(miner, bob.get_keys().m_account_address, amount, TESTS_DEFAULT_FEE);

    std::string const fail_msg =
        (kept_by_block) ? "kept_by_block is true, double spending transactions can be added (incase of reorgs)"
                        : "Can not add a double spending transaction, kept_by_block is false";

    gen.add_tx(tx_1, kept_by_block /*can_be_added_to_blockchain*/, fail_msg, kept_by_block/*kept_by_block*/);
    gen.create_and_add_next_block({tx_1, tx_2}, nullptr /*checkpoint*/, false, "Can not add block using double spend txs, even if one of the double spends is kept by block.");
    crypto::hash last_block_hash = cryptonote::get_block_hash(gen.top().block);

    loki_register_callback(events, "check_balances", [&events, miner, bob, last_block_hash](cryptonote::core &c, size_t ev_index)
    {
      DEFINE_TESTS_ERROR_CONTEXT("check_balances");
      std::vector<cryptonote::block> chain;
      map_hash2tx_t mtx;
      CHECK_TEST_CONDITION(find_block_chain(events, chain, mtx, last_block_hash));
      CHECK_EQ(get_balance(bob, chain, mtx), 0);
      return true;
    });
  }
  return true;
}

bool gen_double_spend_in_different_blocks::generate(std::vector<test_event_entry>& events) const
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(10);
  gen.add_mined_money_unlock_blocks();

  cryptonote::account_base const &miner = gen.first_miner_;
  cryptonote::account_base bob          = gen.add_account();
  for (int kept_by_block_int = 0; kept_by_block_int < 2; kept_by_block_int++)
  {
    bool kept_by_block = static_cast<bool>(kept_by_block_int);
    if (kept_by_block) gen.add_event_msg("Double spending transaction kept by block should be allowed");
    else               gen.add_event_msg("Double spending transaction kept by block false, disallowed");

    uint64_t amount              = MK_COINS(10);
    cryptonote::transaction tx_1 = gen.create_tx(miner, bob.get_keys().m_account_address, amount, TESTS_DEFAULT_FEE);
    cryptonote::transaction tx_2 = gen.create_tx(miner, bob.get_keys().m_account_address, amount, TESTS_DEFAULT_FEE);

    std::string const fail_msg =
        (kept_by_block) ? "kept_by_block is true, double spending transactions can be added (incase of reorgs)"
                        : "Can not add a double spending transaction, kept_by_block is false";

    gen.add_tx(tx_1, true /*can_be_added_to_blockchain*/, fail_msg, kept_by_block);
    gen.create_and_add_next_block({tx_1});

    gen.add_tx(tx_2, kept_by_block /*can_be_added_to_blockchain*/, fail_msg, kept_by_block /*kept_by_block*/);
    // NOTE: This should always fail regardless, because even if transaction is kept by block and accepted. Adding this block would enable a double spend.
    // Similarly, if kept by block is false, adding the double spend tx should fail. Adding the new block should also fail because we don't have tx_2
    // sitting in the tx pool.
    gen.create_and_add_next_block({tx_2}, nullptr, false /*can_be_added_to_blockchain*/, fail_msg);
    loki_register_callback(events, "check_txpool", [kept_by_block](cryptonote::core &c, size_t ev_index)
    {
      DEFINE_TESTS_ERROR_CONTEXT("check_txpool");
      if (kept_by_block) CHECK_EQ(c.get_pool().get_transactions_count(), 1);
      else               CHECK_EQ(c.get_pool().get_transactions_count(), 0);
      return true;
    });
  }
  return true;
}

bool gen_double_spend_in_alt_chain_in_the_same_block::generate(std::vector<test_event_entry>& events) const
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(10);
  gen.add_mined_money_unlock_blocks();

  auto fork = gen;
  for (int kept_by_block_int = 0; kept_by_block_int < 2; kept_by_block_int++)
  {
    bool kept_by_block = static_cast<bool>(kept_by_block_int);
    if (kept_by_block)
      fork.add_event_msg("Double spending transaction kept by block should be allowed");
    else
      fork.add_event_msg("Double spending transaction kept by block false, disallowed");

    uint64_t amount                       = MK_COINS(10);
    cryptonote::account_base const &miner = fork.first_miner_;
    cryptonote::account_base bob          = fork.add_account();
    cryptonote::transaction tx_1 = fork.create_tx(miner, bob.get_keys().m_account_address, amount, TESTS_DEFAULT_FEE);
    cryptonote::transaction tx_2 = fork.create_and_add_tx(miner, bob.get_keys().m_account_address, amount, TESTS_DEFAULT_FEE);

    std::string const fail_msg =
        (kept_by_block) ? "kept_by_block is true, double spending transactions can be added (incase of reorgs)"
                        : "Can not add a double spending transaction, kept_by_block is false";

    fork.add_tx(tx_1, kept_by_block /*can_be_added_to_blockchain*/, fail_msg, kept_by_block/*kept_by_block*/);
    fork.create_and_add_next_block({tx_1, tx_2}, nullptr /*checkpoint*/, false, "Can not add block using double spend txs, even if one of the double spends is kept by block.");
    crypto::hash last_block_hash = cryptonote::get_block_hash(fork.top().block);

    loki_register_callback(events, "check_balances", [&events, miner, bob, last_block_hash](cryptonote::core &c, size_t ev_index)
    {
      DEFINE_TESTS_ERROR_CONTEXT("check_balances");
      std::vector<cryptonote::block> chain;
      map_hash2tx_t mtx;
      CHECK_TEST_CONDITION(find_block_chain(events, chain, mtx, last_block_hash));
      CHECK_EQ(get_balance(bob, chain, mtx), 0);
      return true;
    });
  }
  return true;
}

bool gen_double_spend_in_alt_chain_in_different_blocks::generate(std::vector<test_event_entry>& events) const
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(10);
  gen.add_mined_money_unlock_blocks();

  auto fork                             = gen;
  cryptonote::account_base const &miner = fork.first_miner_;
  cryptonote::account_base bob          = fork.add_account();
  for (int kept_by_block_int = 0; kept_by_block_int < 2; kept_by_block_int++)
  {
    bool kept_by_block = static_cast<bool>(kept_by_block_int);
    if (kept_by_block) fork.add_event_msg("Double spending transaction kept by block should be allowed");
    else               fork.add_event_msg("Double spending transaction kept by block false, disallowed");

    uint64_t amount              = MK_COINS(10);
    cryptonote::transaction tx_1 = fork.create_tx(miner, bob.get_keys().m_account_address, amount, TESTS_DEFAULT_FEE);
    cryptonote::transaction tx_2 = fork.create_tx(miner, bob.get_keys().m_account_address, amount, TESTS_DEFAULT_FEE);

    std::string const fail_msg =
        (kept_by_block) ? "kept_by_block is true, double spending transactions can be added (incase of reorgs)"
                        : "Can not add a double spending transaction, kept_by_block is false";

    fork.add_tx(tx_1, true /*can_be_added_to_blockchain*/, fail_msg, kept_by_block);
    fork.create_and_add_next_block({tx_1});

    fork.add_tx(tx_2, kept_by_block /*can_be_added_to_blockchain*/, fail_msg, kept_by_block /*kept_by_block*/);
    fork.create_and_add_next_block({tx_2}, nullptr, false /*can_be_added_to_blockchain*/, fail_msg);
    loki_register_callback(events, "check_txpool", [kept_by_block](cryptonote::core &c, size_t ev_index)
    {
      DEFINE_TESTS_ERROR_CONTEXT("check_txpool");
      if (kept_by_block) CHECK_EQ(c.get_pool().get_transactions_count(), 1);
      else               CHECK_EQ(c.get_pool().get_transactions_count(), 0);
      return true;
    });
  }
  return true;
}

char *tprint(char const *fmt, ...)
{
  LOCAL_PERSIST char buffer[1024];
  buffer[0] = 0;
  snprintf(buffer, );
}

bool gen_double_spend_in_different_chains::generate(std::vector<test_event_entry>& events) const
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table(cryptonote::network_version_15_lns);
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(10);
  gen.add_mined_money_unlock_blocks();

  uint64_t amount = MK_COINS(10);
  cryptonote::account_base const &miner = gen.first_miner_;
  cryptonote::account_base bob          = gen.add_account();
  cryptonote::transaction tx_1          = gen.create_tx(miner, bob.get_keys().m_account_address, amount, TESTS_DEFAULT_FEE);
  cryptonote::transaction tx_2          = gen.create_tx(miner, bob.get_keys().m_account_address, amount, TESTS_DEFAULT_FEE);

  auto fork = gen;
  gen.add_tx(tx_1, true /*can_be_added_to_blockchain*/, "", true /*kept_by_block*/);
  fork.add_tx(tx_2, true /*can_be_added_to_blockchain*/, "", true /*kept_by_block*/);
  gen.create_and_add_next_block({tx_1});
  fork.create_and_add_next_block({tx_2});
  fork.add_event_msg("Add new block to fork to cause a reorg to the alt chain with a double spending transaction");
  fork.create_and_add_next_block();
  crypto::hash block_hash = cryptonote::get_block_hash(fork.top().block);

  loki_register_callback(events, "check_top_block", [block_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_txpool");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(top_hash, block_hash);

    // TODO(loki): This is questionable behaviour, currently we keep alt chains even after switching over
    CHECK_EQ(c.get_pool().get_transactions_count(), 1);
    CHECK_EQ(c.get_alternative_blocks_count(), 1);
    return true;
  });
  return true;
}
