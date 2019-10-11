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

using namespace epee;
using namespace cryptonote;


//======================================================================================================================

gen_double_spend_in_different_chains::gen_double_spend_in_different_chains()
{
  REGISTER_CALLBACK_METHOD(gen_double_spend_in_different_chains, check_double_spend);
}

bool gen_double_spend_in_different_chains::generate(std::vector<test_event_entry>& events) const
{
  INIT_DOUBLE_SPEND_TEST();

  SET_EVENT_VISITOR_SETT(events, event_visitor_settings::set_txs_keeped_by_block, true);
  MAKE_TX(events, tx_1, bob_account, alice_account, send_amount / 2 - TESTS_DEFAULT_FEE, blk_1);
  events.pop_back();
  MAKE_TX(events, tx_2, bob_account, alice_account, send_amount - TESTS_DEFAULT_FEE, blk_1);
  events.pop_back();

  // Main chain
  events.push_back(tx_1);
  MAKE_NEXT_BLOCK_TX1(events, blk_2, blk_1r, miner_account, tx_1);

  // Alternative chain
  events.push_back(tx_2);
  MAKE_NEXT_BLOCK_TX1(events, blk_3, blk_1r, miner_account, tx_2);
  // Switch to alternative chain
  MAKE_NEXT_BLOCK(events, blk_4, blk_3, miner_account);
  //CHECK_AND_NO_ASSERT_MES(expected_blockchain_height == get_block_height(blk_4) + 1, false, "expected_blockchain_height has invalid value");
  if ((expected_blockchain_height != get_block_height(blk_4) + 1)) LOG_ERROR("oops");

  DO_CALLBACK(events, "check_double_spend");

  return true;
}

bool gen_double_spend_in_different_chains::check_double_spend(cryptonote::core& c, size_t /*ev_index*/, const std::vector<test_event_entry>& events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_double_spend_in_different_chains::check_double_spend");

  std::vector<block> blocks;
  bool r = c.get_blocks(0, 100 + 2 * CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, blocks);
  CHECK_TEST_CONDITION(r);

  //CHECK_EQ(expected_blockchain_height, blocks.size());
  if (expected_blockchain_height != blocks.size()) LOG_ERROR ("oops");

  CHECK_EQ(1, c.get_pool().get_transactions_count());
  CHECK_EQ(1, c.get_alternative_blocks_count());

  cryptonote::account_base bob_account = boost::get<cryptonote::account_base>(events[1]);
  cryptonote::account_base alice_account = boost::get<cryptonote::account_base>(events[2]);

  std::vector<cryptonote::block> chain;
  map_hash2tx_t mtx;
  r = find_block_chain(events, chain, mtx, get_block_hash(blocks.back()));
  CHECK_TEST_CONDITION(r);
  CHECK_EQ(0, get_balance(bob_account, blocks, mtx));
  CHECK_EQ(send_amount - TESTS_DEFAULT_FEE, get_balance(alice_account, blocks, mtx));

  return true;
}

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
    if (!construct_tx(gen.first_miner_.get_keys(), sources, destinations, boost::none, std::vector<uint8_t>(), tx_1, 0, gen.hf_version_))
      return false;

    uint64_t expected_height = gen.height();
    loki_blockchain_entry entry = gen.create_next_block({tx_1}); // Double spending TX
    gen.add_tx(tx_1, false /*can_be_added_to_blockchain*/, "Can't add TX with double spending output", false /*kept_by_block*/);
    gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Can't add block with double spending tx");

    loki_register_callback(events, "check_block_and_txpool_unaffected", [&events, expected_height](cryptonote::core &c, size_t ev_index)
    {
      DEFINE_TESTS_ERROR_CONTEXT("check_block_and_txpool_unaffected");
      uint64_t top_height;
      crypto::hash top_hash;
      c.get_blockchain_top(top_height, top_hash);
      CHECK_TEST_CONDITION(top_height == expected_height);
      CHECK_TEST_CONDITION_MSG(c.get_pool_transactions_count() == 0, "The double spend TX should not be added to the pool");
      return true;
    });
  }

  // NOTE: Do the same with a new transaction but this time kept by block, can't reused old transaction because we cache the bad TX hash
  {
    cryptonote::transaction tx_1;
    if (!construct_tx(gen.first_miner_.get_keys(), sources, destinations, boost::none, std::vector<uint8_t>(), tx_1, 0, gen.hf_version_))
      return false;

    uint64_t expected_height    = gen.height();
    loki_blockchain_entry entry = gen.create_next_block({tx_1}); // Double spending TX
    gen.add_tx(tx_1, false /*can_be_added_to_blockchain*/, "Can't add TX with double spending output even if kept by block", true /*kept_by_block*/);
    gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Can't add block with double spending tx");

    loki_register_callback(events, "check_block_and_txpool_unaffected_even_if_kept_by_block", [&events, expected_height](cryptonote::core &c, size_t ev_index)
    {
      DEFINE_TESTS_ERROR_CONTEXT("check_block_and_txpool_unaffected_even_if_kept_by_block");
      uint64_t top_height;
      crypto::hash top_hash;
      c.get_blockchain_top(top_height, top_hash);
      CHECK_TEST_CONDITION(top_height == expected_height);
      CHECK_TEST_CONDITION_MSG(c.get_pool_transactions_count() == 0, "The double spend TX should not be added to the pool");
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
    bool kept_by_block                    = static_cast<bool>(kept_by_block_int);
    uint64_t amount                       = MK_COINS(10);
    cryptonote::account_base const &miner = gen.first_miner_;
    cryptonote::account_base bob          = gen.add_account();
    cryptonote::transaction tx_1 = gen.create_tx(miner, bob, amount, TESTS_DEFAULT_FEE);
    cryptonote::transaction tx_2 = gen.create_and_add_tx(miner, bob, amount, TESTS_DEFAULT_FEE);

    std::string const fail_msg =
        (kept_by_block) ? "If kept_by_block is true, double spending transactions can be added (incase of reorgs)"
                        : "Can not add a double spending transaction if kept_by_block is false";

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
