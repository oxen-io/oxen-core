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

#include "loki_tests.h"
#include "cryptonote_core/service_node_list.h"
#include "common/random.h"

extern "C"
{
#include <sodium.h>
};

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "sn_core_tests"

// Suppose we have checkpoint and alt block at height 40 and the main chain is at height 40 with a differing block.
// Main chain receives checkpoints for height 40 on the alt chain via votes and reorgs back to height 39.
// Now main chain has an alt block sitting in its DB for height 40 which actually starts beyond the chain.

// In Monero land this is NOT ok because of the check in build_alt_chain
// CHECK_AND_ASSERT_MES(m_db->height() > alt_chain.front().height, false, "main blockchain wrong height");
// Where (m_db->height() == 40 and alt_chain.front().height == 40)

// So, we change the > to a >= because it appears the code handles it fine and
// it saves us from having to delete our alt_blocks and have to re-receive the
// block over P2P again "just so that it can go through the normal block added
// code path" again
bool loki_checkpointing_alt_chain_handle_alt_blocks_at_tip::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  int constexpr NUM_SERVICE_NODES = service_nodes::CHECKPOINT_QUORUM_SIZE;
  std::vector<cryptonote::transaction> registration_txs(NUM_SERVICE_NODES);
  for (auto i = 0u; i < NUM_SERVICE_NODES; ++i)
    registration_txs[i] = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block(registration_txs);

  // NOTE: Add blocks until we get to the first height that has a checkpointing quorum AND there are service nodes in the quorum.
  int const MAX_TRIES = 16;
  int tries           = 0;
  for (; tries < MAX_TRIES; tries++)
  {
    gen.add_blocks_until_next_checkpointable_height();
    std::shared_ptr<const service_nodes::quorum> quorum = gen.get_quorum(service_nodes::quorum_type::checkpointing, gen.height());
    if (quorum && quorum->validators.size()) break;
  }
  assert(tries != MAX_TRIES);

  for (size_t i = 0; i < service_nodes::CHECKPOINT_INTERVAL - 1; i++)
    gen.create_and_add_next_block();

  // NOTE: Create next block on checkpoint boundary and add checkpoiont
  loki_chain_generator fork = gen;
  gen.create_and_add_next_block();
  fork.create_and_add_next_block();
  fork.add_service_node_checkpoint(fork.height(), service_nodes::CHECKPOINT_MIN_VOTES);

  // NOTE: Though we receive a checkpoint via votes, the alt block is still in
  // the alt db because we don't trigger a chain switch until we receive a 2nd
  // block that confirms the alt block.
  uint64_t curr_height   = gen.height();
  crypto::hash curr_hash = get_block_hash(gen.top().block);
  loki_register_callback(events, "check_alt_block_count", [curr_height, curr_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_alt_block_count");

    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(top_height, curr_height);
    CHECK_EQ(top_hash, curr_hash);
    CHECK_EQ(c.get_blockchain_storage().get_alternative_blocks_count(), 1);
    return true;
  });

  // NOTE: We add a new block ontop that causes the alt block code path to run
  // again, and calculate that this alt chain now has 2 blocks on it with
  // now same difficulty but more checkpoints, causing a chain switch at this point.
  gen.create_and_add_next_block();
  fork.create_and_add_next_block();
  crypto::hash expected_top_hash = cryptonote::get_block_hash(fork.top().block);
  loki_register_callback(events, "check_chain_reorged", [expected_top_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_chain_reorged");
    CHECK_EQ(c.get_blockchain_storage().get_alternative_blocks_count(), 0);
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(expected_top_hash, top_hash);
    return true;
  });
  return true;
}

// NOTE: - Checks that a chain with a checkpoint but less PoW is preferred over a chain that is longer with more PoW but no checkpoints
bool loki_checkpointing_alt_chain_more_service_node_checkpoints_less_pow_overtakes::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  int constexpr NUM_SERVICE_NODES = service_nodes::CHECKPOINT_QUORUM_SIZE;
  std::vector<cryptonote::transaction> registration_txs(NUM_SERVICE_NODES);
  for (auto i = 0u; i < NUM_SERVICE_NODES; ++i)
    registration_txs[i] = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block(registration_txs);

  // NOTE: Add blocks until we get to the first height that has a checkpointing quorum AND there are service nodes in the quorum.
  int const MAX_TRIES = 16;
  int tries           = 0;
  for (; tries < MAX_TRIES; tries++)
  {
    gen.add_blocks_until_next_checkpointable_height();
    std::shared_ptr<const service_nodes::quorum> quorum = gen.get_quorum(service_nodes::quorum_type::checkpointing, gen.height());
    if (quorum && quorum->validators.size()) break;
  }
  assert(tries != MAX_TRIES);

  loki_chain_generator fork_with_more_checkpoints = gen;
  gen.add_n_blocks(60); // Add blocks so that this chain has more PoW

  cryptonote::checkpoint_t checkpoint = fork_with_more_checkpoints.create_service_node_checkpoint(fork_with_more_checkpoints.height(), service_nodes::CHECKPOINT_MIN_VOTES);
  fork_with_more_checkpoints.create_and_add_next_block({}, &checkpoint);
  uint64_t const fork_top_height   = cryptonote::get_block_height(fork_with_more_checkpoints.top().block);
  crypto::hash const fork_top_hash = cryptonote::get_block_hash(fork_with_more_checkpoints.top().block);

  loki_register_callback(events, "check_switched_to_alt_chain", [fork_top_hash, fork_top_height](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_switched_to_alt_chain");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(top_height, fork_top_height);
    CHECK_EQ(top_hash, fork_top_hash);
    return true;
  });
  return true;
}

// NOTE: - A chain that receives checkpointing votes sufficient to form a checkpoint should reorg back accordingly
bool loki_checkpointing_alt_chain_receive_checkpoint_votes_should_reorg_back::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  int constexpr NUM_SERVICE_NODES = service_nodes::CHECKPOINT_QUORUM_SIZE;
  std::vector<cryptonote::transaction> registration_txs(NUM_SERVICE_NODES);
  for (auto i = 0u; i < NUM_SERVICE_NODES; ++i)
    registration_txs[i] = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block(registration_txs);

  // NOTE: Add blocks until we get to the first height that has a checkpointing quorum AND there are service nodes in the quorum.
  int const MAX_TRIES = 16;
  int tries           = 0;
  for (; tries < MAX_TRIES; tries++)
  {
    gen.add_blocks_until_next_checkpointable_height();
    std::shared_ptr<const service_nodes::quorum> quorum = gen.get_quorum(service_nodes::quorum_type::checkpointing, gen.height());
    if (quorum && quorum->validators.size()) break;
  }
  assert(tries != MAX_TRIES);

  // NOTE: Diverge the two chains in tandem, so they have the same PoW and generate alt service node states, but still remain on the mainchain due to PoW
  loki_chain_generator fork = gen;
  for (size_t i = 0; i < service_nodes::CHECKPOINT_INTERVAL; i++)
  {
    gen.create_and_add_next_block();
    fork.create_and_add_next_block();
  }

  // NOTE: Fork generate two checkpoints worth of blocks.
  uint64_t first_checkpointed_height    = fork.height();
  uint64_t first_checkpointed_height_hf = fork.top().block.major_version;
  crypto::hash first_checkpointed_hash  = cryptonote::get_block_hash(fork.top().block);
  std::shared_ptr<const service_nodes::quorum> first_quorum = fork.get_quorum(service_nodes::quorum_type::checkpointing, gen.height());

  for (size_t i = 0; i < service_nodes::CHECKPOINT_INTERVAL; i++)
  {
    gen.create_and_add_next_block();
    fork.create_and_add_next_block();
  }

  // NOTE: Fork generates service node votes, upon sending them over and the
  // main chain collecting them validly (they should be able to verify
  // signatures because we store alt quorums) it should generate a checkpoint
  // belonging to the forked chain- which should cause it to detach back to the
  // checkpoint height

  // Then we send the votes for the 2nd newest checkpoint. We don't reorg back until we receive a block confirming this checkpoint.
  for (size_t i = 0; i < service_nodes::CHECKPOINT_MIN_VOTES; i++)
  {
    auto keys = gen.get_cached_keys(first_quorum->validators[i]);
    service_nodes::quorum_vote_t fork_vote = service_nodes::make_checkpointing_vote(first_checkpointed_height_hf, first_checkpointed_hash, first_checkpointed_height, i, keys);
    events.push_back(loki_blockchain_addable<service_nodes::quorum_vote_t>(fork_vote, true/*can_be_added_to_blockchain*/, "A first_checkpoint vote from the forked chain should be accepted since we should be storing alternative service node states and quorums"));
  }

  // Upon adding the last block, we should now switch to our forked chain
  fork.create_and_add_next_block({});
  crypto::hash const fork_top_hash = cryptonote::get_block_hash(fork.top().block);
  loki_register_callback(events, "check_switched_to_alt_chain", [fork_top_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_switched_to_alt_chain");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(fork_top_hash, top_hash);
    return true;
  });
  return true;
}

bool loki_checkpointing_alt_chain_too_old_should_be_dropped::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  int constexpr NUM_SERVICE_NODES = service_nodes::CHECKPOINT_QUORUM_SIZE;
  std::vector<cryptonote::transaction> registration_txs(NUM_SERVICE_NODES);
  for (auto i = 0u; i < NUM_SERVICE_NODES; ++i)
    registration_txs[i] = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block(registration_txs);

  // NOTE: Add blocks until we get to the first height that has a checkpointing quorum AND there are service nodes in the quorum.
  int const MAX_TRIES = 16;
  int tries           = 0;
  for (; tries < MAX_TRIES; tries++)
  {
    gen.add_blocks_until_next_checkpointable_height();
    std::shared_ptr<const service_nodes::quorum> quorum = gen.get_quorum(service_nodes::quorum_type::checkpointing, gen.height());
    if (quorum && quorum->validators.size()) break;
  }
  assert(tries != MAX_TRIES);

  loki_chain_generator fork = gen;
  gen.add_service_node_checkpoint(gen.height(), service_nodes::CHECKPOINT_MIN_VOTES);
  gen.add_blocks_until_next_checkpointable_height();
  fork.add_blocks_until_next_checkpointable_height();

  gen.add_service_node_checkpoint(gen.height(), service_nodes::CHECKPOINT_MIN_VOTES);
  gen.add_blocks_until_next_checkpointable_height();
  fork.add_blocks_until_next_checkpointable_height();

  gen.add_service_node_checkpoint(gen.height(), service_nodes::CHECKPOINT_MIN_VOTES);
  gen.create_and_add_next_block();

  // NOTE: We now have 3 checkpoints. Extending this alt-chain is no longer
  // possible because this alt-chain starts before the immutable height, it
  // should be deleted and removed.
  fork.create_and_add_next_block({}, nullptr, false, "Can not add block to alt chain because the alt chain starts before the immutable height. Those blocks should be locked into the chain");
  return true;
}

// NOTE: - Checks that an alt chain eventually takes over the main chain with
// only 1 checkpoint, by progressively adding 2 more checkpoints at the next
// available checkpoint heights whilst maintaining equal heights with the main chain
bool loki_checkpointing_alt_chain_with_increasing_service_node_checkpoints::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  int constexpr NUM_SERVICE_NODES = service_nodes::CHECKPOINT_QUORUM_SIZE;
  std::vector<cryptonote::transaction> registration_txs(NUM_SERVICE_NODES);
  for (auto i = 0u; i < NUM_SERVICE_NODES; ++i)
    registration_txs[i] = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block(registration_txs);
  gen.add_blocks_until_next_checkpointable_height();

  // NOTE: Add blocks until we get to the first height that has a checkpointing quorum AND there are service nodes in the quorum.
  int const MAX_TRIES = 16;
  int tries           = 0;
  for (; tries < MAX_TRIES; tries++)
  {
    gen.add_blocks_until_next_checkpointable_height();
    std::shared_ptr<const service_nodes::quorum> quorum = gen.get_quorum(service_nodes::quorum_type::checkpointing, gen.height());
    if (quorum && quorum->validators.size()) break;
  }
  assert(tries != MAX_TRIES);
  gen.add_n_blocks(service_nodes::CHECKPOINT_INTERVAL - 1);

  // Setup the two chains as follows, where C = checkpointed block, B = normal
  // block, the main chain should NOT reorg to the fork chain as they have the
  // same PoW-ish and equal number of checkpoints.
  // Main chain   C B B B B
  // Fork chain   B B B B C

  loki_chain_generator fork = gen;
  gen.create_and_add_next_block();
  gen.add_service_node_checkpoint(gen.height(), service_nodes::CHECKPOINT_MIN_VOTES);

  gen.add_blocks_until_next_checkpointable_height();
  fork.add_blocks_until_next_checkpointable_height();
  fork.add_service_node_checkpoint(fork.height(), service_nodes::CHECKPOINT_MIN_VOTES);

  crypto::hash const gen_top_hash = cryptonote::get_block_hash(gen.top().block);
  loki_register_callback(events, "check_still_on_main_chain", [gen_top_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_still_on_main_chain");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(top_hash, gen_top_hash);
    return true;
  });

  // Now create the following chain, the fork chain should be switched to due to now having more checkpoints
  // Main chain   C B B B B | B B B B B
  // Fork chain   B B B B C | B B B C
  gen.add_blocks_until_next_checkpointable_height();
  gen.create_and_add_next_block();

  fork.add_blocks_until_next_checkpointable_height();
  cryptonote::checkpoint_t fork_second_checkpoint = fork.create_service_node_checkpoint(fork.height(), service_nodes::CHECKPOINT_MIN_VOTES);
  fork.create_and_add_next_block({}, &fork_second_checkpoint);

  crypto::hash const fork_top_hash = cryptonote::get_block_hash(fork.top().block);
  loki_register_callback(events, "check_switched_to_alt_chain", [fork_top_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_switched_to_alt_chain");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(fork_top_hash, top_hash);
    return true;
  });
  return true;
}

// NOTE: - Checks checkpoints aren't generated until there are enough votes sitting in the vote pool
//       - Checks invalid vote (signature or key) is not accepted due to not being part of the quorum
bool loki_checkpointing_service_node_checkpoint_from_votes::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  int constexpr NUM_SERVICE_NODES = service_nodes::CHECKPOINT_QUORUM_SIZE;
  std::vector<cryptonote::transaction> registration_txs(NUM_SERVICE_NODES);
  for (auto i = 0u; i < NUM_SERVICE_NODES; ++i)
    registration_txs[i] = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block(registration_txs);

  // NOTE: Regarding the 2nd condition in this loop, although the height could
  // be a checkpoint interval, since for checkpoints we offset the height,
  // namely (height - REORG_SAFETY_BUFFER_BLOCKS_POST_HF12) we may use a height
  // before the service nodes were even registered.
  int const MAX_TRIES = 16;
  int tries           = 0;
  for (; tries < MAX_TRIES; tries++)
  {
    gen.add_blocks_until_next_checkpointable_height();
    std::shared_ptr<const service_nodes::quorum> quorum = gen.get_quorum(service_nodes::quorum_type::checkpointing, gen.height());
    if (quorum && quorum->validators.size()) break;
  }
  assert(tries != MAX_TRIES);

  // NOTE: Generate service node votes
  uint64_t checkpointed_height                                = gen.height();
  crypto::hash checkpointed_hash                              = cryptonote::get_block_hash(gen.top().block);
  std::shared_ptr<const service_nodes::quorum> quorum = gen.get_quorum(service_nodes::quorum_type::checkpointing, gen.height());
  std::vector<service_nodes::quorum_vote_t> checkpoint_votes(service_nodes::CHECKPOINT_MIN_VOTES);
  for (size_t i = 0; i < service_nodes::CHECKPOINT_MIN_VOTES; i++)
  {
    auto keys = gen.get_cached_keys(quorum->validators[i]);
    checkpoint_votes[i] = service_nodes::make_checkpointing_vote(gen.top().block.major_version, checkpointed_hash, checkpointed_height, i, keys);
  }

  // NOTE: Submit invalid vote using service node keys not in the quorum
  {
    const cryptonote::keypair invalid_kp = cryptonote::keypair::generate(hw::get_device("default"));
    service_nodes::service_node_keys invalid_keys;
    invalid_keys.pub = invalid_kp.pub;
    invalid_keys.key = invalid_kp.sec;

    service_nodes::quorum_vote_t invalid_vote = service_nodes::make_checkpointing_vote(gen.top().block.major_version, checkpointed_hash, checkpointed_height, 0, invalid_keys);
    gen.events_.push_back(loki_blockchain_addable<decltype(invalid_vote)>(
        invalid_vote,
        false /*can_be_added_to_blockchain*/,
        "Can not add a vote that uses a service node key not part of the quorum"));
  }

  // NOTE: Add insufficient service node votes and check that no checkpoint is generated yet
  for (size_t i = 0; i < service_nodes::CHECKPOINT_MIN_VOTES - 1; i++)
    gen.events_.push_back(loki_blockchain_addable<service_nodes::quorum_vote_t>(checkpoint_votes[i]));

  loki_register_callback(events, "check_service_node_checkpoint_rejected_insufficient_votes", [checkpointed_height](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_service_node_checkpoint_rejected_insufficient_votes");
    cryptonote::Blockchain const &blockchain = c.get_blockchain_storage();
    cryptonote::checkpoint_t real_checkpoint;
    CHECK_TEST_CONDITION(blockchain.get_checkpoint(checkpointed_height, real_checkpoint) == false);
    return true;
  });

  // NOTE: Add last vote and check checkpoint has been generated
  gen.events_.push_back(checkpoint_votes.back());
  loki_register_callback(events, "check_service_node_checkpoint_accepted", [checkpointed_height](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_service_node_checkpoint_accepted");
    cryptonote::Blockchain const &blockchain = c.get_blockchain_storage();
    cryptonote::checkpoint_t real_checkpoint;
    CHECK_TEST_CONDITION(blockchain.get_checkpoint(checkpointed_height, real_checkpoint));
    return true;
  });

  return true;
}

// NOTE: - Checks you can't add blocks before the first 2 checkpoints
//       - Checks you can add a block after the 1st checkpoint out of 2 checkpoints.
bool loki_checkpointing_service_node_checkpoints_check_reorg_windows::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  int constexpr NUM_SERVICE_NODES = service_nodes::CHECKPOINT_QUORUM_SIZE;
  std::vector<cryptonote::transaction> registration_txs(NUM_SERVICE_NODES);
  for (auto i = 0u; i < NUM_SERVICE_NODES; ++i)
    registration_txs[i] = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block(registration_txs);

  // NOTE: Add blocks until we get to the first height that has a checkpointing quorum AND there are service nodes in the quorum.
  int const MAX_TRIES = 16;
  int tries           = 0;
  for (; tries < MAX_TRIES; tries++)
  {
    gen.add_blocks_until_next_checkpointable_height();
    std::shared_ptr<const service_nodes::quorum> quorum = gen.get_quorum(service_nodes::quorum_type::checkpointing, gen.height());
    if (quorum && quorum->validators.size()) break;
  }
  assert(tries != MAX_TRIES);

  // NOTE: Mine up until 1 block before the next checkpointable height, fork the chain.
  gen.add_n_blocks(service_nodes::CHECKPOINT_INTERVAL - 1);
  loki_chain_generator fork_1_block_before_checkpoint = gen;

  // Mine one block and fork the chain before we add the checkpoint.
  gen.create_and_add_next_block();
  loki_chain_generator fork_1_block_after_checkpoint = gen;
  gen.add_service_node_checkpoint(gen.height(), service_nodes::CHECKPOINT_MIN_VOTES);

  // Add the next service node checkpoints on the main chain to lock in the chain preceeding the first checkpoint
  gen.add_n_blocks(service_nodes::CHECKPOINT_INTERVAL - 1);
  loki_chain_generator fork_1_block_before_second_checkpoint = gen;

  gen.create_and_add_next_block();
  gen.add_service_node_checkpoint(gen.height(), service_nodes::CHECKPOINT_MIN_VOTES);

  // Try add a block before first checkpoint, should fail because we are already 2 checkpoints deep.
  fork_1_block_before_checkpoint.create_and_add_next_block({}, nullptr /*checkpoint*/, false /*can_be_added_to_blockchain*/, "Can NOT add a block if the height would equal the immutable height");

  // Try add a block after the first checkpoint. This should succeed because we can reorg the chain within the 2 checkpoint window
  fork_1_block_after_checkpoint.create_and_add_next_block({});

  // Try add a block on the second checkpoint. This should also succeed because we can reorg the chain within the 2
  // checkpoint window, and although the height is checkpointed and should fail checkpoints::check, it should still be
  // allowed as an alt block
  fork_1_block_before_second_checkpoint.create_and_add_next_block({});
  return true;
}

bool loki_core_block_reward_unpenalized::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);

  uint8_t newest_hf = hard_forks.back().first;
  assert(newest_hf >= cryptonote::network_version_13_enforce_checkpoints);

  gen.add_mined_money_unlock_blocks();

  cryptonote::account_base dummy = gen.add_account();
  int constexpr NUM_TXS          = 60;
  std::vector<cryptonote::transaction> txs(NUM_TXS);
  for (int i = 0; i < NUM_TXS; i++)
    txs[i] = gen.create_and_add_tx(gen.first_miner_, dummy.get_keys().m_account_address, MK_COINS(5));

  gen.create_and_add_next_block(txs);
  uint64_t unpenalized_block_reward     = cryptonote::block_reward_unpenalized_formula_v8(gen.height());
  uint64_t expected_service_node_reward = cryptonote::service_node_reward_formula(unpenalized_block_reward, newest_hf);

  loki_register_callback(events, "check_block_rewards", [unpenalized_block_reward, expected_service_node_reward](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_block_rewards");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);

    bool orphan;
    cryptonote::block top_block;
    CHECK_TEST_CONDITION(c.get_block_by_hash(top_hash, top_block, &orphan));
    CHECK_TEST_CONDITION(orphan == false);
    CHECK_TEST_CONDITION_MSG(top_block.miner_tx.vout[0].amount < unpenalized_block_reward, "We should add enough transactions that the penalty is realised on the base block reward");
    CHECK_EQ(top_block.miner_tx.vout[1].amount, expected_service_node_reward);
    return true;
  });
  return true;
}

bool loki_core_fee_burning::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);

  uint8_t newest_hf = hard_forks.back().first;
  assert(newest_hf >= cryptonote::network_version_14_blink);

  gen.add_mined_money_unlock_blocks();

  using namespace cryptonote;
  account_base dummy = gen.add_account();

  static constexpr std::array<std::array<uint64_t, 3>, 3> send_fee_burn{{
    {MK_COINS(5), MK_COINS(3), MK_COINS(1)},
    {MK_COINS(10), MK_COINS(5), MK_COINS(2)},
    {MK_COINS(5), MK_COINS(2), MK_COINS(1)},
  }};

  auto add_burning_tx = [&events, &gen, &dummy, newest_hf](const std::array<uint64_t, 3> &send_fee_burn) {
    auto send = send_fee_burn[0], fee = send_fee_burn[1], burn = send_fee_burn[2];
    transaction tx = gen.create_tx(gen.first_miner_, dummy.get_keys().m_account_address, send, fee);
    std::vector<uint8_t> burn_extra;
    add_burned_amount_to_tx_extra(burn_extra, burn);
    loki_tx_builder(events, tx, gen.blocks().back().block, gen.first_miner_, dummy.get_keys().m_account_address, send, newest_hf).with_fee(fee).with_extra(burn_extra).build();
    gen.add_tx(tx);
    return tx;
  };

  std::vector<transaction> txs;
  for (size_t i = 0; i < 2; i++)
    txs.push_back(add_burning_tx(send_fee_burn[i]));

  gen.create_and_add_next_block(txs);
  auto good_hash = gen.blocks().back().block.hash;
  uint64_t good_miner_reward;

  {
    loki_block_reward_context ctx{};
    ctx.height = get_block_height(gen.blocks().back().block);
    ctx.fee = send_fee_burn[0][1] + send_fee_burn[1][1] - send_fee_burn[0][2] - send_fee_burn[1][2];
    block_reward_parts reward_parts;
    cryptonote::get_loki_block_reward(0, 0, 1 /*already generated, needs to be >0 to avoid premine*/, newest_hf, reward_parts, ctx);
    good_miner_reward = reward_parts.miner_reward();
  }

  txs.clear();
  // Try to add another block with a fee that claims into the amount of the fee that must be burned
  txs.push_back(add_burning_tx(send_fee_burn[2]));

  {
    loki_create_block_params block_params = gen.next_block_params();
    block_params.total_fee = send_fee_burn[2][1] - send_fee_burn[2][2] + 2;

    loki_blockchain_entry next = {};
    assert(gen.create_block(next, block_params, txs));
    gen.add_block(next, false, "Invalid miner reward");
  }

  loki_register_callback(events, "check_fee_burned", [good_hash, good_miner_reward](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_fee_burned");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);

    bool orphan;
    cryptonote::block top_block;
    CHECK_TEST_CONDITION(c.get_block_by_hash(top_hash, top_block, &orphan));
    CHECK_TEST_CONDITION(orphan == false);

    CHECK_EQ(top_hash, good_hash);

    CHECK_EQ(top_block.miner_tx.vout[0].amount, good_miner_reward);

    return true;
  });
  return true;
}

bool loki_core_governance_batched_reward::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table(cryptonote::network_version_10_bulletproofs);

  uint64_t hf10_height = 0;
  for (std::pair<uint8_t, uint64_t> hf_pair : hard_forks)
  {
    if (hf_pair.first == cryptonote::network_version_10_bulletproofs)
    {
      hf10_height = hf_pair.second;
      break;
    }
  }
  assert(hf10_height != 0);

  uint64_t expected_total_governance_paid = 0;
  loki_chain_generator batched_governance_generator(events, hard_forks);
  {
    batched_governance_generator.add_blocks_until_version(cryptonote::network_version_10_bulletproofs);
    constexpr auto& network = cryptonote::get_config(cryptonote::FAKECHAIN);
    uint64_t blocks_to_gen = network.GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS - batched_governance_generator.height();
    batched_governance_generator.add_n_blocks(blocks_to_gen);
  }

  {
    // NOTE(loki): Since hard fork 8 we have an emissions curve change, so if
    // you don't atleast progress and generate blocks from hf8 you will run into
    // problems
    std::vector<std::pair<uint8_t, uint64_t>> other_hard_forks = {
        std::make_pair(cryptonote::network_version_7, 0),
        std::make_pair(cryptonote::network_version_8, 1),
        std::make_pair(cryptonote::network_version_9_service_nodes, hf10_height)};

    std::vector<test_event_entry> unused_events;
    loki_chain_generator no_batched_governance_generator(unused_events, other_hard_forks);
    no_batched_governance_generator.add_blocks_until_version(other_hard_forks.back().first);

    while(no_batched_governance_generator.height() < batched_governance_generator.height())
      no_batched_governance_generator.create_and_add_next_block();

    // NOTE(loki): Skip the last block as that is the batched payout height, we
    // don't include the governance reward of that height, that gets picked up
    // in the next batch.
    const std::vector<loki_blockchain_entry>& blockchain = no_batched_governance_generator.blocks();
    for (size_t block_height = hf10_height; block_height < blockchain.size() - 1; ++block_height)
    {
      const cryptonote::block &block = blockchain[block_height].block;
      expected_total_governance_paid += block.miner_tx.vout.back().amount;
    }
  }

  loki_register_callback(events, "check_batched_governance_amount_matches", [hf10_height, expected_total_governance_paid](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_batched_governance_amount_matches");

    uint64_t height = c.get_current_blockchain_height();
    std::vector<cryptonote::block> blockchain;
    if (!c.get_blocks((uint64_t)0, (size_t)height, blockchain))
      return false;

    uint64_t governance = 0;
    for (size_t block_height = hf10_height; block_height < blockchain.size(); ++block_height)
    {
      const cryptonote::block &block = blockchain[block_height];
      if (cryptonote::block_has_governance_output(cryptonote::FAKECHAIN, block))
        governance += block.miner_tx.vout.back().amount;
    }

    CHECK_EQ(governance, expected_total_governance_paid);
    return true;
  });

  return true;
}

bool loki_core_block_rewards_lrc6::generate(std::vector<test_event_entry>& events)
{
  constexpr auto& network = cryptonote::get_config(cryptonote::FAKECHAIN);
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table(cryptonote::network_version_15_lns);
  hard_forks.emplace_back(cryptonote::network_version_16, hard_forks.back().second + network.GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS + 10);
  loki_chain_generator batched_governance_generator(events, hard_forks);
  batched_governance_generator.add_blocks_until_version(cryptonote::network_version_16);
  batched_governance_generator.add_n_blocks(network.GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS);

  uint64_t hf15_height = 0, hf16_height = 0;
  for (const auto &hf : hard_forks)
  {
    if (hf.first == cryptonote::network_version_15_lns)
      hf15_height = hf.second;
    else if (hf.first == cryptonote::network_version_16)
    {
      hf16_height = hf.second;
      break;
    }
  }

  loki_register_callback(events, "check_lrc6_block_rewards", [hf15_height, hf16_height, interval=network.GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_lrc6_block_rewards");

    uint64_t height = c.get_current_blockchain_height();
    std::vector<cryptonote::block> blockchain;
    if (!c.get_blocks((uint64_t)0, (size_t)height, blockchain))
      return false;

    int hf15_gov = 0, hf16_gov = 0;
    for (size_t block_height = hf15_height; block_height < hf16_height; ++block_height)
    {
      const cryptonote::block &block = blockchain[block_height];
      CHECK_EQ(block.miner_tx.vout.at(0).amount, MINER_REWARD_HF15);
      CHECK_EQ(block.miner_tx.vout.at(1).amount, SN_REWARD_HF15);
      if (cryptonote::block_has_governance_output(cryptonote::FAKECHAIN, block))
      {
        hf15_gov++;
        CHECK_EQ(block.miner_tx.vout.at(2).amount, FOUNDATION_REWARD_HF15 * interval);
        CHECK_EQ(block.miner_tx.vout.size(), 3);
      }
      else
        CHECK_EQ(block.miner_tx.vout.size(), 2);
    }
    for (size_t block_height = hf16_height; block_height < height; ++block_height)
    {
      const cryptonote::block &block = blockchain[block_height];
      // TODO: this 1 sat miner fee is just a placeholder until we address this properly in HF16.
      CHECK_EQ(block.miner_tx.vout.at(0).amount, 1);
      CHECK_EQ(block.miner_tx.vout.at(1).amount, SN_REWARD_HF16);
      if (cryptonote::block_has_governance_output(cryptonote::FAKECHAIN, block))
      {
        hf16_gov++;
        CHECK_EQ(block.miner_tx.vout.at(2).amount, FOUNDATION_REWARD_HF16 * interval);
        CHECK_EQ(block.miner_tx.vout.size(), 3);
      }
      else
        CHECK_EQ(block.miner_tx.vout.size(), 2);
    }
    CHECK_EQ(hf15_gov, 1);
    CHECK_EQ(hf16_gov, 1);

    return true;
  });

  return true;
}

bool loki_core_test_deregister_preferred::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table(cryptonote::network_version_9_service_nodes);
  loki_chain_generator gen(events, hard_forks);
  const auto miner                 = gen.first_miner();
  const auto alice                 = gen.add_account();

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(60); /// give miner some outputs to spend and unlock them
  gen.add_mined_money_unlock_blocks();

  std::vector<cryptonote::transaction> reg_txs; /// register 12 random service nodes
  for (auto i = 0; i < 12; ++i)
  {
    const auto tx = gen.create_and_add_registration_tx(miner);
    reg_txs.push_back(tx);
  }

  gen.create_and_add_next_block(reg_txs);

  /// generate transactions to fill up txpool entirely
  for (auto i = 0u; i < 45; ++i) {
    gen.create_and_add_tx(miner, alice.get_keys().m_account_address, MK_COINS(1), TESTS_DEFAULT_FEE * 100);
  }

  /// generate two deregisters
  const auto deregister_pub_key_1 = gen.top_quorum().obligations->workers[0];
  const auto deregister_pub_key_2 = gen.top_quorum().obligations->workers[1];
  gen.create_and_add_state_change_tx(service_nodes::new_state::deregister, deregister_pub_key_1);
  gen.create_and_add_state_change_tx(service_nodes::new_state::deregister, deregister_pub_key_2);

  loki_register_callback(events, "check_prefer_deregisters", [&events, miner](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_prefer_deregisters");
    const auto tx_count = c.get_pool().get_transactions_count();
    cryptonote::block full_blk;
    {
      cryptonote::difficulty_type diffic;
      uint64_t height;
      uint64_t expected_reward;
      cryptonote::blobdata extra_nonce;
      c.get_block_template(full_blk, miner.get_keys().m_account_address, diffic, height, expected_reward, extra_nonce);
    }

    map_hash2tx_t mtx;
    {
      std::vector<cryptonote::block> chain;
      CHECK_TEST_CONDITION(find_block_chain(events, chain, mtx, get_block_hash(std::get<cryptonote::block>(events[0]))));
    }

    const auto deregister_count =
      std::count_if(full_blk.tx_hashes.begin(), full_blk.tx_hashes.end(), [&mtx](const crypto::hash& tx_hash) {
        return mtx[tx_hash]->type == cryptonote::txtype::state_change;
      });

    CHECK_TEST_CONDITION(tx_count > full_blk.tx_hashes.size()); /// test that there are more transactions in tx pool
    CHECK_EQ(deregister_count, 2);
    return true;
  });
  return true;
}

// Test if a person registers onto the network and they get included in the nodes to test (i.e. heights 0, 5, 10). If
// they get dereigstered in the nodes to test, height 5, and rejoin the network before height 10 (and are in the nodes
// to test), they don't get deregistered.
bool loki_core_test_deregister_safety_buffer::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table(cryptonote::network_version_9_service_nodes);
  loki_chain_generator gen(events, hard_forks);
  const auto miner = gen.first_miner();

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(40); /// give miner some outputs to spend and unlock them
  gen.add_mined_money_unlock_blocks();

  std::vector<cryptonote::keypair> used_sn_keys; /// save generated keys here
  std::vector<cryptonote::transaction> reg_txs; /// register 21 random service nodes

  constexpr auto SERVICE_NODES_NEEDED = service_nodes::STATE_CHANGE_QUORUM_SIZE * 2 + 1;
  for (auto i = 0u; i < SERVICE_NODES_NEEDED; ++i)
  {
    const auto tx = gen.create_and_add_registration_tx(miner);
    reg_txs.push_back(tx);
  }
  gen.create_and_add_next_block({reg_txs});

  const auto height_a                      = gen.height();
  std::vector<crypto::public_key> quorum_a = gen.quorum(height_a).obligations->workers;

  gen.add_n_blocks(5); /// create 5 blocks and find public key to be tested twice

  const auto height_b                      = gen.height();
  std::vector<crypto::public_key> quorum_b = gen.quorum(height_b).obligations->workers;

  std::vector<crypto::public_key> quorum_intersection;
  for (const auto& pub_key : quorum_a)
  {
    if (std::find(quorum_b.begin(), quorum_b.end(), pub_key) != quorum_b.end())
      quorum_intersection.push_back(pub_key);
  }

  const auto deregister_pub_key = quorum_intersection[0];
  {
    const auto dereg_tx = gen.create_and_add_state_change_tx(service_nodes::new_state::deregister, deregister_pub_key, height_a);
    gen.create_and_add_next_block({dereg_tx});
  }

  /// Register the node again
  {
    auto keys = gen.get_cached_keys(deregister_pub_key);
    cryptonote::keypair pair = {keys.pub, keys.key};
    const auto tx = gen.create_and_add_registration_tx(miner, pair);
    gen.create_and_add_next_block({tx});
  }

  /// Try to deregister the node again for heightB (should fail)
  const auto dereg_tx = gen.create_state_change_tx(service_nodes::new_state::deregister, deregister_pub_key, height_b);
  gen.add_tx(dereg_tx, false /*can_be_added_to_blockchain*/, "After a Service Node has deregistered, it can NOT be deregistered from the result of a quorum preceeding the height that the Service Node re-registered as.");
  return true;

}

// Daemon A has a deregistration TX (X) in the pool. Daemon B creates a block before receiving X.
// Daemon A accepts the block without X. Now X is too old and should not be added in future blocks.
bool loki_core_test_deregister_too_old::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table(cryptonote::network_version_9_service_nodes);
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);

  /// generate some outputs and unlock them
  gen.add_n_blocks(20);
  gen.add_mined_money_unlock_blocks();
 
  std::vector<cryptonote::transaction> reg_txs; /// register 11 service nodes (10 voters and 1 to test)
  for (auto i = 0; i < 11; ++i)
  {
    const auto tx = gen.create_and_add_registration_tx(gen.first_miner());
    reg_txs.push_back(tx);
  }
  gen.create_and_add_next_block(reg_txs);

  const auto pk       = gen.top_quorum().obligations->workers[0];
  const auto dereg_tx = gen.create_and_add_state_change_tx(service_nodes::new_state::deregister, pk);
  gen.add_n_blocks(service_nodes::STATE_CHANGE_TX_LIFETIME_IN_BLOCKS); /// create enough blocks to make deregistrations invalid (60 blocks)

  /// In the real world, this transaction should not make it into a block, but in this case we do try to add it (as in
  /// tests we must add specify transactions manually), which should exercise the same validation code and reject the
  /// block
  gen.create_and_add_next_block({dereg_tx},
                nullptr /*checkpoint*/,
                false /*can_be_added_to_blockchain*/,
                "Trying to add a block with an old deregister sitting in the pool that was invalidated due to old age");
  return true;
}

bool loki_core_test_deregister_zero_fee::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  size_t const NUM_SERVICE_NODES = 11;
  std::vector<cryptonote::transaction> reg_txs(NUM_SERVICE_NODES);
  for (auto i = 0u; i < NUM_SERVICE_NODES; ++i)
    reg_txs[i] = gen.create_and_add_registration_tx(gen.first_miner_);

  gen.create_and_add_next_block(reg_txs);
  const auto deregister_pub_key = gen.top_quorum().obligations->workers[0];
  cryptonote::transaction const invalid_deregister =
      gen.create_state_change_tx(service_nodes::new_state::deregister, deregister_pub_key, -1 /*height*/, {} /*voters*/, MK_COINS(1) /*fee*/);
  gen.add_tx(invalid_deregister, false /*can_be_added_to_blockchain*/, "Deregister transactions with non-zero fee can NOT be added to the blockchain");
  return true;
}

// Test a chain that is equal up to a certain point, splits, and 1 of the chains forms a block that has a deregister
// for Service Node A. Chain 2 receives a deregister for Service Node A with a different permutation of votes than
// the one known in Chain 1 and is sitting in the mempool. On reorg, Chain 2 should become the canonical chain and
// those sitting on Chain 1 should not have problems switching over.
bool loki_core_test_deregister_on_split::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();
 
  std::vector<cryptonote::transaction> reg_txs;
  for (auto i = 0; i < 12; ++i) /// register 12 random service nodes
  {
    const auto tx = gen.create_and_add_registration_tx(gen.first_miner());
    reg_txs.push_back(tx);
  }

  gen.create_and_add_next_block(reg_txs);
  gen.create_and_add_next_block(); // Can't change service node state on the same height it was registered in
  auto fork = gen;

  /// public key of the node to deregister (valid at the height of the pivot block)
  const auto pk           = gen.top_quorum().obligations->workers[0];
  const auto split_height = gen.height();

  /// create deregistration A
  std::vector<uint64_t> const quorum_indexes = {1, 2, 3, 4, 5, 6, 7};
  const auto dereg_a                         = gen.create_and_add_state_change_tx(service_nodes::new_state::deregister, pk, split_height, quorum_indexes);

  /// create deregistration on alt chain (B)
  std::vector<uint64_t> const fork_quorum_indexes = {1, 3, 4, 5, 6, 7, 8};
  const auto dereg_b            = fork.create_and_add_state_change_tx(service_nodes::new_state::deregister, pk, split_height, fork_quorum_indexes, 0 /*fee*/, true /*kept_by_block*/);
  crypto::hash expected_tx_hash = cryptonote::get_transaction_hash(dereg_b);
  size_t dereg_index            = gen.event_index();

  gen.create_and_add_next_block({dereg_a});    /// continue main chain with deregister A
  fork.create_and_add_next_block({dereg_b});   /// continue alt chain with deregister B
  fork.create_and_add_next_block();            /// one more block on alt chain to switch

  loki_register_callback(events, "test_on_split", [&events, expected_tx_hash](cryptonote::core &c, size_t ev_index)
  {
    /// Check that the deregister transaction is the one from the alternative branch
    DEFINE_TESTS_ERROR_CONTEXT("test_on_split");
    std::vector<cryptonote::block> blocks; /// find a deregister transaction in the blockchain
    bool r = c.get_blocks(0, 1000, blocks);
    CHECK_TEST_CONDITION(r);

    map_hash2tx_t mtx;
    std::vector<cryptonote::block> chain;
    r = find_block_chain(events, chain, mtx, cryptonote::get_block_hash(blocks.back()));
    CHECK_TEST_CONDITION(r);

    /// get the second last block; it contains the deregister
    const auto blk = blocks[blocks.size() - 2];

    /// find the deregister tx:
    const auto found_tx_hash = std::find_if(blk.tx_hashes.begin(), blk.tx_hashes.end(), [&mtx](const crypto::hash& hash) {
      return mtx.at(hash)->type == cryptonote::txtype::state_change;
    });

    CHECK_TEST_CONDITION(found_tx_hash != blk.tx_hashes.end());
    CHECK_EQ(*found_tx_hash, expected_tx_hash); /// check that it is the expected one
    return true;
  });

  return true;
}

bool loki_core_test_state_change_ip_penalty_disallow_dupes::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  std::vector<cryptonote::transaction> reg_txs;
  for (auto i = 0u; i < service_nodes::STATE_CHANGE_QUORUM_SIZE + 1; ++i)
  {
    const auto tx = gen.create_and_add_registration_tx(gen.first_miner());
    reg_txs.push_back(tx);
  }

  gen.create_and_add_next_block(reg_txs);
  gen.create_and_add_next_block(); // Can't change service node state on the same height it was registered in

  const auto pub_key                         = gen.top_quorum().obligations->workers[0];
  std::vector<uint64_t> const quorum_indexes = {1, 2, 3, 4, 5, 6, 7};
  const auto state_change_1                  = gen.create_and_add_state_change_tx(service_nodes::new_state::ip_change_penalty, pub_key, gen.height(), quorum_indexes);

  // NOTE: Try duplicate state change with different quorum indexes
  {
    std::vector<uint64_t> const alt_quorum_indexes = {1, 3, 4, 5, 6, 7, 8};
    const auto state_change_2 = gen.create_state_change_tx(service_nodes::new_state::ip_change_penalty, pub_key, gen.height(), alt_quorum_indexes);
    gen.add_tx(state_change_2, false /*can_be_added_to_blockchain*/, "Can't add a state change with different permutation of votes than previously submitted");

    // NOTE: Try same duplicate state change on a new height
    {
      gen.create_and_add_next_block({state_change_1});
      gen.add_tx(state_change_2, false /*can_be_added_to_blockchain*/, "Can't add a state change with different permutation of votes than previously submitted, even if the blockchain height has changed");
    }

    // NOTE: Try same duplicate state change on a new height, but set kept_by_block, i.e. this is a TX from a block on another chain
    gen.add_tx(state_change_2, true /*can_be_added_to_blockchain*/, "We should be able to accept dupe ip changes if TX is kept by block (i.e. from alt chain) otherwise we can never reorg to that chain", true /*kept_by_block*/);
  }

  return true;
}

static lns::mapping_value helper_encrypt_lns_value(std::string const &name, lns::mapping_value const &value)
{
  lns::mapping_value result;
  bool encrypted = lns::encrypt_mapping_value(name, value, result);
  assert(encrypted);
  return result;
}

static bool verify_lns_mapping_record(char const *perr_context,
                                      lns::mapping_record const &record,
                                      lns::mapping_type type,
                                      std::string const &name,
                                      lns::mapping_value const &value,
                                      uint64_t register_height,
                                      uint64_t update_height,
                                      crypto::hash const &txid,
                                      crypto::hash const &prev_txid,
                                      lns::generic_owner const &owner,
                                      lns::generic_owner const &backup_owner)
{
  lns::mapping_value encrypted_value = helper_encrypt_lns_value(name, value);
  CHECK_EQ(record.loaded,          true);
  CHECK_EQ(record.type,            type);
  CHECK_EQ(record.name_hash,       lns::name_to_base64_hash(name));
  CHECK_EQ(record.encrypted_value, encrypted_value);
  CHECK_EQ(record.register_height, register_height);
  CHECK_EQ(record.update_height,   update_height);
  CHECK_EQ(record.txid,            txid);
  CHECK_EQ(record.prev_txid,       prev_txid);
  CHECK_TEST_CONDITION_MSG(record.owner == owner, record.owner.to_string(cryptonote::FAKECHAIN) << " == "<< owner.to_string(cryptonote::FAKECHAIN));
  CHECK_TEST_CONDITION_MSG(record.backup_owner == backup_owner, record.backup_owner.to_string(cryptonote::FAKECHAIN) << " == "<< backup_owner.to_string(cryptonote::FAKECHAIN));
  return true;
}

bool loki_name_system_disallow_reserved_type::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  lns::mapping_value mapping_value = {};
  mapping_value.len                = 20;

  auto unusable_type = static_cast<lns::mapping_type>(-1);
  assert(!lns::mapping_type_allowed(gen.hardfork(), unusable_type));
  cryptonote::transaction tx1 = gen.create_loki_name_system_tx(miner, unusable_type, "FriendlyName", mapping_value);
  gen.add_tx(tx1, false /*can_be_added_to_blockchain*/, "Can't create a LNS TX that requests a LNS type that is unused but reserved by the protocol");
  return true;
}

struct lns_keys_t
{
  lns::generic_owner owner;
  lns::mapping_value wallet_value; // NOTE: this field is the binary (value) part of the name -> (value) mapping
  lns::mapping_value lokinet_value;
  lns::mapping_value session_value;
};

static lns_keys_t make_lns_keys(cryptonote::account_base const &src)
{
  lns_keys_t result             = {};
  result.owner                  = lns::make_monero_owner(src.get_keys().m_account_address, false /*is_subaddress*/);
  result.session_value.len      = lns::SESSION_PUBLIC_KEY_BINARY_LENGTH;
  result.wallet_value.len       = sizeof(src.get_keys().m_account_address);
  result.lokinet_value.len      = sizeof(result.owner.wallet.address.m_spend_public_key);

  memcpy(&result.session_value.buffer[0] + 1, &result.owner.wallet.address.m_spend_public_key, result.lokinet_value.len);
  memcpy(&result.wallet_value.buffer[0], (char *)&src.get_keys().m_account_address, result.wallet_value.len);

  // NOTE: Just needs a 32 byte key. Reuse spend key
  memcpy(&result.lokinet_value.buffer[0], (char *)&result.owner.wallet.address.m_spend_public_key, result.lokinet_value.len);

  result.session_value.buffer[0] = 5; // prefix with 0x05
  return result;
}

bool loki_name_system_expiration::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  cryptonote::account_base miner = gen.first_miner_;

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  lns_keys_t miner_key = make_lns_keys(miner);
  for (auto mapping_type = lns::mapping_type::lokinet_1year;
       mapping_type     <= lns::mapping_type::lokinet_10years;
       mapping_type      = static_cast<lns::mapping_type>(static_cast<uint16_t>(mapping_type) + 1))
  {
    std::string const name     = "mydomain.loki";
    if (lns::mapping_type_allowed(gen.hardfork(), mapping_type))
    {
      cryptonote::transaction tx = gen.create_and_add_loki_name_system_tx(miner, mapping_type, name, miner_key.lokinet_value);
      gen.create_and_add_next_block({tx});
      crypto::hash tx_hash = cryptonote::get_transaction_hash(tx);

      uint64_t height_of_lns_entry   = gen.height();
      uint64_t expected_expiry_block = height_of_lns_entry + lns::expiry_blocks(cryptonote::FAKECHAIN, mapping_type, nullptr);
      std::string name_hash = lns::name_to_base64_hash(name);

      loki_register_callback(events, "check_lns_entries", [=](cryptonote::core &c, size_t ev_index)
      {
        DEFINE_TESTS_ERROR_CONTEXT("check_lns_entries");
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::owner_record owner = lns_db.get_owner_by_key(miner_key.owner);
        CHECK_EQ(owner.loaded, true);
        CHECK_EQ(owner.id, 1);
        CHECK_TEST_CONDITION_MSG(miner_key.owner == owner.address,
                                 miner_key.owner.to_string(cryptonote::FAKECHAIN)
                                     << " == " << owner.address.to_string(cryptonote::FAKECHAIN));

        lns::mapping_record record = lns_db.get_mapping(mapping_type, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::lokinet_1year, name, miner_key.lokinet_value, height_of_lns_entry, height_of_lns_entry, tx_hash, crypto::null_hash, miner_key.owner, {} /*backup_owner*/));
        return true;
      });

      while (gen.height() <= expected_expiry_block)
        gen.create_and_add_next_block();

      loki_register_callback(events, "check_expired", [=, blockchain_height = gen.chain_height()](cryptonote::core &c, size_t ev_index)
      {
        DEFINE_TESTS_ERROR_CONTEXT("check_expired");
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();

        // TODO(loki): We should probably expire owners that no longer have any mappings remaining
        lns::owner_record owner = lns_db.get_owner_by_key(miner_key.owner);
        CHECK_EQ(owner.loaded, true);
        CHECK_EQ(owner.id, 1);
        CHECK_TEST_CONDITION_MSG(miner_key.owner == owner.address,
                                 miner_key.owner.to_string(cryptonote::FAKECHAIN)
                                     << " == " << owner.address.to_string(cryptonote::FAKECHAIN));

        lns::mapping_record record = lns_db.get_mapping(mapping_type, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::lokinet_1year, name, miner_key.lokinet_value, height_of_lns_entry, height_of_lns_entry, tx_hash, crypto::null_hash, miner_key.owner, {} /*backup_owner*/));
        CHECK_EQ(record.active(cryptonote::FAKECHAIN, blockchain_height), false);
        return true;
      });
    }
    else
    {
      cryptonote::transaction tx = gen.create_loki_name_system_tx(miner, mapping_type, name, miner_key.lokinet_value);
      gen.add_tx(tx, false /*can_be_added_to_blockchain*/, "Can not add LNS TX that uses disallowed type");
    }
  }
  return true;
}

bool loki_name_system_get_mappings_by_owner::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  cryptonote::account_base bob   = gen.add_account();
  gen.add_blocks_until_version(hard_forks.back().first);

  // NOTE: Fund Bob's wallet
  {
    gen.add_mined_money_unlock_blocks();

    cryptonote::transaction transfer = gen.create_and_add_tx(miner, bob.get_keys().m_account_address, MK_COINS(400));
    gen.create_and_add_next_block({transfer});
    gen.add_mined_money_unlock_blocks();
  }

  lns_keys_t bob_key = make_lns_keys(bob);
  std::string session_name1       = "MyName";
  std::string session_name2       = "AnotherName";
  crypto::hash session_name1_txid = {}, session_name2_txid = {};
  {
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx(bob, lns::mapping_type::session, session_name1, bob_key.session_value);
    cryptonote::transaction tx2 = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::session, session_name2, bob_key.session_value, &bob_key.owner);
    gen.create_and_add_next_block({tx1, tx2});
    session_name1_txid = get_transaction_hash(tx1);
    session_name2_txid = get_transaction_hash(tx2);
  }
  uint64_t session_height = gen.height();

  // NOTE: Register some Lokinet names
  std::string lokinet_name1 = "lorem.loki";
  std::string lokinet_name2 = "ipsum.loki";
  crypto::hash lokinet_name1_txid = {}, lokinet_name2_txid = {};
  if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::lokinet_1year))
  {
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx(bob, lns::mapping_type::lokinet_1year, lokinet_name1, bob_key.lokinet_value);
    cryptonote::transaction tx2 = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::lokinet_1year, lokinet_name2, bob_key.lokinet_value, &bob_key.owner);
    gen.create_and_add_next_block({tx1, tx2});
    lokinet_name1_txid = get_transaction_hash(tx1);
    lokinet_name2_txid = get_transaction_hash(tx2);
  }
  uint64_t lokinet_height = gen.height();

  // NOTE: Register some wallet names
  std::string wallet_name1 = "Wallet1";
  std::string wallet_name2 = "Wallet2";
  crypto::hash wallet_name1_txid = {}, wallet_name2_txid = {};
  if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::wallet))
  {
    std::string bob_addr = cryptonote::get_account_address_as_str(cryptonote::FAKECHAIN, false, bob.get_keys().m_account_address);
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx(bob, lns::mapping_type::wallet, wallet_name1, bob_key.wallet_value);
    cryptonote::transaction tx2 = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::wallet, wallet_name2, bob_key.wallet_value, &bob_key.owner);
    gen.create_and_add_next_block({tx1, tx2});
    wallet_name1_txid = get_transaction_hash(tx1);
    wallet_name2_txid = get_transaction_hash(tx2);
  }
  uint64_t wallet_height = gen.height();

  loki_register_callback(events, "check_lns_entries", [=](cryptonote::core &c, size_t ev_index)
  {
    const char* perr_context = "check_lns_entries";
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
    std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owner(bob_key.owner);

    size_t expected_size = 0;
    if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::session)) expected_size += 2;
    if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::wallet)) expected_size += 2;
    if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::lokinet_1year)) expected_size += 2;
    CHECK_EQ(records.size(), expected_size);

    if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::session))
    {
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[0], lns::mapping_type::session, session_name1, bob_key.session_value, session_height, session_height, session_name1_txid, crypto::null_hash, bob_key.owner, {} /*backup_owner*/));
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[1], lns::mapping_type::session, session_name2, bob_key.session_value, session_height, session_height, session_name2_txid, crypto::null_hash, bob_key.owner, {} /*backup_owner*/));
    }

    if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::lokinet_1year))
    {
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[2], lns::mapping_type::lokinet_1year, lokinet_name1, bob_key.lokinet_value, lokinet_height, lokinet_height, lokinet_name1_txid, crypto::null_hash, bob_key.owner, {} /*backup_owner*/));
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[3], lns::mapping_type::lokinet_1year, lokinet_name2, bob_key.lokinet_value, lokinet_height, lokinet_height, lokinet_name2_txid, crypto::null_hash, bob_key.owner, {} /*backup_owner*/));
    }

    if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::wallet))
    {
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[4], lns::mapping_type::wallet, wallet_name1, bob_key.wallet_value, wallet_height, wallet_height, wallet_name1_txid, crypto::null_hash, bob_key.owner, {} /*backup_owner*/));
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[5], lns::mapping_type::wallet, wallet_name2, bob_key.wallet_value, wallet_height, wallet_height, wallet_name2_txid, crypto::null_hash, bob_key.owner, {} /*backup_owner*/));
    }
    return true;
  });

  return true;
}

bool loki_name_system_get_mappings_by_owners::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  cryptonote::account_base bob   = gen.add_account();
  gen.add_blocks_until_version(hard_forks.back().first);

  // NOTE: Fund Bob's wallet
  {
    gen.add_mined_money_unlock_blocks();
    cryptonote::transaction transfer = gen.create_and_add_tx(miner, bob.get_keys().m_account_address, MK_COINS(400));
    gen.create_and_add_next_block({transfer});
    gen.add_mined_money_unlock_blocks();
  }

  lns_keys_t bob_key   = make_lns_keys(bob);
  lns_keys_t miner_key = make_lns_keys(miner);

  std::string session_name1 = "MyName";
  crypto::hash session_tx_hash1;
  {
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx(bob, lns::mapping_type::session, session_name1, bob_key.session_value);
    session_tx_hash1 = cryptonote::get_transaction_hash(tx1);
    gen.create_and_add_next_block({tx1});
  }
  uint64_t session_height1 = gen.height();
  gen.add_n_blocks(10);

  std::string session_name2 = "MyName2";
  crypto::hash session_tx_hash2;
  {
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx(bob, lns::mapping_type::session, session_name2, bob_key.session_value);
    session_tx_hash2 = cryptonote::get_transaction_hash(tx1);
    gen.create_and_add_next_block({tx1});
  }
  uint64_t session_height2 = gen.height();
  gen.add_n_blocks(10);

  std::string session_name3 = "MyName3";
  crypto::hash session_tx_hash3;
  {
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::session, session_name3, miner_key.session_value);
    session_tx_hash3 = cryptonote::get_transaction_hash(tx1);
    gen.create_and_add_next_block({tx1});
  }
  uint64_t session_height3 = gen.height();
  gen.add_n_blocks(10);

  loki_register_callback(events, "check_lns_entries", [=](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_lns_entries");
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
    std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owners({bob_key.owner, miner_key.owner});
    CHECK_EQ(records.size(), 3);
    std::sort(records.begin(), records.end(), [](lns::mapping_record const &lhs, lns::mapping_record const &rhs) {
      return lhs.register_height < rhs.register_height;
    });

    int index = 0;
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[index++], lns::mapping_type::session, session_name1, bob_key.session_value, session_height1, session_height1, session_tx_hash1, crypto::null_hash, bob_key.owner, {}));
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[index++], lns::mapping_type::session, session_name2, bob_key.session_value, session_height2, session_height2, session_tx_hash2, crypto::null_hash, bob_key.owner, {}));
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[index++], lns::mapping_type::session, session_name3, miner_key.session_value, session_height3, session_height3, session_tx_hash3, crypto::null_hash, miner_key.owner, {}));
    return true;
  });

  return true;
}

bool loki_name_system_get_mappings::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  cryptonote::account_base bob   = gen.add_account();
  gen.add_blocks_until_version(hard_forks.back().first);

  // NOTE: Fund Bob's wallet
  {
    gen.add_mined_money_unlock_blocks();

    cryptonote::transaction transfer = gen.create_and_add_tx(miner, bob.get_keys().m_account_address, MK_COINS(400));
    gen.create_and_add_next_block({transfer});
    gen.add_mined_money_unlock_blocks();
  }

  lns_keys_t bob_key = make_lns_keys(bob);
  std::string session_name1 = "MyName";
  crypto::hash session_tx_hash;
  {
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx(bob, lns::mapping_type::session, session_name1, bob_key.session_value);
    session_tx_hash = cryptonote::get_transaction_hash(tx1);
    gen.create_and_add_next_block({tx1});
  }
  uint64_t session_height = gen.height();

  loki_register_callback(events, "check_lns_entries", [bob_key, session_height, session_name1, session_tx_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_lns_entries");
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
    std::string session_name_hash = lns::name_to_base64_hash(session_name1);
    std::vector<lns::mapping_record> records = lns_db.get_mappings({static_cast<uint16_t>(lns::mapping_type::session)}, session_name_hash);
    CHECK_EQ(records.size(), 1);
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[0], lns::mapping_type::session, session_name1, bob_key.session_value, session_height, session_height, session_tx_hash, crypto::null_hash /*prev_txid*/, bob_key.owner, {} /*backup_owner*/));
    return true;
  });

  return true;
}

bool loki_name_system_handles_duplicate_in_lns_db::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  cryptonote::account_base bob   = gen.add_account();

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  cryptonote::transaction transfer = gen.create_and_add_tx(miner, bob.get_keys().m_account_address, MK_COINS(400));
  gen.create_and_add_next_block({transfer});
  gen.add_mined_money_unlock_blocks();

  lns_keys_t miner_key     = make_lns_keys(miner);
  lns_keys_t bob_key       = make_lns_keys(bob);
  std::string session_name = "myfriendlydisplayname.loki";
  std::string lokinet_name = session_name;
  auto custom_type         = static_cast<lns::mapping_type>(3928);
  crypto::hash session_tx_hash = {}, lokinet_tx_hash = {};
  {
    // NOTE: Allow duplicates with the same name but different type
    cryptonote::transaction bar = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::session, session_name, bob_key.session_value);
    session_tx_hash = get_transaction_hash(bar);

    std::vector<cryptonote::transaction> txs;
    txs.push_back(bar);

    if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::lokinet_1year))
    {
      cryptonote::transaction bar3 = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::lokinet_1year, session_name, miner_key.lokinet_value);
      txs.push_back(bar3);
      lokinet_tx_hash = get_transaction_hash(bar3);
    }

    gen.create_and_add_next_block(txs);
  }
  uint64_t height_of_lns_entry = gen.height();

  {
    cryptonote::transaction bar6 = gen.create_loki_name_system_tx(bob, lns::mapping_type::session, session_name, bob_key.session_value);
    gen.add_tx(bar6, false /*can_be_added_to_blockchain*/, "Duplicate name requested by new owner: original already exists in lns db");
  }

  loki_register_callback(events, "check_lns_entries", [=](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_lns_entries");
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();

    lns::owner_record owner = lns_db.get_owner_by_key(miner_key.owner);
    CHECK_EQ(owner.loaded, true);
    CHECK_EQ(owner.id, 1);
    CHECK_TEST_CONDITION_MSG(miner_key.owner == owner.address,
                             miner_key.owner.to_string(cryptonote::FAKECHAIN)
                                 << " == " << owner.address.to_string(cryptonote::FAKECHAIN));

    std::string session_name_hash = lns::name_to_base64_hash(session_name);
    lns::mapping_record record1 = lns_db.get_mapping(lns::mapping_type::session, session_name_hash);
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record1, lns::mapping_type::session, session_name, bob_key.session_value, height_of_lns_entry, height_of_lns_entry, session_tx_hash, crypto::null_hash /*prev_txid*/, miner_key.owner, {} /*backup_owner*/));
    CHECK_EQ(record1.owner_id, owner.id);

    if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::lokinet_1year))
    {
      lns::mapping_record record2 = lns_db.get_mapping(lns::mapping_type::lokinet_1year, session_name);
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record2, lns::mapping_type::lokinet_1year, lokinet_name, miner_key.lokinet_value, height_of_lns_entry, height_of_lns_entry, lokinet_tx_hash, crypto::null_hash /*prev_txid*/, miner_key.owner, {} /*backup_owner*/));
      CHECK_EQ(record2.owner_id, owner.id);
    }

    lns::owner_record owner2 = lns_db.get_owner_by_key(bob_key.owner);
    CHECK_EQ(owner2.loaded, false);
    return true;
  });
  return true;
}

bool loki_name_system_handles_duplicate_in_tx_pool::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  cryptonote::account_base bob   = gen.add_account();
  {
    gen.add_blocks_until_version(hard_forks.back().first);
    gen.add_mined_money_unlock_blocks();

    cryptonote::transaction transfer = gen.create_and_add_tx(miner, bob.get_keys().m_account_address, MK_COINS(400));
    gen.create_and_add_next_block({transfer});
    gen.add_mined_money_unlock_blocks();
  }

  lns_keys_t bob_key       = make_lns_keys(bob);
  std::string session_name = "myfriendlydisplayname.loki";

  auto custom_type = static_cast<lns::mapping_type>(3928);
  {
    // NOTE: Allow duplicates with the same name but different type
    cryptonote::transaction bar = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::session, session_name, bob_key.session_value);

    if (lns::mapping_type_allowed(gen.hardfork(), custom_type))
      cryptonote::transaction bar2 = gen.create_and_add_loki_name_system_tx(miner, custom_type, session_name, bob_key.session_value);

    // NOTE: Make duplicate in the TX pool, this should be rejected
    cryptonote::transaction bar4 = gen.create_loki_name_system_tx(bob, lns::mapping_type::session, session_name, bob_key.session_value);
    gen.add_tx(bar4, false /*can_be_added_to_blockchain*/, "Duplicate name requested by new owner: original already exists in tx pool");
  }
  return true;
}

bool loki_name_system_invalid_tx_extra_params::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  lns_keys_t miner_key = make_lns_keys(miner);
  // Manually construct transaction with invalid tx extra
  {
    auto make_lns_tx_with_custom_extra = [&](loki_chain_generator &gen,
                                             std::vector<test_event_entry> &events,
                                             cryptonote::account_base const &src,
                                             cryptonote::tx_extra_loki_name_system &data,
                                             bool valid,
                                             char const *reason) -> void {
      uint64_t new_height    = cryptonote::get_block_height(gen.top().block) + 1;
      uint8_t new_hf_version = gen.get_hf_version_at(new_height);
      uint64_t burn_requirement = lns::burn_needed(new_hf_version, static_cast<lns::mapping_type>(data.type));

      std::vector<uint8_t> extra;
      cryptonote::add_loki_name_system_to_tx_extra(extra, data);
      cryptonote::add_burned_amount_to_tx_extra(extra, burn_requirement);

      cryptonote::transaction tx = {};
      loki_tx_builder(events, tx, gen.top().block, src /*from*/, src.get_keys().m_account_address, 0, new_hf_version)
          .with_tx_type(cryptonote::txtype::loki_name_system)
          .with_extra(extra)
          .with_fee(burn_requirement + TESTS_DEFAULT_FEE)
          .build();

      gen.add_tx(tx, valid /*can_be_added_to_blockchain*/, reason, false /*kept_by_block*/);
    };

    std::string name = "my_lns_name";
    cryptonote::tx_extra_loki_name_system valid_data = {};
    valid_data.fields |= lns::extra_field::buy_no_backup;
    valid_data.owner = miner_key.owner;
    valid_data.type  = lns::mapping_type::wallet;
    valid_data.encrypted_value = helper_encrypt_lns_value(name, miner_key.wallet_value).to_string();
    valid_data.name_hash       = lns::name_to_hash(name);

    if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::wallet))
    {
      valid_data.type = lns::mapping_type::wallet;
      // Blockchain name empty
      {
        cryptonote::tx_extra_loki_name_system data = valid_data;
        data.name_hash                             = {};
        data.encrypted_value                       = helper_encrypt_lns_value("", miner_key.wallet_value).to_string();
        make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Blockchain) Empty wallet name in LNS is invalid");
      }

      // Blockchain value (wallet address) is invalid, too short
      {
        cryptonote::tx_extra_loki_name_system data = valid_data;
        data.encrypted_value                       = helper_encrypt_lns_value(name, miner_key.wallet_value).to_string();
        data.encrypted_value.resize(data.encrypted_value.size() - 1);
        make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Blockchain) Wallet value in LNS too long");
      }

      // Blockchain value (wallet address) is invalid, too long
      {
        cryptonote::tx_extra_loki_name_system data = valid_data;
        data.encrypted_value                       = helper_encrypt_lns_value(name, miner_key.wallet_value).to_string();
        data.encrypted_value.resize(data.encrypted_value.size() + 1);
        make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Blockchain) Wallet value in LNS too long");
      }
    }

    if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::lokinet_1year))
    {
      valid_data.type = lns::mapping_type::lokinet_1year;
      // Lokinet name empty
      {
        cryptonote::tx_extra_loki_name_system data = valid_data;
        data.name_hash                             = {};
        data.encrypted_value                       = helper_encrypt_lns_value("", miner_key.lokinet_value).to_string();
        make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Lokinet) Empty domain name in LNS is invalid");
      }

      // Lokinet value too short
      {
        cryptonote::tx_extra_loki_name_system data = valid_data;
        data.encrypted_value                       = helper_encrypt_lns_value(name, miner_key.lokinet_value).to_string();
        data.encrypted_value.resize(data.encrypted_value.size() - 1);
        make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Lokinet) Domain value in LNS too long");
      }

      // Lokinet value too long
      {
        cryptonote::tx_extra_loki_name_system data = valid_data;
        data.encrypted_value                       = helper_encrypt_lns_value(name, miner_key.lokinet_value).to_string();
        data.encrypted_value.resize(data.encrypted_value.size() + 1);
        make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Lokinet) Domain value in LNS too long");
      }
    }

    // Session value too short
    // We added valid tx prior, we should update name to avoid conflict names in session land and test other invalid params
    valid_data.type      = lns::mapping_type::session;
    name                 = "new_friendly_name";
    valid_data.name_hash = lns::name_to_hash(name);
    {
      cryptonote::tx_extra_loki_name_system data = valid_data;
      data.encrypted_value                       = helper_encrypt_lns_value(name, miner_key.session_value).to_string();
      data.encrypted_value.resize(data.encrypted_value.size() - 1);
      make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Session) User id, value too short");
    }

    // Session value too long
    {
      cryptonote::tx_extra_loki_name_system data = valid_data;
      data.encrypted_value                       = helper_encrypt_lns_value(name, miner_key.session_value).to_string();
      data.encrypted_value.resize(data.encrypted_value.size() + 1);
      make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Session) User id, value too long");
    }

    // Session name empty
    {
      cryptonote::tx_extra_loki_name_system data = valid_data;
      data.name_hash                             = {};
      data.encrypted_value                       = helper_encrypt_lns_value("", miner_key.session_value).to_string();
      make_lns_tx_with_custom_extra(gen, events, miner, data, false, "(Session) Name empty");
    }
  }
  return true;
}

bool loki_name_system_large_reorg::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  cryptonote::account_base const miner = gen.first_miner_;
  cryptonote::account_base const bob   = gen.add_account();
  lns_keys_t const miner_key           = make_lns_keys(miner);
  lns_keys_t const bob_key             = make_lns_keys(bob);
  {
    gen.add_blocks_until_version(hard_forks.back().first);
    gen.add_mined_money_unlock_blocks();

    cryptonote::transaction transfer = gen.create_and_add_tx(miner, bob.get_keys().m_account_address, MK_COINS(400));
    gen.create_and_add_next_block({transfer});
    gen.add_mined_money_unlock_blocks();
  }

  // NOTE: Generate the first round of LNS transactions belonging to miner
  uint64_t first_lns_height                 = 0;
  uint64_t miner_earliest_renewable_height  = 0;
  std::string const lokinet_name1           = "website.loki";
  std::string const wallet_name1            = "MyWallet";
  std::string const session_name1           = "I Like Loki";
  crypto::hash session_tx_hash1 = {}, wallet_tx_hash1 = {}, lokinet_tx_hash1 = {};
  {
    // NOTE: Generate and add the (transactions + block) to the blockchain
    {
      std::vector<cryptonote::transaction> txs;
      cryptonote::transaction session_tx = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::session, session_name1, miner_key.session_value);
      session_tx_hash1 = get_transaction_hash(session_tx);
      txs.push_back(session_tx);

      if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::wallet))
      {
        cryptonote::transaction wallet_tx = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::wallet, wallet_name1, miner_key.wallet_value);
        txs.push_back(wallet_tx);
        wallet_tx_hash1 = get_transaction_hash(wallet_tx);
      }

      if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::lokinet_1year))
      {
        cryptonote::transaction lokinet_tx = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::lokinet_1year, lokinet_name1, miner_key.lokinet_value);
        txs.push_back(lokinet_tx);
        lokinet_tx_hash1 = get_transaction_hash(lokinet_tx);
      }
      gen.create_and_add_next_block(txs);
    }
    first_lns_height = gen.height();

    // NOTE: Determine the earliest height we can renew the Lokinet Entry
    {
      uint64_t height_of_lns_entry    = gen.height();
      uint64_t renew_window           = 0;
      uint64_t expiry_blocks          = lns::expiry_blocks(cryptonote::FAKECHAIN, lns::mapping_type::lokinet_1year, &renew_window);
      miner_earliest_renewable_height = first_lns_height + expiry_blocks - renew_window;
    }

    loki_register_callback(events, "check_first_lns_entries", [=](cryptonote::core &c, size_t ev_index)
    {
      DEFINE_TESTS_ERROR_CONTEXT("check_first_lns_entries");
      lns::name_system_db &lns_db        = c.get_blockchain_storage().name_system_db();
      std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owner(miner_key.owner);
      CHECK_EQ(lns_db.height(), first_lns_height);

      size_t expected_size = 1;
      if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::wallet)) expected_size += 1;
      if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::lokinet_1year)) expected_size += 1;
      CHECK_EQ(records.size(), expected_size);

      for (lns::mapping_record const &record : records)
      {
        if (record.type == lns::mapping_type::session)
          CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, session_name1, miner_key.session_value, first_lns_height, first_lns_height, session_tx_hash1, crypto::null_hash /*prev_txid*/, miner_key.owner, {} /*backup_owner*/));
        else if (record.type == lns::mapping_type::lokinet_1year)
          CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::lokinet_1year, lokinet_name1, miner_key.lokinet_value, first_lns_height, first_lns_height, lokinet_tx_hash1, crypto::null_hash /*prev_txid*/, miner_key.owner, {} /*backup_owner*/));
        else if (record.type == lns::mapping_type::wallet)
          CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::wallet, wallet_name1, miner_key.wallet_value, first_lns_height, first_lns_height, wallet_tx_hash1, crypto::null_hash /*prev_txid*/, miner_key.owner, {} /*backup_owner*/));
        else
        {
          assert(false);
        }
      }
      return true;
    });
  }

  while (gen.height() <= miner_earliest_renewable_height)
    gen.create_and_add_next_block();

  // NOTE: Generate and add the second round of (transactions + block) to the blockchain, renew lokinet and add bob's session, update miner's session value to other's session value
  cryptonote::account_base const other = gen.add_account();
  lns_keys_t const other_key           = make_lns_keys(other);
  uint64_t second_lns_height = 0;
  {
    std::string const bob_session_name1 = "I Like Session";
    crypto::hash session_tx_hash2 = {}, lokinet_tx_hash2 = {}, session_tx_hash3;
    {
      std::vector<cryptonote::transaction> txs;
      txs.push_back(gen.create_and_add_loki_name_system_tx(bob, lns::mapping_type::session, bob_session_name1, bob_key.session_value));
      session_tx_hash2 = cryptonote::get_transaction_hash(txs[0]);

      if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::lokinet_1year))
        txs.push_back(gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::lokinet_1year, "loki.loki", miner_key.lokinet_value));

      txs.push_back(gen.create_and_add_loki_name_system_tx_update(miner, lns::mapping_type::session, session_name1, &other_key.session_value));
      session_tx_hash3 = cryptonote::get_transaction_hash(txs.back());

      gen.create_and_add_next_block(txs);
    }
    second_lns_height = gen.height();

    loki_register_callback(events, "check_second_lns_entries", [=](cryptonote::core &c, size_t ev_index)
    {
      DEFINE_TESTS_ERROR_CONTEXT("check_second_lns_entries");
      lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
      CHECK_EQ(lns_db.height(), second_lns_height);

      // NOTE: Check miner's record
      if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::lokinet_1year))
      {
        std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owner(miner_key.owner);
        for (lns::mapping_record const &record : records)
        {
          if (record.type == lns::mapping_type::session)
            CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, session_name1, other_key.session_value, first_lns_height, second_lns_height, session_tx_hash3, session_tx_hash1 /*prev_txid*/, miner_key.owner, {} /*backup_owner*/));
          else if (record.type == lns::mapping_type::lokinet_1year)
            CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::lokinet_1year, lokinet_name1, miner_key.lokinet_value, second_lns_height, second_lns_height, lokinet_tx_hash2, lokinet_tx_hash1 /*prev_txid*/, miner_key.owner, {} /*backup_owner*/));
          else if (record.type == lns::mapping_type::wallet)
            CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::wallet, wallet_name1, miner_key.wallet_value, first_lns_height, first_lns_height, wallet_tx_hash1, crypto::null_hash /*prev_txid*/, miner_key.owner, {} /*backup_owner*/));
          else
          {
            assert(false);
          }
        }
      }

      // NOTE: Check bob's records
      {
        std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owner(bob_key.owner);
        CHECK_EQ(records.size(), 1);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[0], lns::mapping_type::session, bob_session_name1, bob_key.session_value, second_lns_height, second_lns_height, session_tx_hash2, crypto::null_hash /*prev_txid*/, bob_key.owner, {} /*backup_owner*/));
      }

      return true;
    });
  }

  loki_register_callback(events, "trigger_blockchain_detach", [=](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("trigger_blockchain_detach");
    cryptonote::Blockchain &blockchain = c.get_blockchain_storage();

    // NOTE: Reorg to just before the 2nd round of LNS entries
    uint64_t curr_height   = blockchain.get_current_blockchain_height();
    uint64_t blocks_to_pop = curr_height - second_lns_height;
    blockchain.pop_blocks(blocks_to_pop);
    lns::name_system_db &lns_db  = blockchain.name_system_db();
    CHECK_EQ(lns_db.height(), blockchain.get_current_blockchain_height() - 1);

    // NOTE: Check bob's records got removed due to popping back to before it existed
    {
      std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owner(bob_key.owner);
      CHECK_EQ(records.size(), 0);

      lns::owner_record owner = lns_db.get_owner_by_key(bob_key.owner);
      CHECK_EQ(owner.loaded, false);
    }

    // NOTE: Check miner's records reverted
    {
      std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owner(miner_key.owner);
      size_t expected_size = 1;
      if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::wallet)) expected_size += 1;
      if (lns::mapping_type_allowed(c.get_blockchain_storage().get_current_hard_fork_version(), lns::mapping_type::lokinet_1year)) expected_size += 1;
      CHECK_EQ(records.size(), expected_size);

      for (lns::mapping_record const &record : records)
      {
        if (record.type == lns::mapping_type::session)
          CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, session_name1, miner_key.session_value, first_lns_height, first_lns_height, session_tx_hash1, crypto::null_hash /*prev_txid*/, miner_key.owner, {} /*backup_owner*/));
        else if (record.type == lns::mapping_type::lokinet_1year)
          CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::lokinet_1year, lokinet_name1, miner_key.lokinet_value, first_lns_height, first_lns_height, lokinet_tx_hash1, crypto::null_hash /*prev_txid*/, miner_key.owner, {} /*backup_owner*/));
        else if (record.type == lns::mapping_type::wallet)
          CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::wallet, wallet_name1, miner_key.wallet_value, first_lns_height, first_lns_height, wallet_tx_hash1, crypto::null_hash /*prev_txid*/, miner_key.owner, {} /*backup_owner*/));
        else
        {
          assert(false);
        }
      }
    }

    return true;
  });

  loki_register_callback(events, "trigger_blockchain_detach_all_records_gone", [miner_key, first_lns_height](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_second_lns_entries");
    cryptonote::Blockchain &blockchain = c.get_blockchain_storage();

    // NOTE: Reorg to just before the 2nd round of LNS entries
    uint64_t curr_height   = blockchain.get_current_blockchain_height();
    uint64_t blocks_to_pop = curr_height - first_lns_height;
    blockchain.pop_blocks(blocks_to_pop);
    lns::name_system_db &lns_db  = blockchain.name_system_db();
    CHECK_EQ(lns_db.height(), blockchain.get_current_blockchain_height() - 1);

    // NOTE: Check miner's records are gone
    {
      std::vector<lns::mapping_record> records = lns_db.get_mappings_by_owner(miner_key.owner);
      CHECK_EQ(records.size(), 0);

      lns::owner_record owner = lns_db.get_owner_by_key(miner_key.owner);
      CHECK_EQ(owner.loaded, false);
    }
    return true;
  });
  return true;
}

bool loki_name_system_name_renewal::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  cryptonote::account_base miner = gen.first_miner_;

  if (!lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::lokinet_1year))
      return true;

  {
    gen.add_blocks_until_version(hard_forks.back().first);
    gen.add_mined_money_unlock_blocks();
  }

  lns_keys_t miner_key = make_lns_keys(miner);
  std::string const name    = "mydomain.loki";
  lns::mapping_type mapping_type = lns::mapping_type::lokinet_1year;
  cryptonote::transaction tx = gen.create_and_add_loki_name_system_tx(miner, mapping_type, name, miner_key.lokinet_value);
  gen.create_and_add_next_block({tx});
  crypto::hash prev_txid = get_transaction_hash(tx);

  uint64_t height_of_lns_entry = gen.height();
  uint64_t renew_window        = 0;
  uint64_t expiry_blocks       = lns::expiry_blocks(cryptonote::FAKECHAIN, mapping_type, &renew_window);
  uint64_t renew_window_block  = height_of_lns_entry + expiry_blocks - renew_window;

  loki_register_callback(events, "check_lns_entries", [=](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_lns_entries");
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();

    lns::owner_record owner = lns_db.get_owner_by_key(miner_key.owner);
    CHECK_EQ(owner.loaded, true);
    CHECK_EQ(owner.id, 1);
    CHECK_TEST_CONDITION_MSG(miner_key.owner == owner.address,
                             miner_key.owner.to_string(cryptonote::FAKECHAIN)
                                 << " == " << owner.address.to_string(cryptonote::FAKECHAIN));

    std::string name_hash = lns::name_to_base64_hash(name);
    lns::mapping_record record = lns_db.get_mapping(lns::mapping_type::lokinet_1year, name_hash);
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::lokinet_1year, name, miner_key.lokinet_value, height_of_lns_entry, height_of_lns_entry, prev_txid, crypto::null_hash /*prev_txid*/, miner_key.owner, {} /*backup_owner*/));
    return true;
  });

  while (gen.height() <= renew_window_block)
    gen.create_and_add_next_block();

  // In the renewal window, try and renew the lokinet entry
  cryptonote::transaction renew_tx = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::lokinet_1year, name, miner_key.lokinet_value);
  gen.create_and_add_next_block({renew_tx});
  crypto::hash txid       = cryptonote::get_transaction_hash(renew_tx);
  uint64_t renewal_height = gen.height();

  loki_register_callback(events, "check_renewed", [=](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_renewed");
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();

    lns::owner_record owner = lns_db.get_owner_by_key(miner_key.owner);
    CHECK_EQ(owner.loaded, true);
    CHECK_EQ(owner.id, 1);
    CHECK_TEST_CONDITION_MSG(miner_key.owner == owner.address,
                             miner_key.owner.to_string(cryptonote::FAKECHAIN)
                                 << " == " << owner.address.to_string(cryptonote::FAKECHAIN));

    std::string name_hash = lns::name_to_base64_hash(name);
    lns::mapping_record record = lns_db.get_mapping(lns::mapping_type::lokinet_1year, name_hash);
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::lokinet_1year, name, miner_key.lokinet_value, renewal_height, renewal_height, txid, prev_txid, miner_key.owner, {} /*backup_owner*/));
    return true;
  });

  return true;
}

bool loki_name_system_name_value_max_lengths::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  auto make_lns_tx_with_custom_extra = [&](loki_chain_generator &gen,
                                           std::vector<test_event_entry> &events,
                                           cryptonote::account_base const &src,
                                           cryptonote::tx_extra_loki_name_system const &data) -> void {

    uint64_t new_height    = cryptonote::get_block_height(gen.top().block) + 1;
    uint8_t new_hf_version = gen.get_hf_version_at(new_height);
    uint64_t burn_requirement = lns::burn_needed(new_hf_version, static_cast<lns::mapping_type>(data.type));
    std::vector<uint8_t> extra;
    cryptonote::add_loki_name_system_to_tx_extra(extra, data);
    cryptonote::add_burned_amount_to_tx_extra(extra, burn_requirement);

    cryptonote::transaction tx = {};
    loki_tx_builder(events, tx, gen.top().block, src /*from*/, src.get_keys().m_account_address, 0, new_hf_version)
        .with_tx_type(cryptonote::txtype::loki_name_system)
        .with_extra(extra)
        .with_fee(burn_requirement + TESTS_DEFAULT_FEE)
        .build();

    gen.add_tx(tx, true /*can_be_added_to_blockchain*/, "", false /*kept_by_block*/);
  };

  lns_keys_t miner_key = make_lns_keys(miner);
  cryptonote::tx_extra_loki_name_system data = {};
  data.fields |= lns::extra_field::buy_no_backup;
  data.owner = miner_key.owner;

  // Wallet
  if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::wallet))
  {
    std::string name(lns::WALLET_NAME_MAX, 'A');
    data.type            = lns::mapping_type::wallet;
    data.name_hash       = lns::name_to_hash(name);
    data.encrypted_value = helper_encrypt_lns_value(name, miner_key.wallet_value).to_string();
    make_lns_tx_with_custom_extra(gen, events, miner, data);
  }

  // Lokinet
  if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::lokinet_1year))
  {
    std::string name(lns::LOKINET_DOMAIN_NAME_MAX, 'A');
    size_t last_index  = name.size() - 1;
    name[last_index--] = 'i';
    name[last_index--] = 'k';
    name[last_index--] = 'o';
    name[last_index--] = 'l';
    name[last_index--] = '.';

    data.type            = lns::mapping_type::lokinet_1year;
    data.name_hash       = lns::name_to_hash(name);
    data.encrypted_value = helper_encrypt_lns_value(name, miner_key.lokinet_value).to_string();
    make_lns_tx_with_custom_extra(gen, events, miner, data);
  }

  // Session
  {
    std::string name(lns::SESSION_DISPLAY_NAME_MAX, 'A');
    data.type            = lns::mapping_type::session;
    data.name_hash       = lns::name_to_hash(name);
    data.encrypted_value = helper_encrypt_lns_value(name, miner_key.session_value).to_string();
    make_lns_tx_with_custom_extra(gen, events, miner, data);
  }

  return true;
}

bool loki_name_system_update_mapping_after_expiry_fails::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  cryptonote::account_base miner = gen.first_miner_;

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  lns_keys_t miner_key = make_lns_keys(miner);
  if (lns::mapping_type_allowed(gen.hardfork(), lns::mapping_type::lokinet_1year))
  {
    std::string const name     = "mydomain.loki";
    cryptonote::transaction tx = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::lokinet_1year, name, miner_key.lokinet_value);
    crypto::hash tx_hash = cryptonote::get_transaction_hash(tx);
    gen.create_and_add_next_block({tx});

    uint64_t height_of_lns_entry   = gen.height();
    uint64_t expected_expiry_block = height_of_lns_entry + lns::expiry_blocks(cryptonote::FAKECHAIN, lns::mapping_type::lokinet_1year, nullptr);

    while (gen.height() <= expected_expiry_block)
      gen.create_and_add_next_block();

    {
      lns_keys_t bob_key = make_lns_keys(gen.add_account());
      cryptonote::transaction tx1 = gen.create_loki_name_system_tx_update(miner, lns::mapping_type::lokinet_1year, name, &bob_key.lokinet_value);
      gen.add_tx(tx1, false /*can_be_added_to_blockchain*/, "Can not update a LNS record that is already expired");
    }

    loki_register_callback(events, "check_still_expired", [=](cryptonote::core &c, size_t ev_index)
    {
      DEFINE_TESTS_ERROR_CONTEXT("check_still_expired");
      lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();

      lns::owner_record owner = lns_db.get_owner_by_key(miner_key.owner);
      CHECK_EQ(owner.loaded, true);
      CHECK_EQ(owner.id, 1);
      CHECK_TEST_CONDITION_MSG(miner_key.owner == owner.address,
                               miner_key.owner.to_string(cryptonote::FAKECHAIN)
                                   << " == " << owner.address.to_string(cryptonote::FAKECHAIN));

      std::string name_hash        = lns::name_to_base64_hash(name);
      lns::mapping_record record = lns_db.get_mapping(lns::mapping_type::lokinet_1year, name_hash);
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::lokinet_1year, name, miner_key.lokinet_value, height_of_lns_entry, height_of_lns_entry, tx_hash, crypto::null_hash /*prev_txid*/, miner_key.owner, {} /*backup_owner*/));
      CHECK_EQ(record.owner_id, owner.id);
      return true;
    });
  }
  return true;
}

bool loki_name_system_update_mapping::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  cryptonote::account_base miner     = gen.first_miner_;
  cryptonote::account_base const bob = gen.add_account();
  lns_keys_t miner_key               = make_lns_keys(miner);
  lns_keys_t bob_key                 = make_lns_keys(bob);

  crypto::hash session_tx_hash1;
  std::string session_name1 = "MyName";
  {
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::session, session_name1, miner_key.session_value);
    session_tx_hash1 = cryptonote::get_transaction_hash(tx1);
    gen.create_and_add_next_block({tx1});
  }
  uint64_t register_height = gen.height();

  loki_register_callback(events, "check_registered", [=](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_registered");
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();

    std::string name_hash = lns::name_to_base64_hash(session_name1);
    std::vector<lns::mapping_record> records = lns_db.get_mappings({static_cast<uint16_t>(lns::mapping_type::session)}, name_hash);

    CHECK_EQ(records.size(), 1);
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[0], lns::mapping_type::session, session_name1, miner_key.session_value, register_height, register_height, session_tx_hash1, {} /*prev_txid*/, miner_key.owner, {} /*backup_owner*/));
    return true;
  });

  // Test update mapping with same name fails
  {
    cryptonote::transaction tx1 = gen.create_loki_name_system_tx_update(miner, lns::mapping_type::session, session_name1, &miner_key.session_value);
    gen.add_tx(tx1, false /*can_be_added_to_blockchain*/, "Can not add a LNS TX that re-updates the underlying value to same value");
  }

  crypto::hash session_tx_hash2;
  {
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx_update(miner, lns::mapping_type::session, session_name1, &bob_key.session_value);
    session_tx_hash2 = cryptonote::get_transaction_hash(tx1);
    gen.create_and_add_next_block({tx1});
  }

  loki_register_callback(events, "check_updated", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_updated");
    lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();

    std::string name_hash = lns::name_to_base64_hash(session_name1);
    std::vector<lns::mapping_record> records = lns_db.get_mappings({static_cast<uint16_t>(lns::mapping_type::session)}, name_hash);

    CHECK_EQ(records.size(), 1);
    CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, records[0], lns::mapping_type::session, session_name1, bob_key.session_value, register_height, blockchain_height, session_tx_hash2, session_tx_hash1 /*prev_txid*/, miner_key.owner, {} /*backup_owner*/));
    return true;
  });

  return true;
}

bool loki_name_system_update_mapping_multiple_owners::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(10); /// generate some outputs and unlock them
  gen.add_mined_money_unlock_blocks();

  cryptonote::account_base miner = gen.first_miner_;
  lns_keys_t miner_key           = make_lns_keys(miner);

  // Test 2 ed keys as owner
  {
    lns::generic_owner owner1;
    lns::generic_owner owner2;
    crypto::ed25519_secret_key owner1_key;
    crypto::ed25519_secret_key owner2_key;

    crypto_sign_ed25519_keypair(owner1.ed25519.data, owner1_key.data);
    crypto_sign_ed25519_keypair(owner2.ed25519.data, owner2_key.data);
    owner1.type = lns::generic_owner_sig_type::ed25519;
    owner2.type = lns::generic_owner_sig_type::ed25519;

    std::string name      = "Hello_World";
    std::string name_hash = lns::name_to_base64_hash(name);
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::session, name, miner_key.session_value, &owner1, &owner2);
    gen.create_and_add_next_block({tx1});
    uint64_t height = gen.height();
    crypto::hash txid      = cryptonote::get_transaction_hash(tx1);
    crypto::hash prev_txid = crypto::null_hash;

    loki_register_callback(events, "check_update0", [=](cryptonote::core &c, size_t ev_index)
    {
      const char* perr_context = "check_update0";
      lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
      lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
      CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, miner_key.session_value, height, height, txid, prev_txid, owner1, owner2 /*backup_owner*/));
      return true;
    });

    // Update with owner1
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());
      lns::mapping_value encrypted_value = helper_encrypt_lns_value(name, temp_keys.session_value);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_ed25519_signature(hash, owner1_key);

      cryptonote::transaction tx2 = gen.create_and_add_loki_name_system_tx_update(miner, lns::mapping_type::session, name, &temp_keys.session_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      prev_txid = txid;
      txid      = cryptonote::get_transaction_hash(tx2);

      loki_register_callback(events, "check_update1", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update1";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, height, blockchain_height, txid, prev_txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }

    // Update with owner2
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());
      lns::mapping_value encrypted_value = helper_encrypt_lns_value(name, temp_keys.session_value);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_ed25519_signature(hash, owner2_key);

      cryptonote::transaction tx2 = gen.create_and_add_loki_name_system_tx_update(miner, lns::mapping_type::session, name, &temp_keys.session_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      prev_txid = txid;
      txid      = cryptonote::get_transaction_hash(tx2);

      loki_register_callback(events, "check_update2", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update2";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, height, blockchain_height, txid, prev_txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }
  }

  // Test 2 monero keys as owner
  {
    cryptonote::account_base account1 = gen.add_account();
    cryptonote::account_base account2 = gen.add_account();
    lns::generic_owner owner1         = lns::make_monero_owner(account1.get_keys().m_account_address, false /*subaddress*/);
    lns::generic_owner owner2         = lns::make_monero_owner(account2.get_keys().m_account_address, false /*subaddress*/);

    std::string name            = "Hello_Sailor";
    std::string name_hash = lns::name_to_base64_hash(name);
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::session, name, miner_key.session_value, &owner1, &owner2);
    gen.create_and_add_next_block({tx1});
    uint64_t height        = gen.height();
    crypto::hash txid      = cryptonote::get_transaction_hash(tx1);
    crypto::hash prev_txid = crypto::null_hash;

    // Update with owner1
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());
      lns::mapping_value encrypted_value = helper_encrypt_lns_value(name, temp_keys.session_value);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_monero_signature(hash, owner1.wallet.address.m_spend_public_key, account1.get_keys().m_spend_secret_key);

      cryptonote::transaction tx2 = gen.create_and_add_loki_name_system_tx_update(miner, lns::mapping_type::session, name, &temp_keys.session_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      prev_txid = txid;
      txid      = cryptonote::get_transaction_hash(tx2);

      loki_register_callback(events, "check_update3", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update3";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, height, blockchain_height, txid, prev_txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }

    // Update with owner2
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());
      lns::mapping_value encrypted_value = helper_encrypt_lns_value(name, temp_keys.session_value);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_monero_signature(hash, owner2.wallet.address.m_spend_public_key, account2.get_keys().m_spend_secret_key);

      cryptonote::transaction tx2 = gen.create_and_add_loki_name_system_tx_update(miner, lns::mapping_type::session, name, &temp_keys.session_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      prev_txid = txid;
      txid      = cryptonote::get_transaction_hash(tx2);

      loki_register_callback(events, "check_update3", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update3";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, height, blockchain_height, txid, prev_txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }
  }

  // Test 1 ed/1 monero as owner
  {
    cryptonote::account_base account2 = gen.add_account();

    lns::generic_owner owner1;
    lns::generic_owner owner2 = lns::make_monero_owner(account2.get_keys().m_account_address, false /*subaddress*/);
    crypto::ed25519_secret_key owner1_key;

    crypto_sign_ed25519_keypair(owner1.ed25519.data, owner1_key.data);
    owner1.type = lns::generic_owner_sig_type::ed25519;

    std::string name = "Hello_Driver";
    std::string name_hash = lns::name_to_base64_hash(name);
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::session, name, miner_key.session_value, &owner1, &owner2);
    gen.create_and_add_next_block({tx1});
    uint64_t height        = gen.height();
    crypto::hash txid      = cryptonote::get_transaction_hash(tx1);
    crypto::hash prev_txid = crypto::null_hash;

    // Update with owner1
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());
      lns::mapping_value encrypted_value = helper_encrypt_lns_value(name, temp_keys.session_value);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_ed25519_signature(hash, owner1_key);

      cryptonote::transaction tx2 = gen.create_and_add_loki_name_system_tx_update(miner, lns::mapping_type::session, name, &temp_keys.session_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      prev_txid = txid;
      txid      = cryptonote::get_transaction_hash(tx2);

      loki_register_callback(events, "check_update4", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update4";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, height, blockchain_height, txid, prev_txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }

    // Update with owner2
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());
      lns::mapping_value encrypted_value = helper_encrypt_lns_value(name, temp_keys.session_value);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_monero_signature(hash, owner2.wallet.address.m_spend_public_key, account2.get_keys().m_spend_secret_key);

      cryptonote::transaction tx2 = gen.create_and_add_loki_name_system_tx_update(miner, lns::mapping_type::session, name, &temp_keys.session_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      prev_txid = txid;
      txid      = cryptonote::get_transaction_hash(tx2);

      loki_register_callback(events, "check_update5", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update5";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, height, blockchain_height, txid, prev_txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }
  }

  // Test 1 monero/1 ed as owner
  {
    cryptonote::account_base account1 = gen.add_account();
    lns::generic_owner owner1         = lns::make_monero_owner(account1.get_keys().m_account_address, false /*subaddress*/);
    lns::generic_owner owner2;

    crypto::ed25519_secret_key owner2_key;
    crypto_sign_ed25519_keypair(owner2.ed25519.data, owner2_key.data);
    owner2.type = lns::generic_owner_sig_type::ed25519;

    std::string name = "Hello_Passenger";
    std::string name_hash = lns::name_to_base64_hash(name);
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::session, name, miner_key.session_value, &owner1, &owner2);
    gen.create_and_add_next_block({tx1});
    uint64_t height        = gen.height();
    crypto::hash txid      = cryptonote::get_transaction_hash(tx1);
    crypto::hash prev_txid = crypto::null_hash;

    // Update with owner1
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());

      lns::mapping_value encrypted_value = helper_encrypt_lns_value(name, temp_keys.session_value);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_monero_signature(hash, owner1.wallet.address.m_spend_public_key, account1.get_keys().m_spend_secret_key);

      cryptonote::transaction tx2 = gen.create_and_add_loki_name_system_tx_update(miner, lns::mapping_type::session, name, &temp_keys.session_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      prev_txid = txid;
      txid      = cryptonote::get_transaction_hash(tx2);

      loki_register_callback(events, "check_update6", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update6";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, height, blockchain_height, txid, prev_txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }

    // Update with owner2
    {
      lns_keys_t temp_keys = make_lns_keys(gen.add_account());

      lns::mapping_value encrypted_value = helper_encrypt_lns_value(name, temp_keys.session_value);
      crypto::hash hash = lns::tx_extra_signature_hash(encrypted_value.to_view(), nullptr /*owner*/, nullptr /*backup_owner*/, txid);
      auto signature = lns::make_ed25519_signature(hash, owner2_key);

      cryptonote::transaction tx2 = gen.create_and_add_loki_name_system_tx_update(miner, lns::mapping_type::session, name, &temp_keys.session_value, nullptr /*owner*/, nullptr /*backup_owner*/, &signature);
      gen.create_and_add_next_block({tx2});
      prev_txid = txid;
      txid      = cryptonote::get_transaction_hash(tx2);

      loki_register_callback(events, "check_update7", [=, blockchain_height = gen.height()](cryptonote::core &c, size_t ev_index)
      {
        const char* perr_context = "check_update7";
        lns::name_system_db &lns_db = c.get_blockchain_storage().name_system_db();
        lns::mapping_record const record = lns_db.get_mapping(lns::mapping_type::session, name_hash);
        CHECK_TEST_CONDITION(verify_lns_mapping_record(perr_context, record, lns::mapping_type::session, name, temp_keys.session_value, height, blockchain_height, txid, prev_txid, owner1, owner2 /*backup_owner*/));
        return true;
      });
    }
  }
  return true;
}

bool loki_name_system_update_mapping_non_existent_name_fails::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  cryptonote::account_base miner = gen.first_miner_;
  lns_keys_t miner_key           = make_lns_keys(miner);
  std::string name               = "Hello World";
  cryptonote::transaction tx1 = gen.create_loki_name_system_tx_update(miner, lns::mapping_type::session, name, &miner_key.session_value, nullptr /*owner*/, nullptr /*backup_owner*/, nullptr /*signature*/, false /*use_asserts*/);
  gen.add_tx(tx1, false /*can_be_added_to_blockchain*/, "Can not add a updating LNS TX referencing a non-existent LNS entry");
  return true;
}

bool loki_name_system_update_mapping_invalid_signature::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  cryptonote::account_base miner = gen.first_miner_;
  lns_keys_t miner_key           = make_lns_keys(miner);

  std::string const name = "Hello World";
  cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::session, name, miner_key.session_value);
  gen.create_and_add_next_block({tx1});

  lns_keys_t bob_key = make_lns_keys(gen.add_account());
  lns::generic_signature invalid_signature = {};
  cryptonote::transaction tx2 = gen.create_loki_name_system_tx_update(miner, lns::mapping_type::session, name, &bob_key.session_value, nullptr /*owner*/, nullptr /*backup_owner*/, &invalid_signature, false /*use_asserts*/);
  gen.add_tx(tx2, false /*can_be_added_to_blockchain*/, "Can not add a updating LNS TX with an invalid signature");
  return true;
}

bool loki_name_system_update_mapping_replay::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  cryptonote::account_base miner = gen.first_miner_;
  lns_keys_t miner_key           = make_lns_keys(miner);
  lns_keys_t bob_key             = make_lns_keys(gen.add_account());
  lns_keys_t alice_key           = make_lns_keys(gen.add_account());

  std::string const name = "Hello World";
  // Make LNS Mapping
  {
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx(miner, lns::mapping_type::session, name, miner_key.session_value);
    gen.create_and_add_next_block({tx1});
  }

  // (1) Update LNS Mapping
  cryptonote::tx_extra_loki_name_system lns_entry = {};
  {
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx_update(miner, lns::mapping_type::session, name, &bob_key.session_value);
    gen.create_and_add_next_block({tx1});
    [[maybe_unused]] bool found_tx_extra = cryptonote::get_field_from_tx_extra(tx1.extra, lns_entry);
    assert(found_tx_extra);
  }

  // Replay the (1)st update mapping, should fail because the update is to the same session value
  {
    cryptonote::transaction tx1 = gen.create_loki_name_system_tx_update_w_extra(miner, lns_entry);
    gen.add_tx(tx1, false /*can_be_added_to_blockchain*/, "Can not replay an older update mapping to the same session value");
  }

  // (2) Update Again
  crypto::hash new_hash = {};
  {
    cryptonote::transaction tx1 = gen.create_and_add_loki_name_system_tx_update(miner, lns::mapping_type::session, name, &alice_key.session_value);
    gen.create_and_add_next_block({tx1});
    new_hash = cryptonote::get_transaction_hash(tx1);
  }

  // Replay the (1)st update mapping, should fail now even though it's not to the same session value, but that the signature no longer matches so you can't replay.
  lns_entry.prev_txid = new_hash;
  {
    cryptonote::transaction tx1 = gen.create_loki_name_system_tx_update_w_extra(miner, lns_entry);
    gen.add_tx(tx1, false /*can_be_added_to_blockchain*/, "Can not replay an older update mapping, should fail signature verification");
  }

  return true;
}

bool loki_name_system_wrong_burn::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);
  cryptonote::account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().first);

  // NOTE: Fund Miner's wallet
  {
    gen.add_mined_money_unlock_blocks();
  }

  lns_keys_t lns_keys             = make_lns_keys(miner);
  lns::mapping_type const types[] = {lns::mapping_type::session, lns::mapping_type::wallet, lns::mapping_type::lokinet_1year};
  for (int i = 0; i < 2; i++)
  {
    bool under_burn = (i == 0);
    for (auto const type : types)
    {
      if (lns::mapping_type_allowed(gen.hardfork(), type))
      {
        lns::mapping_value value = {};
        std::string name;

        if (type == lns::mapping_type::session)
        {
          value = lns_keys.session_value;
          name  = "My Friendly Session Name";
        }
        else if (type == lns::mapping_type::wallet)
        {
          value = lns_keys.wallet_value;
          name = "My Friendly Wallet Name";
        }
        else if (type == lns::mapping_type::lokinet_1year)
        {
          value = lns_keys.lokinet_value;
          name  = "MyFriendlyLokinetName.loki";
        }
        else
            assert("Unhandled type enum" == nullptr);

        uint64_t new_height      = cryptonote::get_block_height(gen.top().block) + 1;
        uint8_t new_hf_version   = gen.get_hf_version_at(new_height);
        uint64_t burn            = lns::burn_needed(new_hf_version, type);
        if (under_burn) burn -= 1;
        else            burn += 1;

        cryptonote::transaction tx = gen.create_loki_name_system_tx(miner, type, name, value, nullptr /*owner*/, nullptr /*backup_owner*/, burn);
        gen.add_tx(tx, false /*can_be_added_to_blockchain*/, "Wrong burn for a LNS tx", false /*kept_by_block*/);
      }
    }
  }
  return true;
}

bool loki_name_system_wrong_version::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  cryptonote::account_base miner = gen.first_miner_;
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  std::string name = "lns_name";
  lns_keys_t miner_key                       = make_lns_keys(miner);
  cryptonote::tx_extra_loki_name_system data = {};
  data.version                               = 0xFF;
  data.owner                                 = miner_key.owner;
  data.type                                  = lns::mapping_type::session;
  data.name_hash                             = lns::name_to_hash(name);
  data.encrypted_value                       = helper_encrypt_lns_value(name, miner_key.session_value).to_string();

  uint64_t new_height       = cryptonote::get_block_height(gen.top().block) + 1;
  uint8_t new_hf_version    = gen.get_hf_version_at(new_height);
  uint64_t burn_requirement = lns::burn_needed(new_hf_version, lns::mapping_type::session);

  std::vector<uint8_t> extra;
  cryptonote::add_loki_name_system_to_tx_extra(extra, data);
  cryptonote::add_burned_amount_to_tx_extra(extra, burn_requirement);

  cryptonote::transaction tx = {};
  loki_tx_builder(events, tx, gen.top().block, miner /*from*/, miner.get_keys().m_account_address, 0, new_hf_version)
      .with_tx_type(cryptonote::txtype::loki_name_system)
      .with_extra(extra)
      .with_fee(burn_requirement + TESTS_DEFAULT_FEE)
      .build();

  gen.add_tx(tx, false /*can_be_added_to_blockchain*/, "Incorrect LNS record version specified", false /*kept_by_block*/);
  return true;
}

// NOTE: Generate forked block, check that alternative quorums are generated and accessible
bool loki_service_nodes_alt_quorums::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  int constexpr NUM_SERVICE_NODES = service_nodes::STATE_CHANGE_QUORUM_SIZE + 3;
  std::vector<cryptonote::transaction> registration_txs(NUM_SERVICE_NODES);
  for (auto i = 0u; i < NUM_SERVICE_NODES; ++i)
    registration_txs[i] = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block(registration_txs);

  loki_chain_generator fork = gen;
  gen.create_and_add_next_block();
  fork.create_and_add_next_block();
  uint64_t height_with_fork = gen.height();

  service_nodes::quorum_manager fork_quorums = fork.top_quorum();
  loki_register_callback(events, "check_alt_quorums_exist", [fork_quorums, height_with_fork](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_alt_quorums_exist");

    std::vector<std::shared_ptr<const service_nodes::quorum>> alt_quorums;
    c.get_quorum(service_nodes::quorum_type::obligations, height_with_fork, false /*include_old*/, &alt_quorums);
    CHECK_TEST_CONDITION_MSG(alt_quorums.size() == 1, "alt_quorums.size(): " << alt_quorums.size());

    service_nodes::quorum const &fork_obligation_quorum = *fork_quorums.obligations;
    service_nodes::quorum const &real_obligation_quorum = *(alt_quorums[0]);
    CHECK_TEST_CONDITION(fork_obligation_quorum.validators.size() == real_obligation_quorum.validators.size());
    CHECK_TEST_CONDITION(fork_obligation_quorum.workers.size() == real_obligation_quorum.workers.size());

    for (size_t i = 0; i < fork_obligation_quorum.validators.size(); i++)
    {
      crypto::public_key const &fork_key = fork_obligation_quorum.validators[i];
      crypto::public_key const &real_key = real_obligation_quorum.validators[i];
      CHECK_EQ(fork_key, real_key);
    }

    for (size_t i = 0; i < fork_obligation_quorum.workers.size(); i++)
    {
      crypto::public_key const &fork_key = fork_obligation_quorum.workers[i];
      crypto::public_key const &real_key = real_obligation_quorum.workers[i];
      CHECK_EQ(fork_key, real_key);
    }

    return true;
  });

  return true;
}

bool loki_service_nodes_checkpoint_quorum_size::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  std::vector<cryptonote::transaction> registration_txs(service_nodes::CHECKPOINT_QUORUM_SIZE - 1);
  for (auto i = 0u; i < service_nodes::CHECKPOINT_QUORUM_SIZE - 1; ++i)
    registration_txs[i] = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block(registration_txs);

  int const MAX_TRIES = 16;
  int tries           = 0;
  for (; tries < MAX_TRIES; tries++)
    gen.add_blocks_until_next_checkpointable_height();

  uint64_t check_height_1 = gen.height();
  loki_register_callback(events, "check_checkpoint_quorum_should_be_empty", [check_height_1](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_checkpoint_quorum_should_be_empty");
    std::shared_ptr<const service_nodes::quorum> quorum = c.get_quorum(service_nodes::quorum_type::checkpointing, check_height_1);
    CHECK_TEST_CONDITION(quorum != nullptr);
    CHECK_TEST_CONDITION(quorum->validators.size() == 0);
    return true;
  });

  cryptonote::transaction new_registration_tx = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block({new_registration_tx});

  for (tries = 0; tries < MAX_TRIES; tries++)
  {
    gen.add_blocks_until_next_checkpointable_height();
    std::shared_ptr<const service_nodes::quorum> quorum = gen.get_quorum(service_nodes::quorum_type::checkpointing, gen.height());
    if (quorum && quorum->validators.size()) break;
  }
  assert(tries != MAX_TRIES);

  uint64_t check_height_2 = gen.height();
  loki_register_callback(events, "check_checkpoint_quorum_should_be_populated", [check_height_2](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_checkpoint_quorum_should_be_populated");
    std::shared_ptr<const service_nodes::quorum> quorum = c.get_quorum(service_nodes::quorum_type::checkpointing, check_height_2);
    CHECK_TEST_CONDITION(quorum != nullptr);
    CHECK_TEST_CONDITION(quorum->validators.size() > 0);
    return true;
  });

  return true;
}

bool loki_service_nodes_gen_nodes::generate(std::vector<test_event_entry> &events)
{
  const std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table(cryptonote::network_version_9_service_nodes);
  loki_chain_generator gen(events, hard_forks);
  const auto miner                      = gen.first_miner();
  const auto alice                      = gen.add_account();
  size_t alice_account_base_event_index = gen.event_index();

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(10);
  gen.add_mined_money_unlock_blocks();

  const auto tx0 = gen.create_and_add_tx(miner, alice.get_keys().m_account_address, MK_COINS(101));
  gen.create_and_add_next_block({tx0});
  gen.add_mined_money_unlock_blocks();

  const auto reg_tx = gen.create_and_add_registration_tx(alice);
  gen.create_and_add_next_block({reg_tx});

  loki_register_callback(events, "check_registered", [&events, alice](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("gen_service_nodes::check_registered");
    std::vector<cryptonote::block> blocks;
    size_t count = 15 + (2 * CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
    bool r       = c.get_blocks((uint64_t)0, count, blocks);
    CHECK_TEST_CONDITION(r);
    std::vector<cryptonote::block> chain;
    map_hash2tx_t mtx;
    r = find_block_chain(events, chain, mtx, cryptonote::get_block_hash(blocks.back()));
    CHECK_TEST_CONDITION(r);

    // Expect the change to have unlock time of 0, and we get that back immediately ~0.8 loki
    // 101 (balance) - 100 (stake) - 0.2 (test fee) = 0.8 loki
    const uint64_t unlocked_balance    = get_unlocked_balance(alice, blocks, mtx);
    const uint64_t staking_requirement = MK_COINS(100);

    CHECK_EQ(MK_COINS(101) - TESTS_DEFAULT_FEE - staking_requirement, unlocked_balance);

    /// check that alice is registered
    const auto info_v = c.get_service_node_list_state({});
    CHECK_EQ(info_v.empty(), false);
    return true;
  });

  for (auto i = 0u; i < service_nodes::staking_num_lock_blocks(cryptonote::FAKECHAIN); ++i)
    gen.create_and_add_next_block();

  loki_register_callback(events, "check_expired", [&events, alice](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_expired");
    const auto stake_lock_time = service_nodes::staking_num_lock_blocks(cryptonote::FAKECHAIN);

    std::vector<cryptonote::block> blocks;
    size_t count = 15 + (2 * CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW) + stake_lock_time;
    bool r = c.get_blocks((uint64_t)0, count, blocks);
    CHECK_TEST_CONDITION(r);
    std::vector<cryptonote::block> chain;
    map_hash2tx_t mtx;
    r = find_block_chain(events, chain, mtx, cryptonote::get_block_hash(blocks.back()));
    CHECK_TEST_CONDITION(r);

    /// check that alice's registration expired
    const auto info_v = c.get_service_node_list_state({});
    CHECK_EQ(info_v.empty(), true);

    /// check that alice received some service node rewards (TODO: check the balance precisely)
    CHECK_TEST_CONDITION(get_balance(alice, blocks, mtx) > MK_COINS(101) - TESTS_DEFAULT_FEE);
    return true;
  });
  return true;
}

using sn_info_t = service_nodes::service_node_pubkey_info;
static bool contains(const std::vector<sn_info_t>& infos, const crypto::public_key& key)
{
  const auto it =
    std::find_if(infos.begin(), infos.end(), [&key](const sn_info_t& info) { return info.pubkey == key; });
  return it != infos.end();
}

bool loki_service_nodes_test_rollback::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table(cryptonote::network_version_9_service_nodes);
  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(20); /// generate some outputs and unlock them
  gen.add_mined_money_unlock_blocks();

  std::vector<cryptonote::transaction> reg_txs;
  for (auto i = 0; i < 11; ++i) /// register some service nodes
  {
    const auto tx = gen.create_and_add_registration_tx(gen.first_miner());
    reg_txs.push_back(tx);
  }
  gen.create_and_add_next_block(reg_txs);

  gen.add_n_blocks(5);   /// create a few blocks with active service nodes
  auto fork = gen;       /// chain split here

  // deregister some node (A) on main
  const auto pk           = gen.top_quorum().obligations->workers[0];
  const auto dereg_tx     = gen.create_and_add_state_change_tx(service_nodes::new_state::deregister, pk);
  size_t deregister_index = gen.event_index();
  gen.create_and_add_next_block({dereg_tx});

  /// create a new service node (B) in the next block
  {
    const auto tx = gen.create_and_add_registration_tx(gen.first_miner());
    gen.create_and_add_next_block({tx});
  }

  fork.add_n_blocks(3); /// create blocks on the alt chain and trigger chain switch
  fork.add_n_blocks(15); // create a few more blocks to test winner selection
  loki_register_callback(events, "test_registrations", [&events, deregister_index](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("test_registrations");
    const auto sn_list = c.get_service_node_list_state({});
    /// Test that node A is still registered
    {
      /// obtain public key of node A
      const auto event_a = events.at(deregister_index);
      CHECK_TEST_CONDITION(std::holds_alternative<loki_blockchain_addable<loki_transaction>>(event_a));
      const auto dereg_tx = std::get<loki_blockchain_addable<loki_transaction>>(event_a);
      CHECK_TEST_CONDITION(dereg_tx.data.tx.type == cryptonote::txtype::state_change);

      cryptonote::tx_extra_service_node_state_change deregistration;
      cryptonote::get_service_node_state_change_from_tx_extra(
          dereg_tx.data.tx.extra, deregistration, c.get_blockchain_storage().get_current_hard_fork_version());

      const auto uptime_quorum = c.get_quorum(service_nodes::quorum_type::obligations, deregistration.block_height);
      CHECK_TEST_CONDITION(uptime_quorum);
      const auto pk_a = uptime_quorum->workers.at(deregistration.service_node_index);

      /// Check present
      const bool found_a = contains(sn_list, pk_a);
      CHECK_AND_ASSERT_MES(found_a, false, "Node deregistered in alt chain is not found in the main chain after reorg.");
    }

    /// Test that node B is not registered
    {
      /// obtain public key of node B
      constexpr size_t reg_evnt_idx = 73;
      const auto event_b = events.at(reg_evnt_idx);
      CHECK_TEST_CONDITION(std::holds_alternative<loki_blockchain_addable<loki_transaction>>(event_b));
      const auto reg_tx = std::get<loki_blockchain_addable<loki_transaction>>(event_b);

      crypto::public_key pk_b;
      if (!cryptonote::get_service_node_pubkey_from_tx_extra(reg_tx.data.tx.extra, pk_b)) {
        MERROR("Could not get service node key from tx extra");
        return false;
      }

      /// Check not present
      const bool found_b = contains(sn_list, pk_b);
      CHECK_AND_ASSERT_MES(!found_b, false, "Node registered in alt chain is present in the main chain after reorg.");
    }
    return true;
  });

  return true;
}

bool loki_service_nodes_test_swarms_basic::generate(std::vector<test_event_entry>& events)
{
  const std::vector<std::pair<uint8_t, uint64_t>> hard_forks = {
      std::make_pair(7, 0), std::make_pair(8, 1), std::make_pair(9, 2), std::make_pair(10, 150)};

  loki_chain_generator gen(events, hard_forks);
  gen.add_blocks_until_version(hard_forks.rbegin()[1].first);

  /// Create some service nodes before hf version 10
  constexpr size_t INIT_SN_COUNT  = 13;
  constexpr size_t TOTAL_SN_COUNT = 25;
  gen.add_n_blocks(90);
  gen.add_mined_money_unlock_blocks();

  /// register some service nodes
  std::vector<cryptonote::transaction> reg_txs;
  for (auto i = 0u; i < INIT_SN_COUNT; ++i)
  {
    const auto tx = gen.create_and_add_registration_tx(gen.first_miner());
    reg_txs.push_back(tx);
  }

  gen.create_and_add_next_block(reg_txs);

  /// create a few blocks with active service nodes
  gen.add_n_blocks(5);
  assert(gen.hf_version_ == cryptonote::network_version_9_service_nodes);

  gen.add_blocks_until_version(cryptonote::network_version_10_bulletproofs);
  loki_register_callback(events, "test_initial_swarms", [](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("test_swarms_basic::test_initial_swarms");
    const auto sn_list = c.get_service_node_list_state({}); /// Check that there is one active swarm and the swarm queue is not empty
    std::map<service_nodes::swarm_id_t, std::vector<crypto::public_key>> swarms;
    for (const auto& entry : sn_list)
    {
      const auto id = entry.info->swarm_id;
      swarms[id].push_back(entry.pubkey);
    }

    CHECK_EQ(swarms.size(), 1);
    CHECK_EQ(swarms.begin()->second.size(), 13);
    return true;
  });

  /// rewind some blocks and register 1 more service node
  {
    const auto tx = gen.create_and_add_registration_tx(gen.first_miner());
    gen.create_and_add_next_block({tx});
  }

  loki_register_callback(events, "test_with_one_more_sn", [](cryptonote::core &c, size_t ev_index) /// test that another swarm has been created
  {
    DEFINE_TESTS_ERROR_CONTEXT("test_with_one_more_sn");
    const auto sn_list = c.get_service_node_list_state({});
    std::map<service_nodes::swarm_id_t, std::vector<crypto::public_key>> swarms;
    for (const auto& entry : sn_list)
    {
      const auto id = entry.info->swarm_id;
      swarms[id].push_back(entry.pubkey);
    }
    CHECK_EQ(swarms.size(), 2);
    return true;
  });

  for (auto i = INIT_SN_COUNT + 1; i < TOTAL_SN_COUNT; ++i)
  {
    const auto tx = gen.create_and_add_registration_tx(gen.first_miner());
    gen.create_and_add_next_block({tx});
  }

  loki_register_callback(events, "test_with_more_sn", [](cryptonote::core &c, size_t ev_index) /// test that another swarm has been created
  {
    DEFINE_TESTS_ERROR_CONTEXT("test_with_more_sn");
    const auto sn_list = c.get_service_node_list_state({});
    std::map<service_nodes::swarm_id_t, std::vector<crypto::public_key>> swarms;
    for (const auto& entry : sn_list)
    {
      const auto id = entry.info->swarm_id;
      swarms[id].push_back(entry.pubkey);
    }
    CHECK_EQ(swarms.size(), 3);
    return true;
  });

  std::vector<cryptonote::transaction> dereg_txs; /// deregister enough snode to bring all 3 swarm to the min size
  const size_t excess = TOTAL_SN_COUNT - 3 * service_nodes::EXCESS_BASE;
  service_nodes::quorum_manager top_quorum = gen.top_quorum();
  for (size_t i = 0; i < excess; ++i)
  {
    const auto pk = top_quorum.obligations->workers[i];
    const auto tx = gen.create_and_add_state_change_tx(service_nodes::new_state::deregister, pk, cryptonote::get_block_height(gen.top().block));
    dereg_txs.push_back(tx);
  }

  gen.create_and_add_next_block(dereg_txs);
  loki_register_callback(events, "test_after_first_deregisters", [](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("test_after_first_deregisters");
    const auto sn_list = c.get_service_node_list_state({});
    std::map<service_nodes::swarm_id_t, std::vector<crypto::public_key>> swarms;
    for (const auto& entry : sn_list)
    {
      const auto id = entry.info->swarm_id;
      swarms[id].push_back(entry.pubkey);
    }
    CHECK_EQ(swarms.size(), 3);
    return true;
  });

  /// deregister 1 snode, which should trigger a decommission
  dereg_txs.clear();
  {
    const auto pk = gen.top_quorum().obligations->workers[0];
    const auto tx = gen.create_and_add_state_change_tx(service_nodes::new_state::deregister, pk);
    dereg_txs.push_back(tx);
  }
  gen.create_and_add_next_block(dereg_txs);

  loki_register_callback(events, "test_after_final_deregisters", [](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("test_after_first_deregisters");
    const auto sn_list = c.get_service_node_list_state({});
    std::map<service_nodes::swarm_id_t, std::vector<crypto::public_key>> swarms;
    for (const auto &entry : sn_list)
    {
      const auto id = entry.info->swarm_id;
      swarms[id].push_back(entry.pubkey);
    }

    CHECK_EQ(swarms.size(), 2);
    return true;
  });

  gen.add_n_blocks(5); /// test (implicitly) that deregistered nodes do not receive rewards
  return true;
}

bool loki_service_nodes_insufficient_contribution::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  uint64_t operator_portions                = STAKING_PORTIONS / 2;
  uint64_t remaining_portions               = STAKING_PORTIONS - operator_portions;
  cryptonote::keypair sn_keys               = cryptonote::keypair::generate(hw::get_device("default"));
  cryptonote::transaction register_tx       = gen.create_registration_tx(gen.first_miner_, sn_keys, operator_portions);
  gen.add_tx(register_tx);
  gen.create_and_add_next_block({register_tx});

  cryptonote::transaction stake = gen.create_and_add_staking_tx(sn_keys.pub, gen.first_miner_, MK_COINS(1));
  gen.create_and_add_next_block({stake});

  loki_register_callback(events, "test_insufficient_stake_does_not_get_accepted", [sn_keys](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("test_insufficient_stake_does_not_get_accepted");
    const auto sn_list = c.get_service_node_list_state({sn_keys.pub});
    CHECK_TEST_CONDITION(sn_list.size() == 1);

    service_nodes::service_node_pubkey_info const &pubkey_info = sn_list[0];
    CHECK_EQ(pubkey_info.info->total_contributed, MK_COINS(50));
    return true;
  });

  return true;
}

static loki_chain_generator setup_pulse_tests(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator result(events, hard_forks);

  result.add_blocks_until_version(hard_forks.back().first);
  result.add_mined_money_unlock_blocks();

  std::vector<cryptonote::transaction> registration_txs(service_nodes::pulse_min_service_nodes(cryptonote::FAKECHAIN));
  for (auto i = 0u; i < service_nodes::pulse_min_service_nodes(cryptonote::FAKECHAIN); ++i)
    registration_txs[i] = result.create_and_add_registration_tx(result.first_miner());

  // NOTE: Generate Valid Blocks
  result.create_and_add_next_block({registration_txs});
  result.create_and_add_next_block();
  return result;
}

bool loki_pulse_invalid_participation_bits::generate(std::vector<test_event_entry> &events)
{
  loki_chain_generator gen = setup_pulse_tests(events);
  gen.add_event_msg("Invalid Block: Participation bits wrong");
  loki_blockchain_entry entry     = {};
  loki_create_block_params params = gen.next_block_params();
  gen.block_begin(entry, params, {} /*tx_list*/);
  gen.block_fill_pulse_data(entry, params, entry.block.pulse.round);

  // NOTE: Overwrite participation bits to be wrong
  entry.block.pulse.validator_participation_bits = ~service_nodes::pulse_validator_bit_mask();

  gen.block_end(entry, params);
  gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Invalid Pulse Block, specifies the wrong participation bits");

  return true;
}

bool loki_pulse_invalid_signature::generate(std::vector<test_event_entry> &events)
{
  loki_chain_generator gen = setup_pulse_tests(events);
  gen.add_event_msg("Invalid Block: Wrong signature given (null signature)");
  loki_blockchain_entry entry     = {};
  loki_create_block_params params = gen.next_block_params();
  gen.block_begin(entry, params, {} /*tx_list*/);
  gen.block_fill_pulse_data(entry, params, entry.block.pulse.round);

  // NOTE: Overwrite signature
  entry.block.signatures[0].signature = {};
  gen.block_end(entry, params);
  gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Invalid Pulse Block, specifies the wrong participation bits");

  return true;
}

bool loki_pulse_oob_voter_index::generate(std::vector<test_event_entry> &events)
{
  loki_chain_generator gen = setup_pulse_tests(events);
  gen.add_event_msg("Invalid Block: Quorum index that indexes out of bounds");
  loki_blockchain_entry entry     = {};
  loki_create_block_params params = gen.next_block_params();
  gen.block_begin(entry, params, {} /*tx_list*/);
  gen.block_fill_pulse_data(entry, params, entry.block.pulse.round);

  // NOTE: Overwrite oob voter index
  entry.block.signatures.back().voter_index = service_nodes::PULSE_QUORUM_NUM_VALIDATORS + 1;
  gen.block_end(entry, params);
  gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Invalid Pulse Block, specifies the wrong participation bits");

  return true;
}

bool loki_pulse_non_participating_validator::generate(std::vector<test_event_entry> &events)
{
  loki_chain_generator gen = setup_pulse_tests(events);
  gen.add_event_msg("Invalid Block: Validator gave signature but is not locked in to participate this round.");
  loki_blockchain_entry entry     = {};
  loki_create_block_params params = gen.next_block_params();
  gen.block_begin(entry, params, {} /*tx_list*/);

  // NOTE: Manually generate signatures to break test
  {
    {
      entry.block.pulse.round = 0;
      for (size_t i = 0; i < sizeof(entry.block.pulse.random_value.data); i++)
        entry.block.pulse.random_value.data[i] = static_cast<char>(tools::uniform_distribution_portable(tools::rng, 256));
    }

    service_nodes::quorum quorum = {};
    {
      std::vector<service_nodes::pubkey_and_sninfo> active_snode_list = params.prev.service_node_state.active_service_nodes_infos();

      std::vector<crypto::hash> entropy;
      service_nodes::get_pulse_entropy_from_blockchain(gen.db_, cryptonote::get_block_height(entry.block) + 1, entropy, entry.block.pulse.round);
      quorum = generate_pulse_quorum(cryptonote::FAKECHAIN, params.queued_winner.key, entry.block.major_version, active_snode_list, entropy, entry.block.pulse.round);
      assert(quorum.validators.size() == service_nodes::PULSE_QUORUM_NUM_VALIDATORS);
      assert(quorum.workers.size() == 1);
    }

    // NOTE: First 7 validators are locked in. We received signatures from the
    // first 6 in the quorum, then the 8th validator in the quorum (who is not
    // meant to be participating).
    entry.block.pulse.validator_participation_bits = 0b0000'000'0111'1111;
    size_t const voter_indexes[]                  = {0, 1, 2, 3, 4, 5, 7};

    crypto::hash block_hash = cryptonote::get_block_hash(entry.block);
    assert(entry.block.signatures.empty());
    for (size_t index : voter_indexes)
    {
      service_nodes::service_node_keys validator_keys = gen.get_cached_keys(quorum.validators[index]);
      assert(validator_keys.pub == quorum.validators[index]);

      service_nodes::quorum_signature signature = {};
      signature.voter_index                     = index;
      crypto::generate_signature(block_hash, validator_keys.pub, validator_keys.key, signature.signature);
      entry.block.signatures.push_back(signature);
    }
  }

  gen.block_end(entry, params);
  gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Invalid Pulse Block, specifies the wrong participation bits");

  return true;
}

bool loki_pulse_generate_all_rounds::generate(std::vector<test_event_entry> &events)
{
  loki_chain_generator gen = setup_pulse_tests(events);

  for (uint8_t round = 0; round < static_cast<uint8_t>(-1); round++)
  {
    loki_blockchain_entry entry     = {};
    loki_create_block_params params = gen.next_block_params();
    gen.block_begin(entry, params, {} /*tx_list*/);
    gen.block_fill_pulse_data(entry, params, round);
    gen.block_end(entry, params);
    gen.add_block(entry, true);
  }

  return true;
}

bool loki_pulse_out_of_order_voters::generate(std::vector<test_event_entry> &events)
{
  loki_chain_generator gen = setup_pulse_tests(events);
  gen.add_event_msg("Invalid Block: Quorum voters are out of order");
  loki_blockchain_entry entry     = {};
  loki_create_block_params params = gen.next_block_params();
  gen.block_begin(entry, params, {} /*tx_list*/);
  gen.block_fill_pulse_data(entry, params, entry.block.pulse.round);

  // NOTE: Swap voters so that the votes are not sorted in order
  auto tmp                       = entry.block.signatures.back();
  entry.block.signatures.back()  = entry.block.signatures.front();
  entry.block.signatures.front() = tmp;
  gen.block_end(entry, params);
  gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Invalid Pulse Block, specifies the signatures not in sorted order");

  return true;
}

bool loki_pulse_reject_miner_block::generate(std::vector<test_event_entry> &events)
{
  loki_chain_generator gen = setup_pulse_tests(events);
  gen.add_event_msg("Invalid Block: PoW Block but we have enough service nodes for Pulse");
  loki_blockchain_entry entry     = {};
  loki_create_block_params params = gen.next_block_params();
  gen.block_begin(entry, params, {} /*tx_list*/);

  // NOTE: Create an ordinary miner block even when we have enough Service Nodes for Pulse.
  fill_nonce_with_loki_generator(&gen, entry.block, TEST_DEFAULT_DIFFICULTY, cryptonote::get_block_height(entry.block));

  gen.block_end(entry, params);
  gen.add_block(entry, false /*can_be_added_to_blockchain*/, "Invalid Pulse Block, block was mined with a miner but we have enough nodes for Pulse");
  return true;
}

bool loki_pulse_generate_blocks_and_invalid_blocks::generate(std::vector<test_event_entry> &events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_mined_money_unlock_blocks();

  int constexpr NUM_SERVICE_NODES = service_nodes::PULSE_QUORUM_SIZE + 1 /*leader*/;
  std::vector<cryptonote::transaction> registration_txs(NUM_SERVICE_NODES);
  for (auto i = 0u; i < NUM_SERVICE_NODES; ++i)
    registration_txs[i] = gen.create_and_add_registration_tx(gen.first_miner());

  gen.create_and_add_next_block({registration_txs});
  gen.create_and_add_next_block();
  return true;
}
