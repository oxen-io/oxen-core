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

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "sn_core_tests"

// TODO(loki): Improved register callback that all tests should start using.
// Classes are not regenerated when replaying the test through the blockchain.
// Before, state saved in this class like saving indexes where events ocurred
// would not persist because when replaying tests we create a new instance of
// the test class.

  // i.e.
#if 0
    std::vector<events> events;
    {
        gen_service_nodes generator;
        generator.generate(events);
    }

    gen_service_nodes generator;
    replay_events_through_core(generator, ...)
#endif

// Which is stupid. Instead we preserve the original generator. This means
// all the tests that use callbacks to preserve state can be removed.

// TODO(loki): A lot of code using the new lambda callbacks now have access to
// the shared stack frame where before it didn't can be optimised to utilise the
// frame instead of re-deriving where data should be in the
// test_events_entry array
void loki_register_callback(std::vector<test_event_entry> &events,
                            std::string const &callback_name,
                            loki_callback callback)
{
  events.push_back(loki_callback_entry{callback_name, callback});
}

std::vector<std::pair<uint8_t, uint64_t>>
loki_generate_sequential_hard_fork_table(uint8_t max_hf_version)
{
  assert(max_hf_version < cryptonote::network_version_count);
  std::vector<std::pair<uint8_t, uint64_t>> result = {};
  uint64_t version_height = 0;
  for (uint8_t version = cryptonote::network_version_7; version <= max_hf_version; version++)
    result.emplace_back(std::make_pair(version, version_height++));
  return result;
}

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
  gen.add_n_blocks(40);
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
    std::shared_ptr<const service_nodes::testing_quorum> quorum = gen.get_testing_quorum(service_nodes::quorum_type::checkpointing, gen.height());
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

  // NOTE: Checkpoint should cause a reorg back to checkpoint height - 1. The
  // alt block is still in the alt db because we don't trigger a chain switch
  // until we receive a 2nd block that confirms the alt block.
  loki_register_callback(events, "check_alt_block_count", [&events](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_alt_block_count");
    CHECK_EQ(c.get_blockchain_storage().get_alternative_blocks_count(), 1);
    return true;
  });

  // NOTE: We add a new block ontop that causes the alt block code path to run
  // again, and calculate that this alt chain now has 2 blocks on it with
  // a greater cumulative difficulty, causing a chain switch at this point.
  fork.create_and_add_next_block();
  crypto::hash expected_top_hash = cryptonote::get_block_hash(fork.top().block);
  loki_register_callback(events, "check_chain_reorged", [&events, expected_top_hash](cryptonote::core &c, size_t ev_index)
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
  gen.add_n_blocks(40);
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
    std::shared_ptr<const service_nodes::testing_quorum> quorum = gen.get_testing_quorum(service_nodes::quorum_type::checkpointing, gen.height());
    if (quorum && quorum->validators.size()) break;
  }
  assert(tries != MAX_TRIES);

  loki_chain_generator fork_with_more_checkpoints = gen;
  gen.add_n_blocks(60); // Add blocks so that this chain has more PoW

  cryptonote::checkpoint_t checkpoint = fork_with_more_checkpoints.create_service_node_checkpoint(fork_with_more_checkpoints.height(), service_nodes::CHECKPOINT_MIN_VOTES);
  fork_with_more_checkpoints.create_and_add_next_block({}, &checkpoint);
  uint64_t const fork_top_height   = cryptonote::get_block_height(fork_with_more_checkpoints.top().block);
  crypto::hash const fork_top_hash = cryptonote::get_block_hash(fork_with_more_checkpoints.top().block);

  loki_register_callback(events, "check_switched_to_alt_chain", [&events, fork_top_hash, fork_top_height](cryptonote::core &c, size_t ev_index)
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
  gen.add_n_blocks(40);
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
    std::shared_ptr<const service_nodes::testing_quorum> quorum = gen.get_testing_quorum(service_nodes::quorum_type::checkpointing, gen.height());
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
  std::shared_ptr<const service_nodes::testing_quorum> first_quorum = fork.get_testing_quorum(service_nodes::quorum_type::checkpointing, gen.height());

  for (size_t i = 0; i < service_nodes::CHECKPOINT_INTERVAL; i++)
  {
    gen.create_and_add_next_block();
    fork.create_and_add_next_block();
  }

  uint64_t second_checkpointed_height    = fork.height();
  uint64_t second_checkpointed_height_hf = fork.top().block.major_version;
  crypto::hash second_checkpointed_hash  = cryptonote::get_block_hash(fork.top().block);
  std::shared_ptr<const service_nodes::testing_quorum> second_quorum = fork.get_testing_quorum(service_nodes::quorum_type::checkpointing, gen.height());

  // NOTE: Fork generates service node votes, upon sending them over and the
  // main chain collecting them validly (they should be able to verify
  // signatures because we store alt quorums) it should generate a checkpoint
  // belonging to the forked chain- which should cause it to detach back to the
  // checkpoint height

  // First send the votes for the newest checkpoint, we should reorg back halfway
  for (size_t i = 0; i < service_nodes::CHECKPOINT_MIN_VOTES; i++)
  {
    auto keys = gen.get_cached_keys(second_quorum->validators[i]);
    service_nodes::quorum_vote_t fork_vote = service_nodes::make_checkpointing_vote(second_checkpointed_height_hf, second_checkpointed_hash, second_checkpointed_height, i, keys);
    events.push_back(loki_blockchain_addable<service_nodes::quorum_vote_t>(fork_vote, true/*can_be_added_to_blockchain*/, "A second_checkpoint vote from the forked chain should be accepted since we should be storing alternative service node states and quorums"));
  }

  // Then we send the votes for the next newest checkpoint, we should reorg back to our forking point
  for (size_t i = 0; i < service_nodes::CHECKPOINT_MIN_VOTES; i++)
  {
    auto keys = gen.get_cached_keys(first_quorum->validators[i]);
    service_nodes::quorum_vote_t fork_vote = service_nodes::make_checkpointing_vote(first_checkpointed_height_hf, first_checkpointed_hash, first_checkpointed_height, i, keys);
    events.push_back(loki_blockchain_addable<service_nodes::quorum_vote_t>(fork_vote, true/*can_be_added_to_blockchain*/, "A first_checkpoint vote from the forked chain should be accepted since we should be storing alternative service node states and quorums"));
  }

  // Upon adding the last block, we should now switch to our forked chain
  fork.create_and_add_next_block({});
  crypto::hash const fork_top_hash = cryptonote::get_block_hash(fork.top().block);
  loki_register_callback(events, "check_switched_to_alt_chain", [&events, fork_top_hash](cryptonote::core &c, size_t ev_index)
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

// NOTE: - Checks that an alt chain eventually takes over the main chain with
// only 1 checkpoint, by progressively adding 2 more checkpoints at the next
// available checkpoint heights whilst maintaining equal heights with the main chain
bool loki_checkpointing_alt_chain_with_increasing_service_node_checkpoints::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(40);
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
    std::shared_ptr<const service_nodes::testing_quorum> quorum = gen.get_testing_quorum(service_nodes::quorum_type::checkpointing, gen.height());
    if (quorum && quorum->validators.size()) break;
  }
  assert(tries != MAX_TRIES);

  // Setup the two chains as follows, where C = checkpointed block, B = normal
  // block, the main chain should NOT reorg to the fork chain as they have the
  // same PoW-ish and equal number of checkpoints.
  // Main chain - C B B B B
  // Fork chain - B B B B C
  loki_chain_generator fork               = gen;
  cryptonote::checkpoint_t gen_checkpoint = gen.create_service_node_checkpoint(gen.height(), service_nodes::CHECKPOINT_MIN_VOTES);
  gen.create_and_add_next_block({}, &gen_checkpoint);
  fork.create_and_add_next_block();

  gen.add_blocks_until_next_checkpointable_height();
  gen.create_and_add_next_block();

  fork.add_blocks_until_next_checkpointable_height();
  cryptonote::checkpoint_t fork_first_checkpoint = fork.create_service_node_checkpoint(fork.height(), service_nodes::CHECKPOINT_MIN_VOTES);
  fork.create_and_add_next_block({}, &fork_first_checkpoint);

  crypto::hash const gen_top_hash = cryptonote::get_block_hash(gen.top().block);
  loki_register_callback(events, "check_still_on_main_chain", [&events, gen_top_hash](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_still_on_main_chain");
    uint64_t top_height;
    crypto::hash top_hash;
    c.get_blockchain_top(top_height, top_hash);
    CHECK_EQ(top_hash, gen_top_hash);
    return true;
  });

  // Now create the following chain, the fork chain should be switched to due to now having more checkpoints
  // Main chain - C B B B B | B B B B
  // Fork chain - B B B B C | B B B C
  gen.add_blocks_until_next_checkpointable_height();
  gen.create_and_add_next_block();

  fork.add_blocks_until_next_checkpointable_height();
  cryptonote::checkpoint_t fork_second_checkpoint = fork.create_service_node_checkpoint(fork.height(), service_nodes::CHECKPOINT_MIN_VOTES);
  fork.create_and_add_next_block({}, &fork_second_checkpoint);

  crypto::hash const fork_top_hash = cryptonote::get_block_hash(fork.top().block);
  loki_register_callback(events, "check_switched_to_alt_chain", [&events, fork_top_hash](cryptonote::core &c, size_t ev_index)
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
  gen.add_n_blocks(40);
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
    std::shared_ptr<const service_nodes::testing_quorum> quorum = gen.get_testing_quorum(service_nodes::quorum_type::checkpointing, gen.height());
    if (quorum && quorum->validators.size()) break;
  }
  assert(tries != MAX_TRIES);

  // NOTE: Generate service node votes
  uint64_t checkpointed_height                                = gen.height();
  crypto::hash checkpointed_hash                              = cryptonote::get_block_hash(gen.top().block);
  std::shared_ptr<const service_nodes::testing_quorum> quorum = gen.get_testing_quorum(service_nodes::quorum_type::checkpointing, gen.height());
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

  loki_register_callback(events, "check_service_node_checkpoint_rejected_insufficient_votes", [&events, checkpointed_height](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_service_node_checkpoint_rejected_insufficient_votes");
    cryptonote::Blockchain const &blockchain = c.get_blockchain_storage();
    cryptonote::checkpoint_t real_checkpoint;
    CHECK_TEST_CONDITION(blockchain.get_checkpoint(checkpointed_height, real_checkpoint) == false);
    return true;
  });

  // NOTE: Add last vote and check checkpoint has been generated
  gen.events_.push_back(checkpoint_votes.back());
  loki_register_callback(events, "check_service_node_checkpoint_accepted", [&events, checkpointed_height](cryptonote::core &c, size_t ev_index)
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
  gen.add_n_blocks(40);
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
    std::shared_ptr<const service_nodes::testing_quorum> quorum = gen.get_testing_quorum(service_nodes::quorum_type::checkpointing, gen.height());
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

  gen.add_n_blocks(60);
  gen.add_mined_money_unlock_blocks();

  cryptonote::account_base dummy = gen.add_account();
  int constexpr NUM_TXS          = 60;
  std::vector<cryptonote::transaction> txs(NUM_TXS);
  for (int i = 0; i < NUM_TXS; i++)
    txs[i] = gen.create_and_add_tx(gen.first_miner_, dummy, MK_COINS(5));

  gen.create_and_add_next_block(txs);
  uint64_t unpenalized_block_reward     = cryptonote::block_reward_unpenalized_formula_v8(gen.height());
  uint64_t expected_service_node_reward = cryptonote::service_node_reward_formula(unpenalized_block_reward, newest_hf);

  loki_register_callback(events, "check_block_rewards", [&events, unpenalized_block_reward, expected_service_node_reward](cryptonote::core &c, size_t ev_index)
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

bool loki_core_governance_batched_reward::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  const cryptonote::config_t &network = cryptonote::get_config(cryptonote::FAKECHAIN, cryptonote::network_version_count - 1);

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

  loki_register_callback(events, "check_batched_governance_amount_matches", [&events, hf10_height, expected_total_governance_paid](cryptonote::core &c, size_t ev_index)
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
    gen.create_and_add_tx(miner, alice, MK_COINS(1), TESTS_DEFAULT_FEE * 100);
  }

  /// generate two deregisters
  const auto deregister_pub_key_1 = gen.top_quorum().obligations->workers[0];
  const auto deregister_pub_key_2 = gen.top_quorum().obligations->workers[1];
  gen.create_and_add_state_change_tx(service_nodes::new_state::deregister, deregister_pub_key_1);
  gen.create_and_add_state_change_tx(service_nodes::new_state::deregister, deregister_pub_key_2);

  loki_register_callback(events, "check_prefer_deregisters", [&events, miner](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_prefer_deregisters");
    const auto tx_count = c.get_pool_transactions_count();
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
      CHECK_TEST_CONDITION(find_block_chain(events, chain, mtx, get_block_hash(boost::get<cryptonote::block>(events[0]))));
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
  gen.add_n_blocks(20); /// give miner some outputs to spend and unlock them
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
  gen.add_n_blocks(20); /// generate some outputs and unlock them
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
  gen.add_n_blocks(20); /// generate some outputs and unlock them
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

// NOTE: Generate forked block, check that alternative quorums are generated and accessible
bool loki_service_nodes_alt_quorums::generate(std::vector<test_event_entry>& events)
{
  std::vector<std::pair<uint8_t, uint64_t>> hard_forks = loki_generate_sequential_hard_fork_table();
  loki_chain_generator gen(events, hard_forks);

  gen.add_blocks_until_version(hard_forks.back().first);
  gen.add_n_blocks(40);
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
  loki_register_callback(events, "check_alt_quorums_exist", [&events, fork_quorums, height_with_fork](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_alt_quorums_exist");

    std::vector<std::shared_ptr<const service_nodes::testing_quorum>> alt_quorums;
    c.get_testing_quorum(service_nodes::quorum_type::obligations, height_with_fork, false /*include_old*/, &alt_quorums);
    CHECK_TEST_CONDITION_MSG(alt_quorums.size() == 1, "alt_quorums.size(): " << alt_quorums.size());

    service_nodes::testing_quorum const &fork_obligation_quorum = *fork_quorums.obligations;
    service_nodes::testing_quorum const &real_obligation_quorum = *(alt_quorums[0]);
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
  gen.add_n_blocks(40);
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
  loki_register_callback(events, "check_checkpoint_quorum_should_be_empty", [&events, check_height_1](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_checkpoint_quorum_should_be_empty");
    std::shared_ptr<const service_nodes::testing_quorum> quorum = c.get_testing_quorum(service_nodes::quorum_type::checkpointing, check_height_1);
    CHECK_TEST_CONDITION(quorum != nullptr);
    CHECK_TEST_CONDITION(quorum->validators.size() == 0);
    return true;
  });

  cryptonote::transaction new_registration_tx = gen.create_and_add_registration_tx(gen.first_miner());
  gen.create_and_add_next_block({new_registration_tx});

  for (tries = 0; tries < MAX_TRIES; tries++)
  {
    gen.add_blocks_until_next_checkpointable_height();
    std::shared_ptr<const service_nodes::testing_quorum> quorum = gen.get_testing_quorum(service_nodes::quorum_type::checkpointing, gen.height());
    if (quorum && quorum->validators.size()) break;
  }
  assert(tries != MAX_TRIES);

  uint64_t check_height_2 = gen.height();
  loki_register_callback(events, "check_checkpoint_quorum_should_be_populated", [&events, check_height_2](cryptonote::core &c, size_t ev_index)
  {
    DEFINE_TESTS_ERROR_CONTEXT("check_checkpoint_quorum_should_be_populated");
    std::shared_ptr<const service_nodes::testing_quorum> quorum = c.get_testing_quorum(service_nodes::quorum_type::checkpointing, check_height_2);
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

  const auto tx0 = gen.create_and_add_tx(miner, alice, MK_COINS(101));
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
      CHECK_TEST_CONDITION(event_a.type() == typeid(loki_blockchain_addable<loki_transaction>));
      const auto dereg_tx = boost::get<loki_blockchain_addable<loki_transaction>>(event_a);
      CHECK_TEST_CONDITION(dereg_tx.data.tx.type == cryptonote::txtype::state_change);

      cryptonote::tx_extra_service_node_state_change deregistration;
      cryptonote::get_service_node_state_change_from_tx_extra(
          dereg_tx.data.tx.extra, deregistration, c.get_blockchain_storage().get_current_hard_fork_version());

      const auto uptime_quorum = c.get_testing_quorum(service_nodes::quorum_type::obligations, deregistration.block_height);
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
      CHECK_TEST_CONDITION(event_b.type() == typeid(loki_blockchain_addable<loki_transaction>));
      const auto reg_tx = boost::get<loki_blockchain_addable<loki_transaction>>(event_b);

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
  gen.add_n_blocks(100);
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
  loki_register_callback(events, "test_initial_swarms", [&events](cryptonote::core &c, size_t ev_index)
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

  loki_register_callback(events, "test_with_one_more_sn", [&events](cryptonote::core &c, size_t ev_index) /// test that another swarm has been created
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

  loki_register_callback(events, "test_with_more_sn", [&events](cryptonote::core &c, size_t ev_index) /// test that another swarm has been created
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
  loki_register_callback(events, "test_after_first_deregisters", [&events](cryptonote::core &c, size_t ev_index)
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

  loki_register_callback(events, "test_after_final_deregisters", [&events](cryptonote::core &c, size_t ev_index)
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
