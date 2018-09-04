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
#include "service_nodes.h"

using namespace std;

using namespace epee;
using namespace cryptonote;

struct sn_registration {
  cryptonote::keypair keys;
  sn_contributor_t contribution;
};
class linear_chain_generator
{

  private:
    test_generator gen_;
    std::vector<test_event_entry>& events_;
    std::vector<cryptonote::block> blocks_;

    std::vector<sn_registration> sn_owners_;

    int next_winner_idx = 0;

    cryptonote::account_base first_miner_;

  public:
    linear_chain_generator(std::vector<test_event_entry> &events)
      : gen_(), events_(events)
    { }

    cryptonote::account_base create_account()
    {
      cryptonote::account_base account;
      account.generate();
      events_.push_back(account);
      return account;
    }

    void create_genesis_block()
    {
      constexpr uint64_t ts_start = 1338224400;
      first_miner_.generate();
      cryptonote::block gen_block;
      gen_.construct_block(gen_block, first_miner_, ts_start);
      events_.push_back(gen_block);
      blocks_.push_back(gen_block);
    }

    void create_block(const std::vector<cryptonote::transaction>& txs = {})
    {
      const auto sn_pk = crypto::null_pkey;
      const std::vector<sn_contributor_t> contribs = { { { crypto::null_pkey, crypto::null_pkey },
                                                          STAKING_PORTIONS } };

      cryptonote::block blk;
      gen_.construct_block(blk, blocks_.back(), first_miner_, { txs.begin(), txs.end() }, sn_pk, contribs);
      blocks_.push_back(blk);
      events_.push_back(blk);
    }

    void create_block_sn(const std::vector<cryptonote::transaction>& txs = {})
    {

      const auto winner = sn_owners_.at(next_winner_idx);

      next_winner_idx++;
      if (next_winner_idx >= sn_owners_.size()) {
        next_winner_idx = 0;
      }

      const auto sn_pk = winner.keys.pub;
      const std::vector<sn_contributor_t> contribs = { winner.contribution };

      cryptonote::block gen_block;
      gen_.construct_block(gen_block, blocks_.back(), first_miner_, { txs.begin(), txs.end() }, sn_pk, contribs);
      blocks_.push_back(gen_block);
      events_.push_back(gen_block);
    }

    void rewind_until_v9()
    {
      gen_.set_hf_version(8);
      create_block();
      gen_.set_hf_version(9);
      create_block();
    }

    void rewind_blocks_n(int n)
    {
      for (auto i = 0; i < n; ++i) {
        create_block();
      }
    }

    void rewind_blocks()
    {
      rewind_blocks_n(CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW);
    }

    cryptonote::transaction create_tx(const cryptonote::account_base& miner,
                                      const cryptonote::account_base& acc,
                                      uint64_t amount,
                                      uint64_t fee = TESTS_DEFAULT_FEE)
    {
      cryptonote::transaction t;
      construct_tx_to_key(events_, t, blocks_.back(), miner, acc, amount, fee, 9);
      events_.push_back(t);
      return t;
    }

    cryptonote::transaction create_registration_tx(const cryptonote::account_base& acc, const cryptonote::keypair& sn_keys)
    {
      const sn_contributor_t contr = {acc.get_keys().m_account_address, STAKING_PORTIONS};
      const sn_registration owner = {sn_keys, contr};
      sn_owners_.push_back(owner);
      return make_registration_tx(events_, acc, sn_keys, blocks_.back());
    }

    cryptonote::transaction create_registration_tx()
    {
      const auto sn_keys = keypair::generate(hw::get_device("default"));
      return create_registration_tx(first_miner_, sn_keys);
    }

    const cryptonote::account_base& first_miner() const {
      return first_miner_;
    }

    cryptonote::transaction create_deregister_tx(uint32_t idx_to_kick) {

      cryptonote::transaction deregister_tx;

      /// sort service node pub keys; create a copy so that we don't modify the original
      auto sn_owners_sorted = sn_owners_;

      std::sort(sn_owners_sorted.begin(), sn_owners_sorted.end(),
      [](const sn_registration &a, const sn_registration &b) {
        return memcmp(reinterpret_cast<const void*>(&a.keys.pub), reinterpret_cast<const void*>(&b.keys.pub), sizeof(a.keys.pub)) < 0;
      });

      /// NOTE: need to know which service nodes will end up in the quorum
      std::vector<size_t> pub_keys_indexes;
      {
        uint64_t seed = 0;
        const crypto::hash block_hash = cryptonote::get_block_hash(blocks_.back());
        std::memcpy(&seed, block_hash.data, std::min(sizeof(seed), sizeof(block_hash.data)));

        pub_keys_indexes.resize(sn_owners_sorted.size());
        for (size_t i = 0; i < sn_owners_sorted.size(); i++) { pub_keys_indexes[i] = i; }

        service_nodes::loki_shuffle(pub_keys_indexes, seed);
      }

      const std::vector<size_t> quorum_idxs(pub_keys_indexes.begin(), pub_keys_indexes.begin() + service_nodes::QUORUM_SIZE);
      const std::vector<size_t> to_test(pub_keys_indexes.begin() + service_nodes::QUORUM_SIZE, pub_keys_indexes.end());

      if (idx_to_kick >= to_test.size()) {
        std::cerr << "Node to test does not exist\n";
        return {};
      }

      cryptonote::tx_extra_service_node_deregister deregister;
      deregister.block_height = get_block_height(blocks_.back());
      deregister.service_node_index = idx_to_kick; /// idx inside nodes to test

      /// need to create MIN_VOTES_TO_KICK_SERVICE_NODE (7) votes
      for (uint32_t i = 0u; i < quorum_idxs.size(); ++i) {
        const auto idx = quorum_idxs[i];
        const auto pk = sn_owners_sorted.at(idx).keys.pub;
        const auto sk = sn_owners_sorted.at(idx).keys.sec;
        const auto signature = loki::service_node_deregister::sign_vote(deregister.block_height, deregister.service_node_index, pk, sk);

        deregister.votes.push_back({signature, i}); /// index in quorum
      }

      const bool full_tx_deregister_made = cryptonote::add_service_node_deregister_to_tx_extra(deregister_tx.extra, deregister);
      if (full_tx_deregister_made) {
          deregister_tx.version = cryptonote::transaction::version_3_per_output_unlock_times;
          deregister_tx.is_deregister = true;
      }

      events_.push_back(deregister_tx);

      return deregister_tx;

    }
};

//-----------------------------------------------------------------------------------------------------
//---------------------------------- Generate Service Nodes -------------------------------------------
//-----------------------------------------------------------------------------------------------------
gen_service_nodes::gen_service_nodes()
{
  /// NOTE: we don't generate random keys here, because the verification will call its own constructor
  constexpr char pub_key_str[] = "cf6ae1d4e902f7a85af58d6069c29f09702e25fd07cf28d359e64401002db2a1";
  constexpr char sec_key_str[] = "ead4cc692c4237f62f9cefaf5e106995b2dda79a29002a546876f9ee7abcc203";

  epee::string_tools::hex_to_pod(pub_key_str, m_alice_service_node_keys.pub);
  epee::string_tools::hex_to_pod(sec_key_str, m_alice_service_node_keys.sec);

  REGISTER_CALLBACK("check_registered", gen_service_nodes::check_registered);
  REGISTER_CALLBACK("check_expired", gen_service_nodes::check_expired);
}
//-----------------------------------------------------------------------------------------------------
bool gen_service_nodes::generate(std::vector<test_event_entry> &events) const
{

  linear_chain_generator gen(events);
  gen.create_genesis_block();                           //  1

  const auto miner = gen.first_miner();
  const auto alice = gen.create_account();

  gen.rewind_until_v9();                                //  3
  gen.rewind_blocks_n(10);                              // 13

  gen.rewind_blocks();                                  // 13 + N

  const auto tx0 = gen.create_tx(miner, alice, MK_COINS(101));
  gen.create_block({tx0});                              // 14 + N

  gen.rewind_blocks();                                  // 14 + 2N

  const auto reg_tx = gen.create_registration_tx(alice, m_alice_service_node_keys);

  gen.create_block({reg_tx});                           // 15 + 2N

  DO_CALLBACK(events, "check_registered");

  for (auto i = 0u; i < service_nodes::get_staking_requirement_lock_blocks(cryptonote::FAKECHAIN); ++i) {
    /// TODO: expire sn automatically, so the generator can decide whether to announce winners
    /// (and this could be replaced with a regular create_blocks)
    gen.create_block_sn();
  } // 15 + 2N + M

  DO_CALLBACK(events, "check_expired");

  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_service_nodes::check_registered(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_service_nodes::check_registered");

  cryptonote::account_base alice = boost::get<cryptonote::account_base>(events[1]);

  std::vector<block> block_list;
  bool r = c.get_blocks(0, 15 + 2 * CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW, block_list);
  CHECK_TEST_CONDITION(r);
  std::vector<cryptonote::block> chain;
  map_hash2tx_t mtx;
  std::vector<block> blocks(block_list.begin(), block_list.end());
  r = find_block_chain(events, chain, mtx, get_block_hash(blocks.back()));
  CHECK_TEST_CONDITION(r);

  const uint64_t staking_requirement = MK_COINS(100);

  CHECK_EQ(MK_COINS(101) - TESTS_DEFAULT_FEE - staking_requirement, get_unlocked_balance(alice, blocks, mtx));

  /// check that alice is registered
  const auto info_v = c.get_service_node_list_state({m_alice_service_node_keys.pub});
  CHECK_EQ(info_v.empty(), false);

  return true;
}
//-----------------------------------------------------------------------------------------------------
bool gen_service_nodes::check_expired(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{
  DEFINE_TESTS_ERROR_CONTEXT("gen_service_nodes::check_expired");

  cryptonote::account_base alice = boost::get<cryptonote::account_base>(events[1]);

  const auto stake_lock_time = service_nodes::get_staking_requirement_lock_blocks(cryptonote::FAKECHAIN);

  std::vector<block> block_list;

  bool r = c.get_blocks(0, 15 + 2 * CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW + stake_lock_time, block_list);
  CHECK_TEST_CONDITION(r);
  std::vector<cryptonote::block> chain;
  map_hash2tx_t mtx;
  std::vector<block> blocks(block_list.begin(), block_list.end());
  r = find_block_chain(events, chain, mtx, get_block_hash(blocks.back()));
  CHECK_TEST_CONDITION(r);

  /// check that alice's registration expired
  const auto info_v = c.get_service_node_list_state({m_alice_service_node_keys.pub});
  CHECK_EQ(info_v.empty(), true);

  /// check that alice received some service node rewards (TODO: check the balance precisely)
  CHECK_TEST_CONDITION(get_balance(alice, blocks, mtx) > MK_COINS(101) - TESTS_DEFAULT_FEE);

  return true;

}
//-----------------------------------------------------------------------------------------------------
//------------------------------ Test Blocks Prefer Deregisters ---------------------------------------
//-----------------------------------------------------------------------------------------------------
test_prefer_deregisters::test_prefer_deregisters() {
  REGISTER_CALLBACK("check_prefer_deregisters", test_prefer_deregisters::check_prefer_deregisters);
}
//-----------------------------------------------------------------------------------------------------
bool test_prefer_deregisters::generate(std::vector<test_event_entry> &events)
{
  linear_chain_generator gen(events);

  gen.create_genesis_block();

  const auto miner = gen.first_miner();
  const auto alice = gen.create_account();

  gen.rewind_until_v9();

  /// give miner some outputs to spend and unlock them
  gen.rewind_blocks_n(60);
  gen.rewind_blocks();

  /// register 12 random service nodes
  std::vector<cryptonote::transaction> reg_txs;
  for (auto i = 0; i < 12; ++i) {
    const auto tx = gen.create_registration_tx();
    reg_txs.push_back(tx);
  }

  gen.create_block(reg_txs);

  /// generate transactions to fill up txpool entirely
  for (auto i = 0u; i < 45; ++i) {
    gen.create_tx(miner, alice, MK_COINS(1), TESTS_DEFAULT_FEE * 100);
  }

  /// generate two deregisters
  gen.create_deregister_tx(0);
  gen.create_deregister_tx(1);

  DO_CALLBACK(events, "check_prefer_deregisters");

  return true;
}
//-----------------------------------------------------------------------------------------------------
bool test_prefer_deregisters::check_prefer_deregisters(cryptonote::core& c, size_t ev_index, const std::vector<test_event_entry> &events)
{

  DEFINE_TESTS_ERROR_CONTEXT("test_prefer_deregisters::check_prefer_deregisters");

  const auto tx_count = c.get_pool_transactions_count();

  cryptonote::block full_blk;
  {
    difficulty_type diffic;
    uint64_t height;
    uint64_t expected_reward;
    cryptonote::blobdata extra_nonce;
    const auto miner = boost::get<cryptonote::account_base>(events[1]);
    c.get_block_template(full_blk, miner.get_keys().m_account_address, diffic, height, expected_reward, extra_nonce);
  }

  map_hash2tx_t mtx;
  {
    std::vector<cryptonote::block> chain;
    CHECK_TEST_CONDITION(find_block_chain(events, chain, mtx, get_block_hash(boost::get<cryptonote::block>(events[0]))));
  }

  const auto deregister_count =
    std::count_if(full_blk.tx_hashes.begin(), full_blk.tx_hashes.end(), [&mtx](const crypto::hash& tx_hash) {
      return mtx[tx_hash]->is_deregister;
    });

  /// test that there are more transactions in tx pool
  CHECK_TEST_CONDITION(tx_count > full_blk.tx_hashes.size());
  /// test that all 2 deregister tx are in the block
  CHECK_EQ(deregister_count, 2);

  return true;

}