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

#include <boost/algorithm/string/predicate.hpp>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <chrono>
#include <random>
#include <thread>

#include "gtest/gtest.h"

#include "epee/string_tools.h"
#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/lmdb/db_lmdb.h"
#include "blockchain_db/sqlite/blockchain_sqlite.h"
#include "checkpoints/checkpoints.h"
#include "cryptonote_core/service_node_list.h"
#include "cryptonote_core/uptime_proof.h"

#include <sodium/crypto_sign.h>
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "common/fs.h"
#include "logging/oxen_logger.h"
#include "ringct/rctOps.h"

#include "random_path.h"

using namespace cryptonote;

#define ASSERT_HASH_EQ(a,b) ASSERT_EQ(tools::hex_guts(a), tools::hex_guts(b))

namespace {  // anonymous namespace
  
const std::vector<std::string> t_blocks =
  {
    "0100d5adc49a053b8818b2b6023cd2d532c6774e164a8fcacd603651cb3ea0cb7f9340b28ec016b4bc4ca301aa0101ff6e08acbb2702eab03067870349139bee7eab2ca2e030a6bb73d4f68ab6a3b6ca937214054cdac0843d028bbe23b57ea9bae53f12da93bb57bf8a2e40598d9fccd10c2921576e987d93cd80b4891302468738e391f07c4f2b356f7957160968e0bfef6e907c3cee2d8c23cbf04b089680c6868f01025a0f41f063e195a966051e3a29e17130a9ce97d48f55285b9bb04bdd55a09ae78088aca3cf0202d0f26169290450fe17e08974789c3458910b4db18361cdc564f8f2d0bdd2cf568090cad2c60e02d6f3483ec45505cc3be841046c7a12bf953ac973939bc7b727e54258e1881d4d80e08d84ddcb0102dae6dfb16d3e28aaaf43e00170b90606b36f35f38f8a3dceb5ee18199dd8f17c80c0caf384a30202385d7e57a4daba4cdd9e550a92dcc188838386e7581f13f09de796cbed4716a42101c052492a077abf41996b50c1b2e67fd7288bcd8c55cdc657b4e22d0804371f6901beb76a82ea17400cd6d7f595f70e1667d2018ed8f5a78d1ce07484222618c3cd"
  , "0100f9adc49a057d3113f562eac36f14afa08c22ae20bbbf8cffa31a4466d24850732cb96f80e9762365ee01ab0101ff6f08cc953502be76deb845c431f2ed9a4862457654b914003693b8cd672abc935f0d97b16380c08db7010291819f2873e3efbae65ecd5a736f5e8a26318b591c21e39a03fb536520ac63ba80dac40902439a10fde02e39e48e0b31e57cc084a07eedbefb8cbea0143aedd0442b189caa80c6868f010227b84449de4cd7a48cbdce8974baf0b6646e03384e32055e705c243a86bef8a58088aca3cf0202fa7bd15e4e7e884307ab130bb9d50e33c5fcea6546042a26f948efd5952459ee8090cad2c60e028695583dbb8f8faab87e3ef3f88fa827db097bbf51761d91924f5c5b74c6631780e08d84ddcb010279d2f247b54690e3b491e488acff16014a825fd740c23988a25df7c4670c1f2580c0caf384a302022599dfa3f8788b66295051d85937816e1c320cdb347a0fba5219e3fe60c83b2421010576509c5672025d28fd5d3f38efce24e1f9aaf65dd3056b2504e6e2b7f19f7800"
  };

const std::vector<size_t> t_sizes =
  {
    1122
  , 347
  };

const std::vector<difficulty_type> t_diffs =
  {
    4003674
  , 4051757
  };

const std::vector<uint64_t> t_coins =
  {
    1952630229575370
  , 1970220553446486
  };

const std::vector<std::vector<std::string>> t_transactions =
  {
    {
      "0100010280e08d84ddcb0106010401110701f254220bb50d901a5523eaed438af5d43f8c6d0e54ba0632eb539884f6b7c02008c0a8a50402f9c7cf807ae74e56f4ec84db2bd93cfb02c2249b38e306f5b54b6e05d00d543b8095f52a02b6abb84e00f47f0a72e37b6b29392d906a38468404c57db3dbc5e8dd306a27a880d293ad0302cfc40a86723e7d459e90e45d47818dc0e81a1f451ace5137a4af8110a89a35ea80b4c4c321026b19c796338607d5a2c1ba240a167134142d72d1640ef07902da64fed0b10cfc8088aca3cf02021f6f655254fee84161118b32e7b6f8c31de5eb88aa00c29a8f57c0d1f95a24dd80d0b8e1981a023321af593163cea2ae37168ab926efd87f195756e3b723e886bdb7e618f751c480a094a58d1d0295ed2b08d1cf44482ae0060a5dcc4b7d810a85dea8c62e274f73862f3d59f8ed80a0e5b9c2910102dc50f2f28d7ceecd9a1147f7106c8d5b4e08b2ec77150f52dd7130ee4f5f50d42101d34f90ac861d0ee9fe3891656a234ea86a8a93bf51a237db65baa00d3f4aa196a9e1d89bc06b40e94ea9a26059efc7ba5b2de7ef7c139831ca62f3fe0bb252008f8c7ee810d3e1e06313edf2db362fc39431755779466b635f12f9f32e44470a3e85e08a28fcd90633efc94aa4ae39153dfaf661089d045521343a3d63e8da08d7916753c66aaebd4eefcfe8e58e5b3d266b752c9ca110749fa33fce7c44270386fcf2bed4f03dd5dadb2dc1fd4c505419f8217b9eaec07521f0d8963e104603c926745039cf38d31de6ed95ace8e8a451f5a36f818c151f517546d55ac0f500e54d07b30ea7452f2e93fa4f60bdb30d71a0a97f97eb121e662006780fbf69002228224a96bff37893d47ec3707b17383906c0cd7d9e7412b3e6c8ccf1419b093c06c26f96e3453b424713cdc5c9575f81cda4e157052df11f4c40809edf420f88a3dd1f7909bbf77c8b184a933389094a88e480e900bcdbf6d1824742ee520fc0032e7d892a2b099b8c6edfd1123ce58a34458ee20cad676a7f7cfd80a28f0cb0888af88838310db372986bdcf9bfcae2324480ca7360d22bff21fb569a530e"
    }
  , {
    }
  };

// if the return type (std::string for now) of block_to_blob ever changes
// from std::string, this might break.
bool compare_blocks(const block& a, const block& b)
{
  auto hash_a = tools::hex_guts(get_block_hash(a));
  auto hash_b = tools::hex_guts(get_block_hash(b));

  return hash_a == hash_b;
}

/*
void print_block(const block& blk, const std::string& prefix = "")
{
  std::cerr << prefix << ": " << std::endl
            << "\thash - " << tools::hex_guts(get_block_hash(blk)) << std::endl
            << "\tparent - " << tools::hex_guts(blk.prev_id) << std::endl
            << "\ttimestamp - " << blk.timestamp << std::endl
  ;
}

// if the return type (std::string for now) of tx_to_blob ever changes
// from std::string, this might break.
bool compare_txs(const transaction& a, const transaction& b)
{
  auto ab = tx_to_blob(a);
  auto bb = tx_to_blob(b);

  return ab == bb;
}
*/

// convert hex string to string that has values based on that hex
// thankfully should automatically ignore null-terminator.
std::string h2b(const std::string& s)
{
  bool upper = true;
  std::string result;
  unsigned char val = 0;
  for (char c : s)
  {
    if (upper)
    {
      val = 0;
      if (c <= 'f' && c >= 'a')
      {
        val = ((c - 'a') + 10) << 4;
      }
      else
      {
        val = (c - '0') << 4;
      }
    }
    else
    {
      if (c <= 'f' && c >= 'a')
      {
        val |= (c - 'a') + 10;
      }
      else
      {
        val |= c - '0';
      }
      result += (char)val;
    }
    upper = !upper;
  }
  return result;
}

// What each backend's open() takes, given the directory a test puts its database in: LMDB opens a
// directory, SQLite the database file.
template <typename T>
fs::path db_open_path(const fs::path& dir) { return dir; }
template <>
fs::path db_open_path<BlockchainSQLite>(const fs::path& dir) { return dir / SQLITE_DB_FILENAME; }

template <typename T>
class BlockchainDBTest : public testing::Test
{
protected:
  BlockchainDBTest() : m_db(new T())
  {
    auto logcat = oxen::log::Cat("db_test");
    for (auto& i : t_blocks)
    {
      block bl;
      std::string bd = h2b(i);
      CHECK_AND_ASSERT_THROW_MES(parse_and_validate_block_from_blob(bd, bl), "Invalid block");
      m_blocks.push_back(std::make_pair(bl, bd));
    }
    for (auto& i : t_transactions)
    {
      std::vector<std::pair<transaction, std::string>> txs;
      for (auto& j : i)
      {
        transaction tx;
        std::string bd = h2b(j);
        CHECK_AND_ASSERT_THROW_MES(parse_and_validate_tx_from_blob(bd, tx), "Invalid transaction");
        txs.push_back(std::make_pair(tx, bd));
      }
      m_txs.push_back(txs);
    }
  }

  ~BlockchainDBTest() {
    delete m_db;
    remove_files();
  }

  BlockchainDB* m_db;
  fs::path m_prefix;
  std::vector<std::pair<block, std::string>> m_blocks;
  std::vector<std::vector<std::pair<transaction, std::string>>> m_txs;
  std::vector<fs::path> m_filenames;

  void get_filenames()
  {
    m_filenames = m_db->get_filenames();
    for (auto& f : m_filenames)
    {
      std::cerr << "File created by test: " << f << std::endl;
    }
  }

  void remove_files()
  {
    // remove each file the db created, making sure it starts with fname.
    for (auto& f : m_filenames)
    {
      if (f.u8string().starts_with(m_prefix.u8string()))
      {
        fs::remove(f);
      }
      else
      {
        std::cerr << "File created by test not to be removed (for safety): " << f << std::endl;
      }
    }

    // remove directory if it still exists
    fs::remove_all(m_prefix);
  }

  void set_prefix(std::string_view prefix)
  {
    m_prefix = tools::utf8_path(prefix);
  }

  // Opens the database in a new temporary directory.
  void open_db()
  {
    set_prefix(random_tmp_file().string());
    m_db->open(db_open_path<T>(m_prefix), network_type::FAKECHAIN);
    get_filenames();
  }

  void reopen_db()
  {
    m_db->close();
    m_db->open(db_open_path<T>(m_prefix), network_type::FAKECHAIN);
  }

  void add_test_block(size_t i)
  {
    m_db->add_block(m_blocks[i], t_sizes[i], t_sizes[i], t_diffs[i], t_coins[i], m_txs[i]);
  }

  // Opens the database and adds both test blocks to it.
  void open_with_blocks()
  {
    open_db();
    db_wtxn_guard guard{*m_db};
    add_test_block(0);
    add_test_block(1);
  }

  // Extends the chain with copies of the second test block (which has only a miner tx), one per
  // given timestamp, each with its own miner tx; the database checks neither proof of work nor
  // signatures, so this gives tests a longer chain than the two real test blocks.
  void add_synthetic_blocks(const std::vector<uint64_t>& timestamps)
  {
    db_wtxn_guard guard{*m_db};
    for (auto timestamp : timestamps)
    {
      block b = m_blocks[1].first;
      const uint64_t height = m_db->height();
      b.prev_id = m_db->top_block_hash();
      b.timestamp = timestamp;
      b.miner_tx->vin[0] = txin_gen{height};
      b.miner_tx->unprunable_size = 0;
      b.miner_tx->invalidate_hashes();
      b.invalidate_hashes();
      m_db->add_block({b, block_to_blob(b)}, t_sizes[1], t_sizes[1], t_diffs[1] + height, t_coins[1], {});
    }
  }
};

using testing::Types;

typedef Types<BlockchainLMDB, BlockchainSQLite> implementations;

TYPED_TEST_CASE(BlockchainDBTest, implementations);

TYPED_TEST(BlockchainDBTest, OpenAndClose)
{
  fs::path tempPath = random_tmp_file();
  std::string dirPath = tempPath.string();

  this->set_prefix(dirPath);

  // make sure open does not throw
  ASSERT_NO_THROW(this->m_db->open(db_open_path<TypeParam>(dirPath), network_type::FAKECHAIN));
  this->get_filenames();

  // make sure open when already open DOES throw
  ASSERT_THROW(this->m_db->open(db_open_path<TypeParam>(dirPath), network_type::FAKECHAIN), DB_OPEN_FAILURE);

  ASSERT_NO_THROW(this->m_db->close());
}

TYPED_TEST(BlockchainDBTest, AddBlock)
{

  fs::path tempPath = random_tmp_file();
  std::string dirPath = tempPath.string();

  this->set_prefix(dirPath);

  // make sure open does not throw
  ASSERT_NO_THROW(this->m_db->open(db_open_path<TypeParam>(dirPath), network_type::FAKECHAIN));
  this->get_filenames();

  db_wtxn_guard guard{*this->m_db};

  // adding a block with no parent in the blockchain should throw.
  // note: this shouldn't be possible, but is a good (and cheap) failsafe.
  //
  // TODO: need at least one more block to make this reasonable, as the
  // BlockchainDB implementation should not check for parent if
  // no blocks have been added yet (because genesis has no parent).
  //ASSERT_THROW(this->m_db->add_block(this->m_blocks[1], t_sizes[1], t_sizes[1], t_diffs[1], t_coins[1], this->m_txs[1]), BLOCK_PARENT_DNE);

  ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[0], t_sizes[0], t_sizes[0], t_diffs[0], t_coins[0], this->m_txs[0]));
  ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[1], t_sizes[1], t_sizes[1], t_diffs[1], t_coins[1], this->m_txs[1]));

  block b;
  ASSERT_TRUE(this->m_db->block_exists(get_block_hash(this->m_blocks[0].first)));
  ASSERT_NO_THROW(b = this->m_db->get_block(get_block_hash(this->m_blocks[0].first)));

  ASSERT_TRUE(compare_blocks(this->m_blocks[0].first, b));

  ASSERT_NO_THROW(b = this->m_db->get_block_from_height(0));

  ASSERT_TRUE(compare_blocks(this->m_blocks[0].first, b));

  // assert that we can't add the same block twice
  ASSERT_THROW(this->m_db->add_block(this->m_blocks[0], t_sizes[0], t_sizes[0], t_diffs[0], t_coins[0], this->m_txs[0]), TX_EXISTS);

  for (auto& h : this->m_blocks[0].first.tx_hashes)
  {
    transaction tx;
    ASSERT_TRUE(this->m_db->tx_exists(h));
    ASSERT_NO_THROW(tx = this->m_db->get_tx(h));

    ASSERT_HASH_EQ(h, get_transaction_hash(tx));
  }
}

TYPED_TEST(BlockchainDBTest, RetrieveBlockData)
{
  fs::path tempPath = random_tmp_file();
  std::string dirPath = tempPath.string();

  this->set_prefix(dirPath);

  // make sure open does not throw
  ASSERT_NO_THROW(this->m_db->open(db_open_path<TypeParam>(dirPath), network_type::FAKECHAIN));
  this->get_filenames();

  db_wtxn_guard guard{*this->m_db};

  ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[0], t_sizes[0], t_sizes[0],  t_diffs[0], t_coins[0], this->m_txs[0]));

  ASSERT_EQ(t_sizes[0], this->m_db->get_block_weight(0));
  ASSERT_EQ(t_diffs[0], this->m_db->get_block_cumulative_difficulty(0));
  ASSERT_EQ(t_diffs[0], this->m_db->get_block_difficulty(0));
  ASSERT_EQ(t_coins[0], this->m_db->get_block_already_generated_coins(0));

  ASSERT_NO_THROW(this->m_db->add_block(this->m_blocks[1], t_sizes[1], t_sizes[1], t_diffs[1], t_coins[1], this->m_txs[1]));
  ASSERT_EQ(t_diffs[1] - t_diffs[0], this->m_db->get_block_difficulty(1));

  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[0].first), this->m_db->get_block_hash_from_height(0));

  std::vector<block> blks;
  ASSERT_NO_THROW(blks = this->m_db->get_blocks_range(0, 1));
  ASSERT_EQ(2, blks.size());
  
  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[0].first), get_block_hash(blks[0]));
  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[1].first), get_block_hash(blks[1]));

  std::vector<crypto::hash> hashes;
  ASSERT_NO_THROW(hashes = this->m_db->get_hashes_range(0, 1));
  ASSERT_EQ(2, hashes.size());

  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[0].first), hashes[0]);
  ASSERT_HASH_EQ(get_block_hash(this->m_blocks[1].first), hashes[1]);
}

crypto::hash missing_hash()
{
  return crypto::cn_fast_hash("not in the db", 13);
}

TYPED_TEST(BlockchainDBTest, PopBlock)
{
  this->open_db();
  auto& db = *this->m_db;
  const auto& blk0 = this->m_blocks[0].first;
  const auto& blk1 = this->m_blocks[1].first;
  const auto& tx0 = this->m_txs[0][0].first;

  {
    db_wtxn_guard guard{db};
    this->add_test_block(0);
  }

  std::map<uint64_t, uint64_t> outputs_after_0;
  for (const auto* tx : {&*blk0.miner_tx, &tx0, &*blk1.miner_tx})
    for (const auto& out : tx->vout)
      outputs_after_0[out.amount] = db.get_num_outputs(out.amount);
  const uint64_t txs_after_0 = db.get_tx_count();
  ASSERT_EQ(txs_after_0, 2);

  {
    db_wtxn_guard guard{db};
    this->add_test_block(1);
  }
  ASSERT_EQ(db.height(), 2);
  ASSERT_EQ(db.get_tx_count(), 3);

  std::vector<crypto::key_image> key_images;
  for (const auto& in : tx0.vin)
    key_images.push_back(std::get<txin_to_key>(in).k_image);
  ASSERT_FALSE(key_images.empty());
  for (const auto& ki : key_images)
    ASSERT_TRUE(db.has_key_image(ki));

  block popped;
  std::vector<transaction> txs;
  ASSERT_NO_THROW(db.pop_block(popped, txs));
  EXPECT_TRUE(compare_blocks(popped, blk1));
  EXPECT_TRUE(txs.empty());
  EXPECT_EQ(db.height(), 1);
  EXPECT_EQ(db.get_tx_count(), txs_after_0);
  EXPECT_FALSE(db.tx_exists(get_transaction_hash(*blk1.miner_tx)));
  EXPECT_TRUE(db.tx_exists(blk0.tx_hashes[0]));
  for (const auto& [amount, count] : outputs_after_0)
    EXPECT_EQ(db.get_num_outputs(amount), count);
  for (const auto& ki : key_images)
    EXPECT_TRUE(db.has_key_image(ki));

  txs.clear();
  ASSERT_NO_THROW(db.pop_block(popped, txs));
  EXPECT_TRUE(compare_blocks(popped, blk0));
  ASSERT_EQ(txs.size(), 1);
  ASSERT_HASH_EQ(get_transaction_hash(txs[0]), blk0.tx_hashes[0]);
  EXPECT_EQ(db.height(), 0);
  EXPECT_EQ(db.get_tx_count(), 0);
  EXPECT_FALSE(db.tx_exists(blk0.tx_hashes[0]));
  EXPECT_FALSE(db.tx_exists(get_transaction_hash(*blk0.miner_tx)));
  for (const auto& [amount, count] : outputs_after_0)
    EXPECT_EQ(db.get_num_outputs(amount), 0);
  for (const auto& ki : key_images)
    EXPECT_FALSE(db.has_key_image(ki));

  EXPECT_THROW(db.pop_block(popped, txs), BLOCK_DNE);

  // Popping must leave the ids dense, so that adding the blocks again gives the same ids.
  {
    db_wtxn_guard guard{db};
    this->add_test_block(0);
    this->add_test_block(1);
  }
  EXPECT_EQ(db.height(), 2);
  EXPECT_EQ(db.get_tx_count(), 3);
  uint64_t tx_id;
  ASSERT_TRUE(db.tx_exists(blk0.tx_hashes[0], tx_id));
  EXPECT_EQ(tx_id, 1);
}

TYPED_TEST(BlockchainDBTest, GetOutputKey)
{
  this->open_with_blocks();
  auto& db = *this->m_db;
  const auto& miner0 = *this->m_blocks[0].first.miner_tx;

  const uint64_t a = miner0.vout[0].amount;
  const auto& key_a0 = std::get<txout_to_key>(miner0.vout[0].target).key;
  const uint64_t n = db.get_num_outputs(a);
  ASSERT_GE(n, 1);

  output_data_t out = db.get_output_key(a, 0);
  ASSERT_HASH_EQ(out.pubkey, key_a0);
  EXPECT_EQ(out.height, 0);
  EXPECT_EQ(out.commitment, rct::zeroCommit(a));
  EXPECT_THROW(db.get_output_key(a, n), OUTPUT_DNE);
  EXPECT_EQ(db.get_num_outputs(123456789), 0);

  std::vector<output_data_t> outs;
  std::vector<uint64_t> amounts{a};
  ASSERT_NO_THROW(db.get_output_key(amounts, {0, 0, n - 1}, outs));
  ASSERT_EQ(outs.size(), 3);
  ASSERT_HASH_EQ(outs[0].pubkey, key_a0);
  ASSERT_HASH_EQ(outs[1].pubkey, key_a0);
  ASSERT_HASH_EQ(outs[2].pubkey, db.get_output_key(a, n - 1).pubkey);

  EXPECT_THROW(db.get_output_key(amounts, {0, n}, outs), OUTPUT_DNE);
  ASSERT_NO_THROW(db.get_output_key(amounts, {0, n, 0}, outs, true));
  ASSERT_EQ(outs.size(), 1);
  ASSERT_HASH_EQ(outs[0].pubkey, key_a0);

  // One amount per offset
  const tx_out* other = nullptr;
  for (const auto& vout : miner0.vout)
    if (vout.amount != a)
      other = &vout;
  ASSERT_NE(other, nullptr);
  const uint64_t b = other->amount;
  std::vector<uint64_t> per_offset{b, a, b};
  ASSERT_NO_THROW(db.get_output_key(per_offset, {0, 0, 0}, outs));
  ASSERT_EQ(outs.size(), 3);
  ASSERT_HASH_EQ(outs[0].pubkey, db.get_output_key(b, 0).pubkey);
  ASSERT_HASH_EQ(outs[1].pubkey, key_a0);
  ASSERT_HASH_EQ(outs[2].pubkey, db.get_output_key(b, 0).pubkey);
  EXPECT_THROW(db.get_output_key(per_offset, {0, 0}, outs), DB_ERROR);

  auto [tx_hash, local_index] = db.get_output_tx_and_index(a, 0);
  ASSERT_HASH_EQ(tx_hash, get_transaction_hash(miner0));
  EXPECT_EQ(local_index, 0);
  EXPECT_THROW(db.get_output_tx_and_index(a, n), OUTPUT_DNE);

  auto indices = db.get_tx_amount_output_indices(0, 3);
  ASSERT_EQ(indices.size(), 3);
  EXPECT_EQ(indices[0].size(), miner0.vout.size());
  EXPECT_EQ(indices[1].size(), this->m_txs[0][0].first.vout.size());
  EXPECT_EQ(indices[2].size(), this->m_blocks[1].first.miner_tx->vout.size());
  EXPECT_EQ(indices[0][0], 0);
}

TYPED_TEST(BlockchainDBTest, TxLookups)
{
  this->open_with_blocks();
  auto& db = *this->m_db;
  const auto& blk0 = this->m_blocks[0].first;
  const auto miner0_hash = get_transaction_hash(*blk0.miner_tx);
  const auto miner1_hash = get_transaction_hash(*this->m_blocks[1].first.miner_tx);

  EXPECT_EQ(
      db.get_tx_block_heights({blk0.tx_hashes[0], miner1_hash, missing_hash()}),
      (std::vector<uint64_t>{0, 1, std::numeric_limits<uint64_t>::max()}));

  // The test transactions predate RingCT, so have no prunable hash.
  crypto::hash prunable_hash;
  EXPECT_FALSE(db.get_prunable_tx_hash(blk0.tx_hashes[0], prunable_hash));
  EXPECT_FALSE(db.get_prunable_tx_hash(missing_hash(), prunable_hash));

  std::vector<std::string> blobs;
  ASSERT_TRUE(db.get_pruned_tx_blobs_from(miner0_hash, 3, blobs));
  ASSERT_EQ(blobs.size(), 3);
  std::string pruned;
  ASSERT_TRUE(db.get_pruned_tx_blob(blk0.tx_hashes[0], pruned));
  EXPECT_EQ(blobs[1], pruned);

  blobs.clear();
  EXPECT_FALSE(db.get_pruned_tx_blobs_from(miner0_hash, 4, blobs));
  blobs.clear();
  EXPECT_FALSE(db.get_pruned_tx_blobs_from(missing_hash(), 1, blobs));
  EXPECT_TRUE(blobs.empty());
  EXPECT_TRUE(db.get_pruned_tx_blobs_from(missing_hash(), 0, blobs));

  std::string full;
  ASSERT_TRUE(db.get_tx_blob(blk0.tx_hashes[0], full));
  EXPECT_EQ(full, this->m_txs[0][0].second);
  EXPECT_FALSE(db.get_tx_blob(missing_hash(), full));
}

TYPED_TEST(BlockchainDBTest, BlockWeights)
{
  this->open_with_blocks();
  auto& db = *this->m_db;

  EXPECT_EQ(db.get_block_weights(0, 2), (std::vector<uint64_t>{t_sizes[0], t_sizes[1]}));
  EXPECT_EQ(db.get_block_weights(1, 5), (std::vector<uint64_t>{t_sizes[1]}));
  EXPECT_EQ(db.get_long_term_block_weights(0, 1), (std::vector<uint64_t>{t_sizes[0]}));
  EXPECT_THROW(db.get_block_weights(2, 1), DB_ERROR);
  EXPECT_THROW(db.get_long_term_block_weights(2, 1), DB_ERROR);

  EXPECT_EQ(db.get_block_cumulative_rct_outputs({0, 1}), (std::vector<uint64_t>{0, 0}));
  EXPECT_THROW(db.get_block_cumulative_rct_outputs({0, 2}), BLOCK_DNE);

  uint64_t top;
  ASSERT_HASH_EQ(db.top_block_hash(&top), get_block_hash(this->m_blocks[1].first));
  EXPECT_EQ(top, 1);

  EXPECT_EQ(db.get_blocks_range(1, 1).size(), 1);
  EXPECT_TRUE(db.get_blocks_range(1, 0).empty());
  EXPECT_THROW(db.get_blocks_range(1, 3), BLOCK_DNE);
  EXPECT_EQ(db.get_hashes_range(0, 1).size(), 2);
  EXPECT_THROW(db.get_hashes_range(0, 2), BLOCK_DNE);

  const auto& tx0 = this->m_txs[0][0];
  auto txs = db.get_tx_list({get_transaction_hash(tx0.first)});
  ASSERT_EQ(txs.size(), 1);
  ASSERT_HASH_EQ(get_transaction_hash(txs[0]), get_transaction_hash(tx0.first));
  EXPECT_THROW(db.get_tx_list({missing_hash()}), TX_DNE);
}

TYPED_TEST(BlockchainDBTest, OutputHistogramAndDistribution)
{
  this->open_with_blocks();
  auto& db = *this->m_db;
  const auto& blk0 = this->m_blocks[0].first;
  const auto& blk1 = this->m_blocks[1].first;

  // Heights 2-21, with an out-of-order timestamp at height 8.
  std::map<uint64_t, uint64_t> timestamps;
  std::vector<uint64_t> synthetic;
  for (uint64_t h = 2; h < 22; h++)
  {
    timestamps[h] = h == 8 ? 900 : 1000 + 100 * h;
    synthetic.push_back(timestamps[h]);
  }
  this->add_synthetic_blocks(synthetic);
  ASSERT_EQ(db.height(), 22);

  // Expected counts per amount and height, from the blocks' outputs.
  std::map<uint64_t, std::map<uint64_t, uint64_t>> counts;
  auto count = [&](const transaction& tx, uint64_t height) {
    for (const auto& out : tx.vout)
      counts[out.amount][height]++;
  };
  count(*blk0.miner_tx, 0);
  count(this->m_txs[0][0].first, 0);
  for (uint64_t h = 1; h < 22; h++)
    count(*blk1.miner_tx, h);
  const uint64_t a = blk1.miner_tx->vout[0].amount;
  auto& a_counts = counts[a];
  auto total = [](const std::map<uint64_t, uint64_t>& c, uint64_t max_height) {
    uint64_t n = 0;
    for (auto& [h, k] : c)
      if (h <= max_height)
        n += k;
    return n;
  };

  using histo = std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>>;
  const uint64_t all_a = total(a_counts, 100);
  // Spendable once height + 10 <= 22
  const uint64_t unlocked_a = total(a_counts, 12);
  EXPECT_EQ(db.get_output_histogram({a}, false, 0, 0), (histo{{a, {all_a, 0, 0}}}));
  EXPECT_EQ(db.get_output_histogram({a}, true, 0, 0), (histo{{a, {all_a, unlocked_a, 0}}}));
  // Recent: the unlocked outputs from height 12 down, stopping at height 8's old timestamp.
  const uint64_t recent_a = a_counts[12] + a_counts[11] + a_counts[10] + a_counts[9];
  EXPECT_EQ(
      db.get_output_histogram({a}, false, 1500, 0), (histo{{a, {all_a, unlocked_a, recent_a}}}));
  EXPECT_EQ(db.get_output_histogram({123456789}, false, 0, 0), (histo{{123456789, {0, 0, 0}}}));
  EXPECT_EQ(db.get_output_histogram({123456789}, false, 0, 1), histo{});

  histo all_amounts;
  for (auto& [amount, c] : counts)
    if (auto n = total(c, 100); n >= 25)
      all_amounts[amount] = {n, 0, 0};
  EXPECT_EQ(db.get_output_histogram({}, false, 0, 25), all_amounts);
  EXPECT_EQ(db.get_output_histogram({}, false, 0, 0).size(), counts.size());

  // Distribution from height 5 to 9: everything below 5 is folded into the first entry, and (as
  // LMDB has always done) the first output above height 9 is included.
  std::vector<uint64_t> dist;
  uint64_t base = 99;
  ASSERT_TRUE(db.get_output_distribution(a, 5, 9, dist, base));
  EXPECT_EQ(base, 0);
  std::vector<uint64_t> expected(22 - 5, 0);
  for (uint64_t h = 0; h <= 9; h++)
    expected[h < 5 ? 0 : h - 5] += a_counts[h];
  expected[10 - 5] += 1;
  for (size_t i = 1; i < expected.size(); i++)
    expected[i] += expected[i - 1];
  EXPECT_EQ(dist, expected);

  ASSERT_TRUE(db.get_output_distribution(a, 0, 0, dist, base));
  std::vector<uint64_t> cumulative;
  uint64_t sum = 0;
  for (uint64_t h = 0; h < 22; h++)
    cumulative.push_back(sum += a_counts[h]);
  EXPECT_EQ(dist, cumulative);

  EXPECT_FALSE(db.get_output_distribution(a, 22, 0, dist, base));
}

TYPED_TEST(BlockchainDBTest, ReadTransactions)
{
  this->open_db();
  auto& db = *this->m_db;

  {
    db_wtxn_guard guard{db};
    // The writer reads within its write transaction, so it gets no read transaction of its own...
    EXPECT_FALSE(db.block_rtxn_start());
    this->add_test_block(0);
    // ...and sees what it has not committed yet, which other threads do not.
    EXPECT_EQ(db.height(), 1);

    bool started = false;
    uint64_t other_height = 99;
    std::thread reader{[&] {
      started = db.block_rtxn_start();
      other_height = db.height();
      if (started)
        db.block_rtxn_stop();
    }};
    reader.join();
    EXPECT_TRUE(started);
    EXPECT_EQ(other_height, 0);
  }
  EXPECT_EQ(db.height(), 1);

  ASSERT_TRUE(db.block_rtxn_start());
  EXPECT_FALSE(db.block_rtxn_start());
  EXPECT_EQ(db.height(), 1);
  db.block_rtxn_stop();
}

TYPED_TEST(BlockchainDBTest, Batch)
{
  this->open_db();
  auto& db = *this->m_db;
  const uint64_t a = this->m_blocks[0].first.miner_tx->vout[0].amount;

  ASSERT_TRUE(db.batch_start());
  EXPECT_FALSE(db.batch_start());
  {
    // A block transaction inside a batch is part of the batch.
    db_wtxn_guard guard{db};
    this->add_test_block(0);
  }
  this->add_test_block(1);
  EXPECT_EQ(db.height(), 2);
  db.batch_abort();

  EXPECT_EQ(db.height(), 0);
  EXPECT_EQ(db.get_tx_count(), 0);
  EXPECT_EQ(db.get_num_outputs(a), 0);
  EXPECT_FALSE(db.tx_exists(this->m_blocks[0].first.tx_hashes[0]));

  ASSERT_TRUE(db.batch_start());
  this->add_test_block(0);
  this->add_test_block(1);
  db.batch_stop();
  EXPECT_EQ(db.height(), 2);
  EXPECT_EQ(db.get_tx_count(), 3);
}

checkpoint_t make_checkpoint(uint64_t height, size_t num_signatures)
{
  checkpoint_t cp{};
  cp.height = height;
  cp.block_hash = crypto::cn_fast_hash(&height, sizeof(height));
  cp.type = num_signatures ? checkpoint_type::service_node : checkpoint_type::hardcoded;
  for (size_t i = 0; i < num_signatures; i++)
  {
    crypto::signature sig;
    std::memset(&sig, static_cast<int>(height + i), sizeof(sig));
    cp.signatures.emplace_back(static_cast<uint16_t>(2 * i + 1), sig);
  }
  return cp;
}

void expect_checkpoint_eq(const checkpoint_t& a, const checkpoint_t& b)
{
  EXPECT_EQ(a.height, b.height);
  EXPECT_EQ(a.type, b.type);
  ASSERT_HASH_EQ(a.block_hash, b.block_hash);
  ASSERT_EQ(a.signatures.size(), b.signatures.size());
  for (size_t i = 0; i < a.signatures.size(); i++)
  {
    EXPECT_EQ(a.signatures[i].voter_index, b.signatures[i].voter_index);
    ASSERT_HASH_EQ(a.signatures[i].signature, b.signatures[i].signature);
  }
}

std::vector<uint64_t> heights_of(const std::vector<checkpoint_t>& cps)
{
  std::vector<uint64_t> heights;
  for (auto& cp : cps)
    heights.push_back(cp.height);
  return heights;
}

TYPED_TEST(BlockchainDBTest, Checkpoints)
{
  this->open_db();
  auto& db = *this->m_db;
  using v = std::vector<uint64_t>;

  checkpoint_t cp;
  EXPECT_FALSE(db.get_top_checkpoint(cp));
  EXPECT_TRUE(db.get_checkpoints_range(0, 100).empty());

  const std::vector<checkpoint_t> cps{
      make_checkpoint(4, 0), make_checkpoint(8, 3), make_checkpoint(12, 2),
      make_checkpoint(16, 5), make_checkpoint(20, 0)};
  {
    db_wtxn_guard guard{db};
    for (auto& c : cps)
      db.update_block_checkpoint(c);
  }

  ASSERT_TRUE(db.get_top_checkpoint(cp));
  expect_checkpoint_eq(cp, cps[4]);
  ASSERT_TRUE(db.get_block_checkpoint(8, cp));
  expect_checkpoint_eq(cp, cps[1]);
  EXPECT_FALSE(db.get_block_checkpoint(9, cp));

  auto all = db.get_checkpoints_range(4, 20);
  ASSERT_EQ(all.size(), cps.size());
  for (size_t i = 0; i < cps.size(); i++)
    expect_checkpoint_eq(all[i], cps[i]);

  EXPECT_EQ(heights_of(db.get_checkpoints_range(20, 4)), (v{20, 16, 12, 8, 4}));
  EXPECT_EQ(heights_of(db.get_checkpoints_range(5, 13)), (v{8, 12}));
  EXPECT_EQ(heights_of(db.get_checkpoints_range(13, 5)), (v{12, 8}));
  EXPECT_EQ(heights_of(db.get_checkpoints_range(8, 8)), (v{8}));
  EXPECT_EQ(heights_of(db.get_checkpoints_range(5, 7)), (v{}));
  EXPECT_EQ(heights_of(db.get_checkpoints_range(7, 5)), (v{}));
  // Clamped to the stored checkpoints' heights
  EXPECT_EQ(heights_of(db.get_checkpoints_range(0, 100)), (v{4, 8, 12, 16, 20}));
  EXPECT_EQ(heights_of(db.get_checkpoints_range(100, 0)), (v{20, 16, 12, 8, 4}));
  EXPECT_EQ(heights_of(db.get_checkpoints_range(100, 100)), (v{20}));
  EXPECT_EQ(heights_of(db.get_checkpoints_range(0, 0)), (v{4}));
  EXPECT_EQ(heights_of(db.get_checkpoints_range(0, 6)), (v{4}));
  // Limited
  EXPECT_EQ(heights_of(db.get_checkpoints_range(0, 100, 2)), (v{4, 8}));
  EXPECT_EQ(heights_of(db.get_checkpoints_range(100, 0, 2)), (v{20, 16}));
  EXPECT_EQ(heights_of(db.get_checkpoints_range(15, 0, 1)), (v{12}));
  EXPECT_EQ(heights_of(db.get_checkpoints_range(9, 100, 3)), (v{12, 16, 20}));

  // Replacing a checkpoint replaces its signatures; removing a missing one is not an error.
  {
    db_wtxn_guard guard{db};
    auto replaced = make_checkpoint(8, 1);
    db.update_block_checkpoint(replaced);
    db.remove_block_checkpoint(16);
    db.remove_block_checkpoint(17);
  }
  ASSERT_TRUE(db.get_block_checkpoint(8, cp));
  expect_checkpoint_eq(cp, make_checkpoint(8, 1));
  EXPECT_FALSE(db.get_block_checkpoint(16, cp));
  EXPECT_EQ(heights_of(db.get_checkpoints_range(0, 100)), (v{4, 8, 12, 20}));

  // A checkpoint signed by a full quorum
  const auto full = make_checkpoint(24, service_nodes::CHECKPOINT_QUORUM_SIZE);
  {
    db_wtxn_guard guard{db};
    db.update_block_checkpoint(full);
  }
  this->reopen_db();
  ASSERT_TRUE(db.get_top_checkpoint(cp));
  expect_checkpoint_eq(cp, full);
  EXPECT_EQ(cp.signatures.size(), service_nodes::CHECKPOINT_QUORUM_SIZE);
}

TYPED_TEST(BlockchainDBTest, MaxBlockSize)
{
  this->open_db();
  auto& db = *this->m_db;
  EXPECT_EQ(db.get_max_block_size(), std::numeric_limits<uint64_t>::max());
  {
    db_wtxn_guard guard{db};
    db.add_max_block_size(100);
    EXPECT_EQ(db.get_max_block_size(), 100);
    db.add_max_block_size(50);
    EXPECT_EQ(db.get_max_block_size(), 100);
    db.add_max_block_size(200);
  }
  EXPECT_EQ(db.get_max_block_size(), 200);
}

TYPED_TEST(BlockchainDBTest, Txpool)
{
  this->open_db();
  auto& db = *this->m_db;

  txpool_tx_meta_t meta{};
  meta.max_used_block_id = crypto::cn_fast_hash("max used", 8);
  meta.last_failed_id = crypto::cn_fast_hash("last failed", 11);
  meta.weight = 1234;
  meta.fee = 5678;
  meta.max_used_block_height = 9;
  meta.last_failed_height = 7;
  meta.receive_time = 1700000000;
  meta.last_relayed_time = 1700000123;
  meta.kept_by_block = 1;
  meta.relayed = 1;
  meta.double_spend_seen = 1;
  meta.l2_height = 77;
  txpool_tx_meta_t unrelayed = meta;
  unrelayed.do_not_relay = 1;
  unrelayed.double_spend_seen = 0;

  const auto h1 = crypto::cn_fast_hash("tx1", 3), h2 = crypto::cn_fast_hash("tx2", 3);
  const std::string blob1 = "tx one", blob2 = "tx two!";
  {
    db_wtxn_guard guard{db};
    db.add_txpool_tx(h1, blob1, meta);
    db.add_txpool_tx(h2, blob2, unrelayed);
    // Adding an existing tx replaces it
    db.add_txpool_tx(h1, "replaced", unrelayed);
    EXPECT_EQ(db.get_txpool_tx_blob(h1), "replaced");
    db.add_txpool_tx(h1, blob1, meta);
    EXPECT_THROW(db.add_txpool_tx(missing_hash(), "", meta), DB_ERROR);
  }

  EXPECT_EQ(db.get_txpool_tx_count(), 2);
  EXPECT_EQ(db.get_txpool_tx_count(false), 1);
  EXPECT_TRUE(db.txpool_has_tx(h2));
  EXPECT_FALSE(db.txpool_has_tx(missing_hash()));

  txpool_tx_meta_t got;
  ASSERT_TRUE(db.get_txpool_tx_meta(h2, got));
  EXPECT_EQ(std::memcmp(&got, &unrelayed, sizeof(got)), 0);
  EXPECT_FALSE(db.get_txpool_tx_meta(missing_hash(), got));
  EXPECT_EQ(db.get_txpool_tx_blob(h1), blob1);
  std::string bd;
  EXPECT_FALSE(db.get_txpool_tx_blob(missing_hash(), bd));
  EXPECT_THROW(db.get_txpool_tx_blob(missing_hash()), DB_ERROR);

  std::vector<std::pair<crypto::hash, std::string>> seen;
  db.for_all_txpool_txes(
      [&](const crypto::hash& h, const txpool_tx_meta_t& m, const std::string* b) {
        EXPECT_EQ(std::memcmp(&m, &meta, sizeof(m)), 0);
        seen.emplace_back(h, b ? *b : "(none)");
        return true;
      },
      true, false);
  ASSERT_EQ(seen.size(), 1);
  ASSERT_HASH_EQ(seen[0].first, h1);
  EXPECT_EQ(seen[0].second, blob1);

  size_t count = 0;
  db.for_all_txpool_txes([&](const crypto::hash&, const txpool_tx_meta_t&, const std::string* b) {
    EXPECT_EQ(b, nullptr);
    ++count;
    return true;
  });
  EXPECT_EQ(count, 2);

  {
    db_wtxn_guard guard{db};
    meta.fee = 1;
    meta.relayed = 0;
    db.update_txpool_tx(h1, meta);
    EXPECT_THROW(db.update_txpool_tx(missing_hash(), meta), DB_ERROR);
    db.remove_txpool_tx(h2);
    db.remove_txpool_tx(missing_hash());
  }
  ASSERT_TRUE(db.get_txpool_tx_meta(h1, got));
  EXPECT_EQ(std::memcmp(&got, &meta, sizeof(got)), 0);
  EXPECT_EQ(db.get_txpool_tx_count(), 1);
  EXPECT_FALSE(db.txpool_has_tx(h2));

  // Toggling do_not_relay moves a tx in and out of the relayable count.
  {
    db_wtxn_guard guard{db};
    meta.do_not_relay = 1;
    db.update_txpool_tx(h1, meta);
  }
  EXPECT_EQ(db.get_txpool_tx_count(false), 0);
  EXPECT_EQ(db.get_txpool_tx_count(true), 1);
  {
    db_wtxn_guard guard{db};
    meta.do_not_relay = 0;
    db.update_txpool_tx(h1, meta);
  }
  EXPECT_EQ(db.get_txpool_tx_count(false), 1);

  this->reopen_db();
  ASSERT_TRUE(db.get_txpool_tx_meta(h1, got));
  EXPECT_EQ(std::memcmp(&got, &meta, sizeof(got)), 0);
  EXPECT_EQ(db.get_txpool_tx_blob(h1), blob1);
}

TYPED_TEST(BlockchainDBTest, ServiceNodeData)
{
  this->open_with_blocks();
  auto& db = *this->m_db;
  std::string data;
  EXPECT_FALSE(db.get_service_node_data(data, false));
  {
    db_wtxn_guard guard{db};
    db.set_service_node_data("short", false);
    db.set_service_node_data("long", true);
    db.put_service_node_archive(0, "archive 0");
    db.put_service_node_archive(1, "archive 1");
  }
  ASSERT_TRUE(db.get_service_node_data(data, false));
  EXPECT_EQ(data, "short");
  ASSERT_TRUE(db.get_service_node_data(data, true));
  EXPECT_EQ(data, "long");
  EXPECT_EQ(db.get_service_node_archive_heights(), (std::vector<uint64_t>{0, 1}));
  EXPECT_EQ(db.get_service_node_archive(1), "archive 1");
  EXPECT_EQ(db.get_service_node_archive(5), std::nullopt);

  {
    db_wtxn_guard guard{db};
    db.delete_service_node_data(false);
    db.delete_service_node_archives(1, std::numeric_limits<uint64_t>::max());
  }
  EXPECT_FALSE(db.get_service_node_data(data, false));
  EXPECT_EQ(db.get_service_node_archive_heights(), (std::vector<uint64_t>{0}));

  {
    db_wtxn_guard guard{db};
    db.clear_service_node_data();
  }
  EXPECT_FALSE(db.get_service_node_data(data, true));
  EXPECT_TRUE(db.get_service_node_archive_heights().empty());
}

TYPED_TEST(BlockchainDBTest, ServiceNodeProofs)
{
  this->open_db();
  auto& db = *this->m_db;

  // Since SN_PK_IS_ED25519 a service node's pubkey is its ed25519 pubkey.
  unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
  crypto_sign_keypair(pk, sk);
  crypto::public_key pubkey;
  std::memcpy(&pubkey, pk, sizeof(pubkey));
  crypto::ed25519_public_key pubkey_ed25519;
  std::memcpy(pubkey_ed25519.data(), pk, sizeof(pk));

  service_nodes::proof_info proof;
  proof.timestamp = 1700000000;
  proof.proof->public_ip = 0x01020304;
  proof.proof->storage_https_port = 22021;
  proof.proof->storage_omq_port = 22020;
  proof.proof->qnet_port = 22025;
  proof.proof->version = {11, 6, 1};
  proof.proof->storage_server_version = {2, 10, 0};
  proof.proof->lokinet_version = {0, 9, 11};
  proof.proof->pubkey_ed25519 = pubkey_ed25519;

  {
    db_wtxn_guard guard{db};
    db.set_service_node_proof(pubkey, proof);
  }

  service_nodes::proof_info got;
  ASSERT_TRUE(db.get_service_node_proof(pubkey, got));
  EXPECT_FALSE(db.get_service_node_proof(crypto::public_key{}, got));
  auto check = [&](const service_nodes::proof_info& p) {
    EXPECT_EQ(p.timestamp, proof.timestamp);
    EXPECT_GE(p.effective_timestamp, proof.timestamp);
    EXPECT_EQ(p.proof->public_ip, proof.proof->public_ip);
    EXPECT_EQ(p.proof->storage_https_port, proof.proof->storage_https_port);
    EXPECT_EQ(p.proof->storage_omq_port, proof.proof->storage_omq_port);
    EXPECT_EQ(p.proof->qnet_port, proof.proof->qnet_port);
    EXPECT_EQ(p.proof->version, proof.proof->version);
    EXPECT_EQ(p.proof->storage_server_version, proof.proof->storage_server_version);
    EXPECT_EQ(p.proof->lokinet_version, proof.proof->lokinet_version);
    ASSERT_HASH_EQ(p.proof->pubkey_ed25519, pubkey_ed25519);
    EXPECT_TRUE(p.pubkey_x25519);
  };
  check(got);

  auto all = db.get_all_service_node_proofs();
  ASSERT_EQ(all.size(), 1);
  ASSERT_TRUE(all.count(pubkey));
  check(all.at(pubkey));

  // Reloaded from disk, and replaced by a newer proof with the largest version components that
  // can be stored.
  this->reopen_db();
  service_nodes::proof_info reloaded;
  ASSERT_TRUE(db.get_service_node_proof(pubkey, reloaded));
  check(reloaded);
  proof.timestamp += 3600;
  proof.proof->version = {999, 999, 999};
  proof.proof->storage_server_version = {0, 0, 1};
  proof.proof->lokinet_version = {1, 0, 0};
  {
    db_wtxn_guard guard{db};
    db.set_service_node_proof(pubkey, proof);
  }
  this->reopen_db();
  ASSERT_TRUE(db.get_service_node_proof(pubkey, reloaded));
  check(reloaded);

  {
    db_wtxn_guard guard{db};
    EXPECT_TRUE(db.remove_service_node_proof(pubkey));
    EXPECT_FALSE(db.remove_service_node_proof(pubkey));
  }
  EXPECT_TRUE(db.get_all_service_node_proofs().empty());
}

TYPED_TEST(BlockchainDBTest, AltBlocks)
{
  this->open_db();
  auto& db = *this->m_db;
  const auto& [blk0, blob0] = this->m_blocks[0];
  const auto& [blk1, blob1] = this->m_blocks[1];
  const auto id0 = get_block_hash(blk0), id1 = get_block_hash(blk1);

  alt_block_data_t data0{};
  data0.height = 5;
  data0.cumulative_weight = 123;
  data0.cumulative_difficulty = 456;
  data0.already_generated_coins = 789;
  alt_block_data_t data1 = data0;
  data1.height = 6;
  data1.checkpointed = 1;
  const std::string checkpoint_blob = "a serialized checkpoint";

  EXPECT_EQ(db.get_alt_block_count(), 0);
  EXPECT_FALSE(db.get_alt_block(id0, nullptr, nullptr, nullptr));
  {
    db_wtxn_guard guard{db};
    db.add_alt_block(id0, data0, blob0, nullptr);
    db.add_alt_block(id1, data1, blob1, &checkpoint_blob);
    // LMDB means to refuse a duplicate too, but silently overwrites (MDB_NODUPDATA has no effect
    // without MDB_DUPSORT); its caller never adds a duplicate.
    if constexpr (std::is_same_v<TypeParam, BlockchainSQLite>)
      EXPECT_THROW(db.add_alt_block(id0, data0, blob0, nullptr), DB_ERROR);
  }
  EXPECT_EQ(db.get_alt_block_count(), 2);

  alt_block_data_t got{};
  std::string blob, checkpoint;
  ASSERT_TRUE(db.get_alt_block(id1, &got, &blob, &checkpoint));
  EXPECT_EQ(got.height, 6);
  EXPECT_EQ(got.cumulative_weight, 123);
  EXPECT_EQ(got.cumulative_difficulty, 456);
  EXPECT_EQ(got.already_generated_coins, 789);
  EXPECT_EQ(got.checkpointed, 1);
  EXPECT_EQ(blob, blob1);
  EXPECT_EQ(checkpoint, checkpoint_blob);
  ASSERT_TRUE(db.get_alt_block(id0, &got, nullptr, nullptr));
  EXPECT_EQ(got.checkpointed, 0);
  // A block without a checkpoint leaves the checkpoint output alone.
  checkpoint = "untouched";
  ASSERT_TRUE(db.get_alt_block(id0, &got, &blob, &checkpoint));
  EXPECT_EQ(blob, blob0);
  EXPECT_EQ(checkpoint, "untouched");

  size_t without_blobs = 0;
  db.for_all_alt_blocks(
      [&](const crypto::hash&, const alt_block_data_t&, const std::string* b, const std::string* c) {
        EXPECT_EQ(b, nullptr);
        EXPECT_EQ(c, nullptr);
        ++without_blobs;
        return true;
      });
  EXPECT_EQ(without_blobs, 2);

  size_t count = 0;
  db.for_all_alt_blocks(
      [&](const crypto::hash& id, const alt_block_data_t& d, const std::string* b, const std::string* c) {
        EXPECT_NE(b, nullptr);
        EXPECT_NE(c, nullptr);
        if (id == id1) {
          EXPECT_EQ(*b, blob1);
          EXPECT_EQ(*c, checkpoint_blob);
        } else {
          EXPECT_EQ(*b, blob0);
          EXPECT_EQ(d.checkpointed, 0);
        }
        ++count;
        return true;
      },
      true);
  EXPECT_EQ(count, 2);

  {
    db_wtxn_guard guard{db};
    db.remove_alt_block(id0);
    EXPECT_THROW(db.remove_alt_block(id0), DB_ERROR);
  }
  EXPECT_EQ(db.get_alt_block_count(), 1);
  db.drop_alt_blocks();
  EXPECT_EQ(db.get_alt_block_count(), 0);
}

TYPED_TEST(BlockchainDBTest, ServiceNodeArchiveRanges)
{
  this->open_with_blocks();
  this->add_synthetic_blocks(std::vector<uint64_t>(8, 1000));
  auto& db = *this->m_db;
  using v = std::vector<uint64_t>;
  {
    db_wtxn_guard guard{db};
    for (uint64_t h = 0; h < 10; h++)
      db.put_service_node_archive(h, "state " + std::to_string(h));
    db.put_service_node_archive(4, "state 4, again");
  }
  EXPECT_EQ(db.get_service_node_archive_heights(), (v{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}));
  EXPECT_EQ(db.get_service_node_archive(4), "state 4, again");

  {
    db_wtxn_guard guard{db};
    db.delete_service_node_archives(3, 6);
  }
  EXPECT_EQ(db.get_service_node_archive_heights(), (v{0, 1, 2, 6, 7, 8, 9}));
  {
    db_wtxn_guard guard{db};
    db.delete_service_node_archives(8, std::numeric_limits<uint64_t>::max());
  }
  EXPECT_EQ(db.get_service_node_archive_heights(), (v{0, 1, 2, 6, 7}));
  {
    db_wtxn_guard guard{db};
    db.delete_service_node_archives(0, 1);
  }
  this->reopen_db();
  EXPECT_EQ(db.get_service_node_archive_heights(), (v{1, 2, 6, 7}));
  EXPECT_EQ(db.get_service_node_archive(6), "state 6");
}

TYPED_TEST(BlockchainDBTest, Reset)
{
  this->open_with_blocks();
  auto& db = *this->m_db;
  const auto& blk0 = this->m_blocks[0].first;
  const uint64_t a = blk0.miner_tx->vout[0].amount;
  txpool_tx_meta_t meta{};
  {
    db_wtxn_guard guard{db};
    db.update_block_checkpoint(make_checkpoint(1, 2));
    db.set_service_node_data("data", true);
    db.put_service_node_archive(1, "archive");
    db.add_max_block_size(1000);
    db.add_txpool_tx(missing_hash(), "a tx", meta);
    db.add_alt_block(get_block_hash(blk0), alt_block_data_t{}, this->m_blocks[0].second, nullptr);
  }

  db.reset();

  EXPECT_EQ(db.height(), 0);
  EXPECT_EQ(db.get_tx_count(), 0);
  EXPECT_EQ(db.get_num_outputs(a), 0);
  EXPECT_FALSE(db.tx_exists(blk0.tx_hashes[0]));
  checkpoint_t cp;
  EXPECT_FALSE(db.get_top_checkpoint(cp));
  std::string data;
  EXPECT_FALSE(db.get_service_node_data(data, true));
  EXPECT_TRUE(db.get_service_node_archive_heights().empty());
  EXPECT_EQ(db.get_max_block_size(), std::numeric_limits<uint64_t>::max());
  // The LMDB backend's reset leaves the txpool and alt blocks alone; the SQLite one empties every
  // table.
  if constexpr (std::is_same_v<TypeParam, BlockchainSQLite>)
  {
    EXPECT_EQ(db.get_txpool_tx_count(), 0);
    EXPECT_EQ(db.get_alt_block_count(), 0);
  }

  {
    db_wtxn_guard guard{db};
    this->add_test_block(0);
    this->add_test_block(1);
  }
  EXPECT_EQ(db.height(), 2);
  EXPECT_EQ(db.get_tx_count(), 3);
}

TYPED_TEST(BlockchainDBTest, RemoveDataFile)
{
  this->open_with_blocks();
  auto& db = *this->m_db;
  const auto files = db.get_filenames();
  const auto path = db_open_path<TypeParam>(this->m_prefix);
  db.close();
  ASSERT_TRUE(fs::exists(files[0]));

  // SQLite removes its write-ahead log and shared memory files when the last connection closes;
  // make sure that remove_data_file removes them when they are left behind.
  if constexpr (std::is_same_v<TypeParam, BlockchainSQLite>)
    for (const auto& f : files)
      if (!fs::exists(f))
        std::ofstream{f} << "left behind";

  EXPECT_TRUE(db.remove_data_file(path));
  EXPECT_FALSE(fs::exists(files[0]));
  if constexpr (std::is_same_v<TypeParam, BlockchainSQLite>)
    for (const auto& f : files)
      EXPECT_FALSE(fs::exists(f)) << f;

  // Missing files are not an error.
  EXPECT_TRUE(db.remove_data_file(path));
}

struct temp_data_dir
{
  const fs::path path = random_tmp_file();

  temp_data_dir() { fs::create_directories(path); }
  ~temp_data_dir() { fs::remove_all(path); }

  void touch(const fs::path& relative)
  {
    fs::create_directories((path / relative).parent_path());
    std::ofstream{path / relative};
  }
};

TEST(db_backend, detect)
{
  temp_data_dir dir;
  EXPECT_EQ(select_db_backend(dir.path, std::nullopt), FRESH_DB_BACKEND);

  // An lmdb directory without a data.mdb in it is not an LMDB database
  fs::create_directories(dir.path / "lmdb");
  EXPECT_EQ(select_db_backend(dir.path, std::nullopt), FRESH_DB_BACKEND);

  dir.touch("lmdb/data.mdb");
  EXPECT_EQ(select_db_backend(dir.path, std::nullopt), db_backend::lmdb);

  dir.touch("oxen.db");
  EXPECT_EQ(select_db_backend(dir.path, std::nullopt), db_backend::sqlite);
}

TEST(db_backend, explicit_choice)
{
  temp_data_dir dir;
  EXPECT_EQ(select_db_backend(dir.path, db_backend::lmdb), db_backend::lmdb);
  EXPECT_EQ(select_db_backend(dir.path, db_backend::sqlite), db_backend::sqlite);

  dir.touch("lmdb/data.mdb");
  EXPECT_EQ(select_db_backend(dir.path, db_backend::lmdb), db_backend::lmdb);
  EXPECT_THROW(select_db_backend(dir.path, db_backend::sqlite), DB_ERROR);

  dir.touch("oxen.db");
  EXPECT_EQ(select_db_backend(dir.path, db_backend::lmdb), db_backend::lmdb);
  EXPECT_EQ(select_db_backend(dir.path, db_backend::sqlite), db_backend::sqlite);

  fs::remove_all(dir.path / "lmdb");
  EXPECT_THROW(select_db_backend(dir.path, db_backend::lmdb), DB_ERROR);
  EXPECT_EQ(select_db_backend(dir.path, db_backend::sqlite), db_backend::sqlite);
}

TEST(db_backend, option)
{
  temp_data_dir dir;
  dir.touch("lmdb/data.mdb");

  auto parse = [](std::vector<std::string> args) {
    boost::program_options::options_description desc;
    BlockchainDB::init_options(desc);
    boost::program_options::variables_map vm;
    boost::program_options::store(
        boost::program_options::command_line_parser(args).options(desc).run(), vm);
    boost::program_options::notify(vm);
    return vm;
  };

  EXPECT_EQ(select_db_backend(dir.path, parse({})), db_backend::lmdb);
  EXPECT_EQ(select_db_backend(dir.path, parse({"--db-backend=lmdb"})), db_backend::lmdb);
  EXPECT_THROW(select_db_backend(dir.path, parse({"--db-backend=sqlite"})), DB_ERROR);
  EXPECT_THROW(select_db_backend(dir.path, parse({"--db-backend=bdb"})), DB_ERROR);
}

TEST(db_backend, new_db)
{
  EXPECT_NE(dynamic_cast<BlockchainLMDB*>(new_db(db_backend::lmdb).get()), nullptr);
  EXPECT_NE(dynamic_cast<BlockchainSQLite*>(new_db(db_backend::sqlite).get()), nullptr);
}

TEST(BlockchainSQLite, reopen)
{
  temp_data_dir dir;
  const auto path = dir.path / SQLITE_DB_FILENAME;
  {
    BlockchainSQLite db;
    db.open(path, network_type::FAKECHAIN);
    EXPECT_EQ(db.height(), 0);
    db.close();
  }
  BlockchainSQLite db;
  ASSERT_NO_THROW(db.open(path, network_type::FAKECHAIN));
  EXPECT_EQ(db.height(), 0);
}

TEST(BlockchainSQLite, newer_schema)
{
  temp_data_dir dir;
  const auto path = dir.path / SQLITE_DB_FILENAME;
  {
    BlockchainSQLite db;
    db.open(path, network_type::FAKECHAIN);
  }
  {
    session::sqlite::Database raw{path};
    raw.conn().sql.exec("PRAGMA user_version = 1000");
  }
  BlockchainSQLite db;
  EXPECT_THROW(db.open(path, network_type::FAKECHAIN), DB_OPEN_FAILURE);
}

TEST(BlockchainSQLite, own_write_transaction)
{
  temp_data_dir dir;
  BlockchainSQLite db;
  db.open(dir.path / SQLITE_DB_FILENAME, network_type::FAKECHAIN);
  BlockchainDB& base = db;
  base.add_max_block_size(123);
  EXPECT_EQ(base.get_max_block_size(), 123);

  // ...including while this thread is in a read transaction, which it must not nest inside.
  ASSERT_TRUE(db.block_rtxn_start());
  base.add_max_block_size(456);
  db.block_rtxn_stop();
  EXPECT_EQ(base.get_max_block_size(), 456);
}

TEST(BlockchainSQLite, write_needs_transaction)
{
  temp_data_dir dir;
  BlockchainSQLite db;
  db.open(dir.path / SQLITE_DB_FILENAME, network_type::FAKECHAIN);
  block b;
  std::string blob = h2b(t_blocks[0]);
  ASSERT_TRUE(parse_and_validate_block_from_blob(blob, b));
  std::vector<std::pair<transaction, std::string>> txs;
  for (auto& t : t_transactions[0])
  {
    transaction tx;
    std::string bd = h2b(t);
    ASSERT_TRUE(parse_and_validate_tx_from_blob(bd, tx));
    txs.emplace_back(std::move(tx), std::move(bd));
  }
  EXPECT_THROW(
      db.add_block({b, blob}, t_sizes[0], t_sizes[0], t_diffs[0], t_coins[0], txs), DB_ERROR);
  EXPECT_EQ(db.height(), 0);
  EXPECT_EQ(db.get_tx_count(), 0);
}

}  // anonymous namespace
