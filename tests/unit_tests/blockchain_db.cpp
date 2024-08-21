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

#include "blockchain_db/blockchain_db.h"

#include <boost/algorithm/string/predicate.hpp>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <random>
#include <thread>

#include "blockchain_db/lmdb/db_lmdb.h"
#include "common/fs.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "epee/string_tools.h"
#include "gtest/gtest.h"
#include "logging/oxen_logger.h"
#include "random_path.h"

using namespace cryptonote;

#define ASSERT_HASH_EQ(a, b) ASSERT_EQ(tools::hex_guts(a), tools::hex_guts(b))

namespace {  // anonymous namespace

const std::vector<std::string> t_blocks = {
        "0100d5adc49a053b8818b2b6023cd2d532c6774e164a8fcacd603651cb3ea0cb7f9340b28ec016b4bc4ca301aa"
        "0101ff6e08acbb2702eab03067870349139bee7eab2ca2e030a6bb73d4f68ab6a3b6ca937214054cdac0843d02"
        "8bbe23b57ea9bae53f12da93bb57bf8a2e40598d9fccd10c2921576e987d93cd80b4891302468738e391f07c4f"
        "2b356f7957160968e0bfef6e907c3cee2d8c23cbf04b089680c6868f01025a0f41f063e195a966051e3a29e171"
        "30a9ce97d48f55285b9bb04bdd55a09ae78088aca3cf0202d0f26169290450fe17e08974789c3458910b4db183"
        "61cdc564f8f2d0bdd2cf568090cad2c60e02d6f3483ec45505cc3be841046c7a12bf953ac973939bc7b727e542"
        "58e1881d4d80e08d84ddcb0102dae6dfb16d3e28aaaf43e00170b90606b36f35f38f8a3dceb5ee18199dd8f17c"
        "80c0caf384a30202385d7e57a4daba4cdd9e550a92dcc188838386e7581f13f09de796cbed4716a42101c05249"
        "2a077abf41996b50c1b2e67fd7288bcd8c55cdc657b4e22d0804371f6901beb76a82ea17400cd6d7f595f70e16"
        "67d2018ed8f5a78d1ce07484222618c3cd",
        "0100f9adc49a057d3113f562eac36f14afa08c22ae20bbbf8cffa31a4466d24850732cb96f80e9762365ee01ab"
        "0101ff6f08cc953502be76deb845c431f2ed9a4862457654b914003693b8cd672abc935f0d97b16380c08db701"
        "0291819f2873e3efbae65ecd5a736f5e8a26318b591c21e39a03fb536520ac63ba80dac40902439a10fde02e39"
        "e48e0b31e57cc084a07eedbefb8cbea0143aedd0442b189caa80c6868f010227b84449de4cd7a48cbdce8974ba"
        "f0b6646e03384e32055e705c243a86bef8a58088aca3cf0202fa7bd15e4e7e884307ab130bb9d50e33c5fcea65"
        "46042a26f948efd5952459ee8090cad2c60e028695583dbb8f8faab87e3ef3f88fa827db097bbf51761d91924f"
        "5c5b74c6631780e08d84ddcb010279d2f247b54690e3b491e488acff16014a825fd740c23988a25df7c4670c1f"
        "2580c0caf384a302022599dfa3f8788b66295051d85937816e1c320cdb347a0fba5219e3fe60c83b2421010576"
        "509c5672025d28fd5d3f38efce24e1f9aaf65dd3056b2504e6e2b7f19f7800"};

const std::vector<size_t> t_sizes = {1122, 347};

const std::vector<difficulty_type> t_diffs = {4003674, 4051757};

const std::vector<uint64_t> t_coins = {1952630229575370, 1970220553446486};

const std::vector<std::vector<std::string>> t_transactions = {
        {"0100010280e08d84ddcb0106010401110701f254220bb50d901a5523eaed438af5d43f8c6d0e54ba0632eb539"
         "884f6b7c02008c0a8a50402f9c7cf807ae74e56f4ec84db2bd93cfb02c2249b38e306f5b54b6e05d00d543b80"
         "95f52a02b6abb84e00f47f0a72e37b6b29392d906a38468404c57db3dbc5e8dd306a27a880d293ad0302cfc40"
         "a86723e7d459e90e45d47818dc0e81a1f451ace5137a4af8110a89a35ea80b4c4c321026b19c796338607d5a2"
         "c1ba240a167134142d72d1640ef07902da64fed0b10cfc8088aca3cf02021f6f655254fee84161118b32e7b6f"
         "8c31de5eb88aa00c29a8f57c0d1f95a24dd80d0b8e1981a023321af593163cea2ae37168ab926efd87f195756"
         "e3b723e886bdb7e618f751c480a094a58d1d0295ed2b08d1cf44482ae0060a5dcc4b7d810a85dea8c62e274f7"
         "3862f3d59f8ed80a0e5b9c2910102dc50f2f28d7ceecd9a1147f7106c8d5b4e08b2ec77150f52dd7130ee4f5f"
         "50d42101d34f90ac861d0ee9fe3891656a234ea86a8a93bf51a237db65baa00d3f4aa196a9e1d89bc06b40e94"
         "ea9a26059efc7ba5b2de7ef7c139831ca62f3fe0bb252008f8c7ee810d3e1e06313edf2db362fc39431755779"
         "466b635f12f9f32e44470a3e85e08a28fcd90633efc94aa4ae39153dfaf661089d045521343a3d63e8da08d79"
         "16753c66aaebd4eefcfe8e58e5b3d266b752c9ca110749fa33fce7c44270386fcf2bed4f03dd5dadb2dc1fd4c"
         "505419f8217b9eaec07521f0d8963e104603c926745039cf38d31de6ed95ace8e8a451f5a36f818c151f51754"
         "6d55ac0f500e54d07b30ea7452f2e93fa4f60bdb30d71a0a97f97eb121e662006780fbf69002228224a96bff3"
         "7893d47ec3707b17383906c0cd7d9e7412b3e6c8ccf1419b093c06c26f96e3453b424713cdc5c9575f81cda4e"
         "157052df11f4c40809edf420f88a3dd1f7909bbf77c8b184a933389094a88e480e900bcdbf6d1824742ee520f"
         "c0032e7d892a2b099b8c6edfd1123ce58a34458ee20cad676a7f7cfd80a28f0cb0888af88838310db372986bd"
         "cf9bfcae2324480ca7360d22bff21fb569a530e"},
        {}};

// if the return type (std::string for now) of block_to_blob ever changes
// from std::string, this might break.
bool compare_blocks(const block& a, const block& b) {
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
std::string h2b(const std::string& s) {
    bool upper = true;
    std::string result;
    unsigned char val = 0;
    for (char c : s) {
        if (upper) {
            val = 0;
            if (c <= 'f' && c >= 'a') {
                val = ((c - 'a') + 10) << 4;
            } else {
                val = (c - '0') << 4;
            }
        } else {
            if (c <= 'f' && c >= 'a') {
                val |= (c - 'a') + 10;
            } else {
                val |= c - '0';
            }
            result += (char)val;
        }
        upper = !upper;
    }
    return result;
}

template <typename T>
class BlockchainDBTest : public testing::Test {
  protected:
    BlockchainDBTest() : m_db(new T()) {
        auto logcat = oxen::log::Cat("db_test");
        for (auto& i : t_blocks) {
            block bl;
            std::string bd = h2b(i);
            CHECK_AND_ASSERT_THROW_MES(parse_and_validate_block_from_blob(bd, bl), "Invalid block");
            m_blocks.push_back(std::make_pair(bl, bd));
        }
        for (auto& i : t_transactions) {
            std::vector<std::pair<transaction, std::string>> txs;
            for (auto& j : i) {
                transaction tx;
                std::string bd = h2b(j);
                CHECK_AND_ASSERT_THROW_MES(
                        parse_and_validate_tx_from_blob(bd, tx), "Invalid transaction");
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

    void get_filenames() {
        m_filenames = m_db->get_filenames();
        for (auto& f : m_filenames) {
            std::cerr << "File created by test: " << f << std::endl;
        }
    }

    void remove_files() {
        // remove each file the db created, making sure it starts with fname.
        for (auto& f : m_filenames) {
            if (f.u8string().starts_with(m_prefix.u8string())) {
                fs::remove(f);
            } else {
                std::cerr << "File created by test not to be removed (for safety): " << f
                          << std::endl;
            }
        }

        // remove directory if it still exists
        fs::remove_all(m_prefix);
    }

    void set_prefix(std::string_view prefix) {
        m_prefix = fs::path(tools::convert_sv<char8_t>(prefix));
    }
};

using testing::Types;

typedef Types<BlockchainLMDB> implementations;

TYPED_TEST_CASE(BlockchainDBTest, implementations);

TYPED_TEST(BlockchainDBTest, OpenAndClose) {
    fs::path tempPath = random_tmp_file();
    std::string dirPath = tempPath.string();

    this->set_prefix(dirPath);

    // make sure open does not throw
    ASSERT_NO_THROW(this->m_db->open(dirPath, network_type::FAKECHAIN));
    this->get_filenames();

    // make sure open when already open DOES throw
    ASSERT_THROW(this->m_db->open(dirPath, network_type::FAKECHAIN), DB_OPEN_FAILURE);

    ASSERT_NO_THROW(this->m_db->close());
}

TYPED_TEST(BlockchainDBTest, AddBlock) {

    fs::path tempPath = random_tmp_file();
    std::string dirPath = tempPath.string();

    this->set_prefix(dirPath);

    // make sure open does not throw
    ASSERT_NO_THROW(this->m_db->open(dirPath, network_type::FAKECHAIN));
    this->get_filenames();

    db_wtxn_guard guard{*this->m_db};

    // adding a block with no parent in the blockchain should throw.
    // note: this shouldn't be possible, but is a good (and cheap) failsafe.
    //
    // TODO: need at least one more block to make this reasonable, as the
    // BlockchainDB implementation should not check for parent if
    // no blocks have been added yet (because genesis has no parent).
    // ASSERT_THROW(this->m_db->add_block(this->m_blocks[1], t_sizes[1], t_sizes[1], t_diffs[1],
    // t_coins[1], this->m_txs[1]), BLOCK_PARENT_DNE);

    ASSERT_NO_THROW(this->m_db->add_block(
            this->m_blocks[0], t_sizes[0], t_sizes[0], t_diffs[0], t_coins[0], this->m_txs[0]));
    ASSERT_NO_THROW(this->m_db->add_block(
            this->m_blocks[1], t_sizes[1], t_sizes[1], t_diffs[1], t_coins[1], this->m_txs[1]));

    block b;
    ASSERT_TRUE(this->m_db->block_exists(get_block_hash(this->m_blocks[0].first)));
    ASSERT_NO_THROW(b = this->m_db->get_block(get_block_hash(this->m_blocks[0].first)));

    ASSERT_TRUE(compare_blocks(this->m_blocks[0].first, b));

    ASSERT_NO_THROW(b = this->m_db->get_block_from_height(0));

    ASSERT_TRUE(compare_blocks(this->m_blocks[0].first, b));

    // assert that we can't add the same block twice
    ASSERT_THROW(
            this->m_db->add_block(
                    this->m_blocks[0],
                    t_sizes[0],
                    t_sizes[0],
                    t_diffs[0],
                    t_coins[0],
                    this->m_txs[0]),
            TX_EXISTS);

    for (auto& h : this->m_blocks[0].first.tx_hashes) {
        transaction tx;
        ASSERT_TRUE(this->m_db->tx_exists(h));
        ASSERT_NO_THROW(tx = this->m_db->get_tx(h));

        ASSERT_HASH_EQ(h, get_transaction_hash(tx));
    }
}

TYPED_TEST(BlockchainDBTest, RetrieveBlockData) {
    fs::path tempPath = random_tmp_file();
    std::string dirPath = tempPath.string();

    this->set_prefix(dirPath);

    // make sure open does not throw
    ASSERT_NO_THROW(this->m_db->open(dirPath, network_type::FAKECHAIN));
    this->get_filenames();

    db_wtxn_guard guard{*this->m_db};

    ASSERT_NO_THROW(this->m_db->add_block(
            this->m_blocks[0], t_sizes[0], t_sizes[0], t_diffs[0], t_coins[0], this->m_txs[0]));

    ASSERT_EQ(t_sizes[0], this->m_db->get_block_weight(0));
    ASSERT_EQ(t_diffs[0], this->m_db->get_block_cumulative_difficulty(0));
    ASSERT_EQ(t_diffs[0], this->m_db->get_block_difficulty(0));
    ASSERT_EQ(t_coins[0], this->m_db->get_block_already_generated_coins(0));

    ASSERT_NO_THROW(this->m_db->add_block(
            this->m_blocks[1], t_sizes[1], t_sizes[1], t_diffs[1], t_coins[1], this->m_txs[1]));
    ASSERT_EQ(t_diffs[1] - t_diffs[0], this->m_db->get_block_difficulty(1));

    ASSERT_HASH_EQ(
            get_block_hash(this->m_blocks[0].first), this->m_db->get_block_hash_from_height(0));

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

}  // anonymous namespace
