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

#pragma once

#include <boost/program_options/variables_map.hpp>
#include <unordered_map>

#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/verification_context.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_core/service_node_voting.h"
#include "cryptonote_core/tx_blink.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"

namespace tests {
struct block_index {
    size_t height;
    crypto::hash id;
    crypto::hash longhash;
    cryptonote::block blk;
    std::string blob;
    std::list<cryptonote::transaction> txes;

    block_index() : height(0), id{}, longhash{} {}
    block_index(
            size_t _height,
            const crypto::hash& _id,
            const crypto::hash& _longhash,
            const cryptonote::block& _blk,
            const std::string& _blob,
            const std::list<cryptonote::transaction>& _txes) :
            height(_height), id(_id), longhash(_longhash), blk(_blk), blob(_blob), txes(_txes) {}
};

struct fake_lockable {
    void lock() {}
    void unlock() {}
    bool try_lock() { return true; }
    void lock_shared() {}
    void unlock_shared() {}
    bool try_lock_shared() { return true; }
};

class proxy_core {
  public:
    void on_synchronized() {}
    void safesyncmode(const bool) {}
    void set_target_blockchain_height(uint64_t) {}
    bool init(const boost::program_options::variables_map& vm);
    bool deinit() { return true; }
    bool handle_incoming_tx(
            const std::string& tx_blob,
            cryptonote::tx_verification_context& tvc,
            const cryptonote::tx_pool_options& opts);
    std::vector<cryptonote::tx_verification_batch_info> parse_incoming_txs(
            const std::vector<std::string>& tx_blobs, const cryptonote::tx_pool_options& opts);
    bool handle_parsed_txs(
            std::vector<cryptonote::tx_verification_batch_info>& parsed_txs,
            const cryptonote::tx_pool_options& opts,
            uint64_t* blink_rollback_height = nullptr);
    std::vector<cryptonote::tx_verification_batch_info> handle_incoming_txs(
            const std::vector<std::string>& tx_blobs, const cryptonote::tx_pool_options& opts);
    std::pair<std::vector<std::shared_ptr<cryptonote::blink_tx>>, std::unordered_set<crypto::hash>>
    parse_incoming_blinks(const std::vector<cryptonote::serializable_blink_metadata>& blinks);
    int add_blinks(const std::vector<std::shared_ptr<cryptonote::blink_tx>>& blinks) { return 0; }
    bool handle_incoming_block(
            const std::string& block_blob,
            const cryptonote::block* block,
            cryptonote::block_verification_context& bvc,
            cryptonote::checkpoint_t* checkpoint,
            bool update_miner_blocktemplate = true);
    bool handle_uptime_proof(
            const cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request& proof,
            bool& my_uptime_proof_confirmation);
    void pause_mine() {}
    void resume_mine() {}
    bool on_idle() { return true; }
    bool get_test_drop_download() { return true; }
    bool get_test_drop_download_height() { return true; }
    bool prepare_handle_incoming_blocks(
            const std::vector<cryptonote::block_complete_entry>& blocks_entry,
            std::vector<cryptonote::block>& blocks) {
        return true;
    }
    bool cleanup_handle_incoming_blocks(bool force_sync = false) { return true; }
    uint64_t get_target_blockchain_height() const { return 1; }
    size_t get_block_sync_size(uint64_t height) const {
        return cryptonote::BLOCKS_SYNCHRONIZING_DEFAULT_COUNT;
    }
    virtual crypto::hash on_transaction_relayed(const std::string& tx) {
        return crypto::null<crypto::hash>;
    }
    cryptonote::network_type get_nettype() const { return cryptonote::network_type::MAINNET; }
    const cryptonote::network_config& get_net_config() const { return get_config(get_nettype()); }
    class fake_blockchain : public fake_lockable {
        cryptonote::block m_genesis;
        std::list<crypto::hash> m_known_block_list;
        std::list<cryptonote::transaction> txes;
        crypto::hash m_lastblk;
        void build_short_history(std::list<crypto::hash>& m_history, const crypto::hash& m_start);
        std::unordered_map<crypto::hash, block_index> m_hash2blkidx;
        bool add_block(
                const crypto::hash& _id,
                const crypto::hash& _longhash,
                const cryptonote::block& _blk,
                const std::string& _blob,
                const cryptonote::checkpoint_t*);
        friend class proxy_core;

      public:
        uint64_t get_current_blockchain_height() { return 1; }
        std::pair<uint64_t, crypto::hash> get_tail_id() const;
        bool handle_get_blocks(
                cryptonote::NOTIFY_REQUEST_GET_BLOCKS::request& arg,
                cryptonote::NOTIFY_RESPONSE_GET_BLOCKS::request& rsp) {
            return true;
        }
        bool handle_get_txs(
                cryptonote::NOTIFY_REQUEST_GET_TXS::request&,
                cryptonote::NOTIFY_NEW_TRANSACTIONS::request&) {
            return true;
        }
        bool find_blockchain_supplement(
                const std::list<crypto::hash>& qblock_ids,
                cryptonote::NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp) {
            return true;
        }
        bool have_block(const crypto::hash& id);
        bool get_blocks(
                uint64_t start_offset,
                size_t count,
                std::vector<std::pair<std::string, cryptonote::block>>& blocks,
                std::vector<std::string>& txs) const {
            return false;
        }
        bool get_transactions(
                const std::vector<crypto::hash>& txs_ids,
                std::vector<cryptonote::transaction>& txs,
                std::unordered_set<crypto::hash>* missed_txs = nullptr) const {
            return false;
        }
        bool get_block_by_hash(
                const crypto::hash& h, cryptonote::block& blk, bool* orphan = NULL) const {
            return false;
        }
        bool get_short_chain_history(std::list<crypto::hash>& ids);
        bool blink_rollback(uint64_t rollback_height) { return false; }
        bool is_within_compiled_block_hash_area(uint64_t height) const { return false; }
        uint64_t get_immutable_height() const { return 0; }
        uint64_t prevalidate_block_hashes(uint64_t height, const std::list<crypto::hash>& hashes) {
            return 0;
        }
        uint64_t prevalidate_block_hashes(
                uint64_t height, const std::vector<crypto::hash>& hashes) {
            return 0;
        }
        uint32_t get_blockchain_pruning_seed() const { return 0; }

        struct fake_db {
            cryptonote::difficulty_type get_block_cumulative_difficulty(uint64_t height) const {
                return 0;
            }
        } db_;
        fake_db& db() { return db_; }
    } blockchain;
    // TODO(oxen): Write tests
    bool add_service_node_vote(
            const service_nodes::quorum_vote_t& vote, cryptonote::vote_verification_context& vvc) {
        return false;
    }
    void set_service_node_votes_relayed(const std::vector<service_nodes::quorum_vote_t>& votes) {}
    bool pad_transactions() const { return false; }
    bool prune_blockchain(uint32_t pruning_seed) const { return true; }

    bool handle_incoming_blinks(
            const std::vector<cryptonote::serializable_blink_metadata>& blinks,
            std::vector<crypto::hash>* bad_blinks = nullptr,
            std::vector<crypto::hash>* missing_txs = nullptr) {
        return true;
    }

    struct fake_lock {
        ~fake_lock() { /* avoid unused variable warning by having a destructor */
        }
    };
    fake_lock incoming_tx_lock() { return {}; }

    struct fake_pool : public fake_lockable {
        void add_missing_blink_hashes(
                const std::map<uint64_t, std::vector<crypto::hash>>& potential) {}
        template <typename... Args>
        int blink_shared_lock(Args&&... args) {
            return 42;
        }
        std::shared_ptr<cryptonote::blink_tx> get_blink(crypto::hash&) { return nullptr; }
        bool get_transaction(const crypto::hash& id, std::string& tx_blob) const { return false; }
        bool have_tx(const crypto::hash& txid) const { return false; }
        std::map<uint64_t, crypto::hash> get_blink_checksums() const { return {}; }
        std::vector<crypto::hash> get_mined_blinks(const std::set<uint64_t>&) const { return {}; }
        void keep_missing_blinks(std::vector<crypto::hash>& tx_hashes) const {}
    } mempool;
    struct fake_miner {
        void pause() {}
        void resume() {}
    } miner;
};
}  // namespace tests
