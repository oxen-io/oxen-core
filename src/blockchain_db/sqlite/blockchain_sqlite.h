// Copyright (c) 2026, The Oxen Project
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

#include <atomic>
#include <concepts>
#include <memory>
#include <mutex>
#include <optional>
#include <sqlitedb/sqlite.hpp>
#include <thread>
#include <unordered_map>

#include "blockchain_db/blockchain_db.h"

namespace cryptonote {

/// BlockchainDB backend storing the chain in a single SQLite database file (`oxen.db` in the data
/// directory).
///
/// Transactions: all writes happen inside a write transaction, which is either a per-block one
/// (`block_wtxn_start`/`stop`/`abort`) or a batch spanning many blocks (`batch_start`/`stop`/
/// `abort`); block transactions inside a batch do nothing, as with LMDB.  The write transaction is
/// an IMMEDIATE transaction on the writing thread's connection, so every read made on that thread
/// while it is open sees its uncommitted writes.  Other threads read through their own pooled
/// connections, optionally inside a read transaction (`block_rtxn_start`/`stop`) for a consistent
/// snapshot across several calls.  The backend tracks which thread holds which transaction itself
/// and never nests them.
class BlockchainSQLite : public BlockchainDB {
  public:
    explicit BlockchainSQLite(bool batch_transactions = true);
    ~BlockchainSQLite() override;

    void open(const fs::path& filename, network_type nettype, const int db_flags = 0) override;
    void close() override;
    void sync() override;
    void safesyncmode(const bool onoff) override;
    void reset() override;
    std::vector<fs::path> get_filenames() const override;
    bool remove_data_file(const fs::path& filename) const override;
    std::string get_db_name() const override;

    void lock() override;
    bool try_lock() override;
    void unlock() override;

    bool block_exists(const crypto::hash& h, uint64_t* height = nullptr) const override;
    uint64_t get_block_height(const crypto::hash& h) const override;
    block get_block_from_height(uint64_t height, size_t* size = nullptr) const override;
    block_header get_block_header_from_height(uint64_t height) const override;
    std::string get_block_blob(const crypto::hash& h) const override;
    std::string get_block_blob_from_height(uint64_t height) const override;
    std::vector<uint64_t> get_block_cumulative_rct_outputs(
            const std::vector<uint64_t>& heights) const override;
    uint64_t get_block_timestamp(const uint64_t& height) const override;
    uint64_t get_top_block_timestamp() const override;
    size_t get_block_weight(const uint64_t& height) const override;
    std::vector<uint64_t> get_block_weights(uint64_t start_height, size_t count) const override;
    difficulty_type get_block_cumulative_difficulty(const uint64_t& height) const override;
    difficulty_type get_block_difficulty(const uint64_t& height) const override;
    uint64_t get_block_already_generated_coins(const uint64_t& height) const override;
    uint64_t get_block_long_term_weight(const uint64_t& height) const override;
    std::vector<uint64_t> get_long_term_block_weights(
            uint64_t start_height, size_t count) const override;
    crypto::hash get_block_hash_from_height(const uint64_t& height) const override;
    std::vector<block> get_blocks_range(const uint64_t& h1, const uint64_t& h2) const override;
    std::vector<crypto::hash> get_hashes_range(
            const uint64_t& h1, const uint64_t& h2) const override;
    crypto::hash top_block_hash(uint64_t* block_height = nullptr) const override;
    block get_top_block() const override;
    uint64_t height() const override;

    bool tx_exists(const crypto::hash& h) const override;
    bool tx_exists(const crypto::hash& h, uint64_t& tx_id) const override;
    uint64_t get_tx_unlock_time(const crypto::hash& h) const override;
    bool get_tx_blob(const crypto::hash& h, std::string& tx) const override;
    bool get_pruned_tx_blob(const crypto::hash& h, std::string& tx) const override;
    bool get_pruned_tx_blobs_from(
            const crypto::hash& h, size_t count, std::vector<std::string>& bd) const override;
    bool get_prunable_tx_blob(const crypto::hash& h, std::string& tx) const override;
    bool get_prunable_tx_hash(
            const crypto::hash& tx_hash, crypto::hash& prunable_hash) const override;
    uint64_t get_tx_count() const override;
    std::vector<transaction> get_tx_list(const std::vector<crypto::hash>& hlist) const override;
    std::vector<uint64_t> get_tx_block_heights(
            const std::vector<crypto::hash>& hlist) const override;

    uint64_t get_num_outputs(const uint64_t& amount) const override;
    output_data_t get_output_key(
            const uint64_t& amount, const uint64_t& index, bool include_commitment) const override;
    void get_output_key(
            std::span<const uint64_t> amounts,
            const std::vector<uint64_t>& offsets,
            std::vector<output_data_t>& outputs,
            bool allow_partial = false) const override;
    tx_out_index get_output_tx_and_index_from_global(const uint64_t& index) const override;
    tx_out_index get_output_tx_and_index(
            const uint64_t& amount, const uint64_t& index) const override;
    void get_output_tx_and_index(
            const uint64_t& amount,
            const std::vector<uint64_t>& offsets,
            std::vector<tx_out_index>& indices) const override;
    std::vector<std::vector<uint64_t>> get_tx_amount_output_indices(
            const uint64_t tx_id, size_t n_txes) const override;
    bool can_thread_bulk_indices() const override { return true; }

    bool has_key_image(const crypto::key_image& img) const override;

    void get_output_blacklist(std::vector<uint64_t>& blacklist) const override;
    void add_output_blacklist(std::vector<uint64_t> const& blacklist) override;

    bool for_all_key_images(std::function<bool(const crypto::key_image&)>) const override;
    bool for_blocks_range(
            const uint64_t& h1,
            const uint64_t& h2,
            std::function<bool(uint64_t, const crypto::hash&, const cryptonote::block&)>)
            const override;
    bool for_all_transactions(
            std::function<bool(const crypto::hash&, const cryptonote::transaction&)>,
            bool pruned) const override;
    bool for_all_outputs(
            std::function<bool(
                    uint64_t amount, const crypto::hash& tx_hash, uint64_t height, size_t tx_idx)>
                    f) const override;
    bool for_all_outputs(
            uint64_t amount, const std::function<bool(uint64_t height)>& f) const override;

    uint64_t add_block(
            const std::pair<block, std::string>& blk,
            size_t block_weight,
            uint64_t long_term_block_weight,
            const difficulty_type& cumulative_difficulty,
            const uint64_t& coins_generated,
            const std::vector<std::pair<transaction, std::string>>& txs) override;
    void pop_block(block& blk, std::vector<transaction>& txs) override;

    void set_batch_transactions(bool batch_transactions) override;
    bool batch_start(uint64_t bytes_required = 0) override;
    void batch_stop() override;
    void batch_abort() override;

    void block_wtxn_start() override;
    void block_wtxn_stop() override;
    void block_wtxn_abort() override;
    bool block_rtxn_start() const override;
    void block_rtxn_stop() const override;
    void block_rtxn_abort() const override;

    SQLite::Transaction* active_write_transaction() override;
    session::sqlite::Database* sqlite_database() override { return m_sql.get(); }

    uint64_t history() const override { return m_history; }
    uint64_t history_start() const override { return m_history_start; }
    void set_history(uint64_t blocks) override;
    void trim_history() override;

    bool is_read_only() const override;
    uint64_t get_database_size() const override;
    void fixup(network_type nettype) override;

    void add_txpool_tx(
            const crypto::hash& txid,
            const std::string& blob,
            const txpool_tx_meta_t& meta) override;
    void update_txpool_tx(const crypto::hash& txid, const txpool_tx_meta_t& meta) override;
    uint64_t get_txpool_tx_count(bool include_unrelayed_txes = true) const override;
    bool txpool_has_tx(const crypto::hash& txid) const override;
    void remove_txpool_tx(const crypto::hash& txid) override;
    bool get_txpool_tx_meta(const crypto::hash& txid, txpool_tx_meta_t& meta) const override;
    bool get_txpool_tx_blob(const crypto::hash& txid, std::string& bd) const override;
    std::string get_txpool_tx_blob(const crypto::hash& txid) const override;
    bool for_all_txpool_txes(
            std::function<bool(const crypto::hash&, const txpool_tx_meta_t&, const std::string*)> f,
            bool include_blob = false,
            bool include_unrelayed_txes = true) const override;

    void add_alt_block(
            const crypto::hash& blkid,
            const cryptonote::alt_block_data_t& data,
            const std::string& blob,
            const std::string* checkpoint) override;
    bool get_alt_block(
            const crypto::hash& blkid,
            alt_block_data_t* data,
            std::string* blob,
            std::string* checkpoint) const override;
    void remove_alt_block(const crypto::hash& blkid) override;
    uint64_t get_alt_block_count() override;
    void drop_alt_blocks() override;
    bool for_all_alt_blocks(
            std::function<
                    bool(const crypto::hash& blkid,
                         const alt_block_data_t& data,
                         const std::string* block_blob,
                         const std::string* checkpoint_blob)> f,
            bool include_blob = false) const override;

    void update_block_checkpoint(checkpoint_t const& checkpoint) override;
    void remove_block_checkpoint(uint64_t height) override;
    bool get_block_checkpoint(uint64_t height, checkpoint_t& checkpoint) const override;
    bool get_top_checkpoint(checkpoint_t& checkpoint) const override;
    std::vector<checkpoint_t> get_checkpoints_range(
            uint64_t start,
            uint64_t end,
            size_t num_desired_checkpoints = GET_ALL_CHECKPOINTS) const override;

    std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> get_output_histogram(
            const std::vector<uint64_t>& amounts,
            bool unlocked,
            uint64_t recent_cutoff,
            uint64_t min_count) const override;
    bool get_output_distribution(
            uint64_t amount,
            uint64_t from_height,
            uint64_t to_height,
            std::vector<uint64_t>& distribution,
            uint64_t& base) const override;

    // There are no service node data blobs here: the SN list keeps its recent states as archive
    // entries too (every STATE_SNAPSHOT_INTERVAL blocks).  Setting one throws; there's never one
    // to get or delete.
    void set_service_node_data(const std::string& data, bool long_term) override;
    bool get_service_node_data(std::string& data, bool long_term) const override;
    void delete_service_node_data(bool long_term) override;
    void clear_service_node_data() override;

    void put_service_node_archive(
            uint64_t height, std::string_view data, bool quorums_only) override;
    std::optional<std::string> get_service_node_archive(uint64_t height) const override;
    std::optional<std::pair<uint64_t, std::string>> get_newest_full_service_node_archive(
            uint64_t height) const override;
    std::vector<uint64_t> get_service_node_archive_heights() const override;
    void delete_service_node_archives(uint64_t begin, uint64_t end) override;

    bool get_service_node_proof(
            const crypto::public_key& pubkey, service_nodes::proof_info& proof) const override;
    void set_service_node_proof(
            const crypto::public_key& pubkey, const service_nodes::proof_info& proof) override;
    std::unordered_map<crypto::public_key, service_nodes::proof_info> get_all_service_node_proofs()
            const override;
    bool remove_service_node_proof(const crypto::public_key& pubkey) override;

  private:
    uint64_t get_max_block_size() override;
    void add_max_block_size(uint64_t sz) override;

    void add_block(
            const block& blk,
            size_t block_weight,
            uint64_t long_term_block_weight,
            const difficulty_type& cumulative_difficulty,
            const uint64_t& coins_generated,
            uint64_t num_rct_outs,
            const crypto::hash& block_hash) override;
    void remove_block() override;
    uint64_t add_transaction_data(
            const crypto::hash& blk_hash,
            const std::pair<transaction, std::string>& tx,
            const crypto::hash& tx_hash,
            const crypto::hash& tx_prunable_hash) override;
    void remove_transaction_data(const crypto::hash& tx_hash, const transaction& tx) override;
    uint64_t add_output(
            const crypto::hash& tx_hash,
            const tx_out& tx_output,
            const uint64_t& local_index,
            const uint64_t unlock_time,
            const rct::key* commitment) override;
    void add_tx_amount_output_indices(
            const uint64_t tx_id, const std::vector<uint64_t>& amount_output_indices) override;
    void add_spent_key(const crypto::key_image& k_image) override;
    void remove_spent_key(const crypto::key_image& k_image) override;

    void check_open() const;
    void create_schema();

    // The calling thread's connection for a write.  Throws if the calling thread does not hold the
    // write transaction: writes made outside of one would each commit on their own, and the
    // deferred foreign keys to `blocks` can only be satisfied when a block's transactions, outputs
    // and key images are committed together with its row.
    session::sqlite::Connection& write_conn();

    // Runs `f(conn)` for a write that callers make both inside and outside of a write transaction
    // (the txpool, alt blocks, max block size, proofs): inside the calling thread's write
    // transaction if it holds one, otherwise inside a write transaction of its own, on a connection
    // of its own (so that it can't nest inside a read transaction of this thread), committed when
    // `f` returns.
    template <std::invocable<session::sqlite::Connection&> F>
    void in_write_txn(F&& f);

    // Starts a read transaction for a read made up of more than one statement, so that it sees one
    // consistent state of the database, unless the calling thread already has a read or write
    // transaction open (in which case the statements run in that one).
    std::optional<SQLite::Transaction> read_tx(session::sqlite::Connection& conn) const;

    // Ends any read transaction of the calling thread, committing it or rolling it back.
    void end_read_txn(bool commit) const;

    void begin_write(bool batch);
    void end_write(bool commit);

    // Throw unless the calling thread holds the write transaction (respectively: a batch); `action`
    // is what was attempted.
    void require_writer(std::string_view action) const;
    void require_batch_writer() const;

    template <typename T>
    T get_block_column(uint64_t height, std::string_view column, std::string_view what) const;

    // The stored block at `height`, as a block, block_header or (serialized) std::string.
    template <typename T>
    T get_stored_block(uint64_t height, size_t* size = nullptr) const;

    std::vector<uint64_t> get_block_weight_column(
            std::string_view column, uint64_t start_height, size_t count) const;

    // Drops everything outside the history below height `to` (see trim_history), in chunks, each
    // in the calling thread's write transaction if it holds one, otherwise in one of its own.
    void trim_history_to(uint64_t to);

    // Rewrites the database file without its free pages (VACUUM INTO, then swapped in), if they
    // make up a substantial part of it.  Only when nothing else is using the database.
    void compact_if_worthwhile();

    std::unique_ptr<session::sqlite::Database> m_sql;
    fs::path m_filename;
    network_type m_nettype = network_type::UNDEFINED;
    int m_db_flags = 0;
    bool m_read_only = false;

    // The stored `history` and `history_start` properties (see history() and history_start()).
    // Only changed by the writer.
    uint64_t m_history = 0;
    uint64_t m_history_start = 0;

    std::mutex m_lock;

    struct write_txn {
        // conn must outlive tx, which rolls back (if still open) on destruction.
        session::sqlite::Connection conn;
        SQLite::Transaction tx;

        explicit write_txn(session::sqlite::Database& db);
    };
    // Only touched by the thread in m_writer while that is set; other threads only look at
    // m_writer and m_batch_active.
    std::optional<write_txn> m_write;
    std::atomic<std::thread::id> m_writer{};
    std::atomic<bool> m_batch_active{false};
    bool m_batch_transactions = true;

    struct read_txn {
        session::sqlite::Connection conn;
        SQLite::Transaction tx;

        explicit read_txn(session::sqlite::Database& db);
    };
    mutable std::mutex m_read_mutex;
    mutable std::unordered_map<std::thread::id, std::unique_ptr<read_txn>> m_reads;
};

}  // namespace cryptonote
