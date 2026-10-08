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

#include "blockchain_sqlite.h"

#include <fmt/std.h>

#include <algorithm>
#include <chrono>
#include <session/placeholders.hpp>
#include <unordered_map>

#include "checkpoints/checkpoints.h"
#include "common/format.h"
#include "common/guts.h"
#include "common/oxen.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/service_node_list.h"
#include "cryptonote_core/uptime_proof.h"
#include "logging/oxen_logger.h"
#include "ringct/rctOps.h"

namespace cryptonote {

static auto logcat = log::Cat("blockchain.db.sqlite");

using db::as_i64;
using db::as_u64;
using session::sqlite::bind_each;
using session::sqlite::blob;
using session::sqlite::blob_guts;
using session::sqlite::Connection;
using session::sqlite::placeholders;
using tools::span_guts;

namespace {

    // PRAGMA user_version of the current schema.
    constexpr int SCHEMA_VERSION = 1;

    // PRAGMA synchronous values
    constexpr int SYNC_OFF = 0;
    constexpr int SYNC_NORMAL = 1;
    constexpr int SYNC_FULL = 2;

    // Upper bound on the values bound into one `IN (...)` list, well below SQLite's limit on the
    // number of bound parameters in one statement.
    constexpr size_t MAX_IN_LIST = 500;

    // The foreign keys from the per-block tables to `blocks` are deferred because
    // BlockchainDB::add_block adds a block's transactions, outputs and key images before the
    // block's own row; all of them are written in the same write transaction, so the keys are
    // satisfied by the time it commits.  The cascade still happens immediately, so popping a block
    // is a single delete of its `blocks` row.
    //
    // outputs_tx exists because get_tx_amount_output_indices looks up outputs by
    // transaction (for every transaction served to syncing peers and wallets), which would
    // otherwise be a scan of the whole table.  It is partial so that outputs whose transaction has
    // been dropped (light mode) do not take up space in it.
    constexpr auto SCHEMA = R"(
CREATE TABLE blocks (
    height                INTEGER PRIMARY KEY,
    hash                  BLOB    NOT NULL UNIQUE CHECK(length(hash) = 32),
    timestamp             INTEGER NOT NULL,
    weight                INTEGER NOT NULL,
    long_term_weight      INTEGER NOT NULL,
    cumulative_difficulty INTEGER NOT NULL,
    coins_generated       INTEGER NOT NULL,
    rct_outputs           INTEGER NOT NULL,
    blob                  BLOB
) STRICT;

CREATE TABLE transactions (
    id            INTEGER PRIMARY KEY,
    hash          BLOB    NOT NULL UNIQUE CHECK(length(hash) = 32),
    height        INTEGER NOT NULL REFERENCES blocks(height) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    type          INTEGER NOT NULL,
    miner         INTEGER NOT NULL DEFAULT 0,
    unlock_time   INTEGER NOT NULL,
    unprunable    BLOB    NOT NULL,
    prunable      BLOB,
    prunable_hash BLOB    CHECK(prunable_hash IS NULL OR length(prunable_hash) = 32)
) STRICT;
CREATE INDEX transactions_height ON transactions(height);

CREATE TABLE outputs (
    id           INTEGER PRIMARY KEY,
    amount       INTEGER NOT NULL DEFAULT 0,
    amount_index INTEGER NOT NULL,
    height       INTEGER NOT NULL REFERENCES blocks(height) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    unlock_time  INTEGER NOT NULL,
    pubkey       BLOB    NOT NULL CHECK(length(pubkey) = 32),
    commitment   BLOB    NOT NULL CHECK(length(commitment) = 32),
    tx_id        INTEGER,
    local_index  INTEGER,
    blacklisted  INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE UNIQUE INDEX outputs_amount_index ON outputs(amount, amount_index);
CREATE INDEX        outputs_height       ON outputs(height);
CREATE INDEX        outputs_blacklisted  ON outputs(id) WHERE blacklisted;
CREATE INDEX        outputs_tx           ON outputs(tx_id, local_index) WHERE tx_id IS NOT NULL;

CREATE TABLE key_images (
    key_image BLOB    PRIMARY KEY CHECK(length(key_image) = 32),
    height    INTEGER NOT NULL REFERENCES blocks(height) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;
CREATE INDEX key_images_height ON key_images(height);

CREATE TABLE properties (
    key   TEXT PRIMARY KEY,
    value ANY NOT NULL
) STRICT, WITHOUT ROWID;

-- No foreign key to blocks: hardcoded checkpoints are stored at startup, long before the chain
-- reaches their heights.
CREATE TABLE checkpoints (
    height INTEGER PRIMARY KEY,
    hash   BLOB    NOT NULL CHECK(length(hash) = 32),
    type   INTEGER NOT NULL
) STRICT;
CREATE TABLE checkpoint_signatures (
    height      INTEGER NOT NULL REFERENCES checkpoints(height) ON DELETE CASCADE,
    voter_index INTEGER NOT NULL,
    signature   BLOB    NOT NULL CHECK(length(signature) = 64),
    PRIMARY KEY(height, voter_index)
) STRICT, WITHOUT ROWID;

CREATE TABLE txpool (
    hash                  BLOB    PRIMARY KEY CHECK(length(hash) = 32),
    blob                  BLOB    NOT NULL,
    weight                INTEGER NOT NULL,
    fee                   INTEGER NOT NULL,
    receive_time          INTEGER NOT NULL,
    last_relayed_time     INTEGER NOT NULL,
    max_used_block_height INTEGER NOT NULL,
    max_used_block_hash   BLOB    NOT NULL,
    last_failed_height    INTEGER NOT NULL,
    last_failed_hash      BLOB    NOT NULL,
    l2_height             INTEGER NOT NULL,
    kept_by_block         INTEGER NOT NULL,
    relayed               INTEGER NOT NULL,
    do_not_relay          INTEGER NOT NULL,
    double_spend_seen     INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

-- The service node list's short-term (0) and long-term (1) state blobs.
CREATE TABLE sn_data (
    long_term INTEGER PRIMARY KEY,
    blob      BLOB    NOT NULL
) STRICT, WITHOUT ROWID;

CREATE TABLE sn_states (
    height INTEGER PRIMARY KEY REFERENCES blocks(height) ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    blob   BLOB    NOT NULL
) STRICT;

CREATE TABLE sn_proofs (
    pubkey             BLOB    PRIMARY KEY CHECK(length(pubkey) = 32),
    timestamp          INTEGER NOT NULL,
    ip                 INTEGER NOT NULL,
    storage_https_port INTEGER NOT NULL,
    storage_omq_port   INTEGER NOT NULL,
    quorumnet_port     INTEGER NOT NULL,
    version            INTEGER NOT NULL,
    storage_version    INTEGER NOT NULL,
    lokinet_version    INTEGER NOT NULL
) STRICT, WITHOUT ROWID;
)";

    // Tables in the order they can be emptied in without violating a foreign key.
    constexpr std::array ALL_TABLES{
            "key_images",
            "outputs",
            "transactions",
            "sn_states",
            "blocks",
            "properties",
            "checkpoint_signatures",
            "checkpoints",
            "txpool",
            "sn_data",
            "sn_proofs"};

    // Views a byte string as unsigned chars, so that it binds as a BLOB rather than as TEXT (which
    // a STRICT BLOB column refuses).
    std::span<const unsigned char> as_blob(std::string_view s) {
        return {reinterpret_cast<const unsigned char*>(s.data()), s.size()};
    }

    std::string_view as_view(blob b) {
        return {reinterpret_cast<const char*>(b.data()), b.size()};
    }

    fs::path with_suffix(fs::path p, std::string_view suffix) {
        p += suffix;
        return p;
    }

    uint64_t chain_height(Connection& conn) {
        return as_u64(conn.prepared_get<int64_t>("SELECT COALESCE(MAX(height) + 1, 0) FROM blocks"));
    }

    [[noreturn]] void not_implemented(std::string_view method) {
        throw DB_ERROR("BlockchainSQLite::{} is not implemented yet"_format(method));
    }

    SQLite::Database& with_sync_mode(Connection& conn, int sync) {
        conn.sql.exec("PRAGMA synchronous = {}"_format(sync));
        return conn.sql;
    }

}  // namespace

// PRAGMA synchronous can't be changed inside a transaction, so it is set on the writing connection
// just before each write transaction begins: that is what lets safesyncmode() take effect on
// connections that already exist in the pool.
BlockchainSQLite::write_txn::write_txn(session::sqlite::Database& db, int sync) :
        conn{db.conn()}, tx{with_sync_mode(conn, sync), SQLite::TransactionBehavior::IMMEDIATE} {}

BlockchainSQLite::read_txn::read_txn(session::sqlite::Database& db) :
        conn{db.conn()}, tx{conn.sql, SQLite::TransactionBehavior::DEFERRED} {}

BlockchainSQLite::BlockchainSQLite(bool batch_transactions) :
        m_batch_transactions{batch_transactions} {}

BlockchainSQLite::~BlockchainSQLite() {
    if (m_open) {
        try {
            close();
        } catch (const std::exception& e) {
            log::error(logcat, "Failed to close the blockchain database: {}", e.what());
        }
    }
}

void BlockchainSQLite::check_open() const {
    if (!m_open)
        throw DB_ERROR("DB operation attempted on a not-open DB instance");
}

void BlockchainSQLite::open(const fs::path& filename, network_type, const int db_flags) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    if (m_open)
        throw DB_OPEN_FAILURE("Attempted to open db, but it's already open");

    m_read_only = db_flags & DBF_RDONLY;
    m_configured_sync = (db_flags & DBF_FASTEST) ? SYNC_OFF
                      : (db_flags & DBF_FAST)    ? SYNC_NORMAL
                      : (db_flags & DBF_SAFE)    ? SYNC_FULL
                                                 : SYNC_NORMAL;

    try {
        if (!m_read_only && filename.has_parent_path())
            fs::create_directories(filename.parent_path());

        m_sql = std::make_unique<session::sqlite::Database>(
                filename,
                session::sqlite::open_readonly{m_read_only},
                session::sqlite::open_create{!m_read_only});

        auto conn = m_sql->conn();
        auto version = conn.sql.execAndGet("PRAGMA user_version").getInt();
        if (version > SCHEMA_VERSION)
            throw DB_OPEN_FAILURE(
                    "{} has schema version {}, but this version of oxend only supports up to {}; "
                    "it was probably created by a newer version"_format(
                            filename, version, SCHEMA_VERSION));
        if (version == 0) {
            if (m_read_only)
                throw DB_OPEN_FAILURE(
                        "{} is not an initialized blockchain database, and cannot be initialized "
                        "when opened read-only"_format(filename));
            SQLite::Transaction tx{conn.sql, SQLite::TransactionBehavior::IMMEDIATE};
            conn.sql.exec(SCHEMA);
            conn.sql.exec("PRAGMA user_version = {}"_format(SCHEMA_VERSION));
            tx.commit();
            log::info(logcat, "Created blockchain database {}", filename);
        }
    } catch (const DB_OPEN_FAILURE&) {
        m_sql.reset();
        throw;
    } catch (const std::exception& e) {
        m_sql.reset();
        throw DB_OPEN_FAILURE("Failed to open blockchain database {}: {}"_format(filename, e.what()));
    }

    m_filename = filename;
    m_sync = m_configured_sync;
    m_open = true;
}

void BlockchainSQLite::close() {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    if (!m_open)
        return;
    if (m_write) {
        log::warning(logcat, "Closing the database with a write transaction open; rolling it back");
        m_write.reset();
        m_batch_active = false;
        m_writer = std::thread::id{};
    }
    {
        std::lock_guard lock{m_read_mutex};
        m_reads.clear();
    }
    sync();
    m_sql.reset();
    m_open = false;
}

void BlockchainSQLite::sync() {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    if (m_read_only)
        return;
    // Its own connection, so that this never runs inside a transaction of the calling thread.
    auto conn = m_sql->unique_conn();
    conn.sql.exec("PRAGMA wal_checkpoint(PASSIVE)");
}

void BlockchainSQLite::safesyncmode(const bool onoff) {
    log::info(logcat, "switching safe mode {}", onoff ? "on" : "off");
    m_sync = onoff ? SYNC_FULL : m_configured_sync;
}

void BlockchainSQLite::reset() {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    if (m_writer.load() != std::thread::id{})
        throw DB_ERROR("Cannot reset the database while a write transaction is open");
    end_read_txn(false);

    auto conn = m_sql->conn();
    SQLite::Transaction tx{conn.sql, SQLite::TransactionBehavior::IMMEDIATE};
    for (auto table : ALL_TABLES)
        conn.sql.exec("DELETE FROM {}"_format(table));
    tx.commit();
}

std::vector<fs::path> BlockchainSQLite::get_filenames() const {
    return {m_filename, with_suffix(m_filename, "-wal"), with_suffix(m_filename, "-shm")};
}

bool BlockchainSQLite::remove_data_file(const fs::path& filename) const {
    for (auto& f : {filename, with_suffix(filename, "-wal"), with_suffix(filename, "-shm")}) {
        std::error_code ec;
        fs::remove(f, ec);
        if (ec) {
            log::error(logcat, "Failed to remove {}: {}", f, ec.message());
            return false;
        }
    }
    return true;
}

std::string BlockchainSQLite::get_db_name() const {
    return std::string{SQLITE_DB_FILENAME};
}

void BlockchainSQLite::lock() {
    m_lock.lock();
}

bool BlockchainSQLite::try_lock() {
    return m_lock.try_lock();
}

void BlockchainSQLite::unlock() {
    m_lock.unlock();
}

bool BlockchainSQLite::is_read_only() const {
    return m_read_only;
}

uint64_t BlockchainSQLite::get_database_size() const {
    auto size = fs::file_size(m_filename);
    std::error_code ec;
    if (auto wal = fs::file_size(with_suffix(m_filename, "-wal"), ec); !ec)
        size += wal;
    return size;
}

void BlockchainSQLite::fixup(network_type nettype) {
    BlockchainDB::fixup(nettype);
}

// ---------------------------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------------------------

void BlockchainSQLite::begin_write(bool batch) {
    // A read transaction of this thread is on the same connection, and SQLite does not nest them.
    end_read_txn(true);
    m_write.emplace(*m_sql, m_sync.load());
    m_batch_active = batch;
    m_writer = std::this_thread::get_id();
}

void BlockchainSQLite::end_write(bool commit) {
    // m_write must be gone before other threads can see that there is no writer.
    auto done = oxen::defer([this] {
        m_write.reset();  // Rolls back if not committed
        m_batch_active = false;
        m_writer = std::thread::id{};
    });
    if (commit) {
        auto started = std::chrono::steady_clock::now();
        m_write->tx.commit();
        time_commit1 += std::chrono::steady_clock::now() - started;
    }
}

Connection& BlockchainSQLite::write_conn() {
    check_open();
    if (m_writer.load() != std::this_thread::get_id())
        throw DB_ERROR("Attempted a blockchain database write without an open write transaction");
    return m_write->conn;
}

template <std::invocable<Connection&> F>
void BlockchainSQLite::in_write_txn(F&& f) {
    check_open();
    if (m_writer.load() == std::this_thread::get_id()) {
        f(m_write->conn);
        return;
    }
    auto conn = m_sql->unique_conn();
    SQLite::Transaction tx{with_sync_mode(conn, m_sync.load()), SQLite::TransactionBehavior::IMMEDIATE};
    f(conn);
    tx.commit();
}

SQLite::Transaction* BlockchainSQLite::active_write_transaction() {
    if (m_writer.load() != std::this_thread::get_id())
        return nullptr;
    return &m_write->tx;
}

void BlockchainSQLite::block_wtxn_start() {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto writer = m_writer.load();
    if (writer == std::thread::id{}) {
        begin_write(false);
        return;
    }
    if (!m_batch_active)
        throw DB_ERROR_TXN_START(
                "Attempted to start new write txn when write txn already exists in {}"_format(
                        __func__));
    if (writer != std::this_thread::get_id())
        throw DB_ERROR_TXN_START(
                "Attempted to start new write txn when batch txn already exists in another thread in {}"_format(
                        __func__));
}

void BlockchainSQLite::block_wtxn_stop() {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    auto writer = m_writer.load();
    if (writer == std::thread::id{})
        throw DB_ERROR_TXN_START(
                "Attempted to stop write txn when no such txn exists in {}"_format(__func__));
    if (writer != std::this_thread::get_id())
        throw DB_ERROR_TXN_START(
                "Attempted to stop write txn from the wrong thread in {}"_format(__func__));
    if (!m_batch_active)
        end_write(true);
}

void BlockchainSQLite::block_wtxn_abort() {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    auto writer = m_writer.load();
    if (writer == std::thread::id{})
        throw DB_ERROR_TXN_START(
                "Attempted to abort write txn when no such txn exists in {}"_format(__func__));
    if (writer != std::this_thread::get_id())
        throw DB_ERROR_TXN_START(
                "Attempted to abort write txn from the wrong thread in {}"_format(__func__));
    if (!m_batch_active)
        end_write(false);
}

void BlockchainSQLite::set_batch_transactions(bool batch_transactions) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    if (batch_transactions && m_batch_transactions)
        log::info(logcat, "batch transaction mode already enabled, but asked to enable batch mode");
    m_batch_transactions = batch_transactions;
    log::info(logcat, "batch transactions {}", m_batch_transactions ? "enabled" : "disabled");
}

bool BlockchainSQLite::batch_start(uint64_t) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    if (!m_batch_transactions)
        throw DB_ERROR("batch transactions not enabled");
    if (m_batch_active)
        return false;
    if (m_writer.load() != std::thread::id{})
        throw DB_ERROR("batch transaction attempted, but a write transaction is already open");
    check_open();
    begin_write(true);
    log::trace(logcat, "batch transaction: begin");
    return true;
}

void BlockchainSQLite::batch_stop() {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    if (!m_batch_transactions)
        throw DB_ERROR("batch transactions not enabled");
    if (!m_batch_active)
        throw DB_ERROR("batch transaction not in progress");
    if (m_writer.load() != std::this_thread::get_id())
        throw DB_ERROR("batch transaction owned by other thread");
    end_write(true);
    log::trace(logcat, "batch transaction: end");
}

void BlockchainSQLite::batch_abort() {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    if (!m_batch_transactions)
        throw DB_ERROR("batch transactions not enabled");
    if (!m_batch_active)
        throw DB_ERROR("batch transaction not in progress");
    if (m_writer.load() != std::this_thread::get_id())
        throw DB_ERROR("batch transaction owned by other thread");
    end_write(false);
    log::trace(logcat, "batch transaction: aborted");
}

bool BlockchainSQLite::block_rtxn_start() const {
    check_open();
    auto me = std::this_thread::get_id();
    // The writer reads inside its own write transaction, which is how its reads see the writes it
    // has not yet committed.
    if (m_writer.load() == me)
        return false;
    std::lock_guard lock{m_read_mutex};
    if (m_reads.count(me))
        return false;
    m_reads.emplace(me, std::make_unique<read_txn>(*m_sql));
    return true;
}

void BlockchainSQLite::end_read_txn(bool commit) const {
    std::unique_ptr<read_txn> r;
    {
        std::lock_guard lock{m_read_mutex};
        auto it = m_reads.find(std::this_thread::get_id());
        if (it == m_reads.end())
            return;
        r = std::move(it->second);
        m_reads.erase(it);
    }
    if (commit)
        r->tx.commit();
}

void BlockchainSQLite::block_rtxn_stop() const {
    end_read_txn(true);
}

void BlockchainSQLite::block_rtxn_abort() const {
    end_read_txn(false);
}

std::optional<SQLite::Transaction> BlockchainSQLite::read_tx(Connection& conn) const {
    auto me = std::this_thread::get_id();
    if (m_writer.load() == me)
        return std::nullopt;
    {
        std::lock_guard lock{m_read_mutex};
        if (m_reads.count(me))
            return std::nullopt;
    }
    return std::make_optional<SQLite::Transaction>(conn.sql, SQLite::TransactionBehavior::DEFERRED);
}

// ---------------------------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------------------------

uint64_t BlockchainSQLite::add_block(
        const std::pair<block, std::string>& blk,
        size_t block_weight,
        uint64_t long_term_block_weight,
        const difficulty_type& cumulative_difficulty,
        const uint64_t& coins_generated,
        const std::vector<std::pair<transaction, std::string>>& txs) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    uint64_t new_height = chain_height(write_conn());
    BlockchainDB::add_block(
            blk, block_weight, long_term_block_weight, cumulative_difficulty, coins_generated, txs);
    return new_height + 1;
}

void BlockchainSQLite::add_block(
        const block& blk,
        size_t block_weight,
        uint64_t long_term_block_weight,
        const difficulty_type& cumulative_difficulty,
        const uint64_t& coins_generated,
        uint64_t num_rct_outs,
        const crypto::hash& blk_hash) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    auto& conn = write_conn();
    uint64_t height = chain_height(conn);

    if (conn.prepared_maybe_get<int64_t>(
                "SELECT height FROM blocks WHERE hash = ?", span_guts(blk_hash)))
        throw BLOCK_EXISTS("Attempting to add block that's already in the db");

    int64_t prev_rct_outputs = 0;
    if (height > 0) {
        auto [top_hash, rct_outputs] = conn.prepared_get<blob_guts<crypto::hash>, int64_t>(
                "SELECT hash, rct_outputs FROM blocks WHERE height = ?", as_i64(height - 1));
        if (static_cast<const crypto::hash&>(top_hash) != blk.prev_id)
            throw BLOCK_PARENT_DNE("Top block is not new block's parent");
        prev_rct_outputs = rct_outputs;
    }

    std::string block_blob = block_to_blob(blk);
    conn.prepared_exec(
            "INSERT INTO blocks (height, hash, timestamp, weight, long_term_weight, "
            "cumulative_difficulty, coins_generated, rct_outputs, blob) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            as_i64(height),
            span_guts(blk_hash),
            as_i64(blk.timestamp),
            as_i64(block_weight),
            as_i64(long_term_block_weight),
            as_i64(cumulative_difficulty),
            as_i64(coins_generated),
            prev_rct_outputs + as_i64(num_rct_outs),
            as_blob(block_blob));
}

void BlockchainSQLite::remove_block() {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    auto& conn = write_conn();
    uint64_t height = chain_height(conn);
    if (height == 0)
        throw BLOCK_DNE("Attempting to remove block from an empty blockchain");
    // Cascades to the block's transactions, outputs and key images.
    conn.prepared_exec("DELETE FROM blocks WHERE height = ?", as_i64(height - 1));
}

void BlockchainSQLite::pop_block(block& blk, std::vector<transaction>& txs) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();

    // Unlike BlockchainDB::pop_block this reads everything it returns before removing anything,
    // because removing the block's row also removes (via the cascade) its transactions.
    block_wtxn_start();
    try {
        if (height() == 0)
            throw BLOCK_DNE("Attempting to remove block from an empty blockchain");
        blk = get_top_block();
        for (auto it = blk.tx_hashes.rbegin(); it != blk.tx_hashes.rend(); ++it) {
            transaction tx;
            if (!get_tx(*it, tx) && !get_pruned_tx(*it, tx))
                throw DB_ERROR("Failed to get pruned or unpruned transaction from the db");
            txs.push_back(std::move(tx));
        }
        remove_block();
        block_wtxn_stop();
    } catch (...) {
        block_wtxn_abort();
        throw;
    }
}

bool BlockchainSQLite::block_exists(const crypto::hash& h, uint64_t* height) const {
    log::trace(logcat, "BlockchainSQLite::{} {}", __func__, h);
    check_open();
    auto conn = m_sql->conn();
    auto found = conn.prepared_maybe_get<int64_t>(
            "SELECT height FROM blocks WHERE hash = ?", span_guts(h));
    if (!found) {
        log::trace(logcat, "Block with hash {} not found in db", h);
        return false;
    }
    if (height)
        *height = as_u64(*found);
    return true;
}

uint64_t BlockchainSQLite::get_block_height(const crypto::hash& h) const {
    log::trace(logcat, "BlockchainSQLite::{} {}", __func__, h);
    uint64_t height;
    if (!block_exists(h, &height))
        throw BLOCK_DNE("Attempted to retrieve non-existent block height from hash {}"_format(h));
    return height;
}

template <typename T>
T BlockchainSQLite::get_block_column(
        uint64_t height, std::string_view column, std::string_view what) const {
    check_open();
    auto conn = m_sql->conn();
    auto value = conn.prepared_maybe_get<T>(
            "SELECT {} FROM blocks WHERE height = ?"_format(column), as_i64(height));
    if (!value)
        throw BLOCK_DNE(
                "Attempt to get {} from height {} failed -- block not in db"_format(what, height));
    return *std::move(value);
}

namespace {
    template <typename T>
        requires std::is_same_v<T, block> || std::is_same_v<T, block_header> ||
                 std::is_same_v<T, std::string>
    T convert_block_blob(std::string_view blob) {
        T result;
        if constexpr (std::is_same_v<T, block>) {
            if (!parse_and_validate_block_from_blob(blob, result))
                throw DB_ERROR("Failed to parse block from blob retrieved from the db");
        } else if constexpr (std::is_same_v<T, block_header>) {
            serialization::binary_string_unarchiver ba{blob};
            serialization::value(ba, result);
        } else {
            result = blob;
        }
        return result;
    }
}  // namespace

template <typename T>
static T get_converted_block(Connection& conn, uint64_t height, size_t* size) {
    for (auto data : conn.prepared_results<std::optional<blob>>(
                 "SELECT blob FROM blocks WHERE height = ?", as_i64(height))) {
        if (!data)
            throw BLOCK_DNE("Block at height {} is not stored in the db"_format(height));
        if (size)
            *size = data->size();
        return convert_block_blob<T>(as_view(*data));
    }
    throw BLOCK_DNE("Attempt to get block from height {} failed -- block not in db"_format(height));
}

block BlockchainSQLite::get_block_from_height(uint64_t height, size_t* size) const {
    log::trace(logcat, "BlockchainSQLite::{} {}", __func__, height);
    check_open();
    auto conn = m_sql->conn();
    return get_converted_block<block>(conn, height, size);
}

block_header BlockchainSQLite::get_block_header_from_height(uint64_t height) const {
    log::trace(logcat, "BlockchainSQLite::{} {}", __func__, height);
    check_open();
    auto conn = m_sql->conn();
    return get_converted_block<block_header>(conn, height, nullptr);
}

std::string BlockchainSQLite::get_block_blob_from_height(uint64_t height) const {
    log::trace(logcat, "BlockchainSQLite::{} {}", __func__, height);
    check_open();
    auto conn = m_sql->conn();
    return get_converted_block<std::string>(conn, height, nullptr);
}

std::string BlockchainSQLite::get_block_blob(const crypto::hash& h) const {
    log::trace(logcat, "BlockchainSQLite::{} {}", __func__, h);
    return get_block_blob_from_height(get_block_height(h));
}

std::vector<uint64_t> BlockchainSQLite::get_block_cumulative_rct_outputs(
        const std::vector<uint64_t>& heights) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    if (heights.empty())
        return {};

    auto conn = m_sql->conn();
    auto tx = read_tx(conn);
    const uint64_t top = chain_height(conn);
    for (auto h : heights)
        if (h >= top)
            throw BLOCK_DNE(
                    "Attempt to get rct distribution from height {} failed -- block size not in db"_format(
                            h));

    std::vector<uint64_t> res;
    res.reserve(heights.size());
    for (auto h : heights)
        res.push_back(as_u64(conn.prepared_get<int64_t>(
                "SELECT rct_outputs FROM blocks WHERE height = ?", as_i64(h))));
    return res;
}

uint64_t BlockchainSQLite::get_block_timestamp(const uint64_t& height) const {
    return as_u64(get_block_column<int64_t>(height, "timestamp", "timestamp"));
}

uint64_t BlockchainSQLite::get_top_block_timestamp() const {
    check_open();
    auto conn = m_sql->conn();
    return as_u64(conn.prepared_maybe_get<int64_t>(
                              "SELECT timestamp FROM blocks ORDER BY height DESC LIMIT 1")
                          .value_or(0));
}

size_t BlockchainSQLite::get_block_weight(const uint64_t& height) const {
    return as_u64(get_block_column<int64_t>(height, "weight", "block weight"));
}

static std::vector<uint64_t> get_block_weight_range(
        Connection& conn, std::string_view column, uint64_t start_height, size_t count) {
    std::vector<uint64_t> ret;
    for (auto w : conn.prepared_results<int64_t>(
                 "SELECT {} FROM blocks WHERE height >= ? ORDER BY height LIMIT ?"_format(column),
                 as_i64(start_height),
                 as_i64(count)))
        ret.push_back(as_u64(w));
    return ret;
}

std::vector<uint64_t> BlockchainSQLite::get_block_weights(uint64_t start_height, size_t count) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    auto tx = read_tx(conn);
    if (start_height >= chain_height(conn))
        throw DB_ERROR("Height {} not in blockchain"_format(start_height));
    return get_block_weight_range(conn, "weight", start_height, count);
}

std::vector<uint64_t> BlockchainSQLite::get_long_term_block_weights(
        uint64_t start_height, size_t count) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    auto tx = read_tx(conn);
    if (start_height >= chain_height(conn))
        throw DB_ERROR("Height {} not in blockchain"_format(start_height));
    return get_block_weight_range(conn, "long_term_weight", start_height, count);
}

difficulty_type BlockchainSQLite::get_block_cumulative_difficulty(const uint64_t& height) const {
    return as_u64(
            get_block_column<int64_t>(height, "cumulative_difficulty", "cumulative difficulty"));
}

difficulty_type BlockchainSQLite::get_block_difficulty(const uint64_t& height) const {
    difficulty_type diff = get_block_cumulative_difficulty(height);
    if (height != 0)
        diff -= get_block_cumulative_difficulty(height - 1);
    return diff;
}

uint64_t BlockchainSQLite::get_block_already_generated_coins(const uint64_t& height) const {
    return as_u64(get_block_column<int64_t>(height, "coins_generated", "generated coins"));
}

uint64_t BlockchainSQLite::get_block_long_term_weight(const uint64_t& height) const {
    return as_u64(get_block_column<int64_t>(height, "long_term_weight", "long term weight"));
}

crypto::hash BlockchainSQLite::get_block_hash_from_height(const uint64_t& height) const {
    return get_block_column<blob_guts<crypto::hash>>(height, "hash", "hash");
}

std::vector<block> BlockchainSQLite::get_blocks_range(const uint64_t& h1, const uint64_t& h2) const {
    std::vector<block> v;
    for (uint64_t height = h1; height <= h2; ++height)
        v.push_back(get_block_from_height(height));
    return v;
}

std::vector<crypto::hash> BlockchainSQLite::get_hashes_range(
        const uint64_t& h1, const uint64_t& h2) const {
    std::vector<crypto::hash> v;
    for (uint64_t height = h1; height <= h2; ++height)
        v.push_back(get_block_hash_from_height(height));
    return v;
}

crypto::hash BlockchainSQLite::top_block_hash(uint64_t* block_height) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    auto top = conn.prepared_maybe_get<int64_t, blob_guts<crypto::hash>>(
            "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1");
    if (block_height)
        *block_height = top ? as_u64(std::get<0>(*top)) : uint64_t{0} - 1;
    if (!top)
        return crypto::null<crypto::hash>;
    return std::get<1>(*top);
}

block BlockchainSQLite::get_top_block() const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    for (auto data : conn.prepared_results<std::optional<blob>>(
                 "SELECT blob FROM blocks ORDER BY height DESC LIMIT 1")) {
        if (!data)
            throw BLOCK_DNE("Top block is not stored in the db");
        return convert_block_blob<block>(as_view(*data));
    }
    return block{};
}

uint64_t BlockchainSQLite::height() const {
    check_open();
    auto conn = m_sql->conn();
    return chain_height(conn);
}

// ---------------------------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------------------------

uint64_t BlockchainSQLite::add_transaction_data(
        const crypto::hash&,
        const std::pair<transaction, std::string>& txp,
        const crypto::hash& tx_hash,
        const crypto::hash& tx_prunable_hash) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    auto& conn = write_conn();

    if (auto id = conn.prepared_maybe_get<int64_t>(
                "SELECT id FROM transactions WHERE hash = ?", span_guts(tx_hash)))
        throw TX_EXISTS(
                "Attempting to add transaction that's already in the db (tx id {})"_format(*id));

    const transaction& tx = txp.first;
    const std::string& blob = txp.second;

    size_t unprunable_size = tx.unprunable_size;
    if (unprunable_size == 0) {
        serialization::binary_string_archiver ba;
        try {
            const_cast<transaction&>(tx).serialize_base(ba);
        } catch (const std::exception& e) {
            throw DB_ERROR("Failed to serialize pruned tx: "s + e.what());
        }
        unprunable_size = ba.str().size();
    }
    if (unprunable_size > blob.size())
        throw DB_ERROR("pruned tx size is larger than tx size");

    std::string_view b{blob};
    std::optional<std::span<const unsigned char>> prunable_hash;
    if (tx.version >= txversion::v2_ringct)
        prunable_hash = span_guts(tx_prunable_hash);

    return as_u64(conn.prepared_get<int64_t>(
            "INSERT INTO transactions (id, hash, height, type, miner, unlock_time, unprunable, "
            "prunable, prunable_hash) VALUES ((SELECT COALESCE(MAX(id) + 1, 0) FROM transactions), "
            "?, (SELECT COALESCE(MAX(height) + 1, 0) FROM blocks), ?, ?, ?, ?, ?, ?) RETURNING id",
            span_guts(tx_hash),
            tx.type,
            tx.is_miner_tx() ? 1 : 0,
            as_i64(tx.unlock_time),
            as_blob(b.substr(0, unprunable_size)),
            as_blob(b.substr(unprunable_size)),
            prunable_hash));
}

void BlockchainSQLite::remove_transaction_data(const crypto::hash& tx_hash, const transaction&) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    auto& conn = write_conn();
    // Only reachable through BlockchainDB::remove_transaction, which this backend's pop_block does
    // not use (removing a block's row removes its transactions and outputs through the cascade),
    // so the rows may well already be gone: that is not an error.
    conn.prepared_exec(
            "DELETE FROM outputs WHERE tx_id = (SELECT id FROM transactions WHERE hash = ?)",
            span_guts(tx_hash));
    conn.prepared_exec("DELETE FROM transactions WHERE hash = ?", span_guts(tx_hash));
}

bool BlockchainSQLite::tx_exists(const crypto::hash& h) const {
    uint64_t tx_id;
    return tx_exists(h, tx_id);
}

bool BlockchainSQLite::tx_exists(const crypto::hash& h, uint64_t& tx_id) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    auto started = std::chrono::steady_clock::now();
    auto id = conn.prepared_maybe_get<int64_t>(
            "SELECT id FROM transactions WHERE hash = ?", span_guts(h));
    time_tx_exists += std::chrono::steady_clock::now() - started;
    if (!id) {
        log::info(logcat, "transaction with hash {} not found in db", h);
        return false;
    }
    tx_id = as_u64(*id);
    return true;
}

uint64_t BlockchainSQLite::get_tx_unlock_time(const crypto::hash& h) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    auto unlock = conn.prepared_maybe_get<int64_t>(
            "SELECT unlock_time FROM transactions WHERE hash = ?", span_guts(h));
    if (!unlock)
        throw TX_DNE("tx data with hash {} not found in db"_format(h));
    return as_u64(*unlock);
}

bool BlockchainSQLite::get_tx_blob(const crypto::hash& h, std::string& bd) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    for (auto [unprunable, prunable] : conn.prepared_results<blob, std::optional<blob>>(
                 "SELECT unprunable, prunable FROM transactions WHERE hash = ?", span_guts(h))) {
        if (!prunable)
            return false;
        bd.reserve(bd.size() + unprunable.size() + prunable->size());
        bd.append(as_view(unprunable));
        bd.append(as_view(*prunable));
        return true;
    }
    return false;
}

bool BlockchainSQLite::get_pruned_tx_blob(const crypto::hash& h, std::string& bd) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    for (auto unprunable : conn.prepared_results<blob>(
                 "SELECT unprunable FROM transactions WHERE hash = ?", span_guts(h))) {
        bd.assign(as_view(unprunable));
        return true;
    }
    return false;
}

bool BlockchainSQLite::get_pruned_tx_blobs_from(
        const crypto::hash& h, size_t count, std::vector<std::string>& bd) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    if (!count)
        return true;
    auto conn = m_sql->conn();
    bd.reserve(bd.size() + count);
    size_t found = 0;
    for (auto unprunable : conn.prepared_results<blob>(
                 "SELECT unprunable FROM transactions "
                 "WHERE id >= (SELECT id FROM transactions WHERE hash = ?) ORDER BY id LIMIT ?",
                 span_guts(h),
                 as_i64(count))) {
        bd.emplace_back(as_view(unprunable));
        ++found;
    }
    return found == count;
}

bool BlockchainSQLite::get_prunable_tx_blob(const crypto::hash& h, std::string& bd) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    for (auto prunable : conn.prepared_results<std::optional<blob>>(
                 "SELECT prunable FROM transactions WHERE hash = ?", span_guts(h))) {
        if (!prunable)
            return false;
        bd.assign(as_view(*prunable));
        return true;
    }
    return false;
}

bool BlockchainSQLite::get_prunable_tx_hash(
        const crypto::hash& tx_hash, crypto::hash& prunable_hash) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    auto row = conn.prepared_maybe_get<std::optional<blob_guts<crypto::hash>>>(
            "SELECT prunable_hash FROM transactions WHERE hash = ?", span_guts(tx_hash));
    if (!row || !*row)
        return false;
    prunable_hash = **row;
    return true;
}

uint64_t BlockchainSQLite::get_tx_count() const {
    check_open();
    auto conn = m_sql->conn();
    return as_u64(
            conn.prepared_get<int64_t>("SELECT COALESCE(MAX(id) + 1, 0) FROM transactions"));
}

std::vector<transaction> BlockchainSQLite::get_tx_list(
        const std::vector<crypto::hash>& hlist) const {
    std::vector<transaction> v;
    for (auto& h : hlist)
        v.push_back(get_tx(h));
    return v;
}

std::vector<uint64_t> BlockchainSQLite::get_tx_block_heights(
        const std::vector<crypto::hash>& hs) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    auto tx = read_tx(conn);
    std::vector<uint64_t> result;
    result.reserve(hs.size());
    for (const auto& h : hs)
        result.push_back(as_u64(conn.prepared_maybe_get<int64_t>(
                                            "SELECT height FROM transactions WHERE hash = ?",
                                            span_guts(h))
                                        .value_or(-1)));
    return result;
}

// ---------------------------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------------------------

uint64_t BlockchainSQLite::add_output(
        const crypto::hash& tx_hash,
        const tx_out& tx_output,
        const uint64_t& local_index,
        const uint64_t unlock_time,
        const rct::key* commitment) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    auto& conn = write_conn();

    if (!std::holds_alternative<txout_to_key>(tx_output.target))
        throw DB_ERROR("Wrong output type: expected txout_to_key");
    if (tx_output.amount == 0 && !commitment)
        throw DB_ERROR("RCT output without commitment");

    // Pre-RingCT outputs get the commitment they are implicitly verified against, so that every
    // row can be read the same way.
    const rct::key c = commitment ? *commitment : rct::zeroCommit(tx_output.amount);

    return as_u64(conn.prepared_get<int64_t>(
            "INSERT INTO outputs (id, amount, amount_index, height, unlock_time, pubkey, "
            "commitment, tx_id, local_index) VALUES ("
            "(SELECT COALESCE(MAX(id) + 1, 0) FROM outputs), ?1, "
            "(SELECT COALESCE(MAX(amount_index) + 1, 0) FROM outputs WHERE amount = ?1), "
            "(SELECT COALESCE(MAX(height) + 1, 0) FROM blocks), ?2, ?3, ?4, "
            "(SELECT id FROM transactions WHERE hash = ?5), ?6) RETURNING amount_index",
            as_i64(tx_output.amount),
            as_i64(unlock_time),
            span_guts(std::get<txout_to_key>(tx_output.target).key),
            span_guts(c),
            span_guts(tx_hash),
            as_i64(local_index)));
}

void BlockchainSQLite::add_tx_amount_output_indices(
        const uint64_t, const std::vector<uint64_t>&) {
    // Nothing to store: each output row already records its transaction and position in it, which
    // is what get_tx_amount_output_indices reads.
}

std::vector<std::vector<uint64_t>> BlockchainSQLite::get_tx_amount_output_indices(
        const uint64_t tx_id, size_t n_txes) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    std::vector<std::vector<uint64_t>> result(n_txes);
    if (!n_txes)
        return result;
    auto conn = m_sql->conn();
    for (auto [id, amount_index] : conn.prepared_results<int64_t, int64_t>(
                 "SELECT tx_id, amount_index FROM outputs WHERE tx_id BETWEEN ? AND ? "
                 "ORDER BY tx_id, local_index",
                 as_i64(tx_id),
                 as_i64(tx_id + n_txes - 1)))
        result[as_u64(id) - tx_id].push_back(as_u64(amount_index));
    return result;
}

uint64_t BlockchainSQLite::get_num_outputs(const uint64_t& amount) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    return as_u64(conn.prepared_get<int64_t>(
            "SELECT COALESCE(MAX(amount_index) + 1, 0) FROM outputs WHERE amount = ?",
            as_i64(amount)));
}

output_data_t BlockchainSQLite::get_output_key(
        const uint64_t& amount, const uint64_t& index, bool include_commitment) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    output_data_t ret{};
    bool found = false;
    if (include_commitment) {
        if (auto row = conn.prepared_maybe_get<
                       blob_guts<crypto::public_key>,
                       int64_t,
                       int64_t,
                       blob_guts<rct::key>>(
                    "SELECT pubkey, unlock_time, height, commitment FROM outputs "
                    "WHERE amount = ? AND amount_index = ?",
                    as_i64(amount),
                    as_i64(index))) {
            auto& [pubkey, unlock_time, height, commitment] = *row;
            ret = {pubkey, as_u64(unlock_time), as_u64(height), commitment};
            found = true;
        }
    } else if (auto row = conn.prepared_maybe_get<blob_guts<crypto::public_key>, int64_t, int64_t>(
                       "SELECT pubkey, unlock_time, height FROM outputs "
                       "WHERE amount = ? AND amount_index = ?",
                       as_i64(amount),
                       as_i64(index))) {
        auto& [pubkey, unlock_time, height] = *row;
        ret.pubkey = pubkey;
        ret.unlock_time = as_u64(unlock_time);
        ret.height = as_u64(height);
        found = true;
    }
    if (!found)
        throw OUTPUT_DNE(
                "Attempting to get output pubkey by index, but key does not exist: amount {}, "
                "index {}"_format(amount, index));
    return ret;
}

void BlockchainSQLite::get_output_key(
        std::span<const uint64_t> amounts,
        const std::vector<uint64_t>& offsets,
        std::vector<output_data_t>& outputs,
        bool allow_partial) const {
    if (amounts.size() != 1 && amounts.size() != offsets.size())
        throw DB_ERROR("Invalid sizes of amounts and offets");
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    outputs.clear();
    outputs.reserve(offsets.size());

    auto amount_at = [&](size_t i) { return amounts.size() == 1 ? amounts[0] : amounts[i]; };

    // Intent: each distinct amount's wanted indices, deduplicated, so that each can be fetched with
    // as few IN-list queries as possible.
    std::unordered_map<uint64_t, std::vector<int64_t>> wanted;
    for (size_t i = 0; i < offsets.size(); ++i)
        wanted[amount_at(i)].push_back(as_i64(offsets[i]));

    auto conn = m_sql->conn();
    auto tx = read_tx(conn);

    std::unordered_map<uint64_t, std::unordered_map<uint64_t, output_data_t>> found;
    for (auto& [amount, indices] : wanted) {
        std::sort(indices.begin(), indices.end());
        indices.erase(std::unique(indices.begin(), indices.end()), indices.end());
        auto& found_amount = found[amount];
        for (size_t start = 0; start < indices.size(); start += MAX_IN_LIST) {
            auto end = std::min(indices.size(), start + MAX_IN_LIST);
            SQLite::Statement st{
                    conn.sql,
                    "SELECT amount_index, pubkey, unlock_time, height, commitment FROM outputs "
                    "WHERE amount = ? AND amount_index IN ({})"_format(
                            placeholders(static_cast<int>(end - start)))};
            session::sqlite::bind_oneshot(
                    st,
                    as_i64(amount),
                    bind_each{indices.begin() + start, indices.begin() + end});
            while (st.executeStep()) {
                auto [amount_index, pubkey, unlock_time, height, commitment] = session::sqlite::
                        get<int64_t,
                            blob_guts<crypto::public_key>,
                            int64_t,
                            int64_t,
                            blob_guts<rct::key>>(st);
                found_amount.emplace(
                        as_u64(amount_index),
                        output_data_t{pubkey, as_u64(unlock_time), as_u64(height), commitment});
            }
        }
    }

    for (size_t i = 0; i < offsets.size(); ++i) {
        const uint64_t amount = amount_at(i);
        auto& found_amount = found[amount];
        auto it = found_amount.find(offsets[i]);
        if (it == found_amount.end()) {
            if (allow_partial) {
                log::debug(logcat, "Partial result: {}/{}", outputs.size(), offsets.size());
                break;
            }
            throw OUTPUT_DNE(
                    "Attempting to get output pubkey by global index (amount {}, index {}, count "
                    "{}), but key does not exist (current height {})"_format(
                            amount, offsets[i], get_num_outputs(amount), height()));
        }
        outputs.push_back(it->second);
    }
}

tx_out_index BlockchainSQLite::get_output_tx_and_index_from_global(const uint64_t& index) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    auto row = conn.prepared_maybe_get<blob_guts<crypto::hash>, int64_t>(
            "SELECT t.hash, o.local_index FROM outputs o JOIN transactions t ON t.id = o.tx_id "
            "WHERE o.id = ?",
            as_i64(index));
    if (!row)
        throw OUTPUT_DNE("output with given index not in db");
    return {std::get<0>(*row), as_u64(std::get<1>(*row))};
}

tx_out_index BlockchainSQLite::get_output_tx_and_index(
        const uint64_t& amount, const uint64_t& index) const {
    std::vector<tx_out_index> indices;
    get_output_tx_and_index(amount, {index}, indices);
    return indices.front();
}

void BlockchainSQLite::get_output_tx_and_index(
        const uint64_t& amount,
        const std::vector<uint64_t>& offsets,
        std::vector<tx_out_index>& indices) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    indices.clear();
    indices.reserve(offsets.size());
    auto conn = m_sql->conn();
    auto tx = read_tx(conn);
    for (auto index : offsets) {
        auto row = conn.prepared_maybe_get<blob_guts<crypto::hash>, int64_t>(
                "SELECT t.hash, o.local_index FROM outputs o "
                "JOIN transactions t ON t.id = o.tx_id WHERE o.amount = ? AND o.amount_index = ?",
                as_i64(amount),
                as_i64(index));
        if (!row)
            throw OUTPUT_DNE("Attempting to get output by index, but key does not exist");
        indices.emplace_back(std::get<0>(*row), as_u64(std::get<1>(*row)));
    }
}

// Blacklisted outputs are only ever the RingCT (amount 0) outputs of a transaction, and what
// consumers (the wallet's ring member selection, via RPC) compare the list against are their amount
// indices, so those are what this stores and returns, as the LMDB backend does.
void BlockchainSQLite::get_output_blacklist(std::vector<uint64_t>& blacklist) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    for (auto amount_index : conn.prepared_results<int64_t>(
                 "SELECT amount_index FROM outputs WHERE blacklisted ORDER BY amount_index"))
        blacklist.push_back(as_u64(amount_index));
}

void BlockchainSQLite::add_output_blacklist(std::vector<uint64_t> const& blacklist) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    if (blacklist.empty())
        return;
    auto& conn = write_conn();
    std::vector<int64_t> indices;
    indices.reserve(blacklist.size());
    for (auto i : blacklist)
        indices.push_back(as_i64(i));
    std::sort(indices.begin(), indices.end());
    indices.erase(std::unique(indices.begin(), indices.end()), indices.end());

    for (size_t start = 0; start < indices.size(); start += MAX_IN_LIST) {
        auto end = std::min(indices.size(), start + MAX_IN_LIST);
        SQLite::Statement st{
                conn.sql,
                "UPDATE outputs SET blacklisted = 1 WHERE amount = 0 AND amount_index IN ({})"_format(
                        placeholders(static_cast<int>(end - start)))};
        session::sqlite::bind_oneshot(st, bind_each{indices.begin() + start, indices.begin() + end});
        if (auto updated = st.exec(); static_cast<size_t>(updated) != end - start)
            throw DB_ERROR("Failed to blacklist outputs: {} of {} outputs not found"_format(
                    end - start - updated, end - start));
    }
}

// ---------------------------------------------------------------------------------------------
// Key images
// ---------------------------------------------------------------------------------------------

void BlockchainSQLite::add_spent_key(const crypto::key_image& k_image) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    auto& conn = write_conn();
    if (conn.prepared_maybe_get<int>(
                "SELECT 1 FROM key_images WHERE key_image = ?", span_guts(k_image)))
        throw KEY_IMAGE_EXISTS("Attempting to add spent key image that's already in the db");
    conn.prepared_exec(
            "INSERT INTO key_images (key_image, height) "
            "VALUES (?, (SELECT COALESCE(MAX(height) + 1, 0) FROM blocks))",
            span_guts(k_image));
}

void BlockchainSQLite::remove_spent_key(const crypto::key_image& k_image) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    auto& conn = write_conn();
    conn.prepared_exec("DELETE FROM key_images WHERE key_image = ?", span_guts(k_image));
}

bool BlockchainSQLite::has_key_image(const crypto::key_image& img) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    return conn
            .prepared_maybe_get<int>(
                    "SELECT 1 FROM key_images WHERE key_image = ?", span_guts(img))
            .has_value();
}

// ---------------------------------------------------------------------------------------------
// Iteration
// ---------------------------------------------------------------------------------------------

bool BlockchainSQLite::for_all_key_images(std::function<bool(const crypto::key_image&)> f) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    for (auto ki : conn.prepared_results<blob_guts<crypto::key_image>>(
                 "SELECT key_image FROM key_images ORDER BY key_image"))
        if (!f(ki))
            return false;
    return true;
}

bool BlockchainSQLite::for_blocks_range(
        const uint64_t& h1,
        const uint64_t& h2,
        std::function<bool(uint64_t, const crypto::hash&, const cryptonote::block&)> f) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    for (auto [height, data] : conn.prepared_results<int64_t, std::optional<blob>>(
                 "SELECT height, blob FROM blocks WHERE height BETWEEN ? AND ? ORDER BY height",
                 as_i64(h1),
                 as_i64(h2))) {
        if (!data)
            throw DB_ERROR("Block at height {} is not stored in the db"_format(height));
        auto b = convert_block_blob<block>(as_view(*data));
        crypto::hash hash;
        if (!get_block_hash(b, hash))
            throw DB_ERROR("Failed to get block hash from blob retrieved from the db");
        if (!f(as_u64(height), hash, b))
            return false;
    }
    return true;
}

bool BlockchainSQLite::for_all_transactions(
        std::function<bool(const crypto::hash&, const cryptonote::transaction&)> f,
        bool pruned) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    for (auto [hash, unprunable, prunable] :
         conn.prepared_results<blob_guts<crypto::hash>, blob, std::optional<blob>>(
                 "SELECT hash, unprunable, prunable FROM transactions ORDER BY id")) {
        transaction tx;
        std::string bd{as_view(unprunable)};
        if (pruned) {
            if (!parse_and_validate_tx_base_from_blob(bd, tx))
                throw DB_ERROR("Failed to parse tx from blob retrieved from the db");
        } else {
            if (!prunable)
                throw DB_ERROR("Failed to get prunable tx data from the db");
            bd.append(as_view(*prunable));
            if (!parse_and_validate_tx_from_blob(bd, tx))
                throw DB_ERROR("Failed to parse tx from blob retrieved from the db");
        }
        if (!f(hash, tx))
            return false;
    }
    return true;
}

bool BlockchainSQLite::for_all_outputs(
        std::function<bool(
                uint64_t amount, const crypto::hash& tx_hash, uint64_t height, size_t tx_idx)> f)
        const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    for (auto [amount, tx_hash, height, local_index] :
         conn.prepared_results<int64_t, blob_guts<crypto::hash>, int64_t, int64_t>(
                 "SELECT o.amount, t.hash, o.height, o.local_index FROM outputs o "
                 "JOIN transactions t ON t.id = o.tx_id ORDER BY o.amount, o.amount_index"))
        if (!f(as_u64(amount), tx_hash, as_u64(height), as_u64(local_index)))
            return false;
    return true;
}

bool BlockchainSQLite::for_all_outputs(
        uint64_t amount, const std::function<bool(uint64_t height)>& f) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    for (auto height : conn.prepared_results<int64_t>(
                 "SELECT height FROM outputs WHERE amount = ? ORDER BY amount_index",
                 as_i64(amount)))
        if (!f(as_u64(height)))
            return false;
    return true;
}

// ---------------------------------------------------------------------------------------------
// Checkpoints
// ---------------------------------------------------------------------------------------------

void BlockchainSQLite::update_block_checkpoint(checkpoint_t const& checkpoint) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    auto& conn = write_conn();
    const auto height = as_i64(checkpoint.height);
    conn.prepared_exec(
            "INSERT INTO checkpoints (height, hash, type) VALUES (?, ?, ?) "
            "ON CONFLICT(height) DO UPDATE SET hash = excluded.hash, type = excluded.type",
            height,
            span_guts(checkpoint.block_hash),
            checkpoint.type);
    conn.prepared_exec("DELETE FROM checkpoint_signatures WHERE height = ?", height);
    for (const auto& sig : checkpoint.signatures)
        conn.prepared_exec(
                "INSERT INTO checkpoint_signatures (height, voter_index, signature) "
                "VALUES (?, ?, ?)",
                height,
                sig.voter_index,
                span_guts(sig.signature));
}

void BlockchainSQLite::remove_block_checkpoint(uint64_t height) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    auto& conn = write_conn();
    conn.prepared_exec("DELETE FROM checkpoints WHERE height = ?", as_i64(height));
}

static checkpoint_t load_checkpoint(
        Connection& conn, int64_t height, const crypto::hash& hash, checkpoint_type type) {
    checkpoint_t checkpoint{};
    checkpoint.type = type;
    checkpoint.height = as_u64(height);
    checkpoint.block_hash = hash;
    for (auto [voter_index, signature] : conn.prepared_results<int, blob_guts<crypto::signature>>(
                 "SELECT voter_index, signature FROM checkpoint_signatures WHERE height = ? "
                 "ORDER BY voter_index",
                 height))
        checkpoint.signatures.emplace_back(static_cast<uint16_t>(voter_index), signature);
    return checkpoint;
}

bool BlockchainSQLite::get_block_checkpoint(uint64_t height, checkpoint_t& checkpoint) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    auto tx = read_tx(conn);
    auto row = conn.prepared_maybe_get<blob_guts<crypto::hash>, checkpoint_type>(
            "SELECT hash, type FROM checkpoints WHERE height = ?", as_i64(height));
    if (!row)
        return false;
    checkpoint = load_checkpoint(conn, as_i64(height), std::get<0>(*row), std::get<1>(*row));
    return true;
}

bool BlockchainSQLite::get_top_checkpoint(checkpoint_t& checkpoint) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    auto tx = read_tx(conn);
    auto row = conn.prepared_maybe_get<int64_t, blob_guts<crypto::hash>, checkpoint_type>(
            "SELECT height, hash, type FROM checkpoints ORDER BY height DESC LIMIT 1");
    if (!row)
        return false;
    auto& [height, hash, type] = *row;
    checkpoint = load_checkpoint(conn, height, hash, type);
    return true;
}

// The same results as the LMDB backend's walk: start and end are clamped to the stored checkpoints'
// heights, and the result is the checkpoints between them (both inclusive), in order from start
// towards end (so descending if start > end), at most num_desired_checkpoints of them.
std::vector<checkpoint_t> BlockchainSQLite::get_checkpoints_range(
        uint64_t start, uint64_t end, size_t num_desired_checkpoints) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    std::vector<checkpoint_t> result;

    auto conn = m_sql->conn();
    auto tx = read_tx(conn);
    auto [bottom, top] = conn.prepared_get<std::optional<int64_t>, std::optional<int64_t>>(
            "SELECT MIN(height), MAX(height) FROM checkpoints");
    if (!bottom)
        return result;

    start = std::clamp(start, as_u64(*bottom), as_u64(*top));
    end = std::clamp(end, as_u64(*bottom), as_u64(*top));
    const int64_t limit = num_desired_checkpoints == GET_ALL_CHECKPOINTS
                                ? -1
                                : as_i64(num_desired_checkpoints);

    std::vector<std::tuple<int64_t, blob_guts<crypto::hash>, checkpoint_type>> rows;
    for (auto row : conn.prepared_results<int64_t, blob_guts<crypto::hash>, checkpoint_type>(
                 start <= end ? "SELECT height, hash, type FROM checkpoints "
                                "WHERE height BETWEEN ? AND ? ORDER BY height LIMIT ?"
                              : "SELECT height, hash, type FROM checkpoints "
                                "WHERE height BETWEEN ? AND ? ORDER BY height DESC LIMIT ?",
                 as_i64(std::min(start, end)),
                 as_i64(std::max(start, end)),
                 limit))
        rows.push_back(std::move(row));

    result.reserve(rows.size());
    for (auto& [height, hash, type] : rows)
        result.push_back(load_checkpoint(conn, height, hash, type));
    return result;
}

// ---------------------------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------------------------

uint64_t BlockchainSQLite::get_max_block_size() {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    auto size = conn.prepared_maybe_get<int64_t>(
            "SELECT value FROM properties WHERE key = 'max_block_size'");
    return size ? as_u64(*size) : std::numeric_limits<uint64_t>::max();
}

void BlockchainSQLite::add_max_block_size(uint64_t sz) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    in_write_txn([&](Connection& conn) {
        conn.prepared_exec(
                "INSERT INTO properties (key, value) VALUES ('max_block_size', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = MAX(value, excluded.value)",
                as_i64(sz));
    });
}

// ---------------------------------------------------------------------------------------------
// Txpool
// ---------------------------------------------------------------------------------------------

namespace {
    constexpr auto TXPOOL_META_COLUMNS =
            "weight, fee, receive_time, last_relayed_time, max_used_block_height, "
            "max_used_block_hash, last_failed_height, last_failed_hash, l2_height, kept_by_block, "
            "relayed, do_not_relay, double_spend_seen"sv;

    // Reads the TXPOOL_META_COLUMNS of the current row of `st`, which start at column `col`.
    txpool_tx_meta_t read_txpool_meta(SQLite::Statement& st, int col) {
        auto u64 = [&](int i) { return as_u64(st.getColumn(col + i).getInt64()); };
        auto u8 = [&](int i) { return static_cast<uint8_t>(st.getColumn(col + i).getInt()); };
        auto hash = [&](int i) -> crypto::hash {
            return blob_guts<crypto::hash>{st.getColumn(col + i)};
        };
        txpool_tx_meta_t meta{};
        meta.weight = u64(0);
        meta.fee = u64(1);
        meta.receive_time = u64(2);
        meta.last_relayed_time = u64(3);
        meta.max_used_block_height = u64(4);
        meta.max_used_block_id = hash(5);
        meta.last_failed_height = u64(6);
        meta.last_failed_id = hash(7);
        meta.l2_height = u64(8);
        meta.kept_by_block = u8(9);
        meta.relayed = u8(10);
        meta.do_not_relay = u8(11);
        meta.double_spend_seen = u8(12);
        return meta;
    }
}  // namespace

void BlockchainSQLite::add_txpool_tx(
        const crypto::hash& txid, const std::string& blob, const txpool_tx_meta_t& meta) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    if (blob.empty())
        throw DB_ERROR("Attempting to add txpool tx with empty blob");
    // Adding a tx that is already there replaces it, as it always has with LMDB.
    in_write_txn([&](Connection& conn) {
        conn.prepared_exec(
                "INSERT OR REPLACE INTO txpool (hash, blob, {}) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"_format(TXPOOL_META_COLUMNS),
                span_guts(txid),
                as_blob(blob),
                as_i64(meta.weight),
                as_i64(meta.fee),
                as_i64(meta.receive_time),
                as_i64(meta.last_relayed_time),
                as_i64(meta.max_used_block_height),
                span_guts(meta.max_used_block_id),
                as_i64(meta.last_failed_height),
                span_guts(meta.last_failed_id),
                as_i64(meta.l2_height),
                meta.kept_by_block,
                meta.relayed,
                meta.do_not_relay,
                static_cast<int>(meta.double_spend_seen));
    });
}

void BlockchainSQLite::update_txpool_tx(const crypto::hash& txid, const txpool_tx_meta_t& meta) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    in_write_txn([&](Connection& conn) {
        auto updated = conn.prepared_exec(
                "UPDATE txpool SET weight = ?, fee = ?, receive_time = ?, last_relayed_time = ?, "
                "max_used_block_height = ?, max_used_block_hash = ?, last_failed_height = ?, "
                "last_failed_hash = ?, l2_height = ?, kept_by_block = ?, relayed = ?, "
                "do_not_relay = ?, double_spend_seen = ? WHERE hash = ?",
                as_i64(meta.weight),
                as_i64(meta.fee),
                as_i64(meta.receive_time),
                as_i64(meta.last_relayed_time),
                as_i64(meta.max_used_block_height),
                span_guts(meta.max_used_block_id),
                as_i64(meta.last_failed_height),
                span_guts(meta.last_failed_id),
                as_i64(meta.l2_height),
                meta.kept_by_block,
                meta.relayed,
                meta.do_not_relay,
                static_cast<int>(meta.double_spend_seen),
                span_guts(txid));
        if (updated == 0)
            throw DB_ERROR("Error finding txpool tx meta to update");
    });
}

uint64_t BlockchainSQLite::get_txpool_tx_count(bool include_unrelayed_txes) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    return as_u64(conn.prepared_get<int64_t>(
            include_unrelayed_txes ? "SELECT COUNT(*) FROM txpool"
                                   : "SELECT COUNT(*) FROM txpool WHERE NOT do_not_relay"));
}

bool BlockchainSQLite::txpool_has_tx(const crypto::hash& txid) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    return conn.prepared_maybe_get<int>("SELECT 1 FROM txpool WHERE hash = ?", span_guts(txid))
            .has_value();
}

void BlockchainSQLite::remove_txpool_tx(const crypto::hash& txid) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    in_write_txn([&](Connection& conn) {
        conn.prepared_exec("DELETE FROM txpool WHERE hash = ?", span_guts(txid));
    });
}

bool BlockchainSQLite::get_txpool_tx_meta(const crypto::hash& txid, txpool_tx_meta_t& meta) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    auto st = conn.prepared_bind(
            "SELECT {} FROM txpool WHERE hash = ?"_format(TXPOOL_META_COLUMNS), span_guts(txid));
    if (!st->executeStep())
        return false;
    meta = read_txpool_meta(st, 0);
    return true;
}

bool BlockchainSQLite::get_txpool_tx_blob(const crypto::hash& txid, std::string& bd) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    for (auto data : conn.prepared_results<blob>(
                 "SELECT blob FROM txpool WHERE hash = ?", span_guts(txid))) {
        if (data.empty())
            throw DB_ERROR("Error finding txpool tx blob: tx is present, but data is empty");
        bd.assign(as_view(data));
        return true;
    }
    return false;
}

std::string BlockchainSQLite::get_txpool_tx_blob(const crypto::hash& txid) const {
    std::string bd;
    if (!get_txpool_tx_blob(txid, bd))
        throw DB_ERROR("Tx not found in txpool: ");
    return bd;
}

bool BlockchainSQLite::for_all_txpool_txes(
        std::function<bool(const crypto::hash&, const txpool_tx_meta_t&, const std::string*)> f,
        bool include_blob,
        bool include_unrelayed_txes) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    auto st = conn.prepared_st(
            "SELECT hash, {}{} FROM txpool{} ORDER BY hash"_format(
                    TXPOOL_META_COLUMNS,
                    include_blob ? ", blob" : "",
                    include_unrelayed_txes ? "" : " WHERE NOT do_not_relay"));
    std::string bd;
    while (st->executeStep()) {
        crypto::hash txid = blob_guts<crypto::hash>{st->getColumn(0)};
        auto meta = read_txpool_meta(st, 1);
        if (include_blob)
            bd.assign(as_view(blob{st->getColumn(14)}));
        if (!f(txid, meta, include_blob ? &bd : nullptr))
            return false;
    }
    return true;
}

// ---------------------------------------------------------------------------------------------
// Service nodes
// ---------------------------------------------------------------------------------------------

void BlockchainSQLite::set_service_node_data(const std::string& data, bool long_term) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    in_write_txn([&](Connection& conn) {
        conn.prepared_exec(
                "INSERT OR REPLACE INTO sn_data (long_term, blob) VALUES (?, ?)",
                long_term ? 1 : 0,
                as_blob(data));
    });
}

bool BlockchainSQLite::get_service_node_data(std::string& data, bool long_term) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    for (auto b : conn.prepared_results<blob>(
                 "SELECT blob FROM sn_data WHERE long_term = ?", long_term ? 1 : 0)) {
        data.assign(as_view(b));
        return true;
    }
    return false;
}

void BlockchainSQLite::delete_service_node_data(bool long_term) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    in_write_txn([&](Connection& conn) {
        conn.prepared_exec("DELETE FROM sn_data WHERE long_term = ?", long_term ? 1 : 0);
    });
}

void BlockchainSQLite::clear_service_node_data() {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    in_write_txn([&](Connection& conn) {
        conn.prepared_exec("DELETE FROM sn_data");
        conn.prepared_exec("DELETE FROM sn_states");
    });
}

void BlockchainSQLite::put_service_node_archive(uint64_t height, std::string_view data) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    in_write_txn([&](Connection& conn) {
        conn.prepared_exec(
                "INSERT OR REPLACE INTO sn_states (height, blob) VALUES (?, ?)",
                as_i64(height),
                as_blob(data));
    });
}

std::optional<std::string> BlockchainSQLite::get_service_node_archive(uint64_t height) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    for (auto b : conn.prepared_results<blob>(
                 "SELECT blob FROM sn_states WHERE height = ?", as_i64(height)))
        return std::string{as_view(b)};
    return std::nullopt;
}

std::vector<uint64_t> BlockchainSQLite::get_service_node_archive_heights() const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    std::vector<uint64_t> heights;
    for (auto h : conn.prepared_results<int64_t>("SELECT height FROM sn_states ORDER BY height"))
        heights.push_back(as_u64(h));
    return heights;
}

void BlockchainSQLite::delete_service_node_archives(uint64_t begin, uint64_t end) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    in_write_txn([&](Connection& conn) {
        // Heights are stored as signed integers, so an `end` past the largest one (as given to
        // delete everything from `begin` on) has to become an open upper bound.
        if (end > static_cast<uint64_t>(std::numeric_limits<int64_t>::max()))
            conn.prepared_exec("DELETE FROM sn_states WHERE height >= ?", as_i64(begin));
        else
            conn.prepared_exec(
                    "DELETE FROM sn_states WHERE height >= ? AND height < ?",
                    as_i64(begin),
                    as_i64(end));
    });
}

namespace {
    constexpr auto SN_PROOF_COLUMNS =
            "pubkey, timestamp, ip, storage_https_port, storage_omq_port, quorumnet_port, version, "
            "storage_version, lokinet_version"sv;

    int64_t pack_version(const std::array<uint16_t, 3>& v) {
        return v[0] * int64_t{1'000'000} + v[1] * int64_t{1'000} + v[2];
    }
    std::array<uint16_t, 3> unpack_version(int64_t v) {
        return {static_cast<uint16_t>(v / 1'000'000),
                static_cast<uint16_t>(v / 1'000 % 1'000),
                static_cast<uint16_t>(v % 1'000)};
    }

    // Updates `info` from the SN_PROOF_COLUMNS of the current row of `st`, as the LMDB backend's
    // stored proof does: the effective timestamp only ever moves forward.
    void update_proof_info(SQLite::Statement& st, service_nodes::proof_info& info) {
        if (!info.proof)
            info.proof = std::make_unique<uptime_proof::Proof>();
        info.timestamp = as_u64(st.getColumn(1).getInt64());
        if (info.timestamp > info.effective_timestamp)
            info.effective_timestamp = info.timestamp;
        info.proof->public_ip = static_cast<uint32_t>(st.getColumn(2).getInt64());
        info.proof->storage_https_port = static_cast<uint16_t>(st.getColumn(3).getInt());
        info.proof->storage_omq_port = static_cast<uint16_t>(st.getColumn(4).getInt());
        info.proof->qnet_port = static_cast<uint16_t>(st.getColumn(5).getInt());
        info.proof->version = unpack_version(st.getColumn(6).getInt64());
        info.proof->storage_server_version = unpack_version(st.getColumn(7).getInt64());
        info.proof->lokinet_version = unpack_version(st.getColumn(8).getInt64());
        // Since SN_PK_IS_ED25519 a service node's pubkey is its ed25519 pubkey, so that is not
        // stored separately.
        info.update_pubkey(blob_guts<crypto::ed25519_public_key>{st.getColumn(0)});
    }
}  // namespace

bool BlockchainSQLite::get_service_node_proof(
        const crypto::public_key& pubkey, service_nodes::proof_info& proof) const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    auto conn = m_sql->conn();
    auto st = conn.prepared_bind(
            "SELECT {} FROM sn_proofs WHERE pubkey = ?"_format(SN_PROOF_COLUMNS), span_guts(pubkey));
    if (!st->executeStep())
        return false;
    update_proof_info(st, proof);
    return true;
}

void BlockchainSQLite::set_service_node_proof(
        const crypto::public_key& pubkey, const service_nodes::proof_info& proof) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    const auto& p = *proof.proof;
    in_write_txn([&](Connection& conn) {
        conn.prepared_exec(
                "INSERT OR REPLACE INTO sn_proofs ({}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"_format(
                        SN_PROOF_COLUMNS),
                span_guts(pubkey),
                as_i64(proof.timestamp),
                p.public_ip,
                p.storage_https_port,
                p.storage_omq_port,
                p.qnet_port,
                pack_version(p.version),
                pack_version(p.storage_server_version),
                pack_version(p.lokinet_version));
    });
}

std::unordered_map<crypto::public_key, service_nodes::proof_info>
BlockchainSQLite::get_all_service_node_proofs() const {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    check_open();
    std::unordered_map<crypto::public_key, service_nodes::proof_info> result;
    auto conn = m_sql->conn();
    auto st = conn.prepared_st("SELECT {} FROM sn_proofs"_format(SN_PROOF_COLUMNS));
    while (st->executeStep()) {
        crypto::public_key pubkey = blob_guts<crypto::public_key>{st->getColumn(0)};
        update_proof_info(st, result[pubkey]);
    }
    return result;
}

bool BlockchainSQLite::remove_service_node_proof(const crypto::public_key& pubkey) {
    log::trace(logcat, "BlockchainSQLite::{}", __func__);
    bool removed = false;
    in_write_txn([&](Connection& conn) {
        removed = conn.prepared_exec("DELETE FROM sn_proofs WHERE pubkey = ?", span_guts(pubkey)) >
                  0;
    });
    return removed;
}

// ---------------------------------------------------------------------------------------------
// Not yet implemented
// ---------------------------------------------------------------------------------------------

void BlockchainSQLite::add_alt_block(
        const crypto::hash&, const alt_block_data_t&, const std::string&, const std::string*) {
    not_implemented(__func__);
}
bool BlockchainSQLite::get_alt_block(
        const crypto::hash&, alt_block_data_t*, std::string*, std::string*) const {
    not_implemented(__func__);
}
void BlockchainSQLite::remove_alt_block(const crypto::hash&) {
    not_implemented(__func__);
}
uint64_t BlockchainSQLite::get_alt_block_count() {
    not_implemented(__func__);
}
void BlockchainSQLite::drop_alt_blocks() {
    not_implemented(__func__);
}
bool BlockchainSQLite::for_all_alt_blocks(
        std::function<
                bool(const crypto::hash&,
                     const alt_block_data_t&,
                     const std::string*,
                     const std::string*)>,
        bool) const {
    not_implemented(__func__);
}

std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> BlockchainSQLite::get_output_histogram(
        const std::vector<uint64_t>&, bool, uint64_t, uint64_t) const {
    not_implemented(__func__);
}
bool BlockchainSQLite::get_output_distribution(
        uint64_t, uint64_t, uint64_t, std::vector<uint64_t>&, uint64_t&) const {
    not_implemented(__func__);
}


}  // namespace cryptonote
