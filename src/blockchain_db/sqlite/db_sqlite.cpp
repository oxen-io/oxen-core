// Copyright (c) 2021, The Oxen Project
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

#include "db_sqlite.h"

#include <common/exception.h>
#include <common/formattable.h>
#include <common/guts.h>
#include <cryptonote_basic/hardfork.h>
#include <cryptonote_config.h>
#include <cryptonote_core/blockchain.h>
#include <cryptonote_core/cryptonote_tx_utils.h>
#include <cryptonote_core/sesh_transition/sesh_transition.h>
#include <fmt/core.h>
#include <sodium.h>
#include <sqlite3.h>

#include <cassert>
#include <type_traits>
#include <variant>

#include "cryptonote_basic/cryptonote_basic.h"
#include "snapshots.h"

namespace {

auto logcat = oxen::log::Cat("blockchain.db.sqlite");

// Helper for putting addresses in log statements: this does the actual conversion to string on
// demand, so that this can be cheaply used in debug log statements to avoid the expensive stringify
// when not needed.
struct log_addr {
    const eth::address* eth = nullptr;
    const cryptonote::account_public_address* oxen = nullptr;
    cryptonote::network_type nettype = cryptonote::network_type::UNDEFINED;
    mutable std::optional<std::string> cache;

    log_addr(
            const std::variant<eth::address, cryptonote::account_public_address>& a,
            cryptonote::network_type nettype) :
            eth{std::get_if<eth::address>(&a)},
            oxen{std::get_if<cryptonote::account_public_address>(&a)},
            nettype{nettype} {}
    explicit log_addr(const eth::address& a) : eth{&a} {}
    explicit log_addr(
            const cryptonote::account_public_address& a, cryptonote::network_type nettype) :
            oxen{&a}, nettype{nettype} {}

    const std::string& to_string() const {
        if (!cache)
            cache = eth ? "{}"_format(*eth) : get_account_address_as_str(nettype, 0, *oxen);
        return *cache;
    }
};

}  // namespace

template <>
inline constexpr bool formattable::via_to_string<log_addr> = true;

namespace cryptonote {

using namespace fmt::literals;
using db::as_i64;
using db::as_u64;
using session::sqlite::blob;
using session::sqlite::blob_guts;
using session::sqlite::Connection;
using tools::span_guts;

// The DB height as seen by `conn`, which may differ from the `height` member when used from a
// thread other than the one adding blocks.
static uint64_t db_height(Connection& conn) {
    return as_u64(conn.prepared_get<int64_t>("SELECT height FROM batch_db_info"));
}

// Readers on other threads make more than one query (for the height, and the values at that
// height), so need them in one read transaction to see a consistent state of the DB.  On a
// connection already in a transaction (i.e. the thread adding blocks) that one is used instead.
static std::optional<SQLite::Transaction> read_tx(Connection& conn) {
    if (!sqlite3_get_autocommit(conn.sql.getHandle()))
        return std::nullopt;
    return std::make_optional<SQLite::Transaction>(conn.sql, SQLite::TransactionBehavior::DEFERRED);
}

BlockchainSQLite::BlockchainSQLite(network_type nettype, std::filesystem::path db_path) :
        db{std::move(db_path)}, nettype{nettype} {
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);
    height = 0;

    auto conn = db.conn();
    if (!conn.table_exists("batched_payments_accrued"))
        create_schema();
    upgrade_schema();

    height = db_height(conn);

    auto row_count = batch_payments_accrued_row_count();
    auto [recent_count, recent_min_height, recent_max_height] = conn.prepared_get<int, int, int>(
            "SELECT COUNT(*), MIN(height), MAX(height) FROM batched_payments_accrued_recent");
    auto [archive_count, archive_min_height, archive_max_height] = conn.prepared_get<int, int, int>(
            "SELECT COUNT(*), MIN(height), MAX(height) FROM batched_payments_accrued_archive");

    log::info(
            globallogcat,
            "{} rows, {} recent [blks {}-{}], {} historical [blks {}-{}] loaded @ height: {}",
            row_count,
            recent_count,
            recent_min_height,
            recent_max_height,
            archive_count,
            archive_min_height,
            archive_max_height,
            height);
}

// Used in queries.  NOTE: does not include `height`!
static constexpr auto BATCHED_PAYMENTS_COLS =
        "address, amount, payout_offset, lifetime_locked_stakes, lifetime_unlocked_stakes, "
        "lifetime_liquidated_stakes, lifetime_rewards"sv;
static std::string CREATE_BATCHED_PAYMENTS(std::string_view table_name, bool with_height) {
    std::string result = R"(CREATE TABLE {table}(
  address                    BLOB NOT NULL,
  amount                     INTEGER NOT NULL DEFAULT 0, -- Claimable amount (lifetime rewards and unlocked stakes)
  payout_offset              INTEGER,)"_format("table"_a = table_name);

    if (with_height)
        result += R"(
  height                     INTEGER NOT NULL DEFAULT 0, -- Height at which the row was recorded)";

    result += R"(
  lifetime_locked_stakes     INTEGER NOT NULL DEFAULT 0,
  lifetime_unlocked_stakes   INTEGER NOT NULL DEFAULT 0,
  lifetime_liquidated_stakes INTEGER NOT NULL DEFAULT 0,
  lifetime_rewards           INTEGER NOT NULL DEFAULT 0, -- Lifetime accumulated rewards (i.e. not including unlocked stakes)
  PRIMARY KEY({pk})
  CHECK(amount >= 0)
);)"_format("table"_a = table_name, "pk"_a = with_height ? "height, address" : "address");

    return result;
}

// Used in queries.
static constexpr auto DELAYED_PAYMENTS_COLS =
        "eth_address, amount, payout_height, height, block_height, block_tx_index, "
        "contributor_index, liquidation_amount"sv;
static std::string CREATE_DELAYED_PAYMENTS(std::string_view table_name) {
    return R"(
CREATE TABLE {table}(
  eth_address        BLOB    NOT NULL,
  amount             INTEGER NOT NULL,           -- Original amount the 'eth_address' staked
  payout_height      INTEGER NOT NULL,           -- Height that the payment was given to 'eth_address' and removed from this table
  height             INTEGER NOT NULL,           -- Height that the payment was added to the DB
  block_height       INTEGER NOT NULL,           -- Height that the TX with the SN exit event was mined in
  block_tx_index     INTEGER NOT NULL,           -- Index of the TX in the block at 'block_height'
  contributor_index  INTEGER NOT NULL,           -- Index of the contributor in a multi-contributor SN's stake
  liquidation_amount INTEGER NOT NULL DEFAULT 0, -- Liquidation penalty (if applicable), 0 otherwise
  UNIQUE(block_height, block_tx_index, contributor_index)
  CHECK(amount            >= 0)
  CHECK(payout_height     >= 0)
  CHECK(height            >= 0)
  CHECK(block_height      >= 0)
  CHECK(block_tx_index    >= 0)
  CHECK(contributor_index >= 0)
);
CREATE INDEX {table}_height_idx ON {table}(height);
   )"_format("table"_a = table_name);
}

// Constants for PRAGMA user_version for DB fixup handling:
constexpr int FIXUP_DELAYED_PAYMENT_REWARDS = 2;

constexpr int FIXUP_MAX = FIXUP_DELAYED_PAYMENT_REWARDS;

void BlockchainSQLite::create_schema() {
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);
    auto& netconf = get_config(nettype);

    auto conn = db.conn();
    assert(!conn.table_exists("batched_payments_accrued"));
    conn.sql.exec(CREATE_BATCHED_PAYMENTS("batched_payments_accrued", false));
    conn.sql.exec(
            R"(CREATE INDEX IF NOT EXISTS batched_payments_accrued_payout_offset_idx ON batched_payments_accrued(payout_offset);
               CREATE TABLE IF NOT EXISTS batch_db_info(height INTEGER NOT NULL);
               INSERT INTO  batch_db_info(height) VALUES(0);)");
    conn.sql.exec("PRAGMA user_version = {}"_format(FIXUP_MAX));
    log::debug(logcat, "Database setup complete");
}

std::optional<SQLite::Transaction> BlockchainSQLite::begin_tx(
        Connection& conn, SQLite::TransactionBehavior behave) {
    if (batch) {
        assert(std::this_thread::get_id() == batch_thread);
        return std::nullopt;
    }
    return std::make_optional<SQLite::Transaction>(conn.sql, behave);
}

BlockchainSQLite::Batch::Batch(BlockchainSQLite& sql) :
        sql{sql},
        conn{sql.db.conn()},
        tx{std::in_place, conn.sql, SQLite::TransactionBehavior::IMMEDIATE} {
    assert(!sql.batch);
    sql.batch = this;
    sql.batch_thread = std::this_thread::get_id();
}

void BlockchainSQLite::Batch::block_added() {
    if (++blocks < BLOCKS)
        return;
    log::debug(logcat, "committing batched blocks at height {}", sql.height);
    tx->commit();
    tx.emplace(conn.sql, SQLite::TransactionBehavior::IMMEDIATE);
    blocks = 0;
}

void BlockchainSQLite::Batch::finish() {
    tx->commit();
    tx.reset();
}

BlockchainSQLite::Batch::~Batch() {
    sql.batch = nullptr;
    if (!tx)
        return;
    try {
        tx.reset();  // Rolls back
        sql.height = db_height(conn);
        log::warning(
                logcat,
                "Rolled back unfinished batch of blocks; rewards DB is now at height {}",
                sql.height);
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to roll back unfinished batch of blocks: {}", e.what());
    }
}

static bool has_column(Connection& conn, std::string_view table, std::string_view column) {
    for (const auto& col : conn.get_columns(table))
        if (col.name == column)
            return true;
    return false;
}

void BlockchainSQLite::upgrade_schema() {
    auto conn = db.conn();
    bool have_offset = has_column(conn, "batched_payments_accrued", "payout_offset");

    auto& netconf = get_config(nettype);

    auto transaction = begin_tx(conn);
    // NOTE: Rename 'batched_payments_accrued_archive' 'archive_height' column to 'height'. This
    // unifies the height label across the batch payment, recent and archive table making querying
    // from them require less code.
    // TODO: Eventually we can remove this code (doing so will make it impossible to upgrade a
    // pre-HF20 oxend database).
    if (has_column(conn, "batched_payments_accrued_archive", "archive_height"))
        conn.sql.exec(
                "ALTER TABLE batched_payments_accrued_archive RENAME COLUMN archive_height to "
                "height;\n");

    if (!have_offset) {
        log::debug(logcat, "Adding payout_offset to batching db");

        conn.sql.exec(R"(
            ALTER TABLE batched_payments_accrued ADD COLUMN payout_offset INTEGER;
            CREATE INDEX batched_payments_accrued_payout_offset_idx ON batched_payments_accrued(payout_offset);
        )");

        constexpr auto all_addresses = "SELECT address FROM batched_payments_accrued";
        for (const auto& address : conn.prepared_results<std::string>(all_addresses)) {
            address_parse_info addr_info{};
            get_account_address_from_str(addr_info, nettype, address);
            auto offset = static_cast<int>(addr_info.address.modulus(netconf.BATCHING_INTERVAL));
            conn.prepared_exec(
                    "UPDATE batched_payments_accrued SET payout_offset = ? WHERE address = ?",
                    offset,
                    address);
        }

        auto count = conn.prepared_get<int>(
                "SELECT COUNT(*) FROM batched_payments_accrued WHERE payout_offset IS NULL");

        if (count != 0) {
            constexpr auto error =
                    "Batching db update to add offsets failed: not all addresses were converted";
            log::error(logcat, error);
            throw oxen::traced<std::runtime_error>{error};
        }
    }

    // Remove old no-longer-used tables and triggers
    conn.sql.exec(R"(
        DROP TRIGGER IF EXISTS batch_payments_prune;
        DROP TRIGGER IF EXISTS batch_payments_delete_empty;
        DROP TRIGGER IF EXISTS clear_archive;
        DROP TRIGGER IF EXISTS clear_recent;
        DROP TRIGGER IF EXISTS rollback_payment;
        DROP TRIGGER IF EXISTS delayed_payments_prune;

        DROP TABLE IF EXISTS batched_payments_raw;
        DROP VIEW  IF EXISTS batched_payments_paid;
        DROP TABLE IF EXISTS batched_payments_accrued_raw;
        DROP VIEW  IF EXISTS batched_payments_accrued_paid;

        DROP TABLE IF EXISTS delayed_payments_archive;
        DROP TABLE IF EXISTS delayed_payments_recent;
    )");

    // delayed_payments: Stores time-locked payments that will/did pay out when 'payout_height'
    // is/was reached. This applies when SNs exit the network via dereg: upon confirmation of the
    // associated event removing the node from the ETH side, we create a row in here which is where
    // we store the locked stakes until they are due to be released back into the claimable rewards
    // amount (currently 30 days after dereg, on mainnet).
    //
    // Note that these rows also serve as their own archive, i.e. they are not cleared after being
    // paid: rows with a payout_height > current height are to-be-paid, while other rows are archive
    // rows that are used if the blockchain reorgs.
    if (!conn.table_exists("delayed_payments")) {
        log::debug(logcat, "Adding delayed_payments table to batching db");
        conn.sql.exec(CREATE_DELAYED_PAYMENTS("delayed_payments"));
    }

    // Not all of these were present if the table was created before 11.4.0:
    conn.sql.exec(R"(
        CREATE INDEX IF NOT EXISTS delayed_payments_height_idx ON delayed_payments(height);
        CREATE INDEX IF NOT EXISTS delayed_payments_payout_height_idx ON delayed_payments(payout_height);
        CREATE INDEX IF NOT EXISTS delayed_payments_eth_address_idx ON delayed_payments(eth_address);
    )");

    // NOTE: The archive table stores copies of 'batch_payments_accrued' rows at
    // intervals of 'HISTORY_ARCHIVE_INTERVAL' blocks in a rolling window of
    // 'HISTORY_ARCHIVE_KEEP_WINDOW'
    //
    // The recent table is effectively identical to the above, but because we insert and delete on
    // it for *every* height, partitioning the recent rows in a separate table makes deletions of
    // stale rows a bit faster because we can use a simple `height < x` query rather than a much
    // more complicated (and much less indexable) condition that also worries about not deleting
    // long-term archive rows.
    for (auto table : {"batched_payments_accrued_archive", "batched_payments_accrued_recent"}) {
        if (!conn.table_exists(table)) {
            log::debug(logcat, "Adding {} to batching db", table);
            conn.sql.exec(CREATE_BATCHED_PAYMENTS(table, true));
        }
    }

    // NOTE: Add new stakes fields to batch accrued table row for tracking
    {
        std::string_view tables[] = {
                "batched_payments_accrued",
                "batched_payments_accrued_archive",
                "batched_payments_accrued_recent",
        };

        std::string_view fields[] = {
                "lifetime_locked_stakes",
                "lifetime_unlocked_stakes",
                "lifetime_liquidated_stakes",
                "lifetime_rewards",
        };

        for (auto it : tables)
            for (auto field : fields)
                if (!has_column(conn, it, field))
                    conn.sql.exec("ALTER TABLE {} ADD COLUMN {} INTEGER NOT NULL DEFAULT 0;"_format(
                            it, field));
    }

    // Before 11.4.0 the state of the accrued tables was rather variable, depending on when they
    // were created and the range over which a rescan happened.
    // - they might or might not have a CHECK constraint on the non-consensus accounting fields
    //   (lifetime_locked_stakes, etc.) that could, in the presence of bugs or unexpected network
    //   events (such as purges) result in a check constraint failure in the middle of a block
    //   update, with catastrophic effects leaving the current SN state half-mutated.
    //   - the CHECK constraints are present on new 11.3.0+ installs that sync from scratch
    //   - the CHECK constraints are missing on installs that upgraded to 11.2.0, *unless*:
    //   - the CHECK constraints are present on 11.3.0+ installs that rescanned the SN state from
    //     some height before HF19.
    // - for archive/recent, they might or might not have a UNIQUE(address, height) constraint
    //   - conditions are essentially the same as the as for the CHECK constraints presence above.
    //   - in either case, these should be a PRIMARY KEY(height, address) instead (not the reversed
    //     order), so that we don't need a separate index on `height`, and because we never query
    //     these tables by address.
    // - payout_offset was NOT NULL (and no longer is) and might or might not have a default, and if
    //   present could be 0 or -1 depending on how the table was created and/or upgraded in past
    //   releases.
    // - amount might or might not have a default, and might have been declared as either INTEGER or
    //   BIGINT
    // - archive/recent have an index on `height` which is unnecessary with the above primary key
    //   and should be dropped.
    //
    // We also, starting with the 11.4 release, change various table values that never have
    // sub-atomic values (such as lifetime_unlocked_stakes) to store atomic amounts instead.
    // (amount and lifetime_rewards also become atomic values, but not here: that happens starting
    // at HF22; before HF22 they contain subatomic values that affect consensus).
    //
    // Finally, because we have to recreate anything anyway, we also convert all the addresses to
    // binary so that we don't have to parse and encode them every time we go from/to the database.
    //
    // And so here we basically look for anything that isn't our current CREATE TABLE statement and,
    // if we find it, recreate the whole thing (copying current data from old to new to avoid
    // needing a rescan).
    bool need_11_4_migration = false;
    // The most recent change we've made is to make `payout_offset` nullable, so that's what we
    // look for here for our decision of whether to migrate:
    for (const auto& col : conn.get_columns("batched_payments_accrued")) {
        if (col.name == "payout_offset"sv) {
            need_11_4_migration = col.not_null;
            break;
        }
    }
    if (need_11_4_migration) {
        // Drop the potentially referencing triggers (they will get recreated below) because
        // otherwise the DROP and/or ALTER below will fail because of SQLite design limitations.
        conn.sql.exec(R"(
            DROP TRIGGER IF EXISTS make_recent;
            DROP TRIGGER IF EXISTS make_archive;
            DROP TRIGGER IF EXISTS clear_recent_and_archive;
            DROP TRIGGER IF EXISTS delayed_payments_prune;
        )");

        conn.sql.createFunction(
                "oxen_upgrade_addr_to_blob",
                1,
                true,
                this,
                [](sqlite3_context* ctx, int argc, sqlite3_value** argv) {
                    assert(argc == 1);
                    if (sqlite3_value_type(argv[0]) != SQLITE_TEXT) {
                        sqlite3_result_error(
                                ctx, "oxen_uint128_cast cannot be called with non-TEXT value", -1);
                        return;
                    }
                    std::string_view addr{
                            reinterpret_cast<const char*>(sqlite3_value_text(argv[0])),
                            static_cast<size_t>(sqlite3_value_bytes(argv[0]))};

                    static_assert(std::is_trivially_copyable_v<eth::address>);
                    if (addr.size() == 2 /*0x*/ + 2 * sizeof(eth::address)) {
                        if (eth::address a; tools::try_load_from_hex_guts(addr, a))
                            return sqlite3_result_blob(ctx, &a, sizeof(a), SQLITE_TRANSIENT);
                        return sqlite3_result_error(
                                ctx,
                                "Invalid value: failed to parse 42-byte input as hex ETH address",
                                -1);
                    }

                    auto* self = static_cast<BlockchainSQLite*>(sqlite3_user_data(ctx));
                    address_parse_info info{};
                    static_assert(std::is_trivially_copyable_v<account_public_address>);
                    if (get_account_address_from_str(info, self->nettype, addr))
                        return sqlite3_result_blob(
                                ctx, &info.address, sizeof(info.address), SQLITE_TRANSIENT);
                    return sqlite3_result_error(
                            ctx, "Invalid value: failed to parse input as an OXEN address", -1);
                });

        for (auto table :
             {"batched_payments_accrued",
              "batched_payments_accrued_archive",
              "batched_payments_accrued_recent"}) {

            const bool is_primary = table == "batched_payments_accrued"sv;

            log::debug(logcat, "Migrating {} table", table);

            {
                SQLite::Statement no_subatomic_stakes{
                        conn.sql,
                        "SELECT COUNT(*) FROM {table} WHERE"
                        " lifetime_locked_stakes % {factor} != 0 OR"
                        " lifetime_unlocked_stakes % {factor} != 0 OR"
                        " lifetime_liquidated_stakes % {factor} != 0"_format(
                                "table"_a = table, "factor"_a = BATCH_REWARD_FACTOR)};
                if (int uhoh = session::sqlite::exec_and_get<int>(no_subatomic_stakes); uhoh > 0)
                    throw oxen::traced<std::logic_error>{
                            "Internal error: 11.4.0 transition code found {} {} rows with"
                            " unexpected sub-atomic stake values"_format(uhoh, table)};
            }

            conn.sql.exec(CREATE_BATCHED_PAYMENTS(
                    "{}_tmp"_format(table),
                    /*with_height=*/!is_primary));

            conn.sql.exec(
                    R"(
            INSERT INTO {table}_tmp
                (address, amount, payout_offset, lifetime_locked_stakes, lifetime_unlocked_stakes,
                    lifetime_liquidated_stakes, lifetime_rewards{maybe_height})
            SELECT oxen_upgrade_addr_to_blob(address),
                amount,
                CASE WHEN length(address) = 42 THEN NULL ELSE payout_offset END AS payout_offset,
                lifetime_locked_stakes / {factor},
                lifetime_unlocked_stakes / {factor},
                lifetime_liquidated_stakes / {factor},
                lifetime_rewards
                {maybe_height}
            FROM {table}
            )"_format("table"_a = table,
                      "maybe_height"_a = is_primary ? "" : ", height",
                      "factor"_a = BATCH_REWARD_FACTOR));

            conn.sql.exec(R"(
                DROP TABLE {table};
                ALTER TABLE {table}_tmp RENAME TO {table};
            )"_format("table"_a = table));
            if (is_primary)
                conn.sql.exec(
                        "CREATE INDEX IF NOT EXISTS {table}_payout_offset_idx ON "
                        "{table}(payout_offset)"
                        " WHERE payout_offset IS NOT NULL"_format("table"_a = table));

            // HF22 accounting fixup.  See cryptonote_core/service_node_fixes.cpp for details.  This
            // really belongs there, but we can't easily get there from here (in terms of available
            // objects, or linkage).  Note that these fields are only used to distinguish between
            // rewards and stakes, and don't actually award anything, but keep the accounting code
            // consistent.
            //
            // NOTE: if the above table recreation changes sometime after HF22, this should be fixed
            // to detect that and not apply the fixup again!  (There is a safeguard, below, that
            // checks and aborts the upgrade if that happens by mistake.)
            //
            int64_t fixup_height = 0;
            reward_money fixup_amount;
            std::string fixup_addr;
            switch (nettype) {
                case network_type::MAINNET:
                    fixup_height = 1852106;
                    fixup_amount = reward_money::from_coin(25000'000000000);
                    fixup_addr = "0x3ada97d64272ac01cf832e930259f078f337e5a5";
                    break;
                case network_type::TESTNET:
                    fixup_height = 790188;
                    fixup_amount = reward_money::from_coin(20000'000000000);
                    fixup_addr = "0xb0cefd61ddb88176fb972955341adc6c1d05230e";
                    break;
                default: break;
            }

            if (fixup_height) {
                auto db_h = conn.prepared_get<int64_t>("SELECT height FROM batch_db_info");
                if (is_hard_fork_at_least(nettype, hf::hf22_eth_fixup, db_h)) {
                    log::critical(
                            logcat,
                            "DB setup error: HF21 transition code attempted to run on a database "
                            "already on HF22");
                    throw oxen::traced<std::logic_error>{
                            "HF21 transition code called on HF22 database"};
                }
                if (is_primary) {
                    if (db_h > fixup_height) {
                        // This amount should have been subtracted when processing the purge in
                        // block 1852106, but if the database didn't have this new table yet then it
                        // also had the same bug that missed this subtraction (because it was the
                        // first purge in a block with two purges, and only the last purge was being
                        // properly accounted for):
                        session::sqlite::exec_query(
                                conn.sql,
                                "UPDATE {} SET lifetime_locked_stakes = lifetime_locked_stakes - ? "
                                "WHERE address = ?"_format(table),
                                fixup_amount.to_db_atomic(),
                                fixup_addr);
                        log::debug(
                                logcat,
                                "Applied block 1852106 purge accounting fixup to {}",
                                table);
                    }
                } else {
                    session::sqlite::exec_query(
                            conn.sql,
                            "UPDATE {} SET lifetime_locked_stakes = lifetime_locked_stakes - ? "
                            "WHERE address = ? AND height >= ?"_format(table),
                            // As above, this will only run on a HF21 db.
                            fixup_amount.to_db_atomic(),
                            fixup_addr,
                            fixup_height);
                    log::debug(logcat, "Applied block 1852106 purge accounting fixup to {}", table);
                }
            }
        }

        // Finally we also replace the delayed_payments tables to use blob addresses, and to store
        // atomic amounts rather than milli-atomics as the code now expects atomics (and despite
        // being stored as milli-atomics, these values could never have subatomic components).

        // Safety check first: there should not actually be any sub-atomic values in the table.
        {
            SQLite::Statement no_subatomic_amount{
                    conn.sql,
                    "SELECT COUNT(*) FROM delayed_payments WHERE"
                    " amount % {factor} != 0 OR liquidation_amount % {factor} != 0"_format(
                            "factor"_a = BATCH_REWARD_FACTOR)};
            if (int uhoh = session::sqlite::exec_and_get<int>(no_subatomic_amount); uhoh > 0)
                throw oxen::traced<std::logic_error>{
                        "Internal error: 11.4.0 transition code found {} delayed_payments rows with"
                        " unexpected sub-atomic amounts"_format(uhoh)};
        }

        conn.sql.exec(CREATE_DELAYED_PAYMENTS("delayed_payments_tmp"));
        conn.sql.exec(
                R"(
        INSERT INTO delayed_payments_tmp
            (eth_address, amount, liquidation_amount,
                payout_height, height, block_height, block_tx_index, contributor_index)
        SELECT
            oxen_upgrade_addr_to_blob(eth_address),
            amount / {factor},
            liquidation_amount / {factor},
            payout_height, height, block_height, block_tx_index, contributor_index
        FROM delayed_payments;

        DROP TABLE delayed_payments;
        ALTER TABLE delayed_payments_tmp RENAME TO delayed_payments;

        )"_format("factor"_a = BATCH_REWARD_FACTOR));
    }

    // This code block could be moved, someday, into schema creation to avoid needing to recreate
    // the trigger on every startup.  However both HF20 and the copied/recreated tables above update
    // things in such a way that this needs to be created anyway and so, pending some database
    // upgrade refactor, we just always do it to be safe.
    //
    // - make_recent
    // - make_archive
    // - clear_recent_and_archive
    //
    // Triggers to maintain the table when blocks are added or the blockchain
    // detaches with the following format specifiers. Note that _order_ of the
    // triggers is important as the operations has side effects on tables.
    {
        conn.sql.exec(
                R"(
        -- Saves the current payments into their recent table(s) for the current height
        DROP   TRIGGER IF EXISTS make_recent;
        CREATE TRIGGER           make_recent AFTER UPDATE ON batch_db_info
        FOR EACH ROW WHEN NEW.height > OLD.height BEGIN
            -- Batched payments
            INSERT INTO batched_payments_accrued_recent ({batched_fields}, height)
                SELECT {batched_fields}, NEW.height FROM batched_payments_accrued;

            DELETE FROM batched_payments_accrued_recent WHERE height < (NEW.height - {recent_keep});
        END;

        -- Keep a copy of all the rows for payments for this height if it's on an archival
        -- interval. It allows the DB to gracefully handle block re-orgs without having to
        -- recalculate from scratch.
        --
        -- We archive state at every 'HISTORY_ARCHIVE_INTERVAL' height and we prune the stored
        -- archive to encompass the past 'HISTORY_ARCHIVE_WINDOW' blocks worth of history.
        --
        -- When pruning we floor to the closest interval to make the SQL table match the equivalent
        -- pruning math ('cull_height') in the SNL at 'process_block()'.
        --
        -- For delayed_payments we drop any rows that paid out before the oldest archive height,
        -- since in those cases we won't have the batched_payments_accrued archive and will need a
        -- full rescan anyway.
        DROP   TRIGGER IF EXISTS make_archive;
        CREATE TRIGGER           make_archive AFTER UPDATE ON batch_db_info
        FOR EACH ROW WHEN (NEW.height % {archive_interval}) = 0 AND NEW.height > OLD.height BEGIN

            -- Batch payments
            INSERT INTO batched_payments_accrued_archive ({batched_fields}, height)
                SELECT {batched_fields}, NEW.height
                FROM batched_payments_accrued;

            DELETE FROM batched_payments_accrued_archive WHERE height < NEW.height - {archive_keep};

            DELETE FROM delayed_payments WHERE payout_height < NEW.height - {archive_keep};
        END;

        -- On re-org to a lower height, delete all recent rows that are newer
        -- than the re-org height in all the tables
        DROP   TRIGGER IF EXISTS clear_recent_and_archive;
        CREATE TRIGGER           clear_recent_and_archive AFTER UPDATE ON batch_db_info
        FOR EACH ROW WHEN NEW.height < OLD.height BEGIN

            -- Batched payments
            DELETE FROM batched_payments_accrued_recent  WHERE height > NEW.height;
            DELETE FROM batched_payments_accrued_archive WHERE height > NEW.height;

            -- Delayed payments
            DELETE FROM delayed_payments                 WHERE height > NEW.height;

        END;
        )"_format("recent_keep"_a = netconf.HISTORY_RECENT_KEEP_WINDOW,
                  "archive_interval"_a = netconf.HISTORY_ARCHIVE_INTERVAL,
                  "archive_keep"_a = netconf.HISTORY_ARCHIVE_KEEP_WINDOW,
                  "batched_fields"_a = BATCHED_PAYMENTS_COLS));
    }

    // NOTE: Add new liquidation field to delayed payment table
    if (!has_column(conn, "delayed_payments", "liquidation_amount"))
        conn.sql.exec(
                "ALTER TABLE delayed_payments ADD COLUMN liquidation_amount INTEGER NOT NULL "
                "DEFAULT 0");

    if (transaction)
        transaction->commit();
}

void BlockchainSQLite::reset_database() {
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    auto conn = db.conn();
    conn.sql.exec(R"(
      DROP TABLE IF EXISTS delayed_payments;

      DROP TABLE IF EXISTS batched_payments_accrued;
      DROP TABLE IF EXISTS batched_payments_accrued_archive;
      DROP TABLE IF EXISTS batched_payments_accrued_recent;

      DROP TABLE IF EXISTS batch_db_info;
    )");

    create_schema();
    upgrade_schema();
    update_height(0);
    log::debug(logcat, "Database reset complete");
}

void BlockchainSQLite::update_height(uint64_t new_height) {
    ZoneScoped;
    log::trace(
            logcat,
            "BlockchainDB_SQLITE::{} Changing to height: {}, prev: {}",
            __func__,
            new_height,
            height);
    height = new_height;
    db.conn().prepared_exec("UPDATE batch_db_info SET height = ?", as_i64(height));
}

void BlockchainSQLite::blockchain_detached(PaymentTableType history, uint64_t new_height) {
    std::string detach_label = "";
    int rows_restored = 0;
    int rows_removed = 0;
    if (new_height == height) {
        detach_label = " (DB is already at requested height)";
    } else if (history == PaymentTableType::Nil) {
        // Detach, with nothing to restore so wipe everything
        reset_database();
        detach_label = " (via reset)";
    } else {
        // Detached to the given archive/recent height
        const auto suffix = history == PaymentTableType::Archive ? "archive"sv : "recent"sv;
        auto conn = db.conn();
        rows_removed = conn.prepared_exec("DELETE FROM batched_payments_accrued");
        rows_restored = conn.prepared_exec(
                "INSERT INTO batched_payments_accrued ({batched_fields}) "
                "SELECT {batched_fields} FROM batched_payments_accrued_{suffix}"
                " WHERE height = ?"_format(
                        "batched_fields"_a = BATCHED_PAYMENTS_COLS, "suffix"_a = suffix),
                as_i64(new_height));
    }

    update_height(new_height);

    log::debug(
            logcat,
            "Detach request for SQL @ {} executed to {}{} (-{} rows deleted, +{} restored)",
            new_height,
            height,
            detach_label,
            rows_removed,
            rows_restored);
}

constexpr std::string_view WALLET_METADATA_FIELDS =
        " amount,"
        " lifetime_locked_stakes,"
        " lifetime_unlocked_stakes,"
        " lifetime_liquidated_stakes,"
        " lifetime_rewards";

template <typename Results>
static block_payments get_delayed_payments_impl(Results&& rows) {
    block_payments result;
    for (auto [addr, amount, liquidation_amount] : rows) {
        auto& payment = result[static_cast<const eth::address&>(addr)];
        payment.amount += reward_money::from_db_atomic(amount);
        payment.liquidation += reward_money::from_db_atomic(liquidation_amount);
    }
    return result;
}

// Delayed payments for `addr` that are still pending (i.e. not yet paid out) at `height`.
static block_payments pending_delayed_payments(
        Connection& conn, const eth::address& addr, uint64_t height) {
    return get_delayed_payments_impl(
            conn.prepared_results<blob_guts<eth::address>, int64_t, int64_t>(
                    "SELECT eth_address, amount, liquidation_amount FROM delayed_payments"
                    " WHERE eth_address = ? AND payout_height > ?",
                    span_guts(addr),
                    as_i64(height)));
}

BlockchainSQLite::wallet_info::wallet_info(
        const BlockchainSQLite& sql,
        Connection& conn,
        uint64_t height,
        std::span<const unsigned char> addr_bytes,
        std::optional<std::tuple<int64_t, int64_t, int64_t, int64_t, int64_t>> metadata,
        std::optional<hf> hf_version) :
        height{height} {

    if (metadata) {
        bool is_eth = addr_bytes.size() == sizeof(eth::address);

        const auto& [amt, life_locked, life_unlocked, life_liquidated, life_rewards] = *metadata;
        assert(amt >= 0);

        found = true;

        if (!hf_version)
            hf_version = get_network_version(sql.nettype, height);
        amount = reward_money::from_db_amount(amt, *hf_version);
        lifetime_locked_stakes = reward_money::from_db_atomic(life_locked);
        lifetime_unlocked_stakes = reward_money::from_db_atomic(life_unlocked);
        lifetime_liquidated_stakes = reward_money::from_db_atomic(life_liquidated);
        lifetime_rewards = reward_money::from_db_amount(life_rewards, *hf_version);
        // LOCKED = STAKES_IN - STAKES_OUT, where STAKES_IN are contributions made, and STAKES_OUT
        // consists of both the amount that got released back to you (lifetime_unlocked_stakes)
        // *and* any liquidation amounts that got subtracted from your balance in case of a
        // liquidation (to match the liquidation amount that got transferred into the pool and
        // liquidator via the SNRewards contract liquidation call).
        locked_stakes =
                lifetime_locked_stakes - lifetime_unlocked_stakes - lifetime_liquidated_stakes;

        // NOTE: Some of these fields are only enumerated on ETH addresses so gate error
        // checking behind said flag.
        if (is_eth) {
            assert(!lifetime_locked_stakes.negative());
            assert(!lifetime_unlocked_stakes.negative());
            assert(!lifetime_rewards.negative());

            // Your lifetime claimable amount (`amount`) should equal exactly whatever stakes came
            // back to you via unlocking, plus whatever rewards you have ever earned.  (But no
            // liquidated amounts, since those *don't* come back to you and don't enter
            // `unlocked_stakes`):
            auto rederived = lifetime_unlocked_stakes + lifetime_rewards;
            if (amount != rederived) {
                // clang-format off
                // NOTE: The affected address that we patched up in the fixups in SNL received a
                // payment before the fix could be applied so this assert would trigger. 2 blocks
                // later at 1871520 is when their DB entry is sorted, so we add an exception here to
                // skip it.
                //
                // [sqlite/db_sqlite.cpp:872] Internal error: SN contributor 0x7AaF70e681F17aae9284dC311431341CB7b64A43 at height 1871518 lifetime claimable mismatch:
                // lifetime claimable 34.840001830887 != 18766.090001830887 (= 16.090001830887 rewards + 18750 unlocked - 0 liquidated)
                // db_sqlite.cpp:873: wallet_info(...): Assertion `amount == rederived' failed.
                // clang-format on
                bool skip = sql.nettype == network_type::MAINNET && height == 1871518;
                if (!skip) {
                    log::error(
                            logcat,
                            "Internal error: SN contributor {} at height {} lifetime claimable "
                            "mismatch:\n"
                            "lifetime claimable {} != {} (= {} rewards + {} unlocked) [lifetime "
                            "stakes={}, liquidated={}]",
                            log_addr{tools::make_from_guts<eth::address>(addr_bytes)},
                            height,
                            amount,
                            rederived,
                            lifetime_rewards,
                            lifetime_unlocked_stakes,
                            lifetime_locked_stakes,
                            lifetime_liquidated_stakes);
                    assert(amount == rederived);
                }
            }

            // NOTE: Delayed payments is only supported on ETH addresses
            for (const auto& [addr, payment] : pending_delayed_payments(
                         conn, tools::make_from_guts<eth::address>(addr_bytes), height)) {
                if (payment.amount >= payment.liquidation)
                    timelocked_stakes += payment.amount - payment.liquidation;
                else {
                    log::error(
                            logcat,
                            "Internal error: delayed payment liquidation value ({}) is higher than "
                            "the amount ({})",
                            payment.liquidation,
                            payment.amount);
                    assert(payment.amount >= payment.liquidation);
                }
            }
        }
    }
}

BlockchainSQLite::wallet_info::wallet_info(uint64_t height, bool found) :
        height{height}, found{found} {}

// `height` is the DB height as seen by `conn`.
static BlockchainSQLite::wallet_info get_accrued_rewards_impl(
        const BlockchainSQLite& sql,
        Connection& conn,
        uint64_t height,
        std::span<const unsigned char> addr_bytes,
        std::optional<hf> hf = std::nullopt) {
    log::trace(logcat, "BlockchainDB_SQLITE {}", __func__);
    auto tuple = conn.prepared_maybe_get<int64_t, int64_t, int64_t, int64_t, int64_t>(
            "SELECT {} FROM batched_payments_accrued WHERE address = ?"_format(
                    WALLET_METADATA_FIELDS),
            addr_bytes);

    return {sql, conn, height, addr_bytes, std::move(tuple), hf};
}

void BlockchainSQLite::add_sn_rewards(
        hf hf_version, const block_payments& payments, bool rewards_payment) {
    ZoneScoped;
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    std::string query;
    if (hf_version >= hf::hf21_eth) {
        if (rewards_payment)
            query = R"(
            INSERT INTO batched_payments_accrued (address, amount, lifetime_rewards)
                VALUES (?1, ?2, ?2)
                ON CONFLICT (address) DO UPDATE SET
                    amount = amount + excluded.amount,
                    lifetime_rewards = lifetime_rewards + excluded.lifetime_rewards)"s;
        else
            query = R"(
            INSERT INTO batched_payments_accrued (address, amount, lifetime_unlocked_stakes, lifetime_liquidated_stakes)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (address) DO UPDATE SET
                    amount = amount + excluded.amount,
                    lifetime_unlocked_stakes = lifetime_unlocked_stakes + excluded.lifetime_unlocked_stakes,
                    lifetime_liquidated_stakes = lifetime_liquidated_stakes + excluded.lifetime_liquidated_stakes)"s;
    } else {
        assert(rewards_payment);
        query = R"(
            INSERT INTO batched_payments_accrued (address, payout_offset, amount)
                VALUES (?, ?, ?)
                ON CONFLICT (address) DO UPDATE SET amount = amount + excluded.amount)"s;
    }

    const auto& netconf = get_config(nettype);
    auto conn = db.conn();

    for (const auto& [vaddr, payment] : payments) {
        auto amount = payment.amount - payment.liquidation;

        log::trace(
                logcat,
                "Adding record for SN reward contributor {} to database with amount {}",
                log_addr{vaddr, nettype},
                amount);

        auto addr_blob = std::visit(
                [](const auto& a) -> std::span<const unsigned char> { return span_guts(a); },
                vaddr);
        if (hf_version >= hf::hf21_eth) {
            if (rewards_payment)
                conn.prepared_exec(query, addr_blob, amount.to_db_amount(hf_version));
            else
                conn.prepared_exec(
                        query,
                        addr_blob,
                        amount.to_db_amount(hf_version),
                        amount.to_db_atomic(),
                        payment.liquidation.to_db_atomic());
        } else {
            int offset = std::get<account_public_address>(vaddr).modulus(netconf.BATCHING_INTERVAL);
            conn.prepared_exec(query, addr_blob, offset, amount.to_db_amount(hf_version));
        }
    }
}

int BlockchainSQLite::batch_payments_accrued_row_count() {
    return db.conn().prepared_get<int>("SELECT COUNT(*) FROM batched_payments_accrued");
}
bool BlockchainSQLite::batch_payments_accrued_has_any(bool recent, uint64_t height) {
    return db.conn().prepared_get<int>(
            "SELECT EXISTS(SELECT 1 FROM batched_payments_accrued_{} WHERE height = ?)"_format(
                    recent ? "recent" : "archive"),
            as_i64(height));
}

std::vector<batch_sn_payment> BlockchainSQLite::get_sn_payments(uint64_t block_height) {
    ZoneScoped;
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    // <= here because we might have crap in the db that we don't clear until we actually add
    // the HF block later on.  (This is a pretty slim edge case that happened on devnet and is
    // probably virtually impossible on mainnet).
    if (nettype != network_type::FAKECHAIN &&
        block_height <= hard_fork_begins(nettype, hf::hf19_reward_batching).value_or(0))
        return {};

    const auto& conf = get_config(nettype);
    auto hf_version = get_network_version(nettype, block_height);
    assert(hf_version < hf::hf21_eth);  // HF21+ has no auto-payments and shouldn't call this

    auto conn = db.conn();
    std::vector<std::pair<account_public_address, reward_money>> accrued_pairs;
    for (auto [address, amount] : conn.prepared_results<blob_guts<account_public_address>, int64_t>(
                 "SELECT address, amount FROM batched_payments_accrued"
                 " WHERE payout_offset = ? AND amount >= ? ORDER BY address ASC",
                 static_cast<int>(block_height % conf.BATCHING_INTERVAL),
                 as_i64(conf.MIN_BATCH_PAYMENT_AMOUNT * BATCH_REWARD_FACTOR)))
        accrued_pairs.emplace_back(address, reward_money::from_db_amount(amount, hf_version));

    // The block before HF21, addresses which have not registered an ETH address for the
    // SESH transition will have their balances paid out, regardless of balance.
    bool pre_hf21_final_payout = false;
    auto hf21_begins = hard_fork_begins(nettype, hf::hf21_eth);
    if (hf21_begins && block_height == *hf21_begins - 1) {
        pre_hf21_final_payout = true;

        if (nettype == network_type::TESTNET) {
            // Testnet forked before this final block payout code was added (and just dropped
            // pending rewards), so skip the handling.
            using namespace oxenc::literals;
            constexpr auto id = "223a7865e16fcab802a1dc17616415bf"_hex_u;
            static_assert(
                    std::equal(
                            id.begin(),
                            id.end(),
                            get_config(network_type::TESTNET).NETWORK_ID.begin()),
                    "If rebooting testnet, remove this workaround code!");

            // TODO: When removing this also remove the workaround in src/oxen_economy.h's
            // burn_needed() function!

            pre_hf21_final_payout = false;
        }
    }

    if (pre_hf21_final_payout) {
        log::debug(
                logcat,
                "block before hf21, doing final payout to addresses not registered for "
                "conversion");
        constexpr auto all_accrued =
                "SELECT address, amount FROM batched_payments_accrued ORDER BY address ASC";
        accrued_pairs.clear();
        for (auto [address, amount] :
             conn.prepared_results<blob_guts<account_public_address>, int64_t>(all_accrued))
            accrued_pairs.emplace_back(address, reward_money::from_db_amount(amount, hf_version));
    }

    std::vector<batch_sn_payment> payments;

    const auto& sesh_addr_map =
            *oxen::sesh::get_transition_context(nettype, block_height).addresses;
    for (const auto& [address, amount] : accrued_pairs) {
        if (pre_hf21_final_payout) {
            auto addr_str = get_account_address_as_str(nettype, 0, address);

            log::debug(logcat, "address {} has amount {}", addr_str, amount);
            if (sesh_addr_map.contains(addr_str))  // Registered for transition
                continue;

            if (amount.to_coin() > 0) {
                log::debug(logcat, "pre_hf21_final_payout, paying out {}", addr_str);
            } else {
                log::debug(logcat, "pre_hf21_final_payout, skipping {} (truncated to 0)", addr_str);
                continue;  // Insufficient OXEN to payout
            }
        }

        payments.emplace_back(address, amount.truncate());
    }

    return payments;
}

static BlockchainSQLite::wallet_info get_accrued_rewards_at_impl(
        const BlockchainSQLite& sql,
        Connection& conn,
        std::span<const unsigned char> addr_bytes,
        uint64_t at_height) {
    log::trace(logcat, "BlockchainDB_SQLITE {}", __func__);
    auto tx = read_tx(conn);
    auto curr_top_height = db_height(conn);
    if (at_height > curr_top_height)
        return {};

    if (at_height == curr_top_height)
        return get_accrued_rewards_impl(sql, conn, curr_top_height, addr_bytes);

    if (auto tuple = conn.prepared_maybe_get<int64_t, int64_t, int64_t, int64_t, int64_t>(
                "SELECT {} FROM batched_payments_accrued_recent"
                " WHERE address = ? AND height = ?"_format(WALLET_METADATA_FIELDS),
                addr_bytes,
                as_i64(at_height)))
        return {sql, conn, curr_top_height, addr_bytes, tuple};

    // No rewards found; check to see if we actually have any recent records for that height and
    // if not, return a "don't know" nullopt value.  Otherwise we fall through and return an
    // authoritive 0 value.
    auto min_height =
            as_u64(conn.prepared_get<int64_t>("SELECT COALESCE(MIN(height), 0)"
                                              " FROM batched_payments_accrued_recent"));
    if (at_height < min_height)
        return {};

    return {min_height, true};
}

BlockchainSQLite::wallet_info BlockchainSQLite::get_accrued_rewards(
        const eth::address& address, std::optional<hf> hf) {
    auto conn = db.conn();
    auto tx = read_tx(conn);
    return get_accrued_rewards_impl(*this, conn, db_height(conn), span_guts(address), hf);
}

BlockchainSQLite::wallet_info BlockchainSQLite::get_accrued_rewards(
        const account_public_address& address) {
    auto conn = db.conn();
    auto tx = read_tx(conn);
    return get_accrued_rewards_impl(*this, conn, db_height(conn), span_guts(address));
}

BlockchainSQLite::wallet_info BlockchainSQLite::get_accrued_rewards(
        const eth::address& address, uint64_t at_height) {
    auto conn = db.conn();
    return get_accrued_rewards_at_impl(*this, conn, span_guts(address), at_height);
}

BlockchainSQLite::wallet_info BlockchainSQLite::get_accrued_rewards(
        const account_public_address& address, uint64_t at_height) {
    auto conn = db.conn();
    return get_accrued_rewards_at_impl(*this, conn, span_guts(address), at_height);
}

std::vector<std::pair<
        std::variant<eth::address, account_public_address>,
        BlockchainSQLite::wallet_info>>
BlockchainSQLite::get_all_accrued_rewards() {
    ZoneScoped;
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    std::vector<std::pair<std::variant<eth::address, account_public_address>, wallet_info>> result;

    auto conn = db.conn();
    auto tx = read_tx(conn);
    auto h = db_height(conn);
    for (blob b : conn.prepared_results<blob>("SELECT address FROM batched_payments_accrued")) {
        std::span<const unsigned char> addr{
                reinterpret_cast<const unsigned char*>(b.data()), b.size()};
        if (addr.size() == sizeof(eth::address))
            result.emplace_back(
                    tools::make_from_guts<eth::address>(addr),
                    get_accrued_rewards_impl(*this, conn, h, addr));
        else
            result.emplace_back(
                    tools::make_from_guts<account_public_address>(addr),
                    get_accrued_rewards_impl(*this, conn, h, addr));
    }

    return result;
}

void BlockchainSQLite::add_rewards(
        hf hf_version,
        reward_money distribution_amount,
        const service_nodes::service_node_info& sn_info,
        block_payments& payments) const {
    ZoneScoped;

    uint64_t milli_amount;
    if (auto opt_amt = distribution_amount.to_intermediate())
        milli_amount = *opt_amt;
    else {
        // If to_intermediate returns nullopt then the distribution_amount was either negative, or
        // would overflow, but neither of those should be possible here.
        log::critical(
                logcat, "Internal error: invalid SN reward distribution: {}", distribution_amount);
        assert(opt_amt);
        throw oxen::traced<std::logic_error>{"Invalid SN reward distribution"};
    }

    // Find out how much is due for the operator: fee_portions/PORTIONS * reward

    auto operator_fee = reward_money::from_intermediate(
            mul128_div64(sn_info.portions_for_operator, milli_amount, old::STAKING_PORTIONS));

    assert(sn_info.portions_for_operator <= old::STAKING_PORTIONS);
    assert(operator_fee <= distribution_amount);

    // NOTE: Localdev does not have a cryptonote->ETH address step, so, old pre-ETH SN nodes
    // don't have an address assigned to it. This breaks tests that expect pre-ETH SN's to
    // receive funds in order to proceed.
    bool use_eth_address = hf_version >= hf::hf21_eth;
    if (use_eth_address && nettype == network_type::LOCALDEV) {
        if (!sn_info.operator_ethereum_address)
            use_eth_address = false;
    }

    constexpr reward_money zero{};
    // Pay the operator fee to the operator
    if (operator_fee > zero) {
        if (use_eth_address) {
            assert(sn_info.contributors.size());  // NOTE: Be paranoid, check contributors size
            eth::address fee_recipient = sn_info.contributors.size()
                                               ? sn_info.contributors[0].ethereum_beneficiary
                                               : sn_info.operator_ethereum_address;
            payments[fee_recipient].amount += operator_fee;
        } else {
            payments[sn_info.operator_address].amount += operator_fee;
        }
    }

    // Pay the balance to all the contributors (including the operator again)
    uint64_t milli_post_fee_amt = *(distribution_amount - operator_fee).to_intermediate();

    for (auto& contributor : sn_info.contributors) {
        // This calculates:
        // (contributor.amount / staking_requirement) * (distribution_amount - operator_fee)
        // but using 128 bit integer math

        auto c_reward = reward_money::from_intermediate(
                mul128_div64(contributor.amount, milli_post_fee_amt, sn_info.staking_requirement));

        if (c_reward > zero) {
            // NOTE: At minimum, when we parsed the contributor if no benficiary is set, it
            // should be assigned to the ethereum address by default.
            auto& balance = use_eth_address ? payments[contributor.ethereum_beneficiary]
                                            : payments[contributor.address];
            balance.amount += c_reward;
        }
    }
}

void BlockchainSQLite::reward_handler(
        const block& block,
        const service_nodes::service_node_list::state_t& sn_state,
        const service_nodes::block_add_result& block_add) {
    ZoneScoped;
    assert(block.major_version >= hf::hf19_reward_batching);

    // From here on we calculate everything in milli-atomic OXEN/SESH (i.e. thousanths of an atomic
    // unit) so that our integer math has reduced loss from integer division.  Before HF22 that
    // amount goes directly into the database, as of HF22 the final reward for each recipient gets
    // truncated to an atomic unit.
    if (block.reward > std::numeric_limits<uint64_t>::max() / BATCH_REWARD_FACTOR)
        throw oxen::traced<std::logic_error>{"Reward distribution amount is too large"};

    auto block_reward = reward_money::from_coin(block.reward);

    block_payments payments;
    if (block.major_version < feature::ETH_BLS) {
        // Step 1: Pay out the block producer their tx fees (note that, unlike the
        // below, this applies even if the SN isn't currently payable).
        auto base_sn_reward = reward_money::from_coin(oxen::SN_REWARD_HF15);
        if (block_reward < base_sn_reward)
            throw oxen::traced<std::logic_error>{"Invalid payment: block reward is too small"};
        if (auto tx_fees = block_reward - base_sn_reward;
            tx_fees.to_intermediate() > 0 && block.has_pulse()) {
            auto pulse_leader = sn_state.get_block_producer();
            if (!pulse_leader && !sn_state.sn_list)
                // No sn_list means we're in the test suite, so to make this work, we'll use the
                // block_leader.  (NOTE: this will break if some new core_tests tries expects to
                // award batched backup pulse quorum tx fees as they'll go to the first round
                // leader, rather than the actual producer, but it isn't worth adding to every
                // single state_t to avoid that).
                pulse_leader = sn_state.block_leader;

            if (pulse_leader)
                add_rewards(
                        block.major_version,
                        tx_fees,
                        *sn_state.service_nodes_infos.at(pulse_leader),
                        payments);
        }
        block_reward = base_sn_reward;

        // Step 2: Add Governance reward to the list
        if (nettype != network_type::FAKECHAIN) {
            if (parsed_governance_addr.first != block.major_version) {
                get_account_address_from_str(
                        parsed_governance_addr.second,
                        nettype,
                        get_config(nettype).governance_wallet_address(block.major_version));
                parsed_governance_addr.first = block.major_version;
            }

            auto foundation_reward =
                    reward_money::from_coin(governance_reward_formula(block.major_version));
            payments[parsed_governance_addr.second.address].amount += foundation_reward;
        }
    }

    // Step 3: Iterate over the payable (active for >=24h) N service nodes and pay each node 1/N
    // fraction of the total block reward.
    reward_money per_sn_reward;
    if (const auto N = block_add.payable_nodes_hf19_onwards.size())
        per_sn_reward = block_reward / N;

    for (const auto& node_pubkey : block_add.payable_nodes_hf19_onwards)
        add_rewards(
                block.major_version,
                per_sn_reward,
                *sn_state.service_nodes_infos.at(node_pubkey),
                payments);

    auto delayed = get_delayed_payments(block.get_height());
    if (block.major_version >= hf::hf21_eth)
        add_sn_rewards(block.major_version, std::move(delayed), false /*rewards_payment*/);
    else
        assert(delayed.empty());  // There should be no delayed payments before HF21!

    add_sn_rewards(block.major_version, std::move(payments), true /*rewards_payment*/);
}

block_payments BlockchainSQLite::get_delayed_payments() {
    ZoneScoped;
    auto conn = db.conn();
    auto tx = read_tx(conn);
    return get_delayed_payments_impl(
            conn.prepared_results<blob_guts<eth::address>, int64_t, int64_t>(
                    "SELECT eth_address, amount, liquidation_amount FROM delayed_payments"
                    " WHERE payout_height > ?",
                    as_i64(db_height(conn))));
}

block_payments BlockchainSQLite::get_delayed_payments(const eth::address& addr) {
    ZoneScoped;
    auto conn = db.conn();
    auto tx = read_tx(conn);
    return pending_delayed_payments(conn, addr, db_height(conn));
}

block_payments BlockchainSQLite::get_delayed_payments(uint64_t payout_height) {
    ZoneScoped;
    return get_delayed_payments_impl(
            db.conn().prepared_results<blob_guts<eth::address>, int64_t, int64_t>(
                    "SELECT eth_address, amount, liquidation_amount FROM delayed_payments"
                    " WHERE payout_height = ?",
                    as_i64(payout_height)));
}

void BlockchainSQLite::submit_stakes_metadata(
        const service_nodes::block_add_result& block_add, bool _no_transaction) {
    // NOTE: Submit (locked) stakes information
    // New ETH addresses that are staking may not exist in the table yet if it's their first
    // time because they haven't received rewards yet. The adding of locked stakes has to
    // account for if it doesn't exist, hence we use a INSERT INTO instead of just using UPDATE
    // as we do in the subtraction query below.
    constexpr auto lifetime_locked_stakes = R"(
        INSERT INTO batched_payments_accrued (lifetime_locked_stakes, address)
            VALUES (?, ?)
            ON CONFLICT(address) DO UPDATE SET
                lifetime_locked_stakes = lifetime_locked_stakes + excluded.lifetime_locked_stakes
    )";

    auto conn = db.conn();
    std::optional<SQLite::Transaction> transaction =
            _no_transaction ? std::nullopt : begin_tx(conn, SQLite::TransactionBehavior::DEFERRED);

    // NOTE: Submit locked stakes
    for (const auto& stake : block_add.locked_stakes) {
        assert(stake.amount.to_coin() > 0);

#ifndef NDEBUG
        BlockchainSQLite::wallet_info wallet_info_before =
                get_accrued_rewards_impl(*this, conn, height, stake.addr);
#endif

        // NOTE: Add the locked SESH
        int rows_changed = conn.prepared_exec(
                lifetime_locked_stakes, stake.amount.to_db_atomic(), span_guts(stake.addr));
        assert(rows_changed == 1);

#ifndef NDEBUG
        // NOTE: Verify the DB operations did what we expected
        BlockchainSQLite::wallet_info wallet_info_after =
                get_accrued_rewards_impl(*this, conn, height, stake.addr);
        assert(wallet_info_after.found);
        log::trace(
                logcat,
                "SN contributor {} at height {} locked {} SESH ({} => {} total) into SN {}",
                log_addr{stake.addr},
                height + 1,
                stake.amount,
                wallet_info_before.lifetime_locked_stakes,
                wallet_info_after.lifetime_locked_stakes,
                stake.sn);
        assert(wallet_info_before.locked_stakes.to_coin() + stake.amount.to_coin() ==
               wallet_info_after.locked_stakes.to_coin());
#endif
    }

    // NOTE: Submit purge stakes
    // For purged stakes, these funds have "disappeared" from the contract (node is in the SNL
    // but _not_ in the contract). To account for this we need to undo the stakes we counted as
    // being locked up.
    constexpr auto purged_stakes = R"(
        UPDATE batched_payments_accrued
            SET lifetime_locked_stakes = lifetime_locked_stakes - ?
            WHERE address = ?)";

    for (const auto& purge : block_add.purged_stakes) {
        assert(purge.amount.to_coin() > 0);

        // NOTE: Verify remaining locked stakes don't go below 0
        auto wallet_info_before = get_accrued_rewards_impl(*this, conn, height, purge.addr);
        assert(wallet_info_before.found);
        if (wallet_info_before.locked_stakes < purge.amount) {
            log::error(
                    logcat,
                    "Internal error: SN contributor ({}) purged more stake ({} SESH) than is "
                    "available in their locked balance ({} SESH)",
                    log_addr{purge.addr},
                    purge.amount,
                    wallet_info_before.lifetime_locked_stakes);
            assert(wallet_info_before.locked_stakes >= purge.amount);
        }

        // NOTE: Add the purged SESH
        int rows_changed = conn.prepared_exec(
                purged_stakes, purge.amount.to_db_atomic(), span_guts(purge.addr));
        assert(rows_changed == 1);

#ifndef NDEBUG
        // NOTE: Verify the DB operations did what we expected
        auto wallet_info_after = get_accrued_rewards_impl(*this, conn, height, purge.addr);
        assert(wallet_info_after.found);
        log::trace(
                logcat,
                "SN contributor {} at height {} purged {} SESH ({} => {} total) into SN {}",
                log_addr{purge.addr},
                height + 1,
                purge.amount,
                wallet_info_before.locked_stakes,
                wallet_info_after.locked_stakes,
                purge.sn);
#endif
    }

    if (transaction)
        transaction->commit();
}

void BlockchainSQLite::convert_hf22() {
    log::debug(logcat, "Converting accrued values to atomic SESH");
    db.conn().sql.exec(
            "UPDATE batched_payments_accrued SET amount = amount / {factor},"
            " lifetime_rewards = lifetime_rewards / {factor}"_format(
                    "factor"_a = BATCH_REWARD_FACTOR));
}

bool BlockchainSQLite::add_block(
        const block& block,
        const service_nodes::service_node_list::state_t& service_nodes_state,
        const service_nodes::block_add_result& block_add,
        const std::optional<service_nodes::rescan_context>& rescan) {
    ZoneScoped;
    auto block_height = block.get_height();
    log::trace(logcat, "BlockchainDB_SQLITE::{} called on height: {}", __func__, block_height);

    auto hf_version = block.major_version;
    if (hf_version < hf::hf19_reward_batching) {
        update_height(block_height);
        if (batch)
            batch->block_added();
        return true;
    }

    if (block_height == hard_fork_begins(nettype, hf::hf19_reward_batching).value_or(0)) {
        log::debug(logcat, "Batching of Service Node Rewards Begins");
        reset_database();
        update_height(block_height - 1);
    }

    if (block_height != height + 1) {
        log::error(
                logcat,
                "Block height ({}) out of sync with batching database ({})",
                block_height,
                (height + 1));
        return false;
    }

    // We query our own database as a source of truth to verify the blocks payments against. The
    // calculated_rewards variable contains a known good list of who should have been paid in this
    // block this only applies before the ETH BLS hard fork. After that the rewards are claimed by
    // the users when they wish
    std::vector<batch_sn_payment> calculated_rewards;
    if (hf_version < feature::ETH_BLS) {
        calculated_rewards = get_sn_payments(block_height);
    }

    // We iterate through the block's coinbase payments and build a copy of our own list of the
    // payments miner_tx_vouts this will be compared against calculated_rewards and if they match we
    // know the block is paying the correct people only.
    std::vector<std::pair<crypto::public_key, uint64_t>> miner_tx_vouts;
    if (block.miner_tx)
        for (auto& vout : block.miner_tx->vout)
            miner_tx_vouts.emplace_back(std::get<txout_to_key>(vout.target).key, vout.amount);

    try {
        auto conn = db.conn();
        auto transaction = begin_tx(conn);

        // Goes through the miner transactions vouts checks they are right and marks them as paid in
        // the database
        if (!validate_batch_payment(miner_tx_vouts, calculated_rewards, block_height, rescan))
            return false;

        reward_handler(block, service_nodes_state, block_add);
        if (hf_version >= hf::hf21_eth)
            submit_stakes_metadata(block_add, true);
        update_height(
                height + 1);  // NOTE: Update height which synchronises the archive/recent tables

        if (transaction)
            transaction->commit();
        else
            batch->block_added();

    } catch (std::exception& e) {
        log::error(
                logcat,
                "Error adding reward payments at block {}: {}",
                block.get_height(),
                e.what());
        return false;
    }
    return true;
}

bool BlockchainSQLite::add_delayed_payments(
        std::span<const service_nodes::eth_stake> payments,
        uint64_t at_height,
        uint64_t delay_blocks) {
    ZoneScoped;
    log::trace(logcat, "BlockchainSQLite::{} called", __func__);
    try {
        auto conn = db.conn();
        auto transaction = begin_tx(conn);

        // Basic checks can be done here
        // if (amount > max_staked_amount)
        // throw std::logic_error{"Invalid payment: staked returned is too large"};

        assert(at_height >= height);

        int64_t payout_height = at_height + (delay_blocks > 0 ? delay_blocks : 1);
        constexpr auto insert_payment = R"(
            INSERT INTO delayed_payments
                (eth_address, amount, payout_height, height, block_height, block_tx_index, contributor_index, liquidation_amount)
                VALUES
                (?,           ?,      ?,             ?,      ?,            ?,              ?,                 ?))";

        for (auto& payment : payments) {
            const auto amount = static_cast<int64_t>(payment.amount.to_db_atomic());
            // const auto eth_address = eth_address_to_sql_address(payment.addr);
            log::trace(
                    logcat,
                    "Adding delayed payment for SN reward contributor {} to Database"
                    " with amount {}; height {}; payout height {}",
                    log_addr{payment.addr},
                    amount,
                    at_height,
                    payout_height);
            conn.prepared_exec(
                    insert_payment,
                    span_guts(payment.addr),
                    static_cast<int64_t>(payment.amount.to_db_atomic()),
                    payout_height,
                    as_i64(at_height),
                    payment.block_height,
                    payment.tx_index,
                    payment.contributor_index,
                    static_cast<int64_t>(payment.liquidation.to_db_atomic()));
        }

        if (transaction)
            transaction->commit();
    } catch (std::exception& e) {
        log::error(logcat, "Error returning stakes: {}", e.what());
        return false;
    }
    return true;
}

bool BlockchainSQLite::validate_batch_payment(
        const std::vector<std::pair<crypto::public_key, uint64_t>>& miner_tx_vouts,
        const std::vector<batch_sn_payment>& calculated_payments_from_batching_db,
        uint64_t block_height,
        const std::optional<service_nodes::rescan_context>& rescan) {
    ZoneScoped;
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    std::span<const batch_sn_payment> payments = calculated_payments_from_batching_db;
    if (!rescan || !rescan->skip_verify) {
        if (miner_tx_vouts.size() != calculated_payments_from_batching_db.size()) {
            log::error(
                    logcat,
                    "Length of batch payments ({}) does not match block vouts ({})",
                    calculated_payments_from_batching_db.size(),
                    miner_tx_vouts.size());
            return false;
        }

        uint64_t total_oxen_payout_in_our_db = 0;
        for (const auto& payment : calculated_payments_from_batching_db)
            total_oxen_payout_in_our_db += payment.amount.to_coin();
        uint64_t total_oxen_payout_in_vouts = 0;
        std::vector<batch_sn_payment> finalised_payments;
        const auto deterministic_keypair = get_deterministic_keypair_from_height(block_height);
        for (size_t vout_index = 0; vout_index < miner_tx_vouts.size(); vout_index++) {
            const auto& [pubkey, amt] = miner_tx_vouts[vout_index];
            auto amount = reward_money::from_coin(amt);
            const auto& from_db = calculated_payments_from_batching_db[vout_index];
            if (amount != from_db.amount) {
                log::error(
                        logcat,
                        "Batched payout amount incorrect. Should be {}, not {}",
                        from_db.amount,
                        amount);
                return false;
            }
            crypto::public_key out_eph_public_key{};
            if (!get_deterministic_output_key(
                        from_db.address, deterministic_keypair, vout_index, out_eph_public_key)) {
                log::error(logcat, "Failed to generate output one-time public key");
                return false;
            }
            if (tools::view_guts(pubkey) != tools::view_guts(out_eph_public_key)) {
                log::error(logcat, "Output ephemeral public key does not match");
                return false;
            }
            total_oxen_payout_in_vouts += amount.to_coin();
            finalised_payments.emplace_back(from_db.address, amount);
        }
        if (total_oxen_payout_in_vouts != total_oxen_payout_in_our_db) {
            log::error(
                    logcat,
                    "Total batched payout amount incorrect. Should be {}, not {}",
                    total_oxen_payout_in_our_db,
                    total_oxen_payout_in_vouts);
            return false;
        }
    }

    return save_payments(block_height, payments);
}

bool BlockchainSQLite::save_payments(
        uint64_t block_height, std::span<const batch_sn_payment> paid_amounts) {
    ZoneScoped;
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    auto conn = db.conn();
    for (const auto& payment : paid_amounts) {
        if (auto maybe_amount = conn.prepared_maybe_get<int64_t>(
                    "SELECT amount FROM batched_payments_accrued WHERE address = ?",
                    span_guts(payment.address))) {
            // Truncate the thousanths amount to an atomic OXEN:
            // Hard-code hf20 here because this code only runs in HF20 and earlier (and
            // from_db_amount is the same for everything <= 21).
            auto amount = reward_money::from_db_amount(*maybe_amount, hf::hf20_eth_transition);
            if (amount.truncate() != payment.amount) {
                log::error(
                        logcat,
                        "Invalid amounts passed in to save payments for {addr}: received {recv}, "
                        "expected {expected} (truncated from {untrunc})",
                        "addr"_a = log_addr{payment.address, nettype},
                        "recv"_a = payment.amount,
                        "expected"_a = amount.truncate(),
                        "untrunc"_a = amount);
                return false;
            }

            conn.prepared_exec(
                    "UPDATE batched_payments_accrued SET amount = amount - ? WHERE address = ?",
                    payment.amount.to_db_amount(hf::hf20_eth_transition),
                    span_guts(payment.address));
        } else {
            // This shouldn't occur: we validate payout addresses much earlier in the block
            // validation.
            log::error(
                    logcat,
                    "Internal error: Invalid amounts passed in to save payments for address {}: "
                    "that address has no accrued rewards",
                    log_addr{payment.address, nettype});
            return false;
        }
    }

    // NOTE: For pre-ETH hardfork. Oxen SN's were paid and the amount paid was subtracted
    // from the accumulated amount in the DB. After the ETH hardfork the DB tracks
    // the lifetime rewards and instead the smart contract tracks how much has been paid
    // out. The delta in how much the DB has allocated and how much the smart contract
    // has paid is the amount owed.
    //
    // In other words after hardforking, rewards amounts are strictly accumulative which
    // means this condition will never trigger.
    //
    // Paid amounts is only populated with miner-tx, OXEN style payments. This array is empty
    // if payouts are being done with SESH rewards.
    if (paid_amounts.size())
        conn.prepared_exec("DELETE FROM batched_payments_accrued WHERE amount = 0");
    return true;
}

std::optional<uint64_t> BlockchainSQLite::fixup(bool recheck) {
    auto conn = db.conn();
    auto tx = begin_tx(conn);

    auto with_commit = [&tx](std::optional<uint64_t> ret) {
        if (tx)
            tx->commit();
        return ret;
    };

    auto prev_db_version = conn.prepared_get<int>("PRAGMA user_version");
    if (!recheck) {
        if (prev_db_version >= FIXUP_DELAYED_PAYMENT_REWARDS)
            return with_commit(std::nullopt);

        conn.sql.exec("PRAGMA user_version = {}"_format(FIXUP_DELAYED_PAYMENT_REWARDS));
    } else {
        assert(prev_db_version >= FIXUP_DELAYED_PAYMENT_REWARDS);
    }

    if (nettype != cryptonote::network_type::MAINNET)
        return with_commit(std::nullopt);

    auto hf21_started = get_hard_fork_heights(nettype, hf::hf21_eth).first.value();
    if (height < hf21_started)
        // If we're before HF21 then there are no fixups to apply because we already have to rescan
        // the entirety of HF21+ which should get everything right.
        return with_commit(std::nullopt);

    // If we select a straight sum of all amounts then we would overflow, so select the sum of
    // values modulo a large (but not too large) prime as a checksum to verify the aggregate amount
    // without having to resort to 128-bit math:
    constexpr int64_t CSUM_MOD = 789012345678901;
    struct fixup_record {
        int64_t height;
        int64_t checksum;
    };
    constexpr std::array<fixup_record, 4> RECORDS{{
            {1'860'000, 212'642'223'336'227'860},
            {1'870'000, 227'908'952'909'310'216},
            {1'880'000, 19'447'225'076'325'721},
            {1'890'000, 22'402'200'527'873'036},
    }};

    // If we can't find a way to do better, the fallback option is to require a rescan from HF21:
    int64_t detach = hf21_started - 1;

    // We are *always* going to force delete all HF21+ current and recent rows because we just don't
    // know if they are correct and we need to rescan from one of the known-correct archive heights,
    // above (or from our reproduced 1890k snapshot, if your node has an invalid 1890k value).
    if (!recheck) {
        session::sqlite::exec_query(
                conn.sql,
                "DELETE FROM batched_payments_accrued_recent WHERE height >= ?",
                as_i64(hf21_started));
        if (height >= hf21_started)
            conn.sql.exec("DELETE FROM batched_payments_accrued");
    }

    //
    // If any of the archive checksums don't match the above then we will delete it because it isn't
    // correct and we don't ever want you to use it (e.g. if you every roll back into the range).
    bool have_snapshot_height = false;
    for (const auto& [archive_height, checksum] : RECORDS) {
        auto [db_csum, db_count] = conn.prepared_get<int64_t, int>(
                "SELECT SUM(amount % ?), COUNT(*) FROM batched_payments_accrued_archive"
                " WHERE height = ?",
                CSUM_MOD,
                archive_height);

        if (!db_count)
            continue;
        if (db_csum == checksum) {
            detach = archive_height;
            if (archive_height == snapshots::height)
                have_snapshot_height = true;
            continue;
        }
        if (recheck) {
            log::critical(
                    logcat,
                    "Database fixup recheck failed: still have invalid reward archive checksum "
                    "at block {} (db: {}, expected: {})",
                    archive_height,
                    db_csum,
                    checksum);
            return with_commit(0);  // any non-nullopt signifies the failure
        }

        log::warning(
                logcat,
                "Deleting invalid reward archive at blk {} (checksum failed)",
                archive_height);
        session::sqlite::exec_query(
                conn.sql,
                "DELETE FROM batched_payments_accrued_archive WHERE height = ?",
                archive_height);
    }

    if (recheck)
        return with_commit(std::nullopt);  // Passed all rechecks

    if (height >= static_cast<uint64_t>(snapshots::height) && !have_snapshot_height) {
        // As long as we are synced above 1'890'000 then we can load our hard-coded snapshot data
        // into the archive to rescan from there even if you had invalid 1'890'000 reward data.
        detach = snapshots::height;
        for (auto& r : snapshots::batched_payments)
            conn.prepared_exec(
                    "INSERT INTO batched_payments_accrued_archive ("
                    "address, amount, payout_offset, height, lifetime_locked_stakes, "
                    "lifetime_unlocked_stakes, lifetime_liquidated_stakes, lifetime_rewards"
                    ") VALUES (?, ?, NULL, ?, ?, ?, ?, ?)",
                    span_guts(r.addr),
                    r.amount,
                    snapshots::height,
                    r.lifetime_locked_stakes,
                    r.lifetime_unlocked_stakes,
                    r.lifetime_liquidated_stakes,
                    r.lifetime_rewards);

        log::warning(logcat, "Loaded reward archive snapshot for height {}", snapshots::height);
    }

    // Earlier versions had a bug where the delayed_payments table could end up with missing rows
    // (which then later cause missing rewards when the row should have been released into the
    // reward table).  Rather than forcing a rescan from the beginning of HF21 we instead load a
    // hard-coded list of values that include all values up to 1'890'000, so that the rescan doesn't
    // have to cover as much.
    conn.sql.exec("DELETE FROM delayed_payments");
    int count = 0;
    for (auto& [addr, amt, pay_h, h, block_h, block_tx, contr_i, liq] :
         snapshots::delayed_payments) {
        // Values are sorted by `height`, and so once we find a height above the height
        // we're going to detach to there is no need to continue
        if (h > detach)
            break;
        conn.prepared_exec(
                "INSERT INTO delayed_payments ("
                "eth_address, amount, payout_height, height, block_height, block_tx_index, "
                "contributor_index, liquidation_amount"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                span_guts(addr),
                amt,
                pay_h,
                h,
                block_h,
                block_tx,
                contr_i,
                liq);
        count++;
    }
    log::warning(
            logcat,
            "Repopulated {} delayed_payments rows from snapshot up to height {}",
            count,
            detach);

    if (tx)
        tx->commit();

    log::warning(logcat, "Forcing rescan from block {} to ensure correct reward values", detach);
    return static_cast<uint64_t>(detach);
}

}  // namespace cryptonote
