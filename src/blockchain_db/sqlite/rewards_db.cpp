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

#include "rewards_db.h"

#include <SQLiteCpp/Savepoint.h>
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

#include <algorithm>
#include <cassert>
#include <mutex>
#include <shared_mutex>
#include <type_traits>
#include <variant>

#include "cryptonote_basic/cryptonote_basic.h"
#include "snapshots.h"

namespace {

auto logcat = oxen::log::Cat("blockchain.db.rewards");

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
using db::CREATE_PROPERTIES;
using session::sqlite::blob;
using session::sqlite::blob_guts;
using session::sqlite::Connection;
using tools::span_guts;

// For a write that belongs in `active_tx` if given one, or else in a transaction of its own: returns
// that new transaction (for the caller to commit), or nullopt when given one.
static std::optional<SQLite::Transaction> own_tx(Connection& conn, SQLite::Transaction* active_tx) {
    if (active_tx) {
        assert(!sqlite3_get_autocommit(conn.sql.getHandle()));
        return std::nullopt;
    }
    return std::make_optional<SQLite::Transaction>(
            conn.sql, SQLite::TransactionBehavior::IMMEDIATE);
}

// For a write that reports failure rather than throwing, so whose caller won't abandon its
// transaction when it fails: inside `active_tx` this is a savepoint, so that the failure doesn't
// leave partial writes for that transaction to commit.
class atomic_write {
    std::optional<SQLite::Transaction> tx;
    std::optional<SQLite::Savepoint> savepoint;

  public:
    atomic_write(Connection& conn, SQLite::Transaction* active_tx, const std::string& name) :
            tx{own_tx(conn, active_tx)} {
        if (active_tx)
            savepoint.emplace(conn.sql, name);
    }

    void commit() {
        if (tx)
            tx->commit();
        else
            savepoint->release();
    }
};

static rewards_address address_from_blob(std::span<const std::byte> b) {
    if (b.size() == sizeof(eth::address))
        return tools::make_from_guts<eth::address>(b);
    if (b.size() == sizeof(account_public_address))
        return tools::make_from_guts<account_public_address>(b);
    throw oxen::traced<std::runtime_error>{
            "Invalid {}-byte address in the stored rewards"_format(b.size())};
}

static std::span<const unsigned char> address_bytes(const rewards_address& a) {
    return std::visit(
            [](const auto& addr) -> std::span<const unsigned char> { return span_guts(addr); }, a);
}

static void upgrade_legacy_tables(Connection& conn, const network_type& nettype);
static void migrate_legacy_tables(Connection& conn);
static void create_schema(Connection& conn);

RewardsDB::RewardsDB(network_type nettype, session::sqlite::Database& db) :
        db{db}, nettype{nettype} {
    log::trace(logcat, "RewardsDB::{}", __func__);

    auto conn = db.conn();
    SQLite::Transaction tx{conn.sql, SQLite::TransactionBehavior::IMMEDIATE};
    conn.sql.exec(CREATE_PROPERTIES);
    const bool legacy = conn.table_exists("batched_payments_accrued");
    if (legacy)
        upgrade_legacy_tables(conn, this->nettype);
    create_schema(conn);
    if (legacy)
        migrate_legacy_tables(conn);

    auto newest = conn.prepared_get<std::optional<int64_t>>(
            "SELECT MAX(height) FROM rewards_snapshot_heights");
    load_stored(conn, newest ? as_u64(*newest) : 0);
    tx.commit();

    log::info(
            globallogcat,
            "Rewards of {} addresses ({} delayed payments pending) loaded @ height: {}",
            history.snapshot_rows(height).size(),
            delayed.size(),
            height);
}

// Used in queries.  NOTE: does not include `height`!
static constexpr auto BATCHED_PAYMENTS_COLS =
        "address, amount, payout_offset, lifetime_locked_stakes, lifetime_unlocked_stakes, "
        "lifetime_liquidated_stakes, lifetime_rewards"sv;

constexpr auto CREATE_REWARDS_SNAPSHOTS = R"(
CREATE TABLE IF NOT EXISTS rewards_snapshot_heights (
  height INTEGER PRIMARY KEY
) STRICT;

CREATE TABLE IF NOT EXISTS rewards_snapshots (
  height                     INTEGER NOT NULL REFERENCES rewards_snapshot_heights(height) ON DELETE CASCADE,
  address                    BLOB NOT NULL,
  amount                     INTEGER NOT NULL, -- Claimable amount (lifetime rewards and unlocked stakes)
  payout_offset              INTEGER,
  lifetime_locked_stakes     INTEGER NOT NULL,
  lifetime_unlocked_stakes   INTEGER NOT NULL,
  lifetime_liquidated_stakes INTEGER NOT NULL,
  lifetime_rewards           INTEGER NOT NULL, -- Lifetime accumulated rewards (i.e. not including unlocked stakes)
  PRIMARY KEY(height, address)
  CHECK(amount >= 0)
) STRICT, WITHOUT ROWID;
)";
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
) STRICT;)"_format("table"_a = table_name, "pk"_a = with_height ? "height, address" : "address");

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
) STRICT;
CREATE INDEX {table}_height_idx ON {table}(height);
   )"_format("table"_a = table_name);
}

// Values of the rewards_fixup_version property for DB fixup handling:
constexpr int FIXUP_DELAYED_PAYMENT_REWARDS = 2;

constexpr int FIXUP_MAX = FIXUP_DELAYED_PAYMENT_REWARDS;

static std::optional<int> get_fixup_version(Connection& conn) {
    return conn.prepared_maybe_get<int>(
            "SELECT value FROM properties WHERE key = 'rewards_fixup_version'");
}

static void set_fixup_version(Connection& conn, int version) {
    conn.prepared_exec(
            "INSERT INTO properties (key, value) VALUES ('rewards_fixup_version', ?)"
            " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            version);
}

// The legacy tables' height, as its single row
constexpr auto CREATE_BATCH_DB_HEIGHT = R"(
CREATE TABLE batch_db_height (
  id     INTEGER PRIMARY KEY CHECK (id = 1),
  height INTEGER NOT NULL
) STRICT;
)";

static void create_delayed_payments_indices(Connection& conn) {
    conn.sql.exec(R"(
        CREATE INDEX IF NOT EXISTS delayed_payments_height_idx ON delayed_payments(height);
        CREATE INDEX IF NOT EXISTS delayed_payments_payout_height_idx ON delayed_payments(payout_height);
        CREATE INDEX IF NOT EXISTS delayed_payments_eth_address_idx ON delayed_payments(eth_address);
    )");
}

// Creates whatever of the current tables doesn't exist yet.
static void create_schema(Connection& conn) {
    conn.sql.exec(CREATE_REWARDS_SNAPSHOTS);

    // delayed_payments: Stores time-locked payments that will/did pay out when 'payout_height'
    // is/was reached. This applies when SNs exit the network via dereg: upon confirmation of the
    // associated event removing the node from the ETH side, we create a row in here which is where
    // we store the locked stakes until they are due to be released back into the claimable rewards
    // amount (currently 30 days after dereg, on mainnet).
    //
    // The rows are not deleted when they pay out, because a restore to a snapshot from before then
    // needs them again; see RewardsDB for when they are.
    if (!conn.table_exists("delayed_payments"))
        conn.sql.exec(CREATE_DELAYED_PAYMENTS("delayed_payments"));
    create_delayed_payments_indices(conn);

    if (!get_fixup_version(conn))
        set_fixup_version(conn, FIXUP_MAX);
}

static bool has_column(Connection& conn, std::string_view table, std::string_view column) {
    for (const auto& col : conn.get_columns(table))
        if (col.name == column)
            return true;
    return false;
}

// Brings the tables of releases before 11.7, which kept the live values in the database (in
// batched_payments_accrued, with copies of it in batched_payments_accrued_recent at every height and
// batched_payments_accrued_archive at archive heights), up to the last of their own formats, for
// migrate_legacy_tables to move into the current ones.
static void upgrade_legacy_tables(Connection& conn, const network_type& nettype) {
    bool have_offset = has_column(conn, "batched_payments_accrued", "payout_offset");

    auto& netconf = get_config(nettype);

    // The fixup version used to be kept in PRAGMA user_version, which isn't ours to use when these
    // tables share a database with other things.
    if (!get_fixup_version(conn))
        set_fixup_version(conn, conn.sql.execAndGet("PRAGMA user_version").getInt());

    // The height used to be in a batch_db_info table, which nothing kept to a single row.  (Dropping
    // it drops its triggers too.)
    if (conn.table_exists("batch_db_info")) {
        conn.sql.exec(CREATE_BATCH_DB_HEIGHT);
        conn.sql.exec(R"(
INSERT INTO batch_db_height (id, height) SELECT 1, height FROM batch_db_info LIMIT 1;
DROP TABLE batch_db_info;
)");
    }

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

    if (!conn.table_exists("delayed_payments")) {
        log::debug(logcat, "Adding delayed_payments table to batching db");
        conn.sql.exec(CREATE_DELAYED_PAYMENTS("delayed_payments"));
    }

    // Not all of these were present if the table was created before 11.4.0:
    create_delayed_payments_indices(conn);

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
        // Drop the potentially referencing triggers because otherwise the DROP and/or ALTER below
        // will fail because of SQLite design limitations.
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
                const_cast<network_type*>(&nettype),
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

                    auto nettype = *static_cast<const network_type*>(sqlite3_user_data(ctx));
                    address_parse_info info{};
                    static_assert(std::is_trivially_copyable_v<account_public_address>);
                    if (get_account_address_from_str(info, nettype, addr))
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
                auto db_h = conn.prepared_get<int64_t>(
                        "SELECT height FROM batch_db_height WHERE id = 1");
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

    // NOTE: Add new liquidation field to delayed payment table
    if (!has_column(conn, "delayed_payments", "liquidation_amount"))
        conn.sql.exec(
                "ALTER TABLE delayed_payments ADD COLUMN liquidation_amount INTEGER NOT NULL "
                "DEFAULT 0");
}

// Moves the (upgraded) legacy tables into the current ones: the live values become the snapshot at
// their height, the archived ones snapshots at their archive heights, and the recent ones at heights
// divisible by STATE_SNAPSHOT_INTERVAL snapshots there too (the heights that the SN list stores its
// states at, which makes them heights that both can be restored to).  The ones the retention rules
// don't keep get deleted when the next snapshot is written.
static void migrate_legacy_tables(Connection& conn) {
    const auto h = conn.prepared_get<int64_t>("SELECT height FROM batch_db_height WHERE id = 1");

    conn.prepared_exec("INSERT INTO rewards_snapshot_heights (height) VALUES (?)", h);
    conn.prepared_exec(
            "INSERT INTO rewards_snapshots (height, {0}) SELECT ?, {0} FROM batched_payments_accrued"_format(
                    BATCHED_PAYMENTS_COLS),
            h);

    for (auto [table, condition] :
         {std::pair{"batched_payments_accrued_archive"sv, ""s},
          std::pair{
                  "batched_payments_accrued_recent"sv,
                  " AND height % {} = 0"_format(service_nodes::STATE_SNAPSHOT_INTERVAL)}}) {
        conn.prepared_exec(
                "INSERT OR IGNORE INTO rewards_snapshot_heights (height)"
                " SELECT DISTINCT height FROM {} WHERE height < ?{}"_format(table, condition),
                h);
        conn.prepared_exec(
                "INSERT OR IGNORE INTO rewards_snapshots (height, {0})"
                " SELECT height, {0} FROM {1} WHERE height < ?{2}"_format(
                        BATCHED_PAYMENTS_COLS, table, condition),
                h);
    }

    conn.prepared_exec("DELETE FROM delayed_payments WHERE height > ?", h);
    conn.sql.exec(R"(
        DROP TABLE batched_payments_accrued;
        DROP TABLE batched_payments_accrued_recent;
        DROP TABLE batched_payments_accrued_archive;
        DROP TABLE batch_db_height;
    )");

    log::info(
            globallogcat,
            "Moved the rewards into {} snapshots, the newest at height {}",
            conn.prepared_get<int>("SELECT COUNT(*) FROM rewards_snapshot_heights"),
            h);
}

uint64_t RewardsDB::hf19_height() const {
    return hard_fork_begins(nettype, hf::hf19_reward_batching)
            .value_or(std::numeric_limits<uint64_t>::max());
}

static bool have_stored_snapshot(Connection& conn, uint64_t height) {
    return conn.prepared_get<int>(
            "SELECT EXISTS(SELECT 1 FROM rewards_snapshot_heights WHERE height = ?)",
            as_i64(height));
}

void RewardsDB::load_stored(Connection& conn, uint64_t new_height) {
    conn.prepared_exec(
            "DELETE FROM rewards_snapshot_heights WHERE height > ?", as_i64(new_height));
    conn.prepared_exec("DELETE FROM delayed_payments WHERE height > ?", as_i64(new_height));

    accrued_rows rows;
    for (auto [addr, amount, offset, locked, unlocked, liquidated, rewards] :
         conn.prepared_results<
                 blob,
                 int64_t,
                 std::optional<int32_t>,
                 int64_t,
                 int64_t,
                 int64_t,
                 int64_t>(
                 "SELECT {} FROM rewards_snapshots WHERE height = ?"_format(BATCHED_PAYMENTS_COLS),
                 as_i64(new_height)))
        rows.emplace_back(
                address_from_blob(addr),
                accrued_row{
                        .amount = amount,
                        .payout_offset = offset,
                        .lifetime_locked_stakes = locked,
                        .lifetime_unlocked_stakes = unlocked,
                        .lifetime_liquidated_stakes = liquidated,
                        .lifetime_rewards = rewards});

    std::vector<delayed_payment> pending_payments;
    for (auto [addr, amount, liquidation, payout_h, h, block_h, tx_index, contributor] :
         conn.prepared_results<
                 blob_guts<eth::address>,
                 int64_t,
                 int64_t,
                 int64_t,
                 int64_t,
                 int64_t,
                 int64_t,
                 int64_t>(
                 "SELECT eth_address, amount, liquidation_amount, payout_height, height,"
                 " block_height, block_tx_index, contributor_index"
                 " FROM delayed_payments WHERE payout_height > ?",
                 as_i64(new_height)))
        pending_payments.push_back(
                {.addr = addr,
                 .amount = amount,
                 .liquidation = liquidation,
                 .payout_height = as_u64(payout_h),
                 .height = as_u64(h),
                 .block_height = static_cast<uint32_t>(block_h),
                 .block_tx_index = static_cast<uint32_t>(tx_index),
                 .contributor_index = static_cast<uint32_t>(contributor)});

    pending.reset();
    std::unique_lock lock{mutex};
    history.reset(new_height, rows);
    delayed = std::move(pending_payments);
    height = new_height;
}

void RewardsDB::reset_database(SQLite::Transaction* active_tx) {
    log::trace(logcat, "RewardsDB::{}", __func__);

    auto conn = db.conn();
    auto transaction = own_tx(conn, active_tx);
    reset_to(conn, 0);
    if (transaction)
        transaction->commit();
    log::debug(logcat, "Database reset complete");
}

void RewardsDB::reset_to(Connection& conn, uint64_t new_height) {
    conn.sql.exec(R"(
        DELETE FROM rewards_snapshot_heights;
        DELETE FROM delayed_payments;
    )");
    load_stored(conn, new_height);
}

bool RewardsDB::can_restore(uint64_t h) const {
    if (history.contains(h) || h < hf19_height())
        return true;
    auto conn = db.conn();
    return have_stored_snapshot(conn, h);
}

void RewardsDB::blockchain_detached(uint64_t new_height, SQLite::Transaction* active_tx) {
    auto conn = db.conn();
    auto transaction = own_tx(conn, active_tx);
    const uint64_t prev_height = height;

    std::string_view from;
    if (history.contains(new_height)) {
        conn.prepared_exec(
                "DELETE FROM rewards_snapshot_heights WHERE height > ?", as_i64(new_height));
        conn.prepared_exec("DELETE FROM delayed_payments WHERE height > ?", as_i64(new_height));
        pending.reset();
        std::unique_lock lock{mutex};
        history.rewind(new_height);
        std::erase_if(delayed, [new_height](const auto& d) { return d.height > new_height; });
        height = new_height;
        from = "memory";
    } else if (have_stored_snapshot(conn, new_height)) {
        load_stored(conn, new_height);
        from = "stored snapshot";
    } else if (new_height < hf19_height()) {
        load_stored(conn, new_height);
        from = "pre-HF19 empty state";
    } else {
        throw oxen::traced<std::logic_error>{
                "Internal error: rewards cannot be restored to height {}"_format(new_height)};
    }

    if (transaction)
        transaction->commit();

    log::debug(
            logcat,
            "Rewards detached from height {} to {} (from {})",
            prev_height,
            new_height,
            from);
}

void RewardsDB::begin_block() {
    pending.reset();
}

void RewardsDB::copy_state_from(const RewardsDB& other) {
    std::shared_lock other_lock{other.mutex};
    std::unique_lock lock{mutex};
    history = other.history;
    delayed = other.delayed;
    height = other.height;
    pending.reset();
}

// The row of `addr` at the current height, which (as the values every block builds on) must be known.
static std::optional<accrued_row> current_row(
        const accrued_history& history, const rewards_address& addr, uint64_t height) {
    auto r = history.lookup(addr, height);
    if (!r.known)
        throw oxen::traced<std::logic_error>{
                "Internal error: the rewards at the current height {} are unknown"_format(height)};
    return std::move(r.row);
}

std::optional<accrued_row> RewardsDB::pending_lookup(const rewards_address& addr) const {
    if (pending)
        if (auto it = pending->accrued.find(addr); it != pending->accrued.end())
            return it->second;
    return current_row(history, addr, height);
}

accrued_row& RewardsDB::pending_row(
        const rewards_address& addr, std::optional<int32_t> payout_offset) {
    if (!pending)
        pending.emplace();
    auto [it, inserted] = pending->accrued.try_emplace(addr);
    if (inserted)
        it->second = current_row(history, addr, height);
    if (!it->second)
        it->second.emplace().payout_offset = payout_offset;
    return *it->second;
}

void RewardsDB::update_pending_rows(const std::function<bool(accrued_row&)>& f) {
    if (!pending)
        pending.emplace();
    history.for_each(height, [this](const auto& addr, const auto& row) {
        pending->accrued.try_emplace(addr, row);
    });
    for (auto& [addr, row] : pending->accrued)
        if (row && !f(*row))
            row.reset();
}

// Adds a delayed payment's amounts to `payments`
static void add_delayed(block_payments& payments, const delayed_payment& d) {
    auto& payment = payments[d.addr];
    payment.amount += reward_money::from_db_atomic(d.amount);
    payment.liquidation += reward_money::from_db_atomic(d.liquidation);
}

// The caller holds (at least) a shared lock on the in-memory state, or is the block thread.
RewardsDB::wallet_info RewardsDB::make_wallet_info(
        uint64_t at_height,
        const rewards_address& addr,
        const std::optional<accrued_row>& row,
        std::optional<hf> hf_version) const {
    wallet_info info{at_height, row.has_value()};
    if (row) {
        const auto* eth_addr = std::get_if<eth::address>(&addr);
        assert(row->amount >= 0);

        if (!hf_version)
            hf_version = get_network_version(nettype, at_height);
        auto& amount = info.amount;
        auto& lifetime_locked_stakes = info.lifetime_locked_stakes;
        auto& lifetime_unlocked_stakes = info.lifetime_unlocked_stakes;
        auto& lifetime_liquidated_stakes = info.lifetime_liquidated_stakes;
        auto& lifetime_rewards = info.lifetime_rewards;
        amount = reward_money::from_db_amount(row->amount, *hf_version);
        lifetime_locked_stakes = reward_money::from_db_atomic(row->lifetime_locked_stakes);
        lifetime_unlocked_stakes = reward_money::from_db_atomic(row->lifetime_unlocked_stakes);
        lifetime_liquidated_stakes = reward_money::from_db_atomic(row->lifetime_liquidated_stakes);
        lifetime_rewards = reward_money::from_db_amount(row->lifetime_rewards, *hf_version);
        // LOCKED = STAKES_IN - STAKES_OUT, where STAKES_IN are contributions made, and STAKES_OUT
        // consists of both the amount that got released back to you (lifetime_unlocked_stakes)
        // *and* any liquidation amounts that got subtracted from your balance in case of a
        // liquidation (to match the liquidation amount that got transferred into the pool and
        // liquidator via the SNRewards contract liquidation call).
        info.locked_stakes =
                lifetime_locked_stakes - lifetime_unlocked_stakes - lifetime_liquidated_stakes;

        // NOTE: Some of these fields are only enumerated on ETH addresses so gate error
        // checking behind said flag.
        if (eth_addr) {
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
                bool skip = nettype == network_type::MAINNET && at_height == 1871518;
                if (!skip) {
                    log::error(
                            logcat,
                            "Internal error: SN contributor {} at height {} lifetime claimable "
                            "mismatch:\n"
                            "lifetime claimable {} != {} (= {} rewards + {} unlocked) [lifetime "
                            "stakes={}, liquidated={}]",
                            log_addr{*eth_addr},
                            at_height,
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
            for (const auto& d : delayed) {
                if (d.addr != *eth_addr || d.height > at_height || d.payout_height <= at_height)
                    continue;
                if (d.amount >= d.liquidation)
                    info.timelocked_stakes += reward_money::from_db_atomic(d.amount - d.liquidation);
                else {
                    log::error(
                            logcat,
                            "Internal error: delayed payment liquidation value ({}) is higher than "
                            "the amount ({})",
                            d.liquidation,
                            d.amount);
                    assert(d.amount >= d.liquidation);
                }
            }
        }
    }
    return info;
}

void RewardsDB::add_sn_rewards(
        hf hf_version, const block_payments& payments, bool rewards_payment) {
    ZoneScoped;
    log::trace(logcat, "RewardsDB::{}", __func__);

    const auto& netconf = get_config(nettype);
    for (const auto& [vaddr, payment] : payments) {
        auto amount = payment.amount - payment.liquidation;

        log::trace(
                logcat,
                "Adding record for SN reward contributor {} with amount {}",
                log_addr{vaddr, nettype},
                amount);

        if (hf_version >= hf::hf21_eth) {
            auto& row = pending_row(vaddr);
            row.amount += amount.to_db_amount(hf_version);
            if (rewards_payment)
                row.lifetime_rewards += amount.to_db_amount(hf_version);
            else {
                row.lifetime_unlocked_stakes += amount.to_db_atomic();
                row.lifetime_liquidated_stakes += payment.liquidation.to_db_atomic();
            }
        } else {
            assert(rewards_payment);
            auto offset = static_cast<int32_t>(
                    std::get<account_public_address>(vaddr).modulus(netconf.BATCHING_INTERVAL));
            pending_row(vaddr, offset).amount += amount.to_db_amount(hf_version);
        }
    }
}

std::vector<batch_sn_payment> RewardsDB::get_sn_payments(uint64_t block_height) const {
    ZoneScoped;
    log::trace(logcat, "RewardsDB::{}", __func__);

    // <= here because we might have crap in the db that we don't clear until we actually add
    // the HF block later on.  (This is a pretty slim edge case that happened on devnet and is
    // probably virtually impossible on mainnet).
    if (nettype != network_type::FAKECHAIN &&
        block_height <= hard_fork_begins(nettype, hf::hf19_reward_batching).value_or(0))
        return {};

    const auto& conf = get_config(nettype);
    auto hf_version = get_network_version(nettype, block_height);
    assert(hf_version < hf::hf21_eth);  // HF21+ has no auto-payments and shouldn't call this

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

    const auto offset = static_cast<int32_t>(block_height % conf.BATCHING_INTERVAL);
    const auto min_amount = static_cast<int64_t>(conf.MIN_BATCH_PAYMENT_AMOUNT * BATCH_REWARD_FACTOR);
    accrued_rows due;
    {
        std::shared_lock lock{mutex};
        history.for_each(history.newest(), [&](const auto& addr, const auto& row) {
            if (pre_hf21_final_payout || (row.payout_offset == offset && row.amount >= min_amount))
                due.emplace_back(addr, row);
        });
    }
    std::sort(due.begin(), due.end(), [](const auto& a, const auto& b) {
        return rewards_address_less{}(a.first, b.first);
    });

    std::vector<std::pair<account_public_address, reward_money>> accrued_pairs;
    for (const auto& [addr, row] : due)
        accrued_pairs.emplace_back(
                std::get<account_public_address>(addr),
                reward_money::from_db_amount(row.amount, hf_version));

    if (pre_hf21_final_payout)
        log::debug(
                logcat,
                "block before hf21, doing final payout to addresses not registered for "
                "conversion");

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

RewardsDB::wallet_info RewardsDB::current_wallet_info(const rewards_address& address) const {
    std::shared_lock lock{mutex};
    auto h = history.newest();
    auto r = history.lookup(address, h);
    if (!r.known)
        return {};
    return make_wallet_info(h, address, r.row);
}

std::optional<RewardsDB::wallet_info> RewardsDB::wallet_info_at(
        const rewards_address& address, uint64_t at_height) const {
    std::shared_lock lock{mutex};
    auto r = history.lookup(address, at_height);
    if (!r.known)
        return std::nullopt;
    return make_wallet_info(at_height, address, r.row);
}

RewardsDB::wallet_info RewardsDB::get_accrued_rewards(const eth::address& address) const {
    return current_wallet_info(address);
}

RewardsDB::wallet_info RewardsDB::get_accrued_rewards(const account_public_address& address) const {
    return current_wallet_info(address);
}

std::optional<RewardsDB::wallet_info> RewardsDB::get_accrued_rewards(
        const eth::address& address, uint64_t at_height) const {
    return wallet_info_at(address, at_height);
}

std::optional<RewardsDB::wallet_info> RewardsDB::get_accrued_rewards(
        const account_public_address& address, uint64_t at_height) const {
    return wallet_info_at(address, at_height);
}

RewardsDB::wallet_info RewardsDB::pending_accrued_rewards(
        const eth::address& address, hf hf_version) const {
    return make_wallet_info(height, address, pending_lookup(address), hf_version);
}

std::vector<std::pair<rewards_address, RewardsDB::wallet_info>>
RewardsDB::get_all_accrued_rewards() const {
    ZoneScoped;
    log::trace(logcat, "RewardsDB::{}", __func__);

    std::vector<std::pair<rewards_address, wallet_info>> result;
    std::shared_lock lock{mutex};
    auto h = history.newest();
    for (const auto& [addr, row] : history.snapshot_rows(h))
        result.emplace_back(addr, make_wallet_info(h, addr, row));
    return result;
}

accrued_rows RewardsDB::get_accrued_rows() const {
    std::shared_lock lock{mutex};
    return history.snapshot_rows(history.newest());
}

void RewardsDB::add_rewards(
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

void RewardsDB::reward_handler(
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

    auto delayed = delayed_payments_due(block.get_height());
    if (block.major_version >= hf::hf21_eth)
        add_sn_rewards(block.major_version, std::move(delayed), false /*rewards_payment*/);
    else
        assert(delayed.empty());  // There should be no delayed payments before HF21!

    add_sn_rewards(block.major_version, std::move(payments), true /*rewards_payment*/);
}

block_payments RewardsDB::get_delayed_payments() const {
    ZoneScoped;
    block_payments result;
    std::shared_lock lock{mutex};
    for (const auto& d : delayed)
        if (d.payout_height > history.newest())
            add_delayed(result, d);
    return result;
}

block_payments RewardsDB::get_delayed_payments(const eth::address& addr) const {
    ZoneScoped;
    block_payments result;
    std::shared_lock lock{mutex};
    for (const auto& d : delayed)
        if (d.addr == addr && d.payout_height > history.newest())
            add_delayed(result, d);
    return result;
}

block_payments RewardsDB::delayed_payments_due(uint64_t payout_height) const {
    block_payments result;
    for (const auto& d : delayed)
        if (d.payout_height == payout_height)
            add_delayed(result, d);
    return result;
}

void RewardsDB::submit_stakes_metadata(const service_nodes::block_add_result& block_add) {
    // NOTE: Submit locked stakes.  New ETH addresses that are staking may not have a row yet if
    // it's their first time, because they haven't received rewards yet.
    for (const auto& stake : block_add.locked_stakes) {
        assert(stake.amount.to_coin() > 0);

#ifndef NDEBUG
        auto wallet_info_before =
                make_wallet_info(height, stake.addr, pending_lookup(stake.addr));
#endif

        pending_row(stake.addr).lifetime_locked_stakes += stake.amount.to_db_atomic();

#ifndef NDEBUG
        // NOTE: Verify the operations did what we expected
        auto wallet_info_after = make_wallet_info(height, stake.addr, pending_lookup(stake.addr));
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
    for (const auto& purge : block_add.purged_stakes) {
        assert(purge.amount.to_coin() > 0);

        // NOTE: Verify remaining locked stakes don't go below 0
        auto before = pending_lookup(purge.addr);
        auto wallet_info_before = make_wallet_info(height, purge.addr, before);
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

        // A purge of an address without a row has nothing to undo
        if (!before)
            continue;
        pending_row(purge.addr).lifetime_locked_stakes -= purge.amount.to_db_atomic();

#ifndef NDEBUG
        // NOTE: Verify the operations did what we expected
        auto wallet_info_after = make_wallet_info(height, purge.addr, pending_lookup(purge.addr));
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
}

void RewardsDB::clear_accrued_rewards() {
    update_pending_rows([](accrued_row&) { return false; });
}

void RewardsDB::convert_hf22() {
    log::debug(logcat, "Converting accrued values to atomic SESH");
    update_pending_rows([](accrued_row& row) {
        row.amount /= BATCH_REWARD_FACTOR;
        row.lifetime_rewards /= BATCH_REWARD_FACTOR;
        return true;
    });
}

bool RewardsDB::add_block(
        const block& block,
        const service_nodes::service_node_list::state_t& service_nodes_state,
        const service_nodes::block_add_result& block_add,
        const std::optional<service_nodes::rescan_context>& rescan,
        SQLite::Transaction* active_tx) {
    ZoneScoped;
    auto block_height = block.get_height();
    log::trace(logcat, "RewardsDB::{} called on height: {}", __func__, block_height);

    auto hf_version = block.major_version;
    if (hf_version >= hf::hf19_reward_batching && block_height == hf19_height()) {
        log::debug(logcat, "Batching of Service Node Rewards Begins");
        auto conn = db.conn();
        auto transaction = own_tx(conn, active_tx);
        reset_to(conn, block_height - 1);
        if (transaction)
            transaction->commit();
    }

    if (block_height != height + 1) {
        log::error(
                logcat,
                "Block height ({}) out of sync with batching database ({})",
                block_height,
                (height + 1));
        pending.reset();
        return false;
    }

    try {
        if (hf_version >= hf::hf19_reward_batching) {
            // We query our own values as a source of truth to verify the blocks payments against.
            // The calculated_rewards variable contains a known good list of who should have been
            // paid in this block this only applies before the ETH BLS hard fork. After that the
            // rewards are claimed by the users when they wish
            std::vector<batch_sn_payment> calculated_rewards;
            if (hf_version < feature::ETH_BLS)
                calculated_rewards = get_sn_payments(block_height);

            // We iterate through the block's coinbase payments and build a copy of our own list of
            // the payments miner_tx_vouts this will be compared against calculated_rewards and if
            // they match we know the block is paying the correct people only.
            std::vector<std::pair<crypto::public_key, uint64_t>> miner_tx_vouts;
            if (block.miner_tx)
                for (auto& vout : block.miner_tx->vout)
                    miner_tx_vouts.emplace_back(
                            std::get<txout_to_key>(vout.target).key, vout.amount);

            // Checks the miner transaction's vouts are right, and subtracts them as paid
            if (!validate_batch_payment(miner_tx_vouts, calculated_rewards, block_height, rescan)) {
                pending.reset();
                return false;
            }

            reward_handler(block, service_nodes_state, block_add);
            if (hf_version >= hf::hf21_eth)
                submit_stakes_metadata(block_add);
        }

        publish_block(rescan, active_tx);
    } catch (std::exception& e) {
        pending.reset();
        log::error(
                logcat,
                "Error adding reward payments at block {}: {}",
                block.get_height(),
                e.what());
        return false;
    }
    return true;
}

void RewardsDB::publish_block(
        const std::optional<service_nodes::rescan_context>& rescan,
        SQLite::Transaction* active_tx) {
    const uint64_t block_height = height + 1;
    pending_block changes = pending ? std::move(*pending) : pending_block{};
    pending.reset();
    for (const auto& [addr, row] : changes.accrued)
        if (row && row->amount < 0)
            throw oxen::traced<std::runtime_error>{
                    "Accrued amount of {} would become negative"_format(log_addr{addr, nettype})};

    {
        std::unique_lock lock{mutex};
        history.advance(block_height, changes.accrued);
        delayed.insert(delayed.end(), changes.delayed.begin(), changes.delayed.end());
        std::erase_if(delayed, [oldest = history.oldest()](const auto& d) {
            return d.payout_height <= oldest;
        });
        height = block_height;
    }

    bool snapshot = wants_snapshot(block_height, rescan);
    if (!snapshot && changes.delayed.empty())
        return;
    try {
        auto conn = db.conn();
        atomic_write write{conn, active_tx, "rewards_add_block"};
        for (const auto& d : changes.delayed)
            conn.prepared_exec(
                    "INSERT INTO delayed_payments (eth_address, amount, liquidation_amount,"
                    " payout_height, height, block_height, block_tx_index, contributor_index)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    span_guts(d.addr),
                    d.amount,
                    d.liquidation,
                    as_i64(d.payout_height),
                    as_i64(d.height),
                    d.block_height,
                    d.block_tx_index,
                    d.contributor_index);
        if (snapshot)
            write_snapshot(conn, block_height);
        write.commit();
    } catch (...) {
        std::unique_lock lock{mutex};
        history.rewind(block_height - 1);
        std::erase_if(delayed, [block_height](const auto& d) { return d.height == block_height; });
        height = block_height - 1;
        throw;
    }
}

void RewardsDB::add_delayed_payments(
        std::span<const service_nodes::eth_stake> payments,
        uint64_t at_height,
        uint64_t delay_blocks) {
    ZoneScoped;
    log::trace(logcat, "RewardsDB::{} called", __func__);
    assert(at_height == height + 1);
    if (!pending)
        pending.emplace();

    // Each exit stake is identified by where its event is in the chain, which (as the stored
    // delayed payments' UNIQUE constraint requires) only one payment may come from.
    auto exists = [this](const service_nodes::eth_stake& p) {
        auto same = [&p](const delayed_payment& d) {
            return d.block_height == p.block_height && d.block_tx_index == p.tx_index &&
                   d.contributor_index == p.contributor_index;
        };
        return std::ranges::any_of(delayed, same) || std::ranges::any_of(pending->delayed, same);
    };
    if (std::ranges::any_of(payments, exists)) {
        log::error(
                logcat,
                "Error returning stakes: a delayed payment already exists for the exit at block {}",
                payments.front().block_height);
        return;
    }

    uint64_t payout_height = at_height + std::max<uint64_t>(delay_blocks, 1);
    for (const auto& payment : payments) {
        log::trace(
                logcat,
                "Adding delayed payment for SN reward contributor {} with amount {}; height {};"
                " payout height {}",
                log_addr{payment.addr},
                payment.amount,
                at_height,
                payout_height);
        pending->delayed.push_back(
                {.addr = payment.addr,
                 .amount = payment.amount.to_db_atomic(),
                 .liquidation = payment.liquidation.to_db_atomic(),
                 .payout_height = payout_height,
                 .height = at_height,
                 .block_height = payment.block_height,
                 .block_tx_index = payment.tx_index,
                 .contributor_index = payment.contributor_index});
    }
}

bool RewardsDB::wants_snapshot(
        uint64_t h, const std::optional<service_nodes::rescan_context>& rescan) const {
    const auto& netconf = get_config(nettype);
    const bool grid = h % service_nodes::STATE_SNAPSHOT_INTERVAL == 0;
    const bool archive = h % netconf.HISTORY_ARCHIVE_INTERVAL == 0;
    if (!rescan)
        return grid || archive;

    // A rescan doesn't write the snapshots that the retention rules would delete again before it
    // reaches the top of the chain (as the SN list doesn't write the states it would delete).
    const uint64_t top = rescan->top_block_height > 0 ? rescan->top_block_height - 1 : 0;
    const uint64_t below_top = top > h ? top - h : 0;
    return (grid && below_top < 3 * service_nodes::STATE_SNAPSHOT_INTERVAL) ||
           (archive && h >= service_nodes::oldest_retained_archive(netconf, top));
}

void RewardsDB::write_snapshot(Connection& conn, uint64_t h) {
    ZoneScoped;
    conn.prepared_exec("DELETE FROM rewards_snapshot_heights WHERE height = ?", as_i64(h));
    conn.prepared_exec("INSERT INTO rewards_snapshot_heights (height) VALUES (?)", as_i64(h));
    for (const auto& [addr, row] : history.snapshot_rows(h))
        conn.prepared_exec(
                "INSERT INTO rewards_snapshots (height, {}) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"_format(
                        BATCHED_PAYMENTS_COLS),
                as_i64(h),
                address_bytes(addr),
                row.amount,
                row.payout_offset,
                row.lifetime_locked_stakes,
                row.lifetime_unlocked_stakes,
                row.lifetime_liquidated_stakes,
                row.lifetime_rewards);

    // The retention rules (see RewardsDB)
    const auto& netconf = get_config(nettype);
    if (auto third_newest = conn.prepared_maybe_get<int64_t>(
                "SELECT height FROM rewards_snapshot_heights ORDER BY height DESC LIMIT 1 OFFSET 2"))
        conn.prepared_exec(
                "DELETE FROM rewards_snapshot_heights WHERE height < ?"
                " AND NOT (height % ? = 0 AND height >= ?)",
                *third_newest,
                as_i64(netconf.HISTORY_ARCHIVE_INTERVAL),
                as_i64(service_nodes::oldest_retained_archive(netconf, h)));
    conn.prepared_exec(
            "DELETE FROM delayed_payments"
            " WHERE payout_height <= (SELECT MIN(height) FROM rewards_snapshot_heights)");
}

bool RewardsDB::validate_batch_payment(
        const std::vector<std::pair<crypto::public_key, uint64_t>>& miner_tx_vouts,
        const std::vector<batch_sn_payment>& calculated_payments_from_batching_db,
        uint64_t block_height,
        const std::optional<service_nodes::rescan_context>& rescan) {
    ZoneScoped;
    log::trace(logcat, "RewardsDB::{}", __func__);

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

bool RewardsDB::save_payments(
        uint64_t block_height, std::span<const batch_sn_payment> paid_amounts) {
    ZoneScoped;
    log::trace(logcat, "RewardsDB::{}", __func__);

    for (const auto& payment : paid_amounts) {
        if (auto row = pending_lookup(payment.address)) {
            // Truncate the thousanths amount to an atomic OXEN:
            // Hard-code hf20 here because this code only runs in HF20 and earlier (and
            // from_db_amount is the same for everything <= 21).
            auto amount = reward_money::from_db_amount(row->amount, hf::hf20_eth_transition);
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

            pending_row(payment.address).amount -=
                    payment.amount.to_db_amount(hf::hf20_eth_transition);
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
    if (paid_amounts.size()) {
        std::vector<rewards_address> zeroed;
        history.for_each(height, [&](const auto& addr, const auto& row) {
            if (row.amount == 0 && !pending->accrued.count(addr))
                zeroed.push_back(addr);
        });
        for (auto& [addr, row] : pending->accrued)
            if (row && row->amount == 0)
                row.reset();
        for (const auto& addr : zeroed)
            pending->accrued[addr] = std::nullopt;
    }
    return true;
}

std::optional<uint64_t> RewardsDB::fixup(bool recheck, SQLite::Transaction* active_tx) {
    auto conn = db.conn();
    auto tx = own_tx(conn, active_tx);

    auto with_commit = [&tx](std::optional<uint64_t> ret) {
        if (tx)
            tx->commit();
        return ret;
    };

    auto prev_db_version = get_fixup_version(conn).value_or(0);
    if (!recheck) {
        if (prev_db_version >= FIXUP_DELAYED_PAYMENT_REWARDS)
            return with_commit(std::nullopt);

        set_fixup_version(conn, FIXUP_DELAYED_PAYMENT_REWARDS);
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

    // We are *always* going to force delete all HF21+ snapshots other than those at the archive
    // heights checked below, because we just don't know if they are correct and we need to rescan
    // from one of the known-correct archive heights (or from our reproduced 1890k snapshot, if your
    // node has an invalid 1890k value).
    if (!recheck) {
        std::string checked;
        for (const auto& r : RECORDS)
            checked += "{}{}"_format(checked.empty() ? "" : ", ", r.height);
        conn.prepared_exec(
                "DELETE FROM rewards_snapshot_heights WHERE height >= ? AND height NOT IN ({})"_format(
                        checked),
                as_i64(hf21_started));
    }

    //
    // If any of the archive checksums don't match the above then we will delete it because it isn't
    // correct and we don't ever want you to use it (e.g. if you every roll back into the range).
    bool have_snapshot_height = false;
    for (const auto& [archive_height, checksum] : RECORDS) {
        auto [db_csum, db_count] = conn.prepared_get<std::optional<int64_t>, int>(
                "SELECT SUM(amount % ?), COUNT(*) FROM rewards_snapshots WHERE height = ?",
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
                    db_csum.value_or(0),
                    checksum);
            return with_commit(0);  // any non-nullopt signifies the failure
        }

        log::warning(
                logcat,
                "Deleting invalid reward archive at blk {} (checksum failed)",
                archive_height);
        conn.prepared_exec(
                "DELETE FROM rewards_snapshot_heights WHERE height = ?", archive_height);
    }

    if (recheck)
        return with_commit(std::nullopt);  // Passed all rechecks

    if (height >= static_cast<uint64_t>(snapshots::height) && !have_snapshot_height) {
        // As long as we are synced above 1'890'000 then we can load our hard-coded snapshot data
        // to rescan from there even if you had invalid 1'890'000 reward data.
        detach = snapshots::height;
        conn.prepared_exec(
                "INSERT INTO rewards_snapshot_heights (height) VALUES (?)", snapshots::height);
        for (auto& r : snapshots::batched_payments)
            conn.prepared_exec(
                    "INSERT INTO rewards_snapshots (height, {}) VALUES (?, ?, ?, NULL, ?, ?, ?, ?)"_format(
                            BATCHED_PAYMENTS_COLS),
                    snapshots::height,
                    span_guts(r.addr),
                    r.amount,
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

    // The in-memory values (from above `detach`) are among those we don't trust, so the rewards go
    // back to the newest snapshot we do; the detach that follows then goes no higher than that.
    if (auto restore = conn.prepared_get<std::optional<int64_t>>(
                "SELECT MAX(height) FROM rewards_snapshot_heights WHERE height <= ?", detach))
        load_stored(conn, as_u64(*restore));
    else
        reset_to(conn, 0);

    if (tx)
        tx->commit();

    log::warning(logcat, "Forcing rescan from block {} to ensure correct reward values", detach);
    return static_cast<uint64_t>(detach);
}

}  // namespace cryptonote
