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

namespace cryptonote {

static auto logcat = log::Cat("blockchain.db.sqlite");

BlockchainSQLite::BlockchainSQLite(
        cryptonote::network_type nettype, std::filesystem::path db_path) :
        db::Database(db_path, ""), m_nettype(nettype) {
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);
    height = 0;

    if (!table_exists("batched_payments_accrued"))
        create_schema();
    upgrade_schema();

    height = prepared_get<int64_t>("SELECT height FROM batch_db_info");

    uint64_t row_count =
            batch_payments_accrued_row_count(PaymentTableType::Nil, /*height*/ std::nullopt);
    uint64_t recent_count =
            batch_payments_accrued_row_count(PaymentTableType::Recent, /*height*/ std::nullopt);
    uint64_t recent_min_height =
            prepared_get<int>("SELECT MIN(height) FROM batched_payments_accrued_recent");
    uint64_t recent_max_height =
            prepared_get<int>("SELECT MAX(height) FROM batched_payments_accrued_recent");

    uint64_t archive_count =
            batch_payments_accrued_row_count(PaymentTableType::Archive, /*height*/ std::nullopt);
    uint64_t archive_min_height =
            prepared_get<int>("SELECT MIN(height) FROM batched_payments_accrued_archive");
    uint64_t archive_max_height =
            prepared_get<int>("SELECT MAX(height) FROM batched_payments_accrued_archive");

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

static std::string CREATE_BATCHED_PAYMENTS(std::string_view table_name, bool with_height) {
    std::string result = R"(CREATE TABLE {}(
  address                    TEXT NOT NULL,
  amount                     INTEGER NOT NULL DEFAULT 0, -- Claimable amount (lifetime rewards and unlocked stakes)
  payout_offset              INTEGER,)"_format(table_name);

    if (with_height)
        result += R"(
  height                     INTEGER NOT NULL DEFAULT 0, -- Height at which the row was recorded)";

    result += R"(
  lifetime_locked_stakes     INTEGER NOT NULL DEFAULT 0,
  lifetime_unlocked_stakes   INTEGER NOT NULL DEFAULT 0,
  lifetime_liquidated_stakes INTEGER NOT NULL DEFAULT 0,
  lifetime_rewards           INTEGER NOT NULL DEFAULT 0, -- Lifetime accumulated rewards (i.e. not including unlocked stakes)
  PRIMARY KEY({})
  CHECK(amount >= 0)
);)"_format(with_height ? "height, address" : "address");

    return result;
}

static std::string CREATE_DELAYED_PAYMENTS(std::string_view table_name) {
    return R"(
CREATE TABLE {0}(
  eth_address        TEXT    NOT NULL,
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
CREATE INDEX {0}_height_idx ON {0}(height);
   )"_format(table_name);
}

void BlockchainSQLite::create_schema() {
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);
    auto& netconf = cryptonote::get_config(m_nettype);

    if (!table_exists("batched_payments_accrued"))
        db.exec(CREATE_BATCHED_PAYMENTS("batched_payments_accrued", false));
    db.exec(R"(CREATE INDEX IF NOT EXISTS batched_payments_accrued_payout_offset_idx ON batched_payments_accrued(payout_offset);
               CREATE TABLE IF NOT EXISTS batch_db_info(height INTEGER NOT NULL);
               INSERT INTO  batch_db_info(height) VALUES(0);)");
    log::debug(logcat, "Database setup complete");
}

bool BlockchainSQLite::table_exists(const std::string& table_name) {
    return prepared_get<int>(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)", table_name);
}

bool BlockchainSQLite::index_exists(const std::string& index_name) {
    return prepared_get<int>(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='index' AND name=?)", index_name);
}

bool BlockchainSQLite::trigger_exists(const std::string& trigger_name) {
    return prepared_get<int>(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='trigger' AND name=?)",
            trigger_name);
}

std::optional<SQLite::Transaction> BlockchainSQLite::begin_tx(SQLite::TransactionBehavior behave) {
    if (rescan_tx)
        return std::nullopt;
    return std::make_optional<SQLite::Transaction>(db, behave);
}

void BlockchainSQLite::upgrade_schema() {
    bool have_offset = false;
    for (SQLite::Statement msg_cols{db, "PRAGMA main.table_info(batched_payments_accrued)"};
         msg_cols.executeStep();) {
        auto [cid, name] = db::get<int64_t, std::string>(msg_cols);
        if (name == "payout_offset")
            have_offset = true;
    }

    auto& netconf = get_config(m_nettype);

    auto transaction = begin_tx();
    // NOTE: Rename 'batched_payments_accrued_archive' 'archive_height' column to 'height'. This
    // unifies the height label across the batch payment, recent and archive table making querying
    // from them require less code.
    // TODO: Eventually we can remove this code (doing so will make it impossible to upgrade a
    // pre-HF20 oxend database).
    {
        bool has_deprecated_archive_height_column = false;
        SQLite::Statement msg_cols{db, "PRAGMA main.table_info(batched_payments_accrued_archive)"};
        while (msg_cols.executeStep()) {
            auto [cid, name] = db::get<int64_t, std::string>(msg_cols);
            if (name == "archive_height") {
                has_deprecated_archive_height_column = true;
                break;
            }
        }

        if (has_deprecated_archive_height_column)
            db.exec("ALTER TABLE batched_payments_accrued_archive RENAME COLUMN archive_height to "
                    "height;\n");
    }

    if (!have_offset) {
        log::debug(logcat, "Adding payout_offset to batching db");

        db.exec(R"(
            ALTER TABLE batched_payments_accrued ADD COLUMN payout_offset INTEGER;
            CREATE INDEX batched_payments_accrued_payout_offset_idx ON batched_payments_accrued(payout_offset);
        )");

        auto st = prepared_st(
                "UPDATE batched_payments_accrued SET payout_offset = ? WHERE address = ?");
        for (const auto& address : prepared_results<std::string>("SELECT address FROM "
                                                                 "batched_payments_accrued")) {
            cryptonote::address_parse_info addr_info{};
            cryptonote::get_account_address_from_str(addr_info, m_nettype, address);
            auto offset = static_cast<int>(addr_info.address.modulus(netconf.BATCHING_INTERVAL));
            exec_query(st, offset, address);
            st->reset();
        }

        auto count = prepared_get<int>(
                "SELECT COUNT(*) FROM batched_payments_accrued WHERE payout_offset IS NULL");

        if (count != 0) {
            constexpr auto error =
                    "Batching db update to add offsets failed: not all addresses were converted";
            log::error(logcat, error);
            throw oxen::traced<std::runtime_error>{error};
        }
    }

    // delayed_payments: Stores time-locked payments that will be paid out once 'payout_height' is
    // met. This is typically then for when SN's exit the network, their stake is locked for X
    // amount of time before the network merges these payments into 'batch_payments_accrued`.
    //
    // The network will then uniformly agree to sign a signature to permit the address to withdraw
    // those tokens from the smart contract.
    //
    // delayed_payments_archive: stores copies of 'delayed_payments' rows at intervals of
    // 'HISTORY_ARCHIVE_INTERVAL' blocks in a rolling window of 'HISTORY_ARCHIVE_KEEP_WINDOW'
    //
    // delayed_payments_recent: stores copies of 'batch_payments_accrued' rows at each height in a
    // rolling window consisting of the past 'HISTORY_RECENT_KEEP_WINDOW' heights.
    for (auto table : {"delayed_payments", "delayed_payments_archive", "delayed_payments_recent"}) {
        if (!table_exists(table)) {
            log::debug(logcat, "Adding {} table to batching db", table);
            db.exec(CREATE_DELAYED_PAYMENTS(table));
        }
    }
    // Not all of these were present if the table was created before 11.4.0:
    db.exec(R"(
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
        if (!table_exists(table)) {
            log::debug(logcat, "Adding {} to batching db", table);
            db.exec(CREATE_BATCHED_PAYMENTS(table, true));
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

        for (auto it : tables) {
            for (auto field : fields) {
                bool has_field = false;
                SQLite::Statement msg_cols{db, "PRAGMA main.table_info({})"_format(it)};
                while (msg_cols.executeStep()) {
                    auto [cid, name] = db::get<int64_t, std::string>(msg_cols);
                    if (name == field) {
                        has_field = true;
                        break;
                    }
                }
                msg_cols.reset();

                if (!has_field)
                    db.exec("ALTER TABLE {} ADD COLUMN {} INTEGER NOT NULL DEFAULT 0;"_format(
                            it, field));
            }
        }
    }

    bool dropped_accrued_triggers = false;
    for (auto table :
         {"batched_payments_accrued",
          "batched_payments_accrued_archive",
          "batched_payments_accrued_recent"}) {
        // Before 11.4.0 the state of these tables was rather variable, depending on when they were
        // created and the range over which a rescan happened.
        // - they might or might not have a CHECK constraint on the non-consensus accounting fields
        //   (lifetime_locked_stakes, etc.) that could, in the presence of bugs or unexpected
        //   network events (such as purges) result in a check constraint failure in the middle of a
        //   block update, with catastrophic effects leaving the current SN state half-mutated.
        //   - the CHECK constraints are present on new 11.3.0+ installs that sync from scratch
        //   - the CHECK constraints are missing on installs that upgraded to 11.2.0, *unless*:
        //   - the CHECK constraints are present on 11.3.0+ installs that rescanned the SN state
        //     from some height before HF19.
        // - for archive/recent, they might or might not have a UNIQUE(address, height) constraint
        //   - conditions are essentially the same as the as for the CHECK constraints presence
        //     above.
        //   - in either case, these should be a PRIMARY KEY(height, address) instead (not the
        //     reversed order), so that we don't need a separate index on `height`, and because we
        //     never query these tables by address.
        // - payout_offset was NOT NULL (and no longer is) and might or might not have a default,
        //   and if present could be 0 or -1 depending on how the table was created and/or upgraded
        //   in past releases.
        // - amount might or might not have a default, and might have been declared as either
        //   INTEGER or BIGINT
        // - archive/recent have an index on `height` which is unnecessary with the above primary
        //   key and should be dropped.
        //
        // And so here we basically look for anything that isn't our current CREATE TABLE statement
        // and, if we find it, recreate the whole thing (copying current data from old to new to
        // avoid needing a rescan).

        const bool is_primary = table == "batched_payments_accrued"sv;

        // The most recent change we've made is to make `payout_offset` nullable, so that's what we
        // look for here for our decision of whether to recreate:
        bool recreate = false;
        for (SQLite::Statement msg_cols{db, "PRAGMA main.table_info({})"_format(table)};
             msg_cols.executeStep();) {
            auto [cid, name, type, notnull] =
                    db::get<int64_t, std::string, std::string, int>(msg_cols);
            if (name == "payout_offset"sv) {
                recreate = notnull;
                break;
            }
        }
        if (!recreate)
            continue;

        log::debug(logcat, "Upgrading {} table for consistency", table);

        db.exec(CREATE_BATCHED_PAYMENTS(
                "{}_tmp"_format(table),
                /*with_height=*/!is_primary));
        db.exec("INSERT INTO {0}_tmp ({1}{2}) SELECT {1}{2} FROM {0}"_format(
                table,
                is_primary ? "" : "height, ",
                "address, amount, payout_offset, lifetime_locked_stakes, lifetime_unlocked_stakes, "
                "lifetime_liquidated_stakes, lifetime_rewards"));

        if (!dropped_accrued_triggers) {
            // Drop the potentially referencing triggers (they will get recreated below)
            // because otherwise the DROP and/or ALTER below will fail because of SQLite design
            // limitations.
            db.exec(R"(
                DROP TRIGGER IF EXISTS make_recent;
                DROP TRIGGER IF EXISTS make_archive;
                DROP TRIGGER IF EXISTS clear_recent_and_archive;
            )");
            dropped_accrued_triggers = true;
        }
        db.exec(R"(
            DROP TABLE {0};
            ALTER TABLE {0}_tmp RENAME TO {0};
            UPDATE {0} SET payout_offset = NULL WHERE length(address) = 42; -- eth address rows
        )"_format(table));
        if (is_primary)
            db.exec("CREATE INDEX IF NOT EXISTS {0}_payout_offset_idx ON {0}(payout_offset)"_format(
                    table));
    }

    // This code block could be moved, someday, into schema creation to avoid needing to recreate
    // the trigger on every startup.  However both HF20 and the copied/recreated tables above update
    // things in such a way that this needs to be created anyway and so, pending some database
    // upgrade refactor, we just always do it to be safe.
    //
    // - make_recent
    // - make_archive
    // - clear_recent_and_archive
    // - delayed_payments_prune
    //
    // Triggers to maintain the table when blocks are added or the blockchain
    // detaches with the following format specifiers. Note that _order_ of the
    // triggers is important as the operations has side effects on tables.
    //
    // {0} => Recent window    => HISTORY_RECENT_KEEP_WINDOW
    // {1} => Archive interval => HISTORY_ARCHIVE_INTERVAL
    // {2} => Archive window   => HISTORY_ARCHIVE_KEEP_WINDOW
    //
    {
        db.exec(
                R"(
        -- Saves the current payments into their recent table(s) for the current height
        DROP   TRIGGER IF EXISTS make_recent;
        CREATE TRIGGER           make_recent AFTER UPDATE ON batch_db_info
        FOR EACH ROW WHEN NEW.height > OLD.height BEGIN
            -- Batched payments
            INSERT INTO batched_payments_accrued_recent
                SELECT address, amount, payout_offset, NEW.height, lifetime_locked_stakes,
                    lifetime_unlocked_stakes, lifetime_liquidated_stakes, lifetime_rewards
                FROM batched_payments_accrued;

            DELETE FROM batched_payments_accrued_recent WHERE height < (NEW.height - {0});

            -- Delayed payments
            INSERT INTO delayed_payments_recent SELECT * FROM  delayed_payments WHERE height == NEW.height;
            DELETE FROM delayed_payments_recent WHERE height < (NEW.height - {0});

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
        DROP   TRIGGER IF EXISTS make_archive;
        CREATE TRIGGER           make_archive AFTER UPDATE ON batch_db_info
        FOR EACH ROW WHEN (NEW.height % {1}) = 0 AND NEW.height > OLD.height BEGIN

            -- Batch payments
            INSERT INTO batched_payments_accrued_archive
                SELECT address, amount, payout_offset, NEW.height, lifetime_locked_stakes,
                    lifetime_unlocked_stakes, lifetime_liquidated_stakes, lifetime_rewards
                FROM batched_payments_accrued;

            DELETE FROM batched_payments_accrued_archive
                WHERE height < (NEW.height - {2});

            -- Delayed payments
            INSERT INTO delayed_payments_archive SELECT * FROM delayed_payments;
            DELETE FROM delayed_payments_archive WHERE height < (NEW.height - {2});

        END;

        -- On re-org to a lower height, delete all recent rows that are newer
        -- than the re-org height in all the tables
        --
        -- We rename the trigger to be more apt for its new role of handling
        -- both archive and recent tables.
        DROP   TRIGGER IF EXISTS clear_archive;
        DROP   TRIGGER IF EXISTS clear_recent;
        DROP   TRIGGER IF EXISTS clear_recent_and_archive;
        CREATE TRIGGER           clear_recent_and_archive AFTER UPDATE ON batch_db_info
        FOR EACH ROW WHEN NEW.height < OLD.height BEGIN

            -- Batched payments
            DELETE FROM batched_payments_accrued_recent  WHERE height > NEW.height;
            DELETE FROM batched_payments_accrued_archive WHERE height > NEW.height;

            -- Delayed payments
            DELETE FROM delayed_payments_recent          WHERE height > NEW.height;
            DELETE FROM delayed_payments_archive         WHERE height > NEW.height;

        END;

        -- Delete processed delayed payments from the DB when a block is added to the blockchain
        DROP TRIGGER IF EXISTS delayed_payments_prune;
        CREATE TRIGGER         delayed_payments_prune AFTER UPDATE ON batch_db_info
        FOR EACH ROW WHEN NEW.height > OLD.height BEGIN
            DELETE FROM delayed_payments WHERE payout_height <= NEW.height;
        END;

        -- Remove old trigger from pre-ETH hardfork. It is replaced with a manual delete of rows
        -- when the correct conditions are met.
        DROP TRIGGER IF EXISTS batch_payments_delete_empty;
        )"_format(netconf.HISTORY_RECENT_KEEP_WINDOW,
                  netconf.HISTORY_ARCHIVE_INTERVAL,
                  netconf.HISTORY_ARCHIVE_KEEP_WINDOW));
    }

    // NOTE: Add new liquidation field to delayed payment table
    {
        std::string_view tables[] = {
                "delayed_payments",
                "delayed_payments_archive",
                "delayed_payments_recent",
        };

        constexpr std::string_view field = "liquidation_amount";
        for (auto it : tables) {
            bool has_field = false;
            SQLite::Statement msg_cols{db, "PRAGMA main.table_info({})"_format(it)};
            while (msg_cols.executeStep()) {
                auto [cid, name] = db::get<int64_t, std::string>(msg_cols);
                if (name == field) {
                    has_field = true;
                    break;
                }
            }
            msg_cols.reset();

            if (!has_field)
                db.exec("ALTER TABLE {} ADD COLUMN {} INTEGER NOT NULL DEFAULT 0;"_format(
                        it, field));
        }
    }

    // NOTE: Remove deprecated tables, this can be removed post HF21 as everyone
    // will have upgraded.
    db.exec(R"(DROP TABLE IF EXISTS batched_payments_accrued_raw;
               DROP VIEW  IF EXISTS batched_payments_accrued_paid;)");

    if (transaction)
        transaction->commit();
}

void BlockchainSQLite::reset_database() {
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    db.exec(R"(
      DROP TABLE IF EXISTS delayed_payments;
      DROP TABLE IF EXISTS delayed_payments_archive;
      DROP TABLE IF EXISTS delayed_payments_recent;

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
    prepared_exec("UPDATE batch_db_info SET height = ?", static_cast<int64_t>(height));
}

void BlockchainSQLite::blockchain_detached(
        PaymentTableType history, uint64_t new_height, uint64_t target_height) {
    const auto& netconf = get_config(m_nettype);

    std::string detach_label = "";
    int rows_restored = 0;
    int rows_removed = 0;
    if (new_height == height) {
        detach_label = " (DB is already at requested height)";
    } else {
        // NOTE: Execute detach
        rows_removed = batch_payments_accrued_row_count(PaymentTableType::Nil, std::nullopt);
        switch (history) {
            case PaymentTableType::Nil: {
                reset_database();
                detach_label = " (via reset)";
            } break;

            default: {
                const auto suffix = history == PaymentTableType::Archive ? "archive"sv : "recent"sv;
                rows_restored = batch_payments_accrued_row_count(history, new_height);
                prepared_exec("DELETE FROM batched_payments_accrued");
                prepared_exec(
                        "INSERT INTO batched_payments_accrued "
                        "SELECT address, amount, payout_offset, lifetime_locked_stakes,"
                        " lifetime_unlocked_stakes, lifetime_liquidated_stakes, lifetime_rewards"
                        " FROM batched_payments_accrued_{}"
                        " WHERE height = ?"_format(suffix),
                        static_cast<int64_t>(new_height));
                prepared_exec("DELETE FROM delayed_payments");
                prepared_exec(
                        "INSERT INTO delayed_payments "
                        " SELECT * FROM delayed_payments_{}"
                        " WHERE ? BETWEEN height AND payout_height"_format(suffix),
                        static_cast<int64_t>(new_height));
            } break;
        }
    }

    update_height(new_height);

    if (height + 5000 < target_height) {
        log::debug(logcat, "large rescan starting");
        rescan_target = target_height;
        rescan_start();
    } else {
        log::debug(
                logcat, "not large rescan, height = {}, target_height = {}", height, target_height);
    }

    log::debug(
            logcat,
            "Detach request for SQL @ {} executed to {}{} (-{} rows deleted, +{} restored)",
            new_height,
            height,
            detach_label,
            rows_removed,
            rows_restored);
}

const std::string& BlockchainSQLite::get_address_str(const cryptonote::batch_sn_payment& addr) {
    ZoneScoped;
    auto& address_str = address_str_cache[addr.address_info.address];
    if (address_str.empty())
        address_str =
                cryptonote::get_account_address_as_str(m_nettype, 0, addr.address_info.address);
    return address_str;
}

// Format an ETH address to the representation that is used in the DB.
//
// TODO: This should be changed to a binary blob instead of a string. Note that the native
// formatting of an ETH address is now the checksum address, and so we explicitly use {:x} here to
// maintain the lower-case hex representation in the database.  We should at some point just migrate
// entirely to byte addresses.
static std::string eth_address_to_sql_address(const eth::address& addr) {
    return "0x{:x}"_format(addr);
}

std::pair<std::optional<int>, std::string> BlockchainSQLite::get_address_str(
        const std::variant<eth::address, cryptonote::account_public_address>& addr,
        uint64_t batching_interval) {
    ZoneScoped;
    std::pair<std::optional<int>, std::string> result;
    auto& [offset, address_str] = result;
    if (auto* eth_addr = std::get_if<eth::address>(&addr)) {
        address_str = eth_address_to_sql_address(*eth_addr);
    } else {
        auto* oxen_addr = std::get_if<cryptonote::account_public_address>(&addr);
        assert(oxen_addr);
        offset = static_cast<int>(oxen_addr->modulus(batching_interval));
        auto& cached = address_str_cache[*oxen_addr];
        if (cached.empty())
            cached = cryptonote::get_account_address_as_str(m_nettype, 0, *oxen_addr);
        address_str = cached;
    }
    return result;
}

constexpr std::string_view WALLET_METADATA_FIELDS =
        " amount,"
        " lifetime_locked_stakes,"
        " lifetime_unlocked_stakes,"
        " lifetime_liquidated_stakes,"
        " lifetime_rewards";

static BlockchainSQLite::wallet_info wallet_metadata_tuple_to_wallet_info(
        BlockchainSQLite& db,
        std::string_view address,
        std::optional<std::tuple<int64_t, int64_t, int64_t, int64_t, int64_t>> metadata,
        uint64_t height) {
    BlockchainSQLite::wallet_info result = {};
    result.height = height;
    if (metadata) {
        eth::address eth_addr = {};
        bool is_eth = tools::try_load_from_hex_guts(address, eth_addr);

        auto [amount,
              lifetime_locked_stakes,
              lifetime_unlocked_stakes,
              lifetime_liquidated_stakes,
              lifetime_rewards] = *metadata;
        assert(amount >= 0);

        result.found = true;
        result.amount = cryptonote::reward_money::db_amount(amount);
        result.lifetime_locked_stakes = cryptonote::reward_money::db_amount(lifetime_locked_stakes);
        result.lifetime_unlocked_stakes =
                cryptonote::reward_money::db_amount(lifetime_unlocked_stakes);
        result.lifetime_liquidated_stakes =
                cryptonote::reward_money::db_amount(lifetime_liquidated_stakes);
        result.lifetime_rewards = cryptonote::reward_money::db_amount(lifetime_rewards);
        result.locked_stakes = result.lifetime_locked_stakes - result.lifetime_unlocked_stakes;

        // NOTE: Some of these fields are only enumerated on ETH addresses so gate error checking
        // behind said flag.
        if (is_eth) {
            assert(lifetime_locked_stakes >= 0);
            assert(lifetime_unlocked_stakes >= 0);
            assert(lifetime_rewards >= 0);

            int64_t rederived_amount =
                    lifetime_unlocked_stakes + lifetime_rewards - lifetime_liquidated_stakes;
            if (amount != rederived_amount) {
                log::error(
                        logcat,
                        "Internal error: SN contributor {} at height {} lifetime claimable amount "
                        "does not match the sum of the unlocked stakes, rewards and liquidated "
                        "stakes\n"
                        "  lifetime claimable  {}\n"
                        "  lifetime rewards    {}\n"
                        "  lifetime unlocked   {}\n"
                        "  lifetime liquidated {}\n"
                        "Final calculated values were (claimable vs rederived claimable): {} != {}",
                        address,
                        height,
                        cryptonote::print_money(
                                amount,
                                cryptonote::strip_zeros::no,
                                oxen::DISPLAY_DECIMAL_POINT + 3),
                        cryptonote::print_money(
                                lifetime_unlocked_stakes,
                                cryptonote::strip_zeros::no,
                                oxen::DISPLAY_DECIMAL_POINT + 3),
                        cryptonote::print_money(
                                lifetime_rewards,
                                cryptonote::strip_zeros::no,
                                oxen::DISPLAY_DECIMAL_POINT + 3),
                        cryptonote::print_money(
                                lifetime_liquidated_stakes,
                                cryptonote::strip_zeros::no,
                                oxen::DISPLAY_DECIMAL_POINT + 3),
                        cryptonote::print_money(
                                amount,
                                cryptonote::strip_zeros::no,
                                oxen::DISPLAY_DECIMAL_POINT + 3),
                        cryptonote::print_money(
                                rederived_amount,
                                cryptonote::strip_zeros::no,
                                oxen::DISPLAY_DECIMAL_POINT + 3));
                assert(amount == rederived_amount);
            }

            [[maybe_unused]] cryptonote::reward_money rederived_lifetime_rewards =
                    result.amount -
                    (result.lifetime_unlocked_stakes - result.lifetime_liquidated_stakes);
            assert(rederived_lifetime_rewards == result.lifetime_rewards);

            // NOTE: Delayed payments is only supported on ETH addresses
            cryptonote::BlockchainSQLite::delayed_payments_request request = {};
            request.type = cryptonote::BlockchainSQLite::delayed_payments_type::address;
            request.address = eth_addr;

            block_payments delayed_payments = db.get_delayed_payments(request);
            for (auto it : delayed_payments) {
                const cryptonote::sql_payment& payment = it.second;
                assert(payment.amount.to_coin() >= payment.liquidation.to_coin());
                result.timelocked_stakes += payment.amount - payment.liquidation;
            }
        }
    }
    return result;
}

static BlockchainSQLite::wallet_info get_accrued_rewards_impl(
        BlockchainSQLite& db, const std::string& address) {
    log::trace(logcat, "BlockchainDB_SQLITE {} for {}", __func__, address);
    auto tuple = db.prepared_maybe_get<int64_t, int64_t, int64_t, int64_t, int64_t>(
            "SELECT {} FROM batched_payments_accrued WHERE address = ?"_format(
                    WALLET_METADATA_FIELDS),
            address);

    return wallet_metadata_tuple_to_wallet_info(db, address, std::move(tuple), db.height);
}

void BlockchainSQLite::add_sn_rewards(
        hf hf_version, const block_payments& payments, bool rewards_payment) {
    ZoneScoped;
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    auto insert_payment = prepared_st(R"(
        INSERT INTO batched_payments_accrued (address, payout_offset, amount)
            VALUES (?, ?, ?)
            ON CONFLICT (address) DO UPDATE SET amount = amount + excluded.amount{})"_format(
            rewards_payment ? ""
                            : ", lifetime_unlocked_stakes = lifetime_unlocked_stakes + ?"
                              ", lifetime_liquidated_stakes = lifetime_liquidated_stakes + ?"));

    auto update_lifetime_rewards = prepared_st(
            "UPDATE batched_payments_accrued"
            " SET lifetime_rewards = lifetime_rewards + ?"
            " WHERE address = ?");

    const auto& netconf = get_config(m_nettype);

    for (auto& it : payments) {
        const sql_payment& payment = it.second;
        auto [offset, address_str] = get_address_str(it.first, netconf.BATCHING_INTERVAL);
        cryptonote::reward_money amount = payment.amount - payment.liquidation;
        auto amount_i64 = static_cast<int64_t>(amount.to_db());
        log::trace(
                logcat,
                "Adding record for SN reward contributor {} to database with amount {}",
                address_str,
                amount_i64);

        if (rewards_payment) {
            exec_query(insert_payment, address_str, offset, amount_i64);
            if (hf_version >= hf::hf21_eth) {
                exec_query(update_lifetime_rewards, amount_i64, address_str);
                update_lifetime_rewards->reset();
            }
        } else {
            exec_query(
                    insert_payment,
                    address_str,
                    offset,
                    amount_i64,
                    static_cast<int64_t>(payment.amount.to_db()),
                    static_cast<int64_t>(payment.liquidation.to_db()));
        }
        insert_payment->reset();
    }
}

size_t BlockchainSQLite::batch_payments_accrued_row_count(
        PaymentTableType type, std::optional<uint64_t> height) {
    size_t result = 0;
    switch (type) {
        case PaymentTableType::Nil:
            result = prepared_get<int>("SELECT COUNT(*) FROM batched_payments_accrued");
            break;

        case PaymentTableType::Archive:
            if (height) {
                result = prepared_get<int>(
                        "SELECT COUNT(*) FROM batched_payments_accrued_archive WHERE height = ?",
                        static_cast<int64_t>(*height));
            } else {
                result = prepared_get<int>("SELECT COUNT(*) FROM batched_payments_accrued_archive");
            }
            break;

        case PaymentTableType::Recent:
            if (height) {
                result = prepared_get<int>(
                        "SELECT COUNT(*) FROM batched_payments_accrued_recent WHERE height = ?",
                        static_cast<int64_t>(*height));
            } else {
                result = prepared_get<int>("SELECT COUNT(*) FROM batched_payments_accrued_recent");
            }
            break;
    }

    return result;
}

void BlockchainSQLite::rescan_start() {
    assert(!rescan_tx);
    log::debug(logcat, "(re)starting rescan tx");
    rescan_tx.emplace(db, SQLite::TransactionBehavior::IMMEDIATE);
}

void BlockchainSQLite::rescan_stop() {
    if (rescan_tx) {
        log::debug(logcat, "committing rescan tx at height {}", height);
        rescan_tx->commit();
        rescan_tx = std::nullopt;
        rescan_count = 0;
    }
}

std::vector<cryptonote::batch_sn_payment> BlockchainSQLite::get_sn_payments(uint64_t block_height) {
    ZoneScoped;
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    // <= here because we might have crap in the db that we don't clear until we actually add the HF
    // block later on.  (This is a pretty slim edge case that happened on devnet and is probably
    // virtually impossible on mainnet).
    if (m_nettype != cryptonote::network_type::FAKECHAIN &&
        block_height <=
                cryptonote::hard_fork_begins(m_nettype, hf::hf19_reward_batching).value_or(0))
        return {};

    const auto& conf = get_config(m_nettype);

    std::vector<std::pair<std::string, int64_t>> accrued_pairs;
    {
        auto accrued_amounts = prepared_results<std::string_view, int64_t>(
                "SELECT address, amount FROM batched_payments_accrued WHERE payout_offset = ? AND "
                "amount >= ? ORDER BY address ASC",
                static_cast<int>(block_height % conf.BATCHING_INTERVAL),
                static_cast<int64_t>(conf.MIN_BATCH_PAYMENT_AMOUNT * BATCH_REWARD_FACTOR));

        for (const auto& [address, amount] : accrued_amounts)
            accrued_pairs.emplace_back(std::string{address}, amount);
    }

    // The block before HF21, addresses which have not registered an ETH address for the
    // SESH transition will have their balances paid out, regardless of balance.
    bool pre_hf21_final_payout = false;
    auto hf21_begins = cryptonote::hard_fork_begins(m_nettype, hf::hf21_eth);
    if (hf21_begins && block_height == *hf21_begins - 1) {
        pre_hf21_final_payout = true;

        if (m_nettype == network_type::TESTNET) {
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
                "block before hf21, doing final payout to addresses not registered for conversion");
        auto all_accrued_amounts = prepared_results<std::string_view, int64_t>(
                "SELECT address, amount FROM batched_payments_accrued ORDER BY address ASC");
        accrued_pairs.clear();
        for (auto [address, amount] : all_accrued_amounts)
            accrued_pairs.emplace_back(std::string{address}, amount);
    }

    std::vector<cryptonote::batch_sn_payment> payments;

    const auto& sesh_addr_map =
            *oxen::sesh::get_transition_context(m_nettype, block_height).addresses;
    for (const auto& pair : accrued_pairs) {
        const auto& address = pair.first;
        const auto& amount = pair.second;
        const uint64_t truncated_db_amount =
                amount / BATCH_REWARD_FACTOR * BATCH_REWARD_FACTOR;  // truncate to atomic OXEN

        if (pre_hf21_final_payout) {
            log::debug(logcat, "address {} has amount {}", address, amount);
            if (sesh_addr_map.contains(std::string{address}))  // Registered for transition
                continue;

            if (truncated_db_amount > 0) {
                log::debug(logcat, "pre_hf21_final_payout, paying out {}", address);
            } else {
                log::debug(logcat, "pre_hf21_final_payout, skipping {} (truncated to 0)", address);
                continue;  // Insufficient OXEN to payout
            }
        }

        auto& p = payments.emplace_back();
        p.amount = reward_money::db_amount(truncated_db_amount);
        [[maybe_unused]] bool addr_ok =
                cryptonote::get_account_address_from_str(p.address_info, m_nettype, address);
        assert(addr_ok);
    }

    return payments;
}

static BlockchainSQLite::wallet_info get_accrued_rewards_at_impl(
        BlockchainSQLite& db,
        const std::string& address,
        uint64_t at_height,
        uint64_t curr_top_height) {
    log::trace(logcat, "BlockchainDB_SQLITE {} for {}", __func__, address);
    if (at_height > curr_top_height)
        return {};

    if (at_height == curr_top_height)
        return get_accrued_rewards_impl(db, address);

    auto tuple = db.prepared_maybe_get<int64_t, int64_t, int64_t, int64_t, int64_t>(
            "SELECT {} FROM batched_payments_accrued WHERE address = ? AND height = ?"_format(
                    WALLET_METADATA_FIELDS),
            address,
            static_cast<int64_t>(at_height));

    if (tuple)
        return wallet_metadata_tuple_to_wallet_info(db, address, tuple, db.height);

    // No rewards found; check to see if we actually have any recent records for that height and
    // if not, return a "don't know" nullopt value.  Otherwise we fall through and return an
    // authoritive 0 value.
    auto min_height = db.prepared_get<int64_t>(
            "SELECT COALESCE(MIN(height), 0) FROM batched_payments_accrued_recent");
    if (at_height < static_cast<uint64_t>(min_height))
        return {};

    BlockchainSQLite::wallet_info result = {};
    result.height = min_height;
    result.found = true;
    return result;
}

BlockchainSQLite::wallet_info BlockchainSQLite::get_accrued_rewards(const eth::address& address) {
    std::string address_string = eth_address_to_sql_address(address);
    wallet_info result = get_accrued_rewards_impl(*this, address_string);
    return result;
}

BlockchainSQLite::wallet_info BlockchainSQLite::get_accrued_rewards(
        const account_public_address& address) {
    std::string address_string =
            get_account_address_as_str(m_nettype, false /*subaddress*/, address);
    wallet_info result = get_accrued_rewards_impl(*this, address_string);
    return result;
}

BlockchainSQLite::wallet_info BlockchainSQLite::get_accrued_rewards(
        const eth::address& address, uint64_t at_height) {
    std::string address_string = eth_address_to_sql_address(address);
    wallet_info result = get_accrued_rewards_at_impl(*this, address_string, at_height, height);
    return result;
}

BlockchainSQLite::wallet_info BlockchainSQLite::get_accrued_rewards(
        const account_public_address& address, uint64_t at_height) {
    std::string address_string =
            get_account_address_as_str(m_nettype, false /*subaddress*/, address);
    return get_accrued_rewards_at_impl(*this, address_string, at_height, height);
}

std::pair<std::vector<std::string>, std::vector<BlockchainSQLite::wallet_info>>
BlockchainSQLite::get_all_accrued_rewards() {
    ZoneScoped;
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    std::pair<std::vector<std::string>, std::vector<wallet_info>> result;
    auto& [addresses, wallets] = result;

    // NOTE: Reserve
    size_t row_count = batch_payments_accrued_row_count(PaymentTableType::Nil, std::nullopt);
    addresses.reserve(row_count);
    wallets.reserve(row_count);

    // NOTE: Build
    for (auto it : prepared_results<std::string>("SELECT address FROM batched_payments_accrued")) {
        wallet_info info = get_accrued_rewards_impl(*this, it);
        addresses.push_back(it);
        wallets.push_back(std::move(info));
    }

    return result;
}

void BlockchainSQLite::add_rewards(
        hf hf_version,
        cryptonote::reward_money distribution_amount,
        const service_nodes::service_node_info& sn_info,
        block_payments& payments) const {
    ZoneScoped;

    // Find out how much is due for the operator: fee_portions/PORTIONS * reward
    auto operator_fee = cryptonote::reward_money::db_amount(mul128_div64(
            sn_info.portions_for_operator, distribution_amount.to_db(), old::STAKING_PORTIONS));

    assert(sn_info.portions_for_operator <= old::STAKING_PORTIONS);
    assert(operator_fee.to_db() <= distribution_amount.to_db());

    // NOTE: Localdev does not have a cryptonote->ETH address step, so, old pre-ETH SN nodes don't
    // have an address assigned to it. This breaks tests that expect pre-ETH SN's to receive
    // funds in order to proceed.
    bool use_eth_address = hf_version >= hf::hf21_eth;
    if (use_eth_address && m_nettype == network_type::LOCALDEV) {
        if (!sn_info.operator_ethereum_address)
            use_eth_address = false;
    }

    // Pay the operator fee to the operator
    if (operator_fee.to_db() > 0) {
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
    uint64_t total_contributed_to_sn = std::accumulate(
            sn_info.contributors.begin(),
            sn_info.contributors.end(),
            uint64_t(0),
            [](auto&& a, auto&& b) { return a + b.amount; });

    for (auto& contributor : sn_info.contributors) {
        // This calculates (contributor.amount / total_contributed_to_winner_sn) *
        // (distribution_amount - operator_fee) but using 128 bit integer math

        auto c_reward = cryptonote::reward_money::db_amount(mul128_div64(
                contributor.amount,
                distribution_amount.to_db() - operator_fee.to_db(),
                total_contributed_to_sn));

        if (c_reward.to_db() > 0) {
            // NOTE: At minimum, when we parsed the contributor if no benficiary is set, it should
            // be assigned to the ethereum address by default.
            auto& balance = use_eth_address ? payments[contributor.ethereum_beneficiary]
                                            : payments[contributor.address];
            balance.amount += c_reward;
        }
    }
}

void BlockchainSQLite::reward_handler(
        const cryptonote::block& block,
        const service_nodes::service_node_list::state_t& sn_state,
        const service_nodes::block_add_result& block_add) {
    ZoneScoped;
    assert(block.major_version >= hf::hf19_reward_batching);

    // From here on we calculate everything in milli-atomic OXEN/SESH (i.e. thousanths of an atomic
    // unit) so that our integer math has reduced loss from integer division.
    if (block.reward > std::numeric_limits<uint64_t>::max() / BATCH_REWARD_FACTOR)
        throw oxen::traced<std::logic_error>{"Reward distribution amount is too large"};

    auto block_reward = cryptonote::reward_money::coin_amount(block.reward);
    std::lock_guard a_s_lock{address_str_cache_mutex};

    block_payments payments;
    if (block.major_version < feature::ETH_BLS) {
        // Step 1: Pay out the block producer their tx fees (note that, unlike the
        // below, this applies even if the SN isn't currently payable).
        auto base_sn_reward = cryptonote::reward_money::coin_amount(oxen::SN_REWARD_HF15);
        if (block_reward.to_db() < base_sn_reward.to_db())
            throw oxen::traced<std::logic_error>{"Invalid payment: block reward is too small"};
        if (auto tx_fees = block_reward - base_sn_reward;
            tx_fees.to_db() > 0 && block.has_pulse()) {
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
        if (m_nettype != cryptonote::network_type::FAKECHAIN) {
            if (parsed_governance_addr.first != block.major_version) {
                cryptonote::get_account_address_from_str(
                        parsed_governance_addr.second,
                        m_nettype,
                        cryptonote::get_config(m_nettype).governance_wallet_address(
                                block.major_version));
                parsed_governance_addr.first = block.major_version;
            }

            auto foundation_reward = cryptonote::reward_money::coin_amount(
                    cryptonote::governance_reward_formula(block.major_version));
            payments[parsed_governance_addr.second.address].amount += foundation_reward;
        }
    }

    // Step 3: Iterate over the payable (active for >=24h) N service nodes and pay each node 1/N
    // fraction of the total block reward.
    const uint64_t N = block_add.payable_nodes_hf19_onwards.size();
    const auto per_sn_reward =
            cryptonote::reward_money::db_amount(N ? block_reward.to_db() / N : 0);

    for (const crypto::public_key& node_pubkey : block_add.payable_nodes_hf19_onwards) {
        std::shared_ptr<const service_nodes::service_node_info> node_info =
                sn_state.service_nodes_infos.at(node_pubkey);
        add_rewards(block.major_version, per_sn_reward, *node_info, payments);
    }

    delayed_payments_request request = {};
    request.type = delayed_payments_type::height;
    request.height = block.get_height();

    add_sn_rewards(block.major_version, get_delayed_payments(request), false /*rewards_payment*/);
    add_sn_rewards(block.major_version, payments, true /*rewards_payment*/);
}

block_payments BlockchainSQLite::get_delayed_payments(const delayed_payments_request& request) {
    ZoneScoped;

    std::string query = "SELECT eth_address, amount, liquidation_amount FROM delayed_payments";
    switch (request.type) {
        case delayed_payments_type::all: break;
        case delayed_payments_type::height: query += " WHERE payout_height = ?"; break;
        case delayed_payments_type::address: query += " WHERE eth_address = ?"; break;
    }

    auto stmt = SQLite::Statement(db, query);
    switch (request.type) {
        case delayed_payments_type::all: break;

        case delayed_payments_type::height: {
            stmt.bind(1, static_cast<int64_t>(request.height));
        } break;

        case delayed_payments_type::address: {
            stmt.bind(1, eth_address_to_sql_address(request.address));
        } break;
    }

    block_payments result;
    while (stmt.executeStep()) {
        auto [addr_str, amount, liquidation_amount] = db::get<std::string, int64_t, int64_t>(stmt);
        auto eth_addr = tools::make_from_hex_guts<eth::address>(addr_str);
        auto& it = result[eth_addr];
        it.amount += cryptonote::reward_money::db_amount(amount);
        it.liquidation += cryptonote::reward_money::db_amount(liquidation_amount);
    }

    return result;
}

void BlockchainSQLite::submit_stakes_metadata(
        const service_nodes::block_add_result& block_add, bool _no_transaction) {
    // NOTE: Submit (locked) stakes information
    // New ETH addresses that are staking may not exist in the table yet if it's their first time
    // because they haven't received rewards yet. The adding of locked stakes has to account for
    // if it doesn't exist, hence we use a INSERT INTO instead of just using UPDATE as we do in the
    // subtraction query below.
    auto lifetime_locked_stakes = prepared_st(R"(
        INSERT INTO batched_payments_accrued (lifetime_locked_stakes, address)
            VALUES (?, ?)
            ON CONFLICT(address) DO UPDATE SET
                lifetime_locked_stakes = lifetime_locked_stakes + excluded.lifetime_locked_stakes
    )");

    std::optional<SQLite::Transaction> transaction =
            _no_transaction ? std::nullopt : begin_tx(SQLite::TransactionBehavior::DEFERRED);

    // NOTE: Submit locked stakes
    for (const auto& stake : block_add.locked_stakes) {
        assert(stake.amount.to_db() > 0);

        std::string address = eth_address_to_sql_address(stake.addr);
#ifndef NDEBUG
        BlockchainSQLite::wallet_info wallet_info_before = get_accrued_rewards_impl(*this, address);
#endif

        // NOTE: Add the locked SESH
        int rows_changed = exec_query(
                lifetime_locked_stakes, static_cast<int64_t>(stake.amount.to_db()), address);
        lifetime_locked_stakes->reset();
        assert(rows_changed == 1);

#ifndef NDEBUG
        // NOTE: Verify the DB operations did what we expected
        BlockchainSQLite::wallet_info wallet_info_after = get_accrued_rewards_impl(*this, address);
        assert(wallet_info_after.found);
        log::trace(
                logcat,
                "SN contributor {} at height {} locked {} SESH ({} => {} total) into SN {}",
                address,
                height + 1,
                cryptonote::print_money(stake.amount.to_coin()),
                cryptonote::print_money(wallet_info_before.lifetime_locked_stakes.to_coin()),
                cryptonote::print_money(wallet_info_after.lifetime_locked_stakes.to_coin()),
                stake.sn);
        assert(wallet_info_before.locked_stakes.to_coin() + stake.amount.to_coin() ==
               wallet_info_after.locked_stakes.to_coin());
#endif
    }

    // NOTE: Submit purge stakes
    // For purged stakes, these funds have "disappeared" from the contract (node is in the SNL but
    // _not_ in the contract). To account for this we need to undo the stakes we counted as being
    // locked up.
    auto purged_stakes = prepared_st(R"(
        UPDATE batched_payments_accrued
            SET lifetime_locked_stakes = lifetime_locked_stakes - ?
            WHERE address = ?)");

    for (const auto& it : block_add.purged_stakes) {
        assert(it.amount.to_db() > 0);

        // NOTE: Verify remaining locked stakes don't go below 0
        std::string address = eth_address_to_sql_address(it.addr);
        BlockchainSQLite::wallet_info wallet_info_before = get_accrued_rewards_impl(*this, address);
        assert(wallet_info_before.found);
        if (wallet_info_before.locked_stakes.to_db() < it.amount.to_db()) {
            log::error(
                    logcat,
                    "Internal error: SN contributor ({}) purged more stake ({} SESH) than is "
                    "available in their locked balance ({} SESH)",
                    address,
                    cryptonote::print_money(it.amount.to_coin()),
                    cryptonote::print_money(wallet_info_before.lifetime_locked_stakes.to_coin()));
            assert(wallet_info_before.locked_stakes.to_db() >= it.amount.to_db());
        }

        // NOTE: Add the purged SESH
        int rows_changed =
                db::exec_query(purged_stakes, static_cast<int64_t>(it.amount.to_db()), address);
        assert(rows_changed == 1);
        purged_stakes->reset();

#ifndef NDEBUG
        // NOTE: Verify the DB operations did what we expected
        BlockchainSQLite::wallet_info wallet_info_after = get_accrued_rewards_impl(*this, address);
        assert(wallet_info_after.found);
        log::trace(
                logcat,
                "SN contributor {} at height {} purged {} SESH ({} => {} total) into SN {}",
                address,
                height + 1,
                cryptonote::print_money(it.amount.to_coin()),
                cryptonote::print_money(wallet_info_before.locked_stakes.to_coin()),
                cryptonote::print_money(wallet_info_after.locked_stakes.to_coin()),
                it.sn);
#endif
    }

    if (transaction)
        transaction->commit();
}

bool BlockchainSQLite::add_block(
        const cryptonote::block& block,
        const service_nodes::service_node_list::state_t& service_nodes_state,
        const service_nodes::block_add_result& block_add,
        const std::optional<service_nodes::rescan_context>& rescan) {
    ZoneScoped;
    auto block_height = block.get_height();
    log::trace(logcat, "BlockchainDB_SQLITE::{} called on height: {}", __func__, block_height);

    auto hf_version = block.major_version;
    if (hf_version < hf::hf19_reward_batching) {
        update_height(block_height);
        return true;
    }

    if (block_height ==
        cryptonote::hard_fork_begins(m_nettype, hf::hf19_reward_batching).value_or(0)) {
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
    std::vector<cryptonote::batch_sn_payment> calculated_rewards;
    if (hf_version < cryptonote::feature::ETH_BLS) {
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
        auto transaction = begin_tx();

        // Goes through the miner transactions vouts checks they are right and marks them as paid in
        // the database
        if (!validate_batch_payment(miner_tx_vouts, calculated_rewards, block_height, rescan))
            return false;

        reward_handler(block, service_nodes_state, block_add);
        if (hf_version >= hf::hf21_eth)
            submit_stakes_metadata(block_add, true);
        update_height(
                height + 1);  // NOTE: Update height which synchronises the archive/recent tables

        if (transaction) {
            transaction->commit();
        } else {  // rescanning
            if (++rescan_count >= 100 || height >= rescan_target) {
                rescan_stop();
                if (height < rescan_target)
                    rescan_start();
            }
        }

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
        auto transaction = begin_tx();

        // Basic checks can be done here
        // if (amount > max_staked_amount)
        // throw std::logic_error{"Invalid payment: staked returned is too large"};

        std::lock_guard<std::mutex> a_s_lock{address_str_cache_mutex};
        assert(at_height >= height);

        int64_t payout_height = at_height + (delay_blocks > 0 ? delay_blocks : 1);
        auto insert_payment = prepared_st(R"(
            INSERT INTO delayed_payments
                (eth_address, amount, payout_height, height, block_height, block_tx_index, contributor_index, liquidation_amount)
                VALUES
                (?,           ?,      ?,             ?,      ?,            ?,              ?,                 ?))");

        for (auto& payment : payments) {
            const auto amount = static_cast<int64_t>(payment.amount.to_db());
            const auto eth_address = eth_address_to_sql_address(payment.addr);
            log::trace(
                    logcat,
                    "Adding delayed payment for SN reward contributor {} to database with amount "
                    "{}; height {}; payout height {}",
                    eth_address,
                    amount,
                    at_height,
                    payout_height);
            db::exec_query(
                    insert_payment,
                    eth_address,
                    static_cast<int64_t>(payment.amount.to_db()),
                    payout_height,
                    static_cast<int64_t>(at_height),
                    payment.block_height,
                    payment.tx_index,
                    payment.contributor_index,
                    static_cast<int64_t>(payment.liquidation.to_db()));
            insert_payment->reset();
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
        const std::vector<cryptonote::batch_sn_payment>& calculated_payments_from_batching_db,
        uint64_t block_height,
        const std::optional<service_nodes::rescan_context>& rescan) {
    ZoneScoped;
    log::trace(logcat, "BlockchainDB_SQLITE::{}", __func__);

    std::span<const cryptonote::batch_sn_payment> payments = calculated_payments_from_batching_db;
    if (!rescan || !rescan->skip_verify) {
        if (miner_tx_vouts.size() != calculated_payments_from_batching_db.size()) {
            log::error(
                    logcat,
                    "Length of batch payments ({}) does not match block vouts ({})",
                    calculated_payments_from_batching_db.size(),
                    miner_tx_vouts.size());
            return false;
        }

        uint64_t total_oxen_payout_in_our_db = std::accumulate(
                calculated_payments_from_batching_db.begin(),
                calculated_payments_from_batching_db.end(),
                uint64_t(0),
                [](auto&& a, auto&& b) { return a + b.coin_amount(); });
        uint64_t total_oxen_payout_in_vouts = 0;
        std::vector<batch_sn_payment> finalised_payments;
        cryptonote::keypair const deterministic_keypair =
                cryptonote::get_deterministic_keypair_from_height(block_height);
        for (size_t vout_index = 0; vout_index < miner_tx_vouts.size(); vout_index++) {
            const auto& [pubkey, amt] = miner_tx_vouts[vout_index];
            auto amount = reward_money::coin_amount(amt);
            const auto& from_db = calculated_payments_from_batching_db[vout_index];
            if (amount.to_db() != from_db.amount.to_db()) {
                log::error(
                        logcat,
                        "Batched payout amount incorrect. Should be {}, not {}",
                        from_db.amount.to_db(),
                        amount.to_db());
                return false;
            }
            crypto::public_key out_eph_public_key{};
            if (!cryptonote::get_deterministic_output_key(
                        from_db.address_info.address,
                        deterministic_keypair,
                        vout_index,
                        out_eph_public_key)) {
                log::error(logcat, "Failed to generate output one-time public key");
                return false;
            }
            if (tools::view_guts(pubkey) != tools::view_guts(out_eph_public_key)) {
                log::error(logcat, "Output ephemeral public key does not match");
                return false;
            }
            total_oxen_payout_in_vouts += amount.to_coin();
            finalised_payments.emplace_back(from_db.address_info, amount);
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

    auto select_sum = prepared_st("SELECT amount FROM batched_payments_accrued WHERE address = ?");
    auto update_paid = prepared_st(
            "UPDATE batched_payments_accrued SET amount = amount - ? WHERE address = ?");

    std::lock_guard lock{address_str_cache_mutex};
    for (const auto& payment : paid_amounts) {
        const auto address_str = get_address_str(payment);

        if (auto maybe_amount = db::exec_and_maybe_get<int64_t>(select_sum, address_str)) {
            // Truncate the thousanths amount to an atomic OXEN:
            auto amount = static_cast<uint64_t>(*maybe_amount) / BATCH_REWARD_FACTOR *
                          BATCH_REWARD_FACTOR;

            if (amount != payment.amount.to_db()) {
                log::error(
                        logcat,
                        "Invalid amounts passed in to save payments for address {}: received {}, "
                        "expected {} (truncated from {})",
                        address_str,
                        payment.amount.to_db(),
                        amount,
                        *maybe_amount);
                return false;
            }

            db::exec_query(update_paid, static_cast<int64_t>(payment.amount.to_db()), address_str);
            update_paid->reset();
        } else {
            // This shouldn't occur: we validate payout addresses much earlier in the block
            // validation.
            log::error(
                    logcat,
                    "Internal error: Invalid amounts passed in to save payments for address {}: "
                    "that address has no accrued rewards",
                    address_str);
            return false;
        }
        select_sum->reset();
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
        auto cleanup_st = prepared_st("DELETE FROM batched_payments_accrued WHERE amount = 0");
        exec_query(cleanup_st);
    }
    return true;
}
}  // namespace cryptonote
