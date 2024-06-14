#include "walletdb.hpp"

#include <common/hex.h>
#include <common/string_util.h>
#include <cryptonote_basic/cryptonote_basic.h>
#include <fmt/core.h>

#include <iostream>
#include <common/exception.h>

#include "common/guts.h"
#include "wallet3/block.hpp"

namespace wallet {
static auto logcat = oxen::log::Cat("wallet");

WalletDB::~WalletDB() {}

void WalletDB::create_schema(cryptonote::network_type nettype) {
    if (db.tableExists("outputs")) {
        if (auto stored_nettype = this->network_type(); stored_nettype != nettype) {
            std::string err =
                    "Loaded wallet on network type \"{}\" but db has network type \"{}\""_format(
                            cryptonote::network_type_to_string(nettype),
                            cryptonote::network_type_to_string(stored_nettype));
            // TODO: log error as well
            throw oxen::invalid_argument(err);
        }
        return;
    }

    SQLite::Transaction db_tx(db);

    // TODO: set up removal triggers
    // TODO: table for balance "per account"
    db.exec(
            R"(
          CREATE TABLE metadata (
            id TEXT PRIMARY KEY NOT NULL,
            val_numeric INT,
            val_binary BLOB,
            val_text TEXT,
            -- Exactly one val_* must be set:
            CHECK((val_numeric IS NOT NULL) + (val_binary IS NOT NULL) + (val_text IS NOT NULL) == 1)
          ) STRICT;

          INSERT INTO metadata(id, val_numeric)
          VALUES
            ('db_version', 0),
            ('balance', 0),
            ('last_scan_height', 0),
            ('scan_target_height', 0),
            ('output_count', 0);

          INSERT INTO metadata(id, val_text)
          VALUES
            ('nettype', 'testnet'),
            ('scan_target_hash', '');

          CREATE TABLE blocks (
            height INTEGER NOT NULL PRIMARY KEY,
            output_count INTEGER NOT NULL,
            hash TEXT NOT NULL,
            timestamp INTEGER NOT NULL
          );

          -- update scan height when new block added
          CREATE TRIGGER block_added AFTER INSERT ON blocks
          FOR EACH ROW
          BEGIN
            UPDATE metadata SET val_numeric = NEW.height WHERE id = 'last_scan_height';
            UPDATE metadata SET val_numeric = val_numeric + NEW.output_count WHERE id = 'output_count';
          END;

          -- update scan height when new block removed
          CREATE TRIGGER block_removed AFTER DELETE ON blocks
          FOR EACH ROW
          BEGIN
            UPDATE metadata SET val_numeric = OLD.height - 1 WHERE id = 'last_scan_height';
            UPDATE metadata SET val_numeric = val_numeric - OLD.output_count WHERE id = 'last_scan_height';
          END;

          CREATE TABLE transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block INTEGER NOT NULL REFERENCES blocks(height) ON DELETE CASCADE,
            hash TEXT NOT NULL,
            UNIQUE(hash)
          );

          -- will default scan many subaddresses, even if never used, so it is useful to mark
          -- if they have been used (for culling this list later, perhaps)
          CREATE TABLE subaddresses (
            major_index INTEGER NOT NULL,
            minor_index INTEGER NOT NULL,
            address TEXT NOT NULL,
            used BOOLEAN NOT NULL DEFAULT FALSE,
            PRIMARY KEY(major_index, minor_index)
          );

          -- default "main" subaddress
          INSERT INTO subaddresses VALUES (0,0,"",TRUE);

          CREATE TABLE key_images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_image BLOB NOT NULL,
            UNIQUE(key_image)
          );

          CREATE TABLE outputs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            amount BIGINT NOT NULL,
            output_index INTEGER NOT NULL,
            global_index INTEGER NOT NULL,
            unlock_time INTEGER NOT NULL,
            block_height INTEGER NOT NULL REFERENCES blocks(height),
            spending BOOLEAN NOT NULL DEFAULT FALSE,
            spent_height INTEGER NOT NULL DEFAULT 0,
            tx INTEGER NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
            output_key BLOB NOT NULL,
            derivation BLOB NOT NULL,
            rct_mask BLOB NOT NULL,
            key_image INTEGER NOT NULL REFERENCES key_images(id),
            subaddress_major INTEGER NOT NULL,
            subaddress_minor INTEGER NOT NULL
          );
          CREATE INDEX output_key_image ON outputs(key_image);

          -- update balance when new output added
          CREATE TRIGGER output_received AFTER INSERT ON outputs
          FOR EACH ROW
          BEGIN
            UPDATE metadata SET val_numeric = val_numeric + NEW.amount WHERE id = 'balance';
          END;

          -- update balance when output removed (blockchain re-org)
          CREATE TRIGGER output_removed AFTER DELETE ON outputs
          FOR EACH ROW
          BEGIN
            UPDATE metadata SET val_numeric = val_numeric - OLD.amount WHERE id = 'balance';
          END;

          CREATE TABLE spends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_image INTEGER NOT NULL REFERENCES key_images(id),
            height INTEGER REFERENCES blocks(height) ON DELETE CASCADE,
            tx INTEGER REFERENCES transactions(id),
            UNIQUE(key_image)
          );
          CREATE INDEX spend_key_image ON spends(key_image);

          -- update output and balance when output seen as spent
          CREATE TRIGGER output_spend_received AFTER INSERT ON spends
          FOR EACH ROW
          BEGIN
            UPDATE outputs SET spent_height = NEW.height WHERE key_image = NEW.key_image;
            UPDATE metadata SET val_numeric = val_numeric - (SELECT outputs.amount FROM outputs WHERE outputs.key_image = NEW.key_image) where id = 'balance';
          END;

          -- update output and balance when output un-seen as spent (blockchain re-org)
          CREATE TRIGGER output_spend_removed AFTER DELETE ON spends
          FOR EACH ROW
          BEGIN
            UPDATE outputs SET spent_height = 0 WHERE key_image = OLD.key_image;
            UPDATE metadata SET val_numeric = val_numeric + (SELECT outputs.amount FROM outputs WHERE outputs.key_image = OLD.key_image) where id = 'balance';
          END;

          CREATE TRIGGER key_image_output_removed_cleaner AFTER DELETE ON outputs
          FOR EACH ROW WHEN (SELECT COUNT(*) FROM outputs WHERE key_image = OLD.key_image) = 0
            AND (SELECT COUNT(*) FROM spends WHERE key_image = OLD.key_image) = 0
          BEGIN
            DELETE FROM key_images WHERE id = OLD.key_image;   
          END;

          CREATE TRIGGER key_image_spend_removed_cleaner AFTER DELETE ON spends
          FOR EACH ROW WHEN (SELECT COUNT(*) FROM outputs WHERE key_image = OLD.key_image) = 0
          BEGIN
            DELETE FROM key_images WHERE id = OLD.key_image;   
          END;

        )");

    set_metadata_text("nettype", std::string(cryptonote::network_type_to_string(nettype)));

    db_tx.commit();
}

// Helpers to access the metadata table
void WalletDB::set_metadata_int(const std::string& id, int64_t val) {
    prepared_exec(
            "INSERT INTO metadata(id, val_numeric) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET "
            "val_numeric=excluded.val_numeric",
            id,
            val);
}

int64_t WalletDB::get_metadata_int(const std::string& id) {
    return prepared_get<int64_t>("SELECT val_numeric FROM metadata WHERE id = ?", id);
}

void WalletDB::set_metadata_text(const std::string& id, const std::string& val) {
    prepared_exec(
            "INSERT INTO metadata(id, val_text) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET "
            "val_text=excluded.val_text",
            id,
            val);
}

std::string WalletDB::get_metadata_text(const std::string& id) {
    return prepared_get<std::string>("SELECT val_text FROM metadata WHERE id = ?", id);
}

void WalletDB::set_metadata_blob(const std::string& id, std::string_view data) {
    prepared_exec(
            "INSERT INTO metadata(id, val_binary) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET "
            "val_binary=excluded.val_binary",
            id,
            db::blob_binder{data});
}

std::string WalletDB::get_metadata_blob(const std::string& id) {
    return prepared_get<std::string>("SELECT val_binary FROM metadata WHERE id = ?", id);
}

cryptonote::network_type WalletDB::network_type() {
    return cryptonote::network_type_from_string(get_metadata_text("nettype"));
}

void WalletDB::add_address(int32_t major_index, int32_t minor_index, const std::string& address) {
    auto exists = prepared_get<int64_t>(
            "SELECT COUNT(*) FROM subaddresses WHERE major_index = ? AND minor_index = ?",
            major_index,
            minor_index);

    if (exists) {
        auto existing_addr = prepared_get<std::string>(
                "SELECT address FROM subaddresses WHERE major_index = ? AND minor_index = ?",
                major_index,
                minor_index);

        if (major_index == 0 and minor_index == 0 and existing_addr == "") {
            prepared_exec(
                    "UPDATE subaddresses SET address = ? WHERE major_index = ? AND minor_index = ?",
                    address,
                    major_index,
                    minor_index);
            return;
        }

        // FIXME: better error type
        if (existing_addr != address)
            throw oxen::invalid_argument(
                    "WalletDB address insertion, new address mismatch with existing address.");
    } else {
        prepared_exec(
                "INSERT INTO subaddresses(major_index, minor_index, address, used) VALUES(?,?,?)",
                major_index,
                minor_index,
                address,
                true);
    }
}

std::string WalletDB::get_address(int32_t major_index, int32_t minor_index) {
    auto addr = prepared_maybe_get<std::string>(
            "SELECT address FROM subaddresses WHERE major_index = ? AND minor_index = ?",
            major_index,
            minor_index);

    if (addr)
        return *addr;

    throw oxen::invalid_argument(
            "WalletDB address fetch, address for subaddress indices not found in database.");
    return "";  // compilers can be dumb
}

void WalletDB::store_block(const Block& block) {
    int64_t output_count = 0;
    for (const auto& tx : block.transactions) {
        output_count += tx.tx.vout.size();
    }

    prepared_exec(
            "INSERT INTO blocks(height,output_count,hash,timestamp) VALUES(?,?,?,?)",
            block.height,
            output_count,
            tools::hex_guts(block.hash),
            block.timestamp);
}

void WalletDB::pop_block() {
    prepared_exec("DELETE FROM blocks WHERE height = (SELECT MAX(height) FROM blocks)");
}

void WalletDB::store_transaction(
        const crypto::hash& tx_hash, const int64_t height, const std::vector<Output>& outputs) {
    auto hash_str = tools::hex_guts(tx_hash);
    prepared_exec("INSERT INTO transactions(block,hash) VALUES(?,?)", height, hash_str);

    for (const auto& output : outputs) {
        prepared_exec(
                "INSERT INTO key_images(key_image) VALUES(?)", tools::hex_guts(output.key_image));
        prepared_exec(
                R"(
          INSERT INTO outputs(
            amount,
            output_index,
            global_index,
            unlock_time,
            block_height,
            tx,
            output_key,
            derivation,
            rct_mask,
            key_image,
            subaddress_major,
            subaddress_minor)
          VALUES(?,?,?,?,?,
            (SELECT id FROM transactions WHERE hash = ?),
            ?,?,?,
            (SELECT id FROM key_images WHERE key_image = ?),
            ?,?);
          )",
                output.amount,
                output.output_index,
                output.global_index,
                output.unlock_time,
                output.block_height,
                hash_str,
                tools::hex_guts(output.key),
                tools::hex_guts(output.derivation),
                tools::hex_guts(output.rct_mask),
                tools::hex_guts(output.key_image),
                output.subaddress_index.major,
                output.subaddress_index.minor);
    }
}

void WalletDB::store_spends(
        const crypto::hash& tx_hash,
        const int64_t height,
        const std::vector<crypto::key_image>& spends) {
    auto hash_hex = tools::hex_guts(tx_hash);
    prepared_exec(
            "INSERT INTO transactions(block,hash) VALUES(?,?) ON CONFLICT DO NOTHING",
            height,
            hash_hex);

    for (const auto& key_image : spends) {
        prepared_exec(
                R"(INSERT INTO spends(key_image, height, tx)
          VALUES((SELECT id FROM key_images WHERE key_image = ?),
          ?,
          (SELECT id FROM transactions WHERE hash = ?));)",
                tools::hex_guts(key_image),
                height,
                hash_hex);
    }
}

int64_t WalletDB::last_scan_height() {
    return get_metadata_int("last_scan_height");
}

int64_t WalletDB::scan_target_height() {
    return get_metadata_int("scan_target_height");
}

int64_t WalletDB::current_height() {
    return prepared_get<int64_t>("SELECT max(height) from blocks");
}

void WalletDB::update_top_block_info(int64_t height, const crypto::hash& hash) {
    set_metadata_int("scan_target_height", height);
    set_metadata_text("scan_target_hash", tools::hex_guts(hash));
}

int64_t WalletDB::overall_balance() {
    return get_metadata_int("balance");
}

int64_t WalletDB::unlocked_balance() {
    return prepared_get<int64_t>(
            "SELECT sum(o.amount) FROM outputs AS o WHERE o.spent_height = 0 AND o.spending = "
            "false AND (o.block_height + o.unlock_time) <= (SELECT m.val_numeric FROM metadata as "
            "m WHERE m.id = 'last_scan_height')");
}

int64_t WalletDB::available_balance(std::optional<int64_t> min_amount) {
    std::string query =
            "SELECT sum(amount) FROM outputs WHERE spent_height = 0 AND spending = FALSE";

    if (min_amount) {
        query += " AND amount > ?";
        return prepared_get<int64_t>(query, *min_amount);
    }

    return prepared_get<int64_t>(query);
}

std::vector<Output> WalletDB::available_outputs(std::optional<int64_t> min_amount) {
    std::vector<Output> outs;

    std::string query =
            "SELECT amount, output_index, global_index, "
            "unlock_time, block_height, output_key, derivation, rct_mask, key_images.key_image, "
            "spent_height, spending FROM outputs JOIN key_images ON outputs.key_image = "
            "key_images.id WHERE spent_height = 0 AND spending = FALSE ";

    if (min_amount) {
        query += "AND amount > ? ";
    }

    query += "ORDER BY amount";

    auto st = prepared_st(query);

    if (min_amount)
        st->bind(1, *min_amount);

    while (st->executeStep()) {
        auto& out = outs.emplace_back();
        auto from_db =
                db::get<int64_t,
                        int64_t,
                        int64_t,
                        int64_t,
                        int64_t,
                        std::string,
                        std::string,
                        std::string,
                        std::string,
                        int64_t,
                        int64_t>(st);
        out.amount = std::get<0>(from_db);
        out.output_index = std::get<1>(from_db);
        out.global_index = std::get<2>(from_db);
        out.unlock_time = std::get<3>(from_db);
        out.block_height = std::get<4>(from_db);
        tools::load_from_hex_guts(std::get<5>(from_db), out.key);
        tools::load_from_hex_guts(std::get<6>(from_db), out.derivation);
        tools::load_from_hex_guts(std::get<7>(from_db), out.rct_mask);
        tools::load_from_hex_guts(std::get<8>(from_db), out.key_image);
        out.spent_height = std::get<9>(from_db);
        out.spending = std::get<10>(from_db);
    }

    return outs;
}

int64_t WalletDB::chain_output_count() {
    return get_metadata_int("output_count");
}
void WalletDB::save_keys(const std::shared_ptr<WalletKeys> keys) {
    const auto maybe_db_keys = load_keys();
    if (maybe_db_keys.has_value()) {
        if ((tools::view_guts(maybe_db_keys->spend_privkey()) !=
             tools::view_guts(keys->spend_privkey())) ||
            (tools::view_guts(maybe_db_keys->spend_pubkey()) !=
             tools::view_guts(keys->spend_pubkey())) ||
            (tools::view_guts(maybe_db_keys->view_privkey()) !=
             tools::view_guts(keys->view_privkey())) ||
            (tools::view_guts(maybe_db_keys->view_pubkey()) !=
             tools::view_guts(keys->view_pubkey())))
            throw oxen::runtime_error("provided keys do not match database file");
    }

    set_metadata_blob_guts("spend_priv", keys->spend_privkey());
    set_metadata_blob_guts("spend_pub", keys->spend_pubkey());
    set_metadata_blob_guts("view_priv", keys->view_privkey());
    set_metadata_blob_guts("view_pub", keys->view_pubkey());
}

std::optional<DBKeys> WalletDB::load_keys() {
    DBKeys keys;
    // Will throw if the keys do not exist in the database (for example when the wallet is first
    // created) catch this and return nullopt. This means all 4 keys need to exist in the database.
    // In future view only wallets will need the ability to return an empty spend_priv key
    try {
        keys.ssk = get_metadata_blob_guts<crypto::secret_key>("spend_priv");
        keys.spk = get_metadata_blob_guts<crypto::public_key>("spend_pub");
        keys.vsk = get_metadata_blob_guts<crypto::secret_key>("view_priv");
        keys.vpk = get_metadata_blob_guts<crypto::public_key>("view_pub");
    } catch (const std::exception& e) {
        oxen::log::debug(logcat, "Could not load keys: {}", e.what());
        return std::nullopt;
    }

    return keys;
}
}  // namespace wallet
