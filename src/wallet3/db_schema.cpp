#include "db_schema.hpp"

#include "output.hpp"
#include "block.hpp"

#include <common/hex.h>
#include <cryptonote_basic/cryptonote_basic.h>

namespace wallet
{
  // FIXME: BLOB or TEXT for binary data below?
  void
  WalletDB::create_schema()
  {
    if (db.tableExists("outputs"))
      return;

    SQLite::Transaction db_tx(db);

    // TODO: set up removal triggers
    // TODO: table for balance "per account"
    db.exec(
        R"(
          CREATE TABLE blocks (
            height INTEGER NOT NULL PRIMARY KEY,
            transaction_count INTEGER NOT NULL,
            hash TEXT NOT NULL,
            timestamp INTEGER NOT NULL
          );

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
            used BOOLEAN NOT NULL DEFAULT FALSE,
            PRIMARY KEY(major_index, minor_index)
          );

          -- default "main" subaddress
          INSERT INTO subaddresses VALUES (0,0,TRUE);

          -- CHECK (id = 0) restricts this table to a single row
          CREATE TABLE metadata (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
            db_version INTEGER NOT NULL DEFAULT 0,
            balance INTEGER NOT NULL DEFAULT 0,
            unlocked_balance INTEGER NOT NULL DEFAULT 0,
            last_scan_height INTEGER NOT NULL DEFAULT -1,
            scan_target_hash TEXT NOT NULL,
            scan_target_height INTEGER NOT NULL DEFAULT 0
          );
          -- insert metadata row as default
          INSERT INTO metadata VALUES (0,0,0,0,-1,"",0);

          CREATE TABLE key_images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_image BLOB NOT NULL,
            UNIQUE(key_image)
          );

          CREATE TABLE outputs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            amount INTEGER NOT NULL,
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
            subaddress_minor INTEGER NOT NULL,
            FOREIGN KEY(subaddress_major, subaddress_minor) REFERENCES subaddresses(major_index, minor_index)
          );
          CREATE INDEX output_key_image ON outputs(key_image);

          -- update balance when new output added
          CREATE TRIGGER output_received AFTER INSERT ON outputs
          FOR EACH ROW
          BEGIN
            UPDATE metadata SET balance = balance + NEW.amount WHERE id = 0;
          END;

          -- update balance when output removed (blockchain re-org)
          CREATE TRIGGER output_removed AFTER DELETE ON outputs
          FOR EACH ROW
          BEGIN
            UPDATE metadata SET balance = balance - OLD.amount WHERE id = 0;
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
            UPDATE metadata SET balance = balance - (SELECT outputs.amount FROM outputs WHERE outputs.key_image = NEW.key_image);
          END;

          -- update output and balance when output un-seen as spent (blockchain re-org)
          CREATE TRIGGER output_spend_removed AFTER DELETE ON spends
          FOR EACH ROW
          BEGIN
            UPDATE outputs SET spent_height = 0 WHERE key_image = OLD.key_image;
            UPDATE metadata SET balance = balance + (SELECT outputs.amount FROM outputs WHERE outputs.key_image = OLD.key_image);
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

    db_tx.commit();
  }

  void
  WalletDB::store_block(const Block& block)
  {
    prepared_exec(
        "INSERT INTO blocks(height,transaction_count,hash,timestamp) VALUES(?,?,?,?)",
        block.height,
        static_cast<int64_t>(block.transactions.size()),
        tools::type_to_hex(block.hash),
        block.timestamp);
  }

  void
  WalletDB::store_transaction(
      const crypto::hash& tx_hash, const int64_t height, const std::vector<Output>& outputs)
  {
    auto hash_str = tools::type_to_hex(tx_hash);
    prepared_exec(
        "INSERT INTO transactions(block,hash) VALUES(?,?)", height, hash_str);

    for (const auto& output : outputs)
    {
      prepared_exec(
          "INSERT INTO key_images(key_image) VALUES(?)", tools::type_to_hex(output.key_image));
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
          tools::type_to_hex(output.key),
          tools::type_to_hex(output.derivation),
          tools::type_to_hex(output.rct_mask),
          tools::type_to_hex(output.key_image),
          output.subaddress_index.major,
          output.subaddress_index.minor);
    }
  }

  void
  WalletDB::store_spends(
      const crypto::hash& tx_hash,
      const int64_t height,
      const std::vector<crypto::key_image>& spends)
  {
    auto hash_hex = tools::type_to_hex(tx_hash);
    prepared_exec(
        "INSERT INTO transactions(block,hash) VALUES(?,?) ON CONFLICT DO NOTHING",
        height,
        hash_hex);

    for (const auto& key_image : spends)
    {
      prepared_exec(
          R"(INSERT INTO spends(key_image, height, tx)
          VALUES((SELECT id FROM key_images WHERE key_image = ?),
          ?,
          (SELECT id FROM transactions WHERE hash = ?));)",
          tools::type_to_hex(key_image),
          height,
          hash_hex);
    }
  }

  int64_t
  WalletDB::last_scan_height()
  {
    return prepared_get<int64_t>("SELECT last_scan_height FROM metadata WHERE id=0;");
  }

  int64_t
  WalletDB::scan_target_height()
  {
    return prepared_get<int64_t>("SELECT scan_target_height FROM metadata WHERE id=0;");
  }

  void
  WalletDB::update_top_block_info(int64_t height, const crypto::hash& hash)
  {
    prepared_exec("UPDATE metadata SET scan_target_height = ?, scan_target_hash = ? WHERE id = 0",
      height, tools::type_to_hex(hash));
  }

  int64_t
  WalletDB::overall_balance()
  {
    return prepared_get<int64_t>("SELECT balance FROM metadata WHERE id=0;");
  }

  int64_t
  WalletDB::available_balance(std::optional<int64_t> min_amount)
  {
    std::string query = "SELECT sum(amount) FROM outputs WHERE spent_height = 0 AND spending = FALSE";

    if (min_amount)
    {
      query += " AND amount > ?";
      return prepared_get<int64_t>(query, *min_amount);
    }

    return prepared_get<int64_t>(query);
  }

  std::vector<Output>
  WalletDB::available_outputs(std::optional<int64_t> min_amount)
  {
    std::vector<Output> outs;

    std::string query = "SELECT amount, output_index, global_index, unlock_time, block_height, "
        "spent_height, spending FROM outputs WHERE spent_height = 0 AND spending = FALSE ";

    if (min_amount)
    {
      query += "AND amount > ? ";
    }

    query += "ORDER BY amount";

    auto st = prepared_st(query);

    if (min_amount)
      st->bind(1, *min_amount);

    while (st->executeStep())
    {
      outs.emplace_back(db::get<int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t>(st));
    }

    return outs;
  }

  int64_t
  WalletDB::chain_output_count()
  {
    //TODO: this
    return 0;
  }

}  // namespace wallet
