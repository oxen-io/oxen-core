#include "db_schema.hpp"

#include "output.hpp"
#include "block.hpp"

#include <common/hex.h>
#include <cryptonote_basic/cryptonote_basic.h>

#include <fmt/core.h>
#include <iostream>

namespace wallet
{
  static auto logcat = oxen::log::Cat("wallet");

  WalletDB::~WalletDB()
  {
  }

  void
  WalletDB::create_schema(cryptonote::network_type nettype)
  {
    if (db.tableExists("outputs"))
    {
      if (auto stored_nettype = this->network_type(); stored_nettype != nettype)
      {
        std::string err = "Loaded wallet on network type \"{}\" but db has network type \"{}\""_format(
            cryptonote::network_type_to_string(nettype),
            cryptonote::network_type_to_string(stored_nettype));
        //TODO: log error as well
        throw std::invalid_argument(err);
      }
      return;
    }

    SQLite::Transaction db_tx(db);

    // TODO: set up removal triggers
    // TODO: table for balance "per account"
    db.exec(
        R"(
          -- CHECK (id = 0) restricts this table to a single row
          CREATE TABLE metadata (
            id INTEGER NOT NULL PRIMARY KEY CHECK (id = 0),
            db_version INTEGER NOT NULL DEFAULT 0,
            nettype TEXT NOT NULL DEFAULT "testnet",
            balance INTEGER NOT NULL DEFAULT 0,
            unlocked_balance INTEGER NOT NULL DEFAULT 0,
            last_scan_height INTEGER NOT NULL DEFAULT -1,
            scan_target_hash TEXT NOT NULL,
            scan_target_height INTEGER NOT NULL DEFAULT 0,
            output_count INTEGER NOT NULL DEFAULT 0,
            spend_priv TEXT,
            spend_pub TEXT,
            view_priv TEXT,
            view_pub TEXT
          );

          -- insert metadata row as default
          INSERT INTO metadata VALUES (0,0,"testnet",0,0,-1,"",0,0,"","","","");

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
            UPDATE metadata SET last_scan_height = NEW.height WHERE id = 0;
            UPDATE metadata SET output_count = output_count + NEW.output_count WHERE id = 0;
          END;

          -- update scan height when new block removed
          CREATE TRIGGER block_removed AFTER DELETE ON blocks
          FOR EACH ROW
          BEGIN
            UPDATE metadata SET last_scan_height = OLD.height - 1 WHERE id = 0;
            UPDATE metadata SET output_count = output_count - OLD.output_count WHERE id = 0;
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

    prepared_exec("UPDATE metadata SET nettype = ? WHERE id = 0;", std::string(cryptonote::network_type_to_string(nettype)));

    db_tx.commit();
  }

  cryptonote::network_type
  WalletDB::network_type()
  {
    return cryptonote::network_type_from_string(prepared_get<std::string>("SELECT nettype FROM metadata WHERE id=0;"));
  }


  void
  WalletDB::add_address(int32_t major_index, int32_t minor_index, const std::string& address)
  {
    auto exists = prepared_get<int64_t>("SELECT COUNT(*) FROM subaddresses WHERE major_index = ? AND minor_index = ?;",
        major_index,
        minor_index);

    if (exists)
    {
      auto existing_addr = prepared_get<std::string>("SELECT address FROM subaddresses WHERE major_index = ? AND minor_index = ?;",
          major_index,
          minor_index);

      if (major_index == 0 and minor_index == 0 and existing_addr == "")
      {
        prepared_exec("UPDATE subaddresses SET address = ? WHERE major_index = ? AND minor_index = ?;",
            address,
            major_index,
            minor_index);
        return;
      }

      //FIXME: better error type
      if (existing_addr != address)
        throw std::invalid_argument("WalletDB address insertion, new address mismatch with existing address.");
    }
    else
    {
      prepared_exec("INSERT INTO subaddresses(major_index, minor_index, address, used) VALUES(?,?,?);",
          major_index,
          minor_index,
          address,
          true);
    }
  }

  std::string
  WalletDB::get_address(int32_t major_index, int32_t minor_index)
  {
    auto addr = prepared_maybe_get<std::string>("SELECT address FROM subaddresses WHERE major_index = ? AND minor_index = ?;",
        major_index,
        minor_index);

    if (addr)
      return *addr;
    
    throw std::invalid_argument("WalletDB address fetch, address for subaddress indices not found in database.");
    return ""; // compilers can be dumb
  }

  void
  WalletDB::store_block(const Block& block)
  {
    int64_t output_count = 0;
    for (const auto& tx : block.transactions)
    {
      output_count += tx.tx.vout.size();
    }

    prepared_exec(
        "INSERT INTO blocks(height,output_count,hash,timestamp) VALUES(?,?,?,?)",
        block.height,
        output_count,
        tools::type_to_hex(block.hash),
        block.timestamp);
  }

  void
  WalletDB::pop_block()
  {
    prepared_exec("DELETE FROM blocks WHERE height = (SELECT MAX(height) FROM blocks)");
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

    std::string query = "SELECT amount, output_index, global_index, "
        "unlock_time, block_height, output_key, derivation, rct_mask, key_images.key_image, "
        "spent_height, spending FROM outputs JOIN key_images ON outputs.key_image = key_images.id WHERE spent_height = 0 AND spending = FALSE ";

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
      auto& out = outs.emplace_back();
      auto from_db = db::get<int64_t, int64_t, int64_t, int64_t, int64_t, std::string,
           std::string, std::string, std::string, int64_t, int64_t>(st);
      out.amount = std::get<0>(from_db);
      out.output_index = std::get<1>(from_db);
      out.global_index = std::get<2>(from_db);
      out.unlock_time = std::get<3>(from_db);
      out.block_height = std::get<4>(from_db);
      tools::hex_to_type(std::get<5>(from_db), out.key);
      tools::hex_to_type(std::get<6>(from_db), out.derivation);
      tools::hex_to_type(std::get<7>(from_db), out.rct_mask);
      tools::hex_to_type(std::get<8>(from_db), out.key_image);
      out.spent_height = std::get<9>(from_db);
      out.spending = std::get<10>(from_db);
    }

    return outs;
  }

  int64_t
  WalletDB::chain_output_count()
  {
    return prepared_get<int64_t>("SELECT output_count FROM metadata WHERE id=0;");
  }
  void
  WalletDB::save_keys(std::shared_ptr<Keyring> keys) 
  {
    std::string query = "SELECT spend_priv, spend_pub, view_priv, view_pub FROM metadata WHERE id=0";
    auto st = prepared_st(query);
    std::string spend_priv_str;
    std::string spend_pub_str;
    std::string view_priv_str;
    std::string view_pub_str;
    while (st->executeStep())
    {
      auto from_db = db::get<std::string, std::string, std::string, std::string>(st);
      spend_priv_str = std::get<0>(from_db);
      spend_pub_str = std::get<1>(from_db);
      view_priv_str = std::get<2>(from_db);
      view_pub_str = std::get<3>(from_db);
    }
    if (spend_priv_str != "" || spend_pub_str != "" || view_priv_str != "" || view_pub_str != "")
    {
      crypto::secret_key spend_priv;
      crypto::public_key spend_pub;
      crypto::secret_key view_priv;
      crypto::public_key view_pub;
      tools::hex_to_type<crypto::secret_key>(spend_priv_str, spend_priv);
      tools::hex_to_type<crypto::public_key>(spend_pub_str, spend_pub);
      tools::hex_to_type<crypto::secret_key>(view_priv_str, view_priv);
      tools::hex_to_type<crypto::public_key>(view_pub_str, view_pub);
      auto keyring = Keyring(spend_priv, spend_pub, view_priv, view_pub, keys->nettype);
      if (keyring.get_main_address() != keys->get_main_address())
        throw std::runtime_error("loaded keys do not match database file");

    } else {
      auto account_keys = keys->export_keys();
      prepared_exec("UPDATE metadata SET spend_priv = ?, spend_pub = ?, view_priv = ?, view_pub = ? where id = 0;",
          tools::type_to_hex(account_keys.m_spend_secret_key),
          tools::type_to_hex(account_keys.m_account_address.m_spend_public_key),
          tools::type_to_hex(account_keys.m_view_secret_key),
          tools::type_to_hex(account_keys.m_account_address.m_view_public_key));

    }
  }

  std::shared_ptr<Keyring>
  WalletDB::load_keys(cryptonote::network_type _nettype) 
  {
    std::string query = "SELECT spend_priv, spend_pub, view_priv, view_pub FROM metadata WHERE id=0";
    auto st = prepared_st(query);
    crypto::secret_key spend_priv;
    crypto::public_key spend_pub;
    crypto::secret_key view_priv;
    crypto::public_key view_pub;
    while (st->executeStep())
    {
      auto from_db = db::get<std::string, std::string, std::string, std::string>(st);
      tools::hex_to_type<crypto::secret_key>(std::get<0>(from_db), spend_priv);
      tools::hex_to_type<crypto::public_key>(std::get<1>(from_db), spend_pub);
      tools::hex_to_type<crypto::secret_key>(std::get<2>(from_db), view_priv);
      tools::hex_to_type<crypto::public_key>(std::get<3>(from_db), view_pub);
    }
    return std::make_shared<wallet::Keyring>(spend_priv, spend_pub, view_priv, view_pub, _nettype);
  }

}  // namespace wallet
