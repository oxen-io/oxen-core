#include "wallet.hpp"

#include "db_schema.hpp"
#include "wallet2½.hpp"
#include "block.hpp"
#include "block_tx.hpp"

#include <common/hex.h>
#include <cryptonote_basic/cryptonote_basic.h>

#include <sqlitedb/database.hpp>
#include <oxenmq/oxenmq.h>

#include <filesystem>
#include <future>

#include <iostream>

namespace wallet
{
  Wallet::Wallet(
      std::shared_ptr<oxenmq::OxenMQ> omq,
      std::shared_ptr<Keyring> keys,
      std::shared_ptr<TransactionConstructor> tx_constructor,
      std::shared_ptr<DaemonComms> daemon_comms,
      std::string_view dbFilename,
      std::string_view dbPassword)
      : omq(omq)
      , db{std::make_shared<db::Database>(std::filesystem::path(dbFilename), dbPassword)}
      , keys{keys}
      , tx_scanner{keys, db}
      , tx_constructor{tx_constructor}
      , daemon_comms{daemon_comms}
      , request_handler{*this}
      , omq_server{omq, request_handler}
  {
    create_schema(db->db);
    last_scanned_height = db->prepared_get<int64_t>("SELECT last_scan_height FROM metadata WHERE id=0;");
    scan_target_height = db->prepared_get<int64_t>("SELECT scan_target_height FROM metadata WHERE id=0;");
  }

  void
  Wallet::init()
  {
    omq->start();
    daemon_comms->set_remote("ipc://./oxend.sock");
    daemon_comms->register_wallet(*this, last_scanned_height + 1 /*next needed block*/, true);
  }

  Wallet::~Wallet()
  {
    std::cout << "Wallet::~Wallet()\n";
  }

  uint64_t
  Wallet::get_balance()
  {
    return db->prepared_get<int64_t>("SELECT balance FROM metadata WHERE id=0;");
  }

  void
  Wallet::add_block(const Block& block)
  {
    SQLite::Transaction db_tx(db->db);

    db->prepared_exec(
        "INSERT INTO blocks(height,transaction_count,hash,timestamp) VALUES(?,?,?,?)",
        block.height,
        static_cast<int64_t>(block.transactions.size()),
        tools::type_to_hex(block.hash),
        block.timestamp);

    for (const auto& tx : block.transactions)
    {
      if (auto outputs = tx_scanner.scan_received(tx, block.height, block.timestamp);
          not outputs.empty())
      {
        store_transaction(tx.hash, block.height, outputs);
      }

      if (auto spends = tx_scanner.scan_spent(tx.tx); not spends.empty())
      {
        store_spends(tx.hash, block.height, spends);
      }
    }

    db_tx.commit();
    last_scanned_height++;
  }

  void
  Wallet::add_blocks(const std::vector<Block>& blocks)
  {
    if (not running)
      return;

    if (blocks.size() == 0)
      //TODO: error handling; this shouldn't be able to happen
      return;

    if (blocks.front().height > last_scanned_height + 1)
    {
      daemon_comms->register_wallet(*this, last_scanned_height + 1 /*next needed block*/, true);
      return;
    }

    for (const auto& block : blocks)
    {
      if (block.height == last_scanned_height + 1)
        add_block(block);
    }
    daemon_comms->register_wallet(*this, last_scanned_height + 1 /*next needed block*/, false);
  }

  void
  Wallet::update_top_block_info(int64_t height, const crypto::hash& hash)
  {
    if (not running)
      return;

    auto hash_str = tools::type_to_hex(hash);
    db->prepared_exec("UPDATE metadata SET scan_target_height = ?, scan_target_hash = ? WHERE id = 0",
        height, hash_str);

    scan_target_height = height;
  }

  void
  Wallet::deregister()
  {
    auto self = weak_from_this();
    std::cout << "Wallet ref count before deregister: " << self.use_count() << "\n";
    running = false;
    std::promise<void> p;
    auto f = p.get_future();
    daemon_comms->deregister_wallet(*this, p);
    f.wait();
    std::cout << "Wallet ref count after deregister: " << self.use_count() << "\n";
  }

  void
  Wallet::store_transaction(
      const crypto::hash& tx_hash, const int64_t height, const std::vector<Output>& outputs)
  {
    auto hash_str = tools::type_to_hex(tx_hash);
    db->prepared_exec(
        "INSERT INTO transactions(block,hash) VALUES(?,?)", height, hash_str);

    for (const auto& output : outputs)
    {
      db->prepared_exec(
          "INSERT INTO key_images(key_image) VALUES(?)", tools::type_to_hex(output.key_image));
      db->prepared_exec(
          R"(
          INSERT INTO outputs(
            amount,
            output_index,
            global_index,
            unlock_time,
            block_height,
            tx,
            output_key,
            rct_mask,
            key_image,
            subaddress_major,
            subaddress_minor)
          VALUES(?,?,?,?,?,
            (SELECT id FROM transactions WHERE hash = ?),
            ?,?,
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
          tools::type_to_hex(output.rct_mask),
          tools::type_to_hex(output.key_image),
          output.subaddress_index.major,
          output.subaddress_index.minor);
    }
  }

  void
  Wallet::store_spends(
      const crypto::hash& tx_hash,
      const int64_t height,
      const std::vector<crypto::key_image>& spends)
  {
    auto hash_hex = tools::type_to_hex(tx_hash);
    db->prepared_exec(
        "INSERT INTO transactions(block,hash) VALUES(?,?) ON CONFLICT DO NOTHING",
        height,
        hash_hex);

    for (const auto& key_image : spends)
    {
      db->prepared_exec(
          R"(INSERT INTO spends(key_image, height, tx)
          VALUES((SELECT id FROM key_images WHERE key_image = ?),
          ?,
          (SELECT id FROM transactions WHERE hash = ?));)",
          tools::type_to_hex(key_image),
          height,
          hash_hex);
    }
  }

}  // namespace wallet
