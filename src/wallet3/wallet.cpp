#include "wallet.hpp"

#include "db_schema.hpp"
#include "wallet2½.hpp"
#include "block.hpp"
#include "block_tx.hpp"
#include "default_daemon_comms.hpp"

#include <common/hex.h>
#include <cryptonote_basic/cryptonote_basic.h>

#include <sqlitedb/database.hpp>
#include <oxenmq/oxenmq.h>

#include <filesystem>
#include <future>
#include <chrono>
#include <thread>

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
      , db{std::make_shared<WalletDB>(std::filesystem::path(dbFilename), dbPassword)}
      , keys{keys}
      , tx_scanner{keys, db}
      , tx_constructor{tx_constructor}
      , daemon_comms{daemon_comms}
      , request_handler{weak_from_this()}
      , omq_server{request_handler}
      , config()
  {
    if (not omq)
    {
      omq = std::make_shared<oxenmq::OxenMQ>();
      daemon_comms = std::make_shared<DefaultDaemonComms>(omq, config.daemon);
      omq_server.set_omq(omq);
    }
    if (not daemon_comms)
      daemon_comms = std::make_shared<DefaultDaemonComms>(omq, config.daemon);
    if (not tx_constructor)
      tx_constructor = std::make_shared<TransactionConstructor>(db, daemon_comms); // TODO sean fix the input that is blank

    db->create_schema();
    last_scan_height = db->last_scan_height();
    scan_target_height = db->scan_target_height();
  }

  void
  Wallet::init()
  {
    omq->start();
    daemon_comms->set_remote("ipc://./oxend.sock");
    daemon_comms->register_wallet(*this, last_scan_height + 1 /*next needed block*/,
        true /* update sync height */,
        true /* new wallet */);
  }

  Wallet::~Wallet()
  {
  }

  void
  Wallet::propogate_config()
  {
    daemon_comms->propogate_config();
  }

  uint64_t
  Wallet::get_balance()
  {
    return db->overall_balance();
  }

  cryptonote::account_keys
  Wallet::export_keys()
  {
    return keys->export_keys();
  };

  void
  Wallet::add_block(const Block& block)
  {
    auto db_tx = db->db_transaction();

    db->store_block(block);

    for (const auto& tx : block.transactions)
    {
      if (auto outputs = tx_scanner.scan_received(tx, block.height, block.timestamp);
          not outputs.empty())
      {
        db->store_transaction(tx.hash, block.height, outputs);
      }

      if (auto spends = tx_scanner.scan_spent(tx.tx); not spends.empty())
      {
        db->store_spends(tx.hash, block.height, spends);
      }
    }

    db_tx.commit();
    last_scan_height++;
  }

  void
  Wallet::add_blocks(const std::vector<Block>& blocks)
  {
    if (not running)
      return;

    if (blocks.size() == 0)
      //TODO: error handling; this shouldn't be able to happen
      return;

    if (blocks.front().height > last_scan_height + 1)
    {
      daemon_comms->register_wallet(*this, last_scan_height + 1 /*next needed block*/, true);
      return;
    }

    for (const auto& block : blocks)
    {
      if (block.height == last_scan_height + 1)
        add_block(block);
    }
    daemon_comms->register_wallet(*this, last_scan_height + 1 /*next needed block*/, false);
  }

  void
  Wallet::update_top_block_info(int64_t height, const crypto::hash& hash)
  {
    if (not running)
      return;

    db->update_top_block_info(height, hash);

    scan_target_height = height;
  }

  void
  Wallet::deregister()
  {
    running = false;
    auto self = weak_from_this();
    std::promise<void> p;
    auto f = p.get_future();
    daemon_comms->deregister_wallet(*this, p);
    f.wait();

    /*
    // At this point, only the true "owner" should have a reference
    using namespace std::chrono_literals;
    while (self.use_count() > 1)
      std::this_thread::sleep_for(50ms);
    */
  }

}  // namespace wallet
