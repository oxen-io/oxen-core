#pragma once

#include "transaction_scanner.hpp"
#include "transaction_constructor.hpp"
#include "daemon_comms.hpp"
#include "keyring.hpp"

#include "config/config.hpp"

#include "rpc/request_handler.h"
#include "rpc/omq_server.h"

#include <memory>
#include <string_view>

namespace oxenmq
{
  class OxenMQ;
  class TimerID;
}

namespace wallet
{
  class WalletDB;

  struct Block;

  class Wallet : public std::enable_shared_from_this<Wallet>
  {
    friend class wallet::rpc::RequestHandler;

   protected:
    Wallet(
        std::shared_ptr<oxenmq::OxenMQ> omq,
        std::shared_ptr<Keyring> keys,
        std::shared_ptr<TransactionConstructor> tx_constructor,
        std::shared_ptr<DaemonComms> daemon_comms,
        std::string_view dbFilename,
        std::string_view dbPassword);

    void
    init();

   public:
    template <typename... T>
    [[nodiscard]] static std::shared_ptr<Wallet>
    create(T&&... args)
    {
      std::shared_ptr<Wallet> p{new Wallet(std::forward<T>(args)...)};
      p->init();
      return p;
    }

    ~Wallet();

    Config config;

    void
    propogate_config();

    uint64_t
    get_balance();
    uint64_t
    get_unlocked_balance();

    cryptonote::address_parse_info
    get_address();

    cryptonote::account_keys
    export_keys();

    // FIXME: argument nomenclature
    cryptonote::address_parse_info
    get_subaddress(int32_t account, int32_t index);

    // TODO: error types to throw
    PendingTransaction
    create_transaction(
        const std::vector<std::pair<address, int64_t>>& recipients, int64_t feePerKB);
    void
    sign_transaction(PendingTransaction& tx);
    void
    submit_transaction(const PendingTransaction& tx);

    void
    add_block(const Block& block);

    void
    add_blocks(const std::vector<Block>& blocks);

    // Called by daemon comms to inform of new sync target.
    void
    update_top_block_info(int64_t height, const crypto::hash& hash);

    /* Tells the wallet to inform comms that it is going away.
     *
     * This MUST be called before the wallet is destroyed.
     */
    void
    deregister();

    int64_t scan_target_height = 0;
    int64_t last_scan_height = -1;

   protected:

    std::shared_ptr<oxenmq::OxenMQ> omq;

    std::shared_ptr<WalletDB> db;

    std::shared_ptr<Keyring> keys;
    TransactionScanner tx_scanner;
    std::shared_ptr<TransactionConstructor> tx_constructor;
    std::shared_ptr<DaemonComms> daemon_comms;
    wallet::rpc::RequestHandler request_handler;
    wallet::rpc::OmqServer omq_server;
    bool running = true;

    cryptonote::network_type nettype = cryptonote::TESTNET;
  };

}  // namespace wallet
