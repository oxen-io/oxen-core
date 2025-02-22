#pragma once

#include <memory>
#include <string_view>

#include "common/fs.h"
#include "config/config.hpp"
#include "daemon_comms.hpp"
#include "keyring.hpp"
#include "rpc/omq_server.h"
#include "rpc/request_handler.h"
#include "transaction_constructor.hpp"
#include "transaction_scanner.hpp"

namespace oxenmq {
class OxenMQ;
class TimerID;
}  // namespace oxenmq

namespace wallet {
fs::path file_path_from_default_datadir(const Config& c, const fs::path& filename);

class WalletDB;

struct Block;

class Wallet : public std::enable_shared_from_this<Wallet> {
    friend class wallet::rpc::RequestHandler;

  protected:
    Wallet(std::shared_ptr<oxenmq::OxenMQ> omq,
           std::shared_ptr<Keyring> keyring,
           std::shared_ptr<TransactionConstructor> tx_constructor,
           std::shared_ptr<DaemonComms> daemon_comms,
           std::string_view dbFilename,
           std::string_view dbPassword,
           wallet::Config config_in = {});

    void init();

  public:
    template <typename... T>
    [[nodiscard]] static std::shared_ptr<Wallet> create(T&&... args) {
        std::shared_ptr<Wallet> p{new Wallet(std::forward<T>(args)...)};
        p->init();
        return p;
    }

    virtual ~Wallet();

    Config config;

    void propogate_config();

    uint64_t get_balance();
    uint64_t get_unlocked_balance();

    cryptonote::account_keys export_keys();

    // TODO: error types to throw
    PendingTransaction create_transaction(
            const std::vector<std::pair<address, int64_t>>& recipients, int64_t feePerKB);
    void sign_transaction(PendingTransaction& tx);
    void submit_transaction(const PendingTransaction& tx);

    void add_block(const Block& block);

    void add_blocks(const std::vector<Block>& blocks);

    // Called by daemon comms to inform of new sync target.
    void update_top_block_info(int64_t height, const crypto::hash& hash);

    /* Tells the wallet to inform comms that it is going away.
     *
     * This MUST be called before the wallet is destroyed.
     */
    void deregister();

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

    // TODO get this from config
    cryptonote::network_type nettype = cryptonote::network_type::TESTNET;
};

}  // namespace wallet
