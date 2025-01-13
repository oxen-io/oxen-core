#pragma once

#include <wallet3/wallet.hpp>
#include <wallet3/block.hpp>
#include <sqlitedb/database.hpp>
#include <wallet3/db/walletdb.hpp>
#include "mock_daemon_comms.hpp"

namespace wallet
{

template <typename T>
T debug_random_filled(uint64_t seed) {
    static_assert(sizeof(T) % 8 == 0 && alignof(T) >= alignof(uint64_t)
        && std::is_trivially_copyable_v<T>);
    T value;
    auto* value_u64 = reinterpret_cast<uint64_t*>(&value);
    std::mt19937_64 rng{seed};
    for (size_t i = 0; i < sizeof(T) / sizeof(uint64_t); i++)
        value_u64[i] = rng();
    return value;
}

class MockWallet : public Wallet
{
  public:

    MockWallet() : Wallet({},std::make_shared<Keyring>(),{},std::make_shared<MockDaemonComms>(),":memory:","",{}){};
    MockWallet(
        crypto::secret_key _spend_private_key,
        crypto::public_key _spend_public_key,
        crypto::secret_key _view_private_key,
        crypto::public_key _view_public_key,
        cryptonote::network_type _nettype = cryptonote::network_type::TESTNET
        ) : Wallet({},std::make_shared<Keyring>(_spend_private_key, _spend_public_key, _view_private_key, _view_public_key),{},std::make_shared<MockDaemonComms>(),":memory:","",{}){};

    int64_t height = 0;

    std::shared_ptr<WalletDB> get_db() { return db; };

    void
    store_test_transaction(const int64_t amount) 
    {
      height++;

      wallet::Block b{};
      b.height = height;
      auto hash = debug_random_filled<crypto::hash>(height);
      b.hash = hash;
      add_block(b);

      std::vector<wallet::Output> dummy_outputs;
      wallet::Output o{};
      o.amount = amount;
      o.block_height = height;
      o.subaddress_index = cryptonote::subaddress_index{0,0};
      o.key_image = debug_random_filled<crypto::key_image>(height);
      o.tx_public_key = debug_random_filled<crypto::public_key>(height);
      dummy_outputs.push_back(o);

      auto db_tx = db->db_transaction();
      db->store_transaction(hash, height, dummy_outputs);
      db_tx.commit();
    };

    void
    store_test_output(wallet::Output o) 
    {
      height++;

      wallet::Block b{};
      b.height = height;
      auto hash = debug_random_filled<crypto::hash>(height);
      b.hash = hash;
      add_block(b);

      std::vector<wallet::Output> dummy_outputs;
      o.block_height = height;
      dummy_outputs.push_back(o);

      SQLite::Transaction db_tx(db->db);
      db->store_transaction(hash, height, dummy_outputs);
      db_tx.commit();
    };
};


} // namespace wallet
