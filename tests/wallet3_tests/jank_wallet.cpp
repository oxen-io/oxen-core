#include <cryptonote_core/cryptonote_core.h>
#include <wallet3/wallet.hpp>
#include <wallet3/default_daemon_comms.hpp>
#include <wallet3/keyring.hpp>
#include <wallet3/block.hpp>
#include <wallet3/block_tx.hpp>
#include <wallet3/wallet2½.hpp>
#include <common/hex.h>
#include <oxenmq/oxenmq.h>

#include <atomic>
#include <thread>
#include <future>

int main(void)
{
  crypto::secret_key spend_priv;
  tools::hex_to_type<crypto::secret_key>("d6a2eac72d1432fb816793aa7e8e86947116ac1423cbad5804ca49893e03b00c", spend_priv);
  crypto::public_key spend_pub;
  tools::hex_to_type<crypto::public_key>("2fc259850413006e39450de23e3c63e69ccbdd3a14329707db55e3501bcda5fb", spend_pub);

  crypto::secret_key view_priv;
  tools::hex_to_type<crypto::secret_key>("e93c833da9342958aff37c030cadcd04df8976c06aa2e0b83563205781cb8a02", view_priv);
  crypto::public_key view_pub;
  tools::hex_to_type<crypto::public_key>("5c1e8d44b4d7cb1269e69180dbf7aaf9c1fed4089b2bd4117dd1a70e90f19600", view_pub);

  auto keyring = std::make_shared<wallet::Keyring>(spend_priv, spend_pub, view_priv, view_pub);

  auto oxenmq = std::make_shared<oxenmq::OxenMQ>();
  auto comms = std::make_shared<wallet::DefaultDaemonComms>(oxenmq);
  auto ctor = std::make_shared<wallet::TransactionConstructor>(nullptr, comms);

  auto wallet = wallet::Wallet::create(oxenmq, keyring, ctor, comms, ":memory:", "");

  std::this_thread::sleep_for(2s);
  auto chain_height = comms->get_height();

  std::cout << "chain height: " << chain_height << "\n";

  while (true)
  {
    using namespace std::chrono_literals;

    std::this_thread::sleep_for(1s);
    std::cout << "after block " << wallet->last_scanned_height << ", balance is: " << wallet->get_balance() << "\n";
  }
}
