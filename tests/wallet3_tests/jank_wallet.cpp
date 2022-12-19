#include <wallet3/wallet.hpp>
#include <wallet3/default_daemon_comms.hpp>
#include <wallet3/keyring.hpp>
#include <wallet3/block.hpp>
#include <wallet3/block_tx.hpp>
#include <wallet3/wallet2½.hpp>
#include <wallet3/config/config.hpp>

#include <cryptonote_core/cryptonote_core.h>
#include <common/hex.h>
#include <common/string_util.h>
#include <oxenmq/oxenmq.h>

#include <atomic>
#include <thread>
#include <future>
#include <algorithm>

int main(int argc, char** argv)
{
  std::string wallet_name = "test_wallet1";
  crypto::secret_key spend_priv;
  crypto::public_key spend_pub;
  crypto::secret_key view_priv;
  crypto::public_key view_pub;
  std::string wallet_addr = "T6SYSC9FVpn15BGNpYYx3dHiATyjXoyqbSGBqgu5QbqEUmETnGSFqjtay42DBs6yZpVbgJcyhsbDUcUL3msN4GyW2HhR7aTmh";
  if (argc == 1 or std::string(argv[1]) == "1") // no cli arg = test wallet 1
  {
    tools::hex_to_type<crypto::secret_key>("d6a2eac72d1432fb816793aa7e8e86947116ac1423cbad5804ca49893e03b00c", spend_priv);
    tools::hex_to_type<crypto::public_key>("2fc259850413006e39450de23e3c63e69ccbdd3a14329707db55e3501bcda5fb", spend_pub);

    tools::hex_to_type<crypto::secret_key>("e93c833da9342958aff37c030cadcd04df8976c06aa2e0b83563205781cb8a02", view_priv);
    tools::hex_to_type<crypto::public_key>("5c1e8d44b4d7cb1269e69180dbf7aaf9c1fed4089b2bd4117dd1a70e90f19600", view_pub);
  }
  else // cli arg that isn't "1" = test wallet 2
  {
    wallet_name = "test_wallet2";
    wallet_addr = "T6ThzoXPCEvKjB9jce9rhd5gpovK5hvfX6yE1d6nC2H7QobLgoYNvW12qrahC9HtrtHNty58UXHZoNGyDnCeSFbY3Bu8yFtgh";
    tools::hex_to_type<crypto::secret_key>("e6c9165356c619a64a0d26fafd99891acccccf8717a8067859d972ecd8bcfc0a", spend_priv);
    tools::hex_to_type<crypto::public_key>("b76f2d7c8a036ff65c564dcb27081c04fe3f2157942e23b0496ca797ba728e4f", spend_pub);
    tools::hex_to_type<crypto::secret_key>("961d67bb5b3ed1af8678bbfcf621f9c15c2b7bff080892890020bdfd47fe4f0a", view_priv);
    tools::hex_to_type<crypto::public_key>("8a0ebacd613e0b03b8f27bc64bd961ea2ebf4c671c6e7f3268651acf0823fed5", view_pub);
  }

  std::cout << "Loading wallet \"" << wallet_name << "\" with address " << wallet_addr << "\n";

  auto keyring = std::make_shared<wallet::Keyring>(spend_priv, spend_pub, view_priv, view_pub, cryptonote::network_type::TESTNET);

  wallet::Config config = {};
  auto& comms_config = config.daemon;
  auto& omq_rpc_config = config.omq_rpc;
  auto oxenmq = std::make_shared<oxenmq::OxenMQ>();
  auto comms = std::make_shared<wallet::DefaultDaemonComms>(oxenmq, comms_config);
  config.omq_rpc.sockname = wallet_name + ".sock";
  auto wallet = wallet::Wallet::create(oxenmq, keyring, nullptr, comms, ":memory:", "", config);

  std::this_thread::sleep_for(1s);

  std::atomic<bool> done = false;


  oxenmq::address remote{std::string("ipc://") + wallet_name + ".sock"};
  oxenmq::ConnectionID conn;
  conn = oxenmq->connect_remote(remote, [](auto){}, [](auto,auto){});

  auto send_func = [&](std::string_view dest, std::string_view amount){
    oxenc::bt_dict req;
    oxenc::bt_list dests;
    oxenc::bt_dict d;
    d["address"] = dest;
    uint64_t amount_int = stoi(std::string(amount));
    d["amount"] = amount_int;
    dests.push_back(std::move(d));
    req["destinations"] = std::move(dests);

    std::promise<bool> p;
    auto f = p.get_future();

    auto req_cb = [&p](bool ok, std::vector<std::string> response) mutable
        {
          std::cout << "transfer response, bool ok = " << std::boolalpha << ok << "\n";
          size_t n = 0;
          for (const auto& s : response)
          {
            std::cout << "response string " << n++ << ": " << s << "\n";
          }
          p.set_value(ok);
        };

    oxenmq->request(conn, "restricted.transfer", req_cb, oxenc::bt_serialize(req));

    f.wait();
  };

  std::thread exit_thread([&](){
      while (not done)
      {
        std::string foo;
        std::getline(std::cin, foo);
        if (foo == "stop" or foo == "quit" or foo == "exit" or foo.empty())
        {
          done = true;
          break;
        }

        auto chain_height = comms->get_height();
        auto scan_height = wallet->last_scan_height;

        auto args = tools::split(foo, " ", true);
        if (args[0] == "send")
        {
          if (args.size() != 3)
            std::cout << "malformed send command.  Use \"send address amount\"\n";
          else
            send_func(args[1], args[2]);
        }
        else if (args[0] == "balance")
        {
          std::cout << "after block " << scan_height << ", " << wallet_name << " balance is: " << wallet->get_balance() << "\n";
        }
        else if (args[0] == "height")
        {
          std::cout << "chain height: " << chain_height << "\n";
        }
      }
      });

  auto current_chain_height = comms->get_height();
  int64_t last_scan_height = -1;
  bool printed_synced = false;

  while (not done)
  {
    using namespace std::chrono_literals;

    last_scan_height = wallet->last_scan_height;
    current_chain_height = comms->get_height();
    if ((not printed_synced) and current_chain_height > 0 and last_scan_height == current_chain_height)
    {
      std::cout << "syncing appears finished, " << wallet_name << "height = " << last_scan_height << ", balance = " << wallet->get_balance() << "\n";
      printed_synced = true;
    }

    std::this_thread::sleep_for(1s);
  }

  exit_thread.join();


  wallet->deregister();
}
