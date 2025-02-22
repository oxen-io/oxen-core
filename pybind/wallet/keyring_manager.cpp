#include "wallet3/keyring_manager.hpp"

#include <crypto/crypto.h>
#include <cryptonote_basic/cryptonote_basic.h>

#include "../common.hpp"

namespace wallet {
void KeyringManager_Init(py::module& mod) {
    py::class_<KeyringManager, std::shared_ptr<KeyringManager>>(mod, "KeyringManager")
            .def(py::init([](std::string nettype) {
                auto type = cryptonote::network_type::MAINNET;
                if (nettype == "testnet")
                    type = cryptonote::network_type::TESTNET;
                else if (nettype == "devnet")
                    type = cryptonote::network_type::DEVNET;
                return KeyringManager(std::move(type));
            }))

            .def("generate_keyring_from_electrum_seed",
                 &KeyringManager::generate_keyring_from_electrum_seed);
}

}  // namespace wallet
