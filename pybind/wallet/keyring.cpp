#include "wallet3/keyring.hpp"

#include <common/hex.h>
#include <crypto/crypto.h>
#include <cryptonote_basic/cryptonote_basic.h>

#include "../common.hpp"

namespace wallet {
void Keyring_Init(py::module& mod) {
    py::class_<Keyring, std::shared_ptr<Keyring>>(mod, "Keyring")
            .def(py::init([](std::string ssk,
                             std::string spk,
                             std::string vsk,
                             std::string vpk,
                             std::string nettype) {
                auto type = cryptonote::network_type::MAINNET;
                if (nettype == "testnet")
                    type = cryptonote::network_type::TESTNET;
                else if (nettype == "devnet")
                    type = cryptonote::network_type::DEVNET;
                crypto::secret_key spend_priv;
                crypto::public_key spend_pub;
                crypto::secret_key view_priv;
                crypto::public_key view_pub;
                tools::hex_to_type<crypto::secret_key>(ssk, spend_priv);
                tools::hex_to_type<crypto::public_key>(spk, spend_pub);
                tools::hex_to_type<crypto::secret_key>(vsk, view_priv);
                tools::hex_to_type<crypto::public_key>(vpk, view_pub);
                return Keyring(spend_priv, spend_pub, view_priv, view_pub, std::move(type));
            }))

            .def("get_main_address", &Keyring::get_main_address);
}

}  // namespace wallet
