#include "common.hpp"

PYBIND11_MODULE(pywallet3, m) {
    wallet::Wallet_Init(m);
    wallet::Keyring_Init(m);
    wallet::KeyringManager_Init(m);
    wallet::WalletConfig_Init(m);
    wallet::GeneralWalletConfig_Init(m);
    wallet::LoggingConfig_Init(m);
    wallet::DaemonCommsConfig_Init(m);
    wallet::RPCConfig_Init(m);
}
