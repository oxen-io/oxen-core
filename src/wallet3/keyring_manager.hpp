#pragma once

#include "keyring.hpp"

namespace wallet {
class KeyringManager {
  public:
    KeyringManager() = default;
    KeyringManager(const cryptonote::network_type& type) : nettype(type){};
    std::shared_ptr<Keyring> generate_keyring_from_electrum_seed(
            std::string& seed_phrase, std::string& seed_phrase_passphrase);

  private:
    cryptonote::network_type nettype = cryptonote::network_type::MAINNET;
};

}  // namespace wallet
