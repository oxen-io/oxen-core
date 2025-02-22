#include "keyring_manager.hpp"

#include "mnemonics/electrum-words.h"

namespace wallet {
std::shared_ptr<Keyring> KeyringManager::generate_keyring_from_electrum_seed(
        std::string& seed_phrase, std::string& seed_phrase_passphrase) {
    std::string old_language;
    crypto::secret_key recovery_key;
    if (!crypto::ElectrumWords::words_to_bytes(seed_phrase, recovery_key, old_language))
        throw std::runtime_error("Electrum-style word list failed verification");

    if (!seed_phrase_passphrase.empty())
        recovery_key = cryptonote::decrypt_key(recovery_key, seed_phrase_passphrase);

    cryptonote::account_base account;
    // Generate the account keys using the recovery key
    //  param  recovery_param          If it is a restore, the recovery key
    //  param  recover                 Whether it is a restore
    //  param  two_random              Whether it is a non-deterministic wallet
    account.generate(recovery_key, true, false);
    cryptonote::account_keys account_keys = account.get_keys();

    return std::make_shared<wallet::Keyring>(
            account_keys.m_spend_secret_key,
            account_keys.m_account_address.m_spend_public_key,
            account_keys.m_view_secret_key,
            account_keys.m_account_address.m_view_public_key,
            nettype);
}

}  // namespace wallet
