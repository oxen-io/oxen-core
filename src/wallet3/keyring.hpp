#pragma once

#include <crypto/crypto.h>
#include <cryptonote_basic/cryptonote_basic.h>
#include <cryptonote_basic/subaddress_index.h>
#include <cryptonote_core/oxen_name_system.h>
#include <ringct/rctSigs.h>

#include <device/device_default.hpp>
#include <optional>

#include "pending_transaction.hpp"
#include "walletkeys.hpp"

namespace wallet {
class Keyring : public WalletKeys {
  public:
    Keyring(crypto::secret_key _spend_private_key,
            crypto::public_key _spend_public_key,
            crypto::secret_key _view_private_key,
            crypto::public_key _view_public_key,
            cryptonote::network_type _nettype = cryptonote::network_type::TESTNET) :
            spend_private_key(_spend_private_key),
            spend_public_key(_spend_public_key),
            view_private_key(_view_private_key),
            view_public_key(_view_public_key),
            nettype(_nettype) {}

    Keyring(std::string _spend_private_key,
            std::string _spend_public_key,
            std::string _view_private_key,
            std::string _view_public_key,
            cryptonote::network_type _nettype = cryptonote::network_type::TESTNET) :
            nettype(_nettype) {
        tools::load_from_hex_guts<crypto::secret_key>(_spend_private_key, spend_private_key);
        tools::load_from_hex_guts<crypto::public_key>(_spend_public_key, spend_public_key);
        tools::load_from_hex_guts<crypto::secret_key>(_view_private_key, view_private_key);
        tools::load_from_hex_guts<crypto::public_key>(_view_public_key, view_public_key);
    }

    Keyring() {}

    virtual std::string get_main_address();

    virtual crypto::secret_key generate_tx_key(cryptonote::hf hf_version);

    // Derivation = a*R where
    //      `a` is the private view key of the recipient
    //      `R` is the tx public key for the output
    //
    //      For standard address:
    //          `R` = `r*G` for random `r`
    //
    //      For subaddress:
    //          `R` = `s*D` for random `s`, `D` = recipient public spend key
    virtual crypto::key_derivation generate_key_derivation(
            const crypto::public_key& tx_pubkey) const;

    virtual crypto::public_key secret_tx_key_to_public_tx_key(const crypto::secret_key tx_key);

    virtual std::vector<crypto::key_derivation> generate_key_derivations(
            const std::vector<crypto::public_key>& tx_pubkeys) const;

    virtual crypto::public_key output_spend_key(
            const crypto::key_derivation& derivation,
            const crypto::public_key& output_key,
            uint64_t output_index);

    virtual std::optional<cryptonote::subaddress_index> output_and_derivation_ours(
            const crypto::key_derivation& derivation,
            const crypto::public_key& output_key,
            uint64_t output_index);

    virtual crypto::key_image key_image(
            const crypto::key_derivation& derivation,
            const crypto::public_key& output_key,
            uint64_t output_index,
            const cryptonote::subaddress_index& sub_index);

    virtual crypto::key_image generate_key_image(const crypto::secret_key& output_private_key);

    virtual crypto::signature generate_key_image_signature(const crypto::secret_key& output_private_key, const crypto::key_image& key_image);

    virtual std::pair<uint64_t, rct::key> output_amount_and_mask(
            const rct::rctSig& rv, const crypto::key_derivation& derivation, unsigned int i);

    virtual crypto::public_key generate_output_ephemeral_keys(
            const crypto::secret_key& tx_key,
            const cryptonote::tx_destination_entry& dst_entr,
            const size_t output_index,
            std::vector<rct::key>& amount_keys);

    virtual crypto::public_key generate_change_address_ephemeral_keys(
            const crypto::secret_key& tx_key,
            const cryptonote::tx_destination_entry& dst_entr,
            const size_t output_index,
            std::vector<rct::key>& amount_keys);

    virtual crypto::secret_key derive_output_secret_key(
            const crypto::key_derivation& key_derivation,
            const size_t output_index,
            const cryptonote::subaddress_index& sub_index);

    virtual crypto::hash get_transaction_prefix_hash(const cryptonote::transaction_prefix&);

    virtual void sign_transaction(PendingTransaction& ptx);

    virtual std::vector<crypto::public_key> get_subaddress_spend_public_keys(
            uint32_t account, uint32_t begin, uint32_t end);

    virtual void expand_subaddresses(const cryptonote::subaddress_index& lookahead);

    virtual cryptonote::account_keys export_keys();

    virtual ons::generic_signature generate_ons_signature(
            const std::string& curr_owner,
            const ons::generic_owner* new_owner,
            const ons::generic_owner* new_backup_owner,
            const ons::mapping_value& encrypted_value,
            const crypto::hash& prev_txid,
            const cryptonote::network_type& nettype);

    virtual crypto::signature generate_stake_unlock_signature(
            const Output& locked_stake_output);

    cryptonote::network_type nettype;

    crypto::secret_key spend_private_key;
    crypto::public_key spend_public_key;

    crypto::secret_key view_private_key;
    crypto::public_key view_public_key;

    const crypto::secret_key& spend_privkey() const override { return spend_private_key; }
    const crypto::public_key& spend_pubkey() const override { return spend_public_key; }
    const crypto::secret_key& view_privkey() const override { return view_private_key; }
    const crypto::public_key& view_pubkey() const override { return view_public_key; }

  private:
    hw::core::device_default key_device;
    // TODO persist the subaddresses list to the database
    std::unordered_map<crypto::public_key, cryptonote::subaddress_index> subaddresses;
};

}  // namespace wallet
