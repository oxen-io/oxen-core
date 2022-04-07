#pragma once

#include <crypto/crypto.h>
#include <cryptonote_basic/subaddress_index.h>
#include <cryptonote_basic/cryptonote_basic.h>
#include <device/device_default.hpp>
#include <ringct/rctSigs.h>

#include <optional>

#include "pending_transaction.hpp"

namespace wallet
{
  class Keyring
  {
   public:
    Keyring(
        crypto::secret_key _spend_private_key,
        crypto::public_key _spend_public_key,
        crypto::secret_key _view_private_key,
        crypto::public_key _view_public_key)
        : spend_private_key(_spend_private_key)
        , spend_public_key(_spend_public_key)
        , view_private_key(_view_private_key)
        , view_public_key(_view_public_key)
    {}

    Keyring() {}

    virtual crypto::secret_key
    generate_tx_key(uint8_t hf_version);

    // Derivation = a*R where
    //      `a` is the private view key of the recipient
    //      `R` is the tx public key for the output
    //
    //      For standard address:
    //          `R` = `r*G` for random `r`
    //
    //      For subaddress:
    //          `R` = `s*D` for random `s`, `D` = recipient public spend key
    virtual crypto::key_derivation
    generate_key_derivation(const crypto::public_key& tx_pubkey) const;

    virtual crypto::public_key
    secret_tx_key_to_public_tx_key(const crypto::secret_key tx_key);

    virtual std::vector<crypto::key_derivation>
    generate_key_derivations(const std::vector<crypto::public_key>& tx_pubkeys) const;

    virtual crypto::public_key
    output_spend_key(
        const crypto::key_derivation& derivation,
        const crypto::public_key& output_key,
        uint64_t output_index);

    virtual std::optional<cryptonote::subaddress_index>
    output_and_derivation_ours(
        const crypto::key_derivation& derivation,
        const crypto::public_key& output_key,
        uint64_t output_index);

    virtual crypto::key_image
    key_image(
        const crypto::key_derivation& derivation,
        const crypto::public_key& output_key,
        uint64_t output_index,
        const cryptonote::subaddress_index& sub_index);

    virtual uint64_t
    output_amount(
        const rct::rctSig& rv,
        const crypto::key_derivation& derivation,
        unsigned int i,
        rct::key& mask);

    virtual crypto::public_key
    generate_output_ephemeral_keys(
        const crypto::secret_key& tx_key,
        const cryptonote::tx_destination_entry& dst_entr,
        const size_t output_index,
        std::vector<rct::key>& amount_keys);

    virtual crypto::public_key
    generate_change_address_ephemeral_keys(
        const crypto::secret_key& tx_key,
        const cryptonote::tx_destination_entry& dst_entr,
        const size_t output_index,
        std::vector<rct::key>& amount_keys);

    virtual crypto::secret_key
    derive_transaction_secret_key(
        const crypto::key_derivation& key_derivation,
        const size_t output_index
    );

    virtual crypto::hash
    get_transaction_prefix_hash(
        const cryptonote::transaction_prefix&
    );

    virtual void
    sign_transaction(
        PendingTransaction& ptx
    );

    virtual cryptonote::account_keys
    export_keys();

   private:
    crypto::secret_key spend_private_key;
    crypto::public_key spend_public_key;

    crypto::secret_key view_private_key;
    crypto::public_key view_public_key;

    hw::core::device_default key_device;
  };

}  // namespace wallet
