#pragma once

#include <cryptonote_basic/cryptonote_basic.h>

namespace wallet
{

  class Keys
  {
  public:

    virtual cryptonote::account_public_address GetAddress() = 0;

    //TODO: use this type or just "public_key", as the derivation is just a public key?
    crypto::key_derivation KeyDerivation(const crypto::public_key& tx_key);

    // compute what the address spend public key must be if the output is for this wallet
    crypto::public_key OutputSpendKey(const crypto::key_derivation& derivation, const crypto::public_key& output_key, uint64_t output_index);

    crypto::key_image KeyImage(const crypto::public_key& output_key, const crypto::key_derivation& derivation, uint64_t output_index, cryptonote::subaddress_index subaddress);

  };

} // namespace wallet
