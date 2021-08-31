#include "transaction_scanner.hpp"

#include <common/string_util.h>

#include <vector>

namespace
{

} // anonymous namespace

namespace wallet
{

  std::vector<Output> TransactionScanner::ScanTransactionReceived(const cryptonote::transaction& tx, const crypto::hash& tx_hash, uint64_t height, uint64_t timestamp)
  {

    auto tx_public_keys = tx.get_public_keys();

    if (tx_public_keys.empty())
    {
      LOG_PRINT_L0("TransactionScanner found no tx public keys in transaction with hash <" << tx_hash << ">.");
      return;
    }

    // simple case first, handle only first found tx pubkey
    // TODO: handle all tx pub keys

    // Derivation = a*R where
    //      `a` is the private view key of the recipient
    //      `R` is the tx public key for the output
    //
    //      For standard address:
    //          `R` = `r*G` for random `r`
    //
    //      For subaddress:
    //          `R` = `s*D` for random `s`, `D` = recipient public spend key
    auto derivation = wallet_keys->KeyDerivation(tx_public_keys[0]);

    // Output belongs to public key derived as follows:
    //      let `Hs` := hash_to_scalar
    //      let `B`  := recipient public spend key
    //      `out_key = Hs(R || output_index)*G + B`
    // 
    // Output belongs to us if we have a public key B such that
    //      `out_key - Hs(R || output_index) * G == B`
    for (size_t output_index = 0; output_index < tx.vout.size(); output_index++)
    {
      const auto& output = tx.vout[output_index];

      if (auto* output_target = std::get_if<cryptonote::txout_to_key>(&output.target))
      {
        auto output_spend_key = wallet_keys->OutputSpendKey(derivation, output_target->key, output_index);

        // TODO: check if we have a subaddress with public spend key `output_spend_key`
        //       if so, this output is for us.

        // auto subaddress_index = <check if we have the public key output_spend_key, get the subaddress index>
        auto key_image = wallet_keys->KeyImage(tx_public_keys[0], derivation, output_index, subaddress_index);
      }
      else
      {
        throw std::invalid_argument("Invalid output target, only txout_to_key is valid.");
      }

    }


    return {};
  }

  std::vector<Output> TransactionScanner::ScanTransactionSpent(const cryptonote::transaction& tx, const crypto::hash& tx_hash, uint64_t height, uint64_t timestamp)
  {
    return {};
  }

} // namespace wallet
