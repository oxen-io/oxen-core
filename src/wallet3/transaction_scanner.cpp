#include "transaction_scanner.hpp"

#include "block_tx.hpp"

#include <sqlitedb/database.hpp>
#include <common/string_util.h>

#include <vector>

namespace wallet
{
  std::vector<Output>
  TransactionScanner::scan_received(
      const BlockTX& tx, int64_t height, int64_t timestamp)
  {
    const auto tx_public_keys = tx.tx.get_public_keys();

    std::vector<Output> received_outputs;

    if (tx_public_keys.empty())
    {
      LOG_PRINT_L0(
          "TransactionScanner found no tx public keys in transaction with hash <" << tx.hash
                                                                                  << ">.");
      return {};
    }
    if (tx.tx.vout.size() != tx.global_indices.size())
    {
      throw std::invalid_argument(
          "Invalid wallet::BlockTX, created outputs count != global indices count.");
    }

    auto derivations = wallet_keys->generate_key_derivations(tx_public_keys);

    // Output belongs to public key derived as follows:
    //      let `Hs` := hash_to_scalar
    //      let `B`  := recipient public spend key
    //      `out_key = Hs(R || output_index)*G + B`
    //
    // Output belongs to us if we have a public key B such that
    //      `out_key - Hs(R || output_index) * G == B`
    for (size_t output_index = 0; output_index < tx.tx.vout.size(); output_index++)
    {
      const auto& output = tx.tx.vout[output_index];

      if (auto* output_target = std::get_if<cryptonote::txout_to_key>(&output.target))
      {
        size_t derivation_index = 0;
        std::optional<cryptonote::subaddress_index> sub_index{std::nullopt};
        for (derivation_index = 0; derivation_index < derivations.size(); derivation_index++)
        {
          sub_index = wallet_keys->output_and_derivation_ours(
              derivations[derivation_index], output_target->key, output_index);
          if (sub_index)
            break;
        }

        if (not sub_index)
          continue;  // not ours, move on to the next output

        // TODO: device "conceal derivation" as needed

        auto key_image = wallet_keys->key_image(
            derivations[derivation_index], output_target->key, output_index, *sub_index);

        Output o;

        // TODO: ringct mask returned by reference.  ugh.
        auto amount = wallet_keys->output_amount(
            tx.tx.rct_signatures, derivations[derivation_index], output_index, o.rct_mask);

        o.amount = amount;
        o.key_image = key_image;
        o.subaddress_index = *sub_index;
        o.output_index = output_index;
        o.global_index = tx.global_indices[output_index];
        o.tx_hash = tx.hash;
        o.tx_public_key = tx_public_keys[0];
        o.block_height = height;
        o.block_time = timestamp;
        o.unlock_time = tx.tx.get_unlock_time(output_index);
        o.key = output_target->key;
        o.derivation = derivations[derivation_index];

        received_outputs.push_back(std::move(o));
      }
      else
      {
        throw std::invalid_argument("Invalid output target variant, only txout_to_key is valid.");
      }
    }

    return received_outputs;
  }

  std::vector<crypto::key_image>
  TransactionScanner::scan_spent(const cryptonote::transaction& tx)
  {
    std::vector<crypto::key_image> spends;

    for (size_t input_index = 0; input_index < tx.vin.size(); input_index++)
    {
      const auto& input_variant = tx.vin[input_index];
      if (auto* input = std::get_if<cryptonote::txin_to_key>(&input_variant))
      {
        auto our_spend = db->prepared_get<int>(
            "SELECT COUNT(*) FROM key_images WHERE key_image = ?",
            tools::type_to_hex(input->k_image));

        if (our_spend > 0)
          spends.push_back(input->k_image);
      }
    }
    return spends;
  }

}  // namespace wallet
