#include "transaction_scanner.hpp"

#include <common/string_util.h>
#include "common/exception.h"

#include <sqlitedb/database.hpp>
#include <vector>

#include "block_tx.hpp"

namespace wallet {
namespace log = oxen::log;
static auto logcat = log::Cat("wallet");

std::vector<Output> TransactionScanner::scan_received(
        const BlockTX& tx, int64_t height, int64_t timestamp) {
    const auto tx_public_keys = tx.tx.get_public_keys();

    std::vector<Output> received_outputs;

    if (tx_public_keys.empty()) {
        // This sometimes occurs for things like recommission transactions sent by the quorum
        log::trace(
                logcat,
                "TransactionScanner found no tx public keys in transaction with hash <{}>.",
                tx.hash);
        return {};
    }
    if (tx.tx.vout.size() != tx.global_indices.size()) {
        throw oxen::traced<std::invalid_argument>(
                "Invalid wallet::BlockTX, created outputs count != global indices count.");
    }

    // A derivation is simply the private view key multiplied by the tx public key
    // do this for every tx public key in the transaction
    auto derivations = wallet_keys->generate_key_derivations(tx_public_keys);
    bool coinbase_transaction = tx.tx.is_miner_tx();
    // Output belongs to public key derived as follows:
    //      let `Hs` := hash_to_scalar
    //      let `B`  := recipient public spend key
    //      let `R`  := transaction public key
    //      `out_key = Hs(R || output_index)*G + B`
    //
    // Output belongs to us if we have a public key B such that
    //      `out_key - Hs(R || output_index) * G == B`
    for (size_t output_index = 0; output_index < tx.tx.vout.size(); output_index++) {
        log::debug(logcat, "scanning output at height: {} output index: {}", height, output_index);
        const auto& output = tx.tx.vout[output_index];

        if (auto* output_target = std::get_if<cryptonote::txout_to_key>(&output.target)) {
            size_t derivation_index = 0;
            std::optional<cryptonote::subaddress_index> sub_index{std::nullopt};
            for (derivation_index = 0; derivation_index < derivations.size(); derivation_index++) {
                sub_index = wallet_keys->output_and_derivation_ours(
                        derivations[derivation_index], output_target->key, output_index);
                if (sub_index)
                    break;
            }

            if (not sub_index)
                continue;  // not ours, move on to the next output
                           //
            log::info(
                    logcat,
                    "Found an output belonging to us with subindex: {}:{}",
                    sub_index->major,
                    sub_index->minor);

            // TODO: device "conceal derivation" as needed

            auto key_image = wallet_keys->key_image(
                    derivations[derivation_index], output_target->key, output_index, *sub_index);

            Output o;

            if (coinbase_transaction) {
                o.amount = output.amount;
                o.rct_mask = rct::identity();
            } else {
                std::tie(o.amount, o.rct_mask) = wallet_keys->output_amount_and_mask(
                        tx.tx.rct_signatures, derivations[derivation_index], output_index);
            }

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
        } else {
            throw oxen::traced<std::invalid_argument>(
                    "Invalid output target variant, only txout_to_key is valid.");
        }
    }

    return received_outputs;
}

std::vector<crypto::key_image> TransactionScanner::scan_spent(const cryptonote::transaction& tx) {
    std::vector<crypto::key_image> spends;

    for (size_t input_index = 0; input_index < tx.vin.size(); input_index++) {
        const auto& input_variant = tx.vin[input_index];
        if (auto* input = std::get_if<cryptonote::txin_to_key>(&input_variant)) {
            auto our_spend = db->prepared_get<int>(
                    "SELECT COUNT(*) FROM key_images WHERE key_image = ?",
                    tools::hex_guts(input->k_image));

            if (our_spend > 0)
                spends.push_back(input->k_image);
        }
    }
    return spends;
}

void TransactionScanner::set_keys(std::shared_ptr<Keyring> keys) {
    if (wallet_keys != keys)
        wallet_keys = keys;
}

}  // namespace wallet
