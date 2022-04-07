#include "keyring.hpp"

#include "wallet2½.hpp"

#include <stdexcept>
#include <cryptonote_core/cryptonote_tx_utils.h>
#include <cryptonote_basic/cryptonote_basic.h>
#include <cryptonote_basic/txtypes.h>
#include <cryptonote_basic/account.h>
#include <device/device.hpp>

namespace wallet
{
  crypto::secret_key
  Keyring::generate_tx_key(uint8_t hf_version)
  {
    // TODO sean make sure this is zero
    crypto::secret_key tx_key{};
    // TODO sean this should base itself on the hf version
    //return key_device.open_tx(tx_key, transaction::get_max_version_for_hf(hf_version), txtype::standard);
    if (!key_device.open_tx(tx_key, cryptonote::txversion::v4_tx_types, cryptonote::txtype::standard))
      throw std::runtime_error("Could not generate transaction secret key");

    return tx_key;
  }

  crypto::public_key
  Keyring::secret_tx_key_to_public_tx_key(const crypto::secret_key a)
  {
    // TODO sean make sure this is zero
    rct::key aG{};
    if (!key_device.scalarmultBase(aG, rct::sk2rct(a)))
      throw std::runtime_error("Could not convert secret tx key to public tx key");
    return  rct::rct2pk(aG);
  }

  crypto::key_derivation
  Keyring::generate_key_derivation(const crypto::public_key& tx_pubkey) const
  {
    return crypto::generate_key_derivation(tx_pubkey, view_private_key);
  }

  std::vector<crypto::key_derivation>
  Keyring::generate_key_derivations(const std::vector<crypto::public_key>& tx_pubkeys) const
  {
    std::vector<crypto::key_derivation> derivations;
    for (const auto& key : tx_pubkeys)
    {
      derivations.push_back(generate_key_derivation(key));
    }
    return derivations;
  }

  crypto::public_key
  Keyring::output_spend_key(
      const crypto::key_derivation& derivation,
      const crypto::public_key& output_key,
      uint64_t output_index)
  {
    crypto::public_key ret;

    // bool return here is pretty meaningless, but allocate it anyway to not discard its existence
    // entirely
    bool r = key_device.derive_subaddress_public_key(output_key, derivation, output_index, ret);

    return ret;
  }

  std::optional<cryptonote::subaddress_index>
  Keyring::output_and_derivation_ours(
      const crypto::key_derivation& derivation,
      const crypto::public_key& output_key,
      uint64_t output_index)
  {
    auto candidate_key = output_spend_key(derivation, output_key, output_index);

    // TODO: handle checking against subaddresses
    if (candidate_key == spend_public_key)
    {
      return cryptonote::subaddress_index{0, 0};
    }
    return std::nullopt;
  }

  crypto::key_image
  Keyring::key_image(
      const crypto::key_derivation& derivation,
      const crypto::public_key& output_key,
      uint64_t output_index,
      const cryptonote::subaddress_index& sub_index)
  {
    // TODO: subaddress support, for now throw if not main address
    if (not sub_index.is_zero())
    {
      throw std::invalid_argument("Subaddresses not yet supported in wallet3");
    }

    crypto::secret_key output_private_key;

    // computes Hs(a*R || idx) + b
    key_device.derive_secret_key(derivation, output_index, spend_private_key, output_private_key);

    crypto::public_key output_pubkey_computed;
    key_device.secret_key_to_public_key(output_private_key, output_pubkey_computed);

    // confirm derived output public key matches the output key in the transaction
    if (output_key != output_pubkey_computed)
    {
      throw std::invalid_argument("Output public key does not match derived output key.");
    }

    crypto::key_image ret;
    key_device.generate_key_image(output_key, output_private_key, ret);
    return ret;
  }

  // TODO: replace later when removing wallet2½ layer
  uint64_t
  Keyring::output_amount(
      const rct::rctSig& rv,
      const crypto::key_derivation& derivation,
      unsigned int i,
      rct::key& mask)
  {
    return wallet25::output_amount(rv, derivation, i, mask, key_device);
  }

  // This gets called for every output in the transaction, there is some complication for how the 
  // key gets generated for change address because the derivation is a*R or some simpler calc i guess
  // set the bool for this_dst_is_change_addr to false and optional null for the actual thingo
  crypto::public_key
  Keyring::generate_output_ephemeral_keys(const crypto::secret_key& tx_key, const cryptonote::tx_destination_entry& dst_entr, const size_t output_index, std::vector<rct::key>& amount_keys)
  {
    crypto::public_key out_eph_public_key;
    cryptonote::account_keys sender_account_keys{};
    sender_account_keys.m_view_secret_key = view_private_key;
    const auto tx_key_pub = secret_tx_key_to_public_tx_key(tx_key);
    bool this_dst_is_change_addr = false;
    //std::optional<cryptonote::tx_destination_entry> change_addr = std::nullopt;
    bool need_additional_txkeys = false;
    std::vector<crypto::secret_key> additional_tx_keys{};
    std::vector<crypto::public_key> additional_tx_public_keys{};
    key_device.generate_output_ephemeral_keys(
        static_cast<uint16_t>(cryptonote::txversion::v4_tx_types), // size_t -> should be 4?
        this_dst_is_change_addr, // bool -> found change. Return parameter?
        sender_account_keys, // cryptonote::account_keys -> only uses view key i believe
        tx_key_pub, // crypto::public_key -> public key of the transaction
        tx_key, // crypto::secret_key -> secret key of the transaction
        dst_entr, // cryptonote::tx_destination_entry -> data of the transaction
        std::nullopt, // std::optional<cryptonote::tx_destination_entry> -> it will check if the data is the change because the one time address is different
        output_index, // position the output is in the transaction, concatenated to generate consistently
        need_additional_txkeys, // bool -> what are additional_txkeys ffs
        additional_tx_keys, // std::vector<crypto::secret_key> more additional tx keys, this time secret keys
        additional_tx_public_keys, // std::vector<crypto::public_key> public keys of additional keys. Return parameter?
        amount_keys, // std::vector<rct::key> keys that committing to the amount. Device APPENDS to the vector, is essentially a return parameter
        out_eph_public_key); // crypto::public_key -> Return parameter
    return out_eph_public_key;
  }

  crypto::public_key
  Keyring::generate_change_address_ephemeral_keys(const crypto::secret_key& tx_key, const cryptonote::tx_destination_entry& dst_entr, const size_t output_index, std::vector<rct::key>& amount_keys)
  {
    crypto::public_key out_eph_public_key;
    cryptonote::account_keys sender_account_keys{};
    sender_account_keys.m_view_secret_key = view_private_key;
    const auto tx_key_pub = secret_tx_key_to_public_tx_key(tx_key);
    bool this_dst_is_change_addr = true;
    bool need_additional_txkeys = false;
    std::vector<crypto::secret_key> additional_tx_keys{};
    std::vector<crypto::public_key> additional_tx_public_keys{};
    key_device.generate_output_ephemeral_keys(
        static_cast<uint16_t>(cryptonote::txversion::v4_tx_types), // size_t -> should be 4?
        this_dst_is_change_addr, // bool -> found change. Return parameter?
        sender_account_keys, // cryptonote::account_keys -> only uses view key i believe
        tx_key_pub, // crypto::public_key -> public key of the transaction
        tx_key, // crypto::secret_key -> secret key of the transaction
        dst_entr, // cryptonote::tx_destination_entry -> data of the transaction
        dst_entr, // std::optional<cryptonote::tx_destination_entry> -> it will check if the data is the change because the one time address is different
        output_index, // position the output is in the transaction, concatenated to generate consistently
        need_additional_txkeys, // bool -> what are additional_txkeys ffs
        additional_tx_keys, // std::vector<crypto::secret_key> more additional tx keys, this time secret keys
        additional_tx_public_keys, // std::vector<crypto::public_key> public keys of additional keys. Return parameter?
        amount_keys, // std::vector<rct::key> keys that committing to the amount. Device APPENDS to the vector, is essentially a return parameter
        out_eph_public_key); // crypto::public_key -> Return parameter
    return out_eph_public_key;
  }

  // This is called over a transaction input to produce the secret key that can spend an outputs funds.
  // The key derivation is usually produced from calling generate_key_derivation().
  crypto::secret_key
  Keyring::derive_transaction_secret_key(const crypto::key_derivation& key_derivation, const size_t output_index)
  {
    crypto::secret_key output_secret_key;
    key_device.derive_secret_key(key_derivation, output_index, spend_private_key, output_secret_key);
    return output_secret_key;
  }

  crypto::hash
  Keyring::get_transaction_prefix_hash(const cryptonote::transaction_prefix& tx)
  {
    crypto::hash h = crypto::null_hash;
    key_device.get_transaction_prefix_hash(tx, h);
    return h;
  }

  void
  Keyring::sign_transaction(PendingTransaction& ptx)
  {
    uint8_t hf_version = cryptonote::network_version_19;
    auto tx_key = generate_tx_key(hf_version);

    rct::ctkeyV inSk;
    rct::keyV dest_keys;
    rct::ctkeyM mixRing(ptx.chosen_outputs.size());
    uint64_t amount_in = 0, amount_out = 0;
    std::vector<uint64_t> inamounts, outamounts;
    std::vector<unsigned int> index;
    inSk.reserve(ptx.chosen_outputs.size() + 1);

    // Loop over inputs for the transaction to build the VIN array (Amount = 0, keyimage, array of offsets for ring)
    // and collect all the transaction private keys so we can spend our outputs in this transaction.
    int i = 0;
    for(const auto& src_entr: ptx.chosen_outputs)
    {
      // This takes the source outputs public transaction and combines it with our secret view key 
      // to make a key derivation. This derivation can be used evaluate an output on the 
      // blockchain to see if it is ours to spend. We already know its ours because the wallet 
      // has collected them at an earlier point in time. Now we combine this derivation
      // with the output index and our secret spend key to generate
      // the actual transaction secret key which we can use to spend the output.
      crypto::secret_key output_secret_key = derive_transaction_secret_key(src_entr.derivation, src_entr.output_index);

      // There is a input secret keys structure (inSk) that gets passed to the ringct library/module and it is
      // essentially an array of our output secret keys. It also needs to know the mask which is
      // another random number used to hide the amounts in our pederson commitments.
      rct::ctkey ctkey;
      ctkey.dest = rct::sk2rct(output_secret_key);
      ctkey.mask = src_entr.rct_mask;
      inSk.push_back(ctkey);

      // Bookkeeping structures keeping track of how much $$ we are putting into the transaction
      inamounts.push_back(src_entr.amount);
      amount_in += src_entr.amount;

      // Create the VIN structure of the transaction. This will just be a simple JSON without any crypto magic that
      // shows the key images and a now redundant amount field which always says zero. We generated the key images
      // when first scanning the outputs so we can just copy it straight from the database
      cryptonote::txin_to_key input_to_key;
      input_to_key.amount = 0;
      input_to_key.k_image = key_image(src_entr.derivation, src_entr.key, src_entr.output_index, src_entr.subaddress_index);
      // The outputs array in the VIN structure lists all the global indexs of the ring decoys,
      // it uses offsets relative to the first output to save space on chain, so they need 
      // to be converted from absolute to relative afterwards using the utility function.
      //
      // At this point we also push the public keys of the decoys into our mixRing struct which will get
      // passed to the ringct module which it actually will use to generate a ring signature.
      mixRing[i].reserve(ptx.decoys[i].size());
      for(const auto& decoy: ptx.decoys[i])
      {
        input_to_key.key_offsets.push_back(decoy.global_index);
        mixRing[i].push_back(rct::ctkey{});
        rct::ctkey& decoypk = mixRing[i].back();
        decoypk.dest = rct::pk2rct(decoy.key);
        decoypk.mask = decoy.mask;
      }
      input_to_key.key_offsets.push_back(src_entr.global_index);
      index.push_back(src_entr.global_index);

      input_to_key.key_offsets = cryptonote::absolute_output_offsets_to_relative(input_to_key.key_offsets);
      ptx.tx.vin.push_back(input_to_key);
      i++;
    }

    /*
    // Sort the inputs by their key image
    std::sort(ptx.tx.vin.begin(), ptx.tx.vin.end(), [&](const auto& a, const auto& b) {
      const cryptonote::txin_to_key &tk0 = var::get<cryptonote::txin_to_key>(a);
      const cryptonote::txin_to_key &tk1 = var::get<cryptonote::txin_to_key>(b);
      return memcmp(&tk0.k_image, &tk1.k_image, sizeof(tk0.k_image)) > 0;
    });
    */

    // TODO: apply the above sorting

    auto txkey_pub = secret_tx_key_to_public_tx_key(tx_key);
    cryptonote::remove_field_from_tx_extra<cryptonote::tx_extra_pub_key>(ptx.tx.extra);
    cryptonote::add_tx_extra<cryptonote::tx_extra_pub_key>(ptx.tx, txkey_pub);

    std::vector<rct::key> amount_keys;
    amount_keys.clear();
    i = 0;
    // Loop over destinations and generate one time destination keys (Output Ephemeral Key)
    for(const cryptonote::tx_destination_entry& recipient: ptx.recipients)
    {
      //amount_keys is a return parameter here, generate_output_ephemeral keys appends to the vector as it goes
      crypto::public_key out_eph_public_key = generate_output_ephemeral_keys(tx_key, recipient, i, amount_keys);
      cryptonote::tx_out out{};
      out.amount = recipient.amount;
      cryptonote::txout_to_key tk{};
      tk.key = out_eph_public_key;
      out.target = tk;
      dest_keys.push_back(rct::pk2rct(out_eph_public_key));
      outamounts.push_back(recipient.amount);
      amount_out += recipient.amount;
      ptx.tx.vout.push_back(out);
      // TODO sean the output should be shuffled
      i++;
    }

    // TODO: extra pub keys as needed (will come into play with subaddresses)

    // Generate one time destination key for change address (Output Ephemeral Key)
    crypto::public_key change_out_eph_public_key = generate_change_address_ephemeral_keys(tx_key, ptx.change, i, amount_keys);
    cryptonote::tx_out change_out{};
    change_out.amount = ptx.change.amount;
    cryptonote::txout_to_key change_tk{};
    change_tk.key = change_out_eph_public_key;
    change_out.target = change_tk;
    dest_keys.push_back(rct::pk2rct(change_out_eph_public_key));
    outamounts.push_back(ptx.change.amount);
    ptx.tx.vout.push_back(change_out);
    amount_out += ptx.change.amount;

    // Zero amounts in tx.vin and tx.vout before ringct step
    for (auto& i : ptx.tx.vin)
      var::get<cryptonote::txin_to_key>(i).amount = 0;
    for (auto& o : ptx.tx.vout)
      o.amount = 0;

    crypto::hash tx_prefix_hash = get_transaction_prefix_hash(ptx.tx);

    rct::ctkeyV outSk;
    const rct::RCTConfig rct_config{rct::RangeProofType::PaddedBulletproof, 3/*CLSAG*/};

    // This generates the bulletproofs and also the ring signature, pretty much does everything and adds
    // the information for rct_signatures and rctsig_prunable to the transaction
    ptx.tx.rct_signatures = rct::genRctSimple(
        rct::hash2rct(tx_prefix_hash), // rct::key& message
        inSk, // rct::ctkeyV inSk
        dest_keys, // rct::keyV destinations
        inamounts, // std::vector<xmr_amount>& inamounts
        outamounts, // std::vector<xmr_amount>& outamounts
        amount_in - amount_out, // xmr_amount txnFee
        mixRing, // rct::ctkeyM& mixRing
        amount_keys, // rct::keyV amount_keys -> Return Parameter
        NULL, // std::vector<multisig_kLRki>* kLRki -> no multisig
        nullptr, // rct::multisig_out* msout -> no multisig
        index, // std::vector<unsigned int>& index -> array of real outputs within the mixRing keys
        outSk, // rct::ctkeyV& outSk -> Return Parameter
        rct_config, // rct::RCTConfig& rct_config
        key_device); // hw::device& hwdev
  }

  cryptonote::account_keys
  Keyring::export_keys()
  {
    cryptonote::account_keys returned_keys{};
    returned_keys.m_account_address = cryptonote::account_public_address{spend_public_key, view_public_key};
    returned_keys.m_spend_secret_key = spend_private_key;
    returned_keys.m_view_secret_key = view_private_key;
    return returned_keys;
  }

}  // namespace wallet
