#include "keyring.hpp"

#include <common/apply_permutation.h>
#include <common/hex.h>
#include <cryptonote_basic/account.h>
#include <cryptonote_basic/cryptonote_basic.h>
#include <cryptonote_basic/txtypes.h>
#include <cryptonote_core/cryptonote_tx_utils.h>

#include <device/device.hpp>
#include <stdexcept>
#include <common/exception.h>

#include "wallet2½.hpp"

namespace wallet {
static auto logcat = oxen::log::Cat("wallet");

std::string Keyring::get_main_address() {
    cryptonote::account_public_address addr{spend_public_key, view_public_key};
    return get_account_address_as_str(nettype, false, addr);
}

crypto::secret_key Keyring::generate_tx_key(cryptonote::hf hf_version) {
    crypto::secret_key tx_key{};

    if (!key_device.open_tx(
                tx_key,
                cryptonote::transaction::get_max_version_for_hf(hf_version),
                cryptonote::txtype::standard))
        throw oxen::traced<std::runtime_error>("Could not generate transaction secret key");

    return tx_key;
}

crypto::public_key Keyring::secret_tx_key_to_public_tx_key(const crypto::secret_key a) {
    rct::key aG{};
    if (!key_device.scalarmultBase(aG, rct::sk2rct(a)))
        throw oxen::traced<std::runtime_error>("Could not convert secret tx key to public tx key");
    return rct::rct2pk(aG);
}

// Derivation Key = View Private Key * Transaction Pubkey = bR
crypto::key_derivation Keyring::generate_key_derivation(const crypto::public_key& tx_pubkey) const {
    return crypto::generate_key_derivation(tx_pubkey, view_private_key);
}

std::vector<crypto::key_derivation> Keyring::generate_key_derivations(
        const std::vector<crypto::public_key>& tx_pubkeys) const {
    std::vector<crypto::key_derivation> derivations;
    for (const auto& key : tx_pubkeys) {
        derivations.push_back(generate_key_derivation(key));
    }
    return derivations;
}

crypto::public_key Keyring::output_spend_key(
        const crypto::key_derivation& derivation,
        const crypto::public_key& output_key,
        uint64_t output_index) {
    crypto::public_key ret;

    // bool return here is pretty meaningless, but allocate it anyway to not discard its existence
    // entirely
    bool r = key_device.derive_subaddress_public_key(output_key, derivation, output_index, ret);

    return ret;
}

std::optional<cryptonote::subaddress_index> Keyring::output_and_derivation_ours(
        const crypto::key_derivation& derivation,
        const crypto::public_key& output_key,
        uint64_t output_index) {
    auto candidate_key = output_spend_key(derivation, output_key, output_index);

    // Searchs against our map for subaddress public view keys which also includes our
    // regular view key at index (0,0)
    if (const auto subaddress_index = subaddresses.find(candidate_key);
        subaddress_index != subaddresses.end())
        return subaddress_index->second;

    return std::nullopt;
}

crypto::key_image Keyring::key_image(
        const crypto::key_derivation& derivation,
        const crypto::public_key& output_key,
        uint64_t output_index,
        const cryptonote::subaddress_index& sub_index) {
    auto output_private_key = derive_output_secret_key(derivation, output_index, sub_index);

    crypto::public_key output_pubkey_computed;
    key_device.secret_key_to_public_key(output_private_key, output_pubkey_computed);

    // confirm derived output public key matches the output key in the transaction
    if (output_key != output_pubkey_computed) {
        throw std::invalid_argument("Output public key does not match derived output key.");
    }

    crypto::key_image ret;
    key_device.generate_key_image(output_key, output_private_key, ret);
    return ret;
}

// TODO: replace later when removing wallet2½ layer
std::pair<uint64_t, rct::key> Keyring::output_amount_and_mask(
        const rct::rctSig& rv, const crypto::key_derivation& derivation, unsigned int i) {
    rct::key mask{};
    auto amount = wallet25::output_amount(rv, derivation, i, mask, key_device);
    return {amount, std::move(mask)};
}

// This gets called for every output in the transaction, there is some complication for how the
// key gets generated for change address because the derivation is a*R or some simpler calc i guess
// set the bool for this_dst_is_change_addr to false and optional null for the actual thingo
crypto::public_key Keyring::generate_output_ephemeral_keys(
        const crypto::secret_key& tx_key,
        const cryptonote::tx_destination_entry& dst_entr,
        const size_t output_index,
        std::vector<rct::key>& amount_keys) {
    crypto::public_key out_eph_public_key;
    cryptonote::account_keys sender_account_keys{};
    sender_account_keys.m_view_secret_key = view_private_key;
    const auto tx_key_pub = secret_tx_key_to_public_tx_key(tx_key);
    bool this_dst_is_change_addr = false;
    // std::optional<cryptonote::tx_destination_entry> change_addr = std::nullopt;
    bool need_additional_txkeys = false;
    std::vector<crypto::secret_key> additional_tx_keys{};
    std::vector<crypto::public_key> additional_tx_public_keys{};
    key_device.generate_output_ephemeral_keys(
            static_cast<uint16_t>(cryptonote::txversion::v4_tx_types),  // size_t -> should be 4?
            this_dst_is_change_addr,  // bool -> found change. Return parameter?
            sender_account_keys,      // cryptonote::account_keys -> only uses view key i believe
            tx_key_pub,               // crypto::public_key -> public key of the transaction
            tx_key,                   // crypto::secret_key -> secret key of the transaction
            dst_entr,                 // cryptonote::tx_destination_entry -> data of the transaction
            std::nullopt,  // std::optional<cryptonote::tx_destination_entry> -> it will check if
                           // the data is the change because the one time address is different
            output_index,  // position the output is in the transaction, concatenated to generate
                           // consistently
            need_additional_txkeys,  // bool -> what are additional_txkeys ffs
            additional_tx_keys,  // std::vector<crypto::secret_key> more additional tx keys, this
                                 // time secret keys
            additional_tx_public_keys,  // std::vector<crypto::public_key> public keys of additional
                                        // keys. Return parameter?
            amount_keys,  // std::vector<rct::key> keys that committing to the amount. Device
                          // APPENDS to the vector, is essentially a return parameter
            out_eph_public_key);  // crypto::public_key -> Return parameter
    return out_eph_public_key;
}

crypto::public_key Keyring::generate_change_address_ephemeral_keys(
        const crypto::secret_key& tx_key,
        const cryptonote::tx_destination_entry& dst_entr,
        const size_t output_index,
        std::vector<rct::key>& amount_keys) {
    crypto::public_key out_eph_public_key;
    cryptonote::account_keys sender_account_keys{};
    sender_account_keys.m_view_secret_key = view_private_key;
    const auto tx_key_pub = secret_tx_key_to_public_tx_key(tx_key);
    bool this_dst_is_change_addr = true;
    bool need_additional_txkeys = false;
    std::vector<crypto::secret_key> additional_tx_keys{};
    std::vector<crypto::public_key> additional_tx_public_keys{};
    key_device.generate_output_ephemeral_keys(
            static_cast<uint16_t>(cryptonote::txversion::v4_tx_types),  // size_t -> should be 4?
            this_dst_is_change_addr,  // bool -> found change. Return parameter?
            sender_account_keys,      // cryptonote::account_keys -> only uses view key i believe
            tx_key_pub,               // crypto::public_key -> public key of the transaction
            tx_key,                   // crypto::secret_key -> secret key of the transaction
            dst_entr,                 // cryptonote::tx_destination_entry -> data of the transaction
            dst_entr,  // std::optional<cryptonote::tx_destination_entry> -> it will check if the
                       // data is the change because the one time address is different
            output_index,  // position the output is in the transaction, concatenated to generate
                           // consistently
            need_additional_txkeys,  // bool -> what are additional_txkeys ffs
            additional_tx_keys,  // std::vector<crypto::secret_key> more additional tx keys, this
                                 // time secret keys
            additional_tx_public_keys,  // std::vector<crypto::public_key> public keys of additional
                                        // keys. Return parameter?
            amount_keys,  // std::vector<rct::key> keys that committing to the amount. Device
                          // APPENDS to the vector, is essentially a return parameter
            out_eph_public_key);  // crypto::public_key -> Return parameter
    return out_eph_public_key;
}

// This is called over a transaction input to produce the secret key that can spend an outputs
// funds. The key derivation is usually produced from calling generate_key_derivation(). computes
// Hs(a*R || idx) + b if main address computes Hs(a*R || idx) + b + m if subaddress
crypto::secret_key Keyring::derive_output_secret_key(
        const crypto::key_derivation& key_derivation,
        const size_t output_index,
        const cryptonote::subaddress_index& sub_index) {
    crypto::secret_key output_secret_key;
    key_device.derive_secret_key(
            key_derivation, output_index, spend_private_key, output_secret_key);

    // If we have a subaddress that received the output then add the subaddress private key to the
    // output secret key
    if (!sub_index.is_zero())
        key_device.sc_secret_add(
                output_secret_key,
                output_secret_key,
                key_device.get_subaddress_secret_key(view_private_key, sub_index));

    return output_secret_key;
}

crypto::hash Keyring::get_transaction_prefix_hash(const cryptonote::transaction_prefix& tx) {
    crypto::hash h{};
    key_device.get_transaction_prefix_hash(tx, h);
    return h;
}

void Keyring::sign_transaction(PendingTransaction& ptx) {
    auto hf_version = cryptonote::hf::hf19_reward_batching;
    auto tx_key = generate_tx_key(hf_version);

    rct::ctkeyV inSk;
    rct::keyV dest_keys;
    rct::ctkeyM mixRing(ptx.chosen_outputs.size());
    uint64_t amount_in = 0, amount_out = 0;
    std::vector<uint64_t> inamounts, outamounts;
    std::vector<unsigned int> index;
    inSk.reserve(ptx.chosen_outputs.size());

    // Sort the inputs by their key image
    // TODO: is this *required*?
    std::vector<size_t> ins_order(ptx.chosen_outputs.size());
    for (size_t n = 0; n < ptx.chosen_outputs.size(); ++n)
        ins_order[n] = n;

    std::sort(ins_order.begin(), ins_order.end(), [&](const size_t i0, const size_t i1) {
        const crypto::key_image& img0 = ptx.chosen_outputs[i0].key_image;
        const crypto::key_image& img1 = ptx.chosen_outputs[i1].key_image;
        return memcmp(&img0, &img1, sizeof(img0)) > 0;
    });
    tools::apply_permutation(ins_order, [&](size_t i0, size_t i1) {
        std::swap(ptx.chosen_outputs[i0], ptx.chosen_outputs[i1]);
        std::swap(ptx.decoys[i0], ptx.decoys[i1]);
    });

    // Loop over inputs for the transaction to build the VIN array (Amount = 0, keyimage, array of
    // offsets for ring) and collect all the transaction private keys so we can spend our outputs in
    // this transaction.
    int i = 0;
    for (auto& src_entr : ptx.chosen_outputs) {
        // This takes the source outputs public transaction and combines it with our secret view key
        // to make a key derivation. This derivation can be used evaluate an output on the
        // blockchain to see if it is ours to spend. We already know its ours because the wallet
        // has collected them at an earlier point in time. Now we combine this derivation
        // with the output index and our secret spend key to generate
        // the output secret key which we can use to spend the output.
        crypto::secret_key output_secret_key = derive_output_secret_key(
                src_entr.derivation, src_entr.output_index, src_entr.subaddress_index);

        crypto::public_key computed_output_pubkey{};
        if (!key_device.secret_key_to_public_key(output_secret_key, computed_output_pubkey) or
            (computed_output_pubkey != src_entr.key))
            throw oxen::traced<std::runtime_error>("computed output secret key wrong, pubkey mismatch");

        // There is a input secret keys structure (inSk) that gets passed to the ringct
        // library/module and it is essentially an array of our output secret keys. It also needs to
        // know the mask which is another random number used to hide the amounts in our pederson
        // commitments.
        rct::ctkey ctkey;
        ctkey.dest = rct::sk2rct(output_secret_key);
        ctkey.mask = src_entr.rct_mask;
        inSk.push_back(ctkey);

        // Bookkeeping structures keeping track of how much $$ we are putting into the transaction
        inamounts.push_back(src_entr.amount);
        amount_in += src_entr.amount;

        // Create the VIN structure of the transaction. This will just be a simple JSON without any
        // crypto magic that shows the key images and a now redundant amount field which always says
        // zero. We generated the key images when first scanning the outputs so we can just copy it
        // straight from the database
        cryptonote::txin_to_key input_to_key;
        input_to_key.amount = src_entr.amount;
        input_to_key.k_image = key_image(
                src_entr.derivation,
                src_entr.key,
                src_entr.output_index,
                src_entr.subaddress_index);
        if (input_to_key.k_image != src_entr.key_image)
            throw oxen::traced<std::runtime_error>("computed key_image wrong");

        // The outputs array in the VIN structure lists all the global indexs of the ring decoys,
        // it uses offsets relative to the first output to save space on chain, so they need
        // to be converted from absolute to relative afterwards using the utility function.
        //
        // At this point we also push the public keys of the decoys into our mixRing struct which
        // will get passed to the ringct module which it actually will use to generate a ring
        // signature.
        mixRing[i].reserve(ptx.decoys[i].size());

        // The decoys must be sorted by global output index in order for the relative indexing below
        // to work.
        std::sort(ptx.decoys[i].begin(), ptx.decoys[i].end(), [](auto& a, auto& b) {
            return a.global_index < b.global_index;
        });

        // Find where our real output ended up in the sorting
        unsigned int ours = 0;
        for (const auto& decoy : ptx.decoys[i]) {
            if (decoy.key == src_entr.key) {
                index.push_back(ours);
                break;
            }
            ours++;
        }

        for (const auto& decoy : ptx.decoys[i]) {
            input_to_key.key_offsets.push_back(decoy.global_index);
            mixRing[i].push_back(rct::ctkey{});
            rct::ctkey& decoypk = mixRing[i].back();
            decoypk.dest = rct::pk2rct(decoy.key);
            decoypk.mask = decoy.mask;
        }

        input_to_key.key_offsets =
                cryptonote::absolute_output_offsets_to_relative(input_to_key.key_offsets);
        ptx.tx.vin.push_back(input_to_key);
        i++;
    }

    auto txkey_pub = secret_tx_key_to_public_tx_key(tx_key);
    cryptonote::remove_field_from_tx_extra<cryptonote::tx_extra_pub_key>(ptx.tx.extra);
    cryptonote::add_tx_extra<cryptonote::tx_extra_pub_key>(ptx.tx, txkey_pub);

    std::vector<rct::key> amount_keys;
    amount_keys.clear();
    i = 0;
    // Loop over destinations and generate one time destination keys (Output Ephemeral Key)
    for (const cryptonote::tx_destination_entry& recipient : ptx.recipients) {
        // amount_keys is a return parameter here, generate_output_ephemeral keys appends to the
        // vector as it goes
        crypto::public_key out_eph_public_key =
                generate_output_ephemeral_keys(tx_key, recipient, i, amount_keys);
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
    crypto::public_key change_out_eph_public_key =
            generate_change_address_ephemeral_keys(tx_key, ptx.change, i, amount_keys);
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
    const rct::RCTConfig rct_config{rct::RangeProofType::PaddedBulletproof, 3 /*CLSAG*/};

    // This generates the bulletproofs and also the ring signature, pretty much does everything and
    // adds the information for rct_signatures and rctsig_prunable to the transaction
    ptx.tx.rct_signatures = rct::genRctSimple(
            rct::hash2rct(tx_prefix_hash),  // rct::key& message
            inSk,                           // rct::ctkeyV inSk
            dest_keys,                      // rct::keyV destinations
            inamounts,                      // std::vector<xmr_amount>& inamounts
            outamounts,                     // std::vector<xmr_amount>& outamounts
            amount_in - amount_out,         // xmr_amount txnFee
            mixRing,                        // rct::ctkeyM& mixRing
            amount_keys,                    // rct::keyV amount_keys -> Return Parameter
            NULL,                           // std::vector<multisig_kLRki>* kLRki -> no multisig
            nullptr,                        // rct::multisig_out* msout -> no multisig
            index,  // std::vector<unsigned int>& index -> array of real outputs within the mixRing
                    // keys
            outSk,  // rct::ctkeyV& outSk -> Return Parameter
            rct_config,   // rct::RCTConfig& rct_config
            key_device);  // hw::device& hwdev

    if (not rct::verRctNonSemanticsSimple(ptx.tx.rct_signatures))
        throw oxen::traced<std::runtime_error>(
                "RCT signing went wrong -- verRctNonSemanticsSimple returned false");
}

// Will create subaddress spend public keys from {account, begin} to {account, end} inclusive of
// begin and end
std::vector<crypto::public_key> Keyring::get_subaddress_spend_public_keys(
        uint32_t account, uint32_t begin, uint32_t end) {
    if (begin > end)
        throw oxen::traced<std::runtime_error>("begin > end");

    std::vector<crypto::public_key> pkeys;
    pkeys.reserve(end - begin + 1);
    cryptonote::subaddress_index index = {account, begin};

    ge_p3 p3;
    ge_cached cached;
    if (ge_frombytes_vartime(&p3, spend_public_key.data()) != 0)
        throw oxen::traced<std::runtime_error>("ge_frombytes_vartime failed to convert spend public key");
    ge_p3_to_cached(&cached, &p3);

    for (uint32_t idx = begin; idx <= end; ++idx) {
        index.minor = idx;
        if (index.is_zero()) {
            pkeys.push_back(spend_public_key);
            continue;
        }
        crypto::secret_key m = key_device.get_subaddress_secret_key(view_private_key, index);

        // M = m*G
        ge_scalarmult_base(&p3, m.data());

        // D = B + M
        crypto::public_key D;
        ge_p1p1 p1p1;
        ge_add(&p1p1, &p3, &cached);
        ge_p1p1_to_p3(&p3, &p1p1);
        ge_p3_tobytes(D.data(), &p3);

        pkeys.push_back(D);
    }
    return pkeys;
}

void Keyring::expand_subaddresses(const cryptonote::subaddress_index& lookahead) {
    for (uint32_t i = 0; i < lookahead.major; i++) {
        const std::vector<crypto::public_key> pkeys =
                get_subaddress_spend_public_keys(i, 0, lookahead.minor);
        for (uint32_t j = 0; j < lookahead.minor; j++) {
            subaddresses[pkeys[j]] = {i, j};
        }
    }
}

cryptonote::account_keys Keyring::export_keys() {
    cryptonote::account_keys returned_keys{};
    returned_keys.m_account_address =
            cryptonote::account_public_address{spend_public_key, view_public_key};
    returned_keys.m_spend_secret_key = spend_private_key;
    returned_keys.m_view_secret_key = view_private_key;
    return returned_keys;
}

ons::generic_signature Keyring::generate_ons_signature(
        const std::string& curr_owner,
        const ons::generic_owner* new_owner,
        const ons::generic_owner* new_backup_owner,
        const ons::mapping_value& encrypted_value,
        const crypto::hash& prev_txid,
        const cryptonote::network_type& nettype) {
    ons::generic_signature result;
    cryptonote::address_parse_info curr_owner_parsed = {};
    if (!cryptonote::get_account_address_from_str(curr_owner_parsed, nettype, curr_owner))
        throw oxen::traced<std::runtime_error>("Could not parse address");

    // TODO sean this should actually get it from the db
    cryptonote::subaddress_index index = {0, 0};

    // std::optional<cryptonote::subaddress_index> index =
    // get_subaddress_index(curr_owner_parsed.address); if (!index) return false;

    auto sig_data = ons::tx_extra_signature(
            encrypted_value.to_view(), new_owner, new_backup_owner, prev_txid);
    if (sig_data.empty())
        throw oxen::traced<std::runtime_error>("Could not generate signature");

    cryptonote::account_base account;
    account.create_from_keys(
            cryptonote::account_public_address{spend_public_key, view_public_key},
            spend_private_key,
            view_private_key);
    auto& hwdev = account.get_device();
    hw::mode_resetter rst{key_device};
    key_device.generate_ons_signature(sig_data, account.get_keys(), index, result.monero);
    result.type = ons::generic_owner_sig_type::monero;

    return result;
}

}  // namespace wallet
