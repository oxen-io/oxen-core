#include "transaction_constructor.hpp"

#include <cryptonote_basic/hardfork.h>
#include <oxenc/base64.h>

#include "db/walletdb.hpp"
#include "decoy.hpp"
#include "decoy_selection/decoy_selection.hpp"
#include "output_selection/output_selection.hpp"
#include "pending_transaction.hpp"

namespace wallet
{
  static auto logcat = oxen::log::Cat("wallet");

  // create_transaction will create a vanilla spend transaction without any special features.
  PendingTransaction
  TransactionConstructor::create_transaction(
      const std::vector<cryptonote::tx_destination_entry>& recipients,
      const cryptonote::tx_destination_entry& change_recipient)
  {
    PendingTransaction new_tx(recipients);
    auto [hf, hf_uint8] =
            cryptonote::get_ideal_block_version(db->network_type(), db->scan_target_height());
    cryptonote::oxen_construct_tx_params tx_params{hf, cryptonote::txtype::standard, 0, 0};
    new_tx.tx.version = cryptonote::transaction::get_max_version_for_hf(hf);
    new_tx.tx.type = cryptonote::txtype::standard;
    new_tx.fee_per_byte = fee_per_byte;
    new_tx.fee_per_output = fee_per_output;
    new_tx.change = change_recipient;
    select_inputs_and_finalise(new_tx);
    return new_tx;
}

PendingTransaction TransactionConstructor::create_ons_buy_transaction(
        std::string_view name,
        std::string_view type_str,
        std::string_view value,
        std::optional<std::string_view> owner_str,
        std::optional<std::string_view> backup_owner_str,
        const cryptonote::tx_destination_entry& change_recipient) {
    std::vector<cryptonote::tx_destination_entry> recipients;
    PendingTransaction new_tx(recipients);
    auto [hf, hf_uint8] =
            cryptonote::get_ideal_block_version(db->network_type(), db->scan_target_height());
    new_tx.tx.version = cryptonote::transaction::get_max_version_for_hf(hf);
    new_tx.tx.type = cryptonote::txtype::oxen_name_system;
    new_tx.fee_per_byte = fee_per_byte;
    new_tx.fee_per_output = fee_per_output;
    new_tx.change = change_recipient;
    new_tx.blink = false;

    std::string reason = "";

    const auto type = ons::parse_ons_type(std::string(type_str));
    if (!type.has_value())
        throw std::runtime_error("invalid type provided");

    const auto lower_name = tools::lowercase_ascii_string(name);
    if (!ons::validate_ons_name(*type, lower_name, &reason))
        throw std::runtime_error(reason);
    const auto name_hash = ons::name_to_hash(lower_name);

    ons::mapping_value encrypted_value;
    if (!ons::mapping_value::validate(nettype, *type, value, &encrypted_value, &reason))
        throw std::runtime_error(reason);

    if (!encrypted_value.encrypt(lower_name, &name_hash))
        throw std::runtime_error("Fail to encrypt mapping value="s + value.data());

    ons::generic_owner owner;
    ons::generic_owner backup_owner;

    if (not owner_str.has_value())
        owner = ons::make_monero_owner(change_recipient.addr, change_recipient.is_subaddress);
    else if (not ons::parse_owner_to_generic_owner(nettype, *owner_str, owner, &reason))
        throw std::runtime_error(reason);

    if (backup_owner_str.has_value() &&
        !ons::parse_owner_to_generic_owner(nettype, *backup_owner_str, backup_owner, &reason))
        throw std::runtime_error(reason);

    // No prev_txid for initial ons buy
    crypto::hash prev_txid = {};

    auto ons_buy_data = cryptonote::tx_extra_oxen_name_system::make_buy(
            owner,
            backup_owner_str.has_value() ? &backup_owner : nullptr,
            *type,
            name_hash,
            encrypted_value.to_string(),
            prev_txid);

    new_tx.burn_fixed = ons::burn_needed(cryptonote::get_latest_hard_fork(nettype).version, *type);
    new_tx.update_change();

    // Finally save the data to the extra field of our transaction
    cryptonote::add_oxen_name_system_to_tx_extra(new_tx.extra, ons_buy_data);
    cryptonote::add_burned_amount_to_tx_extra(new_tx.extra, new_tx.burn_fixed);

    select_inputs_and_finalise(new_tx);
    return new_tx;
}

PendingTransaction TransactionConstructor::create_ons_update_transaction(
        const std::string& name,
        const std::string& type_str,
        std::optional<std::string_view> value,
        std::optional<std::string_view> owner_str,
        std::optional<std::string_view> backup_owner_str,
        const cryptonote::tx_destination_entry& change_recipient,
        std::shared_ptr<Keyring> keyring) {
    if (not owner_str.has_value())
        if (not value.has_value() && not owner_str.has_value() && not backup_owner_str.has_value())
            throw std::runtime_error(
                    "Value, owner and backup owner are not specified. Atleast one field must be "
                    "specified for updating the ONS record");

    const auto lower_name = tools::lowercase_ascii_string(name);
    std::string reason;
    const auto type = ons::parse_ons_type(type_str);
    if (!type.has_value())
        throw std::runtime_error("invalid type provided");
    if (!ons::validate_ons_name(*type, lower_name, &reason))
        throw std::runtime_error(reason);
    const auto name_hash = ons::name_to_hash(lower_name);

    auto submit_ons_future = daemon->ons_names_to_owners(
            oxenc::to_base64(tools::view_guts(name_hash)), ons::db_mapping_type(*type));
    if (submit_ons_future.wait_for(5s) != std::future_status::ready)
        throw std::runtime_error("request to daemon for ons_names_to_owners timed out");

    const auto [curr_owner, prev_txid] = submit_ons_future.get();

    ons::mapping_value encrypted_value;
    if (value.has_value()) {
        if (!ons::mapping_value::validate(nettype, *type, *value, &encrypted_value, &reason))
            throw std::runtime_error(reason);

        if (!encrypted_value.encrypt(lower_name, &name_hash))
            throw std::runtime_error("Fail to encrypt name");
    }

    ons::generic_owner owner;
    if (owner_str.has_value() &&
        !ons::parse_owner_to_generic_owner(nettype, *owner_str, owner, &reason))
        throw std::runtime_error(reason);

    ons::generic_owner backup_owner;
    if (backup_owner_str.has_value() &&
        !ons::parse_owner_to_generic_owner(nettype, *backup_owner_str, backup_owner, &reason))
        throw std::runtime_error(reason);

    const auto signature = keyring->generate_ons_signature(
            curr_owner,
            owner_str.has_value() ? &owner : nullptr,
            backup_owner_str.has_value() ? &backup_owner : nullptr,
            encrypted_value,
            prev_txid,
            nettype);

    std::vector<cryptonote::tx_destination_entry> recipients;
    PendingTransaction new_tx(recipients);
    auto [hf, hf_uint8] =
            cryptonote::get_ideal_block_version(db->network_type(), db->scan_target_height());
    new_tx.tx.version = cryptonote::transaction::get_max_version_for_hf(hf);
    new_tx.tx.type = cryptonote::txtype::oxen_name_system;
    new_tx.fee_per_byte = fee_per_byte;
    new_tx.fee_per_output = fee_per_output;
    new_tx.change = change_recipient;
    new_tx.blink = false;

    auto ons_update_data = cryptonote::tx_extra_oxen_name_system::make_update(
            signature,
            *type,
            name_hash,
            encrypted_value.to_string(),
            owner_str != "" ? &owner : nullptr,
            backup_owner_str != "" ? &backup_owner : nullptr,
            prev_txid);

    // Finally save the data to the extra field of our transaction
    cryptonote::add_oxen_name_system_to_tx_extra(new_tx.extra, ons_update_data);
    new_tx.update_change();

    select_inputs_and_finalise(new_tx);
    return new_tx;
}

  void
  TransactionConstructor::validate_register_service_node_parameters(
      const std::string& service_node_key,
      const service_nodes::registration_details& registration,
      cryptonote::hf hf_version
      )
  {
    auto staking_requirement = service_nodes::get_staking_requirement(nettype, db->scan_target_height());
    auto now = std::chrono::system_clock::now();

    if (uint64_t(hf_version) != registration.hf)
      throw service_nodes::invalid_registration{"hardfork is invalid"};
    // Validate registration
    service_nodes::validate_registration(hf_version, nettype, staking_requirement, std::chrono::system_clock::to_time_t(now), registration);
    auto hash = service_nodes::get_registration_hash(registration);
    if (!crypto::check_key(registration.service_node_pubkey))
      throw service_nodes::invalid_registration{"Service Node Key is not a valid public key (" + tools::type_to_hex(registration.service_node_pubkey) + ")"};

    if (!crypto::check_signature(hash, registration.service_node_pubkey, registration.signature))
      throw service_nodes::invalid_registration{"Registration signature verification failed for pubkey/hash: " +
        tools::type_to_hex(registration.service_node_pubkey) + "/" + tools::type_to_hex(hash)};

    // Check Service Node is able to be registered
    auto get_service_node_future = daemon->get_service_nodes({service_node_key});
    if (get_service_node_future.wait_for(5s) != std::future_status::ready)
      throw std::runtime_error("request to daemon for get_service_nodes timed out");

    auto response = get_service_node_future.get();
    if(!response.is_finished())
      throw service_nodes::invalid_registration{"This service node is already registered"};
  }

  PendingTransaction
  TransactionConstructor::create_register_service_node_transaction(
      const uint64_t fee,
      const std::vector<std::string>& addresses,
      const std::vector<uint64_t>& amounts,
      const uint64_t registration_hardfork,
      const std::string& service_node_key,
      const std::string& signature_str,
      const cryptonote::tx_destination_entry& change_recipient,
      std::shared_ptr<Keyring> keyring)
  {

    std::vector<cryptonote::tx_destination_entry> recipients;
    auto& staked_amount_to_self = recipients.emplace_back();
    staked_amount_to_self.original = change_recipient.original;
    staked_amount_to_self.amount = amounts[0];
    staked_amount_to_self.addr = change_recipient.addr;
    staked_amount_to_self.is_subaddress = change_recipient.is_subaddress;
    staked_amount_to_self.is_integrated = change_recipient.is_integrated;

    PendingTransaction new_tx(recipients);
    auto [hf, hf_uint8] = cryptonote::get_ideal_block_version(db->network_type(), db->scan_target_height());
    new_tx.tx.version = cryptonote::transaction::get_max_version_for_hf(hf);
    new_tx.tx.type = cryptonote::txtype::stake;
    new_tx.fee_per_byte = fee_per_byte;
    new_tx.fee_per_output = fee_per_output;
    new_tx.change = change_recipient;
    new_tx.blink = false;

    cryptonote::add_service_node_contributor_to_tx_extra(new_tx.extra, change_recipient.addr);

    crypto::public_key service_node_public_key;
    if (!tools::hex_to_type(service_node_key, service_node_public_key))
      throw std::runtime_error("could not read service node key");
    cryptonote::add_service_node_pubkey_to_tx_extra(new_tx.extra, service_node_public_key);

    crypto::signature signature;
    if (!tools::hex_to_type(signature_str, signature))
      throw std::runtime_error("could not read signature");
    service_nodes::registration_details registration{service_node_public_key, {}, fee, registration_hardfork, false, signature};
    cryptonote::address_parse_info addr_info;
    for (size_t i = 0; i < amounts.size(); i++) {
      cryptonote::get_account_address_from_str(addr_info, nettype, addresses[i]);
      if (addr_info.has_payment_id)
        throw service_nodes::invalid_registration{"Can't use a payment id for staking tx"};

      if (addr_info.is_subaddress)
        throw service_nodes::invalid_registration{"Can't use a subaddress for staking tx"};
      registration.reserved.emplace_back(addr_info.address, amounts[i]);
    }
    if (!cryptonote::add_service_node_registration_to_tx_extra(new_tx.extra, registration))
      throw std::runtime_error("Failed to serialize service node registration tx extra");


    new_tx.tx_secret_key = keyring->generate_tx_key(hf);
    cryptonote::add_tx_secret_key_to_tx_extra(new_tx.extra, *new_tx.tx_secret_key);
    // TODO this sends the secret key to the hardware device so it know to use it
    //if (!hwdev.update_staking_tx_secret_key(tx_sk)) {
        //log::warning(globallogcat, "Failed to add tx secret key to stake transaction");
        //return false;
    //}
    
    cryptonote::tx_extra_tx_key_image_proofs key_image_proofs;

    auto& proof = key_image_proofs.proofs.emplace_back();
    proof.key_image = keyring->generate_key_image(*new_tx.tx_secret_key);
    proof.signature = keyring->generate_key_image_signature(*new_tx.tx_secret_key, proof.key_image);
    cryptonote::add_tx_key_image_proofs_to_tx_extra(new_tx.extra, key_image_proofs);

    validate_register_service_node_parameters(service_node_key, registration, hf);

    new_tx.update_change();

    //TODO sean get use the new tx_key from somewhere
    select_inputs_and_finalise(new_tx);
    return new_tx;
  }

  void
  TransactionConstructor::validate_stake_parameters(
      const std::string& service_node_key,
      uint64_t& amount,
      const cryptonote::tx_destination_entry& change_recipient
      )
  {
    if (change_recipient.is_integrated)
      throw std::runtime_error{"Payment IDs cannot be used in a staking transaction"};

    if (change_recipient.is_subaddress)
      throw std::runtime_error{"Subaddresses cannot be used in a staking transaction"};

    /// check that the service node is registered
    auto get_service_node_future = daemon->get_service_nodes({service_node_key});
    if (get_service_node_future.wait_for(5s) != std::future_status::ready)
      throw std::runtime_error("request to daemon for get_service_nodes timed out");

    auto response = get_service_node_future.get();
    if(response.is_finished())
      throw std::runtime_error("Could not find service node in service node list, please make sure it is registered first.");
    auto snode_info = response.consume_dict_consumer();

    const auto hf_version = cryptonote::get_latest_hard_fork(nettype).version;

    if (not snode_info.skip_until("contributors"))
      throw std::runtime_error{"Invalid response from daemon"};
    auto contributors = snode_info.consume_list_consumer();

    if (not snode_info.skip_until("staking_requirement"))
      throw std::runtime_error{"Invalid response from daemon"};
    const auto staking_req = snode_info.consume_integer<int64_t>();

    if (not snode_info.skip_until("total_contributed"))
      throw std::runtime_error{"Invalid response from daemon"};
    const auto total_contributed = snode_info.consume_integer<int64_t>();

    uint64_t total_res = 0;
    if (snode_info.skip_until("total_reserved"))
      total_res = snode_info.consume_integer<int64_t>();

    size_t total_existing_contributions = 0; // Count both contributions and reserved spots
    bool is_preexisting_contributor = false;
    uint64_t reserved_amount_not_contributed_yet = 0;
    while (not contributors.is_finished())
    {
      auto contributor = contributors.consume_dict_consumer();

      if (not contributor.skip_until("address"))
        throw std::runtime_error{"Invalid response from daemon"};
      auto contributor_address = contributor.consume_string();

      if (not contributor.skip_until("amount"))
        throw std::runtime_error{"Invalid response from daemon"};
      auto amount = contributor.consume_integer<int64_t>();

      if (not contributor.skip_until("locked_contributions"))
        throw std::runtime_error{"Invalid response from daemon"};
      auto locked_contributions = contributor.consume_list_consumer();

      while (not locked_contributions.is_finished())
      {
        locked_contributions.consume_dict_consumer();
        total_existing_contributions++;
      }

      int64_t reserved = 0;
      if (contributor.skip_until("reserved"))
        reserved = contributor.consume_integer<int64_t>();

      if (reserved > amount)
          total_existing_contributions++; // reserved contributor spot
                                          
      if (contributor_address == change_recipient.address(nettype, {}))
      {
        is_preexisting_contributor = true;
        reserved_amount_not_contributed_yet = reserved - amount;
      }
    }

    uint64_t max_contrib_total = staking_req - total_res + reserved_amount_not_contributed_yet;

    uint64_t min_contrib_total = service_nodes::get_min_node_contribution(hf_version, staking_req, total_res, total_existing_contributions);
    if (min_contrib_total == UINT64_MAX || reserved_amount_not_contributed_yet > min_contrib_total)
      min_contrib_total = reserved_amount_not_contributed_yet;

    if (max_contrib_total == 0)
      throw std::runtime_error("The service node cannot receive any more Oxen from this wallet");

    const bool full = total_existing_contributions >= oxen::MAX_CONTRIBUTORS_HF19;

    if (full && !is_preexisting_contributor)
      throw std::runtime_error("The service node already has the maximum number of participants and this wallet is not one of them");


    if (amount == 0)
    {
      oxen::log::info(logcat, "No amount provided to stake txn, assuming minimum contributrion of: {}", cryptonote::print_money(min_contrib_total));
      amount = min_contrib_total;
    }

    if (amount < min_contrib_total)
    {
      const uint64_t DUST = oxen::MAX_CONTRIBUTORS_HF19;
      if (min_contrib_total - amount <= DUST)
      {
        oxen::log::info(logcat, "Seeing as this is insufficient by dust amounts, amount was increased automatically to ", cryptonote::print_money(min_contrib_total));
        amount = min_contrib_total;
      }
      else
        throw std::runtime_error(fmt::format("You must contribute at least {} oxen to become a contributor for this service node.", min_contrib_total));
    }

    if (amount > max_contrib_total)
    {
      oxen::log::info(logcat, "You may only contribute up to {} more oxen to this service node. Reducing your stake from {} to {}", max_contrib_total, amount, max_contrib_total);
      amount = max_contrib_total;
    }
  }

  PendingTransaction
  TransactionConstructor::create_stake_transaction(
      const std::string& destination,
      const std::string& service_node_key,
      const uint64_t requested_amount,
      const cryptonote::tx_destination_entry& change_recipient
      )
  {
    uint64_t amount = requested_amount;
    double amount_fraction = 0;
    validate_stake_parameters(service_node_key, amount, change_recipient);

    std::vector<cryptonote::tx_destination_entry> recipients;
    auto& staked_amount_to_self = recipients.emplace_back();
    staked_amount_to_self.original = change_recipient.original;
    staked_amount_to_self.amount = amount;
    staked_amount_to_self.addr = change_recipient.addr;
    staked_amount_to_self.is_subaddress = change_recipient.is_subaddress;
    staked_amount_to_self.is_integrated = change_recipient.is_integrated;

    PendingTransaction new_tx(recipients);
    auto [hf, hf_uint8] = cryptonote::get_ideal_block_version(db->network_type(), db->scan_target_height());
    new_tx.tx.version = cryptonote::transaction::get_max_version_for_hf(hf);
    new_tx.tx.type = cryptonote::txtype::stake;
    new_tx.fee_per_byte = fee_per_byte;
    new_tx.fee_per_output = fee_per_output;
    new_tx.change = change_recipient;
    new_tx.blink = false;

    crypto::public_key service_node_public_key;
    if (!tools::hex_to_type(service_node_key, service_node_public_key))
      throw std::runtime_error("could not read service node key");

    cryptonote::add_service_node_pubkey_to_tx_extra(new_tx.extra, service_node_public_key);
    cryptonote::add_service_node_contributor_to_tx_extra(new_tx.extra, change_recipient.addr);

    new_tx.update_change();

    select_inputs_and_finalise(new_tx);
    return new_tx;
  }

  PendingTransaction
  TransactionConstructor::create_stake_unlock_transaction(
      const std::string& service_node_key,
      const cryptonote::tx_destination_entry& change_recipient,
      std::shared_ptr<Keyring> keyring)
  {

    std::vector<cryptonote::tx_destination_entry> recipients;
    PendingTransaction new_tx(recipients);
    auto [hf, hf_uint8] = cryptonote::get_ideal_block_version(db->network_type(), db->scan_target_height());
    new_tx.tx.version = cryptonote::transaction::get_max_version_for_hf(hf);
    new_tx.tx.type = cryptonote::txtype::stake;
    new_tx.fee_per_byte = fee_per_byte;
    new_tx.fee_per_output = fee_per_output;
    new_tx.change = change_recipient;
    new_tx.blink = false;

    crypto::public_key service_node_public_key;
    if (!tools::hex_to_type(service_node_key, service_node_public_key))
      throw std::runtime_error("could not read service node key");
    cryptonote::add_service_node_pubkey_to_tx_extra(new_tx.extra, service_node_public_key);

    auto get_service_node_future = daemon->get_service_nodes({service_node_key});
    if (get_service_node_future.wait_for(5s) != std::future_status::ready)
      throw std::runtime_error("request to daemon for get_service_nodes timed out");

    auto response = get_service_node_future.get();
    if(response.is_finished())
      throw std::runtime_error("Could not find service node in service node list, please make sure it is registered first.");
    auto snode_info = response.consume_dict_consumer();

    const auto hf_version = cryptonote::get_latest_hard_fork(nettype).version;

    if (not snode_info.skip_until("contributors"))
      throw std::runtime_error{"Invalid response from daemon"};
    auto contributors = snode_info.consume_list_consumer();

    cryptonote::tx_extra_tx_key_image_unlock unlock = {};
    unlock.nonce = cryptonote::tx_extra_tx_key_image_unlock::FAKE_NONCE;
    // Loop over contributors
    bool found_our_contribution = false;
    while (not contributors.is_finished())
    {
        auto contributor = contributors.consume_dict_consumer();

        if (not contributor.skip_until("address"))
            throw std::runtime_error{"Invalid response from daemon"};
        auto contributor_address = contributor.consume_string();
        if (contributor_address != change_recipient.address(nettype, {}))
            continue;

        found_our_contribution = true;

        if (not contributor.skip_until("key_image"))
            throw std::runtime_error{"Invalid response from daemon"};

        const auto key_image = response.consume_string();
        if(!tools::hex_to_type(key_image, unlock.key_image))
            throw std::runtime_error{"Failed to parse hex representation of key image"s + key_image};

        const auto locked_stake_output = db->get_output_from_key_image(key_image);

        unlock.signature = keyring->generate_stake_unlock_signature(locked_stake_output);
    }

    // If did not find then throw
    if (not found_our_contribution)
        throw std::runtime_error{"did not find our contribution in this service node"};

    add_tx_key_image_unlock_to_tx_extra(new_tx.extra, unlock);
    new_tx.update_change();
    select_inputs_and_finalise(new_tx);

    return new_tx;
  }


  // SelectInputs will choose some available unspent outputs from the database and allocate to the
  // transaction can be called multiple times and will add until enough is sufficient
  void
  TransactionConstructor::select_inputs(PendingTransaction& ptx) const
  {
    const int64_t single_input_size = ptx.get_fee(1);
    const int64_t double_input_size = ptx.get_fee(2);
    const int64_t additional_input = double_input_size - single_input_size;
    const int64_t dust_amount = single_input_size * ptx.fee_per_byte;

    OutputSelector select_outputs{};
    const int noutputs_estimate = 300;  // number of outputs to precompute fee for
    for (int64_t output_count = 1; output_count < noutputs_estimate; ++output_count) {
        select_outputs.push_fee(output_count, ptx.get_fee(output_count));
    }
    int64_t transaction_total = ptx.sum_outputs();

    // Check that we actually have enough in the outputs to build this transaction. Fail early. We
    // then increase the transaction_total to include an amount sufficient to cover a reasonable
    // change amount. Transaction fee is high for the first input because there is overhead to cover
    // and prefer that the change amount is enough to cover that overhead, but if we dont have
    // enough in the wallet then try to ensure there is enough to cover the fee as an additional
    // (2nd+) input. Finally if the wallet balance is not sufficient allow the change to be dust but
    // this will only occur if the wallet has enough to cover the transaction but not enough to also
    // cover the dust which should be extremely unlikely.
    int64_t wallet_balance =
            db->available_balance(additional_input * static_cast<int64_t>(ptx.fee_per_byte));
    if (wallet_balance < transaction_total)
        throw std::runtime_error("Insufficient Wallet Balance");
    else if (
            wallet_balance >
            transaction_total + single_input_size * static_cast<int64_t>(ptx.fee_per_byte))
        transaction_total += single_input_size * ptx.fee_per_byte;
    else if (
            wallet_balance >
            transaction_total + additional_input * static_cast<int64_t>(ptx.fee_per_byte))
        transaction_total += additional_input * ptx.fee_per_byte;

    // Selects all outputs where the amount is greater than the estimated fee for an ADDITIONAL
    // input.
    auto available_outputs =
            db->available_outputs(additional_input * static_cast<int64_t>(ptx.fee_per_byte));
    ptx.chosen_outputs = select_outputs(available_outputs, ptx.sum_outputs());
    ptx.fee = ptx.get_fee();
    ptx.update_change();
}

// select_and_fetch_decoys will choose some available outputs from the database, fetch the
// details necessary for a ring signature from the daemon and add them to the
// transaction ready to sign at a later point in time.
void TransactionConstructor::select_and_fetch_decoys(PendingTransaction& ptx) {
    ptx.decoys = {};
    // This initialises the decoys to be selected from global_output_index= 0 to global_output_index
    // = highest_output_index
    int64_t max_output_index = db->chain_output_count();
    // DecoySelector decoy_selection(0, max_output_index);
    DecoySelector& decoy_selection = *decoy_selector;
    std::vector<int64_t> indexes;
    for (const auto& output : ptx.chosen_outputs) {
        indexes = decoy_selection(output);
        auto decoy_future = daemon->fetch_decoys(indexes);
        decoy_future.wait();
        ptx.decoys.emplace_back(decoy_future.get());

        bool good = false;
        for (const auto& decoy : ptx.decoys.back())
            good |= (output.key == decoy.key);
        if (!good)
            throw std::runtime_error{
                    "Key from daemon for real output does not match our stored key."};
    }
}

void TransactionConstructor::select_inputs_and_finalise(PendingTransaction& ptx) {
    while (true) {
        if (ptx.finalise())
            break;
        else
            select_inputs(ptx);
    }
    select_and_fetch_decoys(ptx);
}
}  // namespace wallet
