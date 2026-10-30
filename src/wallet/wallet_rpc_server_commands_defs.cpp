// Copyright (c) 2018-2020, The Loki Project
// Copyright (c) 2014-2019, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include "wallet_rpc_server_commands_defs.h"

#include "serialization/levin_kv/archive.h"

namespace tools::wallet_rpc {

void EMPTY::serialize(levin_kv::archive&) {}

void GET_BALANCE::request::serialize(levin_kv::archive& ar) {
    ar.value("account_index", account_index);
    ar.value("address_indices", address_indices);
    ar.value_or("all_accounts", all_accounts, false);
    ar.value_or("strict", strict, false);
}

void GET_BALANCE::per_subaddress_info::serialize(levin_kv::archive& ar) {
    ar.value("account_index", account_index);
    ar.value("address_index", address_index);
    ar.value("address", address);
    ar.value("balance", balance);
    ar.value("unlocked_balance", unlocked_balance);
    ar.value("label", label);
    ar.value("num_unspent_outputs", num_unspent_outputs);
    ar.value("blocks_to_unlock", blocks_to_unlock);
    ar.value("time_to_unlock", time_to_unlock);
}

void GET_BALANCE::response::serialize(levin_kv::archive& ar) {
    ar.value("balance", balance);
    ar.value("unlocked_balance", unlocked_balance);
    ar.value("accrued_balance", accrued_balance);
    ar.value("accrued_balance_next_payout", accrued_balance_next_payout);
    ar.value("multisig_import_needed", multisig_import_needed);
    ar.value("per_subaddress", per_subaddress);
    ar.value("blocks_to_unlock", blocks_to_unlock);
    ar.value("time_to_unlock", time_to_unlock);
}

void GET_ADDRESS::request::serialize(levin_kv::archive& ar) {
    ar.value("account_index", account_index);
    ar.value("address_index", address_index);
}

void GET_ADDRESS::address_info::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
    ar.value("label", label);
    ar.value("address_index", address_index);
    ar.value("used", used);
}

void GET_ADDRESS::response::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
    ar.value("addresses", addresses);
}

void GET_ADDRESS_INDEX::request::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
}

void GET_ADDRESS_INDEX::response::serialize(levin_kv::archive& ar) {
    ar.value("index", index);
}

void CREATE_ADDRESS::request::serialize(levin_kv::archive& ar) {
    ar.value("account_index", account_index);
    ar.value_or("count", count, 1U);
    ar.value("label", label);
}

void CREATE_ADDRESS::response::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
    ar.value("address_index", address_index);
    ar.value("addresses", addresses);
    ar.value("address_indices", address_indices);
}

void LABEL_ADDRESS::request::serialize(levin_kv::archive& ar) {
    ar.value("index", index);
    ar.value("label", label);
}

void GET_ACCOUNTS::request::serialize(levin_kv::archive& ar) {
    ar.value("tag", tag);
    ar.value_or("strict_balances", strict_balances, false);
}

void GET_ACCOUNTS::subaddress_account_info::serialize(levin_kv::archive& ar) {
    ar.value("account_index", account_index);
    ar.value("base_address", base_address);
    ar.value("balance", balance);
    ar.value("unlocked_balance", unlocked_balance);
    ar.value("label", label);
    ar.value("tag", tag);
}

void GET_ACCOUNTS::response::serialize(levin_kv::archive& ar) {
    ar.value("total_balance", total_balance);
    ar.value("total_unlocked_balance", total_unlocked_balance);
    ar.value("subaddress_accounts", subaddress_accounts);
}

void CREATE_ACCOUNT::request::serialize(levin_kv::archive& ar) {
    ar.value("label", label);
}

void CREATE_ACCOUNT::response::serialize(levin_kv::archive& ar) {
    ar.value("account_index", account_index);
    ar.value("address", address);
}

void LABEL_ACCOUNT::request::serialize(levin_kv::archive& ar) {
    ar.value("account_index", account_index);
    ar.value("label", label);
}

void GET_ACCOUNT_TAGS::account_tag_info::serialize(levin_kv::archive& ar) {
    ar.value("tag", tag);
    ar.value("label", label);
    ar.value("accounts", accounts);
}

void GET_ACCOUNT_TAGS::response::serialize(levin_kv::archive& ar) {
    ar.value("account_tags", account_tags);
}

void TAG_ACCOUNTS::request::serialize(levin_kv::archive& ar) {
    ar.value("tag", tag);
    ar.value("accounts", accounts);
}

void UNTAG_ACCOUNTS::request::serialize(levin_kv::archive& ar) {
    ar.value("accounts", accounts);
}

void SET_ACCOUNT_TAG_DESCRIPTION::request::serialize(levin_kv::archive& ar) {
    ar.value("tag", tag);
    ar.value("description", description);
}

void GET_HEIGHT::response::serialize(levin_kv::archive& ar) {
    ar.value("height", height);
    ar.value("immutable_height", immutable_height);
}

void TRANSFER::request::serialize(levin_kv::archive& ar) {
    ar.value("destinations", destinations);
    ar.value("account_index", account_index);
    ar.value("subaddr_indices", subaddr_indices);
    ar.value("priority", priority);
    ar.value("unlock_time", unlock_time);
    ar.value("payment_id", payment_id);
    ar.value("get_tx_key", get_tx_key);
    ar.value_or("do_not_relay", do_not_relay, false);
    ar.value_or("get_tx_hex", get_tx_hex, false);
    ar.value_or("get_tx_metadata", get_tx_metadata, false);
}

void TRANSFER::response::serialize(levin_kv::archive& ar) {
    ar.value("tx_hash", tx_hash);
    ar.value("tx_key", tx_key);
    ar.value("amount", amount);
    ar.value("fee", fee);
    ar.value("tx_blob", tx_blob);
    ar.value("tx_metadata", tx_metadata);
    ar.value("multisig_txset", multisig_txset);
    ar.value("unsigned_txset", unsigned_txset);
}

void TRANSFER_SPLIT::request::serialize(levin_kv::archive& ar) {
    ar.value("destinations", destinations);
    ar.value("account_index", account_index);
    ar.value("subaddr_indices", subaddr_indices);
    ar.value("priority", priority);
    ar.value("unlock_time", unlock_time);
    ar.value("payment_id", payment_id);
    ar.value("get_tx_keys", get_tx_keys);
    ar.value_or("do_not_relay", do_not_relay, false);
    ar.value_or("get_tx_hex", get_tx_hex, false);
    ar.value_or("get_tx_metadata", get_tx_metadata, false);
}

void TRANSFER_SPLIT::key_list::serialize(levin_kv::archive& ar) {
    ar.value("keys", keys);
}

void TRANSFER_SPLIT::response::serialize(levin_kv::archive& ar) {
    ar.value("tx_hash_list", tx_hash_list);
    ar.value("tx_key_list", tx_key_list);
    ar.value("amount_list", amount_list);
    ar.value("fee_list", fee_list);
    ar.value("tx_blob_list", tx_blob_list);
    ar.value("tx_metadata_list", tx_metadata_list);
    ar.value("multisig_txset", multisig_txset);
    ar.value("unsigned_txset", unsigned_txset);
}

void DESCRIBE_TRANSFER::recipient::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
    ar.value("amount", amount);
}

void DESCRIBE_TRANSFER::transfer_description::serialize(levin_kv::archive& ar) {
    ar.value("amount_in", amount_in);
    ar.value("amount_out", amount_out);
    ar.value("ring_size", ring_size);
    ar.value("unlock_time", unlock_time);
    ar.value("recipients", recipients);
    ar.value("payment_id", payment_id);
    ar.value("change_amount", change_amount);
    ar.value("change_address", change_address);
    ar.value("fee", fee);
    ar.value("dummy_outputs", dummy_outputs);
    ar.value("extra", extra);
}

void DESCRIBE_TRANSFER::request::serialize(levin_kv::archive& ar) {
    ar.value("unsigned_txset", unsigned_txset);
    ar.value("multisig_txset", multisig_txset);
}

void DESCRIBE_TRANSFER::response::serialize(levin_kv::archive& ar) {
    ar.value("desc", desc);
}

void SIGN_TRANSFER::request::serialize(levin_kv::archive& ar) {
    ar.value("unsigned_txset", unsigned_txset);
    ar.value_or("export_raw", export_raw, false);
    ar.value_or("get_tx_keys", get_tx_keys, false);
}

void SIGN_TRANSFER::response::serialize(levin_kv::archive& ar) {
    ar.value("signed_txset", signed_txset);
    ar.value("tx_hash_list", tx_hash_list);
    ar.value("tx_raw_list", tx_raw_list);
    ar.value("tx_key_list", tx_key_list);
}

void SUBMIT_TRANSFER::request::serialize(levin_kv::archive& ar) {
    ar.value("tx_data_hex", tx_data_hex);
}

void SUBMIT_TRANSFER::response::serialize(levin_kv::archive& ar) {
    ar.value("tx_hash_list", tx_hash_list);
}

void SWEEP_DUST::request::serialize(levin_kv::archive& ar) {
    ar.value("get_tx_keys", get_tx_keys);
    ar.value_or("do_not_relay", do_not_relay, false);
    ar.value_or("get_tx_hex", get_tx_hex, false);
    ar.value_or("get_tx_metadata", get_tx_metadata, false);
}

void SWEEP_DUST::key_list::serialize(levin_kv::archive& ar) {
    ar.value("keys", keys);
}

void SWEEP_DUST::response::serialize(levin_kv::archive& ar) {
    ar.value("tx_hash_list", tx_hash_list);
    ar.value("tx_key_list", tx_key_list);
    ar.value("amount_list", amount_list);
    ar.value("fee_list", fee_list);
    ar.value("tx_blob_list", tx_blob_list);
    ar.value("tx_metadata_list", tx_metadata_list);
    ar.value("multisig_txset", multisig_txset);
    ar.value("unsigned_txset", unsigned_txset);
}

void SWEEP_ALL::request::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
    ar.value("account_index", account_index);
    ar.value("subaddr_indices", subaddr_indices);
    ar.value_or("subaddr_indices_all", subaddr_indices_all, false);
    ar.value("priority", priority);
    ar.value_or("outputs", outputs, uint64_t{1});
    ar.value("unlock_time", unlock_time);
    ar.value("payment_id", payment_id);
    ar.value("get_tx_keys", get_tx_keys);
    ar.value("below_amount", below_amount);
    ar.value_or("do_not_relay", do_not_relay, false);
    ar.value_or("get_tx_hex", get_tx_hex, false);
    ar.value_or("get_tx_metadata", get_tx_metadata, false);
}

void SWEEP_ALL::key_list::serialize(levin_kv::archive& ar) {
    ar.value("keys", keys);
}

void SWEEP_ALL::response::serialize(levin_kv::archive& ar) {
    ar.value("tx_hash_list", tx_hash_list);
    ar.value("tx_key_list", tx_key_list);
    ar.value("amount_list", amount_list);
    ar.value("fee_list", fee_list);
    ar.value("tx_blob_list", tx_blob_list);
    ar.value("tx_metadata_list", tx_metadata_list);
    ar.value("multisig_txset", multisig_txset);
    ar.value("unsigned_txset", unsigned_txset);
}

void SWEEP_SINGLE::request::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
    ar.value("priority", priority);
    ar.value_or("outputs", outputs, uint64_t{1});
    ar.value("unlock_time", unlock_time);
    ar.value("payment_id", payment_id);
    ar.value("get_tx_key", get_tx_key);
    ar.value("key_image", key_image);
    ar.value_or("do_not_relay", do_not_relay, false);
    ar.value_or("get_tx_hex", get_tx_hex, false);
    ar.value_or("get_tx_metadata", get_tx_metadata, false);
}

void SWEEP_SINGLE::response::serialize(levin_kv::archive& ar) {
    ar.value("tx_hash", tx_hash);
    ar.value("tx_key", tx_key);
    ar.value("amount", amount);
    ar.value("fee", fee);
    ar.value("tx_blob", tx_blob);
    ar.value("tx_metadata", tx_metadata);
    ar.value("multisig_txset", multisig_txset);
    ar.value("unsigned_txset", unsigned_txset);
}

void RELAY_TX::request::serialize(levin_kv::archive& ar) {
    ar.value("hex", hex);
    ar.value_or("blink", blink, false);
}

void RELAY_TX::response::serialize(levin_kv::archive& ar) {
    ar.value("tx_hash", tx_hash);
}

void payment_details::serialize(levin_kv::archive& ar) {
    ar.value("payment_id", payment_id);
    ar.value("tx_hash", tx_hash);
    ar.value("amount", amount);
    ar.value("block_height", block_height);
    ar.value("unlock_time", unlock_time);
    ar.value("locked", locked);
    ar.value("subaddr_index", subaddr_index);
    ar.value("address", address);
}

void GET_PAYMENTS::request::serialize(levin_kv::archive& ar) {
    ar.value("payment_id", payment_id);
}

void GET_PAYMENTS::response::serialize(levin_kv::archive& ar) {
    ar.value("payments", payments);
}

void GET_BULK_PAYMENTS::request::serialize(levin_kv::archive& ar) {
    ar.value("payment_ids", payment_ids);
    ar.value("min_block_height", min_block_height);
}

void GET_BULK_PAYMENTS::response::serialize(levin_kv::archive& ar) {
    ar.value("payments", payments);
}

void transfer_details::serialize(levin_kv::archive& ar) {
    ar.value("amount", amount);
    ar.value("spent", spent);
    ar.value("global_index", global_index);
    ar.value("tx_hash", tx_hash);
    ar.value("subaddr_index", subaddr_index);
    ar.value("key_image", key_image);
    ar.value("block_height", block_height);
    ar.value("frozen", frozen);
    ar.value("unlocked", unlocked);
}

void INCOMING_TRANSFERS::request::serialize(levin_kv::archive& ar) {
    ar.value("transfer_type", transfer_type);
    ar.value("account_index", account_index);
    ar.value("subaddr_indices", subaddr_indices);
}

void INCOMING_TRANSFERS::response::serialize(levin_kv::archive& ar) {
    ar.value("transfers", transfers);
}

void QUERY_KEY::request::serialize(levin_kv::archive& ar) {
    ar.value("key_type", key_type);
}

void QUERY_KEY::response::serialize(levin_kv::archive& ar) {
    ar.value("key", key);
}

void MAKE_INTEGRATED_ADDRESS::request::serialize(levin_kv::archive& ar) {
    ar.value("standard_address", standard_address);
    ar.value("payment_id", payment_id);
}

void MAKE_INTEGRATED_ADDRESS::response::serialize(levin_kv::archive& ar) {
    ar.value("integrated_address", integrated_address);
    ar.value("payment_id", payment_id);
}

void SPLIT_INTEGRATED_ADDRESS::request::serialize(levin_kv::archive& ar) {
    ar.value("integrated_address", integrated_address);
}

void SPLIT_INTEGRATED_ADDRESS::response::serialize(levin_kv::archive& ar) {
    ar.value("standard_address", standard_address);
    ar.value("payment_id", payment_id);
    ar.value("is_subaddress", is_subaddress);
}

void RESCAN_BLOCKCHAIN::request::serialize(levin_kv::archive& ar) {
    ar.value_or("hard", hard, false);
}

void SET_TX_NOTES::request::serialize(levin_kv::archive& ar) {
    ar.value("txids", txids);
    ar.value("notes", notes);
}

void GET_TX_NOTES::request::serialize(levin_kv::archive& ar) {
    ar.value("txids", txids);
}

void GET_TX_NOTES::response::serialize(levin_kv::archive& ar) {
    ar.value("notes", notes);
}

void SET_ATTRIBUTE::request::serialize(levin_kv::archive& ar) {
    ar.value("key", key);
    ar.value("value", value);
}

void GET_ATTRIBUTE::request::serialize(levin_kv::archive& ar) {
    ar.value("key", key);
}

void GET_ATTRIBUTE::response::serialize(levin_kv::archive& ar) {
    ar.value("value", value);
}

void GET_TX_KEY::request::serialize(levin_kv::archive& ar) {
    ar.value("txid", txid);
}

void GET_TX_KEY::response::serialize(levin_kv::archive& ar) {
    ar.value("tx_key", tx_key);
}

void CHECK_TX_KEY::request::serialize(levin_kv::archive& ar) {
    ar.value("txid", txid);
    ar.value("tx_key", tx_key);
    ar.value("address", address);
}

void CHECK_TX_KEY::response::serialize(levin_kv::archive& ar) {
    ar.value("received", received);
    ar.value("in_pool", in_pool);
    ar.value("confirmations", confirmations);
}

void GET_TX_PROOF::request::serialize(levin_kv::archive& ar) {
    ar.value("txid", txid);
    ar.value("address", address);
    ar.value("message", message);
}

void GET_TX_PROOF::response::serialize(levin_kv::archive& ar) {
    ar.value("signature", signature);
}

void CHECK_TX_PROOF::request::serialize(levin_kv::archive& ar) {
    ar.value("txid", txid);
    ar.value("address", address);
    ar.value("message", message);
    ar.value("signature", signature);
}

void CHECK_TX_PROOF::response::serialize(levin_kv::archive& ar) {
    ar.value("good", good);
    ar.value("received", received);
    ar.value("in_pool", in_pool);
    ar.value("confirmations", confirmations);
}

void GET_SPEND_PROOF::request::serialize(levin_kv::archive& ar) {
    ar.value("txid", txid);
    ar.value("message", message);
}

void GET_SPEND_PROOF::response::serialize(levin_kv::archive& ar) {
    ar.value("signature", signature);
}

void CHECK_SPEND_PROOF::request::serialize(levin_kv::archive& ar) {
    ar.value("txid", txid);
    ar.value("message", message);
    ar.value("signature", signature);
}

void CHECK_SPEND_PROOF::response::serialize(levin_kv::archive& ar) {
    ar.value("good", good);
}

void GET_RESERVE_PROOF::request::serialize(levin_kv::archive& ar) {
    ar.value("all", all);
    ar.value("account_index", account_index);
    ar.value("amount", amount);
    ar.value("message", message);
}

void GET_RESERVE_PROOF::response::serialize(levin_kv::archive& ar) {
    ar.value("signature", signature);
}

void CHECK_RESERVE_PROOF::request::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
    ar.value("message", message);
    ar.value("signature", signature);
}

void CHECK_RESERVE_PROOF::response::serialize(levin_kv::archive& ar) {
    ar.value("good", good);
    ar.value("total", total);
    ar.value("spent", spent);
}

void GET_TRANSFERS::request::serialize(levin_kv::archive& ar) {
    ar.value_or("in", in, true);
    ar.value_or("out", out, true);
    ar.value_or("stake", stake, true);
    ar.value_or("pending", pending, true);
    ar.value_or("failed", failed, true);
    ar.value_or("pool", pool, true);
    ar.value_or("coinbase", coinbase, true);
    ar.value("filter_by_height", filter_by_height);
    ar.value("min_height", min_height);
    ar.value_or("max_height", max_height, cryptonote::MAX_BLOCK_NUMBER);
    ar.value("account_index", account_index);
    ar.value("subaddr_indices", subaddr_indices);
    ar.value_or("all_accounts", all_accounts, false);
}

void GET_TRANSFERS::response::serialize(levin_kv::archive& ar) {
    ar.value("in", in);
    ar.value("out", out);
    ar.value("pending", pending);
    ar.value("failed", failed);
    ar.value("pool", pool);
}

void GET_TRANSFERS_CSV::response::serialize(levin_kv::archive& ar) {
    ar.value("csv", csv);
}

void GET_TRANSFER_BY_TXID::request::serialize(levin_kv::archive& ar) {
    ar.value("txid", txid);
    ar.value_or("account_index", account_index, uint32_t{0});
}

void GET_TRANSFER_BY_TXID::response::serialize(levin_kv::archive& ar) {
    ar.value("transfer", transfer);
    ar.value("transfers", transfers);
}

void SIGN::request::serialize(levin_kv::archive& ar) {
    ar.value("data", data);
    ar.value_or("account_index", account_index, 0u);
    ar.value_or("address_index", address_index, 0u);
}

void SIGN::response::serialize(levin_kv::archive& ar) {
    ar.value("signature", signature);
}

void VERIFY::request::serialize(levin_kv::archive& ar) {
    ar.value("data", data);
    ar.value("address", address);
    ar.value("signature", signature);
}

void VERIFY::response::serialize(levin_kv::archive& ar) {
    ar.value("good", good);
}

void EXPORT_OUTPUTS::request::serialize(levin_kv::archive& ar) {
    ar.value("all", all);
}

void EXPORT_OUTPUTS::response::serialize(levin_kv::archive& ar) {
    ar.value("outputs_data_hex", outputs_data_hex);
}

void EXPORT_TRANSFERS::request::serialize(levin_kv::archive& ar) {
    ar.value("in", in);
    ar.value("out", out);
    ar.value("stake", stake);
    ar.value("pending", pending);
    ar.value("failed", failed);
    ar.value("pool", pool);
    ar.value("coinbase", coinbase);
    ar.value("filter_by_height", filter_by_height);
    ar.value("min_height", min_height);
    ar.value("max_height", max_height);
    ar.value("subaddr_indices", subaddr_indices);
    ar.value("account_index", account_index);
    ar.value("all_accounts", all_accounts);
}

void EXPORT_TRANSFERS::response::serialize(levin_kv::archive& ar) {
    ar.value("data", data);
}

void IMPORT_OUTPUTS::request::serialize(levin_kv::archive& ar) {
    ar.value("outputs_data_hex", outputs_data_hex);
}

void IMPORT_OUTPUTS::response::serialize(levin_kv::archive& ar) {
    ar.value("num_imported", num_imported);
}

void EXPORT_KEY_IMAGES::request::serialize(levin_kv::archive& ar) {
    ar.value_or("requested_only", requested_only, false);
}

void EXPORT_KEY_IMAGES::signed_key_image::serialize(levin_kv::archive& ar) {
    ar.value("key_image", key_image);
    ar.value("signature", signature);
}

void EXPORT_KEY_IMAGES::response::serialize(levin_kv::archive& ar) {
    ar.value("offset", offset);
    ar.value("signed_key_images", signed_key_images);
}

void IMPORT_KEY_IMAGES::signed_key_image::serialize(levin_kv::archive& ar) {
    ar.value("key_image", key_image);
    ar.value("signature", signature);
}

void IMPORT_KEY_IMAGES::request::serialize(levin_kv::archive& ar) {
    ar.value_or("offset", offset, uint32_t{0});
    ar.value("signed_key_images", signed_key_images);
}

void IMPORT_KEY_IMAGES::response::serialize(levin_kv::archive& ar) {
    ar.value("height", height);
    ar.value("spent", spent);
    ar.value("unspent", unspent);
}

void uri_spec::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
    ar.value("payment_id", payment_id);
    ar.value("amount", amount);
    ar.value("tx_description", tx_description);
    ar.value("recipient_name", recipient_name);
}

void MAKE_URI::response::serialize(levin_kv::archive& ar) {
    ar.value("uri", uri);
}

void PARSE_URI::request::serialize(levin_kv::archive& ar) {
    ar.value("uri", uri);
}

void PARSE_URI::response::serialize(levin_kv::archive& ar) {
    ar.value("uri", uri);
    ar.value("unknown_parameters", unknown_parameters);
}

void ADD_ADDRESS_BOOK_ENTRY::request::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
    ar.value("description", description);
}

void ADD_ADDRESS_BOOK_ENTRY::response::serialize(levin_kv::archive& ar) {
    ar.value("index", index);
}

void EDIT_ADDRESS_BOOK_ENTRY::request::serialize(levin_kv::archive& ar) {
    ar.value("index", index);
    ar.value("set_address", set_address);
    ar.value("address", address);
    ar.value("set_description", set_description);
    ar.value("description", description);
}

void GET_ADDRESS_BOOK_ENTRY::request::serialize(levin_kv::archive& ar) {
    ar.value("entries", entries);
}

void GET_ADDRESS_BOOK_ENTRY::entry::serialize(levin_kv::archive& ar) {
    ar.value("index", index);
    ar.value("address", address);
    ar.value("description", description);
}

void GET_ADDRESS_BOOK_ENTRY::response::serialize(levin_kv::archive& ar) {
    ar.value("entries", entries);
}

void DELETE_ADDRESS_BOOK_ENTRY::request::serialize(levin_kv::archive& ar) {
    ar.value("index", index);
}

void REFRESH::request::serialize(levin_kv::archive& ar) {
    ar.value_or("start_height", start_height, uint64_t{0});
}

void REFRESH::response::serialize(levin_kv::archive& ar) {
    ar.value("blocks_fetched", blocks_fetched);
    ar.value("received_money", received_money);
}

void AUTO_REFRESH::request::serialize(levin_kv::archive& ar) {
    ar.value_or("enable", enable, true);
    ar.value_or("period", period, uint32_t{0});
}

void START_MINING::request::serialize(levin_kv::archive& ar) {
    ar.value("threads_count", threads_count);
}

void GET_LANGUAGES::response::serialize(levin_kv::archive& ar) {
    ar.value("languages", languages);
    ar.value("languages_local", languages_local);
}

void CREATE_WALLET::request::serialize(levin_kv::archive& ar) {
    ar.value("filename", filename);
    ar.value("password", password);
    ar.value("language", language);
    ar.value("hardware_wallet", hardware_wallet);
    ar.value("device_name", device_name);
    ar.value("device_label", device_label);
}

void OPEN_WALLET::request::serialize(levin_kv::archive& ar) {
    ar.value("filename", filename);
    ar.value("password", password);
    ar.value_or("autosave_current", autosave_current, true);
}

void CLOSE_WALLET::request::serialize(levin_kv::archive& ar) {
    ar.value_or("autosave_current", autosave_current, true);
}

void CHANGE_WALLET_PASSWORD::request::serialize(levin_kv::archive& ar) {
    ar.value("old_password", old_password);
    ar.value("new_password", new_password);
}

void GENERATE_FROM_KEYS::request::serialize(levin_kv::archive& ar) {
    ar.value_or("restore_height", restore_height, uint64_t{0});
    ar.value("filename", filename);
    ar.value("address", address);
    ar.value("spendkey", spendkey);
    ar.value("viewkey", viewkey);
    ar.value("password", password);
    ar.value_or("autosave_current", autosave_current, true);
}

void GENERATE_FROM_KEYS::response::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
    ar.value("info", info);
}

void RESTORE_DETERMINISTIC_WALLET::request::serialize(levin_kv::archive& ar) {
    ar.value_or("restore_height", restore_height, uint64_t{0});
    ar.value("filename", filename);
    ar.value("seed", seed);
    ar.value("seed_offset", seed_offset);
    ar.value("password", password);
    ar.value("language", language);
    ar.value_or("autosave_current", autosave_current, true);
}

void RESTORE_DETERMINISTIC_WALLET::response::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
    ar.value("seed", seed);
    ar.value("info", info);
    ar.value("was_deprecated", was_deprecated);
}

void IS_MULTISIG::response::serialize(levin_kv::archive& ar) {
    ar.value("multisig", multisig);
    ar.value("ready", ready);
    ar.value("threshold", threshold);
    ar.value("total", total);
}

void PREPARE_MULTISIG::response::serialize(levin_kv::archive& ar) {
    ar.value("multisig_info", multisig_info);
}

void MAKE_MULTISIG::request::serialize(levin_kv::archive& ar) {
    ar.value("multisig_info", multisig_info);
    ar.value("threshold", threshold);
    ar.value("password", password);
}

void MAKE_MULTISIG::response::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
    ar.value("multisig_info", multisig_info);
}

void EXPORT_MULTISIG::response::serialize(levin_kv::archive& ar) {
    ar.value("info", info);
}

void IMPORT_MULTISIG::request::serialize(levin_kv::archive& ar) {
    ar.value("info", info);
}

void IMPORT_MULTISIG::response::serialize(levin_kv::archive& ar) {
    ar.value("n_outputs", n_outputs);
}

void FINALIZE_MULTISIG::request::serialize(levin_kv::archive& ar) {
    ar.value("password", password);
    ar.value("multisig_info", multisig_info);
}

void FINALIZE_MULTISIG::response::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
}

void EXCHANGE_MULTISIG_KEYS::request::serialize(levin_kv::archive& ar) {
    ar.value("password", password);
    ar.value("multisig_info", multisig_info);
}

void EXCHANGE_MULTISIG_KEYS::response::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
    ar.value("multisig_info", multisig_info);
}

void SIGN_MULTISIG::request::serialize(levin_kv::archive& ar) {
    ar.value("tx_data_hex", tx_data_hex);
}

void SIGN_MULTISIG::response::serialize(levin_kv::archive& ar) {
    ar.value("tx_data_hex", tx_data_hex);
    ar.value("tx_hash_list", tx_hash_list);
}

void SUBMIT_MULTISIG::request::serialize(levin_kv::archive& ar) {
    ar.value("tx_data_hex", tx_data_hex);
}

void SUBMIT_MULTISIG::response::serialize(levin_kv::archive& ar) {
    ar.value("tx_hash_list", tx_hash_list);
}

void GET_VERSION::response::serialize(levin_kv::archive& ar) {
    ar.value("version", version);
}

void STAKE::request::serialize(levin_kv::archive& ar) {
    ar.value("subaddr_indices", subaddr_indices);
    ar.value("destination", destination);
    ar.value("amount", amount);
    ar.value("service_node_key", service_node_key);
    ar.value_or("priority", priority, uint32_t{0});
    ar.value("get_tx_key", get_tx_key);
    ar.value_or("do_not_relay", do_not_relay, false);
    ar.value_or("get_tx_hex", get_tx_hex, false);
    ar.value_or("get_tx_metadata", get_tx_metadata, false);
}

void STAKE::response::serialize(levin_kv::archive& ar) {
    ar.value("tx_hash", tx_hash);
    ar.value("tx_key", tx_key);
    ar.value("amount", amount);
    ar.value("fee", fee);
    ar.value("tx_blob", tx_blob);
    ar.value("tx_metadata", tx_metadata);
    ar.value("multisig_txset", multisig_txset);
    ar.value("unsigned_txset", unsigned_txset);
}

void REGISTER_SERVICE_NODE::request::serialize(levin_kv::archive& ar) {
    ar.value("register_service_node_str", register_service_node_str);
    ar.value("get_tx_key", get_tx_key);
    ar.value_or("do_not_relay", do_not_relay, false);
    ar.value_or("get_tx_hex", get_tx_hex, false);
    ar.value_or("get_tx_metadata", get_tx_metadata, false);
}

void REGISTER_SERVICE_NODE::response::serialize(levin_kv::archive& ar) {
    ar.value("tx_hash", tx_hash);
    ar.value("tx_key", tx_key);
    ar.value("amount", amount);
    ar.value("fee", fee);
    ar.value("tx_blob", tx_blob);
    ar.value("tx_metadata", tx_metadata);
    ar.value("multisig_txset", multisig_txset);
    ar.value("unsigned_txset", unsigned_txset);
}

void REQUEST_STAKE_UNLOCK::request::serialize(levin_kv::archive& ar) {
    ar.value("service_node_key", service_node_key);
}

void REQUEST_STAKE_UNLOCK::response::serialize(levin_kv::archive& ar) {
    ar.value("unlocked", unlocked);
    ar.value("msg", msg);
}

void CAN_REQUEST_STAKE_UNLOCK::request::serialize(levin_kv::archive& ar) {
    ar.value("service_node_key", service_node_key);
}

void CAN_REQUEST_STAKE_UNLOCK::response::serialize(levin_kv::archive& ar) {
    ar.value("can_unlock", can_unlock);
    ar.value("msg", msg);
}

void VALIDATE_ADDRESS::request::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
    ar.value_or("any_net_type", any_net_type, false);
    ar.value_or("allow_openalias", allow_openalias, false);
}

void VALIDATE_ADDRESS::response::serialize(levin_kv::archive& ar) {
    ar.value("valid", valid);
    ar.value("integrated", integrated);
    ar.value("subaddress", subaddress);
    ar.value("nettype", nettype);
    ar.value("openalias_address", openalias_address);
}

void SET_DAEMON::request::serialize(levin_kv::archive& ar) {
    ar.value("address", address);
    ar.value("proxy", proxy);
    ar.value_or("trusted", trusted, false);
    ar.value("ssl_private_key_path", ssl_private_key_path);
    ar.value("ssl_certificate_path", ssl_certificate_path);
    ar.value("ssl_ca_file", ssl_ca_file);
    ar.value_or("ssl_allow_any_cert", ssl_allow_any_cert, false);
}

void SET_LOG_LEVEL::request::serialize(levin_kv::archive& ar) {
    ar.value("level", level);
}

void SET_LOG_CATEGORIES::request::serialize(levin_kv::archive& ar) {
    ar.value("categories", categories);
}

void SET_LOG_CATEGORIES::response::serialize(levin_kv::archive& ar) {
    ar.value("categories", categories);
}

void ONS_BUY_MAPPING::request::serialize(levin_kv::archive& ar) {
    ar.value("type", type);
    ar.value("owner", owner);
    ar.value("backup_owner", backup_owner);
    ar.value("name", name);
    ar.value("value", value);
    ar.value_or("account_index", account_index, uint32_t{0});
    ar.value("subaddr_indices", subaddr_indices);
    ar.value_or("priority", priority, uint32_t{0});
    ar.value("get_tx_key", get_tx_key);
    ar.value_or("do_not_relay", do_not_relay, false);
    ar.value_or("get_tx_hex", get_tx_hex, false);
    ar.value_or("get_tx_metadata", get_tx_metadata, false);
}

void ONS_BUY_MAPPING::response::serialize(levin_kv::archive& ar) {
    ar.value("tx_hash", tx_hash);
    ar.value("tx_key", tx_key);
    ar.value("amount", amount);
    ar.value("fee", fee);
    ar.value("tx_blob", tx_blob);
    ar.value("tx_metadata", tx_metadata);
    ar.value("multisig_txset", multisig_txset);
    ar.value("unsigned_txset", unsigned_txset);
}

void ONS_RENEW_MAPPING::request::serialize(levin_kv::archive& ar) {
    ar.value("type", type);
    ar.value("name", name);
    ar.value_or("account_index", account_index, uint32_t{0});
    ar.value("subaddr_indices", subaddr_indices);
    ar.value_or("priority", priority, uint32_t{0});
    ar.value("get_tx_key", get_tx_key);
    ar.value_or("do_not_relay", do_not_relay, false);
    ar.value_or("get_tx_hex", get_tx_hex, false);
    ar.value_or("get_tx_metadata", get_tx_metadata, false);
}

void ONS_UPDATE_MAPPING::request::serialize(levin_kv::archive& ar) {
    ar.value("type", type);
    ar.value("name", name);
    ar.value("value", value);
    ar.value("owner", owner);
    ar.value("backup_owner", backup_owner);
    ar.value("signature", signature);
    ar.value_or("account_index", account_index, uint32_t{0});
    ar.value("subaddr_indices", subaddr_indices);
    ar.value_or("priority", priority, uint32_t{0});
    ar.value("get_tx_key", get_tx_key);
    ar.value_or("do_not_relay", do_not_relay, false);
    ar.value_or("get_tx_hex", get_tx_hex, false);
    ar.value_or("get_tx_metadata", get_tx_metadata, false);
}

void ONS_UPDATE_MAPPING::response::serialize(levin_kv::archive& ar) {
    ar.value("tx_hash", tx_hash);
    ar.value("tx_key", tx_key);
    ar.value("amount", amount);
    ar.value("fee", fee);
    ar.value("tx_blob", tx_blob);
    ar.value("tx_metadata", tx_metadata);
    ar.value("multisig_txset", multisig_txset);
    ar.value("unsigned_txset", unsigned_txset);
}

void ONS_MAKE_UPDATE_SIGNATURE::request::serialize(levin_kv::archive& ar) {
    ar.value("type", type);
    ar.value("name", name);
    ar.value("encrypted_value", encrypted_value);
    ar.value("owner", owner);
    ar.value("backup_owner", backup_owner);
}

void ONS_MAKE_UPDATE_SIGNATURE::response::serialize(levin_kv::archive& ar) {
    ar.value("signature", signature);
}

void ONS_HASH_NAME::request::serialize(levin_kv::archive& ar) {
    ar.value("type", type);
    ar.value("name", name);
}

void ONS_HASH_NAME::response::serialize(levin_kv::archive& ar) {
    ar.value("name", name);
}

void ONS_KNOWN_NAMES::request::serialize(levin_kv::archive& ar) {
    ar.value("decrypt", decrypt);
    ar.value("include_expired", include_expired);
}

void ONS_KNOWN_NAMES::known_record::serialize(levin_kv::archive& ar) {
    ar.value("type", type);
    ar.value("hashed", hashed);
    ar.value("name", name);
    ar.value("owner", owner);
    ar.value("backup_owner", backup_owner);
    ar.value("encrypted_value", encrypted_value);
    ar.value("value", value);
    ar.value("update_height", update_height);
    ar.value("expiration_height", expiration_height);
    ar.value("expired", expired);
    ar.value("txid", txid);
}

void ONS_KNOWN_NAMES::response::serialize(levin_kv::archive& ar) {
    ar.value("known_names", known_names);
}

void ONS_ADD_KNOWN_NAMES::request::serialize(levin_kv::archive& ar) {
    ar.value("names", names);
}

void ONS_ADD_KNOWN_NAMES::record::serialize(levin_kv::archive& ar) {
    ar.value("type", type);
    ar.value("name", name);
}

void ONS_DECRYPT_VALUE::request::serialize(levin_kv::archive& ar) {
    ar.value("name", name);
    ar.value("type", type);
    ar.value("encrypted_value", encrypted_value);
}

void ONS_DECRYPT_VALUE::response::serialize(levin_kv::archive& ar) {
    ar.value("value", value);
}

void ONS_ENCRYPT_VALUE::request::serialize(levin_kv::archive& ar) {
    ar.value("name", name);
    ar.value("type", type);
    ar.value("value", value);
}

void ONS_ENCRYPT_VALUE::response::serialize(levin_kv::archive& ar) {
    ar.value("encrypted_value", encrypted_value);
}

}  // namespace tools::wallet_rpc
