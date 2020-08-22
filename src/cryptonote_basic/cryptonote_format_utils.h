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

#pragma once
#include "blobdatatype.h"
#include "cryptonote_basic_impl.h"
#include "tx_extra.h"
#include "account.h"
#include "subaddress_index.h"
#include "include_base_utils.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "common/meta.h"
#include "common/string_util.h"
#include "serialization/binary_utils.h"
#include <unordered_map>

namespace epee
{
  class wipeable_string;
}

namespace service_nodes { struct quorum_vote_t; }

namespace cryptonote
{
  using namespace std::literals;

  struct tx_verification_context;
  struct vote_verification_context;
  //---------------------------------------------------------------
  void get_transaction_prefix_hash(const transaction_prefix& tx, crypto::hash& h, hw::device &hwdev);
  crypto::hash get_transaction_prefix_hash(const transaction_prefix& tx, hw::device &hwdev);
  void get_transaction_prefix_hash(const transaction_prefix& tx, crypto::hash& h);
  crypto::hash get_transaction_prefix_hash(const transaction_prefix& tx);
  bool parse_and_validate_tx_prefix_from_blob(const std::string_view tx_blob, transaction_prefix& tx);
  bool parse_and_validate_tx_from_blob(const std::string_view tx_blob, transaction& tx, crypto::hash& tx_hash, crypto::hash& tx_prefix_hash);
  bool parse_and_validate_tx_from_blob(const std::string_view tx_blob, transaction& tx, crypto::hash& tx_hash);
  bool parse_and_validate_tx_from_blob(const std::string_view tx_blob, transaction& tx);
  bool parse_and_validate_tx_base_from_blob(const std::string_view tx_blob, transaction& tx);
  bool is_v1_tx(const std::string_view tx_blob);

  // skip_fields: How many fields of type <T> to skip
  template<typename T>
  bool find_tx_extra_field_by_type(const std::vector<tx_extra_field>& tx_extra_fields, T& field, size_t skip_fields = 0)
  {
    if (skip_fields >= tx_extra_fields.size())
      return false;

    for (const auto& f : tx_extra_fields)
    {
      if (!std::holds_alternative<T>(f)) continue;
      if (skip_fields == 0)
      {
        field = std::get<T>(f);
        return true;
      }
      skip_fields--;
    }

    return false;
  }

  // Adds data with a given tag to the given tx_extra vector.  Generally not called directly,
  // instead use one of the `add_tx_extra` overloads.
  void add_tagged_data_to_tx_extra(std::vector<uint8_t>& tx_extra, uint8_t tag, std::string_view data);

  // Adds some data to tx_extra with a tag looked up according to the given template parameter S.  T
  // does not have to be the same as S, but it must have the same size and must be a basic layout,
  // no-padding type.  Intended for use with simple tx extra decorator types, for example:
  //
  //     add_tx_extra<tx_extra_pub_key>(tx.extra, pubkey);
  //
  template <typename S, typename T>
  void add_tx_extra(std::vector<uint8_t>& tx_extra, const T& val)
  {
    static_assert(sizeof(S) == sizeof(T));
    (void) tools::template_index<S, tx_extra_field>;

    add_tagged_data_to_tx_extra(tx_extra, serialization::variant_serialization_tag<S, uint8_t>, tools::view_guts(val));
  }

  // Wrapper around the above that takes the transaction rather than the extra vector, and forwards
  // to one of the above.
  template <typename S, typename T>
  void add_tx_extra(transaction_prefix& tx, const T& val)
  {
    add_tx_extra<S>(tx.extra, val);
  }

  bool parse_tx_extra(const std::vector<uint8_t>& tx_extra, std::vector<tx_extra_field>& tx_extra_fields);
  bool sort_tx_extra(const std::vector<uint8_t>& tx_extra, std::vector<uint8_t>& sorted_tx_extra);

  template <typename T>
  bool get_field_from_tx_extra(const std::vector<uint8_t>& tx_extra, T& field, size_t skip = 0)
  {
    std::vector<tx_extra_field> tx_extra_fields;
    return
      parse_tx_extra(tx_extra, tx_extra_fields) &&
      find_tx_extra_field_by_type(tx_extra_fields, field, skip);
  }

  crypto::public_key get_tx_pub_key_from_extra(const std::vector<uint8_t>& tx_extra, size_t pk_index = 0);
  crypto::public_key get_tx_pub_key_from_extra(const transaction_prefix& tx, size_t pk_index = 0);

  bool add_service_node_state_change_to_tx_extra(std::vector<uint8_t>& tx_extra, const tx_extra_service_node_state_change& state_change, uint8_t hf_version);
  bool get_service_node_state_change_from_tx_extra(const std::vector<uint8_t>& tx_extra, tx_extra_service_node_state_change& state_change, uint8_t hf_version);

  bool get_service_node_pubkey_from_tx_extra(const std::vector<uint8_t>& tx_extra, crypto::public_key& pubkey);
  bool get_service_node_contributor_from_tx_extra(const std::vector<uint8_t>& tx_extra, cryptonote::account_public_address& address);
  bool add_service_node_register_to_tx_extra(std::vector<uint8_t>& tx_extra, const std::vector<cryptonote::account_public_address>& addresses, uint64_t portions_for_operator, const std::vector<uint64_t>& portions, uint64_t expiration_timestamp, const crypto::signature& signature);

  bool get_tx_secret_key_from_tx_extra(const std::vector<uint8_t>& tx_extra, crypto::secret_key& key);
  void add_tx_secret_key_to_tx_extra(std::vector<uint8_t>& tx_extra, const crypto::secret_key& key);
  bool add_tx_key_image_proofs_to_tx_extra  (std::vector<uint8_t>& tx_extra, const tx_extra_tx_key_image_proofs& proofs);
  bool add_tx_key_image_unlock_to_tx_extra(std::vector<uint8_t>& tx_extra, const tx_extra_tx_key_image_unlock& unlock);

  void add_service_node_winner_to_tx_extra(std::vector<uint8_t>& tx_extra, const crypto::public_key& winner);
  void add_service_node_pubkey_to_tx_extra(std::vector<uint8_t>& tx_extra, const crypto::public_key& pubkey);
  void add_service_node_contributor_to_tx_extra(std::vector<uint8_t>& tx_extra, const cryptonote::account_public_address& address);
  crypto::public_key get_service_node_winner_from_tx_extra(const std::vector<uint8_t>& tx_extra);

  void add_loki_name_system_to_tx_extra(std::vector<uint8_t> &tx_extra, tx_extra_loki_name_system const &entry);

  std::vector<crypto::public_key> get_additional_tx_pub_keys_from_extra(const std::vector<uint8_t>& tx_extra);
  std::vector<crypto::public_key> get_additional_tx_pub_keys_from_extra(const transaction_prefix& tx);
  bool add_additional_tx_pub_keys_to_extra(std::vector<uint8_t>& tx_extra, const std::vector<crypto::public_key>& additional_pub_keys);
  bool add_extra_nonce_to_tx_extra(std::vector<uint8_t>& tx_extra, const blobdata& extra_nonce);
  bool remove_field_from_tx_extra(std::vector<uint8_t>& tx_extra, size_t variant_index);
  template <typename T>
  bool remove_field_from_tx_extra(std::vector<uint8_t>& tx_extra) {
    return remove_field_from_tx_extra(tx_extra, tools::template_index<T, tx_extra_field>);
  }
  void set_payment_id_to_tx_extra_nonce(blobdata& extra_nonce, const crypto::hash& payment_id);
  void set_encrypted_payment_id_to_tx_extra_nonce(blobdata& extra_nonce, const crypto::hash8& payment_id);
  bool get_payment_id_from_tx_extra_nonce(const blobdata& extra_nonce, crypto::hash& payment_id);
  bool get_encrypted_payment_id_from_tx_extra_nonce(const blobdata& extra_nonce, crypto::hash8& payment_id);
  bool add_burned_amount_to_tx_extra(std::vector<uint8_t>& tx_extra, uint64_t burn);
  uint64_t get_burned_amount_from_tx_extra(const std::vector<uint8_t>& tx_extra);
  bool is_out_to_acc(const account_keys& acc, const txout_to_key& out_key, const crypto::public_key& tx_pub_key, const std::vector<crypto::public_key>& additional_tx_public_keys, size_t output_index);
  struct subaddress_receive_info
  {
    subaddress_index index;
    crypto::key_derivation derivation;
  };
  std::optional<subaddress_receive_info> is_out_to_acc_precomp(const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, const crypto::public_key& out_key, const crypto::key_derivation& derivation, const std::vector<crypto::key_derivation>& additional_derivations, size_t output_index, hw::device &hwdev);
  bool lookup_acc_outs(const account_keys& acc, const transaction& tx, const crypto::public_key& tx_pub_key, const std::vector<crypto::public_key>& additional_tx_public_keys, std::vector<size_t>& outs, uint64_t& money_transfered);
  bool lookup_acc_outs(const account_keys& acc, const transaction& tx, std::vector<size_t>& outs, uint64_t& money_transfered);
  bool get_tx_miner_fee(const transaction& tx, uint64_t & fee, bool burning_enabled, uint64_t *burned = nullptr);
  uint64_t get_tx_miner_fee(const transaction& tx, bool burning_enabled);
  bool generate_key_image_helper(const account_keys& ack, const std::unordered_map<crypto::public_key, subaddress_index>& subaddresses, const crypto::public_key& out_key, const crypto::public_key& tx_public_key, const std::vector<crypto::public_key>& additional_tx_public_keys, size_t real_output_index, keypair& in_ephemeral, crypto::key_image& ki, hw::device &hwdev);
  bool generate_key_image_helper_precomp(const account_keys& ack, const crypto::public_key& out_key, const crypto::key_derivation& recv_derivation, size_t real_output_index, const subaddress_index& received_index, keypair& in_ephemeral, crypto::key_image& ki, hw::device &hwdev);
  void get_blob_hash(const std::string_view blob, crypto::hash& res);
  crypto::hash get_blob_hash(const std::string_view blob);
  std::string short_hash_str(const crypto::hash& h);

  bool get_registration_hash(const std::vector<cryptonote::account_public_address>& addresses, uint64_t operator_portions, const std::vector<uint64_t>& portions, uint64_t expiration_timestamp, crypto::hash& hash);

  crypto::hash get_transaction_hash(const transaction& t);
  bool get_transaction_hash(const transaction& t, crypto::hash& res);
  bool get_transaction_hash(const transaction& t, crypto::hash& res, size_t& blob_size);
  bool get_transaction_hash(const transaction& t, crypto::hash& res, size_t* blob_size);
  bool calculate_transaction_prunable_hash(const transaction& t, const cryptonote::blobdata *blob, crypto::hash& res);
  crypto::hash get_transaction_prunable_hash(const transaction& t, const cryptonote::blobdata *blob = NULL);
  bool calculate_transaction_hash(const transaction& t, crypto::hash& res, size_t* blob_size);
  crypto::hash get_pruned_transaction_hash(const transaction& t, const crypto::hash &pruned_data_hash);

  blobdata get_block_hashing_blob(const block& b);
  bool calculate_block_hash(const block& b, crypto::hash& res);
  bool get_block_hash(const block& b, crypto::hash& res);
  crypto::hash get_block_hash(const block& b);
  bool parse_and_validate_block_from_blob(const std::string_view b_blob, block& b, crypto::hash *block_hash);
  bool parse_and_validate_block_from_blob(const std::string_view b_blob, block& b);
  bool parse_and_validate_block_from_blob(const std::string_view b_blob, block& b, crypto::hash &block_hash);
  bool get_inputs_money_amount(const transaction& tx, uint64_t& money);
  uint64_t get_outs_money_amount(const transaction& tx);
  bool check_inputs_types_supported(const transaction& tx);
  bool check_outs_valid(const transaction& tx);
  bool parse_amount(uint64_t& amount, std::string_view str_amount);
  uint64_t get_transaction_weight(const transaction &tx);
  uint64_t get_transaction_weight(const transaction &tx, size_t blob_size);
  uint64_t get_pruned_transaction_weight(const transaction &tx);

  bool check_money_overflow(const transaction& tx);
  bool check_outs_overflow(const transaction& tx);
  bool check_inputs_overflow(const transaction& tx);
  uint64_t get_block_height(const block& b);
  std::vector<uint64_t> relative_output_offsets_to_absolute(const std::vector<uint64_t>& off);
  std::vector<uint64_t> absolute_output_offsets_to_relative(const std::vector<uint64_t>& off);
  void set_default_decimal_point(unsigned int decimal_point = CRYPTONOTE_DISPLAY_DECIMAL_POINT);
  unsigned int get_default_decimal_point();
  std::string get_unit(unsigned int decimal_point = -1);
  std::string print_money(uint64_t amount, unsigned int decimal_point = -1);

  std::string print_tx_verification_context  (tx_verification_context const &tvc, transaction const *tx = nullptr);
  std::string print_vote_verification_context(vote_verification_context const &vvc, service_nodes::quorum_vote_t const *vote = nullptr);

  inline std::ostream &operator<<(std::ostream &stream, transaction const &tx)
  {
    stream << "tx={version=" << tx.version << ", type=" << tx.type << ", hash=" << get_transaction_hash(tx) << "}";
    return stream;
  }

  //---------------------------------------------------------------
  template <typename T>
  bool t_serializable_object_from_blob(T& to, const blobdata& blob)
  {
    try {
      serialization::parse_binary(blob, to);
      return true;
    } catch (...) {
      return false;
    }
  }
  //---------------------------------------------------------------
  template <typename T>
  bool t_serializable_object_to_blob(T& val, blobdata& blob)
  {
    try {
      blob = serialization::dump_binary(const_cast<std::remove_const_t<T>&>(val));
      return true;
    } catch (const std::exception& e) {
      LOG_ERROR("Serialization of " << tools::type_name(typeid(T)) << " failed: " << e.what());
      return false;
    }
  }
  //---------------------------------------------------------------
  template <typename T>
  blobdata t_serializable_object_to_blob(const T& val)
  {
    blobdata b;
    t_serializable_object_to_blob(val, b);
    return b;
  }
  //---------------------------------------------------------------
  template <typename T>
  bool get_object_hash(const T& o, crypto::hash& res)
  {
    get_blob_hash(t_serializable_object_to_blob(o), res);
    return true;
  }
  //---------------------------------------------------------------
  template <typename T>
  size_t get_object_blobsize(const T& o)
  {
    return t_serializable_object_to_blob(o).size();
  }
  //---------------------------------------------------------------
  template <typename T>
  bool get_object_hash(const T& o, crypto::hash& res, size_t& blob_size)
  {
    blobdata bl;
    if (!t_serializable_object_to_blob(o, bl))
      return false;
    blob_size = bl.size();
    get_blob_hash(bl, res);
    return true;
  }
  //---------------------------------------------------------------
  template <typename T>
  std::string obj_to_json_str(T&& obj, bool indent = false)
  {
    std::ostringstream ss;
    serialization::json_archiver ar{ss, indent};
    try {
      serialize(ar, obj);
    } catch (const std::exception& e) {
      LOG_ERROR("obj_to_json_str failed: serialization failed: " << e.what());
      return ""s;
    }
    return ss.str();
  }
  //---------------------------------------------------------------
  blobdata block_to_blob(const block& b);
  bool block_to_blob(const block& b, blobdata& b_blob);
  blobdata tx_to_blob(const transaction& b);
  bool tx_to_blob(const transaction& b, blobdata& b_blob);
  void get_tx_tree_hash(const std::vector<crypto::hash>& tx_hashes, crypto::hash& h);
  crypto::hash get_tx_tree_hash(const std::vector<crypto::hash>& tx_hashes);
  crypto::hash get_tx_tree_hash(const block& b);
  void get_hash_stats(uint64_t &tx_hashes_calculated, uint64_t &tx_hashes_cached, uint64_t &block_hashes_calculated, uint64_t & block_hashes_cached);

  crypto::secret_key encrypt_key(crypto::secret_key key, const epee::wipeable_string &passphrase);
  crypto::secret_key decrypt_key(crypto::secret_key key, const epee::wipeable_string &passphrase);
#define CHECKED_GET_SPECIFIC_VARIANT(variant_var, specific_type, variable_name, fail_return_val) \
  CHECK_AND_ASSERT_MES(std::holds_alternative<specific_type>(variant_var), fail_return_val, \
          "wrong variant type: " << tools::type_name(tools::variant_type(variant_var)) << ", expected " << tools::type_name<specific_type>()); \
  auto& variable_name = std::get<specific_type>(variant_var);

  // Provide an inline header implementation of this function because device_default needs it (but
  // it doesn't link to us, rather we link to it).
  inline void get_transaction_prefix_hash(const transaction_prefix& tx, crypto::hash& h)
  {
    std::string str = serialization::dump_binary(const_cast<transaction_prefix&>(tx));
    crypto::cn_fast_hash(str.data(), str.size(), h);
  }

}
