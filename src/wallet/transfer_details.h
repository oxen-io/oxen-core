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

#pragma once

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/subaddress_index.h"
#include "multisig_info.h"

namespace wallet {

struct transfer_details
{
  uint64_t m_block_height;
  cryptonote::transaction_prefix m_tx;
  crypto::hash m_txid;
  size_t m_internal_output_index;
  uint64_t m_global_output_index;
  bool m_spent;
  bool m_frozen;
  bool m_unmined_blink;
  bool m_was_blink;
  uint64_t m_spent_height;
  crypto::key_image m_key_image; //TODO: key_image stored twice :(
  rct::key m_mask;
  uint64_t m_amount;
  bool m_rct;
  bool m_key_image_known;
  bool m_key_image_request; // view wallets: we want to request it; cold wallets: it was requested
  size_t m_pk_index;
  cryptonote::subaddress_index m_subaddr_index;
  bool m_key_image_partial;
  std::vector<rct::key> m_multisig_k;
  std::vector<multisig_info> m_multisig_info; // one per other participant
  std::vector<std::pair<uint64_t, crypto::hash>> m_uses;

  bool is_rct() const { return m_rct; }
  uint64_t amount() const { return m_amount; }
  const crypto::public_key &get_public_key() const {
    return std::get<cryptonote::txout_to_key>(m_tx.vout[m_internal_output_index].target).key;
  }
};


template <class Archive>
void serialize_value(Archive& ar, transfer_details& x) {
  field(ar, "m_block_height", x.m_block_height);
  field(ar, "m_tx", x.m_tx);
  field(ar, "m_txid", x.m_txid);
  field(ar, "m_internal_output_index", x.m_internal_output_index);
  field(ar, "m_global_output_index", x.m_global_output_index);
  field(ar, "m_spent", x.m_spent);
  field(ar, "m_frozen", x.m_frozen);
  field(ar, "m_unmined_blink", x.m_unmined_blink);
  field(ar, "m_was_blink", x.m_was_blink);
  field(ar, "m_spent_height", x.m_spent_height);
  field(ar, "m_key_image", x.m_key_image);
  field(ar, "m_mask", x.m_mask);
  field(ar, "m_amount", x.m_amount);
  field(ar, "m_rct", x.m_rct);
  field(ar, "m_key_image_known", x.m_key_image_known);
  field(ar, "m_key_image_request", x.m_key_image_request);
  field(ar, "m_pk_index", x.m_pk_index);
  field(ar, "m_subaddr_index", x.m_subaddr_index);
  field(ar, "m_key_image_partial", x.m_key_image_partial);
  field(ar, "m_multisig_k", x.m_multisig_k);
  field(ar, "m_multisig_info", x.m_multisig_info);
  field(ar, "m_uses", x.m_uses);
}

}

BOOST_CLASS_VERSION(wallet::transfer_details, 14)

namespace boost::serialization {

template <class Archive>
void serialize(Archive &a, wallet::transfer_details &x, const unsigned int ver)
{
  a & x.m_block_height;
  a & x.m_global_output_index;
  a & x.m_internal_output_index;
  a & x.m_tx;
  a & x.m_spent;
  a & x.m_key_image;
  a & x.m_mask;
  a & x.m_amount;
  a & x.m_spent_height;
  a & x.m_txid;
  a & x.m_rct;
  a & x.m_key_image_known;
  a & x.m_pk_index;
  a & x.m_subaddr_index;
  a & x.m_multisig_info;
  a & x.m_multisig_k;
  a & x.m_key_image_partial;
  if (ver > 9)
    a & x.m_key_image_request;
  if (ver > 10)
    a & x.m_uses;
  if (ver > 11)
    a & x.m_frozen;
  if (ver > 12)
    a & x.m_unmined_blink;
  if (ver > 13)
    a & x.m_was_blink;

  if constexpr (typename Archive::is_loading())
  {
    if (ver < 10)
      x.m_key_image_request = false;
    if (ver < 12)
      x.m_frozen = false;
    if (ver < 13)
      x.m_unmined_blink = false;
    if (ver < 14)
      x.m_was_blink = false;
  }
}

}
