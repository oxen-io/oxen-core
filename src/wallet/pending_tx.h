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
#include <cryptonote_core/cryptonote_tx_utils.h>
#include "tx_construction_data.h"
#include "multisig_sig.h"

namespace wallet {

// The convention for destinations is:
// dests does not include change
// splitted_dsts (in construction_data) does
struct pending_tx
{
  cryptonote::transaction tx;
  uint64_t dust, fee;
  bool dust_added_to_fee;
  cryptonote::tx_destination_entry change_dts;
  std::vector<size_t> selected_transfers;
  std::string key_images;
  crypto::secret_key tx_key;
  std::vector<crypto::secret_key> additional_tx_keys;
  std::vector<cryptonote::tx_destination_entry> dests;
  std::vector<multisig_sig> multisig_sigs;

  wallet::tx_construction_data construction_data;
};

template <class Archive>
void serialize_value(Archive& ar, pending_tx& x) {
  field(ar, "tx", x.tx);
  field(ar, "dust", x.dust);
  field(ar, "fee", x.fee);
  field(ar, "dust_added_to_fee", x.dust_added_to_fee);
  field(ar, "change_dts", x.change_dts);
  field(ar, "selected_transfers", x.selected_transfers);
  field(ar, "key_images", x.key_images);
  field(ar, "tx_key", x.tx_key);
  field(ar, "additional_tx_keys", x.additional_tx_keys);
  field(ar, "dests", x.dests);
  field(ar, "construction_data", x.construction_data);
  field(ar, "multisig_sigs", x.multisig_sigs);
};

}

BOOST_CLASS_VERSION(wallet::pending_tx, 3)

namespace boost::serialization {

template <class Archive>
void serialize(Archive &a, wallet::pending_tx &x, const unsigned int ver)
{
  a & x.tx;
  a & x.dust;
  a & x.fee;
  a & x.dust_added_to_fee;
  a & x.change_dts;
  if (ver < 2)
  {
    // load list to vector
    std::list<size_t> selected_transfers;
    a & selected_transfers;
    x.selected_transfers.clear();
    x.selected_transfers.reserve(selected_transfers.size());
    for (size_t t: selected_transfers)
      x.selected_transfers.push_back(t);
  }
  a & x.key_images;
  a & x.tx_key;
  a & x.dests;
  a & x.construction_data;
  if (ver < 1)
    return;
  a & x.additional_tx_keys;
  if (ver < 2)
    return;
  a & x.selected_transfers;
  if (ver < 3)
    return;
  a & x.multisig_sigs;
}

}
