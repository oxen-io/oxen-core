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

#pragma once
#include "cryptonote_core/cryptonote_tx_utils.h"

namespace wallet {

struct tx_construction_data
{
  std::vector<cryptonote::tx_source_entry> sources;
  cryptonote::tx_destination_entry change_dts;
  std::vector<cryptonote::tx_destination_entry> splitted_dsts; // split, includes change
  std::vector<size_t> selected_transfers;
  std::vector<uint8_t> extra;
  uint64_t unlock_time;
  rct::RCTConfig rct_config;
  std::vector<cryptonote::tx_destination_entry> dests; // original setup, does not include change
  uint32_t subaddr_account;   // subaddress account of your wallet to be used in this transfer
  std::set<uint32_t> subaddr_indices;  // set of address indices used as inputs in this transfer

  uint8_t            hf_version;
  cryptonote::txtype tx_type;
};

template <class Archive>
void serialize_value(Archive& ar, tx_construction_data& x) {
  field(ar, "sources", x.sources);
  field(ar, "change_dts", x.change_dts);
  field(ar, "splitted_dsts", x.splitted_dsts);
  field(ar, "selected_transfers", x.selected_transfers);
  field(ar, "extra", x.extra);
  field(ar, "unlock_time", x.unlock_time);
  field(ar, "rct_config", x.rct_config);
  field(ar, "dests", x.dests);
  field(ar, "subaddr_account", x.subaddr_account);
  field(ar, "subaddr_indices", x.subaddr_indices);

  field(ar, "hf_version", x.hf_version);
  field_varint(ar, "tx_type", x.tx_type, [](auto& t) { return t < cryptonote::txtype::_count; });
}

}

BOOST_CLASS_VERSION(wallet::tx_construction_data, 6)

namespace boost::serialization {

template <class Archive>
void serialize(Archive &a, wallet::tx_construction_data &x, const unsigned int ver)
{
  a & x.sources;
  a & x.change_dts;
  a & x.splitted_dsts;
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
  a & x.extra;
  a & x.unlock_time;
  a & x.dests;
  if (ver < 1)
  {
    x.subaddr_account = 0;
    return;
  }
  a & x.subaddr_account;
  a & x.subaddr_indices;
  if (!typename Archive::is_saving())
  {
    x.rct_config = { rct::RangeProofBorromean, 0 };
    if (ver < 6)
    {
      x.tx_type    = cryptonote::txtype::standard;
      x.hf_version = cryptonote::network_version_13_enforce_checkpoints;
    }
  }

  if (ver < 2)
    return;
  a & x.selected_transfers;
  if (ver < 3)
    return;
  if (ver < 5)
  {
    bool use_bulletproofs = x.rct_config.range_proof_type != rct::RangeProofBorromean;
    a & use_bulletproofs;
    if (!typename Archive::is_saving())
      x.rct_config = { use_bulletproofs ? rct::RangeProofBulletproof : rct::RangeProofBorromean, 0 };
    return;
  }
  a & x.rct_config;

  if (ver < 6) return;
  a & x.tx_type;
  a & x.hf_version;
}

}
