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

#include "tx_construction_data.h"
#include "transfer_details.h"
#include "pending_tx.h"

namespace wallet {

// The term "Unsigned tx" is not really a tx since it's not signed yet.
// It doesnt have tx hash, key and the integrated address is not separated into addr + payment id.
struct unsigned_tx_set
{
  std::vector<wallet::tx_construction_data> txes;
  std::pair<size_t, std::vector<wallet::transfer_details>> transfers;
};

struct signed_tx_set
{
  std::vector<pending_tx> ptx;
  std::vector<crypto::key_image> key_images;
  std::unordered_map<crypto::public_key, crypto::key_image> tx_key_images;
};

struct multisig_tx_set
{
  std::vector<pending_tx> m_ptx;
  std::unordered_set<crypto::public_key> m_signers;
};


template <class Archive>
void serialize_value(Archive& ar, multisig_tx_set& x) {
  field(ar, "m_ptx", x.m_ptx);
  field(ar, "m_signers", x.m_signers);
};

}

BOOST_CLASS_VERSION(wallet::unsigned_tx_set, 0)
BOOST_CLASS_VERSION(wallet::signed_tx_set, 1)
BOOST_CLASS_VERSION(wallet::multisig_tx_set, 1)

namespace boost::serialization {

template <class Archive>
void serialize(Archive &a, wallet::unsigned_tx_set &x, const unsigned int ver)
{
  a & x.txes;
  a & x.transfers;
}

template <class Archive>
void serialize(Archive &a, wallet::signed_tx_set &x, const unsigned int ver)
{
  a & x.ptx;
  a & x.key_images;
  if (ver < 1)
    return;
  a & x.tx_key_images;
}

template <class Archive>
void serialize(Archive &a, wallet::multisig_tx_set &x, const unsigned int ver)
{
  a & x.m_ptx;
  a & x.m_signers;
}

}
