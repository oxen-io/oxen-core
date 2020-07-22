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
#include <ringct/rctTypes.h>
#include <boost/serialization/version.hpp>

namespace wallet {

struct multisig_info
{
  struct LR
  {
    rct::key m_L;
    rct::key m_R;
  };

  crypto::public_key m_signer;
  std::vector<LR> m_LR;
  std::vector<crypto::key_image> m_partial_key_images; // one per key the participant has
};

template <class Archive>
void serialize_value(Archive& ar, multisig_info::LR& x) {
  field(ar, "m_L", x.m_L);
  field(ar, "m_R", x.m_R);
}

template <class Archive>
void serialize_value(Archive& ar, multisig_info& x) {
  field(ar, "m_signer", x.m_signer);
  field(ar, "m_LR", x.m_LR);
  field(ar, "m_partial_key_images", x.m_partial_key_images);
}

}

BOOST_CLASS_VERSION(wallet::multisig_info::LR, 0)
BOOST_CLASS_VERSION(wallet::multisig_info, 1)

namespace boost::serialization {

template <class Archive>
void serialize(Archive &a, wallet::multisig_info::LR &x, const unsigned int /*ver*/)
{
  a & x.m_L;
  a & x.m_R;
}

template <class Archive>
void serialize(Archive &a, wallet::multisig_info &x, const unsigned int /*ver*/)
{
  a & x.m_signer;
  a & x.m_LR;
  a & x.m_partial_key_images;
}

}
