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

#include <vector>

#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "crypto/eth.h"
#include "crypto/hash.h"
#include "serialization.h"

namespace serialization {

// For vector-of-signature serialization, we don't write the size but just dump the contents
// directly.  When reading, the vector must have already been resized to the target size and we
// slurp them in.
template <class Archive>
void serialize_value(Archive& ar, std::vector<crypto::signature>& v) {
    if constexpr (Archive::is_deserializer)
        // very basic sanity check
        ar.remaining_bytes(v.size() * sizeof(crypto::signature));

    ar.serialize_blob(v.data(), v.size() * sizeof(crypto::signature));
}

}  // namespace serialization

BLOB_SERIALIZER(crypto::chacha_iv);
BLOB_SERIALIZER(crypto::hash);
BLOB_SERIALIZER(crypto::hash8);
BLOB_SERIALIZER(crypto::hash4);
BLOB_SERIALIZER(crypto::public_key);
BLOB_SERIALIZER(crypto::secret_key);
BLOB_SERIALIZER(crypto::key_derivation);
BLOB_SERIALIZER(crypto::key_image);
BLOB_SERIALIZER(crypto::signature);
BLOB_SERIALIZER(crypto::ed25519_public_key);
BLOB_SERIALIZER(crypto::ed25519_signature);
BLOB_SERIALIZER(eth::address);
BLOB_SERIALIZER(eth::bls_public_key);
