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

#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_basic/difficulty.h"

namespace cryptonote::bootstrap {

struct file_info {
    uint8_t major_version;
    uint8_t minor_version;
    uint32_t header_size;

    template <class Archive>
    void serialize_object(Archive& ar) {
        field(ar, "major_version", major_version);
        field(ar, "minor_version", minor_version);
        field_varint(ar, "header_size", header_size);
    }
};

struct blocks_info {
    // block heights of file's first and last blocks, zero-based indexes
    uint64_t block_first;
    uint64_t block_last;

    // file position, for directly reading last block
    uint64_t block_last_pos;

    template <class Archive>
    void serialize_object(Archive& ar) {
        field_varint(ar, "block_first", block_first);
        field_varint(ar, "block_last", block_last);
        field_varint(ar, "block_last_pos", block_last_pos);
    }
};

struct block_package {
    cryptonote::block block;
    std::vector<transaction> txs;
    size_t block_weight;
    difficulty_type cumulative_difficulty;
    uint64_t coins_generated;

    template <class Archive>
    void serialize_object(Archive& ar) {
        field(ar, "block", block);
        field(ar, "txs", txs);
        field_varint(ar, "block_weight", block_weight);
        field_varint(ar, "cumulative_difficulty", cumulative_difficulty);
        field_varint(ar, "coins_generated", coins_generated);
    }
};

}  // namespace cryptonote::bootstrap
