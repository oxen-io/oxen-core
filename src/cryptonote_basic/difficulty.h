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

#include <cstdint>
#include <cstddef>
#include <vector>
#include "cryptonote_config.h"
#include "common/util.h"

namespace crypto { struct hash; }

namespace cryptonote
{
    typedef std::uint64_t difficulty_type;

    /**
     * @brief checks if a hash fits the given difficulty
     *
     * The hash passes if (hash * difficulty) < 2^256.
     * Phrased differently, if (hash * difficulty) fits without overflow into
     * the least significant 256 bits of the 320 bit multiplication result.
     *
     * @param hash the hash to check
     * @param difficulty the difficulty to check against
     *
     * @return true if valid, else false
     */
    bool check_hash(const crypto::hash &hash, difficulty_type difficulty);

    // Add one timestamp and difficulty to the input arrays, trimming down the
    // array if necessary for usage in next_difficulty_v2.
    void add_timestamp_and_difficulty(cryptonote::network_type nettype,
                                      uint64_t chain_height,
                                      std::vector<uint64_t> &timestamps,
                                      std::vector<difficulty_type> &difficulties,
                                      uint64_t timestamp,
                                      uint64_t cumulative_difficulty);


    constexpr difficulty_type PULSE_FIXED_DIFFICULTY = 1'000'000 * tools::to_seconds(TARGET_BLOCK_TIME);
    enum struct difficulty_calc_mode
    {
      use_old_lwma,
      hf12_override,
      normal,
    };

    difficulty_calc_mode difficulty_mode(network_type nettype, uint8_t hf_version, uint64_t height);

    difficulty_type next_difficulty_v2(std::vector<std::uint64_t> timestamps,
                                       std::vector<difficulty_type> cumulative_difficulties,
                                       size_t target_second,
                                       difficulty_calc_mode mode);
}
