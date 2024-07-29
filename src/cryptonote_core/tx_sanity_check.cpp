// Copyright (c) 2019, The Monero Project
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

#include "tx_sanity_check.h"

#include <stdint.h>

#include <vector>

#include "blockchain.h"
#include "common/median.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

namespace cryptonote {

static auto logcat = log::Cat("verify");

bool tx_sanity_check(const std::string& tx_blob, uint64_t rct_outs_available) {
    cryptonote::transaction tx;

    if (!cryptonote::parse_and_validate_tx_from_blob(tx_blob, tx)) {
        log::error(logcat, "Failed to parse transaction");
        return false;
    }

    if (tx.is_miner_tx()) {
        log::error(logcat, "Transaction is coinbase");
        return false;
    }
    std::set<uint64_t> rct_indices;
    size_t n_indices = 0;

    for (const auto& txin : tx.vin) {
        auto* in_to_key = std::get_if<cryptonote::txin_to_key>(&txin);
        if (!in_to_key)
            continue;
        if (in_to_key->amount != 0)
            continue;
        for (uint64_t offset :
             cryptonote::relative_output_offsets_to_absolute(in_to_key->key_offsets))
            rct_indices.insert(offset);
        n_indices += in_to_key->key_offsets.size();
    }

    return tx_sanity_check(rct_indices, n_indices, rct_outs_available);
}

bool tx_sanity_check(
        const std::set<uint64_t>& rct_indices, size_t n_indices, uint64_t rct_outs_available) {
    if (n_indices <= 10) {
        log::debug(logcat, "n_indices is only {}, not checking", n_indices);
        return true;
    }

    if (rct_outs_available < 10000)
        return true;

    if (rct_indices.size() < n_indices * 8 / 10) {
        log::error(
                logcat,
                "amount of unique indices is too low (amount of rct indices is {}, out of total {} "
                "indices)",
                rct_indices.size(),
                n_indices);
        return false;
    }

    std::vector<uint64_t> offsets(rct_indices.begin(), rct_indices.end());
    uint64_t median = tools::median(std::move(offsets));
    if (median < rct_outs_available * 6 / 10) {
        log::error(
                logcat,
                "median offset index is too low (median is {} out of total {}offsets). "
                "Transactions should contain a higher fraction of recent outputs.",
                median,
                rct_outs_available);
        return false;
    }

    return true;
}

}  // namespace cryptonote
