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
#include <string>
#include <vector>

#include "common/oxen.h"
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/subaddress_index.h"
#include "transfer_destination.h"

namespace wallet {

enum struct pay_type {
    unspecified,  // For serialized data before this was introduced in hardfork 10
    in,
    out,
    stake,
    miner,
    service_node,
    governance,
    ons
};

inline const char* pay_type_string(pay_type type) {
    switch (type) {
        case pay_type::unspecified: return "n/a";
        case pay_type::in: return "in";
        case pay_type::out: return "out";
        case pay_type::stake: return "stake";
        case pay_type::ons: return "ons";
        case pay_type::miner: return "reward";
        case pay_type::service_node: return "snode";
        case pay_type::governance: return "gov";
        default: assert(false); return "xxxxx";
    }
}

inline pay_type pay_type_from_tx(const cryptonote::transaction tx) {
    switch (tx.type) {
        case cryptonote::txtype::stake: return wallet::pay_type::stake;
        case cryptonote::txtype::oxen_name_system: return wallet::pay_type::ons;
        default: return wallet::pay_type::out;
    }
}

OXEN_RPC_DOC_INTROSPECT
struct transfer_view {
    std::string txid;        // Transaction ID for this transfer.
    std::string payment_id;  // Payment ID for this transfer.
    uint64_t
            height;  // Height of the first block that confirmed this transfer (0 if not mined yet).
    uint64_t timestamp;  // UNIX timestamp for when this transfer was first confirmed in a block (or
                         // timestamp submission if not mined yet).
    uint64_t amount;     // Amount transferred.
    uint64_t fee;        // Transaction fee for this transfer.
    std::string note;    // Note about this transfer.
    std::list<transfer_destination> destinations;  // Array of transfer destinations.
    std::string type;      // Type of transfer, one of the following: "in", "out", "stake", "miner",
                           // "snode", "gov", "pending", "failed", "pool".
    uint64_t unlock_time;  // Number of blocks until transfer is safely spendable.
    bool locked;           // If the transfer is locked or not
    cryptonote::subaddress_index
            subaddr_index;  // Major & minor index, account and subaddress index respectively.
    std::vector<cryptonote::subaddress_index> subaddr_indices;
    std::string address;     // Address that transferred the funds.
    bool double_spend_seen;  // True if the key image(s) for the transfer have been seen before.
    uint64_t confirmations;  // Number of block mined since the block containing this transaction
                             // (or block height at which the transaction should be added to a block
                             // if not yet confirmed).
    uint64_t suggested_confirmations_threshold;  // Estimation of the confirmations needed for the
                                                 // transaction to be included in a block.
    uint64_t checkpointed;  // If transfer is backed by atleast 2 Service Node Checkpoints, 0 if it
                            // is not, see immutable_height in the daemon rpc call get_info
    bool blink_mempool;     // True if this is an approved blink tx in the mempool
    bool was_blink;  // True if we saw this as an approved blink (either in the mempool or a recent,
                     // uncheckpointed block).  Note that if we didn't see it while an active blink
                     // this won't be set.

    // Not serialized, for internal wallet2 use
    wallet::pay_type pay_type;  // @NoLokiRPCDocGen Internal use only, not serialized
    bool confirmed;             // @NoLokiRPCDocGen Internal use only, not serialized
    crypto::hash hash;          // @NoLokiRPCDocGen Internal use only, not serialized
    std::string lock_msg;       // @NoLokiRPCDocGen Internal use only, not serialized

    KV_MAP_SERIALIZABLE
};

}  // namespace wallet
