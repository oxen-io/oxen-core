// Copyright (c) 2018-2021, The Loki Project
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

#include "core_rpc_server_commands_defs.h"

namespace cryptonote::rpc {

struct EMPTY {
    KV_MAP_SERIALIZABLE
};

/// Specifies that the RPC call is legacy, deprecated Monero custom binary input/ouput.  If not
/// given then the command is JSON/bt-encoded values.  For HTTP RPC this also means the command is
/// *not* available via the HTTP JSON RPC.
struct BINARY : virtual RPC_COMMAND {};

/// Get all blocks info. Binary request.
///
/// Inputs:
/// block_ids -- descending list of block IDs used to detect reorganizations and network status:
/// the first 10 are the 10 most recent blocks, after which height decreases by a power of 2.
struct GET_BLOCKS_BIN : PUBLIC, BINARY {
    static constexpr auto names() { return NAMES("get_blocks.bin", "getblocks.bin"); }

    static constexpr size_t MAX_COUNT = 1000;

    struct request {
        std::list<crypto::hash>
                block_ids;  // Descending list of block IDs used to detect reorganizations and
                            // network: the first 10 blocks id are sequential, then height drops by
                            // a power of 2 (2, 4, 8, 16, etc.) down to height 1, and then finally
                            // the genesis block id.
        uint64_t start_height;  // The height of the first block to fetch.
        bool prune;             // Prunes the blockchain, dropping off 7/8ths of the blocks.
        bool no_miner_tx;  // If specified and true, don't include miner transactions in transaction
                           // results.

        KV_MAP_SERIALIZABLE
    };

    struct tx_output_indices {
        std::vector<uint64_t> indices;  // Array of unsigned int.

        KV_MAP_SERIALIZABLE
    };

    struct block_output_indices {
        std::vector<tx_output_indices> indices;  // Array of TX output indices:

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::vector<block_complete_entry> blocks;  // Array of block complete entries
        uint64_t start_height;                     // The starting block's height.
        uint64_t current_height;                   // The current block height.
        std::string status;  // General RPC error code. "OK" means everything looks good.
        std::vector<block_output_indices> output_indices;  // Array of indices.
        bool untrusted;  // States if the result is obtained using the bootstrap mode, and is
                         // therefore not trusted (`true`), or when the daemon is fully synced
                         // (`false`).

        KV_MAP_SERIALIZABLE
    };
};

void to_json(nlohmann::json& j, const GET_BLOCKS_BIN::tx_output_indices& toi);
void to_json(nlohmann::json& j, const GET_BLOCKS_BIN::block_output_indices& boi);

OXEN_RPC_DOC_INTROSPECT
// Get blocks by height. Binary request.
struct GET_BLOCKS_BY_HEIGHT_BIN : PUBLIC, BINARY {
    static constexpr auto names() {
        return NAMES("get_blocks_by_height.bin", "getblocks_by_height.bin");
    }

    struct request {
        std::vector<uint64_t> heights;  // List of block heights

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::vector<block_complete_entry> blocks;  // Array of block complete entries
        std::string status;  // General RPC error code. "OK" means everything looks good.
        bool untrusted;      // States if the result is obtained using the bootstrap mode, and is
                             // therefore not trusted (`true`), or when the daemon is fully synced
                             // (`false`).

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Get the known blocks hashes which are not on the main chain.
struct GET_ALT_BLOCKS_HASHES_BIN : PUBLIC, BINARY {
    static constexpr auto names() { return NAMES("get_alt_blocks_hashes.bin"); }

    struct request : EMPTY {};
    struct response {
        std::vector<std::string> blks_hashes;  // List of alternative blocks hashes to main chain.
        std::string status;  // General RPC error code. "OK" means everything looks good.
        bool untrusted;      // States if the result is obtained using the bootstrap mode, and is
                             // therefore not trusted (`true`), or when the daemon is fully synced
                             // (`false`).

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Get hashes. Binary request.
struct GET_HASHES_BIN : PUBLIC, BINARY {
    static constexpr auto names() { return NAMES("get_hashes.bin", "gethashes.bin"); }

    struct request {
        std::list<crypto::hash> block_ids;  // First 10 blocks id goes sequential, next goes in
                                            // pow(2,n) offset, like 2, 4, 8, 16, 32, 64 and so on,
                                            // and the last one is always genesis block */
        uint64_t start_height;              // The starting block's height.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::vector<crypto::hash> m_block_ids;  // Binary array of hashes, See block_ids above.
        uint64_t start_height;                  // The starting block's height.
        uint64_t current_height;                // The current block height.
        std::string status;  // General RPC error code. "OK" means everything looks good.
        bool untrusted;      // States if the result is obtained using the bootstrap mode, and is
                             // therefore not trusted (`true`), or when the daemon is fully synced
                             // (`false`).

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Get global outputs of transactions. Binary request.
struct GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN : PUBLIC, BINARY {
    static constexpr auto names() { return NAMES("get_o_indexes.bin"); }

    struct request {
        crypto::hash txid;  // Binary txid.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::vector<uint64_t> o_indexes;  // List of output indexes
        std::string status;  // General RPC error code. "OK" means everything looks good.
        bool untrusted;      // States if the result is obtained using the bootstrap mode, and is
                             // therefore not trusted (`true`), or when the daemon is fully synced
                             // (`false`).

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
struct get_outputs_out {
    uint64_t amount;  // Amount of Loki in TXID.
    uint64_t index;

    KV_MAP_SERIALIZABLE
};

OXEN_RPC_DOC_INTROSPECT
// Get outputs. Binary request.
struct GET_OUTPUTS_BIN : PUBLIC, BINARY {
    static constexpr auto names() { return NAMES("get_outs.bin"); }

    /// Maximum outputs that may be requested in a single request (unless admin)
    static constexpr size_t MAX_COUNT = 5000;

    struct request {
        std::vector<get_outputs_out> outputs;  // Array of structure `get_outputs_out`.
        bool get_txid;                         // TXID

        KV_MAP_SERIALIZABLE
    };

    struct outkey {
        crypto::public_key key;  // The public key of the output.
        rct::key mask;
        bool unlocked;      // States if output is locked (`false`) or not (`true`).
        uint64_t height;    // Block height of the output.
        crypto::hash txid;  // Transaction id.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::vector<outkey> outs;  // List of outkey information.
        std::string status;        // General RPC error code. "OK" means everything looks good.
        bool untrusted;  // States if the result is obtained using the bootstrap mode, and is
                         // therefore not trusted (`true`), or when the daemon is fully synced
                         // (`false`).

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Get hashes from transaction pool. Binary request.
struct GET_TRANSACTION_POOL_HASHES_BIN : PUBLIC, BINARY {
    static constexpr auto names() { return NAMES("get_transaction_pool_hashes.bin"); }

    static constexpr std::chrono::seconds long_poll_timeout{15};

    struct request {
        bool blinked_txs_only;  // Optional: If true only transactions that were sent via blink and
                                // approved are queried.
        bool long_poll;  // Optional: If true, this call is blocking until timeout OR tx pool has
                         // changed since the last query. TX pool change is detected by comparing
                         // the hash of all the hashes in the tx pool.  Ignored when using OMQ RPC.
        crypto::hash tx_pool_checksum;  // Optional: If `long_poll` is true the caller must pass the
                                        // hashes of all their known tx pool hashes, XOR'ed
                                        // together.  Ignored when using OMQ RPC.
        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string status;  // General RPC error code. "OK" means everything looks good.
        std::vector<crypto::hash> tx_hashes;  // List of transaction hashes,
        bool untrusted;  // States if the result is obtained using the bootstrap mode, and is
                         // therefore not trusted (`true`), or when the daemon is fully synced
                         // (`false`).

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Exactly like GET_OUTPUT_DISTRIBUTION, but does a binary RPC transfer instead of JSON
struct GET_OUTPUT_DISTRIBUTION_BIN : PUBLIC, BINARY {
    static constexpr auto names() { return NAMES("get_output_distribution.bin"); }

    struct request : GET_OUTPUT_DISTRIBUTION::request {};
    using response = GET_OUTPUT_DISTRIBUTION::response;
};

OXEN_RPC_DOC_INTROSPECT
// Get information on output blacklist.
struct GET_OUTPUT_BLACKLIST_BIN : PUBLIC, BINARY {
    static constexpr auto names() { return NAMES("get_output_blacklist.bin"); }
    struct request : EMPTY {};

    struct response {
        std::vector<uint64_t> blacklist;  // (Developer): Array of indexes from the global output
                                          // list, corresponding to blacklisted key images.
        std::string status;               // Generic RPC error code. "OK" is the success value.
        bool untrusted;  // If the result is obtained using bootstrap mode, and therefore not
                         // trusted `true`, or otherwise `false`.

        KV_MAP_SERIALIZABLE
    };
};

/// List of all supported rpc command structs to allow compile-time enumeration of all supported
/// RPC types.  Every type added above that has an RPC endpoint needs to be added here, and needs
/// a core_rpc_server::invoke() overload that takes a <TYPE>::request and returns a
/// <TYPE>::response.  The <TYPE>::request has to be unique (for overload resolution);
/// <TYPE>::response does not.
using core_rpc_binary_types = tools::type_list<
        GET_ALT_BLOCKS_HASHES_BIN,
        GET_BLOCKS_BIN,
        GET_BLOCKS_BY_HEIGHT_BIN,
        GET_HASHES_BIN,
        GET_OUTPUTS_BIN,
        GET_OUTPUT_BLACKLIST_BIN,
        GET_OUTPUT_DISTRIBUTION_BIN,
        GET_TRANSACTION_POOL_HASHES_BIN,
        GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN>;

}  // namespace cryptonote::rpc
