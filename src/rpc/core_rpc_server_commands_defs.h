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

#include "crypto/crypto.h"
#include "epee/string_tools.h"

#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/verification_context.h"
#include "cryptonote_basic/difficulty.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "cryptonote_core/service_node_voting.h"
#include "common/varint.h"
#include "common/perf_timer.h"
#include "common/meta.h"
#include "common/hex.h"
#include "checkpoints/checkpoints.h"

#include "cryptonote_core/service_node_quorum_cop.h"
#include "cryptonote_core/service_node_list.h"
#include "common/loki.h"

namespace cryptonote {

/// Namespace for core RPC commands.  Every RPC commands gets defined here (including its name(s),
/// access, and data type), and added to `core_rpc_types` list at the bottom of the file.

namespace rpc {

  using version_t = std::pair<uint16_t, uint16_t>;

// When making *any* change here, bump minor
// If the change is incompatible, then bump major and set minor to 0
// This ensures rpc::VERSION always increases, that every change
// has its own version, and that clients can just test major to see
// whether they can talk to a given daemon without having to know in
// advance which version they will stop working with
  constexpr version_t VERSION = {4, 0};

  /// Makes a version array from a packed 32-bit integer version
  constexpr version_t make_version(uint32_t version)
  {
    return {static_cast<uint16_t>(version >> 16), static_cast<uint16_t>(version & 0xffff)};
  }
  /// Packs a version array into a packed 32-bit integer version
  constexpr uint32_t pack_version(version_t version)
  {
    return (uint32_t(version.first) << 16) | version.second;
  }

  const static std::string
    STATUS_OK = "OK",
    STATUS_FAILED = "FAILED",
    STATUS_BUSY = "BUSY",
    STATUS_NOT_MINING = "NOT MINING",
    STATUS_TX_LONG_POLL_TIMED_OUT = "Long polling client timed out before txpool had an update";


  namespace {
    /// Returns a constexpr std::array of string_views from an arbitrary list of string literals
    /// Used to specify RPC names as:
    /// static constexpr auto names() { return NAMES("primary_name", "some_alias"); }
    template <size_t... N>
    constexpr std::array<std::string_view, sizeof...(N)> NAMES(const char (&...names)[N]) {
      static_assert(sizeof...(N) > 0, "RPC command must have at least one name");
      return {std::string_view{names, N-1}...};
    }
  }

  /// Base command that all RPC commands must inherit from (either directly or via one or more of
  /// the below tags).  Inheriting from this (and no others) gives you a private, json, non-legacy
  /// RPC command.  For LMQ RPC the command will be available at `admin.whatever`; for HTTP RPC
  /// it'll be at `whatever`.
  struct RPC_COMMAND {};

  /// Tag types that are used (via inheritance) to set rpc endpoint properties

  /// Specifies that the RPC call is public (i.e. available through restricted rpc).  If this is
  /// *not* inherited from then the command is restricted (i.e. only available to admins).  For LMQ,
  /// PUBLIC commands are available at `rpc.command` (versus non-PUBLIC ones at `admin.command`).
  struct PUBLIC : RPC_COMMAND {};

  /// Specifies that the RPC call is binary input/ouput.  If not given then the command is JSON.
  /// For HTTP RPC this also means the command is *not* available via the HTTP JSON RPC.
  struct BINARY : RPC_COMMAND {};

  /// Specifies a "legacy" JSON RPC command, available via HTTP JSON at /whatever (in addition to
  /// json_rpc as "whatever").  When accessed via legacy mode the result is just the .result element
  /// of the JSON RPC response.  (Only applies to the HTTP RPC interface, and does nothing if BINARY
  /// if specified).
  struct LEGACY : RPC_COMMAND {};


  /// (Not a tag). Generic, serializable, no-argument request type, use as `struct request : EMPTY {};`
  struct EMPTY { KV_MAP_SERIALIZABLE };

  /// (Not a tag). Generic response which contains only a status string; use as `struct response : STATUS {};`
  struct STATUS
  {
    std::string status; // General RPC error code. "OK" means everything looks good.

    KV_MAP_SERIALIZABLE
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get the node's current height.
  struct GET_HEIGHT : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("get_height", "getheight"); }

    struct request : EMPTY {};
    struct response
    {
      uint64_t height;            // The current blockchain height according to the queried daemon.
      std::string status;         // Generic RPC error code. "OK" is the success value.
      bool untrusted;             // If the result is obtained using bootstrap mode, and therefore not trusted `true`, or otherwise `false`.
      std::string hash;           // Hash of the block at the current height
      uint64_t immutable_height;  // The latest height in the blockchain that can not be reorganized from (backed by atleast 2 Service Node, or 1 hardcoded checkpoint, 0 if N/A).
      std::string immutable_hash; // Hash of the highest block in the chain that can not be reorganized.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get all blocks info. Binary request.
  struct GET_BLOCKS_FAST : PUBLIC, BINARY
  {
    static constexpr auto names() { return NAMES("get_blocks.bin", "getblocks.bin"); }

    static constexpr size_t MAX_COUNT = 1000;

    struct request
    {
      std::list<crypto::hash> block_ids; // First 10 blocks id goes sequential, next goes in pow(2,n) offset, like 2, 4, 8, 16, 32, 64 and so on, and the last one is always genesis block
      uint64_t    start_height;          // The starting block's height.
      bool        prune;                 // Prunes the blockchain, drops off 7/8 off the block iirc.
      bool        no_miner_tx;           // Optional (false by default).

      KV_MAP_SERIALIZABLE
    };

    struct tx_output_indices
    {
      std::vector<uint64_t> indices; // Array of unsigned int.

      KV_MAP_SERIALIZABLE
    };

    struct block_output_indices
    {
      std::vector<tx_output_indices> indices; // Array of TX output indices:

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::vector<block_complete_entry> blocks;         // Array of block complete entries
      uint64_t    start_height;                         // The starting block's height.
      uint64_t    current_height;                       // The current block height.
      std::string status;                               // General RPC error code. "OK" means everything looks good.
      std::vector<block_output_indices> output_indices; // Array of indices.
      bool untrusted;                                   // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get blocks by height. Binary request.
  struct GET_BLOCKS_BY_HEIGHT : PUBLIC, BINARY
  {
    static constexpr auto names() { return NAMES("get_blocks_by_height.bin", "getblocks_by_height.bin"); }

    struct request
    {
      std::vector<uint64_t> heights;         // List of block heights

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::vector<block_complete_entry> blocks; // Array of block complete entries
      std::string status;                       // General RPC error code. "OK" means everything looks good.
      bool untrusted;                           // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };


  LOKI_RPC_DOC_INTROSPECT
  // Get the known blocks hashes which are not on the main chain.
  struct GET_ALT_BLOCKS_HASHES : PUBLIC, BINARY
  {
    static constexpr auto names() { return NAMES("get_alt_blocks_hashes.bin"); }

    struct request : EMPTY {};
    struct response
    {
        std::vector<std::string> blks_hashes; // List of alternative blocks hashes to main chain.
        std::string status;                   // General RPC error code. "OK" means everything looks good.
        bool untrusted;                       // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

        KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get hashes. Binary request.
  struct GET_HASHES_FAST : PUBLIC, BINARY
  {
    static constexpr auto names() { return NAMES("get_hashes.bin", "gethashes.bin"); }

    struct request
    {
      std::list<crypto::hash> block_ids; // First 10 blocks id goes sequential, next goes in pow(2,n) offset, like 2, 4, 8, 16, 32, 64 and so on, and the last one is always genesis block */
      uint64_t    start_height;          // The starting block's height.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::vector<crypto::hash> m_block_ids; // Binary array of hashes, See block_ids above.
      uint64_t    start_height;              // The starting block's height.
      uint64_t    current_height;            // The current block height.
      std::string status;                    // General RPC error code. "OK" means everything looks good.
      bool untrusted;                        // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Look up one or more transactions by hash.
  struct GET_TRANSACTIONS : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("get_transactions", "gettransactions"); }

    // Information from a transactions tx-extra fields.  Fields within this will only be populated
    // when actually found in the transaction.  (Requires tx_extra=true in the request).
    struct extra_entry
    {
      struct sn_reg_info
      {
        struct contribution
        {
          std::string wallet; // Contributor wallet
          uint32_t portion;   // Reserved portion, as the rounded nearest value out of 1'000'000 (i.e. 234567 == 23.4567%).
          KV_MAP_SERIALIZABLE
        };

        std::vector<contribution> contributors; // Operator contribution plus any reserved contributions
        uint32_t fee;                           // Operator fee, as the rounded nearest value out of 1'000'000
        uint64_t expiry;                        // unix timestamp at which the registration expires
        KV_MAP_SERIALIZABLE
      };
      struct state_change
      {
        std::optional<bool> old_dereg; // Will be present and set to true iff this record is an old (pre-HF12) deregistration field
        std::string type;              // "dereg", "decom", "recom", or "ip" indicating the state change type
        uint64_t height;               // The voting block height for the changing service node and validators
        uint32_t index;                // The index of all tested nodes at the given height for which this state change applies
        std::vector<uint32_t> voters;  // The position of validators in the testing quorum who validated and voted for this state change. This typically contains just 7 required voter slots (of 10 eligible voters).
        KV_MAP_SERIALIZABLE
      };
      struct lns_details
      {
        std::optional<bool> buy;                 // Provided and true iff this is an LNS buy record
        std::optional<bool> update;              // Provided and true iff this is an LNS record update
        std::optional<bool> renew;               // Provided and true iff this is an LNS record renewal
        std::string type;                        // The LNS request type.  For registrations: "lokinet", "session", "wallet"; for a record update: "update"
        std::optional<uint64_t> blocks;          // The registration length in blocks (only applies to lokinet registrations; session/wallet registrations do not expire)
        std::string name_hash;                   // The hashed name of the record being purchased/updated, in hex (the actual name is not provided on the blockchain).
        std::optional<std::string> prev_txid;    // For an update, this points at the txid of the previous lns update transaction.
        std::optional<std::string> value;        // The encrypted value of the record, in hex.  Note that this is encrypted using the actual name itself (*not* the hashed name).
        std::optional<std::string> owner;        // The owner of this record; this can be a main wallet, wallet subaddress, or a plain public key.
        std::optional<std::string> backup_owner; // Backup owner wallet/pubkey of the record, if provided.
        KV_MAP_SERIALIZABLE
      };

      std::optional<std::string> pubkey;            // The tx extra public key
      std::optional<uint64_t> burn_amount;          // The amount of LOKI that this transaction burns
      std::optional<std::string> extra_nonce;       // Optional extra nonce value (in hex); will be empty if nonce is recognized as a payment id
      std::optional<std::string> payment_id;        // The payment ID, if present. This is either a 16 hex character (8-byte) encrypted payment id, or a 64 hex character (32-byte) deprecated, unencrypted payment ID
      std::optional<uint32_t> mm_depth;             // (Merge-mining) the merge-mined depth
      std::optional<std::string> mm_root;           // (Merge-mining) the merge mining merkle root hash
      std::vector<std::string> additional_pubkeys;  // Additional public keys
      std::optional<std::string> sn_winner;         // Service node block reward winner public key
      std::optional<std::string> sn_pubkey;         // Service node public key (e.g. for registrations, stakes, unlocks)
      std::optional<sn_reg_info> sn_registration;   // Service node registration details
      std::optional<std::string> sn_contributor;    // Service node contributor wallet address (for stakes)
      std::optional<state_change> sn_state_change;  // A state change transaction (deregistration, decommission, recommission, ip change)
      std::optional<std::string> tx_secret_key;     // The transaction secret key, included in registrations/stakes to decrypt transaction amounts and recipients
      std::vector<std::string> locked_key_images;   // Key image(s) locked by the transaction (for registrations, stakes)
      std::optional<std::string> key_image_unlock;  // A key image being unlocked in a stake unlock request (an unlock will be started for *all* key images locked in the same SN contributions).
      std::optional<lns_details> lns;               // an LNS registration or update
      KV_MAP_SERIALIZABLE
    };

    struct entry
    {
      std::string tx_hash;                  // Transaction hash.
      std::optional<std::string> as_hex;    // Full transaction information as a hex string. Always omitted if any of `decode_as_json`, `split`, or `prune` is requested; or if the transaction has been pruned in the database.
      std::optional<std::string> pruned_as_hex;   // The non-prunable part of the transaction. Always included if `split` or `prune` and specified; without those options it will be included instead of `as_hex` if the transaction has been pruned.
      std::optional<std::string> prunable_as_hex; // The prunable part of the transaction.  Only included when `split` is specified, the transaction is prunable, and the tx has not been pruned from the database.
      std::optional<std::string> prunable_hash;   // The hash of the prunable part of the transaction.  Will be provided if either: the tx has been pruned; or the tx is prunable and either of `prune` or `split` are specified.
      std::optional<std::string> as_json;   // Transaction information parsed into json. Requires decode_as_json in request.
      uint32_t size;                        // Size of the transaction, in bytes. Note that if the transaction has been pruned this is the post-pruning size, not the original size.
      bool in_pool;                         // States if the transaction is in pool (`true`) or included in a block (`false`).
      bool double_spend_seen;               // States if the transaction is a double-spend (`true`) or not (`false`).
      uint64_t block_height;                // Block height including the transaction.
      uint64_t block_timestamp;             // Unix time at which the block has been added to the blockchain.
      std::vector<uint64_t> output_indices; // List of transaction indexes.
      uint64_t received_timestamp;          // Timestamp transaction was received in the pool.
      bool relayed;
      bool blink;                           // True if this is an approved, blink transaction (only available for in_pool transactions or txes in recent blocks)
      std::optional<extra_entry> extra;     // Parsed tx_extra information (only if requested)

      KV_MAP_SERIALIZABLE
    };

    struct request
    {
      std::vector<std::string> txs_hashes; // List of transaction hashes to look up.
      bool decode_as_json;                 // Optional (`false` by default). If set true, the returned transaction information will be decoded.
      bool tx_extra;                       // Parse tx-extra information
      bool split;                          // Always split transactions into non-prunable and prunable parts in the response.  `False` by default.
      bool prune;                          // Like `split`, but also omits the prunable part (or details, for decode_as_json) of transactions from the response.  `False` by default.

      KV_MAP_SERIALIZABLE
    };


    struct response
    {
      std::vector<std::string> missed_tx;   // (Optional - returned if not empty) Transaction hashes that could not be found.
      std::vector<entry> txs;               // Array of tx data
      std::string status;                   // General RPC error code. "OK" means everything looks good.
      bool untrusted;                       // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Check if outputs have been spent using the key image associated with the output.
  struct IS_KEY_IMAGE_SPENT : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("is_key_image_spent"); }

    enum STATUS
    {
      UNSPENT = 0,
      SPENT_IN_BLOCKCHAIN = 1,
      SPENT_IN_POOL = 2,
    };

    struct request
    {
      std::vector<std::string> key_images; // List of key image hex strings to check.

      KV_MAP_SERIALIZABLE
    };


    struct response
    {
      std::vector<int> spent_status; // List of statuses for each image checked. Statuses are follows: 0 = unspent, 1 = spent in blockchain, 2 = spent in transaction pool
      std::string status;            // General RPC error code. "OK" means everything looks good.
      bool untrusted;                // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };


  LOKI_RPC_DOC_INTROSPECT
  // Get global outputs of transactions. Binary request.
  struct GET_TX_GLOBAL_OUTPUTS_INDEXES : PUBLIC, BINARY
  {
    static constexpr auto names() { return NAMES("get_o_indexes.bin"); }

    struct request
    {
      crypto::hash txid; // Binary txid.

      KV_MAP_SERIALIZABLE
    };


    struct response
    {
      std::vector<uint64_t> o_indexes; // List of output indexes
      std::string status;              // General RPC error code. "OK" means everything looks good.
      bool untrusted;                  // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  struct get_outputs_out
  {
    uint64_t amount; // Amount of Loki in TXID.
    uint64_t index;

    KV_MAP_SERIALIZABLE
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get outputs. Binary request.
  struct GET_OUTPUTS_BIN : PUBLIC, BINARY
  {
    static constexpr auto names() { return NAMES("get_outs.bin"); }

    /// Maximum outputs that may be requested in a single request (unless admin)
    static constexpr size_t MAX_COUNT = 5000;

    struct request
    {
      std::vector<get_outputs_out> outputs; // Array of structure `get_outputs_out`.
      bool get_txid;                        // TXID

      KV_MAP_SERIALIZABLE
    };

    struct outkey
    {
      crypto::public_key key; // The public key of the output.
      rct::key mask;
      bool unlocked;          // States if output is locked (`false`) or not (`true`).
      uint64_t height;        // Block height of the output.
      crypto::hash txid;      // Transaction id.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::vector<outkey> outs; // List of outkey information.
      std::string status;       // General RPC error code. "OK" means everything looks good.
      bool untrusted;           // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  struct GET_OUTPUTS : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("get_outs"); }

    /// Maximum outputs that may be requested in a single request (unless admin)
    static constexpr size_t MAX_COUNT = 5000;

    struct request
    {
      std::vector<get_outputs_out> outputs; // Array of structure `get_outputs_out`.
      bool get_txid;                        // Request the TXID/hash of the transaction as well.

      KV_MAP_SERIALIZABLE
    };

    struct outkey
    {
      std::string key;  // The public key of the output.
      std::string mask;
      bool unlocked;    // States if output is locked (`false`) or not (`true`).
      uint64_t height;  // Block height of the output.
      std::string txid; // Transaction id.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::vector<outkey> outs; // List of outkey information.
      std::string status;       // General RPC error code. "OK" means everything looks good.
      bool untrusted;           // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Broadcast a raw transaction to the network.
  struct SEND_RAW_TX : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("send_raw_transaction", "sendrawtransaction"); }

    struct request
    {
      std::string tx_as_hex; // Full transaction information as hexidecimal string.
      bool do_not_relay;     // (Optional: Default false) Stop relaying transaction to other nodes.  Ignored if `blink` is true.
      bool do_sanity_checks; // (Optional: Default true) Verify TX params have sane values.
      bool blink;            // (Optional: Default false) Submit this as a blink tx rather than into the mempool.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status; // General RPC error code. "OK" means everything looks good. Any other value means that something went wrong.
      std::string reason; // Additional information. Currently empty, "Not relayed" if transaction was accepted but not relayed, or some descriptive message of why the tx failed.
      bool not_relayed;   // Transaction was not relayed (true) or relayed (false).
      bool untrusted;     // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).
      tx_verification_context tvc;
      bool sanity_check_failed;
      blink_result blink_status; // 0 for a non-blink tx.  For a blink tx: 1 means rejected, 2 means accepted, 3 means timeout.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Start mining on the daemon.
  struct START_MINING : LEGACY
  {
    static constexpr auto names() { return NAMES("start_mining"); }

    struct request
    {
      std::string miner_address;        // Account address to mine to.
      uint64_t    threads_count;        // Number of mining thread to run.
      uint64_t    num_blocks;           // Mine until the blockchain has this many new blocks, then stop (no limit if 0, the default)
      bool        slow_mining;          // Do slow mining (i.e. don't allocate RandomX cache); primarily intended for testing

      KV_MAP_SERIALIZABLE
    };

    struct response : STATUS {};
  };

  LOKI_RPC_DOC_INTROSPECT
  // Stop mining on the daemon.
  struct STOP_MINING : LEGACY
  {
    static constexpr auto names() { return NAMES("stop_mining"); }

    struct request : EMPTY {};
    struct response : STATUS {};
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get the mining status of the daemon.
  struct MINING_STATUS : LEGACY
  {
    static constexpr auto names() { return NAMES("mining_status"); }

    struct request : EMPTY {};
    struct response
    {
      std::string status;                // General RPC error code. "OK" means everything looks good. Any other value means that something went wrong.
      bool active;                       // States if mining is enabled (`true`) or disabled (`false`).
      uint64_t speed;                    // Mining power in hashes per seconds.
      uint32_t threads_count;            // Number of running mining threads.
      std::string address;               // Account address daemon is mining to. Empty if not mining.
      std::string pow_algorithm;         // Current hashing algorithm name
      uint32_t block_target;             // The expected time to solve per block, i.e. TARGET_BLOCK_TIME
      uint64_t block_reward;             // Block reward for the current block being mined.
      uint64_t difficulty;               // The difficulty for the current block being mined.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Retrieve general information about the state of your node and the network.
  // Note that all of the std::optional<> fields here are not included if the request is a public
  // (restricted) RPC request.
  struct GET_INFO : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("get_info", "getinfo"); }

    struct request : EMPTY {};
    struct response
    {
      std::string status;                   // General RPC error code. "OK" means everything looks good.
      uint64_t height;                      // Current length of longest chain known to daemon.
      uint64_t target_height;               // The height of the next block in the chain.
      uint64_t immutable_height;            // The latest height in the blockchain that can not be reorganized from (backed by atleast 2 Service Node, or 1 hardcoded checkpoint, 0 if N/A).
      uint64_t pulse_ideal_timestamp;       // For pulse blocks this is the ideal timestamp of the next block, that is, the timestamp if the network was operating with perfect 2-minute blocks since the pulse hard fork.
      uint64_t pulse_target_timestamp;      // For pulse blocks this is the target timestamp of the next block, which targets 2 minutes after the previous block but will be slightly faster/slower if the previous block is behind/ahead of the ideal timestamp.
      uint64_t difficulty;                  // Network difficulty (analogous to the strength of the network).
      uint64_t target;                      // Current target for next proof of work.
      uint64_t tx_count;                    // Total number of non-coinbase transaction in the chain.
      uint64_t tx_pool_size;                // Number of transactions that have been broadcast but not included in a block.
      std::optional<uint64_t> alt_blocks_count;            // Number of alternative blocks to main chain.
      std::optional<uint64_t> outgoing_connections_count;  // Number of peers that you are connected to and getting information from.
      std::optional<uint64_t> incoming_connections_count;  // Number of peers connected to and pulling from your node.
      std::optional<uint64_t> white_peerlist_size;         // White Peerlist Size
      std::optional<uint64_t> grey_peerlist_size;          // Grey Peerlist Size
      bool mainnet;                         // States if the node is on the mainnet (`true`) or not (`false`).
      bool testnet;                         // States if the node is on the testnet (`true`) or not (`false`).
      bool devnet;                          // States if the node is on the devnet (`true`) or not (`false`).
      std::string nettype;                  // Nettype value used.
      std::string top_block_hash;           // Hash of the highest block in the chain.
      std::string immutable_block_hash;     // Hash of the highest block in the chain that can not be reorganized.
      uint64_t cumulative_difficulty;       // Cumulative difficulty of all blocks in the blockchain.
      uint64_t block_size_limit;            // Maximum allowed block size.
      uint64_t block_weight_limit;          // Maximum allowed block weight.
      uint64_t block_size_median;           // Median block size of latest 100 blocks.
      uint64_t block_weight_median;         // Median block weight of latest 100 blocks.
      std::optional<bool> service_node;                    // Will be true if the node is running in --service-node mode.
      std::optional<uint64_t> start_time;                  // Start time of the daemon, as UNIX time.
      std::optional<uint64_t> last_storage_server_ping;    // Last ping time of the storage server (0 if never or not running as a service node)
      std::optional<uint64_t> last_lokinet_ping;           // Last ping time of lokinet (0 if never or not running as a service node)
      std::optional<uint64_t> free_space;                  // Available disk space on the node.
      bool offline;                         // States if the node is offline (`true`) or online (`false`).
      bool untrusted;                       // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).
      std::optional<std::string> bootstrap_daemon_address; // Bootstrap node to give immediate usability to wallets while syncing by proxying RPC to it. (Note: the replies may be untrustworthy).
      std::optional<uint64_t> height_without_bootstrap;    // Current length of the local chain of the daemon.
      std::optional<bool> was_bootstrap_ever_used;         // States if a bootstrap node has ever been used since the daemon started.
      uint64_t database_size;               // Current size of Blockchain data.  Over public RPC this is rounded up to the next-largest GB value.
      std::string version;                  // Current version of software running.
      std::string status_line;              // A short one-line summary status of the node (requires an admin/unrestricted connection for most details)

      KV_MAP_SERIALIZABLE
    };
  };

  //-----------------------------------------------
  LOKI_RPC_DOC_INTROSPECT
  struct GET_NET_STATS : LEGACY
  {
    static constexpr auto names() { return NAMES("get_net_stats"); }

    struct request : EMPTY {};
    struct response
    {
      std::string status;
      uint64_t start_time;
      uint64_t total_packets_in;
      uint64_t total_bytes_in;
      uint64_t total_packets_out;
      uint64_t total_bytes_out;

      KV_MAP_SERIALIZABLE
    };
  };


  LOKI_RPC_DOC_INTROSPECT
  // Save the blockchain. The blockchain does not need saving and is always saved when modified,
  // however it does a sync to flush the filesystem cache onto the disk for safety purposes against Operating System or Hardware crashes.
  struct SAVE_BC : LEGACY
  {
    static constexpr auto names() { return NAMES("save_bc"); }

    struct request : EMPTY {};
    struct response : STATUS {};
  };

  LOKI_RPC_DOC_INTROSPECT
  // Look up how many blocks are in the longest chain known to the node.
  struct GETBLOCKCOUNT : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block_count", "getblockcount"); }

    struct request : EMPTY {};
    struct response
    {
      uint64_t count;     // Number of blocks in longest chain seen by the node.
      std::string status; // General RPC error code. "OK" means everything looks good.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Look up a block's hash by its height.
  struct GETBLOCKHASH : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block_hash", "on_get_block_hash", "on_getblockhash"); }

    struct request {
      std::vector<uint64_t> height; // Block height (int array of length 1).

      // epee serialization; this is a bit hacky because epee serialization makes things hacky.
      bool load(epee::serialization::portable_storage& ps, epee::serialization::section* hparent_section = nullptr);
      bool store(epee::serialization::portable_storage& ps, epee::serialization::section* hparent_section = nullptr);
    };

    using response = std::string;          // Block hash (string).
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get a block template on which mining a new block.
  struct GETBLOCKTEMPLATE : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block_template", "getblocktemplate"); }

    struct request
    {
      uint64_t reserve_size;      // Max 255 bytes
      std::string wallet_address; // Address of wallet to receive coinbase transactions if block is successfully mined.
      std::string prev_block;
      std::string extra_nonce;

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      uint64_t difficulty;         // Difficulty of next block.
      uint64_t height;             // Height on which to mine.
      uint64_t reserved_offset;    // Reserved offset.
      uint64_t expected_reward;    // Coinbase reward expected to be received if block is successfully mined.
      std::string prev_hash;       // Hash of the most recent block on which to mine the next block.
      std::string seed_hash;       // RandomX current seed hash
      std::string next_seed_hash;  // RandomX upcoming seed hash
      blobdata blocktemplate_blob; // Blob on which to try to mine a new block.
      blobdata blockhashing_blob;  // Blob on which to try to find a valid nonce.
      std::string status;          // General RPC error code. "OK" means everything looks good.
      bool untrusted;              // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Submit a mined block to the network.
  struct SUBMITBLOCK : PUBLIC
  {
    static constexpr auto names() { return NAMES("submit_block", "submitblock"); }

    struct request {
      std::vector<std::string> blob; // Block blob data - array containing exactly one block blob string which has been mined. See get_block_template to get a blob on which to mine.

      // epee serialization; this is a bit hacky because epee serialization makes things hacky.
      bool load(epee::serialization::portable_storage& ps, epee::serialization::section* hparent_section = nullptr);
      bool store(epee::serialization::portable_storage& ps, epee::serialization::section* hparent_section = nullptr);
    };
    struct response : STATUS {};
  };

  LOKI_RPC_DOC_INTROSPECT
  // Developer only.
  struct GENERATEBLOCKS : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("generateblocks"); }

    struct request
    {
      uint64_t amount_of_blocks;
      std::string wallet_address;
      std::string prev_block;
      uint32_t starting_nonce;

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      uint64_t height;
      std::vector<std::string> blocks;
      std::string status; // General RPC error code. "OK" means everything looks good.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  struct block_header_response
  {
      uint8_t major_version;                  // The major version of the loki protocol at this block height.
      uint8_t minor_version;                  // The minor version of the loki protocol at this block height.
      uint64_t timestamp;                     // The unix time at which the block was recorded into the blockchain.
      std::string prev_hash;                  // The hash of the block immediately preceding this block in the chain.
      uint32_t nonce;                         // A cryptographic random one-time number used in mining a Loki block.
      bool orphan_status;                     // Usually `false`. If `true`, this block is not part of the longest chain.
      uint64_t height;                        // The number of blocks preceding this block on the blockchain.
      uint64_t depth;                         // The number of blocks succeeding this block on the blockchain. A larger number means an older block.
      std::string hash;                       // The hash of this block.
      difficulty_type difficulty;             // The strength of the Loki network based on mining power.
      difficulty_type cumulative_difficulty;  // The cumulative strength of the Loki network based on mining power.
      uint64_t reward;                        // The amount of new generated in this block and rewarded to the miner, foundation and service Nodes. Note: 1 LOKI = 1e9 atomic units.
      uint64_t miner_reward;                  // The amount of new generated in this block and rewarded to the miner. Note: 1 LOKI = 1e9 atomic units.
      uint64_t block_size;                    // The block size in bytes.
      uint64_t block_weight;                  // The block weight in bytes.
      uint64_t num_txes;                      // Number of transactions in the block, not counting the coinbase tx.
      std::optional<std::string> pow_hash;    // The hash of the block's proof of work (requires `fill_pow_hash`)
      uint64_t long_term_weight;              // Long term weight of the block.
      std::string miner_tx_hash;              // The TX hash of the miner transaction
      std::vector<std::string> tx_hashes;     // The TX hashes of all non-coinbase transactions (requires `get_tx_hashes`)
      std::string service_node_winner;        // Service node that received a reward for this block

      KV_MAP_SERIALIZABLE
  };

  LOKI_RPC_DOC_INTROSPECT
  // Block header information for the most recent block is easily retrieved with this method. No inputs are needed.
  struct GET_LAST_BLOCK_HEADER : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_last_block_header", "getlastblockheader"); }

    struct request
    {
      bool fill_pow_hash; // Tell the daemon if it should fill out pow_hash field.
      bool get_tx_hashes; // If true (default false) then include the hashes of non-coinbase transactions

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;                 // General RPC error code. "OK" means everything looks good.
      block_header_response block_header; // A structure containing block header information.
      bool untrusted;                     // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Block header information can be retrieved using either a block's hash or height. This method includes a block's hash as an input parameter to retrieve basic information about the block.
  struct GET_BLOCK_HEADER_BY_HASH : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block_header_by_hash", "getblockheaderbyhash"); }

    struct request
    {
      std::string hash;   // The block's SHA256 hash.
      std::vector<std::string> hashes; // Request multiple blocks via an array of hashes
      bool fill_pow_hash; // Tell the daemon if it should fill out pow_hash field.
      bool get_tx_hashes; // If true (default false) then include the hashes of non-coinbase transactions

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;                 // General RPC error code. "OK" means everything looks good.
      std::optional<block_header_response> block_header; // Block header information for the requested `hash` block
      std::vector<block_header_response> block_headers;  // Block header information for the requested `hashes` blocks
      bool untrusted;                     // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Similar to get_block_header_by_hash above, this method includes a block's height as an input parameter to retrieve basic information about the block.
  struct GET_BLOCK_HEADER_BY_HEIGHT : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block_header_by_height", "getblockheaderbyheight"); }

    struct request
    {
      std::optional<uint64_t> height; // A block height to look up; returned in `block_header`
      std::vector<uint64_t> heights;  // Block heights to retrieve; returned in `block_headers`
      bool fill_pow_hash; // Tell the daemon if it should fill out pow_hash field.
      bool get_tx_hashes; // If true (default false) then include the hashes of non-coinbase transactions

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;                 // General RPC error code. "OK" means everything looks good.
      std::optional<block_header_response> block_header; // Block header information for the requested `height` block
      std::vector<block_header_response> block_headers;  // Block header information for the requested `heights` blocks
      bool untrusted;                     // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Full block information can be retrieved by either block height or hash, like with the above block header calls.
  // For full block information, both lookups use the same method, but with different input parameters.
  struct GET_BLOCK : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block", "getblock"); }

    struct request
    {
      std::string hash;   // The block's hash.
      uint64_t height;    // The block's height.
      bool fill_pow_hash; // Tell the daemon if it should fill out pow_hash field.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;                 // General RPC error code. "OK" means everything looks good.
      block_header_response block_header; // A structure containing block header information. See get_last_block_header.
      std::vector<std::string> tx_hashes; // List of hashes of non-coinbase transactions in the block. If there are no other transactions, this will be an empty list.
      std::string blob;                   // Hexadecimal blob of block information.
      std::string json;                   // JSON formatted block details.
      bool untrusted;                     // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get the known peers list.
  struct GET_PEER_LIST : LEGACY
  {
    static constexpr auto names() { return NAMES("get_peer_list"); }

    struct request
    {
      bool public_only;
      KV_MAP_SERIALIZABLE
    };

    struct peer
    {
      uint64_t id;           // Peer id.
      std::string host;      // IP address in string format.
      uint32_t ip;           // IP address in integer format.
      uint16_t port;         // TCP port the peer is using to connect to loki network.
      uint16_t rpc_port;     // RPC port the peer is using
      uint64_t last_seen;    // Unix time at which the peer has been seen for the last time
      uint32_t pruning_seed; //

      peer() = default;

      peer(uint64_t id, const std::string &host, uint64_t last_seen, uint32_t pruning_seed, uint16_t rpc_port)
        : id(id), host(host), ip(0), port(0), rpc_port(rpc_port), last_seen(last_seen), pruning_seed(pruning_seed)
      {}
      peer(uint64_t id, const std::string &host, uint16_t port, uint64_t last_seen, uint32_t pruning_seed, uint16_t rpc_port)
        : id(id), host(host), ip(0), port(port), rpc_port(rpc_port), last_seen(last_seen), pruning_seed(pruning_seed)
      {}
      peer(uint64_t id, uint32_t ip, uint16_t port, uint64_t last_seen, uint32_t pruning_seed, uint16_t rpc_port)
        : id(id), host(epee::string_tools::get_ip_string_from_int32(ip)), ip(ip), port(port), rpc_port(rpc_port), last_seen(last_seen), pruning_seed(pruning_seed)
      {}

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;           // General RPC error code. "OK" means everything looks good. Any other value means that something went wrong.
      std::vector<peer> white_list; // Array of online peer structure.
      std::vector<peer> gray_list;  // Array of offline peer structure.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  struct public_node
  {
    std::string host;
    uint64_t last_seen;
    uint16_t rpc_port;

    public_node() = default;
    public_node(const GET_PEER_LIST::peer &peer) : host(peer.host), last_seen(peer.last_seen), rpc_port(peer.rpc_port) {}

    KV_MAP_SERIALIZABLE
  };

  LOKI_RPC_DOC_INTROSPECT
  // Query the daemon's peerlist and retrieve peers who have set their public rpc port.
  struct GET_PUBLIC_NODES : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_public_nodes"); }

    struct request
    {
      bool gray; // Get peers that have recently gone offline.
      bool white; // Get peers that are online

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status; // General RPC error code. "OK" means everything looks good. Any other value means that something went wrong.
      std::vector<public_node> gray; // Graylist peers
      std::vector<public_node> white; // Whitelist peers

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Set the log hash rate display mode.
  struct SET_LOG_HASH_RATE : LEGACY
  {
    static constexpr auto names() { return NAMES("set_log_hash_rate"); }

    struct request
    {
      bool visible; // States if hash rate logs should be visible (true) or hidden (false)

      KV_MAP_SERIALIZABLE
    };

    struct response : STATUS {};
  };

  LOKI_RPC_DOC_INTROSPECT
  // Set the daemon log level. By default, log level is set to `0`.  For more fine-tuned logging
  // control set the set_log_categories command instead.
  struct SET_LOG_LEVEL : LEGACY
  {
    static constexpr auto names() { return NAMES("set_log_level"); }

    struct request
    {
      int8_t level; // Daemon log level to set from `0` (less verbose) to `4` (most verbose)

      KV_MAP_SERIALIZABLE
    };

    struct response : STATUS {};
  };

  LOKI_RPC_DOC_INTROSPECT
  // Set the daemon log categories. Categories are represented as a comma separated list of `<Category>:<level>` (similarly to syslog standard `<Facility>:<Severity-level>`), where:
  // Category is one of the following: * (all facilities), default, net, net.http, net.p2p, logging, net.trottle, blockchain.db, blockchain.db.lmdb, bcutil, checkpoints, net.dns, net.dl,
  // i18n, perf,stacktrace, updates, account, cn ,difficulty, hardfork, miner, blockchain, txpool, cn.block_queue, net.cn, daemon, debugtools.deserialize, debugtools.objectsizes, device.ledger,
  // wallet.gen_multisig, multisig, bulletproofs, ringct, daemon.rpc, wallet.simplewallet, WalletAPI, wallet.ringdb, wallet.wallet2, wallet.rpc, tests.core.
  //
  // Level is one of the following: FATAL - higher level, ERROR, WARNING, INFO, DEBUG, TRACE.
  // Lower level A level automatically includes higher level. By default, categories are set to:
  // `*:WARNING,net:FATAL,net.p2p:FATAL,net.cn:FATAL,global:INFO,verify:FATAL,stacktrace:INFO,logging:INFO,msgwriter:INFO`
  // Setting the categories to "" prevent any logs to be outputed.
  //
  // You can append to the current the log level for updating just one or more categories while
  // leaving other log levels unchanged by specifying one or more "<category>:<level>" pairs
  // preceded by a "+", for example "+difficulty:DEBUG,net:WARNING".
  struct SET_LOG_CATEGORIES : LEGACY
  {
    static constexpr auto names() { return NAMES("set_log_categories"); }

    struct request
    {
      std::string categories; // Optional, daemon log categories to enable

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;     // General RPC error code. "OK" means everything looks good. Any other value means that something went wrong.
      std::string categories; // Daemon log enabled categories

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  struct tx_info
  {
    std::string id_hash;                // The transaction ID hash.
    std::string tx_json;                // JSON structure of all information in the transaction
    uint64_t blob_size;                 // The size of the full transaction blob.
    uint64_t weight;                    // The weight of the transaction.
    uint64_t fee;                       // The amount of the mining fee included in the transaction, in atomic units.
    std::string max_used_block_id_hash; // Tells the hash of the most recent block with an output used in this transaction.
    uint64_t max_used_block_height;     // Tells the height of the most recent block with an output used in this transaction.
    bool kept_by_block;                 // States if the tx was included in a block at least once (`true`) or not (`false`).
    uint64_t last_failed_height;        // If the transaction validation has previously failed, this tells at what height that occured.
    std::string last_failed_id_hash;    // Like the previous, this tells the previous transaction ID hash.
    uint64_t receive_time;              // The Unix time that the transaction was first seen on the network by the node.
    bool relayed;                       // States if this transaction has been relayed
    uint64_t last_relayed_time;         // Last unix time at which the transaction has been relayed.
    bool do_not_relay;                  // States if this transaction should not be relayed.
    bool double_spend_seen;             // States if this transaction has been seen as double spend.
    std::string tx_blob;                // Hexadecimal blob represnting the transaction.
    bool blink;                         // True if this is a signed blink transaction
    std::optional<GET_TRANSACTIONS::extra_entry> extra; // Parsed tx_extra information (only if requested)

    KV_MAP_SERIALIZABLE
  };

  LOKI_RPC_DOC_INTROSPECT
  struct spent_key_image_info
  {
    std::string id_hash;                 // Key image.
    std::vector<std::string> txs_hashes; // List of tx hashes of the txes (usually one) spending that key image.

    KV_MAP_SERIALIZABLE
  };

  LOKI_RPC_DOC_INTROSPECT
  // Show information about valid transactions seen by the node but not yet mined into a block,
  // as well as spent key image information for the txpool in the node's memory.
  struct GET_TRANSACTION_POOL : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("get_transaction_pool"); }

    struct request
    {
      bool tx_extra;                       // Parse tx-extra information and adds it to the `extra` field.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;                                 // General RPC error code. "OK" means everything looks good.
      std::vector<tx_info> transactions;                  // List of transactions in the mempool are not in a block on the main chain at the moment:
      std::vector<spent_key_image_info> spent_key_images; // List of spent output key images:
      bool untrusted;                                     // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get hashes from transaction pool. Binary request.
  struct GET_TRANSACTION_POOL_HASHES_BIN : PUBLIC, BINARY
  {
    static constexpr auto names() { return NAMES("get_transaction_pool_hashes.bin"); }

    static constexpr std::chrono::seconds long_poll_timeout{15};

    struct request
    {
      bool         blinked_txs_only; // Optional: If true only transactions that were sent via blink and approved are queried.
      bool         long_poll;        // Optional: If true, this call is blocking until timeout OR tx pool has changed since the last query. TX pool change is detected by comparing the hash of all the hashes in the tx pool.  Ignored when using LMQ RPC.
      crypto::hash tx_pool_checksum; // Optional: If `long_poll` is true the caller must pass the hashes of all their known tx pool hashes, XOR'ed together.  Ignored when using LMQ RPC.
      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;                  // General RPC error code. "OK" means everything looks good.
      std::vector<crypto::hash> tx_hashes; // List of transaction hashes,
      bool untrusted;                      // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get hashes from transaction pool.
  struct GET_TRANSACTION_POOL_HASHES : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("get_transaction_pool_hashes"); }

    struct request : EMPTY {};
    struct response
    {
      std::string status;                 // General RPC error code. "OK" means everything looks good.
      std::vector<std::string> tx_hashes; // List of transaction hashes,
      bool untrusted;                     // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  struct tx_backlog_entry
  {
    uint64_t weight;       //
    uint64_t fee;          // Fee in Loki measured in atomic units.
    uint64_t time_in_pool;
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get all transaction pool backlog.
  struct GET_TRANSACTION_POOL_BACKLOG : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_txpool_backlog"); }

    struct request : EMPTY {};

    struct response
    {
      std::string status;                    // General RPC error code. "OK" means everything looks good.
      std::vector<tx_backlog_entry> backlog; // Array of structures tx_backlog_entry (in binary form):
      bool untrusted;                        // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  struct txpool_histo
  {
    uint32_t txs;   // Number of transactions.
    uint64_t bytes; // Size in bytes.

    KV_MAP_SERIALIZABLE
  };

  LOKI_RPC_DOC_INTROSPECT
  struct txpool_stats
  {
    uint64_t bytes_total;            // Total size of all transactions in pool.
    uint32_t bytes_min;              // Min transaction size in pool.
    uint32_t bytes_max;              // Max transaction size in pool.
    uint32_t bytes_med;              // Median transaction size in pool.
    uint64_t fee_total;              // Total fee's in pool in atomic units.
    uint64_t oldest;                 // Unix time of the oldest transaction in the pool.
    uint32_t txs_total;              // Total number of transactions.
    uint32_t num_failing;            // Bumber of failing transactions.
    uint32_t num_10m;                // Number of transactions in pool for more than 10 minutes.
    uint32_t num_not_relayed;        // Number of non-relayed transactions.
    uint64_t histo_98pc;             // the time 98% of txes are "younger" than.
    std::vector<txpool_histo> histo; // List of txpool histo.
    uint32_t num_double_spends;      // Number of double spend transactions.

    txpool_stats(): bytes_total(0), bytes_min(0), bytes_max(0), bytes_med(0), fee_total(0), oldest(0), txs_total(0), num_failing(0), num_10m(0), num_not_relayed(0), histo_98pc(0), num_double_spends(0) {}

    KV_MAP_SERIALIZABLE
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get the transaction pool statistics.
  struct GET_TRANSACTION_POOL_STATS : PUBLIC, LEGACY
  {
    static constexpr auto names() { return NAMES("get_transaction_pool_stats"); }

    struct request : EMPTY {};

    struct response
    {
      std::string status;      // General RPC error code. "OK" means everything looks good.
      txpool_stats pool_stats; // List of pool stats:
      bool untrusted;          // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Retrieve information about incoming and outgoing connections to your node.
  struct GET_CONNECTIONS : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_connections"); }

    struct request : EMPTY {};

    struct response
    {
      std::string status; // General RPC error code. "OK" means everything looks good.
      std::list<connection_info> connections; // List of all connections and their info:

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Similar to get_block_header_by_height above, but for a range of blocks.
  // This method includes a starting block height and an ending block height as
  // parameters to retrieve basic information about the range of blocks.
  struct GET_BLOCK_HEADERS_RANGE : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_block_headers_range", "getblockheadersrange"); }

    struct request
    {
      uint64_t start_height; // The starting block's height.
      uint64_t end_height;   // The ending block's height.
      bool fill_pow_hash;    // Tell the daemon if it should fill out pow_hash field.
      bool get_tx_hashes;    // If true (default false) then include the hashes or txes in the block details

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;                         // General RPC error code. "OK" means everything looks good.
      std::vector<block_header_response> headers; // Array of block_header (a structure containing block header information. See get_last_block_header).
      bool untrusted;                             // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Set the bootstrap daemon to use for data on the blockchain whilst syncing the chain.
  struct SET_BOOTSTRAP_DAEMON : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("set_bootstrap_daemon"); }
    struct request
    {

      std::string address;
      std::string username;
      std::string password;

      KV_MAP_SERIALIZABLE
    };

    struct response : STATUS {};
  };

  LOKI_RPC_DOC_INTROSPECT
  // Send a command to the daemon to safely disconnect and shut down.
  struct STOP_DAEMON : LEGACY
  {
    static constexpr auto names() { return NAMES("stop_daemon"); }

    struct request : EMPTY {};
    struct response : STATUS {};
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get daemon bandwidth limits.
  struct GET_LIMIT : LEGACY
  {
    static constexpr auto names() { return NAMES("get_limit"); }

    struct request : EMPTY {};

    struct response
    {
      std::string status;  // General RPC error code. "OK" means everything looks good.
      uint64_t limit_up;   // Upload limit in kBytes per second.
      uint64_t limit_down; // Download limit in kBytes per second.
      bool untrusted;      // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Set daemon bandwidth limits.
  struct SET_LIMIT : LEGACY
  {
    static constexpr auto names() { return NAMES("set_limit"); }

    struct request
    {
      int64_t limit_down;  // Download limit in kBytes per second (-1 reset to default, 0 don't change the current limit)
      int64_t limit_up;    // Upload limit in kBytes per second (-1 reset to default, 0 don't change the current limit)

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status; // General RPC error code. "OK" means everything looks good.
      int64_t limit_up;   // Upload limit in kBytes per second.
      int64_t limit_down; // Download limit in kBytes per second.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Limit number of Outgoing peers.
  struct OUT_PEERS : LEGACY
  {
    static constexpr auto names() { return NAMES("out_peers"); }

    struct request
    {
      bool set; // If true, set the number of outgoing peers, otherwise the response returns the current limit of outgoing peers. (Defaults to true)
	  uint32_t out_peers; // Max number of outgoing peers
      KV_MAP_SERIALIZABLE
    };

    struct response {
      uint32_t out_peers; // The current limit set for outgoing peers
      std::string status; // General RPC error code. "OK" means everything looks good.
      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Limit number of Incoming peers.
  struct IN_PEERS : LEGACY
  {
    static constexpr auto names() { return NAMES("in_peers"); }

    struct request
    {
      bool set; // If true, set the number of incoming peers, otherwise the response returns the current limit of incoming peers. (Defaults to true)
      uint32_t in_peers; // Max number of incoming peers
      KV_MAP_SERIALIZABLE
    };

    struct response {
      uint32_t in_peers; // The current limit set for outgoing peers
      std::string status; // General RPC error code. "OK" means everything looks good.
      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Look up information regarding hard fork voting and readiness.
  struct HARD_FORK_INFO : PUBLIC
  {
    static constexpr auto names() { return NAMES("hard_fork_info"); }

    struct request
    {
      uint8_t version; // The major block version for the fork.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      uint8_t version;          // The major block version for the fork.
      bool enabled;             // Tells if hard fork is enforced.
      uint32_t window;          // Number of blocks over which current votes are cast. Default is 10080 blocks.
      uint32_t votes;           // Number of votes towards hard fork.
      uint32_t threshold;       // Minimum percent of votes to trigger hard fork. Default is 80.
      uint8_t voting;           // Hard fork voting status.
      uint32_t state;           // Current hard fork state: 0 (There is likely a hard fork), 1 (An update is needed to fork properly), or 2 (Everything looks good).
      uint64_t earliest_height; // Block height at which hard fork would be enabled if voted in.
      std::string status;       // General RPC error code. "OK" means everything looks good.
      bool untrusted;           // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get list of banned IPs.
  struct GETBANS : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_bans"); }

    struct request : EMPTY {};

    struct ban
    {
      std::string host; // Banned host (IP in A.B.C.D form).
      uint32_t ip;      // Banned IP address, in Int format.
      uint32_t seconds; // Local Unix time that IP is banned until.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;    // General RPC error code. "OK" means everything looks good.
      std::vector<ban> bans; // List of banned nodes:

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Ban another node by IP.
  struct SETBANS : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("set_bans"); }

    struct ban
    {
      std::string host; // Host to ban (IP in A.B.C.D form - will support I2P address in the future).
      uint32_t ip;      // IP address to ban, in Int format.
      bool ban;         // Set true to ban.
      uint32_t seconds; // Number of seconds to ban node.

      KV_MAP_SERIALIZABLE
    };

    struct request
    {
      std::vector<ban> bans; // List of nodes to ban.

      KV_MAP_SERIALIZABLE
    };

    struct response : STATUS {};
  };

  LOKI_RPC_DOC_INTROSPECT
  // Determine whether a given IP address is banned
  struct BANNED : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("banned"); }

    struct request
    {
      std::string address; // The IP address to check

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status; // General RPC error code. "OK" means everything looks good.
      bool banned;        // True if the given address is banned, false otherwise.
      uint32_t seconds;   // The number of seconds remaining in the ban.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Flush tx ids from transaction pool..
  struct FLUSH_TRANSACTION_POOL : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("flush_txpool"); }

    struct request
    {
      std::vector<std::string> txids; // Optional, list of transactions IDs to flush from pool (all tx ids flushed if empty).

      KV_MAP_SERIALIZABLE
    };

    struct response : STATUS {};
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get a histogram of output amounts. For all amounts (possibly filtered by parameters),
  // gives the number of outputs on the chain for that amount. RingCT outputs counts as 0 amount.
  struct GET_OUTPUT_HISTOGRAM : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_output_histogram"); }

    struct request
    {
      std::vector<uint64_t> amounts; // list of amounts in Atomic Units.
      uint64_t min_count;            // The minimum amounts you are requesting.
      uint64_t max_count;            // The maximum amounts you are requesting.
      bool unlocked;                 // Look for locked only.
      uint64_t recent_cutoff;

      KV_MAP_SERIALIZABLE
    };

    struct entry
    {
      uint64_t amount;            // Output amount in atomic units.
      uint64_t total_instances;
      uint64_t unlocked_instances;
      uint64_t recent_instances;

      KV_MAP_SERIALIZABLE

      entry(uint64_t amount, uint64_t total_instances, uint64_t unlocked_instances, uint64_t recent_instances):
          amount(amount), total_instances(total_instances), unlocked_instances(unlocked_instances), recent_instances(recent_instances) {}
      entry() = default;
    };

    struct response
    {
      std::string status;           // General RPC error code. "OK" means everything looks good.
      std::vector<entry> histogram; // List of histogram entries:
      bool untrusted;               // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get current RPC protocol version.
  struct GET_VERSION : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_version"); }

    struct request : EMPTY {};

    struct response
    {
      std::string status; // General RPC error code. "OK" means everything looks good.
      uint32_t version;   // RPC current version.
      bool untrusted;     // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get the coinbase amount and the fees amount for n last blocks starting at particular height.
  struct GET_COINBASE_TX_SUM : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_coinbase_tx_sum"); }

    struct request
    {
      uint64_t height; // Block height from which getting the amounts.
      uint64_t count;  // Number of blocks to include in the sum.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;       // General RPC error code. "OK" means everything looks good.
      uint64_t emission_amount; // Amount of coinbase reward in atomic units.
      uint64_t fee_amount;      // Amount of fees in atomic units.
      uint64_t burn_amount;      // Amount of burnt loki.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Gives an estimation of per-output + per-byte fees
  struct GET_BASE_FEE_ESTIMATE : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_fee_estimate"); }

    struct request
    {
      uint64_t grace_blocks; // Optional

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;         // General RPC error code. "OK" means everything looks good.
      uint64_t fee_per_byte;      // Amount of fees estimated per byte in atomic units
      uint64_t fee_per_output;    // Amount of fees per output generated by the tx (adds to the `fee_per_byte` per-byte value)
      uint64_t blink_fee_per_byte;   // `fee_per_byte` value for sending a blink. The portion of the overall blink fee above the overall base fee is burned.
      uint64_t blink_fee_per_output; // `fee_per_output` value for sending a blink. The portion of the overall blink fee above the overall base fee is burned.
      uint64_t blink_fee_fixed;      // Fixed blink fee in addition to the per-output and per-byte amounts. The portion of the overall blink fee above the overall base fee is burned.
      uint64_t quantization_mask;
      bool untrusted;             // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Display alternative chains seen by the node.
  struct GET_ALTERNATE_CHAINS : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_alternative_chains"); }

    struct request : EMPTY {};

    struct chain_info
    {
      std::string block_hash;                // The block hash of the first diverging block of this alternative chain.
      uint64_t height;                       // The block height of the first diverging block of this alternative chain.
      uint64_t length;                       // The length in blocks of this alternative chain, after divergence.
      uint64_t difficulty;                   // The cumulative difficulty of all blocks in the alternative chain.
      std::vector<std::string> block_hashes;
      std::string main_chain_parent_block;

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;             // General RPC error code. "OK" means everything looks good.
      std::vector<chain_info> chains; // Array of Chains.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Relay a list of transaction IDs.
  struct RELAY_TX : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("relay_tx"); }

    struct request
    {
      std::vector<std::string> txids; // List of transactions IDs to relay from pool.

      KV_MAP_SERIALIZABLE
    };

    struct response : STATUS {};
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get synchronisation information.
  struct SYNC_INFO : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("sync_info"); }

    struct request : EMPTY {};

    struct peer
    {
      connection_info info; // Structure of connection info, as defined in get_connections.

      KV_MAP_SERIALIZABLE
    };

    struct span
    {
      uint64_t start_block_height; // Block height of the first block in that span.
      uint64_t nblocks;            // Number of blocks in that span.
      std::string connection_id;   // Id of connection.
      uint32_t rate;               // Connection rate.
      uint32_t speed;              // Connection speed.
      uint64_t size;               // Total number of bytes in that span's blocks (including txes).
      std::string remote_address;  // Peer address the node is downloading (or has downloaded) than span from.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;                // General RPC error code. "OK" means everything looks good. Any other value means that something went wrong.
      uint64_t height;                   // Block height.
      uint64_t target_height;            // Target height the node is syncing from (optional, absent if node is fully synced).
      uint32_t next_needed_pruning_seed;
      std::list<peer> peers;             // Array of Peer structure
      std::list<span> spans;             // Array of Span Structure.
      std::string overview;

      KV_MAP_SERIALIZABLE
    };
  };

  struct output_distribution_data
  {
    std::vector<std::uint64_t> distribution;
    std::uint64_t start_height;
    std::uint64_t base;
  };


  LOKI_RPC_DOC_INTROSPECT
  struct GET_OUTPUT_DISTRIBUTION : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_output_distribution"); }

    struct request
    {
      std::vector<uint64_t> amounts; // Amounts to look for in atomic units.
      uint64_t from_height;          // (optional, default is 0) starting height to check from.
      uint64_t to_height;            // (optional, default is 0) ending height to check up to.
      bool cumulative;               // (optional, default is false) States if the result should be cumulative (true) or not (false).
      bool binary;
      bool compress;

      KV_MAP_SERIALIZABLE
    };

    struct distribution
    {
      rpc::output_distribution_data data;
      uint64_t amount;
      std::string compressed_data;
      bool binary;
      bool compress;

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;                      // General RPC error code. "OK" means everything looks good.
      std::vector<distribution> distributions; //
      bool untrusted;                          // States if the result is obtained using the bootstrap mode, and is therefore not trusted (`true`), or when the daemon is fully synced (`false`).

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Exactly like GET_OUTPUT_DISTRIBUTION, but does a binary RPC transfer instead of JSON
  struct GET_OUTPUT_DISTRIBUTION_BIN : PUBLIC, BINARY
  {
    static constexpr auto names() { return NAMES("get_output_distribution.bin"); }

    struct request : GET_OUTPUT_DISTRIBUTION::request {};
    using response = GET_OUTPUT_DISTRIBUTION::response;
  };

  LOKI_RPC_DOC_INTROSPECT
  struct POP_BLOCKS : LEGACY
  {
    static constexpr auto names() { return NAMES("pop_blocks"); }

    struct request
    {
      uint64_t nblocks; // Number of blocks in that span.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status; // General RPC error code. "OK" means everything looks good.
      uint64_t height;

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  struct PRUNE_BLOCKCHAIN : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("prune_blockchain"); }

    struct request
    {
      bool check;

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      bool pruned;
      uint32_t pruning_seed;
      std::string status;

      KV_MAP_SERIALIZABLE
    };
  };


  LOKI_RPC_DOC_INTROSPECT
  // Accesses the list of public keys of the nodes who are participating or being tested in a quorum.
  struct GET_QUORUM_STATE : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_quorum_state"); }

    static constexpr size_t MAX_COUNT = 256;
    static constexpr uint64_t HEIGHT_SENTINEL_VALUE = UINT64_MAX;
    static constexpr uint8_t ALL_QUORUMS_SENTINEL_VALUE = 255;
    struct request
    {
      uint64_t start_height; // (Optional): Start height, omit both start and end height to request the latest quorum. Note that "latest" means different heights for different types of quorums as not all quorums exist at every block heights.
      uint64_t end_height;   // (Optional): End height, omit both start and end height to request the latest quorum
      uint8_t  quorum_type;  // (Optional): Set value to request a specific quorum, 0 = Obligation, 1 = Checkpointing, 2 = Blink, 3 = Pulse, 255 = all quorums, default is all quorums. For Pulse quorums, requesting the blockchain height (or latest) returns the primary pulse quorum responsible for the next block; for heights with blocks this returns the actual quorum, which may be a backup quorum if the primary quorum did not produce in time.

      KV_MAP_SERIALIZABLE
    };

    struct quorum_t
    {
      std::vector<std::string> validators; // List of service node public keys in the quorum. For obligations quorums these are the testing nodes; for checkpoint and blink these are the participating nodes (there are no workers); for Pulse blink quorums these are the block signers.
      std::vector<std::string> workers; // Public key of the quorum workers. For obligations quorums these are the nodes being tested; for Pulse quorums this is the block producer. Checkpoint and Blink quorums do not populate this field.

      KV_MAP_SERIALIZABLE

      BEGIN_SERIALIZE() // NOTE: For store_t_to_json
        FIELD(validators)
        FIELD(workers)
      END_SERIALIZE()
    };

    struct quorum_for_height
    {
      uint64_t height;          // The height the quorums are relevant for
      uint8_t  quorum_type;     // The quorum type
      quorum_t quorum;          // Quorum of Service Nodes

      KV_MAP_SERIALIZABLE

      BEGIN_SERIALIZE() // NOTE: For store_t_to_json
        FIELD(height)
        FIELD(quorum_type)
        FIELD(quorum)
      END_SERIALIZE()
    };

    struct response
    {
      std::string status;                     // Generic RPC error code. "OK" is the success value.
      std::vector<quorum_for_height> quorums; // An array of quorums associated with the requested height
      bool untrusted;                         // If the result is obtained using bootstrap mode, and therefore not trusted `true`, or otherwise `false`.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  struct GET_SERVICE_NODE_REGISTRATION_CMD_RAW : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_service_node_registration_cmd_raw"); }

    struct request
    {
      std::vector<std::string> args; // (Developer) The arguments used in raw registration, i.e. portions
      bool make_friendly;            // Provide information about how to use the command in the result.
      uint64_t staking_requirement;  // The staking requirement to become a Service Node the registration command will be generated upon

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;           // Generic RPC error code. "OK" is the success value.
      std::string registration_cmd; // The command to execute in the wallet CLI to register the queried daemon as a Service Node.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  struct GET_SERVICE_NODE_REGISTRATION_CMD : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_service_node_registration_cmd"); }

    struct contribution_t
    {
      std::string address; // The wallet address for the contributor
      uint64_t amount;     // The amount that the contributor will reserve in Loki atomic units towards the staking requirement

      KV_MAP_SERIALIZABLE
    };

    struct request
    {
      std::string operator_cut;                  // The percentage of cut per reward the operator receives expressed as a string, i.e. "1.1%"
      std::vector<contribution_t> contributions; // Array of contributors for this Service Node
      uint64_t staking_requirement;              // The staking requirement to become a Service Node the registration command will be generated upon

      KV_MAP_SERIALIZABLE
    };

    using response = GET_SERVICE_NODE_REGISTRATION_CMD_RAW::response;
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get the service public keys of the queried daemon, encoded in hex.  All three keys are used
  // when running as a service node; when running as a regular node only the x25519 key is regularly
  // used for some RPC and and node-to-SN communication requests.
  struct GET_SERVICE_KEYS : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_service_keys", "get_service_node_key"); }

    struct request : EMPTY {};

    struct response
    {
      std::string service_node_pubkey;         // The queried daemon's service node public key.  Will be empty if not running as a service node.
      std::string service_node_ed25519_pubkey; // The daemon's ed25519 auxiliary public key.
      std::string service_node_x25519_pubkey;  // The daemon's x25519 auxiliary public key.
      std::string status;                      // Generic RPC error code. "OK" is the success value.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get the service private keys of the queried daemon, encoded in hex.  Do not ever share
  // these keys: they would allow someone to impersonate your service node.  All three keys are used
  // when running as a service node; when running as a regular node only the x25519 key is regularly
  // used for some RPC and and node-to-SN communication requests.
  struct GET_SERVICE_PRIVKEYS : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_service_privkeys", "get_service_node_privkey"); }

    struct request : EMPTY {};

    struct response
    {
      std::string service_node_privkey;         // The queried daemon's service node private key.  Will be empty if not running as a service node.
      std::string service_node_ed25519_privkey; // The daemon's ed25519 private key (note that this is in sodium's format, which consists of the private and public keys concatenated together)
      std::string service_node_x25519_privkey;  // The daemon's x25519 private key.
      std::string status;                       // Generic RPC error code. "OK" is the success value.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // TODO: Undocumented, -- unused
  struct PERFORM_BLOCKCHAIN_TEST : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("perform_blockchain_test"); }

    struct request
    {
      uint64_t max_height;
      uint64_t seed;

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;
      uint64_t res_height;

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  struct service_node_contribution
  {
    std::string key_image;         // The contribution's key image that is locked on the network.
    std::string key_image_pub_key; // The contribution's key image, public key component
    uint64_t    amount;            // The amount that is locked in this contribution.

    KV_MAP_SERIALIZABLE
  };

  LOKI_RPC_DOC_INTROSPECT
  struct service_node_contributor
  {
    uint64_t amount;                                             // The total amount of locked Loki in atomic units for this contributor.
    uint64_t reserved;                                           // The amount of Loki in atomic units reserved by this contributor for this Service Node.
    std::string address;                                         // The wallet address for this contributor rewards are sent to and contributions came from.
    std::vector<service_node_contribution> locked_contributions; // Array of contributions from this contributor.

    KV_MAP_SERIALIZABLE
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get information on some, all, or a random subset of Service Nodes.
  struct GET_SERVICE_NODES : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_service_nodes", "get_n_service_nodes", "get_all_service_nodes"); }

    // Boolean values indicate whether corresponding fields should be included in the response
    struct requested_fields_t {
      bool all = false; // If set, overrides any individual requested fields.  Defaults to *true* if "fields" is entirely omitted
      bool service_node_pubkey;
      bool registration_height;
      bool registration_hf_version;
      bool requested_unlock_height;
      bool last_reward_block_height;
      bool last_reward_transaction_index;
      bool active;
      bool funded;
      bool state_height;
      bool decommission_count;
      bool earned_downtime_blocks;

      bool service_node_version;
      bool contributors;
      bool total_contributed;
      bool total_reserved;
      bool staking_requirement;
      bool portions_for_operator;
      bool swarm_id;
      bool operator_address;
      bool public_ip;
      bool storage_port;
      bool storage_lmq_port;
      bool quorumnet_port;
      bool pubkey_ed25519;
      bool pubkey_x25519;

      bool last_uptime_proof;
      bool storage_server_reachable;
      bool storage_server_reachable_timestamp;
      bool checkpoint_participation;
      bool pulse_participation;

      bool block_hash;
      bool height;
      bool target_height;
      bool hardfork;
      KV_MAP_SERIALIZABLE
    };

    struct request
    {
      std::vector<std::string> service_node_pubkeys; // Array of public keys of registered Service Nodes to get information about. Omit to query all Service Nodes.
      bool include_json;                             // When set, the response's as_json member is filled out.
      uint32_t limit;                                // If non-zero, select a random sample (in random order) of the given number of service nodes to return from the full list.
      bool active_only;                              // If true, only include results for active (fully staked, not decommissioned) service nodes.
      std::optional<requested_fields_t> fields;      // If omitted return all fields; otherwise return only the specified fields

      std::string poll_block_hash;                   // If specified this changes the behaviour to only return service node records if the block hash is *not* equal to the given hash; otherwise it omits the records and instead sets `"unchanged": true` in the response. This is primarily used to poll for new results where the requested results only change with new blocks.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {

      struct entry {
        std::string                           service_node_pubkey;           // The public key of the Service Node.
        uint64_t                              registration_height;           // The height at which the registration for the Service Node arrived on the blockchain.
        uint16_t                              registration_hf_version;       // The hard fork at which the registration for the Service Node arrived on the blockchain.
        uint64_t                              requested_unlock_height;       // The height at which contributions will be released and the Service Node expires. 0 if not requested yet.
        uint64_t                              last_reward_block_height;      // The height that determines when this service node will next receive a reward.  This field is updated when receiving a reward, but is also updated when a SN is activated, recommissioned, or has an IP change position reset.
        uint32_t                              last_reward_transaction_index; // When multiple Service Nodes register (or become active/reactivated) at the same height (i.e. have the same last_reward_block_height), this field contains the activating transaction position in the block which is used to break ties in determining which SN is next in the reward list.
        bool                                  active;                        // True if fully funded and not currently decommissioned (and so `active && !funded` implicitly defines decommissioned)
        bool                                  funded;                        // True if the required stakes have been submitted to activate this Service Node
        uint64_t                              state_height;                  // If active: the state at which the service node became active (i.e. fully staked height, or last recommissioning); if decommissioned: the decommissioning height; if awaiting: the last contribution (or registration) height
        uint32_t                              decommission_count;            // The number of times the Service Node has been decommissioned since registration
        int64_t                               earned_downtime_blocks;        // The number of blocks earned towards decommissioning, or the number of blocks remaining until deregistration if currently decommissioned
        std::array<uint16_t, 3>               service_node_version;          // The major, minor, patch version of the Service Node respectively.
        std::vector<service_node_contributor> contributors;                  // Array of contributors, contributing to this Service Node.
        uint64_t                              total_contributed;             // The total amount of Loki in atomic units contributed to this Service Node.
        uint64_t                              total_reserved;                // The total amount of Loki in atomic units reserved in this Service Node.
        uint64_t                              staking_requirement;           // The staking requirement in atomic units that is required to be contributed to become a Service Node.
        uint64_t                              portions_for_operator;         // The operator percentage cut to take from each reward expressed in portions, see cryptonote_config.h's STAKING_PORTIONS.
        uint64_t                              swarm_id;                      // The identifier of the Service Node's current swarm.
        std::string                           operator_address;              // The wallet address of the operator to which the operator cut of the staking reward is sent to.
        std::string                           public_ip;                     // The public ip address of the service node
        uint16_t                              storage_port;                  // The port number associated with the storage server
        uint16_t                              storage_lmq_port;              // The port number associated with the storage server (lokimq interface)
        uint16_t                              quorumnet_port;                // The port for direct SN-to-SN communication
        std::string                           pubkey_ed25519;                // The service node's ed25519 public key for auxiliary services
        std::string                           pubkey_x25519;                 // The service node's x25519 public key for auxiliary services

        // Service Node Testing
        uint64_t                                last_uptime_proof;                   // The last time this Service Node's uptime proof was relayed by at least 1 Service Node other than itself in unix epoch time.
        bool                                    storage_server_reachable;            // Whether the node's storage server has been reported as unreachable for a long time
        uint64_t                                storage_server_reachable_timestamp;  // The last time this Service Node's storage server was contacted
        std::vector<service_nodes::participation_entry> checkpoint_participation;    // Of the last N checkpoints the Service Node is in a checkpointing quorum, record whether or not the Service Node voted to checkpoint a block
        std::vector<service_nodes::participation_entry> pulse_participation;         // Of the last N pulse blocks the Service Node is in a pulse quorum, record whether or not the Service Node voted (participated) in that block
        std::vector<service_nodes::timestamp_participation_entry> timestamp_participation;         // Of the last N timestamp messages, record whether or not the Service Node was in sync with the network
        std::vector<service_nodes::timesync_entry> timesync_status;         // Of the last N timestamp messages, record whether or not the Service Node responded

        KV_MAP_SERIALIZABLE
      };

      requested_fields_t fields; // @NoLokiRPCDocGen Internal use only, not serialized
      bool polling_mode;         // @NoLokiRPCDocGen Internal use only, not serialized

      std::vector<entry> service_node_states; // Array of service node registration information
      uint64_t    height;                     // Current block's height.
      uint64_t    target_height;              // Blockchain's target height.
      std::string block_hash;                 // Current block's hash.
      bool        unchanged;                  // Will be true (and `service_node_states` omitted) if you gave the current block hash to poll_block_hash
      uint8_t     hardfork;                   // Current hardfork version.
      std::string status;                     // Generic RPC error code. "OK" is the success value.
      std::string as_json;                    // If `include_json` is set in the request, this contains the json representation of the `entry` data structure

      KV_MAP_SERIALIZABLE

    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get information on the queried daemon's Service Node state.
  struct GET_SERVICE_NODE_STATUS : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("get_service_node_status"); }

    struct request
    {
      bool include_json;                             // When set, the response's as_json member is filled out.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      GET_SERVICE_NODES::response::entry service_node_state; // Service node registration information
      uint64_t    height;                     // Current block's height.
      std::string block_hash;                 // Current block's hash.
      std::string status;                     // Generic RPC error code. "OK" is the success value.
      std::string as_json;                    // If `include_json` is set in the request, this contains the json representation of the `entry` data structure

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  struct STORAGE_SERVER_PING : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("storage_server_ping"); }

    struct request
    {
      int version_major; // Storage Server Major version
      int version_minor; // Storage Server Minor version
      int version_patch; // Storage Server Patch version
      uint16_t storage_lmq_port; // Storage Server lmq port to include in uptime proofs
      KV_MAP_SERIALIZABLE
    };

    struct response : STATUS {};
  };

  LOKI_RPC_DOC_INTROSPECT
  struct LOKINET_PING : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("lokinet_ping"); }

    struct request
    {
      std::array<int, 3> version; // Lokinet version
      KV_MAP_SERIALIZABLE
    };

    struct response : STATUS {};
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get the required amount of Loki to become a Service Node at the queried height.
  // For devnet and testnet values, ensure the daemon is started with the
  // `--devnet` or `--testnet` flags respectively.
  struct GET_STAKING_REQUIREMENT : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_staking_requirement"); }

    struct request
    {
      uint64_t height; // The height to query the staking requirement for.  0 (or omitting) means current height.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      uint64_t staking_requirement; // The staking requirement in Loki, in atomic units.
      uint64_t height;              // The height requested (or current height if 0 was requested)
      std::string status;           // Generic RPC error code. "OK" is the success value.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get information on blacklisted Service Node key images.
  struct GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_service_node_blacklisted_key_images"); }

    struct request : EMPTY {};

    struct entry
    {
      std::string key_image;  // The key image of the transaction that is blacklisted on the network.
      uint64_t unlock_height; // The height at which the key image is removed from the blacklist and becomes spendable.
      uint64_t amount;        // The total amount of locked Loki in atomic units in this blacklisted stake.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::vector<entry> blacklist; // Array of blacklisted key images, i.e. unspendable transactions
      std::string status;           // Generic RPC error code. "OK" is the success value.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get information on output blacklist.
  struct GET_OUTPUT_BLACKLIST : PUBLIC, BINARY
  {
    static constexpr auto names() { return NAMES("get_output_blacklist.bin"); }
    struct request : EMPTY {};

    struct response
    {
      std::vector<uint64_t> blacklist; // (Developer): Array of indexes from the global output list, corresponding to blacklisted key images.
      std::string status;              // Generic RPC error code. "OK" is the success value.
      bool untrusted;                  // If the result is obtained using bootstrap mode, and therefore not trusted `true`, or otherwise `false`.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Query hardcoded/service node checkpoints stored for the blockchain. Omit all arguments to retrieve the latest "count" checkpoints.
  struct GET_CHECKPOINTS : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_checkpoints"); }

    static constexpr size_t MAX_COUNT = 256;
    static constexpr uint32_t NUM_CHECKPOINTS_TO_QUERY_BY_DEFAULT = 60;
    static constexpr uint64_t HEIGHT_SENTINEL_VALUE               = std::numeric_limits<uint64_t>::max() - 1;
    struct request
    {
      uint64_t start_height; // Optional: Get the first count checkpoints starting from this height. Specify both start and end to get the checkpoints inbetween.
      uint64_t end_height;   // Optional: Get the first count checkpoints before end height. Specify both start and end to get the checkpoints inbetween.
      uint32_t count;        // Optional: Number of checkpoints to query.

      KV_MAP_SERIALIZABLE
    };

    struct quorum_signature_serialized
    {
      uint16_t voter_index;  // Index of the voter in the relevant quorum
      std::string signature; // The signature generated by the voter in the quorum

      quorum_signature_serialized() = default;
      quorum_signature_serialized(service_nodes::quorum_signature const &entry)
      : voter_index(entry.voter_index)
      , signature(tools::type_to_hex(entry.signature)) { }

      KV_MAP_SERIALIZABLE

      BEGIN_SERIALIZE() // NOTE: For store_t_to_json
        FIELD(voter_index)
        FIELD(signature)
      END_SERIALIZE()
    };

    struct checkpoint_serialized
    {
      uint8_t version;
      std::string type;                                    // Either "Hardcoded" or "ServiceNode" for checkpoints generated by Service Nodes or declared in the code
      uint64_t height;                                     // The height the checkpoint is relevant for
      std::string block_hash;                              // The block hash the checkpoint is specifying
      std::vector<quorum_signature_serialized> signatures; // Signatures from Service Nodes who agree on the block hash
      uint64_t prev_height;                                // The previous height the checkpoint is based off

      checkpoint_serialized() = default;
      checkpoint_serialized(checkpoint_t const &checkpoint)
      : version(checkpoint.version)
      , type(checkpoint_t::type_to_string(checkpoint.type))
      , height(checkpoint.height)
      , block_hash(tools::type_to_hex(checkpoint.block_hash))
      , prev_height(checkpoint.prev_height)
      {
        signatures.reserve(checkpoint.signatures.size());
        for (service_nodes::quorum_signature const &entry : checkpoint.signatures)
          signatures.push_back(entry);
      }

      KV_MAP_SERIALIZABLE

      BEGIN_SERIALIZE() // NOTE: For store_t_to_json
        FIELD(version)
        FIELD(type)
        FIELD(height)
        FIELD(block_hash)
        FIELD(signatures)
        FIELD(prev_height)
      END_SERIALIZE()
    };

    struct response
    {
      std::vector<checkpoint_serialized> checkpoints; // Array of requested checkpoints
      std::string status;                             // Generic RPC error code. "OK" is the success value.
      bool untrusted;                                 // If the result is obtained using bootstrap mode, and therefore not trusted `true`, or otherwise `false`.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Query hardcoded/service node checkpoints stored for the blockchain. Omit all arguments to retrieve the latest "count" checkpoints.
  struct GET_SN_STATE_CHANGES : PUBLIC
  {
    static constexpr auto names() { return NAMES("get_service_nodes_state_changes"); }

    static constexpr uint64_t HEIGHT_SENTINEL_VALUE = std::numeric_limits<uint64_t>::max() - 1;
    struct request
    {
      uint64_t start_height;
      uint64_t end_height;   // Optional: If omitted, the tally runs until the current block

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::string status;                    // Generic RPC error code. "OK" is the success value.
      bool untrusted;                        // If the result is obtained using bootstrap mode, and therefore not trusted `true`, or otherwise `false`.

      uint32_t total_deregister;
      uint32_t total_ip_change_penalty;
      uint32_t total_decommission;
      uint32_t total_recommission;
      uint32_t total_unlock;
      uint64_t start_height;
      uint64_t end_height;

      KV_MAP_SERIALIZABLE
    };
  };


  LOKI_RPC_DOC_INTROSPECT
  struct REPORT_PEER_SS_STATUS : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("report_peer_storage_server_status"); }

    struct request
    {
      std::string type; // test type (currently used: ["reachability"])
      std::string pubkey; // service node pubkey
      bool passed; // whether the node is passing the test

      KV_MAP_SERIALIZABLE
    };

    struct response : STATUS {};
  };

  // Deliberately undocumented; this RPC call is really only useful for testing purposes to reset
  // the resync idle timer (which normally fires every 60s) for the test suite.
  struct TEST_TRIGGER_P2P_RESYNC : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("test_trigger_p2p_resync"); }

    struct request : EMPTY {};
    struct response : STATUS {};
  };

  struct TEST_TRIGGER_UPTIME_PROOF : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("test_trigger_uptime_proof"); }
    struct request : EMPTY {};
    struct response : STATUS {};
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get the name mapping for a Loki Name Service entry. Loki currently supports mappings
  // for Session and Lokinet.
  struct LNS_NAMES_TO_OWNERS : PUBLIC
  {
    static constexpr auto names() { return NAMES("lns_names_to_owners"); }

    static constexpr size_t MAX_REQUEST_ENTRIES      = 256;
    static constexpr size_t MAX_TYPE_REQUEST_ENTRIES = 8;
    struct request_entry
    {
      std::string name_hash; // The 32-byte BLAKE2b hash of the name to resolve to a public key via Loki Name Service. The value must be provided either in hex (64 hex digits) or base64 (44 characters with padding, or 43 characters without).
      std::vector<uint16_t> types; // If empty, query all types. Currently supported types are 0 (session) and 2 (lokinet). In future updates more mapping types will be available.

      KV_MAP_SERIALIZABLE
    };

    struct request
    {
      std::vector<request_entry> entries; // Entries to look up
      bool include_expired;               // Optional: if provided and true, include entries in the results even if they are expired

      KV_MAP_SERIALIZABLE
    };

    struct response_entry
    {
      uint64_t entry_index;     // The index in request_entry's `entries` array that was resolved via Loki Name Service.
      lns::mapping_type type;   // The type of Loki Name Service entry that the owner owns: currently supported values are 0 (session), 2 (lokinet)
      std::string name_hash;    // The hash of the name that was queried, in base64
      std::string owner;        // The public key that purchased the Loki Name Service entry.
      std::optional<std::string> backup_owner; // The backup public key that the owner specified when purchasing the Loki Name Service entry. Omitted if no backup owner.
      std::string encrypted_value; // The encrypted value that the name maps to. See the `LNS_RESOLVE` description for information on how this value can be decrypted.
      uint64_t update_height;   // The last height that this Loki Name Service entry was updated on the Blockchain.
      std::optional<uint64_t> expiration_height; // For records that expire, this will be set to the expiration block height.
      std::string txid;                          // The txid of the mapping's most recent update or purchase.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::vector<response_entry> entries;
      std::string status; // Generic RPC error code. "OK" is the success value.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Get all the name mappings for the queried owner. The owner can be either a ed25519 public key or Monero style
  // public key; by default purchases are owned by the spend public key of the purchasing wallet.
  struct LNS_OWNERS_TO_NAMES : PUBLIC
  {
    static constexpr auto names() { return NAMES("lns_owners_to_names"); }

    static constexpr size_t MAX_REQUEST_ENTRIES = 256;
    struct request
    {
      std::vector<std::string> entries; // The owner's public key to find all Loki Name Service entries for.
      bool include_expired;             // Optional: if provided and true, include entries in the results even if they are expired

      KV_MAP_SERIALIZABLE
    };

    struct response_entry
    {
      uint64_t    request_index;   // (Deprecated) The index in request's `entries` array that was resolved via Loki Name Service.
      lns::mapping_type type;      // The category the Loki Name Service entry belongs to; currently 0 for Session and 2 for Lokinet.
      std::string name_hash;       // The hash of the name that the owner purchased via Loki Name Service in base64
      std::string owner;           // The backup public key specified by the owner that purchased the Loki Name Service entry.
      std::optional<std::string> backup_owner; // The backup public key specified by the owner that purchased the Loki Name Service entry. Omitted if no backup owner.
      std::string encrypted_value; // The encrypted value that the name maps to, in hex. This value is encrypted using the name (not the hash) as the secret.
      uint64_t    update_height;   // The last height that this Loki Name Service entry was updated on the Blockchain.
      std::optional<uint64_t> expiration_height; // For records that expire, this will be set to the expiration block height.
      std::string txid;                     // The txid of the mapping's most recent update or purchase.

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::vector<response_entry> entries;
      std::string status; // Generic RPC error code. "OK" is the success value.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Performs a simple LNS lookup of a BLAKE2b-hashed name.  This RPC method is meant for simple,
  // single-value resolutions that do not care about registration details, etc.; if you need more
  // information use LNS_NAMES_TO_OWNERS instead.
  //
  // Technical details: the returned value is encrypted using the name itself so that neither this
  // lokid responding to the RPC request nor any other blockchain observers can (easily) obtain the
  // name of registered addresses or the registration details.  Thus, from a client's point of view,
  // resolving an LNS record involves:
  //
  // - Lower-case the name.
  // - Calculate the name hash as a null-key, 32-byte BLAKE2b hash of the lower-case name.
  // - Obtain the encrypted value and the nonce from this RPC call (or LNS_NAMES_TO_OWNERS); (encode
  //   the name hash using either hex or base64.).
  // - Calculate the decryption key as a 32-byte BLAKE2b keyed hash of the name using the
  //   (unkeyed) name hash calculated above as the hash key.
  // - Decrypt (and verify) using XChaCha20-Poly1305 (for example libsodium's
  //   crypto_aead_xchacha20poly1305_ietf_decrypt) using the above decryption key and using the
  //   first 24 bytes of the name hash as the public nonce.
  struct LNS_RESOLVE : PUBLIC
  {
    static constexpr auto names() { return NAMES("lns_resolve"); }

    struct request
    {
      uint16_t type;         // The LNS type (mandatory); currently supported values are: 0 = session, 2 = lokinet.
      std::string name_hash; // The 32-byte BLAKE2b hash of the name to look up, encoded as 64 hex digits or 44/43 base64 characters (with/without padding).

      KV_MAP_SERIALIZABLE
    };

    struct response
    {
      std::optional<std::string> encrypted_value; // The encrypted LNS value, in hex.  Will be omitted from the response if the given name_hash is not registered.
      std::optional<std::string> nonce; // The nonce value used for encryption, in hex.

      KV_MAP_SERIALIZABLE
    };
  };

  LOKI_RPC_DOC_INTROSPECT
  // Clear TXs from the daemon cache, currently only the cache storing TX hashes that were previously verified bad by the daemon.
  struct FLUSH_CACHE : RPC_COMMAND
  {
    static constexpr auto names() { return NAMES("flush_cache"); }
    struct request
    {
      bool bad_txs; // Clear the cache storing TXs that failed verification.
      bool bad_blocks; // Clear the cache storing blocks that failed verfication.
      KV_MAP_SERIALIZABLE;
    };

    struct response : STATUS { };
  };

  /// List of all supported rpc command structs to allow compile-time enumeration of all supported
  /// RPC types.  Every type added above that has an RPC endpoint needs to be added here, and needs
  /// a core_rpc_server::invoke() overload that takes a <TYPE>::request and returns a
  /// <TYPE>::response.  The <TYPE>::request has to be unique (for overload resolution);
  /// <TYPE>::response does not.
  using core_rpc_types = tools::type_list<
    GET_HEIGHT,
    GET_BLOCKS_FAST,
    GET_BLOCKS_BY_HEIGHT,
    GET_ALT_BLOCKS_HASHES,
    GET_HASHES_FAST,
    GET_TRANSACTIONS,
    IS_KEY_IMAGE_SPENT,
    GET_TX_GLOBAL_OUTPUTS_INDEXES,
    GET_OUTPUTS_BIN,
    GET_OUTPUTS,
    SEND_RAW_TX,
    START_MINING,
    STOP_MINING,
    MINING_STATUS,
    GET_INFO,
    GET_NET_STATS,
    SAVE_BC,
    GETBLOCKCOUNT,
    GETBLOCKHASH,
    GETBLOCKTEMPLATE,
    SUBMITBLOCK,
    GENERATEBLOCKS,
    GET_LAST_BLOCK_HEADER,
    GET_BLOCK_HEADER_BY_HASH,
    GET_BLOCK_HEADER_BY_HEIGHT,
    GET_BLOCK,
    GET_PEER_LIST,
    GET_PUBLIC_NODES,
    SET_LOG_HASH_RATE,
    SET_LOG_LEVEL,
    SET_LOG_CATEGORIES,
    GET_TRANSACTION_POOL,
    GET_TRANSACTION_POOL_HASHES_BIN,
    GET_TRANSACTION_POOL_HASHES,
    GET_TRANSACTION_POOL_BACKLOG,
    GET_TRANSACTION_POOL_STATS,
    GET_CONNECTIONS,
    GET_BLOCK_HEADERS_RANGE,
    SET_BOOTSTRAP_DAEMON,
    STOP_DAEMON,
    GET_LIMIT,
    SET_LIMIT,
    OUT_PEERS,
    IN_PEERS,
    HARD_FORK_INFO,
    GETBANS,
    SETBANS,
    BANNED,
    FLUSH_TRANSACTION_POOL,
    GET_OUTPUT_HISTOGRAM,
    GET_VERSION,
    GET_COINBASE_TX_SUM,
    GET_BASE_FEE_ESTIMATE,
    GET_ALTERNATE_CHAINS,
    RELAY_TX,
    SYNC_INFO,
    GET_OUTPUT_DISTRIBUTION,
    GET_OUTPUT_DISTRIBUTION_BIN,
    POP_BLOCKS,
    PRUNE_BLOCKCHAIN,
    GET_QUORUM_STATE,
    GET_SERVICE_NODE_REGISTRATION_CMD_RAW,
    GET_SERVICE_NODE_REGISTRATION_CMD,
    GET_SERVICE_KEYS,
    GET_SERVICE_PRIVKEYS,
    PERFORM_BLOCKCHAIN_TEST,
    GET_SERVICE_NODES,
    GET_SERVICE_NODE_STATUS,
    STORAGE_SERVER_PING,
    LOKINET_PING,
    GET_STAKING_REQUIREMENT,
    GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES,
    GET_OUTPUT_BLACKLIST,
    GET_CHECKPOINTS,
    GET_SN_STATE_CHANGES,
    REPORT_PEER_SS_STATUS,
    TEST_TRIGGER_P2P_RESYNC,
    TEST_TRIGGER_UPTIME_PROOF,
    LNS_NAMES_TO_OWNERS,
    LNS_OWNERS_TO_NAMES,
    LNS_RESOLVE,
    FLUSH_CACHE
  >;

} } // namespace cryptonote::rpc
