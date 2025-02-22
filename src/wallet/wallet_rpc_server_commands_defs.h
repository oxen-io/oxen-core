// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2018, The Loki Project
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
#include "common/meta.h"
#include "common/oxen.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/subaddress_index.h"
#include "wallet/transfer_destination.h"
#include "wallet/transfer_view.h"
#include "wallet_rpc_server_error_codes.h"

// When making *any* change here, bump minor
// If the change is incompatible, then bump major and set minor to 0
// This ensures WALLET_RPC_VERSION always increases, that every change
// has its own version, and that clients can just test major to see
// whether they can talk to a given wallet without having to know in
// advance which version they will stop working with
// Don't go over 32767 for any of these
#define WALLET_RPC_VERSION_MAJOR 1
#define WALLET_RPC_VERSION_MINOR 17
#define MAKE_WALLET_RPC_VERSION(major, minor) (((major) << 16) | (minor))
#define WALLET_RPC_VERSION \
    MAKE_WALLET_RPC_VERSION(WALLET_RPC_VERSION_MAJOR, WALLET_RPC_VERSION_MINOR)

#define WALLET_RPC_STATUS_OK "OK"
#define WALLET_RPC_STATUS_BUSY "BUSY"

/// Namespace for wallet RPC commands.  Every RPC commands gets defined here and added to
/// `wallet_rpc_types` list at the bottom of the file.

namespace tools::wallet_rpc {

/// Base class that all wallet rpc commands inherit from
struct RPC_COMMAND {};

/// Base class for restricted RPC commands (that is, commands not available when running in
/// restricted mode).
struct RESTRICTED : RPC_COMMAND {};

/// Generic, serializable, no-argument request or response type, use as
/// `struct request : EMPTY {};` or `using response = EMPTY;`
struct EMPTY {
    KV_MAP_SERIALIZABLE
};

namespace {
    /// Returns a constexpr std::array of string_views from an arbitrary list of string literals
    /// Used to specify RPC names as:
    /// static constexpr auto names() { return NAMES("primary_name", "some_alias"); }
    template <size_t... N>
    constexpr std::array<std::string_view, sizeof...(N)> NAMES(const char (&... names)[N]) {
        static_assert(sizeof...(N) > 0, "RPC command must have at least one name");
        return {std::string_view{names, N - 1}...};
    }
}  // namespace

OXEN_RPC_DOC_INTROSPECT
// Return the wallet's balance.
struct GET_BALANCE : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_balance", "getbalance"); }

    struct request {
        uint32_t account_index;  // Return balance for this account.
        std::set<uint32_t>
                address_indices;  // (Optional) Return balance detail for those subaddresses.
        bool all_accounts;        // If true, return balance for all accounts, subaddr_indices and
                                  // account_index are ignored
        bool strict;  // If true, only return the balance for transactions that have been spent and
                      // are not pending (i.e. excluding any transactions sitting in the TX pool)

        KV_MAP_SERIALIZABLE
    };

    struct per_subaddress_info {
        uint32_t account_index;  // Index of the account in the wallet.
        uint32_t address_index;  // Index of the subaddress in the account.
        std::string address;     // Address at this index. Base58 representation of the public keys.
        uint64_t balance;        // Balance for the subaddress (locked or unlocked).
        uint64_t unlocked_balance;  // Unlocked funds are those funds that are sufficiently deep
                                    // enough in the oxen blockchain to be considered safe to spend.
        std::string label;          // Label for the subaddress.
        uint64_t num_unspent_outputs;  // Number of unspent outputs available for the subaddress.
        uint64_t blocks_to_unlock;     // The number of blocks remaining for the balance to unlock
        uint64_t time_to_unlock;       // Timestamp of expected unlock

        KV_MAP_SERIALIZABLE
    };

    struct response {
        uint64_t balance;  // The total balance (atomic units) of the currently opened wallet.
        uint64_t unlocked_balance;  // Unlocked funds are those funds that are sufficiently deep
                                    // enough in the oxen blockchain to be considered safe to spend.
        uint64_t accrued_balance;   // The unpaid accrued service node rewards currently in the
                                    // batching database for this currently opened wallet
        uint64_t accrued_balance_next_payout;  // Height that the accrued service node rewards will
                                               // be paid out
        bool multisig_import_needed;  // True if importing multisig data is needed for returning a
                                      // correct balance.
        std::vector<per_subaddress_info>
                per_subaddress;     // Balance information for each subaddress in an account.
        uint64_t blocks_to_unlock;  // The number of blocks remaining for the balance to unlock
        uint64_t time_to_unlock;    // Timestamp of expected unlock

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Return the wallet's addresses for an account. Optionally filter for specific set of subaddresses.
struct GET_ADDRESS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_address", "getaddress"); }

    struct request {
        uint32_t account_index;               // Get the wallet addresses for the specified account.
        std::vector<uint32_t> address_index;  // (Optional) List of subaddresses to return from the
                                              // aforementioned account.

        KV_MAP_SERIALIZABLE
    };

    struct address_info {
        std::string address;     // The (sub)address string.
        std::string label;       // Label of the (sub)address.
        uint32_t address_index;  // Index of the subaddress
        bool used;               // True if the (sub)address has received funds before.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string address;  // (Deprecated) Remains to be compatible with older RPC format
        std::vector<address_info> addresses;  // Addresses informations.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Get account and address indexes from a specific (sub)address.
struct GET_ADDRESS_INDEX : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_address_index"); }

    struct request {
        std::string address;  // (Sub)address to look for.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        cryptonote::subaddress_index index;  // Account index followed by the subaddress index.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Create a new address for an account. Optionally, label the new address.
struct CREATE_ADDRESS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("create_address"); }

    struct request {
        uint32_t account_index;  // Create a new subaddress for this account.
        std::string label;       // (Optional) Label for the new subaddress.
        uint32_t count;          // Number of addresses to create, defaults to 1.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string address;     // The newly requested address.
        uint32_t address_index;  // Index of the new address in the requested account index.
        std::vector<std::string> addresses;  // The new addresses, if more than 1 is requested
        std::vector<uint32_t>
                address_indices;  // The new addresses indicies if more than 1 is requested

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Label an address.
struct LABEL_ADDRESS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("label_address"); }

    struct request {
        cryptonote::subaddress_index index;  // Major & minor address index
        std::string label;                   // Label for the address.

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Get all accounts for a wallet. Optionally filter accounts by tag.
struct GET_ACCOUNTS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_accounts"); }

    struct request {
        std::string tag;  // (Optional) Tag for filtering accounts. All accounts if empty, otherwise
                          // those accounts with this tag
        bool strict_balances;  // If true, only return the balance for transactions that have been
                               // spent and are not pending (i.e. excluding any transactions sitting
                               // in the TX pool)

        KV_MAP_SERIALIZABLE
    };

    struct subaddress_account_info {
        uint32_t account_index;     // Index of the account.
        std::string base_address;   // The first address of the account (i.e. the primary address).
        uint64_t balance;           // Balance of the account (locked or unlocked).
        uint64_t unlocked_balance;  // Unlocked balance for the account.
        std::string label;          // (Optional) Label of the account.
        std::string tag;            // (Optional) Tag for filtering accounts.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        uint64_t total_balance;  // Total balance of the selected accounts (locked or unlocked).
        uint64_t total_unlocked_balance;  // Total unlocked balance of the selected accounts.
        std::vector<subaddress_account_info> subaddress_accounts;  // Account information.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Create a new account with an optional label.
struct CREATE_ACCOUNT : RPC_COMMAND {
    static constexpr auto names() { return NAMES("create_account"); }

    struct request {
        std::string label;  // (Optional) Label for the account.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        uint32_t account_index;  // Index of the new account.
        std::string address;     // The primary address of the new account.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Label an account.
struct LABEL_ACCOUNT : RPC_COMMAND {
    static constexpr auto names() { return NAMES("label_account"); }

    struct request {
        uint32_t account_index;  // Account index to set the label for.
        std::string label;       // Label for the account.

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Get a list of user-defined account tags.
struct GET_ACCOUNT_TAGS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_account_tags"); }

    struct request : EMPTY {};

    struct account_tag_info {
        std::string tag;                 // Filter tag.
        std::string label;               // Label for the tag.
        std::vector<uint32_t> accounts;  // List of tagged account indices.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::vector<account_tag_info> account_tags;  // Account tag information:

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Apply a filtering tag to a list of accounts.
struct TAG_ACCOUNTS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("tag_accounts"); }

    struct request {
        std::string tag;              // Tag for the accounts.
        std::set<uint32_t> accounts;  // Tag this list of accounts.

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Remove filtering tag from a list of accounts.
struct UNTAG_ACCOUNTS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("untag_accounts"); }

    struct request {
        std::set<uint32_t> accounts;  // Remove tag from this list of accounts.

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Set description for an account tag.
struct SET_ACCOUNT_TAG_DESCRIPTION : RPC_COMMAND {
    static constexpr auto names() { return NAMES("set_account_tag_description"); }

    struct request {
        std::string tag;          // Set a description for this tag.
        std::string description;  // Description for the tag.

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Returns the wallet's current block height and blockchain immutable height
struct GET_HEIGHT : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_height", "getheight"); }

    struct request : EMPTY {};

    struct response {
        uint64_t height;  // The current wallet's blockchain height. If the wallet has been offline
                          // for a long time, it may need to catch up with the daemon.
        uint64_t immutable_height;  // The latest height in the blockchain that can not be
                                    // reorganized from (backed by atleast 2 Service Node, or 1
                                    // hardcoded checkpoint, 0 if N/A).

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Send oxen to a number of recipients. To preview the transaction fee, set do_not_relay to true and
// get_tx_metadata to true. Submit the response using the data in get_tx_metadata in the RPC call,
// relay_tx.
struct TRANSFER : RESTRICTED {
    static constexpr auto names() { return NAMES("transfer"); }

    struct request {
        std::list<wallet::transfer_destination>
                destinations;    // Array of destinations to receive OXEN.
        uint32_t account_index;  // (Optional) Transfer from this account index. (Defaults to 0)
        std::set<uint32_t> subaddr_indices;  // (Optional) Transfer from this set of subaddresses.
                                             // (Defaults to 0)
        uint32_t priority;     // Set a priority for the transaction. Accepted values are: 1 for
                               // unimportant or 5 for blink. (0 and 2-4 are accepted for backwards
                               // compatibility and are equivalent to 5)
        uint64_t unlock_time;  // Number of blocks before the oxen can be spent (0 to use the
                               // default lock time).
        std::string
                payment_id;  // (Optional) Random 64-character hex string to identify a transaction.
        bool get_tx_key;     // (Optional) Return the transaction key after sending.
        bool do_not_relay;  // (Optional) If true, the newly created transaction will not be relayed
                            // to the oxen network. (Defaults to false)
        bool get_tx_hex;  // Return the transaction as hex string after sending. (Defaults to false)
        bool get_tx_metadata;  // Return the metadata needed to relay the transaction. (Defaults to
                               // false)

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string tx_hash;  // Publicly searchable transaction hash.
        std::string tx_key;   // Transaction key if get_tx_key is true, otherwise, blank string.
        uint64_t amount;      // Amount transferred for the transaction.
        uint64_t fee;         // Fee charged for the txn.
        std::string tx_blob;  // Raw transaction represented as hex string, if get_tx_hex is true.
        std::string tx_metadata;     // Set of transaction metadata needed to relay this transfer
                                     // later, if get_tx_metadata is true.
        std::string multisig_txset;  // Set of multisig transactions in the process of being signed
                                     // (empty for non-multisig).
        std::string unsigned_txset;  // Set of unsigned tx for cold-signing purposes.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Same as transfer, but can split into more than one tx if necessary.
struct TRANSFER_SPLIT : RESTRICTED {
    static constexpr auto names() { return NAMES("transfer_split"); }

    struct request {
        std::list<wallet::transfer_destination>
                destinations;    // Array of destinations to receive OXEN:
        uint32_t account_index;  // (Optional) Transfer from this account index. (Defaults to 0)
        std::set<uint32_t> subaddr_indices;  // (Optional) Transfer from this set of subaddresses.
                                             // (Defaults to 0)
        uint32_t priority;     // Set a priority for the transaction. Accepted values are: 1 for
                               // unimportant or 5 for blink. (0 and 2-4 are accepted for backwards
                               // compatibility and are equivalent to 5)
        uint64_t unlock_time;  // Number of blocks before the oxen can be spent (0 to not add a
                               // lock).
        std::string payment_id;  // (Optional) Random 32-byte/64-character hex string to identify a
                                 // transaction.
        bool get_tx_keys;        // (Optional) Return the transaction keys after sending.
        bool do_not_relay;  // (Optional) If true, the newly created transaction will not be relayed
                            // to the oxen network. (Defaults to false)
        bool get_tx_hex;    // Return the transactions as hex string after sending.
        bool get_tx_metadata;  // Return list of transaction metadata needed to relay the transfer
                               // later.

        KV_MAP_SERIALIZABLE
    };

    struct key_list {
        std::list<std::string> keys;  //

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::list<std::string> tx_hash_list;      // The tx hashes of every transaction.
        std::list<std::string> tx_key_list;       // The transaction keys for every transaction.
        std::list<uint64_t> amount_list;          // The amount transferred for every transaction.
        std::list<uint64_t> fee_list;             // The amount of fees paid for every transaction.
        std::list<std::string> tx_blob_list;      // The tx as hex string for every transaction.
        std::list<std::string> tx_metadata_list;  // List of transaction metadata needed to relay
                                                  // the transactions later.
        std::string multisig_txset;  // The set of signing keys used in a multisig transaction
                                     // (empty for non-multisig).
        std::string unsigned_txset;  // Set of unsigned tx for cold-signing purposes.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
struct DESCRIBE_TRANSFER : RESTRICTED {
    static constexpr auto names() { return NAMES("describe_transfer"); }

    struct recipient {
        std::string address;  // Destination public address.
        uint64_t amount;      // Amount in atomic units.

        KV_MAP_SERIALIZABLE
    };

    struct transfer_description {
        uint64_t amount_in;    // Amount in, in atomic units.
        uint64_t amount_out;   // amount out, in atomic units.
        uint32_t ring_size;    // Ring size of transfer.
        uint64_t unlock_time;  // Number of blocks before the oxen can be spent (0 represents the
                               // default network lock time).
        std::list<recipient> recipients;  // List of addresses and amounts.
        std::string payment_id;           // Payment ID matching the input parameter.
        uint64_t change_amount;           // Change received from transaction in atomic units.
        std::string change_address;       // Address the change was sent to.
        uint64_t fee;                     // Fee of the transaction in atomic units.
        uint32_t dummy_outputs;           //
        std::string extra;                // Data stored in the tx extra represented in hex.

        KV_MAP_SERIALIZABLE
    };

    struct request {
        std::string unsigned_txset;  // Set of unsigned tx returned by "transfer" or
                                     // "transfer_split" methods.
        std::string multisig_txset;  // Set of unsigned multisig txes returned by "transfer" or
                                     // "transfer_split" methods

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::list<transfer_description> desc;  // List of information of transfers.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Sign a transaction created on a read-only wallet (in cold-signing process).
struct SIGN_TRANSFER : RESTRICTED {
    static constexpr auto names() { return NAMES("sign_transfer"); }

    struct request {
        std::string unsigned_txset;  // Set of unsigned tx returned by "transfer" or
                                     // "transfer_split" methods.
        bool export_raw;   // (Optional) If true, return the raw transaction data. (Defaults to
                           // false)
        bool get_tx_keys;  // (Optional) Return the transaction keys after sending.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string signed_txset;  // Set of signed tx to be used for submitting transfer.
        std::list<std::string> tx_hash_list;  // The tx hashes of every transaction.
        std::list<std::string> tx_raw_list;   // The tx raw data of every transaction.
        std::list<std::string> tx_key_list;   // The tx key data of every transaction.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Submit a previously signed transaction on a read-only wallet (in cold-signing process).
struct SUBMIT_TRANSFER : RESTRICTED {
    static constexpr auto names() { return NAMES("submit_transfer"); }

    struct request {
        std::string tx_data_hex;  // Set of signed tx returned by "sign_transfer".

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::list<std::string> tx_hash_list;  // The tx hashes of every transaction.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Send all dust outputs back to the wallet's, to make them easier to spend (and mix).
struct SWEEP_DUST : RESTRICTED {
    static constexpr auto names() { return NAMES("sweep_dust", "sweep_unmixable"); }

    struct request {
        bool get_tx_keys;   // (Optional) Return the transaction keys after sending.
        bool do_not_relay;  // (Optional) If true, the newly created transaction will not be relayed
                            // to the oxen network. (Defaults to false)
        bool get_tx_hex;    // (Optional) Return the transactions as hex string after sending.
                            // (Defaults to false)
        bool get_tx_metadata;  // (Optional) Return list of transaction metadata needed to relay the
                               // transfer later. (Defaults to false)

        KV_MAP_SERIALIZABLE
    };

    struct key_list {
        std::list<std::string> keys;

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::list<std::string> tx_hash_list;      // The tx hashes of every transaction.
        std::list<std::string> tx_key_list;       // The transaction keys for every transaction.
        std::list<uint64_t> amount_list;          // The amount transferred for every transaction.
        std::list<uint64_t> fee_list;             // The amount of fees paid for every transaction.
        std::list<std::string> tx_blob_list;      // The tx as hex string for every transaction.
        std::list<std::string> tx_metadata_list;  // List of transaction metadata needed to relay
                                                  // the transactions later.
        std::string multisig_txset;  // The set of signing keys used in a multisig transaction
                                     // (empty for non-multisig).
        std::string unsigned_txset;  // Set of unsigned tx for cold-signing purposes.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Send all unlocked balance to an address.
struct SWEEP_ALL : RESTRICTED {
    static constexpr auto names() { return NAMES("sweep_all"); }

    struct request {
        std::string address;     // Destination public address.
        uint32_t account_index;  // Sweep transactions from this account.
        std::set<uint32_t>
                subaddr_indices;   // (Optional) Sweep from this set of subaddresses in the account.
        bool subaddr_indices_all;  //
        uint32_t priority;         // Set a priority for the transaction. Accepted values are: 1 for
                            // unimportant or 5 for blink. (0 and 2-4 are accepted for backwards
                            // compatibility and are equivalent to 5)
        uint64_t outputs;        //
        uint64_t unlock_time;    // Number of blocks before the oxen can be spent (0 to not add a
                                 // lock).
        std::string payment_id;  // (Optional) 64-character hex string to identify a transaction.
        bool get_tx_keys;        // (Optional) Return the transaction keys after sending.
        uint64_t below_amount;   // (Optional) Include outputs below this amount.
        bool do_not_relay;  // (Optional) If true, do not relay this sweep transfer. (Defaults to
                            // false)
        bool get_tx_hex;  // (Optional) return the transactions as hex encoded string. (Defaults to
                          // false)
        bool get_tx_metadata;  // (Optional) return the transaction metadata as a string. (Defaults
                               // to false)

        KV_MAP_SERIALIZABLE
    };

    struct key_list {
        std::list<std::string> keys;

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::list<std::string> tx_hash_list;      // The tx hashes of every transaction.
        std::list<std::string> tx_key_list;       // The transaction keys for every transaction.
        std::list<uint64_t> amount_list;          // The amount transferred for every transaction.
        std::list<uint64_t> fee_list;             // The amount of fees paid for every transaction.
        std::list<std::string> tx_blob_list;      // The tx as hex string for every transaction.
        std::list<std::string> tx_metadata_list;  // List of transaction metadata needed to relay
                                                  // the transactions later.
        std::string multisig_txset;  // The set of signing keys used in a multisig transaction
                                     // (empty for non-multisig).
        std::string unsigned_txset;  // Set of unsigned tx for cold-signing purposes.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Send all of a specific unlocked output to an address.
struct SWEEP_SINGLE : RESTRICTED {
    static constexpr auto names() { return NAMES("sweep_single"); }

    struct request {
        std::string address;   // Destination public address.
        uint32_t priority;     // Set a priority for the transaction. Accepted values are: 1 for
                               // unimportant or 5 for blink. (0 and 2-4 are accepted for backwards
                               // compatibility and are equivalent to 5)
        uint64_t outputs;      //
        uint64_t unlock_time;  // Number of blocks before the oxen can be spent (0 to not add a
                               // lock).
        std::string payment_id;  // (Optional) 64-character hex string to identify a transaction.
        bool get_tx_key;         // (Optional) Return the transaction keys after sending.
        std::string key_image;   // Key image of specific output to sweep.
        bool do_not_relay;  // (Optional) If true, do not relay this sweep transfer. (Defaults to
                            // false)
        bool get_tx_hex;  // (Optional) return the transactions as hex encoded string. (Defaults to
                          // false)
        bool get_tx_metadata;  // (Optional) return the transaction metadata as a string. (Defaults
                               // to false)

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string tx_hash;         // The tx hashes of the transaction.
        std::string tx_key;          // The tx key of the transaction.
        uint64_t amount;             // The amount transfered in atomic units.
        uint64_t fee;                // The fee paid in atomic units.
        std::string tx_blob;         // The tx as hex string.
        std::string tx_metadata;     // Transaction metadata needed to relay the transaction later.
        std::string multisig_txset;  // The set of signing keys used in a multisig transaction
                                     // (empty for non-multisig).
        std::string unsigned_txset;  // Set of unsigned tx for cold-signing purposes.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Relay transaction metadata to the daemon
struct RELAY_TX : RPC_COMMAND {
    static constexpr auto names() { return NAMES("relay_tx"); }

    struct request {
        std::string hex;  // Transaction metadata returned from a transfer method with
                          // get_tx_metadata set to true.
        bool blink;  // (Optional): Set to true if this tx was constructed with a blink priority and
                     // should be submitted to the blink quorum.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string tx_hash;  // String for the publically searchable transaction hash.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Save the wallet file.
struct STORE : RESTRICTED {
    static constexpr auto names() { return NAMES("store"); }

    struct request : EMPTY {};

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
//
struct payment_details {
    std::string payment_id;  // Payment ID matching the input parameter.
    std::string tx_hash;     // Transaction hash used as the transaction ID.
    uint64_t amount;         // Amount for this payment.
    uint64_t block_height;   // Height of the block that first confirmed this payment.
    uint64_t unlock_time;    // Time (in block height) until this payment is safe to spend.
    bool locked;             // If the payment is spendable or not
    cryptonote::subaddress_index
            subaddr_index;  // Major & minor index, account and subaddress index respectively.
    std::string address;    // Address receiving the payment.

    KV_MAP_SERIALIZABLE
};

OXEN_RPC_DOC_INTROSPECT
// Get a list of incoming payments using a given payment id.
struct GET_PAYMENTS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_payments"); }

    struct request {
        std::string payment_id;  // Payment ID used to find the payments (16 characters hex).

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::list<payment_details> payments;  // List of payment details:

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Get a list of incoming payments using a given payment id,
// or a list of payments ids, from a given height.
//
// This method is the preferred method over  get_paymentsbecause it
// has the same functionality but is more extendable.
// Either is fine for looking up transactions by a single payment ID.
struct GET_BULK_PAYMENTS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_bulk_payments"); }

    struct request {
        std::vector<std::string>
                payment_ids;        // Payment IDs used to find the payments (16 characters hex).
        uint64_t min_block_height;  // The block height at which to start looking for payments.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::list<payment_details> payments;  // List of payment details:

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
//
struct transfer_details {
    uint64_t amount;        // Amount of this transfer.
    bool spent;             // Indicates if this transfer has been spent.
    uint64_t global_index;  // The index into the global list of transactions grouped by amount in
                            // the Loki network.
    std::string tx_hash;  // Several incoming transfers may share the same hash if they were in the
                          // same transaction.
    cryptonote::subaddress_index
            subaddr_index;  // Major & minor index, account and subaddress index respectively.
    std::string key_image;  // Key image for the incoming transfer's unspent output (empty unless
                            // verbose is true).
    uint64_t block_height;  // Block height the transfer occurred on
    bool frozen;    // If the output has been intentionally frozen by the user, i.e. unspendable.
    bool unlocked;  // If the TX is spendable yet

    KV_MAP_SERIALIZABLE
};

OXEN_RPC_DOC_INTROSPECT
// Return a list of incoming transfers to the wallet.
struct INCOMING_TRANSFERS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("incoming_transfers"); }

    struct request {
        std::string transfer_type;  // "all": all the transfers, "available": only transfers which
                                    // are not yet spent, OR "unavailable": only transfers which are
                                    // already spent.
        uint32_t account_index;     // (Optional) Return transfers for this account. (defaults to 0)
        std::set<uint32_t>
                subaddr_indices;  // (Optional) Return transfers sent to these subaddresses.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::list<transfer_details> transfers;  // List of information of the transfers details.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Return the spend or view private key.
struct QUERY_KEY : RESTRICTED {
    static constexpr auto names() { return NAMES("query_key"); }

    struct request {
        std::string key_type;  // Which key to retrieve: "mnemonic" - the mnemonic seed (older
                               // wallets do not have one) OR "view_key" - the view key

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string key;  //  The view key will be hex encoded, while the mnemonic will be a string
                          //  of words.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Make an integrated address from the wallet address and a payment id.
struct MAKE_INTEGRATED_ADDRESS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("make_integrated_address"); }

    struct request {
        std::string standard_address;  // (Optional, defaults to primary address) Destination public
                                       // address.
        std::string payment_id;  // (Optional, defaults to a random ID) 16 characters hex encoded.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string integrated_address;  //
        std::string payment_id;          // Hex encoded.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Retrieve the standard address and payment id corresponding to an integrated address.
struct SPLIT_INTEGRATED_ADDRESS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("split_integrated_address"); }

    struct request {
        std::string integrated_address;  //

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string standard_address;  //
        std::string payment_id;        //
        bool is_subaddress;            //

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Stops the wallet, storing the current state.
struct STOP_WALLET : RESTRICTED {
    static constexpr auto names() { return NAMES("stop_wallet"); }

    struct request : EMPTY {};

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Rescan the blockchain from scratch, losing any information
// which can not be recovered from the blockchain itself.
// This includes destination addresses, tx secret keys, tx notes, etc.

// Warning: This blocks the Wallet RPC executable until rescanning is complete.
struct RESCAN_BLOCKCHAIN : RESTRICTED {
    static constexpr auto names() { return NAMES("rescan_blockchain"); }

    struct request {
        bool hard;  //

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Set arbitrary string notes for transactions.
struct SET_TX_NOTES : RESTRICTED {
    static constexpr auto names() { return NAMES("set_tx_notes"); }

    struct request {
        std::list<std::string> txids;  // Transaction ids.
        std::list<std::string> notes;  // Notes for the transactions.

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Get string notes for transactions.
struct GET_TX_NOTES : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_tx_notes"); }

    struct request {
        std::list<std::string> txids;  // Transaction ids.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::list<std::string> notes;  // Notes for the transactions.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Set arbitrary attribute.
struct SET_ATTRIBUTE : RESTRICTED {
    static constexpr auto names() { return NAMES("set_attribute"); }

    struct request {
        std::string key;    // Attribute name.
        std::string value;  // Attribute value.

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Get attribute value by name.
struct GET_ATTRIBUTE : RESTRICTED {
    static constexpr auto names() { return NAMES("get_attribute"); }

    struct request {

        std::string key;  // Attribute name.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string value;  // Attribute value.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Get transaction secret key from transaction id.
struct GET_TX_KEY : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_tx_key"); }

    struct request {
        std::string txid;  // Transaction id.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string tx_key;  // Transaction secret key.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Check a transaction in the blockchain with its secret key.
struct CHECK_TX_KEY : RPC_COMMAND {
    static constexpr auto names() { return NAMES("check_tx_key"); }

    struct request {
        std::string txid;     // Transaction id.
        std::string tx_key;   // Transaction secret key.
        std::string address;  // Destination public address of the transaction.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        uint64_t received;  // Amount of the transaction.
        bool in_pool;  // States if the transaction is still in pool or has been added to a block.
        uint64_t confirmations;  // Number of block mined after the one with the transaction.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Get transaction signature to prove it.
struct GET_TX_PROOF : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_tx_proof"); }

    struct request {
        std::string txid;     // Transaction id.
        std::string address;  // Destination public address of the transaction.
        std::string message;  // (Optional) add a message to the signature to further authenticate
                              // the prooving process.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string signature;  // Transaction signature.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Prove a transaction by checking its signature.
struct CHECK_TX_PROOF : RPC_COMMAND {
    static constexpr auto names() { return NAMES("check_tx_proof"); }

    struct request {
        std::string txid;       // Transaction id.
        std::string address;    // Destination public address of the transaction.
        std::string message;    // (Optional) Should be the same message used in `get_tx_proof`.
        std::string signature;  // Transaction signature to confirm.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        bool good;          // States if the inputs proves the transaction.
        uint64_t received;  // Amount of the transaction.
        bool in_pool;  // States if the transaction is still in pool or has been added to a block.
        uint64_t confirmations;  // Number of block mined after the one with the transaction.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Generate a signature to prove a spend. Unlike proving a transaction, it does not requires the
// destination public address.
struct GET_SPEND_PROOF : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_spend_proof"); }

    struct request {
        std::string txid;     // Transaction id.
        std::string message;  // (Optional) add a message to the signature to further authenticate
                              // the prooving process.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string signature;  // Spend signature.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Prove a spend using a signature. Unlike proving a transaction, it does not requires the
// destination public address.
struct CHECK_SPEND_PROOF : RPC_COMMAND {
    static constexpr auto names() { return NAMES("check_spend_proof"); }

    struct request {
        std::string txid;       // Transaction id.
        std::string message;    // (Optional) Should be the same message used in `get_spend_proof`.
        std::string signature;  // Spend signature to confirm.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        bool good;  // States if the inputs proves the spend.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Generate a signature to prove of an available amount in a wallet.
struct GET_RESERVE_PROOF : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_reserve_proof"); }

    struct request {
        bool all;                // Proves all wallet balance to be disposable.
        uint32_t account_index;  // Specify the account from witch to prove reserve. (ignored if all
                                 // is set to true)
        uint64_t amount;  // Amount (in atomic units) to prove the account has for reserve. (ignored
                          // if all is set to true)
        std::string message;  // (Optional) add a message to the signature to further authenticate
                              // the prooving process.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string signature;  // Reserve signature.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Proves a wallet has a disposable reserve using a signature.
struct CHECK_RESERVE_PROOF : RPC_COMMAND {
    static constexpr auto names() { return NAMES("check_reserve_proof"); }

    struct request {
        std::string address;    // Public address of the wallet.
        std::string message;    // (Optional) Should be the same message used in get_reserve_proof.
        std::string signature;  // Reserve signature to confirm.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        bool good;       // States if the inputs proves the reserve.
        uint64_t total;  //
        uint64_t spent;  //

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Returns a list of transfers, by default all transfer types are included. If all requested type
// fields are false, then all transfers will be queried.
struct GET_TRANSFERS : RESTRICTED {
    static constexpr auto names() { return NAMES("get_transfers"); }

    struct request {
        bool in;        // (Optional) Include incoming transfers.
        bool out;       // (Optional) Include outgoing transfers.
        bool stake;     // (Optional) Include outgoing stakes.
        bool pending;   // (Optional) Include pending transfers.
        bool failed;    // (Optional) Include failed transfers.
        bool pool;      // (Optional) Include transfers from the daemon's transaction pool.
        bool coinbase;  // (Optional) Include transfers from the daemon's transaction pool.

        bool filter_by_height;  // (Optional) Filter transfers by block height.
        uint64_t min_height;  // (Optional) Minimum block height to scan for transfers, if filtering
                              // by height is enabled.
        uint64_t max_height;  // (Optional) Maximum block height to scan for transfers, if filtering
                              // by height is enabled (defaults to max block height).
        uint32_t account_index;  // (Optional) Index of the account to query for transfers.
                                 // (defaults to 0)
        std::set<uint32_t> subaddr_indices;  // (Optional) List of subaddress indices to query for
                                             // transfers. (defaults to 0)
        bool all_accounts;  // If true, return transfers for all accounts, subaddr_indices and
                            // account_index are ignored

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::list<wallet::transfer_view> in;       //
        std::list<wallet::transfer_view> out;      //
        std::list<wallet::transfer_view> pending;  //
        std::list<wallet::transfer_view> failed;   //
        std::list<wallet::transfer_view> pool;     //

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Returns a string with the transfers formatted as csv
struct GET_TRANSFERS_CSV : RESTRICTED {
    static constexpr auto names() { return NAMES("get_transfers_csv"); }

    struct request : GET_TRANSFERS::request {};

    struct response {
        std::string csv;

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Show information about a transfer to/from this address.
struct GET_TRANSFER_BY_TXID : RESTRICTED {
    static constexpr auto names() { return NAMES("get_transfer_by_txid"); }

    struct request {
        std::string txid;        // Transaction ID used to find the transfer.
        uint32_t account_index;  // (Optional) Index of the account to query for the transfer.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        wallet::transfer_view transfer;              //
        std::list<wallet::transfer_view> transfers;  //

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Sign a string.
struct SIGN : RESTRICTED {
    static constexpr auto names() { return NAMES("sign"); }

    struct request {
        std::string data;        // Anything you need to sign.
        uint32_t account_index;  // The account to use for signing
        uint32_t address_index;  // The subaddress in the account to sign with

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string signature;  // Signature generated against the "data" and the account public
                                // address.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Verify a signature on a string.
struct VERIFY : RESTRICTED {
    static constexpr auto names() { return NAMES("verify"); }

    struct request {
        std::string data;       // What should have been signed.
        std::string address;    // Public address of the wallet used to sign the data.
        std::string signature;  // Signature generated by `sign` method.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        bool good;  //

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Export all outputs in hex format.
struct EXPORT_OUTPUTS : RESTRICTED {
    static constexpr auto names() { return NAMES("export_outputs"); }

    struct request {
        bool all;

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string outputs_data_hex;  // Wallet outputs in hex format.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Export transfers to csv
struct EXPORT_TRANSFERS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("export_transfers"); }

    struct request {
        bool in = false;
        bool out = false;
        bool stake = false;
        bool pending = false;
        bool failed = false;
        bool pool = false;
        bool coinbase = false;
        bool filter_by_height = false;
        uint64_t min_height = 0;
        uint64_t max_height = cryptonote::MAX_BLOCK_NUMBER;
        std::set<uint32_t> subaddr_indices;
        uint32_t account_index;
        bool all_accounts;

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string data;  // CSV data to be written to file by wallet

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Import outputs in hex format.
struct IMPORT_OUTPUTS : RESTRICTED {
    static constexpr auto names() { return NAMES("import_outputs"); }

    struct request {
        std::string outputs_data_hex;  // Wallet outputs in hex format.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        uint64_t num_imported;  // Number of outputs imported.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Export a signed set of key images.
struct EXPORT_KEY_IMAGES : RPC_COMMAND {
    static constexpr auto names() { return NAMES("export_key_images"); }

    struct request {
        bool requested_only;  // Default `false`.

        KV_MAP_SERIALIZABLE
    };

    struct signed_key_image {
        std::string key_image;  //
        std::string signature;  //

        KV_MAP_SERIALIZABLE
    };

    struct response {
        uint32_t offset;                                  //
        std::vector<signed_key_image> signed_key_images;  //

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Import signed key images list and verify their spent status.
struct IMPORT_KEY_IMAGES : RESTRICTED {
    static constexpr auto names() { return NAMES("import_key_images"); }

    struct signed_key_image {
        std::string key_image;  // Key image of specific output
        std::string signature;  // Transaction signature.

        KV_MAP_SERIALIZABLE
    };

    struct request {
        uint32_t offset;
        std::vector<signed_key_image> signed_key_images;

        KV_MAP_SERIALIZABLE
    };

    struct response {
        uint64_t height;
        uint64_t spent;    // Amount (in atomic units) spent from those key images.
        uint64_t unspent;  // Amount (in atomic units) still available from those key images.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
struct uri_spec {
    std::string address;         // Wallet address.
    std::string payment_id;      // (Optional) 16 or 64 character hexadecimal payment id.
    uint64_t amount;             // (Optional) the integer amount to receive, in atomic units.
    std::string tx_description;  // (Optional) Description of the reason for the tx.
    std::string recipient_name;  // (Optional) name of the payment recipient.

    KV_MAP_SERIALIZABLE
};

OXEN_RPC_DOC_INTROSPECT
// Create a payment URI using the official URI spec.
struct MAKE_URI : RPC_COMMAND {
    static constexpr auto names() { return NAMES("make_uri"); }

    struct request : public uri_spec {};

    struct response {
        std::string uri;  // This contains all the payment input information as a properly formatted
                          // payment URI.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Parse a payment URI to get payment information.
struct PARSE_URI : RPC_COMMAND {
    static constexpr auto names() { return NAMES("parse_uri"); }

    struct request {
        std::string uri;  // This contains all the payment input information as a properly formatted
                          // payment URI.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        uri_spec uri;                                 // JSON object containing payment information:
        std::vector<std::string> unknown_parameters;  //

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Add an entry to the address book.
struct ADD_ADDRESS_BOOK_ENTRY : RESTRICTED {
    static constexpr auto names() { return NAMES("add_address_book"); }

    struct request {
        std::string address;      // Public address of the entry.
        std::string description;  // (Optional), defaults to "".

        KV_MAP_SERIALIZABLE
    };

    struct response {
        uint64_t index;  // The index of the address book entry.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Edit a entry in the address book.
struct EDIT_ADDRESS_BOOK_ENTRY : RESTRICTED {
    static constexpr auto names() { return NAMES("edit_address_book"); }

    struct request {
        uint64_t index;
        bool set_address;
        std::string address;
        bool set_description;
        std::string description;

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Retrieves entries from the address book.
struct GET_ADDRESS_BOOK_ENTRY : RESTRICTED {
    static constexpr auto names() { return NAMES("get_address_book"); }

    struct request {
        std::list<uint64_t> entries;  // Indices of the requested address book entries.

        KV_MAP_SERIALIZABLE
    };

    struct entry {
        uint64_t index;           // Index of entry.
        std::string address;      // Public address of the entry
        std::string description;  // Description of this address entry.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::vector<entry> entries;  // List of address book entries information.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Delete an entry from the address book.
struct DELETE_ADDRESS_BOOK_ENTRY : RESTRICTED {
    static constexpr auto names() { return NAMES("delete_address_book"); }

    struct request {
        uint64_t index;  // The index of the address book entry.

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Rescan the blockchain for spent outputs.
struct RESCAN_SPENT : RESTRICTED {
    static constexpr auto names() { return NAMES("rescan_spent"); }

    struct request : EMPTY {};

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Refresh a wallet after opening.
struct REFRESH : RESTRICTED {
    static constexpr auto names() { return NAMES("refresh"); }

    struct request {
        uint64_t start_height;  // (Optional) The block height from which to start refreshing.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        uint64_t blocks_fetched;  // Number of new blocks scanned.
        bool received_money;  // States if transactions to the wallet have been found in the blocks.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
struct AUTO_REFRESH : RESTRICTED {
    static constexpr auto names() { return NAMES("auto_refresh"); }

    struct request {
        bool enable;
        uint32_t period;  // seconds

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Start mining in the oxen daemon.
struct START_MINING : RPC_COMMAND {
    static constexpr auto names() { return NAMES("start_mining"); }

    struct request {
        uint64_t threads_count;  // Number of threads created for mining.

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Stop mining in the oxen daemon.
struct STOP_MINING : RPC_COMMAND {
    static constexpr auto names() { return NAMES("stop_mining"); }

    struct request : EMPTY {};

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Get a list of available languages for your wallet's seed.
struct GET_LANGUAGES : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_languages"); }

    struct request : EMPTY {};

    struct response {
        std::vector<std::string> languages;  // List of available languages.
        std::vector<std::string>
                languages_local;  // List of available languages in the native language

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Create a new wallet. You need to have set the argument "'--wallet-dir" when launching
// oxen-wallet-rpc to make this work.
struct CREATE_WALLET : RPC_COMMAND {
    static constexpr auto names() { return NAMES("create_wallet"); }

    struct request {
        std::string filename;  // Set the wallet file name.
        std::string password;  // (Optional) Set the password to protect the wallet.
        std::string language;  // Language for your wallets' seed.
        bool hardware_wallet;  // Create this wallet from a connected hardware wallet.  (`language`
                               // will be ignored).
        std::string
                device_name;  // When `hardware` is true, this specifies the hardware wallet device
                              // type (currently supported: "Ledger").  If omitted "Ledger" is used.
        std::optional<std::string>
                device_label;  // Custom label to write to a `wallet.hwdev.txt`. Can be empty; omit
                               // the parameter entirely to not write a .hwdev.txt file at all.

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Open a wallet. You need to have set the argument "--wallet-dir" when launching oxen-wallet-rpc to
// make this work. The wallet rpc executable may only open wallet files within the same directory as
// wallet-dir, otherwise use the
// "--wallet-file" flag to open specific wallets.
struct OPEN_WALLET : RPC_COMMAND {
    static constexpr auto names() { return NAMES("open_wallet"); }

    struct request {
        std::string filename;   // Wallet name stored in "--wallet-dir".
        std::string password;   // The wallet password, set as "" if there's no password
        bool autosave_current;  // (Optional: Default true): If a pre-existing wallet is open, save
                                // to disk before opening the new wallet.

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Close the currently opened wallet, after trying to save it.
struct CLOSE_WALLET : RPC_COMMAND {
    static constexpr auto names() { return NAMES("close_wallet"); }

    struct request {
        bool autosave_current;  // Save the wallet state on close

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Change a wallet password.
struct CHANGE_WALLET_PASSWORD : RESTRICTED {
    static constexpr auto names() { return NAMES("change_wallet_password"); }

    struct request {
        std::string old_password;  // (Optional) Current wallet password, if defined.
        std::string new_password;  // (Optional) New wallet password, if not blank.

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Restore a wallet using the private spend key, view key and public address.
struct GENERATE_FROM_KEYS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("generate_from_keys"); }

    struct request {
        uint64_t restore_height;  // (Optional: Default 0) Height in which to start scanning the
                                  // blockchain for transactions into and out of this Wallet.
        std::string filename;     // Set the name of the wallet.
        std::string address;      // The public address of the wallet.
        std::string spendkey;     // The private spend key of the wallet
        std::string viewkey;      // The private view key of the wallet.
        std::string password;     // Set password for Wallet.
        bool autosave_current;  // (Optional: Default true): If a pre-existing wallet is open, save
                                // to disk before opening the new wallet.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string address;
        std::string info;

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Restore a wallet using the seed words.
struct RESTORE_DETERMINISTIC_WALLET : RPC_COMMAND {
    static constexpr auto names() { return NAMES("restore_deterministic_wallet"); }

    struct request {
        uint64_t restore_height;  // Height in which to start scanning the blockchain for
                                  // transactions into and out of this Wallet.
        std::string filename;     // Set the name of the Wallet.
        std::string seed;         // Mnemonic seed of wallet (25 words).
        std::string seed_offset;  //
        std::string password;     // Set password for Wallet.
        std::string language;     // Set language for the wallet.
        bool autosave_current;  // (Optional: Default true): If a pre-existing wallet is open, save
                                // to disk before opening the new wallet.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string address;  // Public address of wallet.
        std::string seed;     // Seed of wallet.
        std::string info;     // Wallet information.
        bool was_deprecated;  //

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Check if a wallet is a multisig one.
struct IS_MULTISIG : RPC_COMMAND {
    static constexpr auto names() { return NAMES("is_multisig"); }

    struct request : EMPTY {};

    struct response {
        bool multisig;       // States if the wallet is multisig.
        bool ready;          //
        uint32_t threshold;  // Amount of signature needed to sign a transfer.
        uint32_t total;      // Total amount of signature in the multisig wallet.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Prepare a wallet for multisig by generating a multisig string to share with peers.
struct PREPARE_MULTISIG : RESTRICTED {
    static constexpr auto names() { return NAMES("prepare_multisig"); }

    struct request : EMPTY {};

    struct response {
        std::string multisig_info;  // Multisig string to share with peers to create the multisig
                                    // wallet.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Make a wallet multisig by importing peers multisig string.
struct MAKE_MULTISIG : RESTRICTED {
    static constexpr auto names() { return NAMES("make_multisig"); }

    struct request {
        std::vector<std::string> multisig_info;  // List of multisig string from peers.
        uint32_t threshold;    // Amount of signatures needed to sign a transfer. Must be less or
                               // equal than the amount of signature in `multisig_info`.
        std::string password;  // Wallet password.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string address;        // Multisig wallet address.
        std::string multisig_info;  // Multisig string to share with peers to create the multisig
                                    // wallet (extra step for N-1/N wallets).

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Export multisig info for other participants.
struct EXPORT_MULTISIG : RESTRICTED {
    static constexpr auto names() { return NAMES("export_multisig_info"); }

    struct request : EMPTY {};

    struct response {
        std::string info;  // Multisig info in hex format for other participants.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Import multisig info from other participants.
struct IMPORT_MULTISIG : RESTRICTED {
    static constexpr auto names() { return NAMES("import_multisig_info"); }

    struct request {
        std::vector<std::string>
                info;  // List of multisig info in hex format from other participants.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        uint64_t n_outputs;  // Number of outputs signed with those multisig info.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Turn this wallet into a multisig wallet, extra step for N-1/N wallets.
struct FINALIZE_MULTISIG : RESTRICTED {
    static constexpr auto names() { return NAMES("finalize_multisig"); }

    struct request {
        std::string password;                    // Wallet password.
        std::vector<std::string> multisig_info;  // List of multisig string from peers.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string address;  // Multisig wallet address.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
//
struct EXCHANGE_MULTISIG_KEYS : RESTRICTED {
    static constexpr auto names() { return NAMES("exchange_multisig_keys"); }

    struct request {
        std::string password;                    // Wallet password.
        std::vector<std::string> multisig_info;  // List of multisig string from peers.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string address;        // Multisig wallet address.
        std::string multisig_info;  // Multisig string to share with peers to create the multisig
                                    // wallet.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Sign a transaction in multisig.
struct SIGN_MULTISIG : RESTRICTED {
    static constexpr auto names() { return NAMES("sign_multisig"); }

    struct request {
        std::string tx_data_hex;  // Multisig transaction in hex format, as returned by transfer
                                  // under `multisig_txset`.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string tx_data_hex;              // Multisig transaction in hex format.
        std::list<std::string> tx_hash_list;  // List of transaction Hash.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Submit a signed multisig transaction.
struct SUBMIT_MULTISIG : RESTRICTED {
    static constexpr auto names() { return NAMES("submit_multisig"); }

    struct request {
        std::string tx_data_hex;  // Multisig transaction in hex format, as returned by
                                  // sign_multisig under tx_data_hex.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::list<std::string> tx_hash_list;  // List of transaction hash.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Get RPC version Major & Minor integer-format, where Major is the first 16 bits and Minor the last
// 16 bits.
struct GET_VERSION : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_version"); }

    struct request : EMPTY {};

    struct response {
        uint32_t version;  // RPC version, formatted with Major * 2^16 + Minor(Major encoded over
                           // the first 16 bits, and Minor over the last 16 bits).

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Stake for Service Node.
struct STAKE : RESTRICTED {
    static constexpr auto names() { return NAMES("stake"); }

    struct request {
        std::string destination;             // Primary Public address that the rewards will go to.
        uint64_t amount;                     // Amount of Loki to stake in atomic units.
        std::set<uint32_t> subaddr_indices;  // (Optional) Transfer from this set of subaddresses.
                                             // (Defaults to 0)
        std::string service_node_key;        // Service Node Public Address.
        uint32_t priority;  // Set a priority for the transaction. Accepted values are: or 0-4 for:
                            // default, unimportant, normal, elevated, priority.
        bool get_tx_key;    // (Optional) Return the transaction key after sending.
        bool do_not_relay;  // (Optional) If true, the newly created transaction will not be relayed
                            // to the oxen network. (Defaults to false)
        bool get_tx_hex;  // Return the transaction as hex string after sending (Defaults to false)
        bool get_tx_metadata;  // Return the metadata needed to relay the transaction. (Defaults to
                               // false)

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string tx_hash;  // Publicly searchable transaction hash.
        std::string tx_key;   // Transaction key if `get_tx_key` is `true`, otherwise, blank string.
        uint64_t amount;      // Amount transferred for the transaction in atomic units.
        uint64_t fee;         // Value in atomic units of the fee charged for the tx.
        std::string tx_blob;  // Raw transaction represented as hex string, if get_tx_hex is true.
        std::string tx_metadata;     // Set of transaction metadata needed to relay this transfer
                                     // later, if `get_tx_metadata` is `true`.
        std::string multisig_txset;  // Set of multisig transactions in the process of being signed
                                     // (empty for non-multisig).
        std::string unsigned_txset;  // Set of unsigned tx for cold-signing purposes.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Register Service Node.
struct REGISTER_SERVICE_NODE : RESTRICTED {
    static constexpr auto names() { return NAMES("register_service_node"); }

    struct request {
        std::string
                register_service_node_str;  // String supplied by the prepare_registration command.
        bool get_tx_key;                    // (Optional) Return the transaction key after sending.
        bool do_not_relay;  // (Optional) If true, the newly created transaction will not be relayed
                            // to the oxen network. (Defaults to false)
        bool get_tx_hex;  // Return the transaction as hex string after sending (Defaults to false)
        bool get_tx_metadata;  // Return the metadata needed to relay the transaction. (Defaults to
                               // false)

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string tx_hash;  // Publicly searchable transaction hash.
        std::string tx_key;   // Transaction key if get_tx_key is true, otherwise, blank string.
        uint64_t amount;      // Amount transferred for the transaction in atomic units.
        uint64_t fee;         // Value in atomic units of the fee charged for the tx.
        std::string tx_blob;  // Raw transaction represented as hex string, if get_tx_hex is true.
        std::string tx_metadata;     // Set of transaction metadata needed to relay this transfer
                                     // later, if `get_tx_metadata` is `true`.
        std::string multisig_txset;  // Set of multisig transactions in the process of being signed
                                     // (empty for non-multisig).
        std::string unsigned_txset;  // Set of unsigned tx for cold-signing purposes.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Request to unlock stake by deregistering Service Node.
struct REQUEST_STAKE_UNLOCK : RESTRICTED {
    static constexpr auto names() { return NAMES("request_stake_unlock"); }

    struct request {
        std::string service_node_key;  // Service Node Public Key.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        bool unlocked;    // States if stake has been unlocked.
        std::string msg;  // Information on the unlocking process.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Check if Service Node can unlock its stake.
struct CAN_REQUEST_STAKE_UNLOCK : RESTRICTED {
    static constexpr auto names() { return NAMES("can_request_stake_unlock"); }

    struct request {
        std::string service_node_key;  // Service node public address.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        bool can_unlock;  // States if the stake can be locked.
        std::string msg;  // Information on the unlocking process.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Parse an address to validate if it's a valid Loki address.
struct VALIDATE_ADDRESS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("validate_address"); }

    struct request {
        std::string address;   // Address to check.
        bool any_net_type;     //
        bool allow_openalias;  //

        KV_MAP_SERIALIZABLE
    };

    struct response {
        bool valid;           // States if it is a valid Loki address.
        bool integrated;      // States if it is an integrated address.
        bool subaddress;      // States if it is a subaddress.
        std::string nettype;  // States if the nettype is mainet, testnet, devnet.
        std::string openalias_address;

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
struct SET_DAEMON : RESTRICTED {
    static constexpr auto names() { return NAMES("set_daemon"); }

    struct request {
        std::string address;  // The remote url of the daemon.
        std::string proxy;    // Optional proxy to use for connection. E.g. socks4a://hostname:port
                              // for a SOCKS proxy.
        bool trusted;         // When true, allow the usage of commands that may compromise privacy
        std::string ssl_private_key_path;  // HTTPS client authentication: path to private key. Must
                                           // use an address starting with https://
        std::string ssl_certificate_path;  // HTTPS client authentication: path to certificate. Must
                                           // use an address starting with https://
        std::string
                ssl_ca_file;  // Path to CA bundle to use for HTTPS server certificate verification
                              // instead of system CA.  Requires an https:// address.
        bool ssl_allow_any_cert;  // Make HTTPS insecure: disable HTTPS certificate verification
                                  // when using an https:// address.

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
struct SET_LOG_LEVEL : RESTRICTED {
    static constexpr auto names() { return NAMES("set_log_level"); }

    struct request {
        int8_t level;

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
struct SET_LOG_CATEGORIES : RESTRICTED {
    static constexpr auto names() { return NAMES("set_log_categories"); }

    struct request {
        std::string categories;

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string categories;

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
struct ONS_BUY_MAPPING : RESTRICTED {
    static constexpr auto names() { return NAMES("ons_buy_mapping"); }

    static constexpr const char* description =
            R"(Buy a Loki Name System (ONS) mapping that maps a unique name to a Session ID or Lokinet address.

Currently supports Session, Lokinet and Wallet registrations. Lokinet registrations can be for 1, 2, 5, or 10 years by specifying a type value of "lokinet", "lokinet_2y", "lokinet_5y", "lokinet_10y". Session registrations do not expire.

The owner of the ONS entry (by default, the purchasing wallet) will be permitted to submit ONS update transactions to the Loki blockchain (for example to update a Session pubkey or the target Lokinet address). You may change the primary owner or add a backup owner in the registration and can change them later with update transactions. Owner addresses can be either Loki wallets, or generic ed25519 pubkeys (for advanced uses).

For Session, the recommended owner or backup owner is the ed25519 public key of the user's Session ID.

When specifying owners, either a wallet (sub)address or standard ed25519 public key is supported per mapping. Updating the value that a name maps to requires one of the owners to sign the update transaction. For wallets, this is signed using the (sub)address's spend key.

For more information on updating and signing see the ONS_UPDATE_MAPPING documentation.)";

    struct request {
        std::string type;   // The mapping type: "session", "lokinet", "lokinet_2y", "lokinet_5y",
                            // "lokinet_10y", "wallet".
        std::string owner;  // (Optional): The ed25519 public key or wallet address that has
                            // authority to update the mapping.
        std::string backup_owner;  // (Optional): The secondary, backup public key that has
                                   // authority to update the mapping.
        std::string name;          // The name to purchase via Oxen Name Service
        std::string value;  // The value that the name maps to via Oxen Name Service, (i.e. For
                            // Session: [display name->session public key],  for wallets:
                            // [name->wallet address], for Lokinet: [name->domain name]).

        uint32_t account_index;  // (Optional) Transfer from this account index. (Defaults to 0)
        std::set<uint32_t> subaddr_indices;  // (Optional) Transfer from this set of subaddresses.
                                             // (Defaults to 0)
        uint32_t priority;  // Set a priority for the transaction. Accepted values are: or 0-4 for:
                            // default, unimportant, normal, elevated, priority.
        bool get_tx_key;    // (Optional) Return the transaction key after sending.
        bool do_not_relay;  // (Optional) If true, the newly created transaction will not be relayed
                            // to the oxen network. (Defaults to false)
        bool get_tx_hex;  // Return the transaction as hex string after sending (Defaults to false)
        bool get_tx_metadata;  // Return the metadata needed to relay the transaction. (Defaults to
                               // false)

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string tx_hash;  // Publicly searchable transaction hash.
        std::string tx_key;   // Transaction key if `get_tx_key` is `true`, otherwise, blank string.
        uint64_t amount;      // Amount transferred for the transaction in atomic units.
        uint64_t fee;         // Value in atomic units of the fee charged for the tx.
        std::string tx_blob;  // Raw transaction represented as hex string, if get_tx_hex is true.
        std::string tx_metadata;     // Set of transaction metadata needed to relay this transfer
                                     // later, if `get_tx_metadata` is `true`.
        std::string multisig_txset;  // Set of multisig transactions in the process of being signed
                                     // (empty for non-multisig).
        std::string unsigned_txset;  // Set of unsigned tx for cold-signing purposes.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Renew an active lokinet ONS registration
struct ONS_RENEW_MAPPING : RESTRICTED {
    static constexpr auto names() { return NAMES("ons_renew_mapping"); }

    static constexpr const char* description =
            R"(Renews a Loki Name System lokinet mapping by adding to the existing expiry time.

The renewal can be for 1, 2, 5, or 10 years by specifying a `type` value of "lokinet_2y", "lokinet_10y", etc.)";

    struct request {
        std::string type;  // The mapping type, "lokinet" (1-year), or "lokinet_2y", "lokinet_5y",
                           // "lokinet_10y" for multi-year registrations.
        std::string name;  // The name to update

        uint32_t account_index;  // (Optional) Transfer from this account index. (Defaults to 0)
        std::set<uint32_t> subaddr_indices;  // (Optional) Transfer from this set of subaddresses.
                                             // (Defaults to 0)
        uint32_t priority;  // Set a priority for the transaction. Accepted values are: 0-4 for:
                            // default, unimportant, normal, elevated, priority.
        bool get_tx_key;    // (Optional) Return the transaction key after sending.
        bool do_not_relay;  // (Optional) If true, the newly created transaction will not be relayed
                            // to the oxen network. (Defaults to false)
        bool get_tx_hex;  // Return the transaction as hex string after sending (Defaults to false)
        bool get_tx_metadata;  // Return the metadata needed to relay the transaction. (Defaults to
                               // false)

        KV_MAP_SERIALIZABLE
    };

    using response = ONS_BUY_MAPPING::response;
};

OXEN_RPC_DOC_INTROSPECT
// Update the underlying value in the name->value mapping via Loki Name Service.
struct ONS_UPDATE_MAPPING : RESTRICTED {
    static constexpr auto names() { return NAMES("ons_update_mapping"); }

    static constexpr const char* description =
            R"(Update a Loki Name System mapping to refer to a new address or owner.

At least one field (value, owner, or backup owner) must be specified in the update.

The existing owner (wallet address or ed25519 public key) of the mapping must be used to sign the update. If no signature is provided then the wallet's active address (or subaddress) will be used to sign the update.

If signing is performed externally then you must first encrypt the `value` (if being updated), then sign a BLAKE2b hash of {encryptedvalue || owner || backup_owner || txid} (where txid is the most recent ONS update or registration transaction of this mapping; each of encrypted/owner/backup are empty strings if not being updated). For a wallet owner this is signed using the owning wallet's spend key; for a Ed25519 key this is a standard Ed25519 signature.)";

    struct request {
        std::string type;   // The mapping type, "session", "lokinet", or "wallet".
        std::string name;   // The name to update via Loki Name Service
        std::string value;  // (Optional): The new value that the name maps to via Loki Name
                            // Service. If not specified or given the empty string "", then the
                            // mapping's value remains unchanged. If using a `signature` then this
                            // value (if non-empty) must be already encrypted.
        std::string owner;  // (Optional): The new owner of the mapping. If not specified or given
                            // the empty string "", then the mapping's owner remains unchanged.
        std::string backup_owner;  // (Optional): The new backup owner of the mapping. If not
                                   // specified or given the empty string "", then the mapping's
                                   // backup owner remains unchanged.
        std::string signature;     // (Optional): Signature derived using libsodium generichash on
                                // {current txid blob, new value blob} of the mapping to update. By
                                // default the hash is signed using the wallet's spend key as an
                                // ed25519 keypair, if signature is specified.

        uint32_t account_index;  // (Optional) Transfer from this account index. (Defaults to 0)
        std::set<uint32_t> subaddr_indices;  // (Optional) Transfer from this set of subaddresses.
                                             // (Defaults to 0)
        uint32_t priority;  // Set a priority for the transaction. Accepted values are: 0-4 for:
                            // default, unimportant, normal, elevated, priority.
        bool get_tx_key;    // (Optional) Return the transaction key after sending.
        bool do_not_relay;  // (Optional) If true, the newly created transaction will not be relayed
                            // to the oxen network. (Defaults to false)
        bool get_tx_hex;  // Return the transaction as hex string after sending (Defaults to false)
        bool get_tx_metadata;  // Return the metadata needed to relay the transaction. (Defaults to
                               // false)

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string tx_hash;  // Publicly searchable transaction hash.
        std::string tx_key;   // Transaction key if `get_tx_key` is `true`, otherwise, blank string.
        uint64_t amount;      // Amount transferred for the transaction in atomic units.
        uint64_t fee;         // Value in atomic units of the fee charged for the tx.
        std::string tx_blob;  // Raw transaction represented as hex string, if get_tx_hex is true.
        std::string tx_metadata;     // Set of transaction metadata needed to relay this transfer
                                     // later, if `get_tx_metadata` is `true`.
        std::string multisig_txset;  // Set of multisig transactions in the process of being signed
                                     // (empty for non-multisig).
        std::string unsigned_txset;  // Set of unsigned tx for cold-signing purposes.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
struct ONS_MAKE_UPDATE_SIGNATURE : RESTRICTED {
    static constexpr auto names() { return NAMES("ons_make_update_mapping_signature"); }

    static constexpr const char* description =
            R"(Generate the signature necessary for updating the requested record using the wallet's active [sub]address's spend key. The signature is only valid if the queried wallet is one of the owners of the ONS record.

This command is only required if the open wallet is one of the owners of a ONS record but wants the update transaction to occur via another non-owning wallet. By default, if no signature is specified to the update transaction, the open wallet is assumed the owner and it's active [sub]address's spend key will automatically be used.)";

    struct request {
        std::string type;  // The mapping type, currently we support "session", "lokinet" and
                           // "wallet" mappings.
        std::string name;  // The desired name to update via Oxen Name Service
        std::string encrypted_value;  // (Optional): The new encrypted value that the name maps to
                                      // via Oxen Name Service. If not specified or given the empty
                                      // string "", then the mapping's value remains unchanged.
        std::string owner;  // (Optional): The new owner of the mapping. If not specified or given
                            // the empty string "", then the mapping's owner remains unchanged.
        std::string backup_owner;  // (Optional): The new backup owner of the mapping. If not
                                   // specified or given the empty string "", then the mapping's
                                   // backup owner remains unchanged.
        uint32_t account_index;    // (Optional) Use this wallet's subaddress account for generating
                                   // the signature

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string
                signature;  // A signature valid for using in ONS to update an underlying mapping.

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Takes a ONS name, upon validating it, generates the hash and returns the base64 representation of
// the hash suitable for use in the daemon ONS name queries.
struct ONS_HASH_NAME : RPC_COMMAND {
    static constexpr auto names() { return NAMES("ons_hash_name"); }

    struct request {
        std::string type;  // The mapping type, "session", "lokinet" or "wallet".
        std::string name;  // The desired name to hash

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string name;  // The name hashed and represented in base64

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Returns a list of known, plain-text ONS names along with record details for names that this
// wallet knows about.  This can optionally decrypt the ONS value as well, or else just return the
// encrypted value.
struct ONS_KNOWN_NAMES : RPC_COMMAND {
    static constexpr auto names() { return NAMES("ons_known_names"); }

    struct known_record {
        std::string type;    // The mapping type, "session" or "lokinet".
        std::string hashed;  // The hashed name (in base64)
        std::string name;    // The plaintext name
        std::string owner;   // The public key that purchased the Loki Name Service entry.
        std::optional<std::string> backup_owner;  // The backup public key or wallet that the owner
                                                  // specified when purchasing the Loki Name Service
                                                  // entry. Omitted if no backup owner.
        std::string encrypted_value;       // The encrypted value that the name maps to, in hex.
        std::optional<std::string> value;  // Decrypted value that that name maps to.  Only provided
                                           // if `decrypt: true` was specified in the request.
        uint64_t update_height;  // The last height that this Loki Name Service entry was updated on
                                 // the Blockchain.
        std::optional<uint64_t> expiration_height;  // For records that expire, this will be set to
                                                    // the expiration block height.
        std::optional<bool>
                expired;  // Indicates whether the record has expired. Only included in the response
                          // if "include_expired" is specified in the request.
        std::string txid;  // The txid of the mapping's most recent update or purchase.

        KV_MAP_SERIALIZABLE
    };
    struct request {
        bool decrypt;  // If true (default false) then also decrypt and include the `value` field
        bool include_expired;  // If true (default false) then also include expired records

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::vector<known_record> known_names;  // List of records known to this wallet

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Adds one or more names to the persistent ONS wallet cache of known names (i.e. for names that
// are owned by this wallet that aren't currently in the cache).
struct ONS_ADD_KNOWN_NAMES : RPC_COMMAND {
    static constexpr auto names() { return NAMES("ons_add_known_names"); }

    struct record {
        std::string type;  // The ONS type (mandatory); currently support values are: "session",
                           // "lokinet"
        std::string name;  // The (unhashed) name of the record

        KV_MAP_SERIALIZABLE
    };

    struct request {
        std::vector<record> names;  // List of names to add to the cache

        KV_MAP_SERIALIZABLE
    };

    using response = EMPTY;
};

OXEN_RPC_DOC_INTROSPECT
// Takes a ONS encrypted value and encrypts the mapping value using the ONS name.
struct ONS_ENCRYPT_VALUE : RPC_COMMAND {
    static constexpr auto names() { return NAMES("ons_encrypt_value"); }

    struct request {
        std::string name;   // The ONS name with which to encrypt the value.
        std::string type;   // The mapping type: "session" or "lokinet".
        std::string value;  // The value to be encrypted.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string encrypted_value;  // The encrypted value, in hex

        KV_MAP_SERIALIZABLE
    };
};

OXEN_RPC_DOC_INTROSPECT
// Takes a ONS encrypted value and decrypts the mapping value using the ONS name.
struct ONS_DECRYPT_VALUE : RPC_COMMAND {
    static constexpr auto names() { return NAMES("ons_decrypt_value"); }

    struct request {
        std::string name;             // The ONS name of the given encrypted value.
        std::string type;             // The mapping type: "session" or "lokinet".
        std::string encrypted_value;  // The encrypted value represented in hex.

        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string value;  // The value decrypted

        KV_MAP_SERIALIZABLE
    };
};

/// List of all supported rpc command structs to allow compile-time enumeration of all supported
/// RPC types.  Every type added above that has an RPC endpoint needs to be added here, and needs
/// a core_rpc_server::invoke() overload that takes a <TYPE>::request and returns a
/// <TYPE>::response.  The <TYPE>::request has to be unique (for overload resolution);
/// <TYPE>::response does not.
using wallet_rpc_types = tools::type_list<
        GET_BALANCE,
        GET_ADDRESS,
        GET_ADDRESS_INDEX,
        CREATE_ADDRESS,
        LABEL_ADDRESS,
        GET_ACCOUNTS,
        CREATE_ACCOUNT,
        LABEL_ACCOUNT,
        GET_ACCOUNT_TAGS,
        TAG_ACCOUNTS,
        UNTAG_ACCOUNTS,
        SET_ACCOUNT_TAG_DESCRIPTION,
        GET_HEIGHT,
        TRANSFER,
        TRANSFER_SPLIT,
        DESCRIBE_TRANSFER,
        SIGN_TRANSFER,
        SUBMIT_TRANSFER,
        SWEEP_DUST,
        SWEEP_ALL,
        SWEEP_SINGLE,
        RELAY_TX,
        STORE,
        GET_PAYMENTS,
        GET_BULK_PAYMENTS,
        INCOMING_TRANSFERS,
        QUERY_KEY,
        MAKE_INTEGRATED_ADDRESS,
        SPLIT_INTEGRATED_ADDRESS,
        STOP_WALLET,
        RESCAN_BLOCKCHAIN,
        SET_TX_NOTES,
        GET_TX_NOTES,
        SET_ATTRIBUTE,
        GET_ATTRIBUTE,
        GET_TX_KEY,
        CHECK_TX_KEY,
        GET_TX_PROOF,
        CHECK_TX_PROOF,
        GET_SPEND_PROOF,
        CHECK_SPEND_PROOF,
        GET_RESERVE_PROOF,
        CHECK_RESERVE_PROOF,
        GET_TRANSFERS,
        GET_TRANSFERS_CSV,
        GET_TRANSFER_BY_TXID,
        SIGN,
        VERIFY,
        EXPORT_OUTPUTS,
        EXPORT_TRANSFERS,
        IMPORT_OUTPUTS,
        EXPORT_KEY_IMAGES,
        IMPORT_KEY_IMAGES,
        MAKE_URI,
        PARSE_URI,
        ADD_ADDRESS_BOOK_ENTRY,
        EDIT_ADDRESS_BOOK_ENTRY,
        GET_ADDRESS_BOOK_ENTRY,
        DELETE_ADDRESS_BOOK_ENTRY,
        RESCAN_SPENT,
        REFRESH,
        AUTO_REFRESH,
        START_MINING,
        STOP_MINING,
        GET_LANGUAGES,
        CREATE_WALLET,
        OPEN_WALLET,
        CLOSE_WALLET,
        CHANGE_WALLET_PASSWORD,
        GENERATE_FROM_KEYS,
        RESTORE_DETERMINISTIC_WALLET,
        IS_MULTISIG,
        PREPARE_MULTISIG,
        MAKE_MULTISIG,
        EXPORT_MULTISIG,
        IMPORT_MULTISIG,
        FINALIZE_MULTISIG,
        EXCHANGE_MULTISIG_KEYS,
        SIGN_MULTISIG,
        SUBMIT_MULTISIG,
        GET_VERSION,
        STAKE,
        REGISTER_SERVICE_NODE,
        REQUEST_STAKE_UNLOCK,
        CAN_REQUEST_STAKE_UNLOCK,
        VALIDATE_ADDRESS,
        SET_DAEMON,
        SET_LOG_LEVEL,
        SET_LOG_CATEGORIES,
        ONS_BUY_MAPPING,
        ONS_UPDATE_MAPPING,
        ONS_RENEW_MAPPING,
        ONS_MAKE_UPDATE_SIGNATURE,
        ONS_HASH_NAME,
        ONS_KNOWN_NAMES,
        ONS_ADD_KNOWN_NAMES,
        ONS_DECRYPT_VALUE,
        ONS_ENCRYPT_VALUE>;

}  // namespace tools::wallet_rpc
