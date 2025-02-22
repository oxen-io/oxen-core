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
#include "rpc/common/command_decorators.h"
#include "rpc/common/rpc_version.h"
#include "wallet/transfer_destination.h"
#include "wallet/transfer_view.h"

/// Namespace for wallet RPC commands.  Every RPC commands gets defined here and added to
/// `wallet_rpc_types` list at the bottom of the file.
namespace wallet::rpc {

using version_t = std::pair<uint16_t, uint16_t>;

// When making *any* change here, bump minor
// If the change is incompatible, then bump major and set minor to 0
// This ensures WALLET_RPC_VERSION always increases, that every change
// has its own version, and that clients can just test major to see
// whether they can talk to a given wallet without having to know in
// advance which version they will stop working with
// Don't go over 32767 for any of these
constexpr version_t VERSION = {2, 0};

const static std::string STATUS_OK = "OK", STATUS_BUSY = "BUSY";

using cryptonote::rpc::LEGACY;
using cryptonote::rpc::NAMES;
using cryptonote::rpc::NO_ARGS;
using cryptonote::rpc::PUBLIC;
using cryptonote::rpc::RESTRICTED;
using cryptonote::rpc::RPC_COMMAND;
struct EMPTY {};

/// Return the wallet's balance.
///
/// Inputs:
///
/// - \p account_index -- Return balance for this account.
/// - \p address_indices -- (Optional) Return balance detail for those subaddresses.
/// - \p all_accounts -- If true, return balance for all accounts, subaddr_indices and account_index
/// are ignored
/// - \p strict -- If true, only return the balance for transactions that have been spent and are
/// not pending (i.e. excluding any transactions sitting in the TX pool)
///
/// Outputs:
///
/// - \p balance -- The total balance (atomic units) of the currently opened wallet.
/// - \p unlocked_balance -- Unlocked funds are those funds that are sufficiently deep enough in the
/// oxen blockchain to be considered safe to spend.
/// - \p multisig_import_needed -- True if importing multisig data is needed for returning a correct
/// balance.
/// - \p per_subaddress -- Balance information for each subaddress in an account.
///   - \p account_index -- Index of the account in the wallet.
///   - \p address_index -- Index of the subaddress in the account.
///   - \p address -- Address at this index. Base58 representation of the public keys.
///   - \p balance -- Balance for the subaddress (locked or unlocked).
///   - \p unlocked_balance -- Unlocked funds are those funds that are sufficiently deep enough in
///   the oxen blockchain to be considered safe to spend.
///   - \p label -- Label for the subaddress.
///   - \p num_unspent_outputs -- Number of unspent outputs available for the subaddress.
///   - \p blocks_to_unlock -- The number of blocks remaining for the balance to unlock
///   - \p time_to_unlock -- Timestamp of expected unlock
/// - \p blocks_to_unlock -- The number of blocks remaining for the balance to unlock
/// - \p time_to_unlock -- Timestamp of expected unlock
struct GET_BALANCE : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_balance", "getbalance"); }

    struct REQUEST {
        uint32_t account_index;  // Return balance for this account.
        std::vector<uint32_t>
                address_indices;  // (Optional) Return balance detail for those subaddresses.
        bool all_accounts;        // If true, return balance for all accounts, subaddr_indices and
                                  // account_index are ignored
        bool strict;  // If true, only return the balance for transactions that have been spent and
                      // are not pending (i.e. excluding any transactions sitting in the TX pool)
    } request;

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
    };
};

/// Return the wallet's addresses for an account. Optionally filter for specific set of
/// subaddresses.
///
/// Inputs:
///
/// - \p account_index -- Get the wallet addresses for the specified account.
/// - \p address_index -- (Optional) List of subaddresses to return from the aforementioned account.
///
/// Outputs:
///
/// - \p address -- (Deprecated) Remains to be compatible with older RPC format
/// - \p addresses -- Addresses informations.
///   - \p address -- The (sub)address string.
///   - \p label -- Label of the (sub)address.
///   - \p address_index -- Index of the subaddress
///   - \p used -- True if the (sub)address has received funds before.
struct GET_ADDRESS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_address", "getaddress"); }

    struct REQUEST {
        uint32_t account_index;               // Get the wallet addresses for the specified account.
        std::vector<uint32_t> address_index;  // (Optional) List of subaddresses to return from the
                                              // aforementioned account.
    } request;

    struct address_info {
        std::string address;     // The (sub)address string.
        std::string label;       // Label of the (sub)address.
        uint32_t address_index;  // Index of the subaddress
        bool used;               // True if the (sub)address has received funds before.
    };
};

/// Get account and address indexes from a specific (sub)address.
///
/// Inputs:
///
/// - \p address -- (Sub)address to look for.
///
/// Outputs:
///
/// - \p index -- Account index followed by the subaddress index.
struct GET_ADDRESS_INDEX : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_address_index"); }

    struct REQUEST {
        std::string address;  // (Sub)address to look for.
    } request;
};

/// Create a new address for an account. Optionally, label the new address.
///
/// Inputs:
///
/// - \p account_index -- Create a new subaddress for this account.
/// - \p label -- (Optional) Label for the new subaddress.
/// - \p count -- Number of addresses to create, defaults to 1.
///
/// Outputs:
///
/// - \p address -- The newly requested address.
/// - \p address_index -- Index of the new address in the requested account index.
/// - \p addresses -- The new addresses, if more than 1 is requested
/// - \p address_indices -- The new addresses indicies if more than 1 is requested
struct CREATE_ADDRESS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("create_address"); }

    struct REQUEST {
        uint32_t account_index;  // Create a new subaddress for this account.
        std::string label;       // (Optional) Label for the new subaddress.
        uint32_t count;          // Number of addresses to create, defaults to 1.
    } request;
};

/// Returns the status of the wallet
///
/// Inputs: No Inputs
///
/// Outputs:
///
/// - \p syncing -- True/False if the wallet is still syncing
/// - \p sync_height -- Current Height of Wallet
/// - \p target_height -- Desired Height of the Wallet
struct STATUS : NO_ARGS {
    static constexpr auto names() { return NAMES("status"); }
};

/// Label an address.
///
/// Inputs:
///
/// - \p index -- Major & minor address index
/// - \p label -- Label for the address.
///
/// Outputs: None
///
struct LABEL_ADDRESS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("label_address"); }

    struct REQUEST {
        cryptonote::subaddress_index index;  // Major & minor address index
        std::string label;                   // Label for the address.
    } request;
};

/// Get all accounts for a wallet. Optionally filter accounts by tag.
///
/// Inputs:
///
/// - \p tag -- (Optional) Tag for filtering accounts. All accounts if empty, otherwise those
/// accounts with this tag
/// - \p strict_balances -- If true, only return the balance for transactions that have been spent
/// and are not pending (i.e. excluding any transactions sitting in the TX pool)
///
/// Outputs:
///
/// - \p total_balance -- Total balance of the selected accounts (locked or unlocked).
/// - \p total_unlocked_balance -- Total unlocked balance of the selected accounts.
/// - \p subaddress_accounts -- Account information.
///   - \p account_index -- Index of the account.
///   - \p base_address -- The first address of the account (i.e. the primary address).
///   - \p balance -- Balance of the account (locked or unlocked).
///   - \p unlocked_balance -- Unlocked balance for the account.
///   - \p label -- (Optional) Label of the account.
///   - \p tag -- (Optional) Tag for filtering accounts.
struct GET_ACCOUNTS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_accounts"); }

    struct REQUEST {
        std::string tag;  // (Optional) Tag for filtering accounts. All accounts if empty, otherwise
                          // those accounts with this tag
        bool strict_balances;  // If true, only return the balance for transactions that have been
                               // spent and are not pending (i.e. excluding any transactions sitting
                               // in the TX pool)
    } request;

    struct subaddress_account_info {
        uint32_t account_index;     // Index of the account.
        std::string base_address;   // The first address of the account (i.e. the primary address).
        uint64_t balance;           // Balance of the account (locked or unlocked).
        uint64_t unlocked_balance;  // Unlocked balance for the account.
        std::string label;          // (Optional) Label of the account.
        std::string tag;            // (Optional) Tag for filtering accounts.
    };
};

// Create a new account with an optional label.
//
// Inputs:
//
// - \p label -- (Optional) Label for the account.
//
// Outputs:
//
// - \p account_index -- Index of the new account.
// - \p address -- The primary address of the new account.
struct CREATE_ACCOUNT : RPC_COMMAND {
    static constexpr auto names() { return NAMES("create_account"); }

    struct REQUEST {
        std::string label;  // (Optional) Label for the account.
    } request;
};

/// Label an account.
///
/// Inputs:
///
/// - \p account_index -- Account index to set the label for.
/// - \p label -- Label for the account.
///
/// Outputs: None
///
struct LABEL_ACCOUNT : RPC_COMMAND {
    static constexpr auto names() { return NAMES("label_account"); }

    struct REQUEST {
        uint32_t account_index;  // Account index to set the label for.
        std::string label;       // Label for the account.
    } request;
};

/// Get a list of user-defined account tags.
///
/// Inputs: None
///
///
/// Outputs:
///
/// - \p account_tags -- Account tag information:
///   - \p tag -- Filter tag.
///   - \p label -- Label for the tag.
///   - \p accounts -- List of tagged account indices.
struct GET_ACCOUNT_TAGS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_account_tags"); }

    struct REQUEST : EMPTY {
    } request;

    struct account_tag_info {
        std::string tag;                 // Filter tag.
        std::string label;               // Label for the tag.
        std::vector<uint32_t> accounts;  // List of tagged account indices.
    };
};

/// Apply a filtering tag to a list of accounts.
///
/// Inputs:
///
/// - \p tag -- Tag for the accounts.
/// - \p accounts -- Tag this list of accounts.
///
/// Outputs: None
///
struct TAG_ACCOUNTS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("tag_accounts"); }

    struct REQUEST {
        std::string tag;              // Tag for the accounts.
        std::set<uint32_t> accounts;  // Tag this list of accounts.
    } request;
};

/// Remove filtering tag from a list of accounts.
///
/// Inputs:
///
/// - \p accounts -- Remove tag from this list of accounts.
///
/// Outputs: None
///
struct UNTAG_ACCOUNTS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("untag_accounts"); }

    struct REQUEST {
        std::set<uint32_t> accounts;  // Remove tag from this list of accounts.
    } request;
};

/// Set description for an account tag.
///
/// Inputs:
///
/// - \p tag -- Set a description for this tag.
/// - \p description -- Description for the tag.
///
/// Outputs: None
///
struct SET_ACCOUNT_TAG_DESCRIPTION : RPC_COMMAND {
    static constexpr auto names() { return NAMES("set_account_tag_description"); }

    struct REQUEST {
        std::string tag;          // Set a description for this tag.
        std::string description;  // Description for the tag.
    } request;
};

/// Returns the wallet's current block height and blockchain immutable height
///
/// Inputs: None
///
///
/// Outputs:
///
/// - \p height -- The current wallet's blockchain height. If the wallet has been offline for a long
/// time, it may need to catch up with the daemon.
/// - \p immutable_height -- The latest height in the blockchain that can not be reorganized from
/// (backed by atleast 2 Service Node, or 1 hardcoded checkpoint, 0 if N/A).
struct GET_HEIGHT : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_height", "getheight"); }

    struct REQUEST : EMPTY {
    } request;
};

/// Send oxen to a number of recipients. To preview the transaction fee, set do_not_relay to true
/// and get_tx_metadata to true. Submit the response using the data in get_tx_metadata in the RPC
/// call, relay_tx.
///
/// Inputs:
///
/// - \p destinations -- Array of destinations to receive OXEN.
///   - \p address -- destination address
///   - \p amount -- destination amount, in atomic units
/// - \p account_index -- (Optional) Transfer from this account index. (Defaults to 0)
/// - \p subaddr_indices -- (Optional) Transfer from this set of subaddresses. (Defaults to 0)
/// - \p priority -- Set a priority for the transaction. Accepted values are: 1 for unimportant or 5
/// for blink. (0 and 2-4 are accepted for backwards compatibility and are equivalent to 5)
/// - \p unlock_time -- Number of blocks before the oxen can be spent (0 to use the default lock
/// time).
/// - \p payment_id -- (Optional) Random 64-character hex string to identify a transaction.
/// - \p get_tx_key -- (Optional) Return the transaction key after sending.
/// - \p do_not_relay -- (Optional) If true, the newly created transaction will not be relayed to
/// the oxen network. (Defaults to false)
/// - \p get_tx_hex -- Return the transaction as hex string after sending. (Defaults to false)
/// - \p get_tx_metadata -- Return the metadata needed to relay the transaction. (Defaults to false)
///
/// Outputs:
///
/// - \p tx_hash -- Publicly searchable transaction hash.
/// - \p tx_key -- Transaction key if get_tx_key is true, otherwise, blank string.
/// - \p amount -- Amount transferred for the transaction.
/// - \p fee -- Fee charged for the txn.
/// - \p tx_blob -- Raw transaction represented as hex string, if get_tx_hex is true.
/// - \p tx_metadata -- Set of transaction metadata needed to relay this transfer later, if
/// get_tx_metadata is true.
/// - \p multisig_txset -- Set of multisig transactions in the process of being signed (empty for
/// non-multisig).
/// - \p unsigned_txset -- Set of unsigned tx for cold-signing purposes.
struct TRANSFER : RESTRICTED {
    static constexpr auto names() { return NAMES("transfer"); }

    using destination = std::pair<std::string, uint64_t>;  // address, amount

    struct REQUEST {
        std::vector<destination> destinations;  // Array of destinations to receive OXEN.
        uint32_t account_index;  // (Optional) Transfer from this account index. (Defaults to 0)
        std::vector<uint32_t> subaddr_indices;  // (Optional) Transfer from this set of
                                                // subaddresses. (Defaults to 0)
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
    } request;
};

/// Same as transfer, but can split into more than one tx if necessary.
///
/// Inputs:
///
/// - \p destinations -- Array of destinations to receive OXEN:
///   - \p TODO: fields here
/// - \p account_index -- (Optional) Transfer from this account index. (Defaults to 0)
/// - \p subaddr_indices -- (Optional) Transfer from this set of subaddresses. (Defaults to 0)
/// - \p priority -- Set a priority for the transaction. Accepted values are: 1 for unimportant or 5
/// for blink. (0 and 2-4 are accepted for backwards compatibility and are equivalent to 5)
/// - \p unlock_time -- Number of blocks before the oxen can be spent (0 to not add a lock).
/// - \p payment_id -- (Optional) Random 32-byte/64-character hex string to identify a transaction.
/// - \p get_tx_keys -- (Optional) Return the transaction keys after sending.
/// - \p do_not_relay -- (Optional) If true, the newly created transaction will not be relayed to
/// the oxen network. (Defaults to false)
/// - \p get_tx_hex -- Return the transactions as hex string after sending.
/// - \p get_tx_metadata -- Return list of transaction metadata needed to relay the transfer later.
///
/// Outputs:
///
/// - \p tx_hash_list -- The tx hashes of every transaction.
/// - \p tx_key_list -- The transaction keys for every transaction.
/// - \p amount_list -- The amount transferred for every transaction.
/// - \p fee_list -- The amount of fees paid for every transaction.
/// - \p tx_blob_list -- The tx as hex string for every transaction.
/// - \p tx_metadata_list -- List of transaction metadata needed to relay the transactions later.
/// - \p multisig_txset -- The set of signing keys used in a multisig transaction (empty for
/// non-multisig).
/// - \p unsigned_txset -- Set of unsigned tx for cold-signing purposes.
struct TRANSFER_SPLIT : RESTRICTED {
    static constexpr auto names() { return NAMES("transfer_split"); }

    struct REQUEST {
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
    } request;
};

// TODO: Confirm these parameters and descriptions even make sense...
/// Get the details of an unsigned transaction blob
///
/// Inputs:
///
/// - \p unsigned_txset -- Set of unsigned tx returned by "transfer" or "transfer_split" methods.
/// - \p multisig_txset -- Set of unsigned multisig txes returned by "transfer" or "transfer_split"
/// methods
///
/// Outputs:
///
/// - \p desc -- List of information of transfers.
///   - \p amount_in -- Amount in, in atomic units.
///   - \p amount_out -- amount out, in atomic units.
///   - \p ring_size -- Ring size of transfer.
///   - \p unlock_time -- Number of blocks before the oxen can be spent (0 represents the default
///   network lock time).
///   - \p recipients -- List of addresses and amounts.
///     - \p address -- Destination public address.
///     - \p amount -- Amount in atomic units.
///   - \p payment_id -- Payment ID matching the input parameter.
///   - \p change_amount -- Change received from transaction in atomic units.
///   - \p change_address -- Address the change was sent to.
///   - \p fee -- Fee of the transaction in atomic units.
///   - \p dummy_outputs -- how many of the created outputs are "dummies"
///   - \p extra -- Data stored in the tx extra represented in hex.
struct DESCRIBE_TRANSFER : RESTRICTED {
    static constexpr auto names() { return NAMES("describe_transfer"); }

    struct recipient {
        std::string address;  // Destination public address.
        uint64_t amount;      // Amount in atomic units.
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
    };

    struct REQUEST {
        std::string unsigned_txset;  // Set of unsigned tx returned by "transfer" or
                                     // "transfer_split" methods.
        std::string multisig_txset;  // Set of unsigned multisig txes returned by "transfer" or
                                     // "transfer_split" methods
    } request;
};

/// Sign a transaction created on a read-only wallet (in cold-signing process).
///
/// Inputs:
///
/// - \p unsigned_txset -- Set of unsigned tx returned by "transfer" or "transfer_split" methods.
/// - \p export_raw -- (Optional) If true, return the raw transaction data. (Defaults to false)
/// - \p get_tx_keys -- (Optional) Return the transaction keys after sending.
///
/// Outputs:
///
/// - \p signed_txset -- Set of signed tx to be used for submitting transfer.
/// - \p tx_hash_list -- The tx hashes of every transaction.
/// - \p tx_raw_list -- The tx raw data of every transaction.
/// - \p tx_key_list -- The tx key data of every transaction.
struct SIGN_TRANSFER : RESTRICTED {
    static constexpr auto names() { return NAMES("sign_transfer"); }

    struct REQUEST {
        std::string unsigned_txset;  // Set of unsigned tx returned by "transfer" or
                                     // "transfer_split" methods.
        bool export_raw;   // (Optional) If true, return the raw transaction data. (Defaults to
                           // false)
        bool get_tx_keys;  // (Optional) Return the transaction keys after sending.
    } request;
};

/// Submit a previously signed transaction on a read-only wallet (in cold-signing process).
///
/// Inputs:
///
/// - \p tx_data_hex -- Set of signed tx returned by "sign_transfer".
///
/// Outputs:
///
/// - \p tx_hash_list -- The tx hashes of every transaction.
struct SUBMIT_TRANSFER : RESTRICTED {
    static constexpr auto names() { return NAMES("submit_transfer"); }

    struct REQUEST {
        std::string tx_data_hex;  // Set of signed tx returned by "sign_transfer".
    } request;
};

/// Send all dust outputs back to the wallet's, to make them easier to spend (and mix).
///
/// Inputs:
///
/// - \p get_tx_keys -- (Optional) Return the transaction keys after sending.
/// - \p do_not_relay -- (Optional) If true, the newly created transaction will not be relayed to
/// the oxen network. (Defaults to false)
/// - \p get_tx_hex -- (Optional) Return the transactions as hex string after sending. (Defaults to
/// false)
/// - \p get_tx_metadata -- (Optional) Return list of transaction metadata needed to relay the
/// transfer later. (Defaults to false)
///
/// Outputs:
///
/// - \p tx_hash_list -- The tx hashes of every transaction.
/// - \p tx_key_list -- The transaction keys for every transaction.
/// - \p amount_list -- The amount transferred for every transaction.
/// - \p fee_list -- The amount of fees paid for every transaction.
/// - \p tx_blob_list -- The tx as hex string for every transaction.
/// - \p tx_metadata_list -- List of transaction metadata needed to relay the transactions later.
/// - \p multisig_txset -- The set of signing keys used in a multisig transaction (empty for
/// non-multisig).
/// - \p unsigned_txset -- Set of unsigned tx for cold-signing purposes.
struct SWEEP_DUST : RESTRICTED {
    static constexpr auto names() { return NAMES("sweep_dust", "sweep_unmixable"); }

    struct REQUEST {
        bool get_tx_keys;   // (Optional) Return the transaction keys after sending.
        bool do_not_relay;  // (Optional) If true, the newly created transaction will not be relayed
                            // to the oxen network. (Defaults to false)
        bool get_tx_hex;    // (Optional) Return the transactions as hex string after sending.
                            // (Defaults to false)
        bool get_tx_metadata;  // (Optional) Return list of transaction metadata needed to relay the
                               // transfer later. (Defaults to false)
    } request;

    struct key_list {
        std::list<std::string> keys;
    };
};

/// Send all unlocked balance to an address.
///
/// Inputs:
///
/// - \p address -- Destination public address.
/// - \p account_index -- Sweep transactions from this account.
/// - \p subaddr_indices -- (Optional) Sweep from this set of subaddresses in the account.
/// - \p subaddr_indices_all -- Set if wanting to sweep from all subaddresses
/// - \p priority -- Set a priority for the transaction. Accepted values are: 1 for unimportant or 5
/// for blink. (0 and 2-4 are accepted for backwards compatibility and are equivalent to 5)
/// - \p outputs -- ???
/// - \p unlock_time -- Number of blocks before the oxen can be spent (0 to not add a lock).
/// - \p payment_id -- (Optional) 64-character hex string to identify a transaction.
/// - \p get_tx_keys -- (Optional) Return the transaction keys after sending.
/// - \p below_amount -- (Optional) Include outputs below this amount.
/// - \p do_not_relay -- (Optional) If true, do not relay this sweep transfer. (Defaults to false)
/// - \p get_tx_hex -- (Optional) return the transactions as hex encoded string. (Defaults to false)
/// - \p get_tx_metadata -- (Optional) return the transaction metadata as a string. (Defaults to
/// false)
///
/// Outputs:
///
/// - \p tx_hash_list -- The tx hashes of every transaction.
/// - \p tx_key_list -- The transaction keys for every transaction.
/// - \p amount_list -- The amount transferred for every transaction.
/// - \p fee_list -- The amount of fees paid for every transaction.
/// - \p tx_blob_list -- The tx as hex string for every transaction.
/// - \p tx_metadata_list -- List of transaction metadata needed to relay the transactions later.
/// - \p multisig_txset -- The set of signing keys used in a multisig transaction (empty for
/// non-multisig).
/// - \p unsigned_txset -- Set of unsigned tx for cold-signing purposes.
struct SWEEP_ALL : RESTRICTED {
    static constexpr auto names() { return NAMES("sweep_all"); }

    struct REQUEST {
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
    } request;

    struct key_list {
        std::list<std::string> keys;
    };
};

/// Send all of a specific unlocked output to an address.
///
/// Inputs:
///
/// - \p address -- Destination public address.
/// - \p priority -- Set a priority for the transaction. Accepted values are: 1 for unimportant or 5
/// for blink. (0 and 2-4 are accepted for backwards compatibility and are equivalent to 5)
/// - \p outputs -- ???
/// - \p unlock_time -- Number of blocks before the oxen can be spent (0 to not add a lock).
/// - \p payment_id -- (Optional) 64-character hex string to identify a transaction.
/// - \p get_tx_key -- (Optional) Return the transaction keys after sending.
/// - \p key_image -- Key image of specific output to sweep.
/// - \p do_not_relay -- (Optional) If true, do not relay this sweep transfer. (Defaults to false)
/// - \p get_tx_hex -- (Optional) return the transactions as hex encoded string. (Defaults to false)
/// - \p get_tx_metadata -- (Optional) return the transaction metadata as a string. (Defaults to
/// false)
///
/// Outputs:
///
/// - \p tx_hash -- The tx hashes of the transaction.
/// - \p tx_key -- The tx key of the transaction.
/// - \p amount -- The amount transfered in atomic units.
/// - \p fee -- The fee paid in atomic units.
/// - \p tx_blob -- The tx as hex string.
/// - \p tx_metadata -- Transaction metadata needed to relay the transaction later.
/// - \p multisig_txset -- The set of signing keys used in a multisig transaction (empty for
/// non-multisig).
/// - \p unsigned_txset -- Set of unsigned tx for cold-signing purposes.
struct SWEEP_SINGLE : RESTRICTED {
    static constexpr auto names() { return NAMES("sweep_single"); }

    struct REQUEST {
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
    } request;
};

/// Relay transaction metadata to the daemon
///
/// Inputs:
///
/// - \p hex -- Transaction metadata returned from a transfer method with get_tx_metadata set to
/// true.
/// - \p blink -- (Optional): Set to true if this tx was constructed with a blink priority and
/// should be submitted to the blink quorum.
///
/// Outputs:
///
/// - \p tx_hash -- String for the publically searchable transaction hash.
struct RELAY_TX : RPC_COMMAND {
    static constexpr auto names() { return NAMES("relay_tx"); }

    struct REQUEST {
        std::string hex;  // Transaction metadata returned from a transfer method with
                          // get_tx_metadata set to true.
        bool blink;  // (Optional): Set to true if this tx was constructed with a blink priority and
                     // should be submitted to the blink quorum.
    } request;
};

/// Tell the wallet to store its data to disk, if needed.
///
/// Inputs: None
///
///
/// Outputs: None
///
struct STORE : RESTRICTED {
    static constexpr auto names() { return NAMES("store"); }

    struct REQUEST : EMPTY {
    } request;
};

/// Payment details struct
///
/// - \p payment_id -- Payment ID matching the input parameter.
/// - \p tx_hash -- Transaction hash used as the transaction ID.
/// - \p amount -- Amount for this payment.
/// - \p block_height -- Height of the block that first confirmed this payment.
/// - \p unlock_time -- Time (in block height) until this payment is safe to spend.
/// - \p locked -- If the payment is spendable or not
/// - \p subaddr_index -- Major & minor index, account and subaddress index respectively.
/// - \p address -- Address receiving the payment.
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
};

/// Get a list of incoming payments using a given payment id.
///
/// Inputs:
///
/// - \p payment_id -- Payment ID used to find the payments (16 characters hex).
///
/// Outputs:
///
/// - \p payments -- List of payment details:
///   - \ref payment_details
struct GET_PAYMENTS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_payments"); }

    struct REQUEST {
        std::string payment_id;  // Payment ID used to find the payments (16 characters hex).
    } request;
};

/// Get a list of incoming payments using a given payment id,
/// or a list of payments ids, from a given height.
///
/// This method is the preferred method over  get_payments because it
/// has the same functionality but is more extendable.
/// Either is fine for looking up transactions by a single payment ID.
///
/// Inputs:
///
/// - \p payment_ids -- Payment IDs used to find the payments (16 characters hex).
/// - \p min_block_height -- The block height at which to start looking for payments.
///
/// Outputs:
///
/// - \p payments -- List of payment details:
///   - \ref payment_details
struct GET_BULK_PAYMENTS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_bulk_payments"); }

    struct REQUEST {
        std::vector<std::string>
                payment_ids;        // Payment IDs used to find the payments (16 characters hex).
        uint64_t min_block_height;  // The block height at which to start looking for payments.
    } request;
};

/// Transfer details struct
///
/// - \p amount -- Amount of this transfer.
/// - \p spent -- Indicates if this transfer has been spent.
/// - \p global_index -- The index into the global list of transactions grouped by amount in the
/// Loki network.
/// - \p tx_hash -- Several incoming transfers may share the same hash if they were in the same
/// transaction.
/// - \p subaddr_index -- Major & minor index, account and subaddress index respectively.
/// - \p key_image -- Key image for the incoming transfer's unspent output (empty unless verbose is
/// true).
/// - \p block_height -- Block height the transfer occurred on
/// - \p frozen -- If the output has been intentionally frozen by the user, i.e. unspendable.
/// - \p unlocked -- If the TX is spendable yet
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
};

/// Return a list of incoming transfers to the wallet.
///
/// Inputs:
///
/// - \p transfer_type -- "all": all the transfers, "available": only transfers which are not yet
/// spent, OR "unavailable": only transfers which are already spent.
/// - \p account_index -- (Optional) Return transfers for this account. (defaults to 0)
/// - \p subaddr_indices -- (Optional) Return transfers sent to these subaddresses.
///
/// Outputs:
///
/// - \p transfers -- List of information of the transfers details.
///   - \ref transfer_details
struct INCOMING_TRANSFERS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("incoming_transfers"); }

    struct REQUEST {
        std::string transfer_type;  // "all": all the transfers, "available": only transfers which
                                    // are not yet spent, OR "unavailable": only transfers which are
                                    // already spent.
        uint32_t account_index;     // (Optional) Return transfers for this account. (defaults to 0)
        std::set<uint32_t>
                subaddr_indices;  // (Optional) Return transfers sent to these subaddresses.
    } request;
};

/// Return the private view key.
///
/// Inputs: None
///
/// Outputs:
///
/// - \p key --  The key will be a hex encoded string.
///
struct EXPORT_VIEW_KEY : RESTRICTED {
    static constexpr auto names() { return NAMES("export_view_key"); }

    struct REQUEST : EMPTY {
    } request;
};

/// Return the private spend key.
///
/// Inputs: None
///
/// Outputs:
///
/// - \p key --  The key will be a hex encoded string.
///
struct EXPORT_SPEND_KEY : RESTRICTED {
    static constexpr auto names() { return NAMES("export_spend_key"); }

    struct REQUEST : EMPTY {
    } request;
};

/// Return the mnemonic.
///
/// Inputs:
///
/// - \p language -- Which language should be used for the wordlist. Defaults to english
///
/// Outputs:
///
/// - \p mnemonic --  The mnemonic will be a string of words.
struct EXPORT_MNEMONIC_KEY : RESTRICTED {
    static constexpr auto names() { return NAMES("export_mnemonic_key"); }

    struct REQUEST {
        std::string language;  // Which key to retrieve: "mnemonic" - the mnemonic seed (older
                               // wallets do not have one) OR "view_key" - the view key
    } request;
};

/// Make an integrated address from the wallet address and a payment id.
///
/// Inputs:
///
/// - \p standard_address -- (Optional, defaults to primary address) Destination public address.
/// - \p payment_id -- (Optional, defaults to a random ID) 16 characters hex encoded.
///
/// Outputs:
///
/// - \p integrated_address -- the resulting integrated address
/// - \p payment_id -- Hex encoded.
struct MAKE_INTEGRATED_ADDRESS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("make_integrated_address"); }

    struct REQUEST {
        std::string standard_address;  // (Optional, defaults to primary address) Destination public
                                       // address.
        std::string payment_id;  // (Optional, defaults to a random ID) 16 characters hex encoded.
    } request;
};

/// Retrieve the standard address and payment id corresponding to an integrated address.
///
/// Inputs:
///
/// - \p integrated_address -- the resulting integrated address
///
/// Outputs:
///
/// - \p standard_address -- the resulting address
/// - \p payment_id -- the payment id
/// - \p is_subaddress -- whether the address is a subaddress
struct SPLIT_INTEGRATED_ADDRESS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("split_integrated_address"); }

    struct REQUEST {
        std::string integrated_address;  //
    } request;
};

// Stops the wallet, storing the current state.
//
// Inputs: None
//
//
// Outputs: None
//
struct STOP_WALLET : RESTRICTED {
    static constexpr auto names() { return NAMES("stop_wallet"); }

    struct REQUEST : EMPTY {
    } request;
};

/// Rescan the blockchain from scratch, losing any information
/// which can not be recovered from the blockchain itself.
/// This includes destination addresses, tx secret keys, tx notes, etc.
///
/// Warning: This blocks the Wallet RPC executable until rescanning is complete.
///
/// Inputs:
///
/// - \p hard -- ???
///
/// Outputs: None
struct RESCAN_BLOCKCHAIN : RESTRICTED {
    static constexpr auto names() { return NAMES("rescan_blockchain"); }

    struct REQUEST {
        bool hard;  //
    } request;
};

/// Set arbitrary string notes for transactions.
///
/// Inputs:
///
/// - \p txids -- Transaction ids.
/// - \p notes -- Notes for the transactions.
///
/// Outputs: None
struct SET_TX_NOTES : RESTRICTED {
    static constexpr auto names() { return NAMES("set_tx_notes"); }

    struct REQUEST {
        std::list<std::string> txids;  // Transaction ids.
        std::list<std::string> notes;  // Notes for the transactions.
    } request;
};

/// Get string notes for transactions.
///
/// Inputs:
///
/// - \p txids -- Transaction ids.
///
/// Outputs:
///
/// - \p notes -- Notes for the transactions.
struct GET_TX_NOTES : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_tx_notes"); }

    struct REQUEST {
        std::list<std::string> txids;  // Transaction ids.
    } request;
};

/// Set arbitrary attribute.
///
/// Inputs:
///
/// - \p key -- Attribute name.
/// - \p value -- Attribute value.
///
/// Outputs: None
struct SET_ATTRIBUTE : RESTRICTED {
    static constexpr auto names() { return NAMES("set_attribute"); }

    struct REQUEST {
        std::string key;    // Attribute name.
        std::string value;  // Attribute value.
    } request;
};

/// Get attribute value by name.
///
/// Inputs:
///
/// - \p key -- Attribute name.
///
/// Outputs:
///
/// - \p value -- Attribute value.
struct GET_ATTRIBUTE : RESTRICTED {
    static constexpr auto names() { return NAMES("get_attribute"); }

    struct REQUEST {

        std::string key;  // Attribute name.
    } request;
};

/// Get transaction secret key from transaction id.
///
/// Inputs:
///
/// - \p txid -- Transaction id.
///
/// Outputs:
///
/// - \p tx_key -- Transaction secret key.
struct GET_TX_KEY : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_tx_key"); }

    struct REQUEST {
        std::string txid;  // Transaction id.
    } request;
};

/// Check a transaction in the blockchain with its secret key.
///
/// Inputs:
///
/// - \p txid -- Transaction id.
/// - \p tx_key -- Transaction secret key.
/// - \p address -- Destination public address of the transaction.
///
/// Outputs:
///
/// - \p received -- Amount of the transaction.
/// - \p in_pool -- States if the transaction is still in pool or has been added to a block.
/// - \p confirmations -- Number of blocks mined after the one with the transaction.
struct CHECK_TX_KEY : RPC_COMMAND {
    static constexpr auto names() { return NAMES("check_tx_key"); }

    struct REQUEST {
        std::string txid;     // Transaction id.
        std::string tx_key;   // Transaction secret key.
        std::string address;  // Destination public address of the transaction.
    } request;
};

/// Get transaction signature to prove it.
///
/// Inputs:
///
/// - \p txid -- Transaction id.
/// - \p address -- Destination public address of the transaction.
/// - \p message -- (Optional) add a message to the signature to further authenticate the prooving
/// process.
///
/// Outputs:
///
/// - \p signature -- Transaction signature.
struct GET_TX_PROOF : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_tx_proof"); }

    struct REQUEST {
        std::string txid;     // Transaction id.
        std::string address;  // Destination public address of the transaction.
        std::string message;  // (Optional) add a message to the signature to further authenticate
                              // the prooving process.
    } request;
};

/// Prove a transaction by checking its signature.
///
/// Inputs:
///
/// - \p txid -- Transaction id.
/// - \p address -- Destination public address of the transaction.
/// - \p message -- (Optional) Should be the same message used in `get_tx_proof`.
/// - \p signature -- Transaction signature to confirm.
///
/// Outputs:
///
/// - \p good -- States if the inputs proves the transaction.
/// - \p received -- Amount of the transaction.
/// - \p in_pool -- States if the transaction is still in pool or has been added to a block.
/// - \p confirmations -- Number of blocks mined after the one with the transaction.
struct CHECK_TX_PROOF : RPC_COMMAND {
    static constexpr auto names() { return NAMES("check_tx_proof"); }

    struct REQUEST {
        std::string txid;       // Transaction id.
        std::string address;    // Destination public address of the transaction.
        std::string message;    // (Optional) Should be the same message used in `get_tx_proof`.
        std::string signature;  // Transaction signature to confirm.
    } request;
};

/// Generate a signature to prove a spend. Unlike proving a transaction, it does not requires the
/// destination public address.
///
/// Inputs:
///
/// - \p txid -- Transaction id.
/// - \p message -- (Optional) add a message to the signature to further authenticate the prooving
/// process.
///
/// Outputs:
///
/// - \p signature -- Spend signature.
struct GET_SPEND_PROOF : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_spend_proof"); }

    struct REQUEST {
        std::string txid;     // Transaction id.
        std::string message;  // (Optional) add a message to the signature to further authenticate
                              // the prooving process.
    } request;
};

/// Prove a spend using a signature. Unlike proving a transaction, it does not requires the
/// destination public address.
///
/// Inputs:
///
/// - \p txid -- Transaction id.
/// - \p message -- (Optional) Should be the same message used in `get_spend_proof`.
/// - \p signature -- Spend signature to confirm.
///
/// Outputs:
///
/// - \p good -- States if the inputs proves the spend.
struct CHECK_SPEND_PROOF : RPC_COMMAND {
    static constexpr auto names() { return NAMES("check_spend_proof"); }

    struct REQUEST {
        std::string txid;       // Transaction id.
        std::string message;    // (Optional) Should be the same message used in `get_spend_proof`.
        std::string signature;  // Spend signature to confirm.
    } request;
};

/// Generate a signature to prove of an available amount in a wallet.
///
/// Inputs:
///
/// - \p all -- Proves all wallet balance to be disposable.
/// - \p account_index -- Specify the account from witch to prove reserve. (ignored if all is set to
/// true)
/// - \p amount -- Amount (in atomic units) to prove the account has for reserve. (ignored if all is
/// set to true)
/// - \p message -- (Optional) add a message to the signature to further authenticate the prooving
/// process.
///
/// Outputs:
///
/// - \p signature -- Reserve signature.
struct GET_RESERVE_PROOF : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_reserve_proof"); }

    struct REQUEST {
        bool all;                // Proves all wallet balance to be disposable.
        uint32_t account_index;  // Specify the account from witch to prove reserve. (ignored if all
                                 // is set to true)
        uint64_t amount;  // Amount (in atomic units) to prove the account has for reserve. (ignored
                          // if all is set to true)
        std::string message;  // (Optional) add a message to the signature to further authenticate
                              // the prooving process.
    } request;
};

/// Proves a wallet has a disposable reserve using a signature.
///
/// Inputs:
///
/// - \p address -- Public address of the wallet.
/// - \p message -- (Optional) Should be the same message used in get_reserve_proof.
/// - \p signature -- Reserve signature to confirm.
///
/// Outputs:
///
/// - \p good -- States if the inputs proves the reserve.
/// - \p total -- ???
/// - \p spent -- ???
struct CHECK_RESERVE_PROOF : RPC_COMMAND {
    static constexpr auto names() { return NAMES("check_reserve_proof"); }

    struct REQUEST {
        std::string address;    // Public address of the wallet.
        std::string message;    // (Optional) Should be the same message used in get_reserve_proof.
        std::string signature;  // Reserve signature to confirm.
    } request;
};

/// Returns a list of transfers, by default all transfer types are included. If all requested type
/// fields are false, then all transfers will be queried.
///
/// Inputs:
///
/// - \p in -- (Optional) Include incoming transfers.
/// - \p out -- (Optional) Include outgoing transfers.
/// - \p stake -- (Optional) Include outgoing stakes.
/// - \p pending -- (Optional) Include pending transfers.
/// - \p failed -- (Optional) Include failed transfers.
/// - \p pool -- (Optional) Include transfers from the daemon's transaction pool.
/// - \p coinbase -- (Optional) Include transfers from the daemon's transaction pool.
/// - \p filter_by_height -- (Optional) Filter transfers by block height.
/// - \p min_height -- (Optional) Minimum block height to scan for transfers, if filtering by height
/// is enabled.
/// - \p max_height -- (Optional) Maximum block height to scan for transfers, if filtering by height
/// is enabled (defaults to max block height).
/// - \p account_index -- (Optional) Index of the account to query for transfers. (defaults to 0)
/// - \p subaddr_indices -- (Optional) List of subaddress indices to query for transfers. (defaults
/// to 0)
/// - \p all_accounts -- If true, return transfers for all accounts, subaddr_indices and
/// account_index are ignored
///
/// Outputs:
///
/// - \p in --
///   - \ref transfer_view
/// - \p out --
///   - \ref transfer_view
/// - \p pending --
///   - \ref transfer_view
/// - \p failed --
///   - \ref transfer_view
/// - \p pool --
///   - \ref transfer_view
struct GET_TRANSFERS : RESTRICTED {
    static constexpr auto names() { return NAMES("get_transfers"); }

    struct REQUEST {
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
    } request;
};

/// Returns a string with the transfers formatted as csv
///
/// Inputs:
///
/// - \p in -- (Optional) Include incoming transfers.
/// - \p out -- (Optional) Include outgoing transfers.
/// - \p stake -- (Optional) Include outgoing stakes.
/// - \p pending -- (Optional) Include pending transfers.
/// - \p failed -- (Optional) Include failed transfers.
/// - \p pool -- (Optional) Include transfers from the daemon's transaction pool.
/// - \p coinbase -- (Optional) Include transfers from the daemon's transaction pool.
/// - \p filter_by_height -- (Optional) Filter transfers by block height.
/// - \p min_height -- (Optional) Minimum block height to scan for transfers, if filtering by height
/// is enabled.
/// - \p max_height -- (Optional) Maximum block height to scan for transfers, if filtering by height
/// is enabled (defaults to max block height).
/// - \p account_index -- (Optional) Index of the account to query for transfers. (defaults to 0)
/// - \p subaddr_indices -- (Optional) List of subaddress indices to query for transfers. (defaults
/// to 0)
/// - \p all_accounts -- If true, return transfers for all accounts, subaddr_indices and
/// account_index are ignored
///
/// Outputs:
///
/// - \p csv -- Show information about a transfer to/from this address.
struct GET_TRANSFERS_CSV : RESTRICTED {
    static constexpr auto names() { return NAMES("get_transfers_csv"); }

    struct REQUEST : GET_TRANSFERS::REQUEST {
    } request;
};

/// Show information about a transfer to/from this address.
///
/// Inputs:
///
/// - \p txid -- Transaction ID used to find the transfer.
/// - \p account_index -- (Optional) Index of the account to query for the transfer.
///
/// Outputs:
///
/// - \p transfer -- the transfer, if found
///   - \ref transfer_view
/// - \p transfers -- ???
///   - \ref transfer_view
struct GET_TRANSFER_BY_TXID : RESTRICTED {
    static constexpr auto names() { return NAMES("get_transfer_by_txid"); }

    struct REQUEST {
        std::string txid;        // Transaction ID used to find the transfer.
        uint32_t account_index;  // (Optional) Index of the account to query for the transfer.
    } request;
};

/// Sign a string.
///
/// Inputs:
///
/// - \p data -- Anything you need to sign.
/// - \p account_index -- The account to use for signing
/// - \p address_index -- The subaddress in the account to sign with
///
/// Outputs:
///
/// - \p signature -- Signature generated against the "data" and the account public address.
struct SIGN : RESTRICTED {
    static constexpr auto names() { return NAMES("sign"); }

    struct REQUEST {
        std::string data;        // Anything you need to sign.
        uint32_t account_index;  // The account to use for signing
        uint32_t address_index;  // The subaddress in the account to sign with
    } request;
};

/// Verify a signature on a string.
///
/// Inputs:
///
/// - \p data -- What should have been signed.
/// - \p address -- Public address of the wallet used to sign the data.
/// - \p signature -- Signature generated by `sign` method.
///
/// Outputs:
///
/// - \p good -- whether the signature was valid
struct VERIFY : RESTRICTED {
    static constexpr auto names() { return NAMES("verify"); }

    struct REQUEST {
        std::string data;       // What should have been signed.
        std::string address;    // Public address of the wallet used to sign the data.
        std::string signature;  // Signature generated by `sign` method.
    } request;
};

/// Export all outputs in hex format.
///
/// Inputs:
///
/// - \p all -- Wallet outputs in hex format.
///
/// Outputs:
///
/// - \p outputs_data_hex -- Wallet outputs in hex format.
struct EXPORT_OUTPUTS : RESTRICTED {
    static constexpr auto names() { return NAMES("export_outputs"); }

    struct REQUEST {
        bool all;
    } request;
};

/// Export transfers to csv
///
/// Inputs:
///
/// - \p in -- ???
/// - \p out -- ???
/// - \p stake -- ???
/// - \p pending -- ???
/// - \p failed -- ???
/// - \p pool -- ???
/// - \p coinbase -- ???
/// - \p filter_by_height -- ???
/// - \p min_height -- ???
/// - \p max_height -- ???
/// - \p subaddr_indices -- ???
/// - \p account_index -- ???
/// - \p all_accounts -- ???
///
/// Outputs:
///
/// - \p data -- CSV data to be written to file by wallet
struct EXPORT_TRANSFERS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("export_transfers"); }

    struct REQUEST {
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
    } request;
};

/// Import outputs in hex format.
///
/// Inputs:
///
/// - \p outputs_data_hex -- Wallet outputs in hex format.
///
/// Outputs:
///
/// - \p num_imported -- Number of outputs imported.
struct IMPORT_OUTPUTS : RESTRICTED {
    static constexpr auto names() { return NAMES("import_outputs"); }

    struct REQUEST {
        std::string outputs_data_hex;  // Wallet outputs in hex format.
    } request;
};

/// Export a signed set of key images.
///
/// Inputs:
///
/// - \p requested_only -- Default `false`.
///
/// Outputs:
///
/// - \p offset -- ???
/// - \p signed_key_images -- the set of signed key images
///   - \p key_image -- key image
///   - \p signature -- signature
struct EXPORT_KEY_IMAGES : RPC_COMMAND {
    static constexpr auto names() { return NAMES("export_key_images"); }

    struct REQUEST {
        bool requested_only;  // Default `false`.
    } request;

    struct signed_key_image {
        std::string key_image;  //
        std::string signature;  //
    };
};

/// Import signed key images list and verify their spent status.
///
/// Inputs:
///
/// - \p offset -- ???
/// - \p signed_key_images -- the key images to import
///   - \p key_image -- Key image of specific output
///   - \p signature -- Transaction signature.
///
/// Outputs:
///
/// - \p height -- ???
/// - \p spent -- Amount (in atomic units) spent from those key images.
/// - \p unspent -- Amount (in atomic units) still available from those key images.
struct IMPORT_KEY_IMAGES : RESTRICTED {
    static constexpr auto names() { return NAMES("import_key_images"); }

    struct signed_key_image {
        std::string key_image;  // Key image of specific output
        std::string signature;  // Transaction signature.
    };

    struct REQUEST {
        uint32_t offset;
        std::vector<signed_key_image> signed_key_images;
    } request;
};

/// URI struct
///
/// - \p address -- Wallet address.
/// - \p payment_id -- (Optional) 16 or 64 character hexadecimal payment id.
/// - \p amount -- (Optional) the integer amount to receive, in atomic units.
/// - \p tx_description -- (Optional) Description of the reason for the tx.
/// - \p recipient_name -- (Optional) name of the payment recipient.
struct uri_spec {
    std::string address;         // Wallet address.
    std::string payment_id;      // (Optional) 16 or 64 character hexadecimal payment id.
    uint64_t amount;             // (Optional) the integer amount to receive, in atomic units.
    std::string tx_description;  // (Optional) Description of the reason for the tx.
    std::string recipient_name;  // (Optional) name of the payment recipient.
};

/// Create a payment URI using the official URI spec.
///
/// Inputs:
///
/// - \ref uri_spec
///
/// Outputs:
///
/// - \p uri -- This contains all the payment input information as a properly formatted payment URI.
struct MAKE_URI : RPC_COMMAND {
    static constexpr auto names() { return NAMES("make_uri"); }

    struct REQUEST : public uri_spec {
    } request;
};

/// Parse a payment URI to get payment information.
///
/// Inputs:
///
/// - \p uri -- This contains all the payment input information as a properly formatted payment URI.
///
/// Outputs:
///
/// - \p uri -- JSON object containing payment information:
///   - \ref uri_spec
/// - \p unknown_parameters -- ???
struct PARSE_URI : RPC_COMMAND {
    static constexpr auto names() { return NAMES("parse_uri"); }

    struct REQUEST {
        std::string uri;  // This contains all the payment input information as a properly formatted
                          // payment URI.
    } request;
};

/// Add an entry to the address book.
///
/// Inputs:
///
/// - \p address -- Public address of the entry.
/// - \p description -- (Optional), defaults to "".
///
/// Outputs:
///
/// - \p index -- The index of the address book entry.
struct ADD_ADDRESS_BOOK_ENTRY : RESTRICTED {
    static constexpr auto names() { return NAMES("add_address_book"); }

    struct REQUEST {
        std::string address;      // Public address of the entry.
        std::string description;  // (Optional), defaults to "".
    } request;
};

/// Edit a entry in the address book.
///
/// Inputs:
///
/// - \p index -- Retrieves entries from the address book.
/// - \p set_address -- Retrieves entries from the address book.
/// - \p address -- Retrieves entries from the address book.
/// - \p set_description -- Retrieves entries from the address book.
/// - \p description -- Retrieves entries from the address book.
///
/// Outputs: None
struct EDIT_ADDRESS_BOOK_ENTRY : RESTRICTED {
    static constexpr auto names() { return NAMES("edit_address_book"); }

    struct REQUEST {
        uint64_t index;
        bool set_address;
        std::string address;
        bool set_description;
        std::string description;
    } request;
};

/// Retrieves entries from the address book.
///
/// Inputs:
///
/// - \p entries -- Indices of the requested address book entries.
///
/// Outputs:
///
/// - \p entries -- List of address book entries information.
///   - \p index -- Index of entry.
///   - \p address -- Public address of the entry
///   - \p description -- Description of this address entry.
struct GET_ADDRESS_BOOK_ENTRY : RESTRICTED {
    static constexpr auto names() { return NAMES("get_address_book"); }

    struct REQUEST {
        std::list<uint64_t> entries;  // Indices of the requested address book entries.
    } request;

    struct entry {
        uint64_t index;           // Index of entry.
        std::string address;      // Public address of the entry
        std::string description;  // Description of this address entry.
    };
};

/// Delete an entry from the address book.
///
/// Inputs:
///
/// - \p index -- The index of the address book entry.
///
/// Outputs: None
struct DELETE_ADDRESS_BOOK_ENTRY : RESTRICTED {
    static constexpr auto names() { return NAMES("delete_address_book"); }

    struct REQUEST {
        uint64_t index;  // The index of the address book entry.
    } request;
};

/// Rescan the blockchain for spent outputs.
///
/// Inputs: None
///
/// Outputs: None
struct RESCAN_SPENT : RESTRICTED {
    static constexpr auto names() { return NAMES("rescan_spent"); }

    struct REQUEST : EMPTY {
    } request;
};

/// Refresh a wallet after opening.
///
/// Inputs:
///
/// - \p start_height -- (Optional) The block height from which to start refreshing.
///
/// Outputs:
///
/// - \p blocks_fetched -- Number of new blocks scanned.
/// - \p received_money -- States if transactions to the wallet have been found in the blocks.
struct REFRESH : RESTRICTED {
    static constexpr auto names() { return NAMES("refresh"); }

    struct REQUEST {
        uint64_t start_height;  // (Optional) The block height from which to start refreshing.
    } request;
};

/// Set wallet to (not) auto-refresh on an interval
///
/// Inputs:
///
/// - \p enable -- enable or disable auto-refresh
/// - \p period -- interval in seconds
///
/// Outputs: None
struct AUTO_REFRESH : RESTRICTED {
    static constexpr auto names() { return NAMES("auto_refresh"); }

    struct REQUEST {
        bool enable;
        uint32_t period;  // seconds
    } request;
};

/// Start mining in the oxen daemon.
///
/// Inputs:
///
/// - \p threads_count -- Number of threads created for mining.
///
/// Outputs: None
struct START_MINING : RPC_COMMAND {
    static constexpr auto names() { return NAMES("start_mining"); }

    struct REQUEST {
        uint64_t threads_count;  // Number of threads created for mining.
    } request;
};

/// Stop mining in the oxen daemon.
///
/// Inputs: None
///
/// Outputs: None
struct STOP_MINING : RPC_COMMAND {
    static constexpr auto names() { return NAMES("stop_mining"); }

    struct REQUEST : EMPTY {
    } request;
};

/// Get a list of available languages for your wallet's seed.
///
/// Inputs: None
///
/// Outputs:
///
/// - \p languages -- List of available languages.
/// - \p languages_local -- List of available languages in the native language
struct GET_LANGUAGES : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_languages"); }

    struct REQUEST : EMPTY {
    } request;
};

/// Create a new wallet. You need to have set the argument "'--wallet-dir" when launching
/// oxen-wallet-rpc to make this work.
///
/// Inputs:
///
/// - \p filename -- Set the wallet file name.
/// - \p password -- (Optional) Set the password to protect the wallet.
/// - \p language -- Language for your wallets' seed.
/// - \p hardware_wallet -- Create this wallet from a connected hardware wallet.  (`language` will
/// be ignored).
/// - \p device_name -- When `hardware` is true, this specifies the hardware wallet device type
/// (currently supported: "Ledger").  If omitted "Ledger" is used.
/// - \p device_label -- (Optional) Custom label to write to a `wallet.hwdev.txt`. Can be empty;
/// omit the parameter entirely to not write a .hwdev.txt file at all.
///
/// Outputs: None
struct CREATE_WALLET : RPC_COMMAND {
    static constexpr auto names() { return NAMES("create_wallet"); }

    struct REQUEST {
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
    } request;
};

/// Open a wallet. You need to have set the argument "--wallet-dir" when launching oxen-wallet-rpc
/// to make this work. The wallet rpc executable may only open wallet files within the same
/// directory as wallet-dir, otherwise use the
/// "--wallet-file" flag to open specific wallets.
///
/// Inputs:
///
/// - \p filename -- Wallet name stored in "--wallet-dir".
/// - \p password -- The wallet password, set as "" if there's no password
/// - \p autosave_current -- (Optional: Default true): If a pre-existing wallet is open, save to
/// disk before opening the new wallet.
///
/// Outputs: None
struct OPEN_WALLET : RPC_COMMAND {
    static constexpr auto names() { return NAMES("open_wallet"); }

    struct REQUEST {
        std::string filename;   // Wallet name stored in "--wallet-dir".
        std::string password;   // The wallet password, set as "" if there's no password
        bool autosave_current;  // (Optional: Default true): If a pre-existing wallet is open, save
                                // to disk before opening the new wallet.
    } request;
};

/// Close the currently opened wallet, after trying to save it.
///
/// Inputs:
///
/// - \p autosave_current -- Save the wallet state on close
///
/// Outputs: None
struct CLOSE_WALLET : RPC_COMMAND {
    static constexpr auto names() { return NAMES("close_wallet"); }

    struct REQUEST {
        bool autosave_current;  // Save the wallet state on close
    } request;
};

/// Change a wallet password.
///
/// Inputs:
///
/// - \p old_password -- (Optional) Current wallet password, if defined.
/// - \p new_password -- (Optional) New wallet password, if not blank.
///
/// Outputs: None
struct CHANGE_WALLET_PASSWORD : RESTRICTED {
    static constexpr auto names() { return NAMES("change_wallet_password"); }

    struct REQUEST {
        std::string old_password;  // (Optional) Current wallet password, if defined.
        std::string new_password;  // (Optional) New wallet password, if not blank.
    } request;
};

/// Restore a wallet using the private spend key, view key and public address.
///
/// Inputs:
///
/// - \p restore_height -- (Optional: Default 0) Height in which to start scanning the blockchain
/// for transactions into and out of this Wallet.
/// - \p filename -- Set the name of the wallet.
/// - \p address -- The public address of the wallet.
/// - \p spendkey -- The private spend key of the wallet
/// - \p viewkey -- The private view key of the wallet.
/// - \p password -- Set password for Wallet.
/// - \p autosave_current -- (Optional: Default true): If a pre-existing wallet is open, save to
/// disk before opening the new wallet.
///
/// Outputs:
///
/// - \p address -- Restore a wallet using the seed words.
/// - \p info -- Restore a wallet using the seed words.
struct GENERATE_FROM_KEYS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("generate_from_keys"); }

    struct REQUEST {
        uint64_t restore_height;  // (Optional: Default 0) Height in which to start scanning the
                                  // blockchain for transactions into and out of this Wallet.
        std::string filename;     // Set the name of the wallet.
        std::string address;      // The public address of the wallet.
        std::string spendkey;     // The private spend key of the wallet
        std::string viewkey;      // The private view key of the wallet.
        std::string password;     // Set password for Wallet.
        bool autosave_current;  // (Optional: Default true): If a pre-existing wallet is open, save
                                // to disk before opening the new wallet.
    } request;
};

/// Restore a wallet using the seed words.
///
/// Inputs:
///
/// - \p restore_height -- Height in which to start scanning the blockchain for transactions into
/// and out of this Wallet.
/// - \p filename -- Set the name of the Wallet.
/// - \p seed -- Mnemonic seed of wallet (25 words).
/// - \p seed_offset -- ???
/// - \p password -- Set password for Wallet.
/// - \p language -- Set language for the wallet.
/// - \p autosave_current -- (Optional: Default true): If a pre-existing wallet is open, save to
/// disk before opening the new wallet.
///
/// Outputs:
///
/// - \p address -- Public address of wallet.
/// - \p seed -- Seed of wallet.
/// - \p info -- Wallet information.
/// - \p was_deprecated -- ???
struct RESTORE_DETERMINISTIC_WALLET : RPC_COMMAND {
    static constexpr auto names() { return NAMES("restore_deterministic_wallet"); }

    struct REQUEST {
        uint64_t restore_height;  // Height in which to start scanning the blockchain for
                                  // transactions into and out of this Wallet.
        std::string filename;     // Set the name of the Wallet.
        std::string seed;         // Mnemonic seed of wallet (25 words).
        std::string seed_offset;  // ???
        std::string password;     // Set password for Wallet.
        std::string language;     // Set language for the wallet.
        bool autosave_current;  // (Optional: Default true): If a pre-existing wallet is open, save
                                // to disk before opening the new wallet.
    } request;
};

/// Check if a wallet is a multisig one.
///
/// Inputs: None
///
/// Outputs:
///
/// - \p multisig -- St@tes if the wallet is multisig.
/// - \p ready -- ???
/// - \p threshold -- Amount of signature needed to sign a transfer.
/// - \p total -- Total amount of signature in the multisig wallet.
struct IS_MULTISIG : RPC_COMMAND {
    static constexpr auto names() { return NAMES("is_multisig"); }

    struct REQUEST : EMPTY {
    } request;
};

/// Prepare a wallet for multisig by generating a multisig string to share with peers.
///
/// Inputs: None
///
/// Outputs:
///
/// - \p multisig_info -- Multisig string to share with peers to create the multisig wallet.
struct PREPARE_MULTISIG : RESTRICTED {
    static constexpr auto names() { return NAMES("prepare_multisig"); }

    struct REQUEST : EMPTY {
    } request;
};

/// Make a wallet multisig by importing peers multisig string.
///
/// Inputs:
///
/// - \p multisig_info -- List of multisig string from peers.
/// - \p threshold -- Amount of signatures needed to sign a transfer. Must be less or equal than the
/// amount of signature in `multisig_info`.
/// - \p password -- Wallet password.
///
/// Outputs:
///
/// - \p address -- Multisig wallet address.
/// - \p multisig_info -- Multisig string to share with peers to create the multisig wallet (extra
/// step for N-1/N wallets).
struct MAKE_MULTISIG : RESTRICTED {
    static constexpr auto names() { return NAMES("make_multisig"); }

    struct REQUEST {
        std::vector<std::string> multisig_info;  // List of multisig string from peers.
        uint32_t threshold;    // Amount of signatures needed to sign a transfer. Must be less or
                               // equal than the amount of signature in `multisig_info`.
        std::string password;  // Wallet password.
    } request;
};

/// Export multisig info for other participants.
///
/// Inputs: None
///
/// Outputs:
///
/// - \p info -- Multisig info in hex format for other participants.
struct EXPORT_MULTISIG : RESTRICTED {
    static constexpr auto names() { return NAMES("export_multisig_info"); }

    struct REQUEST : EMPTY {
    } request;
};

/// Import multisig info from other participants.
///
/// Inputs:
///
/// - \p info -- List of multisig info in hex format from other participants.
///
/// Outputs:
///
/// - \p n_outputs -- Number of outputs signed with those multisig info.
struct IMPORT_MULTISIG : RESTRICTED {
    static constexpr auto names() { return NAMES("import_multisig_info"); }

    struct REQUEST {
        std::vector<std::string>
                info;  // List of multisig info in hex format from other participants.
    } request;
};

/// Turn this wallet into a multisig wallet, extra step for N-1/N wallets.
///
/// Inputs:
///
/// - \p password -- Wallet password.
/// - \p multisig_info -- List of multisig string from peers.
///
/// Outputs:
///
/// - \p address -- Multisig wallet address.
struct FINALIZE_MULTISIG : RESTRICTED {
    static constexpr auto names() { return NAMES("finalize_multisig"); }

    struct REQUEST {
        std::string password;                    // Wallet password.
        std::vector<std::string> multisig_info;  // List of multisig string from peers.
    } request;
};

/// TODO: description
///
/// Inputs:
///
/// - \p password -- Wallet password.
/// - \p multisig_info -- List of multisig string from peers.
///
/// Outputs:
///
/// - \p address -- Multisig wallet address.
/// - \p multisig_info -- Multisig string to share with peers to create the multisig wallet.
struct EXCHANGE_MULTISIG_KEYS : RESTRICTED {
    static constexpr auto names() { return NAMES("exchange_multisig_keys"); }

    struct REQUEST {
        std::string password;                    // Wallet password.
        std::vector<std::string> multisig_info;  // List of multisig string from peers.
    } request;
};

/// Sign a transaction in multisig.
///
/// Inputs:
///
/// - \p tx_data_hex -- Multisig transaction in hex format, as returned by transfer under
/// `multisig_txset`.
///
/// Outputs:
///
/// - \p tx_data_hex -- Multisig transaction in hex format.
/// - \p tx_hash_list -- List of transaction Hash.
struct SIGN_MULTISIG : RESTRICTED {
    static constexpr auto names() { return NAMES("sign_multisig"); }

    struct REQUEST {
        std::string tx_data_hex;  // Multisig transaction in hex format, as returned by transfer
                                  // under `multisig_txset`.
    } request;
};

/// Submit a signed multisig transaction.
///
/// Inputs:
///
/// - \p tx_data_hex -- Multisig transaction in hex format, as returned by sign_multisig under
/// tx_data_hex.
///
/// Outputs:
///
/// - \p tx_hash_list -- List of transaction hash.
struct SUBMIT_MULTISIG : RESTRICTED {
    static constexpr auto names() { return NAMES("submit_multisig"); }

    struct REQUEST {
        std::string tx_data_hex;  // Multisig transaction in hex format, as returned by
                                  // sign_multisig under tx_data_hex.
    } request;
};

/// Get RPC version Major & Minor integer-format, where Major is the first 16 bits and Minor the
/// last 16 bits.
///
/// Inputs: None
///
/// Outputs:
///
/// - \p version -- RPC version, formatted with Major * 2^16 + Minor(Major encoded over the first 16
/// bits, and Minor over the last 16 bits).
struct GET_VERSION : RPC_COMMAND {
    static constexpr auto names() { return NAMES("get_version"); }

    struct REQUEST : EMPTY {
    } request;
};

/// Stake for Service Node.
///
/// Inputs:
///
/// - \p destination -- Primary Public address that the rewards will go to.
/// - \p amount -- Amount of Loki to stake in atomic units.
/// - \p subaddr_indices -- (Optional) Transfer from this set of subaddresses. (Defaults to 0)
/// - \p service_node_key -- Service Node Public Address.
/// - \p priority -- Set a priority for the transaction. Accepted values are: or 0-4 for: default,
/// unimportant, normal, elevated, priority.
/// - \p get_tx_key -- (Optional) Return the transaction key after sending.
/// - \p do_not_relay -- (Optional) If true, the newly created transaction will not be relayed to
/// the oxen network. (Defaults to false)
/// - \p get_tx_hex -- Return the transaction as hex string after sending (Defaults to false)
/// - \p get_tx_metadata -- Return the metadata needed to relay the transaction. (Defaults to false)
///
/// Outputs:
///
/// - \p tx_hash -- Publicly searchable transaction hash.
/// - \p tx_key -- Transaction key if `get_tx_key` is `true`, otherwise, blank string.
/// - \p amount -- Amount transferred for the transaction in atomic units.
/// - \p fee -- Value in atomic units of the fee charged for the tx.
/// - \p tx_blob -- Raw transaction represented as hex string, if get_tx_hex is true.
/// - \p tx_metadata -- Set of transaction metadata needed to relay this transfer later, if
/// `get_tx_metadata` is `true`.
/// - \p multisig_txset -- Set of multisig transactions in the process of being signed (empty for
/// non-multisig).
/// - \p unsigned_txset -- Set of unsigned tx for cold-signing purposes.
struct STAKE : RESTRICTED {
    static constexpr auto names() { return NAMES("stake"); }

    struct REQUEST {
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
    } request;
};

/// Register Service Node.
///
/// Inputs:
///
/// - \p register_service_node_str -- String supplied by the prepare_registration command.
/// - \p get_tx_key -- (Optional) Return the transaction key after sending.
/// - \p do_not_relay -- (Optional) If true, the newly created transaction will not be relayed to
/// the oxen network. (Defaults to false)
/// - \p get_tx_hex -- Return the transaction as hex string after sending (Defaults to false)
/// - \p get_tx_metadata -- Return the metadata needed to relay the transaction. (Defaults to false)
///
/// Outputs:
///
/// - \p tx_hash -- Publicly searchable transaction hash.
/// - \p tx_key -- Transaction key if get_tx_key is true, otherwise, blank string.
/// - \p amount -- Amount transferred for the transaction in atomic units.
/// - \p fee -- Value in atomic units of the fee charged for the tx.
/// - \p tx_blob -- Raw transaction represented as hex string, if get_tx_hex is true.
/// - \p tx_metadata -- Set of transaction metadata needed to relay this transfer later, if
/// `get_tx_metadata` is `true`.
/// - \p multisig_txset -- Set of multisig transactions in the process of being signed (empty for
/// non-multisig).
/// - \p unsigned_txset -- Set of unsigned tx for cold-signing purposes.
struct REGISTER_SERVICE_NODE : RESTRICTED {
    static constexpr auto names() { return NAMES("register_service_node"); }

    struct REQUEST {
        std::string
                register_service_node_str;  // String supplied by the prepare_registration command.
        bool get_tx_key;                    // (Optional) Return the transaction key after sending.
        bool do_not_relay;  // (Optional) If true, the newly created transaction will not be relayed
                            // to the oxen network. (Defaults to false)
        bool get_tx_hex;  // Return the transaction as hex string after sending (Defaults to false)
        bool get_tx_metadata;  // Return the metadata needed to relay the transaction. (Defaults to
                               // false)
    } request;
};

/// Request to unlock stake by deregistering Service Node.
///
/// Inputs:
///
/// - \p service_node_key -- Service Node Public Key.
///
/// Outputs:
///
/// - \p unlocked -- States if stake has been unlocked.
/// - \p msg -- Information on the unlocking process.
struct REQUEST_STAKE_UNLOCK : RESTRICTED {
    static constexpr auto names() { return NAMES("request_stake_unlock"); }

    struct REQUEST {
        std::string service_node_key;  // Service Node Public Key.
    };
};

/// Check if Service Node can unlock its stake.
///
/// Inputs:
///
/// - \p service_node_key -- Service node public address.
///
/// Outputs:
///
/// - \p can_unlock -- States if the stake can be locked.
/// - \p msg -- Information on the unlocking process.
struct CAN_REQUEST_STAKE_UNLOCK : RESTRICTED {
    static constexpr auto names() { return NAMES("can_request_stake_unlock"); }

    struct REQUEST {
        std::string service_node_key;  // Service node public address.
    };
};

/// Parse an address to validate if it's a valid Loki address.
///
/// Inputs:
///
/// - \p address -- Address to check.
/// - \p any_net_type -- ???
/// - \p allow_openalias -- ???
///
/// Outputs:
///
/// - \p valid -- States if it is a valid Loki address.
/// - \p integrated -- States if it is an integrated address.
/// - \p subaddress -- States if it is a subaddress.
/// - \p nettype -- States if the nettype is mainet, testnet, devnet.
/// - \p openalias_address -- ???
struct VALIDATE_ADDRESS : RPC_COMMAND {
    static constexpr auto names() { return NAMES("validate_address"); }

    struct REQUEST {
        std::string address;   // Address to check.
        bool any_net_type;     // ???
        bool allow_openalias;  // ???
    } request;
};

/// TODO: description
///
/// Inputs:
///
/// - \p address -- The remote url of the daemon.
/// - \p proxy -- Optional proxy to use for connection. E.g. socks4a://hostname:port for a SOCKS
/// proxy.
/// - \p trusted -- When true, allow the usage of commands that may compromise privacy
/// - \p ssl_private_key_path -- HTTPS client authentication: path to private key.  Must use an
/// address starting with https://
/// - \p ssl_certificate_path -- HTTPS client authentication: path to certificate.  Must use an
/// address starting with https://
/// - \p ssl_ca_file -- Path to CA bundle to use for HTTPS server certificate verification instead
/// of system CA.  Requires an https:// address.
/// - \p ssl_allow_any_cert -- Make HTTPS insecure: disable HTTPS certificate verification when
/// using an https:// address.
///
/// Outputs: None
struct SET_DAEMON : RESTRICTED {
    static constexpr auto names() { return NAMES("set_daemon"); }

    struct REQUEST {
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
    } request;
};

/// TODO: description
///
/// Inputs:
///
/// - \p level -- ???
///
/// Outputs: None
struct SET_LOG_LEVEL : RESTRICTED {
    static constexpr auto names() { return NAMES("set_log_level"); }

    struct REQUEST {
        int8_t level;  // ???
    } request;
};

/// TODO: description
///
/// Inputs:
///
/// - \p categories -- ???
///
/// Outputs:
///
/// - \p categories -- ???
struct SET_LOG_CATEGORIES : RESTRICTED {
    static constexpr auto names() { return NAMES("set_log_categories"); }

    struct REQUEST {
        std::string categories;  // ???
    } request;
};

/// Buy a Loki Name System (ONS) mapping that maps a unique name to a Session ID or Lokinet address.
///
/// Currently supports Session, Lokinet and Wallet registrations. Lokinet registrations can be for
/// 1, 2, 5, or 10 years by specifying a type value of "lokinet", "lokinet_2y", "lokinet_5y",
/// "lokinet_10y". Session registrations do not expire. The owner of the ONS entry (by default, the
/// purchasing wallet) will be permitted to submit ONS update transactions to the Loki blockchain
/// (for example to update a Session pubkey or the target Lokinet address). You may change the
/// primary owner or add a backup owner in the registration and can change them later with update
/// transactions. Owner addresses can be either Loki wallets, or generic ed25519 pubkeys (for
/// advanced uses). For Session, the recommended owner or backup owner is the ed25519 public key of
/// the user's Session ID. When specifying owners, either a wallet (sub)address or standard ed25519
/// public key is supported per mapping. Updating the value that a name maps to requires one of the
/// owners to sign the update transaction. For wallets, this is signed using the (sub)address's
/// spend key. For more information on updating and signing see the ONS_UPDATE_MAPPING
/// documentation.
///
/// Inputs:
///
/// - \p type -- The mapping type: "session", "lokinet", "lokinet_2y", "lokinet_5y", "lokinet_10y",
/// "wallet".
/// - \p owner -- (Optional): The ed25519 public key or wallet address that has authority to update
/// the mapping.
/// - \p backup_owner -- (Optional): The secondary, backup public key that has authority to update
/// the mapping.
/// - \p name -- The name to purchase via Oxen Name Service
/// - \p value -- The value that the name maps to via Oxen Name Service, (i.e. For Session: [display
/// name->session public key],  for wallets: [name->wallet address], for Lokinet: [name->domain
/// name]).
/// - \p account_index -- (Optional) Transfer from this account index. (Defaults to 0)
/// - \p subaddr_indices -- (Optional) Transfer from this set of subaddresses. (Defaults to 0)
/// - \p priority -- Set a priority for the transaction. Accepted values are: or 0-4 for: default,
/// unimportant, normal, elevated, priority.
/// - \p get_tx_key -- (Optional) Return the transaction key after sending.
/// - \p do_not_relay -- (Optional) If true, the newly created transaction will not be relayed to
/// the oxen network. (Defaults to false)
/// - \p get_tx_hex -- Return the transaction as hex string after sending (Defaults to false)
/// - \p get_tx_metadata -- Return the metadata needed to relay the transaction. (Defaults to false)
///
/// Outputs:
///
/// - \p tx_hash -- Publicly searchable transaction hash.
/// - \p tx_key -- Transaction key if `get_tx_key` is `true`, otherwise, blank string.
/// - \p amount -- Amount transferred for the transaction in atomic units.
/// - \p fee -- Value in atomic units of the fee charged for the tx.
/// - \p tx_blob -- Raw transaction represented as hex string, if get_tx_hex is true.
/// - \p tx_metadata -- Set of transaction metadata needed to relay this transfer later, if
/// `get_tx_metadata` is `true`.
/// - \p multisig_txset -- Set of multisig transactions in the process of being signed (empty for
/// non-multisig).
/// - \p unsigned_txset -- Set of unsigned tx for cold-signing purposes.
struct ONS_BUY_MAPPING : RESTRICTED {
    static constexpr auto names() { return NAMES("ons_buy_mapping"); }

    static constexpr const char* description =
            R"(Buy an Oxen Name System (ONS) mapping that maps a unique name to a Session ID, Oxen Address or Lokinet address.

Currently supports Session, Wallet and Lokinet registrations. Lokinet registrations can be for 1, 2, 5, or 10 years by specifying a type value of "lokinet", "lokinet_2y", "lokinet_5y", "lokinet_10y". Session and Wallet registrations do not expire.

The owner of the ONS entry (by default, the purchasing wallet) will be permitted to submit ONS update transactions to the Loki blockchain (for example to update a Session pubkey or the target Lokinet address). You may change the primary owner or add a backup owner in the registration and can change them later with update transactions. Owner addresses can be either Loki wallets, or generic ed25519 pubkeys (for advanced uses).

When specifying owners, either a wallet (sub)address or standard ed25519 public key is supported per mapping. Updating the value that a name maps to requires one of the owners to sign the update transaction. For wallets, this is signed using the (sub)address's spend key.

For more information on updating and signing see the ONS_UPDATE_MAPPING documentation.)";

    struct REQUEST {
        std::string type;  // The mapping type: "session", "wallet", "lokinet", "lokinet_2y",
                           // "lokinet_5y", "lokinet_10y".
        std::optional<std::string> owner;  // (Optional): The ed25519 public key or wallet address
                                           // that has authority to update the mapping.
        std::optional<std::string> backup_owner;  // (Optional): The secondary, backup public key
                                                  // that has authority to update the mapping.
        std::string name;                         // The name to purchase via Oxen Name Service
        std::string value;  // The value that the name maps to via Oxen Name Service, (i.e. For
                            // Session: [display name->session public key],  for wallets:
                            // [name->wallet address], for Lokinet: [name->domain name]).

        uint32_t account_index;  // (Optional) Transfer from this account index. (Defaults to 0)
        std::vector<uint32_t> subaddr_indices;  // (Optional) Transfer from this set of
                                                // subaddresses. (Defaults to 0)
        uint32_t priority;  // Set a priority for the transaction. Accepted values are: or 0-4 for:
                            // default, unimportant, normal, elevated, priority.
        bool get_tx_key;    // (Optional) Return the transaction key after sending.
        bool do_not_relay;  // (Optional) If true, the newly created transaction will not be relayed
                            // to the oxen network. (Defaults to false)
        bool get_tx_hex;  // Return the transaction as hex string after sending (Defaults to false)
        bool get_tx_metadata;  // Return the metadata needed to relay the transaction. (Defaults to
                               // false)
    } request;
};

/// Renew an active lokinet ONS registration
///
/// Renews a Loki Name System lokinet mapping by adding to the existing expiry time.
/// The renewal can be for 1, 2, 5, or 10 years by specifying a `type` value of "lokinet_2y",
/// "lokinet_10y", etc.
///
/// Inputs:
///
/// - \p type -- The mapping type, "lokinet" (1-year), or "lokinet_2y", "lokinet_5y", "lokinet_10y"
/// for multi-year registrations.
/// - \p name -- The name to update
/// - \p account_index -- (Optional) Transfer from this account index. (Defaults to 0)
/// - \p subaddr_indices -- (Optional) Transfer from this set of subaddresses. (Defaults to 0)
/// - \p priority -- Set a priority for the transaction. Accepted values are: 0-4 for: default,
/// unimportant, normal, elevated, priority.
/// - \p get_tx_key -- (Optional) Return the transaction key after sending.
/// - \p do_not_relay -- (Optional) If true, the newly created transaction will not be relayed to
/// the oxen network. (Defaults to false)
/// - \p get_tx_hex -- Return the transaction as hex string after sending (Defaults to false)
/// - \p get_tx_metadata -- Return the metadata needed to relay the transaction. (Defaults to false)
///
/// Outputs:
///
/// - \p tx_hash -- Publicly searchable transaction hash.
/// - \p tx_key -- Transaction key if `get_tx_key` is `true`, otherwise, blank string.
/// - \p amount -- Amount transferred for the transaction in atomic units.
/// - \p fee -- Value in atomic units of the fee charged for the tx.
/// - \p tx_blob -- Raw transaction represented as hex string, if get_tx_hex is true.
/// - \p tx_metadata -- Set of transaction metadata needed to relay this transfer later, if
/// `get_tx_metadata` is `true`.
/// - \p multisig_txset -- Set of multisig transactions in the process of being signed (empty for
/// non-multisig).
/// - \p unsigned_txset -- Set of unsigned tx for cold-signing purposes.
struct ONS_RENEW_MAPPING : RESTRICTED {
    static constexpr auto names() { return NAMES("ons_renew_mapping"); }

    static constexpr const char* description =
            R"(Renews a Loki Name System lokinet mapping by adding to the existing expiry time.

The renewal can be for 1, 2, 5, or 10 years by specifying a `type` value of "lokinet_2y", "lokinet_10y", etc.)";

    struct REQUEST {
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
    } request;
};

/// Update the underlying value in the name->value mapping via Loki Name Service.
///
/// At least one field (value, owner, or backup owner) must be specified in the update.
/// The existing owner (wallet address or ed25519 public key) of the mapping must be used to sign
/// the update. If no signature is provided then the wallet's active address (or subaddress) will be
/// used to sign the update. If signing is performed externally then you must first encrypt the
/// `value` (if being updated), then sign a BLAKE2b hash of {encryptedvalue || owner || backup_owner
/// || txid} (where txid is the most recent ONS update or registration transaction of this mapping;
/// each of encrypted/owner/backup are empty strings if not being updated). For a wallet owner this
/// is signed using the owning wallet's spend key; for a Ed25519 key this is a standard Ed25519
/// signature.
///
/// Inputs:
///
/// - \p type -- The mapping type, "session", "lokinet", or "wallet".
/// - \p name -- The name to update via Loki Name Service
/// - \p value -- (Optional): The new value that the name maps to via Loki Name Service. If not
/// specified or given the empty string "", then the mapping's value remains unchanged. If using a
/// `signature` then this value (if non-empty) must be already encrypted.
/// - \p owner -- (Optional): The new owner of the mapping. If not specified or given the empty
/// string "", then the mapping's owner remains unchanged.
/// - \p backup_owner -- (Optional): The new backup owner of the mapping. If not specified or given
/// the empty string "", then the mapping's backup owner remains unchanged.
/// - \p signature -- (Optional): Signature derived using libsodium generichash on {current txid
/// blob, new value blob} of the mapping to update. By default the hash is signed using the wallet's
/// spend key as an ed25519 keypair, if signature is specified.
/// - \p account_index -- (Optional) Transfer from this account index. (Defaults to 0)
/// - \p subaddr_indices -- (Optional) Transfer from this set of subaddresses. (Defaults to 0)
/// - \p priority -- Set a priority for the transaction. Accepted values are: 0-4 for: default,
/// unimportant, normal, elevated, priority.
/// - \p get_tx_key -- (Optional) Return the transaction key after sending.
/// - \p do_not_relay -- (Optional) If true, the newly created transaction will not be relayed to
/// the oxen network. (Defaults to false)
/// - \p get_tx_hex -- Return the transaction as hex string after sending (Defaults to false)
/// - \p get_tx_metadata -- Return the metadata needed to relay the transaction. (Defaults to false)
///
/// Outputs:
///
/// - \p tx_hash -- Publicly searchable transaction hash.
/// - \p tx_key -- Transaction key if `get_tx_key` is `true`, otherwise, blank string.
/// - \p amount -- Amount transferred for the transaction in atomic units.
/// - \p fee -- Value in atomic units of the fee charged for the tx.
/// - \p tx_blob -- Raw transaction represented as hex string, if get_tx_hex is true.
/// - \p tx_metadata -- Set of transaction metadata needed to relay this transfer later, if
/// `get_tx_metadata` is `true`.
/// - \p multisig_txset -- Set of multisig transactions in the process of being signed (empty for
/// non-multisig).
/// - \p unsigned_txset -- Set of unsigned tx for cold-signing purposes.
struct ONS_UPDATE_MAPPING : RESTRICTED {
    static constexpr auto names() { return NAMES("ons_update_mapping"); }

    static constexpr const char* description =
            R"(Update a Loki Name System mapping to refer to a new address or owner.

At least one field (value, owner, or backup owner) must be specified in the update.

The existing owner (wallet address or ed25519 public key) of the mapping must be used to sign the update. If no signature is provided then the wallet's active address (or subaddress) will be used to sign the update.

If signing is performed externally then you must first encrypt the `value` (if being updated), then sign a BLAKE2b hash of {encryptedvalue || owner || backup_owner || txid} (where txid is the most recent ONS update or registration transaction of this mapping; each of encrypted/owner/backup are empty strings if not being updated). For a wallet owner this is signed using the owning wallet's spend key; for a Ed25519 key this is a standard Ed25519 signature.)";

    struct REQUEST {
        std::string type;  // The mapping type, "session", "lokinet", or "wallet".
        std::string name;  // The name to update via Loki Name Service
        std::optional<std::string>
                value;  // (Optional): The new value that the name maps to via Loki Name Service. If
                        // not specified or given the empty string "", then the mapping's value
                        // remains unchanged. If using a `signature` then this value (if non-empty)
                        // must be already encrypted.
        std::optional<std::string>
                owner;  // (Optional): The new owner of the mapping. If not specified or given the
                        // empty string "", then the mapping's owner remains unchanged.
        std::optional<std::string>
                backup_owner;   // (Optional): The new backup owner of the mapping. If not specified
                                // or given the empty string "", then the mapping's backup owner
                                // remains unchanged.
        std::string signature;  // (Optional): Signature derived using libsodium generichash on
                                // {current txid blob, new value blob} of the mapping to update. By
                                // default the hash is signed using the wallet's spend key as an
                                // ed25519 keypair, if signature is specified.

        uint32_t account_index;  // (Optional) Transfer from this account index. (Defaults to 0)
        std::vector<uint32_t> subaddr_indices;  // (Optional) Transfer from this set of
                                                // subaddresses. (Defaults to 0)
        uint32_t priority;  // Set a priority for the transaction. Accepted values are: 0-4 for:
                            // default, unimportant, normal, elevated, priority.
        bool get_tx_key;    // (Optional) Return the transaction key after sending.
        bool do_not_relay;  // (Optional) If true, the newly created transaction will not be relayed
                            // to the oxen network. (Defaults to false)
        bool get_tx_hex;  // Return the transaction as hex string after sending (Defaults to false)
        bool get_tx_metadata;  // Return the metadata needed to relay the transaction. (Defaults to
                               // false)

    } request;
};

/// Generate the signature necessary for updating the requested record using the wallet's active
/// [sub]address's spend key. The signature is only valid if the queried wallet is one of the owners
/// of the ONS record.
///
/// This command is only required if the open wallet is one of the owners of a ONS record but wants
/// the update transaction to occur via another non-owning wallet. By default, if no signature is
/// specified to the update transaction, the open wallet is assumed the owner and it's active
/// [sub]address's spend key will automatically be used.
///
/// Inputs:
///
/// - \p type -- The mapping type, currently we support "session", "lokinet" and "wallet" mappings.
/// - \p name -- The desired name to update via Oxen Name Service
/// - \p encrypted_value -- (Optional): The new encrypted value that the name maps to via Oxen Name
/// Service. If not specified or given the empty string "", then the mapping's value remains
/// unchanged.
/// - \p owner -- (Optional): The new owner of the mapping. If not specified or given the empty
/// string "", then the mapping's owner remains unchanged.
/// - \p backup_owner -- (Optional): The new backup owner of the mapping. If not specified or given
/// the empty string "", then the mapping's backup owner remains unchanged.
/// - \p account_index -- (Optional) Use this wallet's subaddress account for generating the
/// signature
///
/// Outputs:
///
/// - \p signature -- A signature valid for using in ONS to update an underlying mapping.
struct ONS_MAKE_UPDATE_SIGNATURE : RESTRICTED {
    static constexpr auto names() { return NAMES("ons_make_update_mapping_signature"); }

    static constexpr const char* description =
            R"(Generate the signature necessary for updating the requested record using the wallet's active [sub]address's spend key. The signature is only valid if the queried wallet is one of the owners of the ONS record.

This command is only required if the open wallet is one of the owners of a ONS record but wants the update transaction to occur via another non-owning wallet. By default, if no signature is specified to the update transaction, the open wallet is assumed the owner and it's active [sub]address's spend key will automatically be used.)";

    struct REQUEST {
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
    } request;
};

/// Takes a ONS name, upon validating it, generates the hash and returns the base64 representation
/// of the hash suitable for use in the daemon ONS name queries.
///
/// Inputs:
///
/// - \p type -- The mapping type, "session", "lokinet" or "wallet".
/// - \p name -- The desired name to hash
///
/// Outputs:
///
/// - \p name -- The name hashed and represented in base64
struct ONS_HASH_NAME : RPC_COMMAND {
    static constexpr auto names() { return NAMES("ons_hash_name"); }

    struct REQUEST {
        std::string type;  // The mapping type, "session", "lokinet" or "wallet".
        std::string name;  // The desired name to hash
    } request;
};

/// Returns a list of known, plain-text ONS names along with record details for names that this
/// wallet knows about.  This can optionally decrypt the ONS value as well, or else just return the
/// encrypted value.
///
/// Inputs:
///
/// - \p decrypt -- If true (default false) then also decrypt and include the `value` field
/// - \p include_expired -- If true (default false) then also include expired records
///
/// Outputs:
///
/// - \p known_names -- List of records known to this wallet
///   - \p type -- The mapping type, "session" or "lokinet".
///   - \p hashed -- The hashed name (in base64)
///   - \p name -- The plaintext name
///   - \p owner -- The public key that purchased the Loki Name Service entry.
///   - \p backup_owner -- The backup public key or wallet that the owner specified when purchasing
///   the Loki Name Service entry. Omitted if no backup owner.
///   - \p encrypted_value -- The encrypted value that the name maps to, in hex.
///   - \p value -- Decrypted value that that name maps to.  Only provided if `decrypt: true` was
///   specified in the request.
///   - \p update_height -- The last height that this Loki Name Service entry was updated on the
///   Blockchain.
///   - \p expiration_height -- For records that expire, this will be set to the expiration block
///   height.
///   - \p expired -- Indicates whether the record has expired. Only included in the response if
///   "include_expired" is specified in the request.
///   - \p txid -- The txid of the mapping's most recent update or purchase.
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
    };
    struct REQUEST {
        bool decrypt;  // If true (default false) then also decrypt and include the `value` field
        bool include_expired;  // If true (default false) then also include expired records
    } request;
};

/// Adds one or more names to the persistent ONS wallet cache of known names (i.e. for names that
/// are owned by this wallet that aren't currently in the cache).
///
/// Inputs:
///
/// - \p names -- List of names to add to the cache
///   - \p type -- The ONS type (mandatory); currently support values are: "session", "lokinet"
///   - \p name -- The (unhashed) name of the record
///
/// Outputs: None
struct ONS_ADD_KNOWN_NAMES : RPC_COMMAND {
    static constexpr auto names() { return NAMES("ons_add_known_names"); }

    struct record {
        std::string type;  // The ONS type (mandatory); currently support values are: "session",
                           // "lokinet"
        std::string name;  // The (unhashed) name of the record
    };

    struct REQUEST {
        std::vector<record> names;  // List of names to add to the cache
    } request;
};

/// Takes a ONS encrypted value and encrypts the mapping value using the ONS name.
///
/// Inputs:
///
/// - \p name -- The ONS name with which to encrypt the value.
/// - \p type -- The mapping type: "session" or "lokinet".
/// - \p value -- The value to be encrypted.
///
/// Outputs:
///
/// - \p encrypted_value -- The encrypted value, in hex
struct ONS_ENCRYPT_VALUE : RPC_COMMAND {
    static constexpr auto names() { return NAMES("ons_encrypt_value"); }

    struct REQUEST {
        std::string name;   // The ONS name with which to encrypt the value.
        std::string type;   // The mapping type: "session" or "lokinet".
        std::string value;  // The value to be encrypted.
    } request;
};

/// Takes a ONS encrypted value and decrypts the mapping value using the ONS name.
///
/// Inputs:
///
/// - \p name -- The ONS name of the given encrypted value.
/// - \p type -- The mapping type: "session" or "lokinet".
/// - \p encrypted_value -- The encrypted value represented in hex.
///
/// Outputs:
///
/// - \p value -- The value decrypted
struct ONS_DECRYPT_VALUE : RPC_COMMAND {
    static constexpr auto names() { return NAMES("ons_decrypt_value"); }

    struct REQUEST {
        std::string name;             // The ONS name of the given encrypted value.
        std::string type;             // The mapping type: "session" or "lokinet".
        std::string encrypted_value;  // The encrypted value represented in hex.
    } request;
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
        EXPORT_VIEW_KEY,
        EXPORT_SPEND_KEY,
        EXPORT_MNEMONIC_KEY,
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
        ONS_ENCRYPT_VALUE,
        STATUS>;

}  // namespace wallet::rpc
