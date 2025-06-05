// Copyright (c) 2021, The Oxen Project
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

#include <SQLiteCpp/SQLiteCpp.h>
#include <cryptonote_basic/cryptonote_basic_impl.h>  // cryptonote::address_parse_info...
#include <cryptonote_config.h>
#include <cryptonote_core/service_node_list.h>  // service_node_list::state_t...

#include <filesystem>
#include <optional>
#include <sqlitedb/database.hpp>
#include <string>

namespace cryptonote {

struct sql_payment {
    cryptonote::reward_money amount;  // The amount to payout not including the liqudation fee

    // Fee to apply on the payment amount, 0 in most cases except when the payment is the return of
    // a stake after being liquidated and the associated address is the operator.
    cryptonote::reward_money liquidation;
};

using block_payments = std::
        unordered_map<std::variant<eth::address, cryptonote::account_public_address>, sql_payment>;

class BlockchainSQLite : public db::Database {
  public:
    explicit BlockchainSQLite(cryptonote::network_type nettype, std::filesystem::path db_path);
    BlockchainSQLite(const BlockchainSQLite&) = delete;

    ~BlockchainSQLite() { rescan_stop(); }

    // Database management functions. Should be called on creation of BlockchainSQLite
    void create_schema();
    void upgrade_schema();
    void reset_database();

    // Update the height stored in the SQL DB that indicates the last block height that this DB has
    // synchronised to in.
    void update_height(uint64_t new_height);

    enum class PaymentTableType {
        Nil,      // Table containing current state
        Archive,  // Table containing state stored periodically at HISTORY_ARCHIVE_INTERVAL
                  // intervals
        Recent,   // Table containing state stored from within the last HISTORY_RECENT_KEEP_WINDOW
    };

    // Rewinds the SQL DB to the specified height. This function is called internally by the SNL on
    // detach.
    void blockchain_detached(PaymentTableType type, uint64_t height, uint64_t target_height = 0);

    // Return the number of rows for the current payments accrued table.
    int batch_payments_accrued_row_count();
    // Returns true if the recent (recent=true) or archive (recent=false) table has any stored
    // payments for the given height.
    bool batch_payments_accrued_has_any(bool recent, uint64_t height);

    // Add payments to the specified addresses to the SQL rewards table. The function throws if
    // insertion into the DB fails.
    //
    // If the payments are token rewards set `is_rewards` to true to ensure that rewards are
    // tracked in a separate column. Set it to `false` if payments are for delayed/exit payments
    // inorder to separate the tracked rewards from the exit payments values.
    void add_sn_rewards(hf hf_version, const block_payments& payments, bool is_rewards);

    // Submit locked and purged stakes to the DB to update the non-consensus metadata that tracks
    // the lifetime total locked stakes for a given ethereum address.
    void submit_stakes_metadata(
            const service_nodes::block_add_result& block_add, bool _no_transaction = false);

    enum class delayed_payments_type {
        all,
        height,
        address,
    };

    // Retrieves all delayed payments:
    block_payments get_delayed_payments();
    // Retrieves delayed payments for a single ETH address:
    block_payments get_delayed_payments(const eth::address& addr);
    // Retrieves delayed payments due at the given height
    block_payments get_delayed_payments(uint64_t height);

  private:
    // This function throws if adding the rewards to the SQL tables for 'block'
    // fails.
    void reward_handler(
            const cryptonote::block& block,
            const service_nodes::service_node_list::state_t& service_nodes_state,
            const service_nodes::block_add_result& block_add);

    std::unordered_map<account_public_address, std::string> address_str_cache;
    std::pair<hf, cryptonote::address_parse_info> parsed_governance_addr = {hf::none, {}};

    // Returns a reference to the underlying string, reference must not be held
    // onto, only transiently in the same frame as the string is requested.
    //
    // This function must be called with the address_str_cache_mutex held!
    const std::string& get_address_str(const cryptonote::batch_sn_payment& addr);
    std::pair<std::optional<int>, std::string> get_address_str(
            const std::variant<eth::address, cryptonote::account_public_address>& addr,
            uint64_t batching_interval);
    std::mutex address_str_cache_mutex;

    bool table_exists(const std::string& name);
    bool index_exists(const std::string& name);
    bool trigger_exists(const std::string& name);

    // Long rescans can take quite a while to process.  Batching block inserts into one database
    // transaction speeds this up considerably.  This is called automatically if a rescan is
    // larger than 5000 blocks.
    void rescan_start();
    void rescan_stop();

    std::optional<SQLite::Transaction> rescan_tx{std::nullopt};
    size_t rescan_count{0};
    uint64_t rescan_target{0};

    // Returns a new transaction *unless* the rescan_tx is already active, in which case you get
    // nullopt.
    std::optional<SQLite::Transaction> begin_tx(
            SQLite::TransactionBehavior behave = SQLite::TransactionBehavior::IMMEDIATE);

  public:
    struct wallet_info {
        uint64_t height;  // Height at which the wallet info was retrieved for

        // True if the wallet has participated in the network or not. When false all values are
        // zeroed (because the wallet has not earnt or spent any tokens on the network).
        bool found;

        // For OXEN addresses, rewards that has been accrued but not paid out to the address yet.
        //
        // For ETH addresses, lifetime rewards _and_ unlocked stakes for the address. (Note that,
        // unlike Oxen addresses, these rewards never reset to zero; but rather the rewards contract
        // keeps track of the current paid and current total and pays out the difference).
        //
        // For ETH addresses, this can be derived by
        // `lifetime_unlocked_stakes + lifetime_rewards - lifetime_liquidated_stakes`
        cryptonote::reward_money amount;

        // For ETH addresses _only_, the total amount of tokens that were locked by this wallet and
        // so forth for lifetime unlocked, rewards and liquidated amounts.
        cryptonote::reward_money lifetime_locked_stakes;
        cryptonote::reward_money lifetime_unlocked_stakes;
        cryptonote::reward_money lifetime_rewards;
        cryptonote::reward_money lifetime_liquidated_stakes;

        // For ETH addresses _only_, the amount of tokens currently locked in the network (e.g.
        // staked in a node). This is defined as `lifetime locked - lifetimed unlocked` and
        // precalculated for convenience. This number includes `timelocked_stakes`.
        cryptonote::reward_money locked_stakes;

        // For ETH addresses _only_, the amount of tokens awaiting to be unlocked from the network
        // (e.g. an exit has been processed and the stake is under a time lock before being
        // claimable by the address)
        cryptonote::reward_money timelocked_stakes;

        wallet_info() = default;
        wallet_info(
                BlockchainSQLite& db,
                std::string_view address,
                std::optional<std::tuple<int64_t, int64_t, int64_t, int64_t, int64_t>> metadata,
                std::optional<hf> hf_version = std::nullopt);
        wallet_info(uint64_t height, bool found);
    };

    // See `wallet_info`
    wallet_info get_accrued_rewards(
            const eth::address& address, std::optional<hf> hf_version = std::nullopt);

    // See `wallet_info`
    wallet_info get_accrued_rewards(const account_public_address& address);

    // Returns `found` as `false` if `at_height` is higher than the current block height, or lower
    // than the oldest stored recent height (see network_config's STORE_RECENT_REWARDS;, otherwise
    // returns the balance.
    wallet_info get_accrued_rewards(const eth::address& address, uint64_t at_height);

    // Returns `found` as `false` if `at_height` is higher than the known height, or lower than the
    // stored recent heights (see network_config's STORE_RECENT_REWARDS); otherwise returns the
    // wallet info.
    wallet_info get_accrued_rewards(const account_public_address& address, uint64_t at_height);

    // get_all_accrued_rewards -> queries the database for all the amounts that have been accrued to
    // nodes and will return 2 vectors corresponding to the addresses's wallet info.
    std::pair<std::vector<std::string>, std::vector<wallet_info>> get_all_accrued_rewards();

    // get_payments -> passing a block height will return an array of payments that should be
    // created in a coinbase transaction on that block given the current batching DB state.
    std::vector<cryptonote::batch_sn_payment> get_sn_payments(uint64_t block_height);

    // Takes the list of contributors from sn_info with their SN contribution amounts and will
    // calculate how much of the block rewards should be the allocated to the contributors. The
    // function will *add* the calculated amounts to the value in the given `payments`, creating new
    // entries (at value 0) as needed and adding to values that are already present.  Existing
    // values in the map are *not* cleared or replaced.
    //
    // Note that distribution_amount here is passed as milli-atomic OXEN for extra precision.
    void add_rewards(
            hf hf_version,
            cryptonote::reward_money distribution_amount,
            const service_nodes::service_node_info& sn_info,
            block_payments& payments) const;

    // add/pop_block -> takes a block that contains new block rewards to be batched and added to the
    // database and/or batching payments that need to be subtracted from the database, in addition
    // it takes a reference to the service node state which it will use to calculate the individual
    // payouts. The function will then process this block add and subtracting to the batching DB
    // appropriately. This is the primary entry point for the blockchain to add to the batching
    // database. Each accepted block should call this passing in the SN list structure.
    bool add_block(
            const cryptonote::block& block,
            const service_nodes::service_node_list::state_t& service_nodes_state,
            const service_nodes::block_add_result& block_add,
            const std::optional<service_nodes::rescan_context>& rescan = std::nullopt);

    // Add a payment to the delayed_payments table. 'at_height' should be greater than or equal to
    // the height of the table or otherwise the payments may be deleted without taking effect. This
    // function asserts if 'at_height' does not meet this criteria.
    bool add_delayed_payments(
            std::span<const service_nodes::eth_stake> payments,
            uint64_t at_height,
            uint64_t delay_blocks);

    // validate_batch_payment -> used to make sure that list of miner_tx_vouts is correct. Compares
    // the miner_tx_vouts with a list previously extracted payments to make sure that the correct
    // persons are being paid.
    bool validate_batch_payment(
            const std::vector<std::pair<crypto::public_key, uint64_t>>& miner_tx_vouts,
            const std::vector<cryptonote::batch_sn_payment>& calculated_payments_from_batching_db,
            uint64_t block_height,
            const std::optional<service_nodes::rescan_context>& rescan = std::nullopt);

    // these keep track of payments made to SN operators after then payment has been made. Allows
    // for popping blocks back and knowing who got paid in those blocks. passing in a list of people
    // to be marked as paid in the paid_amounts vector. Block height will be added to the
    // batched_payments_paid database as height_paid.
    bool save_payments(uint64_t block_height, std::span<const batch_sn_payment> paid_amounts);

    // Applies the subatomic -> atomic value conversion of amount and lifetime_reward values; this
    // must be called once (and only once!) at the HF22 fork height to convert milli-atomic values
    // (for HF21 and earlier blocks) into atomics (expected for HF22+ blocks).
    void convert_hf22();

    uint64_t height;
    const cryptonote::network_type nettype;
};

}  // namespace cryptonote
