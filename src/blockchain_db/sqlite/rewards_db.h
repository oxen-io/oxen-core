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

#include <cryptonote_basic/cryptonote_basic_impl.h>  // cryptonote::address_parse_info...
#include <cryptonote_config.h>
#include <cryptonote_core/service_node_list.h>  // service_node_list::state_t...

#include <functional>
#include <optional>
#include <shared_mutex>
#include <sqlitedb/sqlite.hpp>
#include <string>

#include "accrued_history.h"

namespace cryptonote {

struct sql_payment {
    cryptonote::reward_money amount;  // The amount to payout not including the liqudation fee

    // Fee to apply on the payment amount, 0 in most cases except when the payment is the return of
    // a stake after being liquidated and the associated address is the operator.
    cryptonote::reward_money liquidation;
};

using block_payments = std::unordered_map<rewards_address, sql_payment>;

// A stake returned by a node's exit, held back until the block at `payout_height`, which credits it
// to the contributor.  Amounts are atomic.
struct delayed_payment {
    eth::address addr;
    int64_t amount;
    int64_t liquidation;
    uint64_t payout_height;
    uint64_t height;  // The block that added it
    uint32_t block_height;  // The block that the exit event was mined in
    uint32_t block_tx_index;
    uint32_t contributor_index;
};

// The service node rewards accrued to each address.
//
// The live values are kept in memory, along with those of the heights just before (see
// accrued_history), and are what every block's processing and every query uses.  The
// database holds snapshots of them, written at each height divisible by
// service_nodes::STATE_SNAPSHOT_INTERVAL (in the same transaction as that block's SN list state,
// when that is in the same database) and at each SN archive height, and the delayed payments as
// they are added.  Startup loads the newest snapshot and the blocks after it are replayed; a rewind
// further back than the in-memory heights loads the newest snapshot at or below where it goes to.
//
// Retention of the snapshots, applied whenever one is written:
// - the three newest are kept, whatever their heights;
// - a snapshot at an SN archive height (a multiple of HISTORY_ARCHIVE_INTERVAL) is kept for as long
//   as the SN archive retains its full state there (see service_nodes::oldest_retained_archive), so
//   that each of those is a height that both can be restored to;
// - everything else is deleted.
// Delayed payments are kept until they have paid out at or before the oldest snapshot.
//
// Threads: the thread adding and removing blocks is the only one that changes anything; other
// threads may call the const-qualified queries (get_accrued_rewards, get_all_accrued_rewards,
// get_delayed_payments, get_sn_payments) at any time.  Those take a shared lock on the in-memory
// state, which the block thread locks exclusively only while publishing a block's changes or
// rewinding.  A block's values are visible to them as soon as it has been processed, which can be
// before the blockchain database commits it; if it then fails, its detach rewinds them.
class RewardsDB {
  public:
    // Uses (creating, or migrating from the legacy tables, as needed) the rewards tables in `db`,
    // which must outlive this object, and loads the newest snapshot.  The tables can share a
    // database with other things, such as the blockchain itself.
    RewardsDB(cryptonote::network_type nettype, session::sqlite::Database& db);
    RewardsDB(const RewardsDB&) = delete;

    session::sqlite::Database& db;

    // Transactions
    // ------------
    // Methods that write to the database while adding or removing blocks take an `active_tx`: the
    // transaction that their writes belong in, if the caller has one open on this database.  It
    // must be open on this thread's shared connection (i.e. the one that `db.conn()` returns), as
    // the blockchain database's write transaction is.  Given nullptr, such a method makes its own
    // transaction, which the caller must then not have one open on that connection.

    // Deletes everything, leaving the rewards empty at `height`, which must be before HF19.
    void reset_database(uint64_t height, SQLite::Transaction* active_tx = nullptr);

    // Whether the rewards can be restored to `height` by blockchain_detached: a height still in
    // memory, one with a stored snapshot, or any height before HF19 (when there are no rewards).
    bool can_restore(uint64_t height) const;

    // Restores the rewards to `height`, which can_restore must accept, deleting the stored
    // snapshots and delayed payments from above it.  Called by the SN list on detach, which picks
    // a height that both of them can restore to.
    void blockchain_detached(uint64_t height, SQLite::Transaction* active_tx = nullptr);

    // Changes for the block being added
    // ---------------------------------
    // These accumulate in a pending copy that only add_block publishes, so that nothing changes if
    // the block fails partway through.  discard_pending discards them: those of a block that failed
    // before reaching add_block, or of an alt block, whose processing makes them too but which isn't
    // added.
    void discard_pending();

    // Credits payments to the specified addresses.  If the payments are rewards set `is_rewards`
    // to true to ensure that rewards are tracked separately; set it to `false` for delayed/exit
    // payments, to separate them from the tracked rewards.
    void add_sn_rewards(hf hf_version, const block_payments& payments, bool is_rewards);

    // Applies the locked and purged stakes to the non-consensus metadata that tracks the lifetime
    // total locked stakes of each ethereum address.
    void submit_stakes_metadata(const service_nodes::block_add_result& block_add);

    // Removes every address's accrued values: the HF21 transition drops the unconverted OXEN
    // balances (which the block before it paid out).
    void clear_accrued_rewards();

    // Applies the subatomic -> atomic value conversion of amount and lifetime_reward values; this
    // must be called once (and only once!) at the HF22 fork height to convert milli-atomic values
    // (for HF21 and earlier blocks) into atomics (expected for HF22+ blocks).
    void convert_hf22();

    // Takes a block that contains new block rewards to be accrued and/or batch payments that were
    // paid out, along with the SN list state that it was processed into, and applies its rewards
    // and payments (and any of the above changes pending from its processing).  This is the
    // primary entry point for the blockchain: each accepted block calls this, after the SN list
    // has processed it, and writes the block's delayed payments (the stakes that its exits return,
    // from `block_add`) and (if due) a snapshot in `active_tx`.
    //
    // On failure (returning false), nothing has changed, in memory or in `active_tx`.
    bool add_block(
            const cryptonote::block& block,
            const service_nodes::service_node_list::state_t& service_nodes_state,
            const service_nodes::block_add_result& block_add,
            const std::optional<service_nodes::rescan_context>& rescan = std::nullopt,
            SQLite::Transaction* active_tx = nullptr);

    // Queries
    // -------

    // Pending delayed payments: of every address, or of one.
    block_payments get_delayed_payments() const;
    block_payments get_delayed_payments(const eth::address& addr) const;

    struct wallet_info {
        uint64_t height = 0;  // Height at which the wallet info was retrieved for

        // True if the wallet has participated in the network or not. When false all values are
        // zeroed (because the wallet has not earnt or spent any tokens on the network).
        bool found = false;

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
        wallet_info(uint64_t height, bool found) : height{height}, found{found} {}
    };

    // See `wallet_info`; the values at the current height.
    wallet_info get_accrued_rewards(const eth::address& address) const;
    wallet_info get_accrued_rewards(const account_public_address& address) const;

    // The values at `at_height`, if it is one of the REWARDS_HISTORY heights up to the current
    // height that are held; nullopt (the values there unknown) if not.  As for the current values,
    // an address without any at a held height has `found` false (an authoritative zero).
    std::optional<wallet_info> get_accrued_rewards(
            const eth::address& address, uint64_t at_height) const;
    std::optional<wallet_info> get_accrued_rewards(
            const account_public_address& address, uint64_t at_height) const;

    // For the thread adding a block: the address's values with the block's changes so far (such
    // as an HF22 fixup's) applied, using the rules of `hf_version` (which the height won't reflect
    // until the block has been added).
    wallet_info pending_accrued_rewards(const eth::address& address, hf hf_version) const;

    // The values of every address with any, at the current height.
    std::vector<std::pair<rewards_address, wallet_info>> get_all_accrued_rewards() const;

    // The accrued rows at the current height, as stored, ordered by address.
    accrued_rows get_accrued_rows() const;

    // Passing a block height will return an array of payments that should be created in a coinbase
    // transaction on that block given the current accrued values.
    std::vector<cryptonote::batch_sn_payment> get_sn_payments(uint64_t block_height) const;

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

    // Checks the database for any needed fixes and applies them, returning an optional detach
    // block number that should be applied to rescan the chain if non-nullopt.  When it returns
    // one, the rewards have already been restored to the newest valid snapshot at or below it.
    //
    // NB: the returned value is the block number of the block that we want to *keep*, that is,
    // after the detach, the "lmdb blockchain height" should be that number plus 1.
    //
    // `recheck` is used to confirm that the fixups worked as expected, after a detach induced by a
    // first call to fixup() that returns a non-nullopt value.  If fixup(recheck=true) returns
    // nullopt then all is good; if it returns a value then that means the rescan did *not* resolve
    // the problem it was supposed to resolve!  (The actual value returned by such a failed recheck
    // call is meaningless).
    std::optional<uint64_t> fixup(bool recheck = false, SQLite::Transaction* active_tx = nullptr);

    // The height that the rewards are at.  Only for the thread adding blocks: other threads get the
    // height of the values they query from the wallet_info.
    uint64_t height = 0;
    const cryptonote::network_type nettype;

    // How much history the blockchain database keeps (see BlockchainDB::history()).  When it is
    // limited, the snapshots are kept across the whole of it (so that the rewards can be restored
    // to anywhere in it, as the SN list can) rather than just the newest few, and none are
    // archived (as the blocks to replay from an archived snapshot aren't kept).
    uint64_t kept_history = 0;

  protected:
    // Makes this a copy of `other`'s in-memory state (as the core tests' chain generator copies
    // its rewards along with its chain).
    void copy_state_from(const RewardsDB& other);

    // The last step of add_block: applies the pending changes as the next height, writing its
    // delayed payments and (if due) a snapshot in `active_tx`.  Throws, having changed nothing, on
    // failure.
    void publish_block(
            const std::optional<service_nodes::rescan_context>& rescan = std::nullopt,
            SQLite::Transaction* active_tx = nullptr);

    // Subtracts the block's batch payments (checked against the accrued values) from the accrued
    // values, as pending changes.
    bool save_payments(uint64_t block_height, std::span<const batch_sn_payment> paid_amounts);

    // Adds the stakes returned by the exits of the block being added, at `at_height`, as pending
    // delayed payments.
    void add_delayed_payments(
            std::span<const service_nodes::delayed_stake> stakes, uint64_t at_height);

  private:
    struct pending_block {
        accrued_changes accrued;
        std::vector<delayed_payment> delayed;
    };

    // In-memory state, which `mutex` guards
    accrued_history history;
    // The delayed payments still to pay out at some height of `history`.
    std::vector<delayed_payment> delayed;
    mutable std::shared_mutex mutex;

    // The changes of the block being added; only the block thread uses it.
    std::optional<pending_block> pending;

    std::pair<hf, cryptonote::address_parse_info> parsed_governance_addr = {hf::none, {}};

    // The first block that accrues rewards.  (Looked up as needed, rather than at construction,
    // because the hard forks of a FAKECHAIN aren't set until the blockchain is initialized.)
    uint64_t hf19_height() const;

    // The pending value of `addr`, if it has one, after the changes so far.
    std::optional<accrued_row> pending_lookup(const rewards_address& addr) const;
    // The pending row of `addr`, created (zeroed, with `payout_offset`) if it has none.
    accrued_row& pending_row(
            const rewards_address& addr, std::optional<int32_t> payout_offset = std::nullopt);
    // Applies `f` to (a pending copy of) every row, removing those that it returns false for.
    void update_pending_rows(const std::function<bool(accrued_row&)>& f);

    // Delayed payments due at `payout_height`
    block_payments delayed_payments_due(uint64_t payout_height) const;

    void reward_handler(
            const cryptonote::block& block,
            const service_nodes::service_node_list::state_t& service_nodes_state,
            const service_nodes::block_add_result& block_add);

    // Checks the block's batch payments against the accrued values, and subtracts them.
    bool validate_batch_payment(
            const std::vector<std::pair<crypto::public_key, uint64_t>>& miner_tx_vouts,
            const std::vector<cryptonote::batch_sn_payment>& calculated_payments,
            uint64_t block_height,
            const std::optional<service_nodes::rescan_context>& rescan);

    // Whether a snapshot is to be written at `height`.
    bool wants_snapshot(
            uint64_t height, const std::optional<service_nodes::rescan_context>& rescan) const;
    void write_snapshot(session::sqlite::Connection& conn, uint64_t height);

    // Replaces the in-memory state with the stored snapshot at `height` (or the empty state, before
    // HF19), deleting the stored snapshots and delayed payments from above it.
    void load_stored(session::sqlite::Connection& conn, uint64_t height);

    // Deletes everything stored, leaving the rewards empty at `height`.
    void reset_to(session::sqlite::Connection& conn, uint64_t height);

    wallet_info current_wallet_info(const rewards_address& address) const;
    std::optional<wallet_info> wallet_info_at(
            const rewards_address& address, uint64_t at_height) const;

    wallet_info make_wallet_info(
            uint64_t at_height,
            const rewards_address& addr,
            const std::optional<accrued_row>& row,
            std::optional<hf> hf_version = std::nullopt) const;
};

}  // namespace cryptonote
