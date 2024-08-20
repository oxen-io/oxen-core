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

#include "blockchain.h"

#include <fmt/color.h>
#include <fmt/core.h>
#include <fmt/std.h>
#include <oxenc/endian.h>
#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <limits>
#include <stdexcept>

#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/sqlite/db_sqlite.h"
#include "common/boost_serialization_helper.h"
#include "common/exception.h"
#include "common/guts.h"
#include "common/lock.h"
#include "common/median.h"
#include "common/pruning.h"
#include "common/rules.h"
#include "common/sha256sum.h"
#include "common/string_util.h"
#include "common/threadpool.h"
#include "common/varint.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_basic/miner.h"
#include "cryptonote_config.h"
#include "cryptonote_core.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "epee/int-util.h"
#include "epee/warnings.h"
#include "ethereum_transactions.h"
#include "l2_tracker/events.h"
#include "logging/oxen_logger.h"
#include "oxen/log.hpp"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"
#include "service_node_list.h"
#include "service_node_voting.h"
#include "tx_pool.h"

#ifdef ENABLE_SYSTEMD
extern "C" {
#include <systemd/sd-daemon.h>
}
#endif

#define FIND_BLOCKCHAIN_SUPPLEMENT_MAX_SIZE (100 * 1024 * 1024)  // 100 MB

using namespace crypto;

// #include "serialization/json_archive.h"

/* TODO:
 *  Clean up code:
 *    Possibly change how outputs are referred to/indexed in blockchain and wallets
 *
 */

using namespace cryptonote;

static auto logcat = log::Cat("blockchain");

DISABLE_VS_WARNINGS(4267)

// used to overestimate the block reward when estimating a per kB to use
#define BLOCK_REWARD_OVERESTIMATE (10 * 1000000000000)

Blockchain::block_extended_info::block_extended_info(
        const alt_block_data_t& src, block const& blk, checkpoint_t const* checkpoint) {
    assert((src.checkpointed) == (checkpoint != nullptr));
    *this = {};
    this->bl = blk;
    this->checkpointed = src.checkpointed;
    if (checkpoint)
        this->checkpoint = *checkpoint;
    this->height = src.height;
    this->block_cumulative_weight = src.cumulative_weight;
    this->cumulative_difficulty = src.cumulative_difficulty;
    this->already_generated_coins = src.already_generated_coins;
}

//------------------------------------------------------------------
Blockchain::Blockchain(
        tx_memory_pool& tx_pool, service_nodes::service_node_list& service_node_list) :
        m_db(),
        tx_pool{tx_pool},
        service_node_list(service_node_list),
        m_current_block_cumul_weight_limit(0),
        m_current_block_cumul_weight_median(0),
        m_db_sync_mode(db_async),
        m_fast_sync(true),
        m_show_time_stats(false),
        m_db_default_sync(false),
        m_db_sync_on_blocks(true),
        m_db_sync_threshold(1),
        m_max_prepare_blocks_threads(4),
        m_sync_counter(0),
        m_bytes_to_sync(0),
        m_long_term_block_weights_window(LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE),
        m_long_term_effective_median_block_weight(0),
        m_long_term_block_weights_cache_tip_hash{},
        m_long_term_block_weights_cache_rolling_median(LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE),
        m_cancel(false),
        m_btc_valid(false),
        m_batch_success(true),
        m_prepare_height(0) {
    log::trace(logcat, "Blockchain::{}", __func__);
}
//------------------------------------------------------------------
Blockchain::~Blockchain() {
    try {
        deinit();
    } catch (const std::exception& e) { /* ignore */
    }
}
//------------------------------------------------------------------
bool Blockchain::have_tx(const crypto::hash& id) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
    // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
    // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
    // lock if it is otherwise needed.
    return m_db->tx_exists(id);
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimg_as_spent(const crypto::key_image& key_im) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
    // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
    // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
    // lock if it is otherwise needed.
    return m_db->has_key_image(key_im);
}
//------------------------------------------------------------------
// This function makes sure that each "input" in an input (mixins) exists
// and collects the public key for each from the transaction it was included in
// via the visitor passed to it.
template <class visitor_t>
bool Blockchain::scan_outputkeys_for_indexes(
        const txin_to_key& tx_in_to_key,
        visitor_t& vis,
        const crypto::hash& tx_prefix_hash,
        uint64_t* pmax_related_block_height) const {
    log::trace(logcat, "Blockchain::{}", __func__);

    // ND: Disable locking and make method private.
    // std::unique_lock lock{*this};

    // verify that the input has key offsets (that it exists properly, really)
    if (!tx_in_to_key.key_offsets.size())
        return false;

    // cryptonote_format_utils uses relative offsets for indexing to the global
    // outputs list.  that is to say that absolute offset #2 is absolute offset
    // #1 plus relative offset #2.
    // TODO: Investigate if this is necessary / why this is done.
    std::vector<uint64_t> absolute_offsets =
            relative_output_offsets_to_absolute(tx_in_to_key.key_offsets);
    std::vector<output_data_t> outputs;

    bool found = false;
    auto it = m_scan_table.find(tx_prefix_hash);
    if (it != m_scan_table.end()) {
        auto its = it->second.find(tx_in_to_key.k_image);
        if (its != it->second.end()) {
            outputs = its->second;
            found = true;
        }
    }

    if (!found) {
        try {
            m_db->get_output_key(
                    epee::span<const uint64_t>(&tx_in_to_key.amount, 1),
                    absolute_offsets,
                    outputs,
                    true);
            if (absolute_offsets.size() != outputs.size()) {
                log::error(
                        log::Cat("verify"),
                        "Output does not exist! amount = {}",
                        tx_in_to_key.amount);
                return false;
            }
        } catch (...) {
            log::error(
                    log::Cat("verify"), "Output does not exist! amount = {}", tx_in_to_key.amount);
            return false;
        }
    } else {
        // check for partial results and add the rest if needed;
        if (outputs.size() < absolute_offsets.size() && outputs.size() > 0) {
            log::debug(
                    logcat,
                    "Additional outputs needed: {}",
                    absolute_offsets.size() - outputs.size());
            std::vector<uint64_t> add_offsets;
            std::vector<output_data_t> add_outputs;
            add_outputs.reserve(absolute_offsets.size() - outputs.size());
            for (size_t i = outputs.size(); i < absolute_offsets.size(); i++)
                add_offsets.push_back(absolute_offsets[i]);
            try {
                m_db->get_output_key(
                        epee::span<const uint64_t>(&tx_in_to_key.amount, 1),
                        add_offsets,
                        add_outputs,
                        true);
                if (add_offsets.size() != add_outputs.size()) {
                    log::error(
                            log::Cat("verify"),
                            "Output does not exist! amount = {}",
                            tx_in_to_key.amount);
                    return false;
                }
            } catch (...) {
                log::error(
                        log::Cat("verify"),
                        "Output does not exist! amount = {}",
                        tx_in_to_key.amount);
                return false;
            }
            outputs.insert(outputs.end(), add_outputs.begin(), add_outputs.end());
        }
    }

    size_t count = 0;
    for (const uint64_t& i : absolute_offsets) {
        try {
            output_data_t output_index;
            try {
                // get tx hash and output index for output
                if (count < outputs.size())
                    output_index = outputs.at(count);
                else
                    output_index = m_db->get_output_key(tx_in_to_key.amount, i);

                // call to the passed boost visitor to grab the public key for the output
                if (!vis.handle_output(
                            output_index.unlock_time,
                            output_index.pubkey,
                            output_index.commitment)) {
                    log::error(
                            log::Cat("verify"),
                            "Failed to handle_output for output no = {}, with absolute offset {}",
                            count,
                            i);
                    return false;
                }
            } catch (...) {
                log::error(
                        log::Cat("verify"),
                        "Output does not exist! amount = {}, absolute_offset = {}",
                        tx_in_to_key.amount,
                        i);
                return false;
            }

            // if on last output and pmax_related_block_height not null pointer
            if (++count == absolute_offsets.size() && pmax_related_block_height) {
                // set *pmax_related_block_height to tx block height for this output
                auto h = output_index.height;
                if (*pmax_related_block_height < h) {
                    *pmax_related_block_height = h;
                }
            }

        } catch (const OUTPUT_DNE& e) {
            log::error(log::Cat("verify"), "Output does not exist: {}", e.what());
            return false;
        } catch (const TX_DNE& e) {
            log::error(log::Cat("verify"), "Transaction does not exist: {}", e.what());
            return false;
        }
    }

    return true;
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_blockchain_height(bool lock) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
    // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
    // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
    // lock if it is otherwise needed or set lock to true.
    std::unique_lock lock_{*this, std::defer_lock};
    if (lock)
        lock_.lock();
    return m_db->height();
}
//------------------------------------------------------------------
bool Blockchain::load_missing_blocks_into_oxen_subsystems(const std::atomic<bool>* abort) {
    std::vector<uint64_t> start_height_options;
    uint64_t snl_height = std::max(
            hard_fork_begins(m_nettype, hf::hf9_service_nodes).value_or(0),
            service_node_list.height() + 1);
    uint64_t const ons_height =
            std::max(hard_fork_begins(m_nettype, hf::hf15_ons).value_or(0), m_ons_db.height() + 1);
    start_height_options.push_back(ons_height);
    uint64_t sqlite_height = 0;
    if (m_sqlite_db) {
        sqlite_height = std::max(
                hard_fork_begins(m_nettype, hf::hf19_reward_batching).value_or(0) - 1,
                m_sqlite_db->height + 1);
        start_height_options.push_back(sqlite_height);
    } else {
        if (m_nettype != network_type::FAKECHAIN)
            throw oxen::traced<std::logic_error>("Blockchain missing SQLite Database");
    }
    // If the batching database falls behind it NEEDS the service node list information at that
    // point in time
    if (sqlite_height < snl_height) {
        service_node_list.blockchain_detached(sqlite_height);
        snl_height = std::min(sqlite_height, service_node_list.height()) + 1;
    }
    start_height_options.push_back(snl_height);
    uint64_t const end_height = m_db->height();
    start_height_options.push_back(end_height);
    uint64_t const start_height =
            *std::min_element(start_height_options.begin(), start_height_options.end());

    int64_t const total_blocks =
            static_cast<int64_t>(end_height) - static_cast<int64_t>(start_height);
    if (total_blocks <= 0)
        return true;
    if (total_blocks > 1)
        log::info(
                globallogcat,
                "Loading blocks into oxen subsystems, scanning blockchain from height: {} to: {} "
                "(snl: {}, ons: {}, sqlite: {})",
                start_height,
                end_height,
                snl_height,
                ons_height,
                sqlite_height);

    using clock = std::chrono::steady_clock;
    using dseconds = std::chrono::duration<double>;
    int64_t constexpr BLOCK_COUNT = 100;
    auto work_start = clock::now();
    auto scan_start = work_start;
    dseconds ons_duration{}, snl_duration{}, sqlite_duration{}, ons_iteration_duration{},
            snl_iteration_duration{}, sqlite_iteration_duration{};

    for (int64_t block_count = total_blocks, index = 0; block_count > 0;
         block_count -= BLOCK_COUNT, index++) {
        if (abort && *abort)
            return false;
        auto duration = dseconds{clock::now() - work_start};
        if (block_count == total_blocks || duration >= 10s) {
            service_node_list.store();
            log::info(
                    globallogcat,
                    "... scanning height {} ({:.3f}s) (snl: {:.3f}s, ons: {:.3f}s, batch: {:.3f}s)",
                    start_height + (index * BLOCK_COUNT),
                    duration.count(),
                    snl_iteration_duration.count(),
                    ons_iteration_duration.count(),
                    sqlite_iteration_duration.count());
#ifdef ENABLE_SYSTEMD
            // Tell systemd that we're doing something so that it should let us continue starting up
            // (giving us 120s until we have to send the next notification):
            sd_notify(
                    0,
                    "EXTEND_TIMEOUT_USEC=120000000\nSTATUS=Recanning blockchain; height {}"_format(
                            start_height + (index * BLOCK_COUNT))
                            .c_str());
#endif
            work_start = clock::now();

            ons_duration += ons_iteration_duration;
            snl_duration += snl_iteration_duration;
            sqlite_duration += sqlite_iteration_duration;
            ons_iteration_duration = 0s;
            snl_iteration_duration = 0s;
            sqlite_iteration_duration = 0s;
        }

        std::vector<cryptonote::block> blocks;
        uint64_t height = start_height + (index * BLOCK_COUNT);
        if (!get_blocks(height, static_cast<uint64_t>(BLOCK_COUNT), blocks)) {
            log::error(
                    logcat,
                    "Unable to get checkpointed historical blocks for updating oxen subsystems");
            return false;
        }

        for (cryptonote::block const& blk : blocks) {
            uint64_t block_height = blk.get_height();

            std::vector<cryptonote::transaction> txs;
            if (!get_transactions(blk.tx_hashes, txs)) {
                log::error(
                        logcat,
                        "Unable to get transactions for block for updating ONS DB: {}",
                        cryptonote::get_block_hash(blk));
                return false;
            }

            if (block_height >= snl_height) {
                auto snl_start = clock::now();

                checkpoint_t* checkpoint_ptr = nullptr;
                checkpoint_t checkpoint;
                if (blk.major_version >= hf::hf13_enforce_checkpoints &&
                    get_checkpoint(block_height, checkpoint))
                    checkpoint_ptr = &checkpoint;

                try {
                    // We skip verification here because the fact that this block is already in the
                    // lmdb means it has already been verified:
                    constexpr bool skip_verify = true;
                    service_node_list.block_add(blk, txs, checkpoint_ptr, skip_verify);
                } catch (const std::exception& e) {
                    log::error(
                            logcat,
                            "Unable to process block for updating service node list: {}",
                            e.what());
                    return false;
                }
                snl_iteration_duration += clock::now() - snl_start;
            }

            if (m_ons_db.db && (block_height >= ons_height)) {
                auto ons_start = clock::now();
                if (!m_ons_db.add_block(blk, txs)) {
                    log::error(
                            logcat,
                            "Unable to process block for updating ONS DB: {}",
                            cryptonote::get_block_hash(blk));
                    return false;
                }
                ons_iteration_duration += clock::now() - ons_start;
            }

            if (m_sqlite_db && (block_height >= sqlite_height)) {
                auto sqlite_start = clock::now();
                if (!service_node_list.process_batching_rewards(blk)) {
                    log::error(
                            logcat,
                            "Unable to process block for updating SQLite DB: {}",
                            cryptonote::get_block_hash(blk));
                    return false;
                }
                sqlite_iteration_duration += clock::now() - sqlite_start;
            }
        }
    }

    if (total_blocks > 1) {
        log::info(
                globallogcat,
                "Done recalculating oxen subsystems in {:.2f}s ({:.2f}s snl; {:.2f}s ons; {:.2f}s "
                "batch)",
                dseconds{clock::now() - scan_start}.count(),
                snl_duration.count(),
                ons_duration.count(),
                sqlite_duration.count());
    }

    if (total_blocks > 0)
        service_node_list.store();

    return true;
}
//------------------------------------------------------------------
// FIXME: possibly move this into the constructor, to avoid accidentally
//       dereferencing a null BlockchainDB pointer
//
// FIXME TODO: the number of things we take here seems sort of silly: we could just be holding a
// reference to the `core` that owns us and get most of thoese through that.
bool Blockchain::init(
        std::unique_ptr<BlockchainDB> db,
        const network_type nettype,
        sqlite3* ons_db,
        cryptonote::BlockchainSQLite* sqlite_db,
        eth::L2Tracker* l2_tracker,
        bool offline,
        const cryptonote::test_options* test_options,
        difficulty_type fixed_difficulty,
        const GetCheckpointsCallback& get_checkpoints /* = nullptr*/,
        const std::atomic<bool>* abort)

{
    log::trace(logcat, "Blockchain::{}", __func__);

    CHECK_AND_ASSERT_MES(
            nettype != network_type::FAKECHAIN || test_options,
            false,
            "fakechain network initialization cannot be used without test options");

    CHECK_AND_ASSERT_MES(
            nettype == network_type::FAKECHAIN || !test_options,
            false,
            "non-fakechain network initialization cannot use test options");

    auto lock = tools::unique_locks(tx_pool, *this);

    if (!db) {
        log::error(logcat, "Attempted to init Blockchain with null DB");
        return false;
    }
    if (!db->is_open()) {
        log::error(logcat, "Attempted to init Blockchain with unopened DB");
        db->reset();
        return false;
    }

    m_db = std::move(db);

    m_nettype = test_options != NULL ? network_type::FAKECHAIN : nettype;

    if (!m_checkpoints.init(m_nettype, m_db.get()))
        throw oxen::traced<std::runtime_error>("Failed to initialize checkpoints");

    m_l2_tracker = l2_tracker;

    m_offline = offline;
    m_fixed_difficulty = fixed_difficulty;

    if (test_options)  // Fakechain mode
        fakechain_hardforks = test_options->hard_forks;
    if (sqlite_db) {
        m_sqlite_db.reset(sqlite_db);
    } else {
        if (m_nettype != network_type::FAKECHAIN)
            throw oxen::traced<std::logic_error>("Blockchain missing SQLite Database");
    }

    // if the blockchain is new, add the genesis block
    // this feels kinda kludgy to do it this way, but can be looked at later.
    // TODO: add function to create and store genesis block,
    //       taking testnet into account
    if (!m_db->height()) {
        log::info(logcat, "Blockchain not loaded, generating genesis block.");
        block bl;
        block_verification_context bvc{};
        generate_genesis_block(bl, m_nettype);
        db_wtxn_guard wtxn_guard{*m_db};
        add_new_block(bl, bvc, nullptr /*checkpoint*/);
        CHECK_AND_ASSERT_MES(
                !bvc.m_verifivation_failed, false, "Failed to add genesis block to blockchain");
    }
    // TODO: if blockchain load successful, verify blockchain against both
    //       hard-coded and runtime-loaded (and enforced) checkpoints.
    else {
    }

    if (m_nettype != network_type::FAKECHAIN)
        m_db->fixup(m_nettype);

    db_rtxn_guard rtxn_guard{*m_db};

    // check how far behind we are
    uint64_t top_block_timestamp = m_db->get_top_block_timestamp();
    // genesis block has no timestamp, so use block 1's timestamp if we get that:
    if (!top_block_timestamp)
        top_block_timestamp = 1525306361;

    // create general purpose async service queue

    m_async_work_idle = std::unique_ptr<boost::asio::io_service::work>(
            new boost::asio::io_service::work(m_async_service));
    m_async_thread = std::thread{[this] { m_async_service.run(); }};

#if defined(PER_BLOCK_CHECKPOINT)
    if (m_nettype != network_type::FAKECHAIN)
        load_compiled_in_block_hashes(get_checkpoints);
#endif

    log::info(
            logcat,
            "Blockchain initialized. last block: {}, {} time ago",
            m_db->height() - 1,
            tools::friendly_duration(
                    std::chrono::system_clock::now() -
                    std::chrono::system_clock::from_time_t(top_block_timestamp)));
    rtxn_guard.stop();

    uint64_t num_popped_blocks = 0;
    while (!m_db->is_read_only()) {
        if (abort && *abort)
            return false;
        uint64_t top_height;
        const crypto::hash top_id = m_db->top_block_hash(&top_height);
        const block top_block = m_db->get_top_block();
        const auto ideal_hf_version = get_network_version(top_height);
        if (ideal_hf_version < hf::hf7 || ideal_hf_version == top_block.major_version) {
            if (num_popped_blocks > 0)
                log::info(
                        globallogcat,
                        "Initial popping done, top block: {}, top height: {}, block version: {}",
                        top_id,
                        top_height,
                        (uint64_t)top_block.major_version);
            break;
        } else {
            if (num_popped_blocks == 0)
                log::info(
                        globallogcat,
                        "Current top block {} at height {} has version {} which disagrees with the "
                        "ideal version {}",
                        top_id,
                        top_height,
                        (uint64_t)top_block.major_version,
                        (uint64_t)ideal_hf_version);
            if (num_popped_blocks % 100 == 0)
                log::info(globallogcat, "Popping blocks... {}", top_height);
            ++num_popped_blocks;
            block popped_block;
            std::vector<transaction> popped_txs;
            try {
                m_db->pop_block(popped_block, popped_txs);
                if (!service_node_list.pop_batching_rewards_block(popped_block)) {
                    log::error(logcat, "Failed to pop to batch rewards DB. throwing");
                    throw oxen::traced<std::runtime_error>("Failed to pop to batch reward DB.");
                }
            }
            // anything that could cause this to throw is likely catastrophic,
            // so we re-throw
            catch (const std::exception& e) {
                log::error(logcat, "Error popping block from blockchain: {}", e.what());
                throw;
            } catch (...) {
                log::error(logcat, "Error popping block from blockchain, throwing!");
                throw;
            }
        }
    }
    if (num_popped_blocks > 0) {
        m_cache.m_timestamps_and_difficulties_height = 0;
        tx_pool.on_blockchain_dec();
    }

    if (test_options && test_options->long_term_block_weight_window) {
        m_long_term_block_weights_window = test_options->long_term_block_weight_window;
        m_long_term_block_weights_cache_rolling_median =
                epee::misc_utils::rolling_median_t<uint64_t>(m_long_term_block_weights_window);
    }

    {
        db_txn_guard txn_guard{*m_db, m_db->is_read_only()};
        if (!update_next_cumulative_weight_limit())
            return false;
    }

    if (ons_db && !m_ons_db.init(this, nettype, ons_db)) {
        log::error(logcat, "ONS failed to initialise");
        return false;
    }

    hook_block_add([this](const auto& info) { m_checkpoints.block_add(info); });
    hook_blockchain_detached(
            [this](const auto& info) { m_checkpoints.blockchain_detached(info.height); });
    for (const auto& hook : m_init_hooks)
        hook();

    if (!m_db->is_read_only() && !load_missing_blocks_into_oxen_subsystems(abort)) {
        log::error(logcat, "Failed to load blocks into oxen subsystems");
        return false;
    }

    return true;
}
//------------------------------------------------------------------
bool Blockchain::store_blockchain() {
    log::trace(logcat, "Blockchain::{}", __func__);
    // lock because the rpc_thread command handler also calls this
    std::unique_lock lock{*m_db};

    auto save = std::chrono::steady_clock::now();
    // TODO: make sure sync(if this throws that it is not simply ignored higher
    // up the call stack
    try {
        m_db->sync();
    } catch (const std::exception& e) {
        log::error(
                logcat,
                "Error syncing blockchain db: {}; shutting down now to prevent issues!",
                e.what());
        throw;
    } catch (...) {
        log::error(
                logcat,
                "There was an issue storing the blockchain, shutting down now to prevent issues!");
        throw;
    }

    if (m_show_time_stats)
        log::info(
                logcat,
                "Blockchain stored OK, took: {}",
                tools::friendly_duration(std::chrono::steady_clock::now() - save));
    return true;
}
//------------------------------------------------------------------
bool Blockchain::deinit() {
    log::trace(logcat, "Blockchain::{}", __func__);

    log::trace(logcat, "Stopping blockchain read/write activity");

    // stop async service
    m_async_work_idle.reset();
    m_async_thread.join();
    m_async_service.stop();

    // as this should be called if handling a SIGSEGV, need to check
    // if m_db is a NULL pointer (and thus may have caused the illegal
    // memory operation), otherwise we may cause a loop.
    try {
        if (m_db) {
            m_db->close();
            log::trace(logcat, "Local blockchain read/write activity stopped successfully");
        }
    } catch (const std::exception& e) {
        log::error(logcat, "Error closing blockchain db: {}", e.what());
    } catch (...) {
        log::error(
                logcat,
                "There was an issue closing/storing the blockchain, shutting down now to prevent "
                "issues!");
    }

    m_db.reset();
    return true;
}
//------------------------------------------------------------------
// This function removes blocks from the top of blockchain.
// It starts a batch and calls private method pop_block_from_blockchain().
void Blockchain::pop_blocks(uint64_t nblocks) {
    uint64_t i = 0;
    auto lock = tools::unique_locks(tx_pool, *this);
    bool stop_batch = m_db->batch_start();

    bool pop_batching_rewards;
    try {
        const uint64_t blockchain_height = m_db->height();
        if (blockchain_height > 0)
            nblocks = std::min(nblocks, blockchain_height - 1);

        uint64_t constexpr PERCENT_PER_PROGRESS_UPDATE = 10;
        uint64_t const blocks_per_update = (nblocks / PERCENT_PER_PROGRESS_UPDATE);

        pop_batching_rewards = service_node_list.state_history_exists(blockchain_height - nblocks);
        std::chrono::steady_clock::time_point pop_blocks_started = std::chrono::steady_clock::now();
        uint64_t bpd = get_config(m_nettype).BLOCKS_PER_DAY();
        for (int progress = 0; i < nblocks; ++i) {
            if (nblocks >= bpd && (i != 0 && (i % blocks_per_update == 0))) {
                log::info(
                        globallogcat,
                        "... popping blocks {}% completed, height: {} ({}s)",
                        (++progress * PERCENT_PER_PROGRESS_UPDATE),
                        (blockchain_height - i),
                        std::chrono::duration<double>{
                                std::chrono::steady_clock::now() - pop_blocks_started}
                                .count());
                pop_blocks_started = std::chrono::steady_clock::now();
            }
            pop_block_from_blockchain(pop_batching_rewards);
        }
    } catch (const std::exception& e) {
        log::error(logcat, "Error when popping blocks after processing {} blocks: {}", i, e.what());
        if (stop_batch)
            m_db->batch_abort();
        return;
    }

    detached_info hook_data{m_db->height(), /*by_pop_blocks=*/true};
    for (const auto& hook : m_blockchain_detached_hooks)
        hook(hook_data);
    load_missing_blocks_into_oxen_subsystems();

    if (stop_batch)
        m_db->batch_stop();
}
//------------------------------------------------------------------
// This function tells BlockchainDB to remove the top block from the
// blockchain and then returns all transactions (except the miner tx, of course)
// from it to the tx_pool
block Blockchain::pop_block_from_blockchain(bool pop_batching_rewards = true) {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    m_cache.m_timestamps_and_difficulties_height = 0;

    block popped_block;
    std::vector<transaction> popped_txs;

    CHECK_AND_ASSERT_THROW_MES(m_db->height() > 1, "Cannot pop the genesis block");

    try {
        m_db->pop_block(popped_block, popped_txs);
    }
    // anything that could cause this to throw is likely catastrophic,
    // so we re-throw
    catch (const std::exception& e) {
        log::error(logcat, "Error popping block from blockchain: {}", e.what());
        throw;
    } catch (...) {
        log::error(logcat, "Error popping block from blockchain, throwing!");
        throw;
    }

    if (pop_batching_rewards && !service_node_list.pop_batching_rewards_block(popped_block)) {
        log::error(logcat, "Failed to pop to batch rewards DB");
        throw oxen::traced<std::runtime_error>("Failed to pop batch rewards DB");
    }

    m_ons_db.block_detach(*this, m_db->height());

    // return transactions from popped block to the tx_pool
    size_t pruned = 0;
    for (transaction& tx : popped_txs) {
        if (tx.pruned) {
            ++pruned;
            continue;
        }
        if (!tx.is_miner_tx()) {
            cryptonote::tx_verification_context tvc{};

            auto version = get_network_version(m_db->height());

            // We assume that if they were in a block, the transactions are already
            // known to the network as a whole. However, if we had mined that block,
            // that might not be always true. Unlikely though, and always relaying
            // these again might cause a spike of traffic as many nodes re-relay
            // all the transactions in a popped block when a reorg happens.
            bool r = tx_pool.add_tx(tx, tvc, tx_pool_options::from_block(), version);
            if (!r) {
                log::error(logcat, "Error returning transaction to tx_pool");
            }
        }
    }
    if (pruned)
        log::warning(logcat, "{} pruned txes could not be added back to the txpool", pruned);

    m_blocks_longhash_table.clear();
    m_scan_table.clear();
    m_blocks_txs_check.clear();

    CHECK_AND_ASSERT_THROW_MES(
            update_next_cumulative_weight_limit(), "Error updating next cumulative weight limit");
    tx_pool.on_blockchain_dec();
    invalidate_block_template_cache();
    return popped_block;
}
//------------------------------------------------------------------
bool Blockchain::reset_and_set_genesis_block(const block& b) {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};
    m_cache.m_timestamps_and_difficulties_height = 0;
    invalidate_block_template_cache();
    m_db->reset();
    m_db->drop_alt_blocks();

    for (const auto& hook : m_init_hooks)
        hook();

    db_wtxn_guard wtxn_guard{*m_db};
    block_verification_context bvc{};
    add_new_block(b, bvc, nullptr /*checkpoint*/);
    if (!update_next_cumulative_weight_limit())
        return false;
    return bvc.m_added_to_main_chain && !bvc.m_verifivation_failed;
}
//------------------------------------------------------------------
std::pair<uint64_t, crypto::hash> Blockchain::get_tail_id() const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::pair<uint64_t, crypto::hash> result;
    std::unique_lock lock{*this};
    result.second = m_db->top_block_hash(&result.first);
    return result;
}
//------------------------------------------------------------------
/* Builds a list of block hashes representing certain blocks from the blockchain in reverse
 * chronological order; used when synchronizing to verify that a peer's chain matches ours.
 *
 * The blocks chosen for height H, are:
 *   - the most recent 11 (H-1, H-2, ..., H-10, H-11)
 *   - base-2 exponential drop off from there, so: H-13, H-17, H-25, etc... (going down to, at
 * smallest, height 1)
 *   - the genesis block (height 0)
 */
void Blockchain::get_short_chain_history(std::list<crypto::hash>& ids) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};
    uint64_t sz = m_db->height();
    if (!sz)
        return;

    db_rtxn_guard rtxn_guard{*m_db};
    for (uint64_t i = 0, decr = 1, offset = 1; offset < sz; ++i) {
        ids.push_back(m_db->get_block_hash_from_height(sz - offset));
        if (i >= 10)
            decr *= 2;
        offset += decr;
    }
    ids.push_back(m_db->get_block_hash_from_height(0));
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_block_id_by_height(uint64_t height) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
    // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
    // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
    // lock if it is otherwise needed.
    try {
        return m_db->get_block_hash_from_height(height);
    } catch (const BLOCK_DNE& e) {
    } catch (const std::exception& e) {
        log::error(logcat, "Something went wrong fetching block hash by height: {}", e.what());
        throw;
    } catch (...) {
        log::error(logcat, "Something went wrong fetching block hash by height");
        throw;
    }
    return null<hash>;
}
//------------------------------------------------------------------
crypto::hash Blockchain::get_pending_block_id_by_height(uint64_t height) const {
    if (m_prepare_height && height >= m_prepare_height &&
        height - m_prepare_height < m_prepare_nblocks)
        return (*m_prepare_blocks)[height - m_prepare_height].hash;
    return get_block_id_by_height(height);
}
//------------------------------------------------------------------
bool Blockchain::get_block_by_hash(
        const crypto::hash& h, block& blk, size_t* size, bool* orphan) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    // try to find block in main chain
    try {
        blk = m_db->get_block(h, size);
        if (orphan)
            *orphan = false;
        return true;
    }
    // try to find block in alternative chain
    catch (const BLOCK_DNE& e) {
        alt_block_data_t data;
        std::string blob;
        if (m_db->get_alt_block(h, &data, &blob, nullptr /*checkpoint*/)) {
            if (!cryptonote::parse_and_validate_block_from_blob(blob, blk)) {
                log::error(logcat, "Found block {} in alt chain, but failed to parse it", h);
                throw oxen::traced<std::runtime_error>(
                        "Found block in alt chain, but failed to parse it");
            }
            if (size)
                *size = blob.size();
            if (orphan)
                *orphan = true;
            return true;
        }
    } catch (const std::exception& e) {
        log::error(logcat, "Something went wrong fetching block by hash: {}", e.what());
        throw;
    } catch (...) {
        log::error(logcat, "Something went wrong fetching block hash by hash");
        throw;
    }

    return false;
}
//------------------------------------------------------------------
bool Blockchain::get_block_by_height(uint64_t height, block& blk, size_t* size) const {
    try {
        blk = m_db->get_block_from_height(height, size);
        return true;
    } catch (const BLOCK_DNE& e) {
    }
    return false;
}
//------------------------------------------------------------------
// This function aggregates the cumulative difficulties and timestamps of the
// last DIFFICULTY_WINDOW blocks and passes them to next_difficulty,
// returning the result of that call.  Ignores the genesis block, and can use
// less blocks than desired if there aren't enough.
difficulty_type Blockchain::get_difficulty_for_next_block(bool pulse) {
    log::trace(logcat, "Blockchain::{}", __func__);
    if (m_fixed_difficulty) {
        return m_db->height() ? m_fixed_difficulty : 1;
    }

    // All blocks generated by a Quorum in Pulse have difficulty fixed to
    // 1'000'000 such that, when we have to fallback to PoW difficulty is
    // a reasonable value to allow continuing the network onwards.
    if (pulse) {
        if (m_nettype == network_type::DEVNET || m_nettype == network_type::LOCALDEV ||
            m_nettype == network_type::STAGENET)
            return std::min(PULSE_FIXED_DIFFICULTY, DEVNET_DIFF_CAP);
        return PULSE_FIXED_DIFFICULTY;
    }

    crypto::hash top_hash = m_db->top_block_hash();
    {
        std::unique_lock diff_lock{m_cache.m_difficulty_lock};
        // we can call this without the blockchain lock, it might just give us
        // something a bit out of date, but that's fine since anything which
        // requires the blockchain lock will have acquired it in the first place,
        // and it will be unlocked only when called from the getinfo RPC
        if (top_hash == m_cache.m_difficulty_for_next_block_top_hash)
            return m_cache.m_difficulty_for_next_miner_block;
    }

    std::unique_lock lock{*this};
    uint64_t top_block_height;
    std::tie(top_block_height, top_hash) = get_tail_id();  // get it again now that we have the lock
    uint64_t chain_height = top_block_height + 1;

    m_db->fill_timestamps_and_difficulties_for_pow(
            m_nettype,
            m_cache.m_timestamps,
            m_cache.m_difficulties,
            chain_height,
            m_cache.m_timestamps_and_difficulties_height);
    uint64_t diff = next_difficulty_v2(
            m_cache.m_timestamps,
            m_cache.m_difficulties,
            tools::to_seconds(get_config(m_nettype).TARGET_BLOCK_TIME),
            difficulty_mode(m_nettype, chain_height));

    m_cache.m_timestamps_and_difficulties_height = chain_height;

    std::unique_lock diff_lock{m_cache.m_difficulty_lock};
    m_cache.m_difficulty_for_next_block_top_hash = top_hash;
    m_cache.m_difficulty_for_next_miner_block = diff;
    return diff;
}
//------------------------------------------------------------------
std::vector<time_t> Blockchain::get_last_block_timestamps(unsigned int blocks) const {
    uint64_t height = m_db->height();
    if (blocks > height)
        blocks = height;
    std::vector<time_t> timestamps(blocks);
    while (blocks--)
        timestamps[blocks] = m_db->get_block_timestamp(height - blocks - 1);
    return timestamps;
}
//------------------------------------------------------------------
// This function removes blocks from the blockchain until it gets to the
// position where the blockchain switch started and then re-adds the blocks
// that had been removed.
bool Blockchain::rollback_blockchain_switching(
        const std::list<block_and_checkpoint>& original_chain, uint64_t rollback_height) {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    // fail if rollback_height passed is too high
    if (rollback_height > m_db->height()) {
        return true;
    }

    m_cache.m_timestamps_and_difficulties_height = 0;

    // remove blocks from blockchain until we get back to where we should be.
    while (m_db->height() != rollback_height) {
        pop_block_from_blockchain();
    }

    // Revert all changes from switching to the alt chain before adding the original chain back in
    detached_info rollback_hook_data{rollback_height, /*by_pop_blocks=*/false};
    for (const auto& hook : m_blockchain_detached_hooks)
        hook(rollback_hook_data);
    load_missing_blocks_into_oxen_subsystems();

    // return back original chain
    for (auto& entry : original_chain) {
        block_verification_context bvc{};
        bool r = handle_block_to_main_chain(
                entry.block,
                cryptonote::get_block_hash(entry.block),
                bvc,
                entry.checkpointed ? &entry.checkpoint : nullptr,
                false);
        CHECK_AND_ASSERT_MES(
                r && bvc.m_added_to_main_chain,
                false,
                "PANIC! failed to add (again) block while chain switching during the rollback!");
    }

    log::info(logcat, "Rollback to height {} was successful.", rollback_height);
    if (!original_chain.empty()) {
        log::info(logcat, "Restoration to previous blockchain successful as well.");
    }
    return true;
}
//------------------------------------------------------------------
bool Blockchain::blink_rollback(uint64_t rollback_height) {
    auto lock = tools::unique_locks(tx_pool, *this);
    bool stop_batch = m_db->batch_start();
    log::debug(logcat, "Rolling back to height {}", rollback_height);
    bool ret = rollback_blockchain_switching({}, rollback_height);
    if (stop_batch)
        m_db->batch_stop();
    return ret;
}
//------------------------------------------------------------------
// This function attempts to switch to an alternate chain, returning
// boolean based on success therein.
bool Blockchain::switch_to_alternative_blockchain(
        const std::list<block_extended_info>& alt_chain, bool keep_disconnected_chain) {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    m_cache.m_timestamps_and_difficulties_height = 0;

    // if empty alt chain passed (not sure how that could happen), return false
    CHECK_AND_ASSERT_MES(
            alt_chain.size(), false, "switch_to_alternative_blockchain: empty chain passed");

    // verify that main chain has front of alt chain's parent block
    if (!m_db->block_exists(alt_chain.front().bl.prev_id)) {
        log::error(
                logcat,
                "Attempting to move to an alternate chain, but it doesn't appear to connect to the "
                "main chain!");
        return false;
    }

    // pop blocks from the blockchain until the top block is the parent
    // of the front block of the alt chain.
    std::list<block_and_checkpoint> disconnected_chain;  // TODO(oxen): use a vector and rbegin(),
                                                         // rend() because we don't have push_front
    while (m_db->top_block_hash() != alt_chain.front().bl.prev_id) {
        block_and_checkpoint entry = {};
        entry.block = pop_block_from_blockchain();
        entry.checkpointed = m_db->get_block_checkpoint(entry.block.get_height(), entry.checkpoint);
        disconnected_chain.push_front(entry);
    }

    auto split_height = m_db->height();
    detached_info split_hook_data{split_height, /*by_pop_blocks=*/false};
    for (const auto& hook : m_blockchain_detached_hooks)
        hook(split_hook_data);
    load_missing_blocks_into_oxen_subsystems();

    // connecting new alternative chain
    for (auto alt_ch_iter = alt_chain.begin(); alt_ch_iter != alt_chain.end(); alt_ch_iter++) {
        const auto& bei = *alt_ch_iter;
        block_verification_context bvc{};

        // add block to main chain
        bool r = handle_block_to_main_chain(
                bei.bl,
                cryptonote::get_block_hash(bei.bl),
                bvc,
                bei.checkpointed ? &bei.checkpoint : nullptr,
                false);

        // if adding block to main chain failed, rollback to previous state and
        // return false
        if (!r || !bvc.m_added_to_main_chain) {
            log::error(logcat, "Failed to switch to alternative blockchain");
            // rollback_blockchain_switching should be moved to two different
            // functions: rollback and apply_chain, but for now we pretend it is
            // just the latter (because the rollback was done above).
            rollback_blockchain_switching(disconnected_chain, split_height);

            const crypto::hash blkid = cryptonote::get_block_hash(bei.bl);
            add_block_as_invalid(bei.bl);
            log::error(
                    logcat,
                    "The block was inserted as invalid while connecting new alternative chain, "
                    "block_id: {}",
                    blkid);
            m_db->remove_alt_block(blkid);
            alt_ch_iter++;

            for (auto alt_ch_to_orph_iter = alt_ch_iter; alt_ch_to_orph_iter != alt_chain.end();) {
                const auto& bei = *alt_ch_to_orph_iter++;
                add_block_as_invalid(bei.bl);
                m_db->remove_alt_block(blkid);
            }
            return false;
        }
    }

    if (keep_disconnected_chain)  // pushing old chain as alternative chain
    {
        for (auto& old_ch_ent : disconnected_chain) {
            block_verification_context bvc{};
            bool r = handle_alternative_block(
                    old_ch_ent.block,
                    cryptonote::get_block_hash(old_ch_ent.block),
                    bvc,
                    old_ch_ent.checkpointed ? &old_ch_ent.checkpoint : nullptr);
            if (!r) {
                log::error(logcat, "Failed to push ex-main chain blocks to alternative chain ");
                // previously this would fail the blockchain switching, but I don't
                // think this is bad enough to warrant that.
            }
        }
    }

    // removing alt_chain entries from alternative chains container
    for (const auto& bei : alt_chain) {
        m_db->remove_alt_block(cryptonote::get_block_hash(bei.bl));
    }

    get_block_longhash_reorg(split_height);

    for (auto it = alt_chain.begin(); it != alt_chain.end(); ++it) {
        // Only the first hook gets `reorg=true`, the rest don't count as reorgs
        block_post_add_info hook_data{it->bl, it == alt_chain.begin(), split_height};
        for (const auto& hook : m_block_post_add_hooks)
            hook(hook_data);
    }

    log::info(
            globallogcat,
            fg(fmt::terminal_color::green),
            "REORGANIZE SUCCESS! on height: {}, new blockchain size: {}",
            split_height,
            m_db->height());
    return true;
}
//------------------------------------------------------------------
// This function calculates the difficulty target for the block being added to
// an alternate chain.
difficulty_type Blockchain::get_difficulty_for_alternative_chain(
        const std::list<block_extended_info>& alt_chain,
        uint64_t alt_block_height,
        bool pulse) const {
    if (m_fixed_difficulty) {
        return m_db->height() ? m_fixed_difficulty : 1;
    }

    if (pulse)
        return PULSE_FIXED_DIFFICULTY;

    log::trace(logcat, "Blockchain::{}", __func__);

    uint64_t block_count = 0;
    {
        bool before_hf16 = true;
        if (alt_chain.size())
            before_hf16 = alt_chain.back().bl.major_version < hf::hf16_pulse;
        else
            before_hf16 = !is_hard_fork_at_least(
                    m_nettype, hf::hf16_pulse, get_current_blockchain_height());

        block_count = old::DIFFICULTY_BLOCKS_COUNT(before_hf16);
    }

    std::vector<uint64_t> timestamps;
    std::vector<difficulty_type> cumulative_difficulties;
    // if the alt chain isn't long enough to calculate the difficulty target
    // based on its blocks alone, need to get more blocks from the main chain
    if (alt_chain.size() < block_count) {
        std::unique_lock lock{*this};

        // Figure out start and stop offsets for main chain blocks
        size_t main_chain_stop_offset =
                alt_chain.size() ? alt_chain.front().height : alt_block_height;
        size_t main_chain_count =
                block_count - std::min(static_cast<size_t>(block_count), alt_chain.size());
        main_chain_count = std::min(main_chain_count, main_chain_stop_offset);
        size_t main_chain_start_offset = main_chain_stop_offset - main_chain_count;

        if (!main_chain_start_offset)
            ++main_chain_start_offset;  // skip genesis block

        // get difficulties and timestamps from relevant main chain blocks
        for (; main_chain_start_offset < main_chain_stop_offset; ++main_chain_start_offset) {
            timestamps.push_back(m_db->get_block_timestamp(main_chain_start_offset));
            cumulative_difficulties.push_back(
                    m_db->get_block_cumulative_difficulty(main_chain_start_offset));
        }

        // make sure we haven't accidentally grabbed too many blocks...maybe don't need this check?
        CHECK_AND_ASSERT_MES(
                (alt_chain.size() + timestamps.size()) <= block_count,
                false,
                "Internal error, alt_chain.size()[{}] + timestamps.size()[{}] NOT <= BLOCK COUNT "
                "{}",
                alt_chain.size(),
                timestamps.size(),
                block_count);

        for (const auto& bei : alt_chain) {
            timestamps.push_back(bei.bl.timestamp);
            cumulative_difficulties.push_back(bei.cumulative_difficulty);
        }
    }
    // if the alt chain is long enough for the difficulty calc, grab difficulties
    // and timestamps from it alone
    else {
        timestamps.resize(static_cast<size_t>(block_count));
        cumulative_difficulties.resize(static_cast<size_t>(block_count));
        size_t count = 0;
        size_t max_i = timestamps.size() - 1;
        // get difficulties and timestamps from most recent blocks in alt chain
        for (auto it = alt_chain.rbegin(); it != alt_chain.rend(); ++it) {
            const auto& bei = *it;
            timestamps[max_i - count] = bei.bl.timestamp;
            cumulative_difficulties[max_i - count] = bei.cumulative_difficulty;
            count++;
            if (count >= block_count)
                break;
        }
    }

    // calculate the difficulty target for the block and return it
    uint64_t height =
            (alt_chain.size() ? alt_chain.front().height : alt_block_height) + alt_chain.size() + 1;
    return next_difficulty_v2(
            timestamps,
            cumulative_difficulties,
            tools::to_seconds(get_config(m_nettype).TARGET_BLOCK_TIME),
            difficulty_mode(m_nettype, height));
}
//------------------------------------------------------------------
// This function does a sanity check on basic things that all miner
// transactions have in common, such as:
//   one input, of type txin_gen, with height set to the block's height
//   correct miner tx unlock time
//   a non-overflowing tx amount (dubious necessity on this check)
bool Blockchain::prevalidate_miner_transaction(const block& b, uint64_t height, hf hf_version) {
    log::trace(logcat, "Blockchain::{}", __func__);
    if ((b.major_version >= feature::ETH_BLS) == b.miner_tx.has_value()) {
        log::error(
                logcat,
                "Invalid block: HF {} blocks {} have a miner tx",
                static_cast<int>(b.major_version),
                b.major_version >= feature::ETH_BLS ? "must not" : "must");
        return false;
    }
    if (!b.miner_tx || b.miner_tx->vout.empty())
        return true;

    auto& miner_tx = *b.miner_tx;

    CHECK_AND_ASSERT_MES(
            miner_tx.vin.size() == 1, false, "coinbase transaction in the block has no inputs");
    CHECK_AND_ASSERT_MES(
            miner_tx.is_miner_tx(), false, "coinbase transaction in the block has the wrong type");
    if (b.get_height() != height) {
        log::warning(
                logcat, "The block has invalid height: {}, expected: {}", b.get_height(), height);
        return false;
    }
    if (b.major_version == hf::hf19_reward_batching && b._height != 0 && b._height != height) {
        // Oxen 10 nodes and early Oxen 11 nodes send the height in both the block and the txin_gen;
        // later Oxen 11 nodes will send 0 for the height instead.
        log::warning(
                logcat,
                "HF19 block with invalid mismatched block/txin_gen heights {}/{}",
                b._height,
                b.get_height());
        return false;
    }
    log::debug(logcat, "Miner tx hash: {}", get_transaction_hash(miner_tx));
    CHECK_AND_ASSERT_MES(
            miner_tx.unlock_time == height + MINED_MONEY_UNLOCK_WINDOW,
            false,
            "coinbase transaction transaction has the wrong unlock time={}, expected {}",
            miner_tx.unlock_time,
            height + MINED_MONEY_UNLOCK_WINDOW);

    if (hf_version >= hf::hf12_checkpointing) {
        if (miner_tx.type != txtype::standard) {
            log::error(logcat, "Coinbase invalid transaction type for coinbase transaction.");
            return false;
        }

        txversion min_version = transaction::get_max_version_for_hf(hf_version);
        txversion max_version = transaction::get_min_version_for_hf(hf_version);
        if (miner_tx.version < min_version || miner_tx.version > max_version) {
            log::error(
                    log::Cat("verify"),
                    "Coinbase invalid version: {} for hardfork: {} min/max version: {}/{}",
                    miner_tx.version,
                    static_cast<int>(hf_version),
                    min_version,
                    max_version);
            return false;
        }
    }

    if (hf_version >= feature::REJECT_SIGS_IN_COINBASE)  // Enforce empty rct signatures for
                                                         // miner transactions,
        CHECK_AND_ASSERT_MES(
                miner_tx.rct_signatures.type == rct::RCTType::Null,
                false,
                "RingCT signatures not allowed in coinbase transactions");

    // check outs overflow
    // NOTE: not entirely sure this is necessary, given that this function is
    //       designed simply to make sure the total amount for a transaction
    //       does not overflow a uint64_t, and this transaction *is* a uint64_t...
    if (!check_outs_overflow(miner_tx)) {
        log::error(logcat, "miner transaction has money overflow in block {}", get_block_hash(b));
        return false;
    }

    return true;
}
//------------------------------------------------------------------
// This function validates the miner transaction reward
bool Blockchain::validate_miner_transaction(
        const block& b,
        size_t cumulative_block_weight,
        uint64_t fee,
        uint64_t& base_reward,
        uint64_t already_generated_coins,
        hf version) {
    log::trace(logcat, "Blockchain::{}", __func__);

    if ((b.major_version >= feature::ETH_BLS) == b.miner_tx.has_value()) {
        log::error(
                log::Cat("verify"),
                "Invalid block: HF {} blocks {} have a miner tx",
                static_cast<int>(b.major_version),
                b.miner_tx ? "must not" : "must");
        return false;
    }

    // validate reward
    uint64_t const money_in_use = get_outs_money_amount(b.miner_tx);
    if (b.miner_tx && b.miner_tx->vout.size() == 0 && b.major_version < hf::hf19_reward_batching) {
        log::error(log::Cat("verify"), "miner tx has no outputs");
        return false;
    }

    uint64_t median_weight;
    if (version >= feature::EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY) {
        median_weight = m_current_block_cumul_weight_median;
    } else {
        std::vector<uint64_t> last_blocks_weights;
        get_last_n_blocks_weights(last_blocks_weights, REWARD_BLOCKS_WINDOW);
        median_weight = tools::median(std::move(last_blocks_weights));
    }

    uint64_t height = b.get_height();
    oxen_block_reward_context block_reward_context = {};
    block_reward_context.fee = fee;
    block_reward_context.height = height;
    if (!calc_batched_governance_reward(height, block_reward_context.batched_governance)) {
        log::error(log::Cat("verify"), "Failed to calculate batched governance reward");
        return false;
    }

    block_reward_parts reward_parts{};

    if (!get_oxen_block_reward(
                median_weight,
                cumulative_block_weight,
                already_generated_coins,
                version,
                reward_parts,
                block_reward_context))
        return false;

    std::vector<cryptonote::batch_sn_payment> batched_sn_payments;
    if (m_sqlite_db) {
        if (version < cryptonote::feature::ETH_BLS)
            batched_sn_payments = m_sqlite_db->get_sn_payments(height);
    } else {
        if (m_nettype != network_type::FAKECHAIN)
            throw oxen::traced<std::logic_error>("Blockchain missing SQLite Database");
    }
    miner_tx_info hook_data{b, reward_parts, batched_sn_payments};
    for (const auto& hook : m_validate_miner_tx_hooks) {
        try {
            hook(hook_data);
        } catch (const std::exception& e) {
            log::warning(
                    globallogcat,
                    fg(fmt::terminal_color::red),
                    "Miner tx failed validation: {}",
                    e.what());
            return false;
        }
    }

    if (already_generated_coins != 0 && block_has_governance_output(nettype(), b) &&
        version < hf::hf19_reward_batching) {
        if (version >= hf::hf10_bulletproofs && reward_parts.governance_paid == 0) {
            log::error(
                    log::Cat("verify"),
                    "Governance reward should not be 0 after hardfork v10 if this height has a "
                    "governance output because it is the batched payout height");
            return false;
        }

        if (b.miner_tx->vout.back().amount != reward_parts.governance_paid) {
            log::error(
                    log::Cat("verify"),
                    "Governance reward amount incorrect.  Should be: {}, is: {}",
                    print_money(reward_parts.governance_paid),
                    print_money(b.miner_tx->vout.back().amount));
            return false;
        }

        if (!validate_governance_reward_key(
                    m_db->height(),
                    cryptonote::get_config(m_nettype).governance_wallet_address(version),
                    b.miner_tx->vout.size() - 1,
                    var::get<txout_to_key>(b.miner_tx->vout.back().target).key,
                    m_nettype)) {
            log::error(log::Cat("verify"), "Governance reward public key incorrect.");
            return false;
        }
    }

    // +1 here to allow a 1 atomic unit error in the calculation (which can happen because of
    // floating point errors or rounding)
    // TODO(oxen): eliminate all floating point math in reward calculations.
    uint64_t max_base_reward = reward_parts.governance_paid + 1;

    if (version >= hf::hf19_reward_batching) {
        max_base_reward += std::accumulate(
                batched_sn_payments.begin(),
                batched_sn_payments.end(),
                uint64_t{0},
                [&](auto a, auto b) { return a + b.amount; });
    } else {
        max_base_reward += reward_parts.base_miner + reward_parts.service_node_total;
    }

    uint64_t max_money_in_use = max_base_reward + reward_parts.miner_fee;

    if (money_in_use > max_money_in_use) {
        log::error(
                log::Cat("verify"),
                "coinbase transaction spends too much money ({}). Maximum block reward is {} (= {} "
                "base + {} fees)",
                print_money(money_in_use),
                print_money(max_money_in_use),
                print_money(max_base_reward),
                print_money(reward_parts.miner_fee));
        return false;
    }

    if (version < hf::hf19_reward_batching) {
        CHECK_AND_ASSERT_MES(
                money_in_use >= reward_parts.miner_fee, false, "base reward calculation bug");
        base_reward = money_in_use - reward_parts.miner_fee;

    } else if (version == hf::hf19_reward_batching) {
        if (b.reward != reward_parts.miner_fee + reward_parts.service_node_total) {
            log::error(
                    log::Cat("verify"),
                    "block reward for batching is incorrect: {} != {} ({} SN + {} tx fees)",
                    print_money(b.reward),
                    print_money(reward_parts.miner_fee + reward_parts.service_node_total),
                    print_money(reward_parts.service_node_total),
                    print_money(reward_parts.miner_fee));
            return false;
        }

    } else if (version >= feature::ETH_BLS) {
        // The block's l2_reward published to the network is only permitted to change slightly from
        // the previous block's value.
        uint64_t min_l2r, max_l2r;
        try {
            std::tie(min_l2r, max_l2r) = l2_reward_range(b.get_height());
        } catch (const DB_ERROR& e) {
            log::error(logcat, "failed to retrieve previous block header from DB: {}", e.what());
            return false;
        }

        if (b.l2_reward > max_l2r || b.l2_reward < min_l2r) {
            log::error(
                    log::Cat("verify"),
                    "block has invalid l2_reward {} not in [{}, {}]",
                    print_money(b.l2_reward),
                    print_money(min_l2r),
                    print_money(max_l2r));
            return false;
        }

        // The block must also claim the correct (actual) block reward to be paid out at this
        // height, which is the minimum of the last 15 blocks.
        if (auto expected_reward = eth_consensus_reward(height); b.reward != expected_reward) {
            log::error(
                    log::Cat("verify"),
                    "block reward for height {} is incorrect; block has {} but expected {}",
                    height,
                    print_money(b.reward),
                    print_money(expected_reward));
            return false;
        }
    }

    return true;
}

uint64_t Blockchain::eth_consensus_reward(uint64_t height) const {
    auto eth_height = hard_fork_begins(m_nettype, feature::ETH_BLS);
    if (!eth_height || height < *eth_height)
        return 0;
    if (height < *eth_height + L2_REWARD_CONSENSUS_BLOCKS)
        return oxen::ETH_BLS_INITIAL_REWARD;

    size_t count = 0;
    uint64_t min_l2_reward = std::numeric_limits<uint64_t>::max();
    bool okay = db().for_blocks_range(
            height - L2_REWARD_CONSENSUS_BLOCKS,
            height - 1,
            [&count, &min_l2_reward](
                    uint64_t /*height*/, const crypto::hash& /*hash*/, const block& block) {
                assert(block.major_version >= feature::ETH_BLS);
                if (block.l2_reward < min_l2_reward)
                    min_l2_reward = block.l2_reward;
                count++;
                return true;
            });
    if (!okay || count != L2_REWARD_CONSENSUS_BLOCKS ||
        min_l2_reward == std::numeric_limits<uint64_t>::max())
        throw oxen::traced<std::out_of_range>{
                "Invalid height for eth_consensus_reward: preceeding blocks not found in "
                "blockchain db"};

    return min_l2_reward;
}

std::pair<uint64_t, uint64_t> Blockchain::l2_reward_range(uint64_t height) const {
    auto eth_begins = hard_fork_begins(m_nettype, feature::ETH_BLS);
    if (!eth_begins || height < *eth_begins)
        return {0, 0};

    // For the first ETH_BLS block itself we pretend the previous block had a l2_reward of exactly
    // ETH_BLS_INITIAL_REWARD.
    auto prev_l2_reward = height == *eth_begins
                                ? oxen::ETH_BLS_INITIAL_REWARD
                                : db().get_block_header_from_height(height - 1).l2_reward;

    return {prev_l2_reward - prev_l2_reward / L2_REWARD_MAX_DECREASE_DIVISOR,
            prev_l2_reward + prev_l2_reward / L2_REWARD_MAX_INCREASE_DIVISOR};
}

//------------------------------------------------------------------
// get the block weights of the last <count> blocks, and return by reference <sz>.
void Blockchain::get_last_n_blocks_weights(std::vector<uint64_t>& weights, size_t count) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};
    auto h = m_db->height();

    // this function is meaningless for an empty blockchain...granted it should never be empty
    if (h == 0)
        return;

    // add weight of last <count> blocks to vector <weights> (or less, if blockchain size < count)
    size_t start_offset = h - std::min<size_t>(h, count);
    weights = m_db->get_block_weights(start_offset, count);
}
//------------------------------------------------------------------
uint64_t Blockchain::get_long_term_block_weight_median(uint64_t start_height, size_t count) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    CHECK_AND_ASSERT_THROW_MES(count > 0, "count == 0");

    bool cached = false;
    uint64_t blockchain_height = m_db->height();
    uint64_t tip_height = start_height + count - 1;
    crypto::hash tip_hash{};
    if (tip_height < blockchain_height &&
        count == (size_t)m_long_term_block_weights_cache_rolling_median.size()) {
        tip_hash = m_db->get_block_hash_from_height(tip_height);
        cached = tip_hash == m_long_term_block_weights_cache_tip_hash;
    }

    if (cached) {
        log::trace(logcat, "requesting {} from {}, cached", count, start_height);
        return m_long_term_block_weights_cache_rolling_median.median();
    }

    // in the vast majority of uncached cases, most is still cached,
    // as we just move the window one block up:
    if (tip_height > 0 && count == (size_t)m_long_term_block_weights_cache_rolling_median.size() &&
        tip_height < blockchain_height) {
        crypto::hash old_tip_hash = m_db->get_block_hash_from_height(tip_height - 1);
        if (old_tip_hash == m_long_term_block_weights_cache_tip_hash) {
            log::trace(logcat, "requesting {} from {}, incremental", count, start_height);
            m_long_term_block_weights_cache_tip_hash = tip_hash;
            m_long_term_block_weights_cache_rolling_median.insert(
                    m_db->get_block_long_term_weight(tip_height));
            return m_long_term_block_weights_cache_rolling_median.median();
        }
    }

    log::trace(logcat, "requesting {} from {}, uncached", count, start_height);
    std::vector<uint64_t> weights = m_db->get_long_term_block_weights(start_height, count);
    m_long_term_block_weights_cache_tip_hash = tip_hash;
    m_long_term_block_weights_cache_rolling_median.clear();
    for (uint64_t w : weights)
        m_long_term_block_weights_cache_rolling_median.insert(w);
    return m_long_term_block_weights_cache_rolling_median.median();
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_cumulative_block_weight_limit() const {
    log::trace(logcat, "Blockchain::{}", __func__);
    return m_current_block_cumul_weight_limit;
}
//------------------------------------------------------------------
uint64_t Blockchain::get_current_cumulative_block_weight_median() const {
    log::trace(logcat, "Blockchain::{}", __func__);
    return m_current_block_cumul_weight_median;
}
//------------------------------------------------------------------
// TODO: This function only needed minor modification to work with BlockchainDB,
//      and *works*.  As such, to reduce the number of things that might break
//      in moving to BlockchainDB, this function will remain otherwise
//      unchanged for the time being.
//
// This function makes a new block for a miner to mine the hash for
bool Blockchain::create_block_template_internal(
        block& b,
        const crypto::hash* from_block,
        const block_template_info& info,
        difficulty_type& diffic,
        uint64_t& height,
        uint64_t& expected_reward,
        const std::string& ex_nonce) {
    log::trace(logcat, "Blockchain::{}", __func__);
    size_t median_weight;
    uint64_t already_generated_coins;
    uint64_t pool_cookie;

    auto lock = tools::shared_locks(tx_pool, *this, *m_l2_tracker);
    if (m_btc_valid && !from_block) {
        // The pool cookie is atomic. The lack of locking is OK, as if it changes
        // just as we compare it, we'll just use a slightly old template, but
        // this would be the case anyway if we'd lock, and the change happened
        // just after the block template was created
        if (info.miner_address != m_btc_address && m_btc_nonce == ex_nonce &&
            m_btc_pool_cookie == tx_pool.cookie() && m_btc.prev_id == get_tail_id().second) {
            log::debug(logcat, "Using cached template");
            const uint64_t now = time(NULL);
            if (m_btc.timestamp <
                        now /*ensures it can't get below the median of the last few blocks*/
                || !info.is_miner)
                m_btc.timestamp = now;
            b = m_btc;
            diffic = get_difficulty_for_next_block(!info.is_miner);
            height = m_btc_height;
            expected_reward = m_btc_expected_reward;
            return true;
        }
        log::debug(
                logcat,
                "Not using cached template: address {}, nonce {}, cookie {}, from_block {}",
                (bool)(info.miner_address != m_btc_address),
                (m_btc_nonce == ex_nonce),
                (m_btc_pool_cookie == tx_pool.cookie()),
                (!!from_block));
        invalidate_block_template_cache();
    }

    // from_block is usually nullptr, used to build altchains
    if (from_block) {
        // build alternative subchain, front -> mainchain, back -> alternative head
        // block is not related with head of main chain
        // first of all - look in alternative chains container
        alt_block_data_t prev_data;
        bool parent_in_alt =
                m_db->get_alt_block(*from_block, &prev_data, NULL, nullptr /*checkpoint*/);
        bool parent_in_main = m_db->block_exists(*from_block);
        if (!parent_in_alt && !parent_in_main) {
            log::error(logcat, "Unknown from block");
            return false;
        }

        // we have new block in alternative chain
        std::list<block_extended_info> alt_chain;
        block_verification_context bvc{};
        std::vector<uint64_t> timestamps;
        if (!build_alt_chain(
                    *from_block,
                    alt_chain,
                    timestamps,
                    bvc,
                    nullptr /*num_alt_checkpoints*/,
                    nullptr /*num_checkpoints*/))
            return false;

        if (parent_in_main) {
            cryptonote::block prev_block;
            CHECK_AND_ASSERT_MES(
                    get_block_by_hash(*from_block, prev_block),
                    false,
                    "From block not found");  // TODO
            uint64_t from_block_height = prev_block.get_height();
            height = from_block_height + 1;
        } else {
            height = alt_chain.back().height + 1;
        }
        auto [maj, min] = get_ideal_block_version(m_nettype, height);
        b.major_version = maj;
        b.minor_version = min;
        b.prev_id = *from_block;

        // cheat and use the weight of the block we start from, virtually certain to be acceptable
        // and use 1.9 times rather than 2 times so we're even more sure
        if (parent_in_main) {
            median_weight = m_db->get_block_weight(height - 1);
            already_generated_coins = m_db->get_block_already_generated_coins(height - 1);
        } else {
            median_weight = prev_data.cumulative_weight - prev_data.cumulative_weight / 20;
            already_generated_coins = alt_chain.back().already_generated_coins;
        }

        // FIXME: consider moving away from block_extended_info at some point
        block_extended_info bei{};
        bei.bl = b;
        bei.height =
                alt_chain.size() ? prev_data.height + 1 : m_db->get_block_height(*from_block) + 1;

        diffic = get_difficulty_for_alternative_chain(alt_chain, bei.height, !info.is_miner);
    } else {
        // Creates the block template for next block on main chain
        std::tie(height, b.prev_id) = get_tail_id();
        ++height;  // Convert to the next block's height
        auto [maj, min] = get_ideal_block_version(m_nettype, height);
        b.major_version = maj;
        b.minor_version = min;
        median_weight = m_current_block_cumul_weight_limit / 2;
        diffic = get_difficulty_for_next_block(!info.is_miner);
        already_generated_coins = m_db->get_block_already_generated_coins(height - 1);
    }
    b.timestamp = time(NULL);

    uint64_t median_ts;
    if (!check_block_timestamp(b, median_ts)) {
        b.timestamp = median_ts;
    }

    CHECK_AND_ASSERT_MES(diffic, false, "difficulty overhead.");

    auto hf_version = b.major_version;
    size_t txs_weight;
    uint64_t fee;

    std::optional<uint64_t> l2_mempool_max;
    if (hf_version >= cryptonote::feature::ETH_BLS) {
        b.l2_height = m_l2_tracker->get_safe_height();
        l2_mempool_max = b.l2_height;
    }

    // Add transactions in mempool to block
    if (!tx_pool.fill_block_template(
                b,
                median_weight,
                already_generated_coins,
                txs_weight,
                fee,
                expected_reward,
                b.major_version,
                height,
                l2_mempool_max))
        return false;

    pool_cookie = tx_pool.cookie();

    /*
     two-phase miner transaction generation: we don't know exact block weight until we prepare
     block, but we don't know reward until we know block weight, so first miner transaction
     generated with fake amount of money, and with phase we know think we know expected block weight
     */
    // make blocks coin-base tx looks close to real coinbase tx to get truthful blob weight
    auto miner_tx_context = info.is_miner ? oxen_miner_tx_context::miner_block(
                                                    m_nettype,
                                                    info.miner_address,
                                                    service_node_list.get_next_block_leader())
                                          : oxen_miner_tx_context::pulse_block(
                                                    m_nettype,
                                                    info.service_node_payout,
                                                    service_node_list.get_next_block_leader());

    if (hf_version >= cryptonote::feature::ETH_TRANSITION) {
        std::memcpy(
                b.sn_winner_tail.data(),
                miner_tx_context.block_leader.key.data() +
                        miner_tx_context.block_leader.key.size() - b.sn_winner_tail.size(),
                b.sn_winner_tail.size());
    }

    if (hf_version >= cryptonote::feature::ETH_BLS) {
        auto actual_reward = m_l2_tracker->get_reward_rate(b.l2_height);
        if (!actual_reward) {
            log::error(
                    logcat,
                    "L2 Tracker failed to retrieve the current block reward; unable to create a "
                    "block");
            return false;
        }

        // Clamp the l2_reward value into the maximum allowed range by the chain (this means sudden
        // pool reward changes will only show up gradually in l2_reward, but prevents abuse by
        // faulty/compromised L2 providers or pulse quorums).
        auto l2r_range = l2_reward_range(height);
        b.l2_reward = std::clamp(*actual_reward, l2r_range.first, l2r_range.second);
        b.l2_votes = service_node_list.l2_pending_state_votes();
        b._height = height;

        // No miner tx in HF21+ blocks, so we're done.
        b.miner_tx = std::nullopt;
        return true;
    }

    if (!calc_batched_governance_reward(height, miner_tx_context.batched_governance)) {
        log::error(logcat, "Failed to calculate batched governance reward");
        return false;
    }

    // This will check the batching database for who is due to be paid out in this block
    std::vector<cryptonote::batch_sn_payment> sn_rwds;
    if (hf_version >= hf::hf19_reward_batching) {
        sn_rwds = m_sqlite_db->get_sn_payments(height);  // Rewards to pay out
    }

    b.miner_tx.emplace();
    auto [r, block_rewards] = construct_miner_tx(
            height,
            median_weight,
            already_generated_coins,
            txs_weight,
            fee,
            *b.miner_tx,
            miner_tx_context,
            sn_rwds,
            ex_nonce,
            hf_version);

    CHECK_AND_ASSERT_MES(r, false, "Failed to construct miner tx, first chance");
    size_t cumulative_weight = txs_weight + get_transaction_weight(b.miner_tx);
    for (size_t try_count = 0; try_count != 10; ++try_count) {
        std::tie(r, block_rewards) = construct_miner_tx(
                height,
                median_weight,
                already_generated_coins,
                cumulative_weight,
                fee,
                *b.miner_tx,
                miner_tx_context,
                sn_rwds,
                ex_nonce,
                hf_version);

        CHECK_AND_ASSERT_MES(r, false, "Failed to construct miner tx, second chance");
        size_t coinbase_weight = get_transaction_weight(b.miner_tx);
        if (coinbase_weight > cumulative_weight - txs_weight) {
            cumulative_weight = txs_weight + coinbase_weight;
            continue;
        }

        if (coinbase_weight < cumulative_weight - txs_weight) {
            size_t delta = cumulative_weight - txs_weight - coinbase_weight;
            b.miner_tx->extra.insert(b.miner_tx->extra.end(), delta, 0);
            // here  could be 1 byte difference, because of extra field counter is varint, and it
            // can become from 1-byte len to 2-bytes len.
            if (cumulative_weight != txs_weight + get_transaction_weight(b.miner_tx)) {
                CHECK_AND_ASSERT_MES(
                        cumulative_weight + 1 == txs_weight + get_transaction_weight(b.miner_tx),
                        false,
                        "unexpected case: cumulative_weight={} + 1 does not equal "
                        "txs_cumulative_weight={} + get_transaction_weight(b.miner_tx)={}",
                        cumulative_weight,
                        txs_weight,
                        get_transaction_weight(b.miner_tx));
                b.miner_tx->extra.resize(b.miner_tx->extra.size() - 1);
                if (cumulative_weight != txs_weight + get_transaction_weight(b.miner_tx)) {
                    // fuck, not lucky, -1 makes varint-counter size smaller, in that case we
                    // continue to grow with cumulative_weight
                    log::debug(
                            logcat,
                            "Miner tx creation has no luck with delta_extra size = {} and {}",
                            delta,
                            delta - 1);
                    cumulative_weight += delta - 1;
                    continue;
                }
                log::debug(
                        logcat,
                        "Setting extra for block: {}, try_count={}",
                        b.miner_tx->extra.size(),
                        try_count);
            }
        }
        CHECK_AND_ASSERT_MES(
                cumulative_weight == txs_weight + get_transaction_weight(b.miner_tx),
                false,
                "unexpected case: cumulative_weight={} does not equal txs_cumulative_weight={} + "
                "get_transaction_weight(b.miner_tx)={}",
                cumulative_weight,
                txs_weight,
                get_transaction_weight(b.miner_tx));

        if (!from_block)
            cache_block_template(
                    b, info.miner_address, ex_nonce, diffic, height, expected_reward, pool_cookie);

        if (miner_tx_context.pulse)
            b.oxen10_pulse_producer = miner_tx_context.pulse_block_producer.key;
        else
            b.oxen10_pulse_producer = crypto::null<crypto::public_key>;

        b.reward = block_rewards;
        b._height = height;
        return true;
    }
    log::error(logcat, "Failed to create_block_template with {} tries", 10);
    return false;
}
//------------------------------------------------------------------
bool Blockchain::create_miner_block_template(
        block& b,
        const crypto::hash* from_block,
        const account_public_address& miner_address,
        difficulty_type& diffic,
        uint64_t& height,
        uint64_t& expected_reward,
        const std::string& ex_nonce) {
    block_template_info info = {};
    info.is_miner = true;
    info.miner_address = miner_address;
    return create_block_template_internal(
            b, from_block, info, diffic, height, expected_reward, ex_nonce);
}
//------------------------------------------------------------------
bool Blockchain::create_next_miner_block_template(
        block& b,
        const account_public_address& miner_address,
        difficulty_type& diffic,
        uint64_t& height,
        uint64_t& expected_reward,
        const std::string& ex_nonce) {
    return create_miner_block_template(
            b, nullptr /*from_block*/, miner_address, diffic, height, expected_reward, ex_nonce);
}
//------------------------------------------------------------------
bool Blockchain::create_next_pulse_block_template(
        block& b,
        const service_nodes::payout& block_producer,
        uint8_t round,
        uint16_t validator_bitset,
        uint64_t& height) {
    uint64_t expected_reward = 0;
    block_template_info info = {};
    info.service_node_payout = block_producer;
    uint64_t diffic = 0;
    std::string nonce = {};

    bool result = create_block_template_internal(
            b, nullptr /*from_block*/, info, diffic, height, expected_reward, nonce);
    b.pulse.round = round;
    b.pulse.validator_bitset = validator_bitset;
    return result;
}

//------------------------------------------------------------------
// for an alternate chain, get the timestamps from the main chain to complete
// the needed number of timestamps for the BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.
bool Blockchain::complete_timestamps_vector(
        uint64_t start_top_height, std::vector<uint64_t>& timestamps) const {
    log::trace(logcat, "Blockchain::{}", __func__);

    if (timestamps.size() >= BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW)
        return true;

    std::unique_lock lock{*this};
    size_t need_elements = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW - timestamps.size();
    CHECK_AND_ASSERT_MES(
            start_top_height < m_db->height(),
            false,
            "internal error: passed start_height not < m_db->height() -- {} >= {}",
            start_top_height,
            m_db->height());
    size_t stop_offset = start_top_height > need_elements ? start_top_height - need_elements : 0;
    timestamps.reserve(timestamps.size() + start_top_height - stop_offset);
    while (start_top_height != stop_offset) {
        timestamps.push_back(m_db->get_block_timestamp(start_top_height));
        --start_top_height;
    }
    return true;
}
//------------------------------------------------------------------
bool Blockchain::build_alt_chain(
        const crypto::hash& prev_id,
        std::list<block_extended_info>& alt_chain,
        std::vector<uint64_t>& timestamps,
        block_verification_context& bvc,
        int* num_alt_checkpoints,
        int* num_checkpoints) {
    // build alternative subchain, front -> mainchain, back -> alternative head
    cryptonote::alt_block_data_t data;
    std::string blob;
    timestamps.clear();

    int alt_checkpoint_count = 0;
    int checkpoint_count = 0;
    crypto::hash prev_hash{};
    block_extended_info bei = {};
    std::string checkpoint_blob;
    for (bool found = m_db->get_alt_block(prev_id, &data, &blob, &checkpoint_blob); found;
         found = m_db->get_alt_block(prev_hash, &data, &blob, &checkpoint_blob)) {
        CHECK_AND_ASSERT_MES(
                cryptonote::parse_and_validate_block_from_blob(blob, bei.bl),
                false,
                "Failed to parse alt block");
        if (data.checkpointed)  // Take checkpoint from blob stored alongside alt block
        {
            CHECK_AND_ASSERT_MES(
                    t_serializable_object_from_blob(bei.checkpoint, checkpoint_blob),
                    false,
                    "Failed to parse alt checkpoint from blob");
            alt_checkpoint_count++;
        }

        // NOTE: If we receive or pre-define a checkpoint for a historical block
        // that conflicts with current blocks on the blockchain, upon receipt of
        // a new alt block, along this alt chain we should also double check all
        // blocks that are checkpointed along this chain in m_checkpoints

        // This is particularly relevant for receiving checkpoints via P2P votes
        // Which can form checkpoints retrospectively, that may conflict with
        // your canonical chain.
        bool height_is_checkpointed = false;
        bool alt_block_matches_checkpoint = m_checkpoints.check_block(
                data.height, get_block_hash(bei.bl), &height_is_checkpointed, nullptr);

        if (height_is_checkpointed) {
            if (alt_block_matches_checkpoint) {
                if (!data.checkpointed) {
                    data.checkpointed = true;
                    CHECK_AND_ASSERT_MES(
                            get_checkpoint(data.height, bei.checkpoint),
                            false,
                            "Unexpected failure to retrieve checkpoint after checking it existed");
                    alt_checkpoint_count++;
                }
            } else
                checkpoint_count++;  // One of our stored-checkpoints references another block
                                     // that's not this alt block.
        }

        bei.height = data.height;
        bei.block_cumulative_weight = data.cumulative_weight;
        bei.cumulative_difficulty = data.cumulative_difficulty;
        bei.already_generated_coins = data.already_generated_coins;
        bei.checkpointed = data.checkpointed;

        prev_hash = bei.bl.prev_id;
        timestamps.push_back(bei.bl.timestamp);
        alt_chain.push_front(std::move(bei));
        bei = {};
    }

    if (num_alt_checkpoints)
        *num_alt_checkpoints = alt_checkpoint_count;
    if (num_checkpoints)
        *num_checkpoints = checkpoint_count;

    // if block to be added connects to known blocks that aren't part of the
    // main chain -- that is, if we're adding on to an alternate chain
    if (!alt_chain.empty()) {
        bool failed = false;
        uint64_t blockchain_height = m_db->height();
        // make sure alt chain doesn't somehow start past the end of the main chain
        if (blockchain_height < alt_chain.front().height) {
            log::info(
                    logcat,
                    "main blockchain wrong height: {}, alt_chain: {}",
                    m_db->height(),
                    alt_chain.front().height);
            failed = true;
        }

        // make sure that the blockchain contains the block that should connect
        // this alternate chain with it.
        if (!failed && !m_db->block_exists(alt_chain.front().bl.prev_id)) {
            log::info(
                    logcat,
                    "alternate chain does not appear to connect to main chain...: {}",
                    alt_chain.front().bl.prev_id);
            failed = true;
        }

        // make sure block connects correctly to the main chain
        auto h = m_db->get_block_hash_from_height(alt_chain.front().height - 1);
        if (!failed && h != alt_chain.front().bl.prev_id) {
            log::info(
                    logcat,
                    "alternative chain has wrong connection to main chain: {}, mismatched with: {}",
                    h,
                    alt_chain.front().bl.prev_id);
            failed = true;
        }

        if (!failed && !m_checkpoints.is_alternative_block_allowed(
                               blockchain_height,
                               alt_chain.front().height,
                               nullptr /*service_node_checkpoint*/)) {
            log::debug(logcat, "alternative chain is too old to consider: {}", h);
            failed = true;
        }

        if (failed) {
            // Cleanup alt chain, it's invalid
            bvc.m_verifivation_failed = true;
            for (auto const& bei : alt_chain)
                m_db->remove_alt_block(cryptonote::get_block_hash(bei.bl));

            return false;
        }

        complete_timestamps_vector(
                m_db->get_block_height(alt_chain.front().bl.prev_id), timestamps);
    }
    // if block not associated with known alternate chain
    else {
        // if block parent is not part of main chain or an alternate chain,
        // we ignore it
        bool parent_in_main = m_db->block_exists(prev_id);
        CHECK_AND_ASSERT_MES(
                parent_in_main,
                false,
                "internal error: broken imperative condition: parent_in_main");

        complete_timestamps_vector(m_db->get_block_height(prev_id), timestamps);
    }

    return true;
}
//------------------------------------------------------------------
// If a block is to be added and its parent block is not the current
// main chain top block, then we need to see if we know about its parent block.
// If its parent block is part of a known forked chain, then we need to see
// if that chain is long enough to become the main chain and re-org accordingly
// if so.  If not, we need to hang on to the block in case it becomes part of
// a long forked chain eventually.
bool Blockchain::handle_alternative_block(
        const block& b,
        const crypto::hash& id,
        block_verification_context& bvc,
        checkpoint_t const* checkpoint) {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    uint64_t const blk_height = b.get_height();
    uint64_t const chain_height = get_current_blockchain_height();

    // NOTE: Check block parent's existence
    alt_block_data_t prev_data = {};
    bool parent_in_alt =
            m_db->get_alt_block(b.prev_id, &prev_data, NULL, nullptr /*checkpoint_blob*/);
    bool parent_in_main = m_db->block_exists(b.prev_id);
    if (!(parent_in_main || parent_in_alt)) {
        bvc.m_marked_as_orphaned = true;
        log::error(
                log::Cat("verify"),
                "Block recognized as orphaned and rejected, id = {}, height {}, parent in alt {}, "
                "parent in main {} (parent {}, current top {}, chain height {})",
                id,
                blk_height,
                parent_in_alt,
                parent_in_main,
                b.prev_id,
                get_tail_id().second,
                chain_height);
        return true;
    }

    // NOTE: Basic sanity checks
    if (!basic_block_checks(b, true /*alt_block*/)) {
        bvc.m_verifivation_failed = true;
        return false;
    }

    // NOTE: Reset timestamp/difficulty cache
    m_cache.m_timestamps_and_difficulties_height = 0;

    // NOTE: Build the alternative chain for checking reorg-ability
    std::list<block_extended_info> alt_chain;
    std::vector<uint64_t> timestamps;
    int num_checkpoints_on_alt_chain = 0;
    int num_checkpoints_on_chain = 0;
    if (!build_alt_chain(
                b.prev_id,
                alt_chain,
                timestamps,
                bvc,
                &num_checkpoints_on_alt_chain,
                &num_checkpoints_on_chain))
        return false;

    // NOTE: verify that the block's timestamp is within the acceptable range
    // (not earlier than the median of the last X blocks in the built alt chain)
    if (!check_block_timestamp(std::move(timestamps), b)) {
        log::error(
                log::Cat("verify"),
                "Block with id: {} for alternative chain, has invalid timestamp: {}",
                id,
                b.timestamp);
        bvc.m_verifivation_failed = true;
        return false;
    }

    bool const pulse_block = b.has_pulse();
    std::string_view block_type = pulse_block ? "PULSE"sv : "MINER"sv;

    // NOTE: Check proof of work
    block_pow_verified blk_pow = {};
    difficulty_type const current_diff =
            get_difficulty_for_alternative_chain(alt_chain, blk_height, pulse_block);
    if (pulse_block) {
        // NOTE: Pulse blocks don't use PoW. They use Service Node signatures.
        // Delay signature verification until Service Node List adds the block in
        // the block_add hook.
    } else {
        block_pow_verified const blk_pow =
                verify_block_pow(b, current_diff, chain_height, true /*alt_block*/);
        if (!blk_pow.valid) {
            bvc.m_verifivation_failed = true;
            return false;
        }
    }

    // NOTE: Calculate cumulative difficulty
    cryptonote::alt_block_data_t alt_data = {};
    {
        alt_data.cumulative_difficulty = current_diff;
        if (alt_chain.size())
            alt_data.cumulative_difficulty += prev_data.cumulative_difficulty;
        else  // passed-in block's previous block's cumulative difficulty, found on the main chain
            alt_data.cumulative_difficulty +=
                    m_db->get_block_cumulative_difficulty(m_db->get_block_height(b.prev_id));
    }

    // NOTE: Add alt block to DB storage and alt chain
    {
        CHECK_AND_ASSERT_MES(
                !m_db->get_alt_block(id, NULL, NULL, NULL),
                false,
                "insertion of new alternative block returned as it already exists");

        std::string checkpoint_blob;
        if (checkpoint) {
            alt_data.checkpointed = true;
            checkpoint_blob = t_serializable_object_to_blob(*checkpoint);
            num_checkpoints_on_alt_chain++;
        }

        alt_data.height = blk_height;
        alt_data.cumulative_weight = cryptonote::get_transaction_weight(b.miner_tx);
        for (const crypto::hash& txid : b.tx_hashes) {
            cryptonote::txpool_tx_meta_t tx_meta;
            std::string blob;
            if (db().get_txpool_tx_meta(txid, tx_meta)) {
                alt_data.cumulative_weight += tx_meta.weight;
            } else if (m_db->get_pruned_tx_blob(txid, blob)) {
                cryptonote::transaction tx;
                if (!cryptonote::parse_and_validate_tx_base_from_blob(blob, tx)) {
                    log::error(
                            log::Cat("verify"),
                            "Block with id: {} (as alternative) refers to unparsable transaction "
                            "hash {}.",
                            id,
                            txid);
                    bvc.m_verifivation_failed = true;
                    return false;
                }
                alt_data.cumulative_weight += cryptonote::get_pruned_transaction_weight(tx);
            } else {
                // we can't determine the block weight, set it to 0 and break out of the loop
                alt_data.cumulative_weight = 0;
                break;
            }
        }

        uint64_t block_reward = get_outs_money_amount(b.miner_tx);
        const uint64_t prev_generated_coins =
                alt_chain.size() ? prev_data.already_generated_coins
                                 : m_db->get_block_already_generated_coins(blk_height - 1);
        alt_data.already_generated_coins =
                (block_reward < (oxen::MONEY_SUPPLY - prev_generated_coins))
                        ? prev_generated_coins + block_reward
                        : oxen::MONEY_SUPPLY;
        m_db->add_alt_block(
                id,
                alt_data,
                cryptonote::block_to_blob(b),
                checkpoint_blob.empty() ? nullptr : &checkpoint_blob);

        // Check current height for pre-existing checkpoint
        bool height_is_checkpointed = false;
        bool alt_block_matches_checkpoint =
                m_checkpoints.check_block(alt_data.height, id, &height_is_checkpointed, nullptr);
        if (height_is_checkpointed) {
            if (!alt_block_matches_checkpoint)
                num_checkpoints_on_chain++;
        }

        alt_chain.push_back(block_extended_info(alt_data, b, checkpoint));
    }

    // NOTE: Block is within the allowable service node reorg window due to passing
    // is_alternative_block_allowed(). So we don't need to check that this block matches the
    // checkpoint unless it's a hardcoded checkpoint, in which case it must. Otherwise if it fails a
    // Service Node checkpoint that's fine because we're allowed to replace it in this window
    if (bool service_node_checkpoint = false;
        !checkpoint &&
        !m_checkpoints.check_block(blk_height, id, nullptr, &service_node_checkpoint)) {
        if (!service_node_checkpoint) {
            log::error(logcat, "CHECKPOINT VALIDATION FAILED FOR ALT BLOCK");
            bvc.m_verifivation_failed = true;
            return false;
        }
    }

    // NOTE: Execute Alt Block Hooks
    {
        std::vector<transaction> txs;
        std::unordered_set<crypto::hash> missed;
        if (!get_transactions(b.tx_hashes, txs, &missed)) {
            bvc.m_verifivation_failed = true;
            return false;
        }

        // NOTE: Foreign blocks will not necessarily have TX's stored in the main-db
        // (because they are not part of the main chain) but instead sitting in the
        // mempool.
        for (crypto::hash const& missed_tx : missed) {
            std::string blob;
            if (!tx_pool.get_transaction(missed_tx, blob)) {
                log::error(
                        log::Cat("verify"),
                        "Alternative block references unknown TX, rejected alt block {} {}",
                        blk_height,
                        id);
                return false;
            }

            transaction tx;
            if (!parse_and_validate_tx_from_blob(blob, tx)) {
                log::error(
                        log::Cat("verify"),
                        "Failed to parse block blob from tx pool when querying the missed "
                        "transactions in block {} {}",
                        blk_height,
                        id);
                return false;
            }

            txs.push_back(tx);
        }

        block_add_info hook_data{b, txs, checkpoint};
        for (const auto& hook : m_alt_block_add_hooks) {
            try {
                hook(hook_data);
            } catch (const std::exception& e) {
                log::info(logcat, "Failed to add alt block: {}", e.what());
                return false;
            }
        }
    }

    bool const alt_chain_has_more_checkpoints =
            (num_checkpoints_on_alt_chain > num_checkpoints_on_chain);
    bool const alt_chain_has_equal_checkpoints =
            (num_checkpoints_on_alt_chain == num_checkpoints_on_chain);

    if (b.major_version >= hf::hf16_pulse) {
        // In Pulse, we move away from the concept of difficulty to solve ties
        // between chains. We calculate the preferred chain using a simpler system.
        bool alt_chain_wins = alt_chain_has_more_checkpoints;
        if (!alt_chain_wins && alt_chain_has_equal_checkpoints) {
            uint64_t start = alt_chain.front().height;
            uint64_t end = std::max(alt_chain.back().height + 1, m_db->height());

            std::vector<block> blocks;
            if (!get_blocks(start, end - start, blocks, nullptr /*txs*/)) {
                log::error(
                        logcat,
                        "Unexpected failure to query blocks for alt chain switching calculation "
                        "from {} to {}",
                        start,
                        (end - 1));
                return false;
            }

            // Smallest number divisible by all integers from 1..32.  (This is fairly arbitrary,
            // but avoids remainders below in most cases, while being small enough that we can
            // add up a large number of blocks without risk of overflow).
            constexpr uint64_t PULSE_BASE_WEIGHT = 144403552893600ULL;

            // Minimal value increase for a longer chain so that two chains with the same cumulative
            // weight calculation below will marginally prefer the longer chain.  Also for mined
            // blocks we *only* get this longer chain value, effectively making mined blocks only
            // matter when there is no other chain contention.
            constexpr uint64_t MIN_WEIGHT_INCREMENT = 1;

            uint64_t alt_chain_weight = 0;
            for (auto const& block : alt_chain) {
                alt_chain_weight += MIN_WEIGHT_INCREMENT;
                if (block.bl.has_pulse())
                    alt_chain_weight += PULSE_BASE_WEIGHT /
                                        (1 + block.bl.pulse.round);  // (0-based pulse_round)
            }

            uint64_t main_chain_weight = 0;
            for (auto const& block : blocks) {
                main_chain_weight += MIN_WEIGHT_INCREMENT;
                if (block.has_pulse())
                    main_chain_weight += PULSE_BASE_WEIGHT / (1 + block.pulse.round);
            }

            alt_chain_wins = alt_chain_weight > main_chain_weight;
        }

        if (alt_chain_wins)  // More checkpoints or equal checkpoints and more weight
        {
            bool r = switch_to_alternative_blockchain(alt_chain, false /*keep_alt_chain*/);
            if (r)
                bvc.m_added_to_main_chain = true;
            else
                bvc.m_verifivation_failed = true;
            return r;
        } else {
            std::string msg = "----- {} BLOCK ADDED AS ALTERNATIVE ON HEIGHT {}\nid: {}"_format(
                    block_type, blk_height, id);
            if (!pulse_block)
                fmt::format_to(std::back_inserter(msg), " PoW: {}", blk_pow.proof_of_work);
            fmt::format_to(std::back_inserter(msg), " difficulty {}", current_diff);

            log::info(globallogcat, fg(fmt::terminal_color::blue) | fmt::emphasis::bold, "{}", msg);
            return true;
        }
    } else {
        difficulty_type const main_chain_cumulative_difficulty =
                m_db->get_block_cumulative_difficulty(m_db->height() - 1);
        bool const alt_chain_has_greater_pow =
                alt_data.cumulative_difficulty > main_chain_cumulative_difficulty;

        if (b.major_version >= hf::hf13_enforce_checkpoints) {
            if (alt_chain_has_more_checkpoints ||
                (alt_chain_has_greater_pow && alt_chain_has_equal_checkpoints)) {
                bool keep_alt_chain = false;
                if (alt_chain_has_more_checkpoints) {
                    log::info(
                            globallogcat,
                            fg(fmt::terminal_color::green),
                            "###### REORGANIZE on height: {} of {}, checkpoint is found in "
                            "alternative chain on height {}",
                            alt_chain.front().height,
                            m_db->height() - 1,
                            blk_height);
                } else {
                    keep_alt_chain = true;
                    log::info(
                            globallogcat,
                            fg(fmt::terminal_color::green),
                            "###### REORGANIZE on height: {} of {} with cum_difficulty {}\n "
                            "alternative blockchain size: {} with cum_difficulty {}",
                            alt_chain.front().height,
                            m_db->height() - 1,
                            m_db->get_block_cumulative_difficulty(m_db->height() - 1),
                            alt_chain.size(),
                            alt_data.cumulative_difficulty);
                }

                bool r = switch_to_alternative_blockchain(alt_chain, keep_alt_chain);
                if (r)
                    bvc.m_added_to_main_chain = true;
                else
                    bvc.m_verifivation_failed = true;
                return r;
            } else {
                log::info(
                        logcat,
                        fg(fmt::terminal_color::blue),
                        "----- {} BLOCK ADDED AS ALTERNATIVE ON HEIGHT "
                        "{}\nid:\t{}\nPoW:\t{}\ndifficulty:\t{}",
                        block_type,
                        blk_height,
                        id,
                        blk_pow.proof_of_work,
                        current_diff);
                return true;
            }
        } else {
            if (alt_chain_has_greater_pow) {
                log::info(
                        globallogcat,
                        fg(fmt::terminal_color::green),
                        "###### REORGANIZE on height: {} of {} with cum_difficulty {}\n "
                        "alternative blockchain size: {} with cum_difficulty {}",
                        alt_chain.front().height,
                        m_db->height() - 1,
                        m_db->get_block_cumulative_difficulty(m_db->height() - 1),
                        alt_chain.size(),
                        alt_data.cumulative_difficulty);
                bool r = switch_to_alternative_blockchain(alt_chain, true);
                if (r)
                    bvc.m_added_to_main_chain = true;
                else
                    bvc.m_verifivation_failed = true;
                return r;
            } else {
                log::info(
                        globallogcat,
                        fg(fmt::terminal_color::blue) | fmt::emphasis::bold,
                        "----- {} BLOCK ADDED AS ALTERNATIVE ON HEIGHT "
                        "{}\nid:\t{}\nPoW:\t{}\ndifficulty:\t{}",
                        block_type,
                        blk_height,
                        id,
                        blk_pow.proof_of_work,
                        current_diff);
                return true;
            }
        }
    }

    return true;
}
//------------------------------------------------------------------
bool Blockchain::get_blocks(
        uint64_t start_offset,
        size_t count,
        std::vector<block>& blocks,
        std::vector<std::string>* txs) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};
    const uint64_t height = m_db->height();
    if (start_offset >= height)
        return false;

    const size_t num_blocks = std::min<uint64_t>(height - start_offset, count);
    blocks.reserve(blocks.size() + num_blocks);
    for (size_t i = 0; i < num_blocks; i++) {
        try {
            blocks.emplace_back(m_db->get_block_from_height(start_offset + i));
        } catch (std::exception const& e) {
            log::error(logcat, "Invalid block at height {}. {}", start_offset + i, e.what());
            return false;
        }
    }

    if (txs) {
        for (const auto& blk : blocks) {
            std::unordered_set<crypto::hash> missed_ids;
            get_transactions_blobs(blk.tx_hashes, *txs, &missed_ids);
            CHECK_AND_ASSERT_MES(
                    !missed_ids.size(),
                    false,
                    "has missed transactions in own block in main blockchain");
        }
    }

    return true;
}
//------------------------------------------------------------------
bool Blockchain::get_blocks(
        uint64_t start_offset,
        size_t count,
        std::vector<std::pair<std::string, block>>& blocks,
        std::vector<std::string>& txs) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};
    if (start_offset >= m_db->height())
        return false;

    if (!get_blocks(start_offset, count, blocks)) {
        return false;
    }

    for (const auto& blk : blocks) {
        std::unordered_set<crypto::hash> missed_ids;
        get_transactions_blobs(blk.second.tx_hashes, txs, &missed_ids);
        CHECK_AND_ASSERT_MES(
                !missed_ids.size(),
                false,
                "has missed transactions in own block in main blockchain");
    }

    return true;
}
//------------------------------------------------------------------
bool Blockchain::get_blocks(
        uint64_t start_offset,
        size_t count,
        std::vector<std::pair<std::string, block>>& blocks) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};
    const uint64_t height = m_db->height();
    if (start_offset >= height)
        return false;

    const size_t num_blocks = std::min<uint64_t>(height - start_offset, count);
    blocks.reserve(blocks.size() + num_blocks);
    for (size_t i = 0; i < num_blocks; i++) {
        blocks.emplace_back(m_db->get_block_blob_from_height(start_offset + i), block{});
        if (!parse_and_validate_block_from_blob(blocks.back().first, blocks.back().second)) {
            log::error(logcat, "Invalid block");
            return false;
        }
    }
    return true;
}
//------------------------------------------------------------------
// TODO: This function *looks* like it won't need to be rewritten
//      to use BlockchainDB, as it calls other functions that were,
//      but it warrants some looking into later.
//
// FIXME: This function appears to want to return false if any transactions
//       that belong with blocks are missing, but not if blocks themselves
//       are missing.
bool Blockchain::handle_get_blocks(
        NOTIFY_REQUEST_GET_BLOCKS::request& arg, NOTIFY_RESPONSE_GET_BLOCKS::request& rsp) {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock blockchain_lock{m_blockchain_lock, std::defer_lock};
    auto blink_lock = tx_pool.blink_shared_lock(std::defer_lock);
    std::lock(blockchain_lock, blink_lock);

    db_rtxn_guard rtxn_guard{*m_db};
    rsp.current_blockchain_height = get_current_blockchain_height();
    std::vector<std::pair<std::string, block>> blocks;
    {
        std::unordered_set<crypto::hash> missed_ids;
        get_blocks(arg.blocks, blocks, &missed_ids);
        rsp.missed_ids.insert(rsp.missed_ids.end(), missed_ids.begin(), missed_ids.end());
    }

    uint64_t const top_height = (m_db->height() - 1);
    uint64_t const earliest_height_to_sync_checkpoints_granularly =
            (top_height < service_nodes::CHECKPOINT_STORE_PERSISTENTLY_INTERVAL)
                    ? 0
                    : top_height - service_nodes::CHECKPOINT_STORE_PERSISTENTLY_INTERVAL;

    for (auto& bl : blocks) {
        auto& block_blob = bl.first;
        auto& block = bl.second;

        rsp.blocks.push_back(block_complete_entry());
        block_complete_entry& block_entry = rsp.blocks.back();

        uint64_t const block_height = block.get_height();
        uint64_t checkpoint_interval = service_nodes::CHECKPOINT_STORE_PERSISTENTLY_INTERVAL;
        if (block_height >= earliest_height_to_sync_checkpoints_granularly)
            checkpoint_interval = service_nodes::CHECKPOINT_INTERVAL;

        if ((block_height % checkpoint_interval) == 0) {
            try {
                checkpoint_t checkpoint;
                if (get_checkpoint(block_height, checkpoint))
                    block_entry.checkpoint = t_serializable_object_to_blob(checkpoint);
            } catch (const std::exception& e) {
                log::error(
                        logcat,
                        "Get block checkpoint from DB failed non-trivially at height: {}, what = "
                        "{}",
                        block_height,
                        e.what());
                return false;
            }
        }

        // FIXME: s/rsp.missed_ids/missed_tx_id/ ?  Seems like rsp.missed_ids
        //        is for missed blocks, not missed transactions as well.
        std::unordered_set<crypto::hash> missed_tx_ids;
        get_transactions_blobs(block.tx_hashes, block_entry.txs, &missed_tx_ids);

        for (auto& h : block.tx_hashes) {
            if (auto blink = tx_pool.get_blink(h)) {
                auto l = blink->shared_lock();
                block_entry.blinks.emplace_back();
                blink->fill_serialization_data(block_entry.blinks.back());
            }
        }

        if (missed_tx_ids.size() != 0) {
            // do not display an error if the peer asked for an unpruned block which we are not
            // meant to have
            if (tools::has_unpruned_block(
                        block.get_height(),
                        get_current_blockchain_height(),
                        get_blockchain_pruning_seed())) {
                log::error(
                        logcat,
                        "Error retrieving blocks, missed {} transactions for block with hash: {}",
                        missed_tx_ids.size(),
                        get_block_hash(block));
            }

            rsp.missed_ids.insert(rsp.missed_ids.end(), missed_tx_ids.begin(), missed_tx_ids.end());
            return false;
        }

        // pack block
        block_entry.block = std::move(block_blob);
    }

    return true;
}
//------------------------------------------------------------------
bool Blockchain::handle_get_txs(
        NOTIFY_REQUEST_GET_TXS::request& arg, NOTIFY_NEW_TRANSACTIONS::request& rsp) {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock blockchain_lock{m_blockchain_lock, std::defer_lock};
    auto blink_lock = tx_pool.blink_shared_lock(std::defer_lock);
    std::lock(blockchain_lock, blink_lock);

    db_rtxn_guard rtxn_guard{*m_db};
    std::unordered_set<crypto::hash> missed;

    // First check the blockchain for any txs:
    get_transactions_blobs(arg.txs, rsp.txs, &missed);

    // Look for any missed txes in the mempool:
    tx_pool.find_transactions(missed, rsp.txs);

    for (auto& h : arg.txs) {
        if (auto blink = tx_pool.get_blink(h)) {
            rsp.blinks.emplace_back();
            auto l = blink->shared_lock();
            blink->fill_serialization_data(rsp.blinks.back());
        }
    }

    return true;
}
//------------------------------------------------------------------
bool Blockchain::get_alternative_blocks(std::vector<block>& blocks) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    blocks.reserve(m_db->get_alt_block_count());
    m_db->for_all_alt_blocks(
            [&blocks](
                    const crypto::hash& /*blkid*/,
                    const cryptonote::alt_block_data_t& /*data*/,
                    const std::string* block_blob,
                    const std::string* /*checkpoint_blob*/) {
                if (!block_blob) {
                    log::error(logcat, "No blob, but blobs were requested");
                    return false;
                }
                cryptonote::block bl;
                if (cryptonote::parse_and_validate_block_from_blob(*block_blob, bl))
                    blocks.push_back(std::move(bl));
                else
                    log::error(logcat, "Failed to parse block from blob");
                return true;
            },
            true);
    return true;
}
//------------------------------------------------------------------
size_t Blockchain::get_alternative_blocks_count() const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};
    return m_db->get_alt_block_count();
}
//------------------------------------------------------------------
// This function adds the output specified by <amount, i> to the result_outs container
// unlocked and other such checks should be done by here.
uint64_t Blockchain::get_num_mature_outputs(uint64_t amount) const {
    uint64_t num_outs = m_db->get_num_outputs(amount);
    // ensure we don't include outputs that aren't yet eligible to be used
    // outpouts are sorted by height
    const uint64_t blockchain_height = m_db->height();
    while (num_outs > 0) {
        const tx_out_index toi = m_db->get_output_tx_and_index(amount, num_outs - 1);
        const uint64_t height = m_db->get_tx_block_height(toi.first);
        if (height + DEFAULT_TX_SPENDABLE_AGE <= blockchain_height)
            break;
        --num_outs;
    }

    return num_outs;
}

crypto::public_key Blockchain::get_output_key(uint64_t amount, uint64_t global_index) const {
    output_data_t data = m_db->get_output_key(amount, global_index);
    return data.pubkey;
}

//------------------------------------------------------------------
bool Blockchain::get_outs(
        const rpc::GET_OUTPUTS_BIN::request& req, rpc::GET_OUTPUTS_BIN::response& res) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    res.outs.clear();
    res.outs.reserve(req.outputs.size());

    std::vector<cryptonote::output_data_t> data;
    try {
        std::vector<uint64_t> amounts, offsets;
        amounts.reserve(req.outputs.size());
        offsets.reserve(req.outputs.size());
        for (const auto& i : req.outputs) {
            amounts.push_back(i.amount);
            offsets.push_back(i.index);
        }
        m_db->get_output_key(
                epee::span<const uint64_t>(amounts.data(), amounts.size()), offsets, data);
        if (data.size() != req.outputs.size()) {
            log::error(
                    logcat,
                    "Unexpected output data size: expected {}, got {}",
                    req.outputs.size(),
                    data.size());
            return false;
        }
        for (const auto& t : data)
            res.outs.push_back(
                    {t.pubkey,
                     t.commitment,
                     is_output_spendtime_unlocked(t.unlock_time),
                     t.height,
                     crypto::null<crypto::hash>});

        if (req.get_txid) {
            for (size_t i = 0; i < req.outputs.size(); ++i) {
                tx_out_index toi =
                        m_db->get_output_tx_and_index(req.outputs[i].amount, req.outputs[i].index);
                res.outs[i].txid = toi.first;
            }
        }
    } catch (const std::exception& e) {
        return false;
    }
    return true;
}
//------------------------------------------------------------------
void Blockchain::get_output_key_mask_unlocked(
        const uint64_t& amount,
        const uint64_t& index,
        crypto::public_key& key,
        rct::key& mask,
        bool& unlocked) const {
    const auto o_data = m_db->get_output_key(amount, index);
    key = o_data.pubkey;
    mask = o_data.commitment;
    unlocked = is_output_spendtime_unlocked(o_data.unlock_time);
}
//------------------------------------------------------------------
bool Blockchain::get_output_distribution(
        uint64_t amount,
        uint64_t from_height,
        uint64_t to_height,
        uint64_t& start_height,
        std::vector<uint64_t>& distribution,
        uint64_t& base) const {
    // rct outputs don't exist before v4, NOTE(oxen): we started from v7 so our start is always 0
    start_height = 0;
    base = 0;

    if (to_height > 0 && to_height < from_height)
        return false;

    if (from_height > start_height)
        start_height = from_height;

    distribution.clear();
    uint64_t db_height = m_db->height();
    if (db_height == 0)
        return false;
    if (start_height >= db_height || to_height >= db_height)
        return false;

    if (amount == 0) {
        std::vector<uint64_t> heights;
        heights.reserve(to_height + 1 - start_height);
        const uint64_t real_start_height = start_height > 0 ? start_height - 1 : start_height;
        for (uint64_t h = real_start_height; h <= to_height; ++h)
            heights.push_back(h);
        distribution = m_db->get_block_cumulative_rct_outputs(heights);
        if (start_height > 0) {
            base = distribution[0];
            distribution.erase(distribution.begin());
        }
        return true;
    } else {
        return m_db->get_output_distribution(amount, start_height, to_height, distribution, base);
    }
}
//------------------------------------------------------------------
void Blockchain::get_output_blacklist(std::vector<uint64_t>& blacklist) const {
    m_db->get_output_blacklist(blacklist);
}
//------------------------------------------------------------------
// This function takes a list of block hashes from another node
// on the network to find where the split point is between us and them.
// This is used to see what to send another node that needs to sync.
bool Blockchain::find_blockchain_supplement(
        const std::list<crypto::hash>& qblock_ids, uint64_t& starter_offset) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    // make sure the request includes at least the genesis block, otherwise
    // how can we expect to sync from the client that the block list came from?
    if (qblock_ids.empty()) {
        log::info(
                log::Cat("net.p2p"),
                "Client sent wrong NOTIFY_REQUEST_CHAIN: m_block_ids.size()={}, dropping "
                "connection",
                qblock_ids.size());
        return false;
    }

    db_rtxn_guard rtxn_guard{*m_db};
    // make sure that the last block in the request's block list matches
    // the genesis block
    auto gen_hash = m_db->get_block_hash_from_height(0);
    if (qblock_ids.back() != gen_hash) {
        log::info(
                log::Cat("net.p2p"),
                "Client sent wrong NOTIFY_REQUEST_CHAIN: genesis block mismatch: id: {}, expected: "
                "{}, dropping connection",
                qblock_ids.back(),
                gen_hash);
        return false;
    }

    // Find the first block the foreign chain has that we also have.
    // Assume qblock_ids is in reverse-chronological order.
    auto bl_it = qblock_ids.begin();
    uint64_t split_height = 0;
    for (; bl_it != qblock_ids.end(); bl_it++) {
        try {
            if (m_db->block_exists(*bl_it, &split_height))
                break;
        } catch (const std::exception& e) {
            log::warning(
                    logcat,
                    "Non-critical error trying to find block by hash in BlockchainDB, hash: {}",
                    *bl_it);
            return false;
        }
    }

    // this should be impossible, as we checked that we share the genesis block,
    // but just in case...
    if (bl_it == qblock_ids.end()) {
        log::error(logcat, "Internal error handling connection, can't find split point");
        return false;
    }

    // we start to put block ids INCLUDING last known id, just to make other side be sure
    starter_offset = split_height;
    return true;
}
//------------------------------------------------------------------
uint64_t Blockchain::block_difficulty(uint64_t i) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
    // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
    // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
    // lock if it is otherwise needed.
    try {
        return m_db->get_block_difficulty(i);
    } catch (const BLOCK_DNE& e) {
        log::error(logcat, "Attempted to get block difficulty for height above blockchain height");
    }
    return 0;
}
//------------------------------------------------------------------
// TODO: return type should be void, throw on exception
//       alternatively, return true only if no blocks missed
bool Blockchain::get_blocks(
        const std::vector<crypto::hash>& block_ids,
        std::vector<std::pair<std::string, block>>& blocks,
        std::unordered_set<crypto::hash>* missed_bs) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    blocks.reserve(block_ids.size());
    for (const auto& block_hash : block_ids) {
        try {
            uint64_t height = 0;
            if (m_db->block_exists(block_hash, &height)) {
                blocks.push_back(std::make_pair(m_db->get_block_blob_from_height(height), block()));
                if (!parse_and_validate_block_from_blob(
                            blocks.back().first, blocks.back().second)) {
                    log::error(logcat, "Invalid block: {}", block_hash);
                    blocks.pop_back();
                    if (missed_bs)
                        missed_bs->insert(block_hash);
                }
            } else if (missed_bs)
                missed_bs->insert(block_hash);
        } catch (const std::exception& e) {
            return false;
        }
    }
    return true;
}
//------------------------------------------------------------------
// TODO: return type should be void, throw on exception
//       alternatively, return true only if no transactions missed
bool Blockchain::get_transactions_blobs(
        const std::vector<crypto::hash>& txs_ids,
        std::vector<std::string>& txs,
        std::unordered_set<crypto::hash>* missed_txs,
        bool pruned) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    txs.reserve(txs_ids.size());
    for (const auto& tx_hash : txs_ids) {
        try {
            std::string tx;
            if (pruned && m_db->get_pruned_tx_blob(tx_hash, tx))
                txs.push_back(std::move(tx));
            else if (!pruned && m_db->get_tx_blob(tx_hash, tx))
                txs.push_back(std::move(tx));
            else if (missed_txs)
                missed_txs->insert(tx_hash);
        } catch (const std::exception& e) {
            return false;
        }
    }
    return true;
}
//------------------------------------------------------------------
std::vector<uint64_t> Blockchain::get_transactions_heights(
        const std::vector<crypto::hash>& txs_ids) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    auto heights = m_db->get_tx_block_heights(txs_ids);
    for (auto& h : heights)
        if (h == std::numeric_limits<uint64_t>::max())
            h = 0;

    return heights;
}
//------------------------------------------------------------------
size_t get_transaction_version(const std::string& bd) {
    size_t version;
    const char* begin = static_cast<const char*>(bd.data());
    const char* end = begin + bd.size();
    int read = tools::read_varint(begin, end, version);
    if (read <= 0)
        throw oxen::traced<std::runtime_error>("Internal error getting transaction version");
    return version;
}
//------------------------------------------------------------------
bool Blockchain::get_split_transactions_blobs(
        const std::vector<crypto::hash>& txs_ids,
        std::vector<std::tuple<crypto::hash, std::string, crypto::hash, std::string>>& txs,
        std::unordered_set<crypto::hash>* missed_txs) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    txs.reserve(txs_ids.size());
    for (const auto& tx_hash : txs_ids) {
        try {
            std::string tx;
            if (m_db->get_pruned_tx_blob(tx_hash, tx)) {
                auto& [hash, pruned, pruned_hash, prunable] = txs.emplace_back(
                        tx_hash, std::move(tx), crypto::null<crypto::hash>, std::string());
                if (!is_v1_tx(pruned) && !m_db->get_prunable_tx_hash(tx_hash, pruned_hash)) {
                    log::error(logcat, "Prunable data hash not found for {}", tx_hash);
                    return false;
                }
                if (!m_db->get_prunable_tx_blob(tx_hash, prunable))
                    prunable.clear();
            } else if (missed_txs)
                missed_txs->insert(tx_hash);
        } catch (const std::exception& e) {
            return false;
        }
    }
    return true;
}
//------------------------------------------------------------------
bool Blockchain::get_transactions(
        const std::vector<crypto::hash>& txs_ids,
        std::vector<transaction>& txs,
        std::unordered_set<crypto::hash>* missed_txs) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    txs.reserve(txs_ids.size());
    std::string tx;
    for (const auto& tx_hash : txs_ids) {
        tx.clear();
        try {
            if (m_db->get_tx_blob(tx_hash, tx)) {
                txs.emplace_back();
                if (!parse_and_validate_tx_from_blob(tx, txs.back())) {
                    log::error(logcat, "Invalid transaction");
                    return false;
                }
            } else if (missed_txs)
                missed_txs->insert(tx_hash);
        } catch (const std::exception& e) {
            return false;
        }
    }
    return true;
}
//------------------------------------------------------------------
// Find the split point between us and foreign blockchain and return
// (by reference) the most recent common block hash along with up to
// BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT additional (more recent) hashes.
bool Blockchain::find_blockchain_supplement(
        const std::list<crypto::hash>& qblock_ids,
        std::vector<crypto::hash>& hashes,
        uint64_t& start_height,
        uint64_t& current_height,
        bool clip_pruned) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    // if we can't find the split point, return false
    if (!find_blockchain_supplement(qblock_ids, start_height)) {
        return false;
    }

    db_rtxn_guard rtxn_guard{*m_db};
    current_height = get_current_blockchain_height();
    uint64_t stop_height = current_height;
    if (clip_pruned) {
        const uint32_t pruning_seed = get_blockchain_pruning_seed();
        start_height =
                tools::get_next_unpruned_block_height(start_height, current_height, pruning_seed);
        stop_height =
                tools::get_next_pruned_block_height(start_height, current_height, pruning_seed);
    }
    size_t count = 0;
    hashes.reserve(
            std::min((size_t)(stop_height - start_height), BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT));
    for (size_t i = start_height; i < stop_height && count < BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT;
         i++, count++) {
        hashes.push_back(m_db->get_block_hash_from_height(i));
    }

    return true;
}

bool Blockchain::find_blockchain_supplement(
        const std::list<crypto::hash>& qblock_ids,
        NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    bool result = find_blockchain_supplement(
            qblock_ids, resp.m_block_ids, resp.start_height, resp.total_height, true);
    if (result)
        resp.cumulative_difficulty = m_db->get_block_cumulative_difficulty(resp.total_height - 1);

    return result;
}
//------------------------------------------------------------------
// FIXME: change argument to std::vector, low priority
// find split point between ours and foreign blockchain (or start at
// blockchain height <req_start_block>), and return up to max_count FULL
// blocks by reference.
bool Blockchain::find_blockchain_supplement(
        const uint64_t req_start_block,
        const std::list<crypto::hash>& qblock_ids,
        std::vector<BlockData>& blocks,
        uint64_t& total_height,
        uint64_t& start_height,
        bool pruned,
        bool get_miner_tx_hash,
        size_t max_count) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    // if a specific start height has been requested
    if (req_start_block > 0) {
        // if requested height is higher than our chain, return false -- we can't help
        if (req_start_block >= m_db->height()) {
            return false;
        }
        start_height = req_start_block;
    } else {
        if (!find_blockchain_supplement(qblock_ids, start_height)) {
            return false;
        }
    }

    db_rtxn_guard rtxn_guard{*m_db};
    total_height = get_current_blockchain_height();
    size_t count = 0, size = 0;
    blocks.reserve(
            std::min(std::min(max_count, (size_t)10000), (size_t)(total_height - start_height)));
    for (uint64_t i = start_height; i < total_height && count < max_count &&
                                    (size < FIND_BLOCKCHAIN_SUPPLEMENT_MAX_SIZE || count < 3);
         i++, count++) {
        auto& bd = blocks.emplace_back();
        bd.block_blob = m_db->get_block_blob_from_height(i);
        block b;
        CHECK_AND_ASSERT_MES(
                parse_and_validate_block_from_blob(bd.block_blob, b),
                false,
                "internal error, invalid block");
        bd.miner_tx_hash = get_miner_tx_hash && b.miner_tx
                                 ? cryptonote::get_transaction_hash(*b.miner_tx)
                                 : crypto::null<crypto::hash>;
        std::vector<std::string> txs;
        if (pruned) {
            CHECK_AND_ASSERT_MES(
                    m_db->get_pruned_tx_blobs_from(b.tx_hashes.front(), b.tx_hashes.size(), txs),
                    false,
                    "Failed to retrieve all transactions needed");
        } else {
            std::unordered_set<crypto::hash> mis;
            get_transactions_blobs(b.tx_hashes, txs, &mis, pruned);
            CHECK_AND_ASSERT_MES(
                    mis.empty(), false, "internal error, transaction from block not found");
        }
        size += bd.block_blob.size();
        for (const auto& t : txs)
            size += t.size();

        CHECK_AND_ASSERT_MES(
                txs.size() == b.tx_hashes.size(), false, "mismatched sizes of b.tx_hashes and txs");
        bd.txs.reserve(txs.size());
        for (size_t i = 0; i < txs.size(); ++i)
            bd.txs.emplace_back(b.tx_hashes[i], std::move(txs[i]));
    }
    return true;
}
//------------------------------------------------------------------
bool Blockchain::add_block_as_invalid(cryptonote::block const& block) {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};
    auto i_res = m_invalid_blocks.insert(get_block_hash(block));
    CHECK_AND_ASSERT_MES(i_res.second, false, "at insertion invalid block returned status failed");
    log::info(
            logcat,
            "BLOCK ADDED AS INVALID: {}\n, prev_id={}, m_invalid_blocks count={}",
            (*i_res.first),
            block.prev_id,
            m_invalid_blocks.size());
    return true;
}

hf Blockchain::get_network_version(std::optional<uint64_t> height) const {
    if (!height)
        height = get_current_blockchain_height();
    return cryptonote::get_network_version(m_nettype, *height);
}

cryptonote::BlockchainSQLite& Blockchain::sqlite_db() {
    return *m_sqlite_db;
}

//------------------------------------------------------------------
void Blockchain::flush_invalid_blocks() {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};
    m_invalid_blocks.clear();
}
//------------------------------------------------------------------
bool Blockchain::have_block(const crypto::hash& id) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    if (m_db->block_exists(id)) {
        log::debug(logcat, "block {} found in main chain", id);
        return true;
    }

    if (m_db->get_alt_block(id, NULL, NULL, NULL)) {
        log::debug(logcat, "block {} found in alternative chains", id);
        return true;
    }

    if (m_invalid_blocks.count(id)) {
        log::debug(logcat, "block {} found in m_invalid_blocks", id);
        return true;
    }

    return false;
}
//------------------------------------------------------------------
size_t Blockchain::get_total_transactions() const {
    log::trace(logcat, "Blockchain::{}", __func__);
    // WARNING: this function does not take m_blockchain_lock, and thus should only call read only
    // m_db functions which do not depend on one another (ie, no getheight + gethash(height-1), as
    // well as not accessing class members, even read only (ie, m_invalid_blocks). The caller must
    // lock if it is otherwise needed.

    return m_db->get_tx_count();
}
//------------------------------------------------------------------
// This function checks each input in the transaction <tx> to make sure it
// has not been used already, and adds its key to the container <keys_this_block>.
//
// This container should be managed by the code that validates blocks so we don't
// have to store the used keys in a given block in the permanent storage only to
// remove them later if the block fails validation.
bool Blockchain::check_for_double_spend(
        const transaction& tx, key_images_container& keys_this_block) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};
    auto add_transaction_input_visitor = [&keys_this_block, this]<typename T>(const T& in) {
        if constexpr (std::is_same_v<T, txin_to_key>) {
            // attempt to insert the newly-spent key into the container of
            // keys spent this block.  If this fails, the key was spent already
            // in this block, return false to flag that a double spend was detected.
            //
            // if the insert into the block-wide spent keys container succeeds,
            // check the blockchain-wide spent keys container and make sure the
            // key wasn't used in another block already.
            auto r = keys_this_block.insert(in.k_image);
            return r.second && !m_db->has_key_image(in.k_image);
        } else if constexpr (std::is_same_v<T, txin_gen>)
            return true;
        else  // txin_to_script*
            return false;
    };

    for (const txin_v& in : tx.vin) {
        if (!var::visit(add_transaction_input_visitor, in)) {
            log::error(logcat, "Double spend detected!");
            return false;
        }
    }

    return true;
}
//------------------------------------------------------------------
bool Blockchain::get_tx_outputs_gindexs(
        const crypto::hash& tx_id,
        size_t n_txes,
        std::vector<std::vector<uint64_t>>& indexs) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};
    uint64_t tx_index;
    if (!m_db->tx_exists(tx_id, tx_index)) {
        log::error(
                log::Cat("verify"),
                "get_tx_outputs_gindexs failed to find transaction with id = {}",
                tx_id);
        return false;
    }
    indexs = m_db->get_tx_amount_output_indices(tx_index, n_txes);
    CHECK_AND_ASSERT_MES(n_txes == indexs.size(), false, "Wrong indexs size");

    return true;
}
//------------------------------------------------------------------
bool Blockchain::get_tx_outputs_gindexs(
        const crypto::hash& tx_id, std::vector<uint64_t>& indexs) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};
    uint64_t tx_index;
    if (!m_db->tx_exists(tx_id, tx_index)) {
        log::error(
                log::Cat("verify"),
                "get_tx_outputs_gindexs failed to find transaction with id = {}",
                tx_id);
        return false;
    }
    std::vector<std::vector<uint64_t>> indices = m_db->get_tx_amount_output_indices(tx_index, 1);
    CHECK_AND_ASSERT_MES(indices.size() == 1, false, "Wrong indices size");
    indexs = indices.front();
    return true;
}
//------------------------------------------------------------------
void Blockchain::on_new_tx_from_block(const cryptonote::transaction& tx) {
#if defined(PER_BLOCK_CHECKPOINT)
    // check if we're doing per-block checkpointing
    if (m_db->height() < m_blocks_hash_check.size()) {
        auto a = std::chrono::steady_clock::now();
        m_blocks_txs_check.push_back(get_transaction_hash(tx));
        if (m_show_time_stats) {
            size_t ring_size = 0;
            if (!tx.vin.empty() && std::holds_alternative<txin_to_key>(tx.vin[0]))
                ring_size = var::get<txin_to_key>(tx.vin[0]).key_offsets.size();
            log::info(
                    logcat,
                    "HASH: - I/M/O: {}/{}/{} H: {} chcktx: {}",
                    tx.vin.size(),
                    ring_size,
                    tx.vout.size(),
                    0,
                    tools::friendly_duration(std::chrono::steady_clock::now() - a));
        }
    }
#endif
}
//------------------------------------------------------------------
// FIXME: it seems this function is meant to be merely a wrapper around
//       another function of the same name, this one adding one bit of
//       functionality.  Should probably move anything more than that
//       (getting the hash of the block at height max_used_block_id)
//       to the other function to keep everything in one place.
// This function overloads its sister function with
// an extra value (hash of highest block that holds an output used as input)
// as a return-by-reference.
bool Blockchain::check_tx_inputs(
        transaction& tx,
        tx_verification_context& tvc,
        crypto::hash& max_used_block_id,
        uint64_t& max_used_block_height,
        std::unordered_set<crypto::key_image>* key_image_conflicts,
        bool kept_by_block) {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

#if defined(PER_BLOCK_CHECKPOINT)
    // check if we're doing per-block checkpointing
    if (m_db->height() < m_blocks_hash_check.size() && kept_by_block) {
        max_used_block_id = null<hash>;
        max_used_block_height = 0;
        return true;
    }
#endif

    auto a = std::chrono::steady_clock::now();
    bool res = check_tx_inputs(tx, tvc, &max_used_block_height, key_image_conflicts);
    if (m_show_time_stats) {
        size_t ring_size = 0;
        if (!tx.vin.empty() && std::holds_alternative<txin_to_key>(tx.vin[0]))
            ring_size = var::get<txin_to_key>(tx.vin[0]).key_offsets.size();
        log::info(
                logcat,
                "HASH: {} I/M/O: {}/{}/{} H: {} ms: {} B: {} W: {}",
                get_transaction_hash(tx),
                tx.vin.size(),
                ring_size,
                tx.vout.size(),
                max_used_block_height,
                tools::friendly_duration(std::chrono::steady_clock::now() - a + m_fake_scan_time),
                get_object_blobsize(tx),
                get_transaction_weight(tx));
    }
    if (!res)
        return false;

    CHECK_AND_ASSERT_MES(
            max_used_block_height < m_db->height(),
            false,
            "internal error: max used block index={} is not less than blockchain size={}",
            max_used_block_height,
            m_db->height());
    max_used_block_id = max_used_block_height
                              ? m_db->get_block_hash_from_height(max_used_block_height)
                              : crypto::null<hash>;
    return true;
}
//------------------------------------------------------------------
bool Blockchain::check_tx_outputs(const transaction& tx, tx_verification_context& tvc) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    std::unique_lock lock{*this};

    for (const auto& o : tx.vout) {
        if (o.amount != 0) {  // in a v2 tx, all outputs must have 0 amount NOTE(oxen): All oxen
                              // tx's are atleast v2 from the beginning
            tvc.m_invalid_output = true;
            return false;
        }

        // from hardfork v4, forbid invalid pubkeys NOTE(oxen): We started from hf7 so always
        // execute branch
        if (auto* out_to_key = std::get_if<txout_to_key>(&o.target);
            out_to_key && !crypto::check_key(out_to_key->key)) {
            tvc.m_invalid_output = true;
            return false;
        }
    }

    // Test suite hack: allow some tests to violate these restrictions (necessary when old HF rules
    // are specifically required because older TX types can't be constructed anymore).
    if (hack::test_suite_permissive_txes)
        return true;

    // from v10, allow bulletproofs
    auto height = get_current_blockchain_height();
    const auto hf_version = get_network_version(height);
    if (hf_version < hf::hf10_bulletproofs) {
        const bool bulletproof = rct::is_rct_bulletproof(tx.rct_signatures.type);
        if (bulletproof || !tx.rct_signatures.p.bulletproofs.empty()) {
            log::error(log::Cat("verify"), "Bulletproofs are not allowed before v10");
            tvc.m_invalid_output = true;
            return false;
        }
    } else if (rct::is_rct_borromean(tx.rct_signatures.type)) {
        // The HF10 block height itself was allowed to (and did) have a Borromean tx as an exception
        // to the HF10 rules so that a borderline tx didn't end up unmineable, hence the strict `>`
        // here:
        if (auto hf10_height = hard_fork_begins(m_nettype, hf::hf10_bulletproofs);
            hf10_height && height > *hf10_height) {
            log::error(log::Cat("verify"), "Borromean range proofs are not allowed after v10");
            tvc.m_invalid_output = true;
            return false;
        }
    }

    if (hf_version < feature::SMALLER_BP) {
        if (tx.rct_signatures.type == rct::RCTType::Bulletproof2) {
            log::error(
                    log::Cat("verify"),
                    "Ringct type {} is not allowed before v{}",
                    (unsigned)rct::RCTType::Bulletproof2,
                    static_cast<int>(feature::SMALLER_BP));
            tvc.m_invalid_output = true;
            return false;
        }
    }

    if (hf_version > feature::SMALLER_BP) {
        if (tx.version >= txversion::v4_tx_types && tx.is_transfer()) {
            if (tx.rct_signatures.type == rct::RCTType::Bulletproof) {
                log::error(
                        log::Cat("verify"),
                        "Ringct type {} is not allowed after v{}",
                        (unsigned)rct::RCTType::Bulletproof,
                        static_cast<int>(feature::SMALLER_BP));
                tvc.m_invalid_output = true;
                return false;
            }
        }
    }

    // Disallow CLSAGs before the CLSAG hardfork
    if (hf_version < feature::CLSAG) {
        if (tx.version >= txversion::v4_tx_types && tx.is_transfer()) {
            if (tx.rct_signatures.type == rct::RCTType::CLSAG) {
                log::error(
                        log::Cat("verify"),
                        "Ringct type {} is not allowed before v{}",
                        (unsigned)rct::RCTType::CLSAG,
                        static_cast<int>(feature::CLSAG));
                tvc.m_invalid_output = true;
                return false;
            }
        }
    }

    // Require CLSAGs starting 10 blocks after the CLSAG-enabling hard fork (the 10 block buffer is
    // to allow staggling txes around fork time to still make it into a block). NB: there *are* such
    // txes on mainnet in this 10-block window so this code has to stay.
    if (hf_version >= feature::CLSAG && tx.rct_signatures.type < rct::RCTType::CLSAG &&
        tx.version >= txversion::v4_tx_types && tx.is_transfer() &&
        (hf_version > feature::CLSAG ||
         height >= 10 + *hard_fork_begins(m_nettype, feature::CLSAG))) {
        log::error(
                log::Cat("verify"),
                "Ringct type {} is not allowed from v{}",
                (unsigned)tx.rct_signatures.type,
                static_cast<int>(feature::CLSAG));
        tvc.m_invalid_output = true;
        return false;
    }

    return true;
}
//------------------------------------------------------------------
bool Blockchain::have_tx_keyimges_as_spent(const transaction& tx) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    if (!tx.is_miner_tx()) {
        for (const txin_v& in : tx.vin) {
            CHECKED_GET_SPECIFIC_VARIANT(in, txin_to_key, in_to_key, true);
            if (have_tx_keyimg_as_spent(in_to_key.k_image))
                return true;
        }
    }
    return false;
}
bool Blockchain::expand_transaction_2(
        transaction& tx,
        const crypto::hash& tx_prefix_hash,
        const std::vector<std::vector<rct::ctkey>>& pubkeys) const {
    CHECK_AND_ASSERT_MES(
            tx.version >= txversion::v2_ringct, false, "Transaction version is not 2 or greater");

    rct::rctSig& rv = tx.rct_signatures;

    // message - hash of the transaction prefix
    rv.message = rct::hash2rct(tx_prefix_hash);

    // mixRing - full and simple store it in opposite ways
    if (rv.type == rct::RCTType::Full) {
        CHECK_AND_ASSERT_MES(!pubkeys.empty() && !pubkeys[0].empty(), false, "empty pubkeys");
        rv.mixRing.resize(pubkeys[0].size());
        for (size_t m = 0; m < pubkeys[0].size(); ++m)
            rv.mixRing[m].clear();
        for (size_t n = 0; n < pubkeys.size(); ++n) {
            CHECK_AND_ASSERT_MES(
                    pubkeys[n].size() <= pubkeys[0].size(), false, "More inputs that first ring");
            for (size_t m = 0; m < pubkeys[n].size(); ++m) {
                rv.mixRing[m].push_back(pubkeys[n][m]);
            }
        }
    } else if (tools::equals_any(
                       rv.type,
                       rct::RCTType::Simple,
                       rct::RCTType::Bulletproof,
                       rct::RCTType::Bulletproof2,
                       rct::RCTType::CLSAG)) {
        CHECK_AND_ASSERT_MES(!pubkeys.empty() && !pubkeys[0].empty(), false, "empty pubkeys");
        rv.mixRing.resize(pubkeys.size());
        for (size_t n = 0; n < pubkeys.size(); ++n) {
            rv.mixRing[n].clear();
            for (size_t m = 0; m < pubkeys[n].size(); ++m) {
                rv.mixRing[n].push_back(pubkeys[n][m]);
            }
        }
    } else {
        CHECK_AND_ASSERT_MES(
                false,
                false,
                "Unsupported rct tx type: {}",
                std::underlying_type_t<rct::RCTType>(rv.type));
    }

    // II
    if (rv.type == rct::RCTType::Full) {
        rv.p.MGs.resize(1);
        rv.p.MGs[0].II.resize(tx.vin.size());
        for (size_t n = 0; n < tx.vin.size(); ++n)
            rv.p.MGs[0].II[n] = rct::ki2rct(var::get<txin_to_key>(tx.vin[n]).k_image);
    } else if (tools::equals_any(
                       rv.type,
                       rct::RCTType::Simple,
                       rct::RCTType::Bulletproof,
                       rct::RCTType::Bulletproof2)) {
        CHECK_AND_ASSERT_MES(rv.p.MGs.size() == tx.vin.size(), false, "Bad MGs size");
        for (size_t n = 0; n < tx.vin.size(); ++n) {
            rv.p.MGs[n].II.resize(1);
            rv.p.MGs[n].II[0] = rct::ki2rct(var::get<txin_to_key>(tx.vin[n]).k_image);
        }
    } else if (rv.type == rct::RCTType::CLSAG) {
        if (!tx.pruned) {
            CHECK_AND_ASSERT_MES(rv.p.CLSAGs.size() == tx.vin.size(), false, "Bad CLSAGs size");
            for (size_t n = 0; n < tx.vin.size(); ++n) {
                rv.p.CLSAGs[n].I = rct::ki2rct(var::get<txin_to_key>(tx.vin[n]).k_image);
            }
        }
    } else {
        CHECK_AND_ASSERT_MES(
                false,
                false,
                "Unsupported rct tx type: {}",
                static_cast<std::underlying_type_t<rct::RCTType>>(rv.type));
    }

    // outPk was already done by handle_incoming_tx

    return true;
}
//------------------------------------------------------------------
// This function validates transaction inputs and their keys.
// FIXME: consider moving functionality specific to one input into
//        check_tx_input() rather than here, and use this function simply
//        to iterate the inputs as necessary (splitting the task
//        using threads, etc.)
bool Blockchain::check_tx_inputs(
        transaction& tx,
        tx_verification_context& tvc,
        uint64_t* pmax_used_block_height,
        std::unordered_set<crypto::key_image>* key_image_conflicts) {
    log::trace(logcat, "Blockchain::{}", __func__);
    uint64_t max_used_block_height = 0;
    if (!pmax_used_block_height)
        pmax_used_block_height = &max_used_block_height;
    *pmax_used_block_height = 0;

    const auto hf_version = get_network_version();

    // Min/Max Type/Version Check
    {
        txtype max_type = transaction::get_max_type_for_hf(hf_version);
        txversion min_version = transaction::get_min_version_for_hf(hf_version);
        txversion max_version = transaction::get_max_version_for_hf(hf_version);
        tvc.m_invalid_type = (tx.type > max_type);
        tvc.m_invalid_version = tx.version < min_version || tx.version > max_version;
        if (tvc.m_invalid_version || tvc.m_invalid_type) {
            if (tvc.m_invalid_version)
                log::error(
                        log::Cat("verify"),
                        "TX Invalid version: {} for hardfork: {} min/max version: {}/{}",
                        tx.version,
                        (int)hf_version,
                        min_version,
                        max_version);
            if (tvc.m_invalid_type)
                log::error(
                        log::Cat("verify"),
                        "TX Invalid type: {} for hardfork: {} max type: {}",
                        tx.type,
                        (int)hf_version,
                        max_type);
            return false;
        }
    }

    if (tx.is_transfer()) {
        if (tx.type != txtype::oxen_name_system && !std::holds_alternative<txin_gen>(tx.vin[0]) &&
            hf_version >= feature::MIN_2_OUTPUTS && tx.vout.size() < 2) {
            log::error(
                    log::Cat("verify"),
                    "Tx {} has fewer than two outputs, which is not allowed as of hardfork {}",
                    get_transaction_hash(tx),
                    static_cast<int>(feature::MIN_2_OUTPUTS));
            tvc.m_too_few_outputs = true;
            return false;
        }

        crypto::hash tx_prefix_hash = get_transaction_prefix_hash(tx);

        std::vector<std::vector<rct::ctkey>> pubkeys(tx.vin.size());
        const crypto::key_image* last_key_image = NULL;
        for (size_t sig_index = 0; sig_index < tx.vin.size(); sig_index++) {
            const auto& txin = tx.vin[sig_index];

            //
            // Monero Checks
            //
            // make sure output being spent is of type txin_to_key, rather than e.g.  txin_gen,
            // which is only used for miner transactions
            CHECK_AND_ASSERT_MES(
                    std::holds_alternative<txin_to_key>(txin),
                    false,
                    "wrong type id in tx input at Blockchain::check_tx_inputs");
            const txin_to_key& in_to_key = var::get<txin_to_key>(txin);
            {
                // make sure tx output has key offset(s) (is signed to be used)
                CHECK_AND_ASSERT_MES(
                        in_to_key.key_offsets.size(),
                        false,
                        "empty in_to_key.key_offsets in transaction with id {}",
                        get_transaction_hash(tx));

                // Mixin Check, from hard fork 7, we require mixin at least 9, always.
                if (in_to_key.key_offsets.size() - 1 != cryptonote::TX_OUTPUT_DECOYS) {
                    log::error(
                            log::Cat("verify"),
                            "Tx {} has incorrect ring size: {} expected: {}",
                            get_transaction_hash(tx),
                            in_to_key.key_offsets.size() - 1,
                            cryptonote::TX_OUTPUT_DECOYS);
                    tvc.m_low_mixin = true;
                    return false;
                }

                // from v7, sorted ins
                {
                    if (last_key_image &&
                        memcmp(&in_to_key.k_image, last_key_image, sizeof(*last_key_image)) >= 0) {
                        log::error(log::Cat("verify"), "transaction has unsorted inputs");
                        tvc.m_verifivation_failed = true;
                        return false;
                    }
                    last_key_image = &in_to_key.k_image;
                }

                if (have_tx_keyimg_as_spent(in_to_key.k_image)) {
                    log::error(
                            log::Cat("verify"),
                            "Key image already spent in blockchain: {}",
                            in_to_key.k_image);
                    if (key_image_conflicts)
                        key_image_conflicts->insert(in_to_key.k_image);
                    else {
                        tvc.m_double_spend = true;
                        return false;
                    }
                }

                // make sure that output being spent matches up correctly with the
                // signature spending it.
                if (!check_tx_input(
                            in_to_key,
                            tx_prefix_hash,
                            pubkeys[sig_index],
                            pmax_used_block_height)) {
                    log::error(
                            log::Cat("verify"),
                            "Failed to check ring signature for tx {} vin key with k_image: {} "
                            "sig_index: {}",
                            get_transaction_hash(tx),
                            in_to_key.k_image,
                            sig_index);
                    if (pmax_used_block_height)  // a default value of NULL is used when called from
                                                 // Blockchain::handle_block_to_main_chain()
                    {
                        log::error(
                                log::Cat("verify"),
                                "  *pmax_used_block_height: {}",
                                *pmax_used_block_height);
                    }

                    return false;
                }
            }

            //
            // Service Node Checks
            //
            if (hf_version >= hf::hf11_infinite_staking) {
                const auto& blacklist = service_node_list.get_blacklisted_key_images();
                for (const auto& entry : blacklist) {
                    if (in_to_key.k_image ==
                        entry.key_image)  // Check if key image is on the blacklist
                    {
                        log::error(
                                log::Cat("verify"),
                                "Key image: {} is blacklisted by the service node network",
                                entry.key_image);
                        tvc.m_key_image_blacklisted = true;
                        return false;
                    }
                }

                uint64_t unlock_height = 0;
                if (service_node_list.is_key_image_locked(in_to_key.k_image, &unlock_height)) {
                    log::error(
                            log::Cat("verify"),
                            "Key image: {} is locked in a stake until height: {}",
                            in_to_key.k_image,
                            unlock_height);
                    tvc.m_key_image_locked_by_snode = true;
                    return false;
                }
            }
        }

        if (hf_version >= feature::ENFORCE_MIN_AGE) {
            CHECK_AND_ASSERT_MES(
                    *pmax_used_block_height + DEFAULT_TX_SPENDABLE_AGE <= m_db->height(),
                    false,
                    "Transaction spends at least one output which is too young");
        }

        if (!expand_transaction_2(tx, tx_prefix_hash, pubkeys)) {
            log::error(log::Cat("verify"), "Failed to expand rct signatures!");
            return false;
        }

        // from version 2, check ringct signatures
        // obviously, the original and simple rct APIs use a mixRing that's indexes
        // in opposite orders, because it'd be too simple otherwise...
        const rct::rctSig& rv = tx.rct_signatures;
        switch (rv.type) {
            case rct::RCTType::Null: {
                // we only accept no signatures for coinbase txes
                if (!tx.is_miner_tx()) {
                    log::error(log::Cat("verify"), "Null rct signature on non-coinbase tx");
                    return false;
                }
                break;
            }
            case rct::RCTType::Simple:
            case rct::RCTType::Bulletproof:
            case rct::RCTType::Bulletproof2:
            case rct::RCTType::CLSAG: {
                // check all this, either reconstructed (so should really pass), or not
                {
                    if (pubkeys.size() != rv.mixRing.size()) {
                        log::error(
                                log::Cat("verify"),
                                "Failed to check ringct signatures: mismatched pubkeys/mixRing "
                                "size");
                        return false;
                    }
                    for (size_t i = 0; i < pubkeys.size(); ++i) {
                        if (pubkeys[i].size() != rv.mixRing[i].size()) {
                            log::error(
                                    log::Cat("verify"),
                                    "Failed to check ringct signatures: mismatched pubkeys/mixRing "
                                    "size");
                            return false;
                        }
                    }

                    for (size_t n = 0; n < pubkeys.size(); ++n) {
                        for (size_t m = 0; m < pubkeys[n].size(); ++m) {
                            if (pubkeys[n][m].dest != rct::rct2pk(rv.mixRing[n][m].dest)) {
                                log::error(
                                        log::Cat("verify"),
                                        "Failed to check ringct signatures: mismatched pubkey at "
                                        "vin {}, index {}",
                                        n,
                                        m);
                                return false;
                            }
                            if (pubkeys[n][m].mask != rct::rct2pk(rv.mixRing[n][m].mask)) {
                                log::error(
                                        log::Cat("verify"),
                                        "Failed to check ringct signatures: mismatched commitment "
                                        "at vin {}, index {}",
                                        n,
                                        m);
                                return false;
                            }
                        }
                    }
                }

                const size_t n_sigs =
                        rv.type == rct::RCTType::CLSAG ? rv.p.CLSAGs.size() : rv.p.MGs.size();
                if (n_sigs != tx.vin.size()) {
                    log::error(
                            log::Cat("verify"),
                            "Failed to check ringct signatures: mismatched MGs/vin sizes");
                    return false;
                }
                for (size_t n = 0; n < tx.vin.size(); ++n) {
                    bool error;
                    if (rv.type == rct::RCTType::CLSAG)
                        error = memcmp(
                                &var::get<txin_to_key>(tx.vin[n]).k_image, &rv.p.CLSAGs[n].I, 32);
                    else
                        error = rv.p.MGs[n].II.empty() ||
                                memcmp(&var::get<txin_to_key>(tx.vin[n]).k_image,
                                       &rv.p.MGs[n].II[0],
                                       32);
                    if (error) {
                        log::error(
                                log::Cat("verify"),
                                "Failed to check ringct signatures: mismatched key image");
                        return false;
                    }
                }

                if (!rct::verRctNonSemanticsSimple(rv)) {
                    log::error(log::Cat("verify"), "Failed to check ringct signatures!");
                    return false;
                }
                break;
            }
            case rct::RCTType::Full: {
                // check all this, either reconstructed (so should really pass), or not
                {
                    bool size_matches = true;
                    for (size_t i = 0; i < pubkeys.size(); ++i)
                        size_matches &= pubkeys[i].size() == rv.mixRing.size();
                    for (size_t i = 0; i < rv.mixRing.size(); ++i)
                        size_matches &= pubkeys.size() == rv.mixRing[i].size();
                    if (!size_matches) {
                        log::error(
                                log::Cat("verify"),
                                "Failed to check ringct signatures: mismatched pubkeys/mixRing "
                                "size");
                        return false;
                    }

                    for (size_t n = 0; n < pubkeys.size(); ++n) {
                        for (size_t m = 0; m < pubkeys[n].size(); ++m) {
                            if (pubkeys[n][m].dest != rct::rct2pk(rv.mixRing[m][n].dest)) {
                                log::error(
                                        log::Cat("verify"),
                                        "Failed to check ringct signatures: mismatched pubkey at "
                                        "vin {}, index {}",
                                        n,
                                        m);
                                return false;
                            }
                            if (pubkeys[n][m].mask != rct::rct2pk(rv.mixRing[m][n].mask)) {
                                log::error(
                                        log::Cat("verify"),
                                        "Failed to check ringct signatures: mismatched commitment "
                                        "at vin {}, index {}",
                                        n,
                                        m);
                                return false;
                            }
                        }
                    }
                }

                if (rv.p.MGs.size() != 1) {
                    log::error(
                            log::Cat("verify"), "Failed to check ringct signatures: Bad MGs size");
                    return false;
                }
                if (rv.p.MGs.empty() || rv.p.MGs[0].II.size() != tx.vin.size()) {
                    log::error(
                            log::Cat("verify"),
                            "Failed to check ringct signatures: mismatched II/vin sizes");
                    return false;
                }
                for (size_t n = 0; n < tx.vin.size(); ++n) {
                    if (memcmp(&var::get<txin_to_key>(tx.vin[n]).k_image, &rv.p.MGs[0].II[n], 32)) {
                        log::error(
                                log::Cat("verify"),
                                "Failed to check ringct signatures: mismatched II/vin sizes");
                        return false;
                    }
                }

                if (!rct::verRct(rv, false)) {
                    log::error(log::Cat("verify"), "Failed to check ringct signatures!");
                    return false;
                }
                break;
            }
            default:
                log::error(
                        log::Cat("verify"), "{}: Unsupported rct type: {}", __func__, (int)rv.type);
                return false;
        }

        // for bulletproofs, check they're only multi-output after v8
        if (rct::is_rct_bulletproof(rv.type) && hf_version < hf::hf10_bulletproofs) {
            for (const rct::Bulletproof& proof : rv.p.bulletproofs) {
                if (proof.V.size() > 1 && !hack::test_suite_permissive_txes) {
                    log::error(
                            log::Cat("verify"), "Multi output bulletproofs are invalid before v10");
                    return false;
                }
            }
        }

        if (tx.type == txtype::oxen_name_system) {
            cryptonote::tx_extra_oxen_name_system data;
            std::string fail_reason;
            if (!m_ons_db.validate_ons_tx(
                        hf_version, get_current_blockchain_height(), tx, data, &fail_reason)) {
                log::error(log::Cat("verify"), "Failed to validate ONS TX reason: {}", fail_reason);
                tvc.m_verbose_error = std::move(fail_reason);
                return false;
            }
        }

    } else {
        CHECK_AND_ASSERT_MES(
                tx.vin.size() == 0,
                false,
                "TX type: {} should have 0 inputs. This should have been rejected in "
                "check_tx_semantic!",
                tx.type);

        if (tx.rct_signatures.txnFee != 0) {
            tvc.m_invalid_input = true;
            tvc.m_verifivation_failed = true;
            log::error(log::Cat("verify"), "TX type: {} should have 0 fee!", tx.type);
            return false;
        }

        if (tx.type == txtype::ethereum_new_service_node) {
            if (!eth::validate_event_tx<eth::event::NewServiceNode>(
                        hf_version, tx, tvc.m_verbose_error)) {
                log::error(
                        log::Cat("verify"),
                        "Failed to validate Ethereum New Service Node TX reason: {}",
                        tvc.m_verbose_error);
                return false;
            }
        } else if (tx.type == txtype::ethereum_service_node_removal_request) {
            if (!eth::validate_event_tx<eth::event::ServiceNodeRemovalRequest>(
                        hf_version, tx, tvc.m_verbose_error)) {
                log::error(
                        log::Cat("verify"),
                        "Failed to validate Ethereum Service Node Removal Request TX reason: {}",
                        tvc.m_verbose_error);
                return false;
            }
        } else if (tx.type == txtype::ethereum_service_node_removal) {
            if (!eth::validate_event_tx<eth::event::ServiceNodeRemoval>(
                        hf_version, tx, tvc.m_verbose_error)) {
                log::error(
                        log::Cat("verify"),
                        "Failed to validate Ethereum Service Node Removal TX reason: {}",
                        tvc.m_verbose_error);
                return false;
            }
        } else if (tx.type == txtype::state_change) {
            tx_extra_service_node_state_change state_change;
            if (!get_service_node_state_change_from_tx_extra(tx.extra, state_change, hf_version)) {
                log::error(
                        log::Cat("verify"),
                        "TX did not have the state change metadata in the tx_extra");
                return false;
            }

            auto quorum = service_node_list.get_quorum(
                    service_nodes::quorum_type::obligations, state_change.block_height);
            if (!quorum) {
                log::error(
                        log::Cat("verify"),
                        "could not get obligations quorum for recent state change tx");
                return false;
            }

            if (!service_nodes::verify_tx_state_change(
                        state_change, get_current_blockchain_height(), tvc, *quorum, hf_version)) {
                // will be set by the above on serious failures (i.e. illegal value), but not for
                // less serious ones like state change heights slightly outside of allowed bounds:
                // tvc.m_verifivation_failed = true;
                log::error(
                        log::Cat("verify"),
                        "tx: {}, state change tx could not be completely verified reason: {}",
                        get_transaction_hash(tx),
                        print_vote_verification_context(tvc.m_vote_ctx));
                return false;
            }

            crypto::public_key const& state_change_service_node_pubkey =
                    quorum->workers[state_change.service_node_index];
            //
            // NOTE: Query the Service Node List for the in question Service Node the state change
            // is for and disallow if conflicting
            //
            std::vector<service_nodes::service_node_pubkey_info> service_node_array =
                    service_node_list.get_service_node_list_state(
                            {state_change_service_node_pubkey});
            if (service_node_array.empty()) {
                log::error(
                        log::Cat("verify"),
                        "Service Node no longer exists on the network, state change can be "
                        "ignored");
                return hf_version < hf::hf12_checkpointing;  // NOTE: Used to be allowed pre HF12.
            }

            const auto& service_node_info = *service_node_array[0].info;
            if (!service_node_info.can_transition_to_state(
                        hf_version, state_change.block_height, state_change.state)) {
                log::error(
                        log::Cat("verify"),
                        "State change trying to vote Service Node into the same state is invalid "
                        "(expired, already applied, or impossible)");
                tvc.m_double_spend = true;
                return false;
            }
        } else if (tx.type == txtype::key_image_unlock) {
            cryptonote::tx_extra_tx_key_image_unlock unlock;
            if (!cryptonote::get_field_from_tx_extra(tx.extra, unlock)) {
                log::error(logcat, "TX extra didn't have key image unlock in the tx_extra");
                return false;
            }

            service_nodes::service_node_info::contribution_t contribution = {};
            uint64_t unlock_height = 0;
            if (!service_node_list.is_key_image_locked(
                        unlock.key_image, &unlock_height, &contribution)) {
                log::error(
                        log::Cat("verify"),
                        "Requested key image: {} to unlock is not locked",
                        unlock.key_image);
                tvc.m_invalid_input = true;
                return false;
            }

            if (!crypto::check_signature(
                        service_nodes::generate_request_stake_unlock_hash(unlock.nonce),
                        contribution.key_image_pub_key,
                        unlock.signature)) {
                log::error(
                        logcat,
                        "Could not verify key image unlock transaction signature for tx: {}",
                        get_transaction_hash(tx));
                return false;
            }

            // Otherwise is a locked key image, if the unlock_height is set, it has been previously
            // requested to unlock
            if (unlock_height) {
                tvc.m_double_spend = true;
                return false;
            }
        } else {
            log::error(
                    log::Cat("verify"),
                    "Unhandled tx type: {} rejecting tx: {}",
                    tx.type,
                    get_transaction_hash(tx));
            tvc.m_invalid_type = true;
            ;
            return false;
        }
    }

    return true;
}

//------------------------------------------------------------------
void Blockchain::check_ring_signature(
        const crypto::hash& tx_prefix_hash,
        const crypto::key_image& key_image,
        const std::vector<rct::ctkey>& pubkeys,
        const std::vector<crypto::signature>& sig,
        uint64_t& result) const {
    std::vector<const crypto::public_key*> p_output_keys;
    p_output_keys.reserve(pubkeys.size());
    for (auto& key : pubkeys) {
        // rct::key and crypto::public_key have the same structure, avoid object ctor/memcpy
        p_output_keys.push_back(&(const crypto::public_key&)key.dest);
    }

    result = crypto::check_ring_signature(tx_prefix_hash, key_image, p_output_keys, sig.data()) ? 1
                                                                                                : 0;
}

//------------------------------------------------------------------
uint64_t Blockchain::get_fee_quantization_mask() {
    static uint64_t mask = 0;
    if (mask == 0) {
        mask = 1;
        for (size_t n = FEE_QUANTIZATION_DECIMALS; n < oxen::DISPLAY_DECIMAL_POINT; ++n)
            mask *= 10;
    }
    return mask;
}

//------------------------------------------------------------------
byte_and_output_fees Blockchain::get_dynamic_base_fee(
        uint64_t block_reward, size_t median_block_weight, hf version) {
    const uint64_t min_block_weight = get_min_block_weight(version);
    if (median_block_weight < min_block_weight)
        median_block_weight = min_block_weight;
    byte_and_output_fees fees{0, 0};
    uint64_t hi, &lo = fees.first;

    if (version >= feature::PER_BYTE_FEE) {
        // fee = block_reward * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT / min_block_weight /
        // median_block_weight / 5 (but done in 128-bit math).  Note that the wallet uses
        // FEE_PER_BYTE as a fallback if it can't get the dynamic fee from the daemon, so it needs
        // to satisfy FEE_PER_BYTE >= BLOCK_REWARD * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT /
        // (min_block_weight)^2 / 5 (The square because median_block_weight >= min_block_weight). As
        // of writing we are past block 300000 with base block reward of ~32.04; and so the fee is
        // below 214 (hence the use of 215 in cryptonote_config.h).
        //
        // In v12 we increase the reference transaction fee by 80 (to 240000), and so the
        // FEE_PER_BYTE fallback also goes up (to a conservative estimate of 17200).
        //
        // This calculation was painful for large txes (in particular sweeps and SN stakes), which
        // wasn't intended, so in v13 we reduce the reference tx fee back to what it was before and
        // introduce a per-output fee instead.  (This is why this is an hard == instead of a >=).
        const uint64_t reference_fee = version != feature::INCREASE_FEE
                                             ? DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT
                                             : old::DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT_V12;
        lo = mul128(block_reward, reference_fee, &hi);
        div128_32(hi, lo, min_block_weight, &hi, &lo);
        div128_32(hi, lo, median_block_weight, &hi, &lo);
        assert(hi == 0);
        lo /= 5;

        if (version >= hf::hf18)
            fees.second = FEE_PER_OUTPUT_V18;
        else if (version >= feature::PER_OUTPUT_FEE)
            fees.second = old::FEE_PER_OUTPUT_V13;

        return fees;
    }

    constexpr uint64_t fee_base = old::DYNAMIC_FEE_PER_KB_BASE_FEE_V5;

    uint64_t unscaled_fee_base = (fee_base * min_block_weight / median_block_weight);
    lo = mul128(unscaled_fee_base, block_reward, &hi);
    static_assert(
            old::DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD % 1000000 == 0,
            "DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD must be divisible by 1000000");
    static_assert(
            old::DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD / 1000000 <=
                    std::numeric_limits<uint32_t>::max(),
            "DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD is too large");

    // divide in two steps, since the divisor must be 32 bits, but
    // DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD isn't
    div128_32(hi, lo, old::DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD / 1000000, &hi, &lo);
    div128_32(hi, lo, 1000000, &hi, &lo);
    assert(hi == 0);

    // quantize fee up to 8 decimals
    uint64_t mask = get_fee_quantization_mask();
    uint64_t qlo = (lo + mask - 1) / mask * mask;
    log::debug(logcat, "lo {}, qlo {}, mask {}", print_money(lo), print_money(qlo), mask);

    fees.first = qlo;
    return fees;
}

//------------------------------------------------------------------
bool Blockchain::check_fee(
        size_t tx_weight,
        size_t tx_outs,
        uint64_t fee,
        uint64_t burned,
        const tx_pool_options& opts) const {
    const auto version = get_network_version();
    const uint64_t blockchain_height = get_current_blockchain_height();

    uint64_t median = m_current_block_cumul_weight_limit / 2;
    uint64_t already_generated_coins =
            blockchain_height ? m_db->get_block_already_generated_coins(blockchain_height - 1) : 0;
    uint64_t base_reward, base_reward_unpenalized;
    if (!get_base_block_reward(
                median,
                1,
                already_generated_coins,
                base_reward,
                base_reward_unpenalized,
                version,
                blockchain_height))
        return false;

    uint64_t needed_fee;
    if (version >= feature::PER_BYTE_FEE) {
        const bool use_long_term_median_in_fee = version >= feature::LONG_TERM_BLOCK_WEIGHT;
        auto fees = get_dynamic_base_fee(
                base_reward,
                use_long_term_median_in_fee
                        ? std::min<uint64_t>(median, m_long_term_effective_median_block_weight)
                        : median,
                version);
        log::debug(
                logcat,
                "Using {}/byte + {}/out fee",
                print_money(fees.first),
                print_money(fees.second));
        needed_fee = tx_weight * fees.first + tx_outs * fees.second;
        // quantize fee up to 8 decimals
        const uint64_t mask = get_fee_quantization_mask();
        needed_fee = (needed_fee + mask - 1) / mask * mask;
    } else {
        auto fees = get_dynamic_base_fee(base_reward, median, version);
        assert(fees.second == 0);
        log::debug(logcat, "Using {}/kB fee", print_money(fees.first));

        needed_fee = tx_weight / 1024;
        needed_fee += (tx_weight % 1024) ? 1 : 0;
        needed_fee *= fees.first;
    }

    uint64_t required_percent = std::max(opts.fee_percent, uint64_t{100});

    needed_fee -= needed_fee / 50;  // keep a little 2% buffer on acceptance

    uint64_t base_miner_fee = needed_fee;
    needed_fee = needed_fee * required_percent / 100;

    if (fee < needed_fee) {
        log::error(
                log::Cat("verify"),
                "transaction fee is not enough: {}, minimum fee: {}",
                print_money(fee),
                print_money(needed_fee));
        return false;
    }

    if (opts.burn_fixed || opts.burn_percent) {
        uint64_t need_burned = opts.burn_fixed + base_miner_fee * opts.burn_percent / 100;
        if (burned < need_burned) {
            log::error(
                    log::Cat("verify"),
                    "transaction burned fee is not enough: {}, minimum fee: {}",
                    print_money(burned),
                    print_money(need_burned));
            return false;
        }
    }
    return true;
}

//------------------------------------------------------------------
byte_and_output_fees Blockchain::get_dynamic_base_fee_estimate(uint64_t grace_blocks) const {
    const auto version = get_network_version();
    const uint64_t db_height = m_db->height();

    if (grace_blocks >= REWARD_BLOCKS_WINDOW)
        grace_blocks = REWARD_BLOCKS_WINDOW - 1;

    const uint64_t min_block_weight = get_min_block_weight(version);
    std::vector<uint64_t> weights;
    get_last_n_blocks_weights(weights, REWARD_BLOCKS_WINDOW - grace_blocks);
    weights.reserve(grace_blocks);
    for (size_t i = 0; i < grace_blocks; ++i)
        weights.push_back(min_block_weight);

    uint64_t median = tools::median(std::move(weights));
    if (median <= min_block_weight)
        median = min_block_weight;

    uint64_t already_generated_coins =
            db_height ? m_db->get_block_already_generated_coins(db_height - 1) : 0;
    uint64_t base_reward, base_reward_unpenalized;
    if (!get_base_block_reward(
                m_current_block_cumul_weight_limit / 2,
                1,
                already_generated_coins,
                base_reward,
                base_reward_unpenalized,
                version,
                m_db->height())) {
        log::error(
                logcat,
                "Failed to determine block reward, using placeholder {} as a high bound",
                print_money(BLOCK_REWARD_OVERESTIMATE));
        base_reward = BLOCK_REWARD_OVERESTIMATE;
    }

    const bool use_long_term_median_in_fee = version >= feature::LONG_TERM_BLOCK_WEIGHT;
    const uint64_t use_median_value =
            use_long_term_median_in_fee
                    ? std::min<uint64_t>(median, m_long_term_effective_median_block_weight)
                    : median;
    auto fee = get_dynamic_base_fee(base_reward, use_median_value, version);
    const bool per_byte = version < feature::PER_BYTE_FEE;
    log::debug(
            logcat,
            "Estimating {}-block fee at {}/{} + {}.out",
            grace_blocks,
            print_money(fee.first),
            (per_byte ? "byte" : "kB"),
            print_money(fee.second));
    return fee;
}

//------------------------------------------------------------------
// This function checks to see if a tx is unlocked.  unlock_time is either
// a block index or a unix time.
bool Blockchain::is_output_spendtime_unlocked(uint64_t unlock_time) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    return cryptonote::rules::is_output_unlocked(m_nettype, unlock_time, m_db->height());
}
//------------------------------------------------------------------
// This function locates all outputs associated with a given input (mixins)
// and validates that they exist and are usable.
bool Blockchain::check_tx_input(
        const txin_to_key& txin,
        const crypto::hash& tx_prefix_hash,
        std::vector<rct::ctkey>& output_keys,
        uint64_t* pmax_related_block_height) {
    log::trace(logcat, "Blockchain::{}", __func__);

    // ND:
    // 1. Disable locking and make method private.
    // std::unique_lock lock{*this};

    struct outputs_visitor {
        std::vector<rct::ctkey>& m_output_keys;
        const Blockchain& m_bch;
        outputs_visitor(std::vector<rct::ctkey>& output_keys, const Blockchain& bch) :
                m_output_keys(output_keys), m_bch(bch) {}
        bool handle_output(
                uint64_t unlock_time,
                const crypto::public_key& pubkey,
                const rct::key& commitment) {
            // check tx unlock time
            if (!m_bch.is_output_spendtime_unlocked(unlock_time)) {
                log::error(
                        log::Cat("verify"),
                        "One of outputs for one of inputs has wrong tx.unlock_time = {}",
                        unlock_time);
                return false;
            }

            // The original code includes a check for the output corresponding to this input
            // to be a txout_to_key. This is removed, as the database does not store this info,
            // but only txout_to_key outputs are stored in the DB in the first place, done in
            // Blockchain*::add_output

            m_output_keys.push_back(rct::ctkey({rct::pk2rct(pubkey), commitment}));
            return true;
        }
    };

    output_keys.clear();

    // collect output keys
    outputs_visitor vi(output_keys, *this);
    if (!scan_outputkeys_for_indexes(txin, vi, tx_prefix_hash, pmax_related_block_height)) {
        log::error(
                log::Cat("verify"),
                "Failed to get output keys for tx with amount = {} and count indixes {}",
                print_money(txin.amount),
                txin.key_offsets.size());
        return false;
    }

    if (txin.key_offsets.size() != output_keys.size()) {
        log::error(
                log::Cat("verify"),
                "Output keys for tx with amount = {} and count indexes {} returned wrong keys "
                "count {}",
                txin.amount,
                txin.key_offsets.size(),
                output_keys.size());
        return false;
    }
    // rct_signatures will be expanded after this
    return true;
}
//------------------------------------------------------------------
// TODO: Is this intended to do something else?  Need to look into the todo there.
uint64_t Blockchain::get_adjusted_time() const {
    log::trace(logcat, "Blockchain::{}", __func__);
    // TODO: add collecting median time
    return time(NULL);
}
//------------------------------------------------------------------
// TODO: revisit, has changed a bit on upstream
bool Blockchain::check_block_timestamp(
        std::vector<uint64_t> timestamps, const block& b, uint64_t& median_ts) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    median_ts = tools::median(std::move(timestamps));

    if (b.timestamp < median_ts) {
        log::error(
                log::Cat("verify"),
                "Timestamp of block with id: {}, {}, less than median of last {} blocks, {}",
                get_block_hash(b),
                b.timestamp,
                BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW,
                median_ts);
        return false;
    }

    return true;
}
//------------------------------------------------------------------
// This function grabs the timestamps from the most recent <n> blocks,
// where n = BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW.  If there are not those many
// blocks in the blockchain, the timestap is assumed to be valid.  If there
// are, this function returns:
//   true if the block's timestamp is not less than the timestamp of the
//       median of the selected blocks
//   false otherwise
bool Blockchain::check_block_timestamp(const block& b, uint64_t& median_ts) const {
    log::trace(logcat, "Blockchain::{}", __func__);
    uint64_t cryptonote_block_future_time_limit = old::BLOCK_FUTURE_TIME_LIMIT_V2;
    if (b.timestamp > get_adjusted_time() + cryptonote_block_future_time_limit) {
        log::error(
                log::Cat("verify"),
                "Timestamp of block with id: {}, {}, bigger than adjusted time + 2 hours",
                get_block_hash(b),
                b.timestamp);
        return false;
    }

    const auto h = m_db->height();

    // if not enough blocks, no proper median yet, return true
    if (h < BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW) {
        return true;
    }

    std::vector<uint64_t> timestamps;

    // need most recent 60 blocks, get index of first of those
    size_t offset = h - BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW;
    timestamps.reserve(h - offset);
    for (; offset < h; ++offset) {
        timestamps.push_back(m_db->get_block_timestamp(offset));
    }

    return check_block_timestamp(std::move(timestamps), b, median_ts);
}
//------------------------------------------------------------------
void Blockchain::return_tx_to_pool(std::vector<std::pair<transaction, std::string>>& txs) {
    auto version = get_network_version();
    for (auto& tx : txs) {
        cryptonote::tx_verification_context tvc{};
        // We assume that if they were in a block, the transactions are already
        // known to the network as a whole. However, if we had mined that block,
        // that might not be always true. Unlikely though, and always relaying
        // these again might cause a spike of traffic as many nodes re-relay
        // all the transactions in a popped block when a reorg happens.
        const size_t weight = get_transaction_weight(tx.first, tx.second.size());
        const crypto::hash tx_hash = get_transaction_hash(tx.first);
        if (!tx_pool.add_tx(
                    tx.first,
                    tx_hash,
                    tx.second,
                    weight,
                    tvc,
                    tx_pool_options::from_block(),
                    version)) {
            log::error(
                    logcat,
                    "Failed to return taken transaction with hash: {} to tx_pool",
                    get_transaction_hash(tx.first));
        }
    }
}
//------------------------------------------------------------------
bool Blockchain::flush_txes_from_pool(const std::vector<crypto::hash>& txids) {
    std::unique_lock lock{tx_pool};

    bool res = true;
    for (const auto& txid : txids) {
        cryptonote::transaction tx;
        std::string txblob;
        size_t tx_weight;
        uint64_t fee;
        bool relayed, do_not_relay, double_spend_seen;
        log::info(logcat, "Removing txid {} from the pool", txid);
        if (tx_pool.have_tx(txid) &&
            !tx_pool.take_tx(
                    txid, tx, txblob, tx_weight, fee, relayed, do_not_relay, double_spend_seen)) {
            log::error(logcat, "Failed to remove txid {} from the pool", txid);
            res = false;
        }
    }
    return res;
}

Blockchain::block_pow_verified Blockchain::verify_block_pow(
        cryptonote::block const& blk,
        difficulty_type difficulty,
        uint64_t chain_height,
        bool alt_block) {
    block_pow_verified result = {};
    std::memset(result.proof_of_work.data(), 0xff, result.proof_of_work.size());
    crypto::hash const blk_hash = cryptonote::get_block_hash(blk);
    uint64_t const blk_height = blk.get_height();

    // There is a difficulty bug in oxend that caused a network disagreement at height 526483 where
    // somewhere around half the network had a slightly-too-high difficulty value and accepted the
    // block while nodes with the correct difficulty value rejected it.  However this
    // not-quite-enough difficulty chain had enough of the network following it that it got
    // checkpointed several times and so cannot be rolled back.
    //
    // Hence this hack: starting at that block until the next hard fork, we allow a slight grace
    // (0.2%) on the required difficulty (but we don't *change* the actual difficulty value used for
    // diff calculation).
    if (blk.get_height() >= 526483 && get_network_version() < hf::hf16_pulse)
        difficulty = (difficulty * 998) / 1000;

    CHECK_AND_ASSERT_MES(difficulty, result, "!!!!!!!!! difficulty overhead !!!!!!!!!");
    if (alt_block) {
        randomx_longhash_context randomx_context = {};
        if (blk.major_version >= hf::hf12_checkpointing) {
            randomx_context.current_blockchain_height = chain_height;
            randomx_context.seed_height = rx_seedheight(blk_height);
            randomx_context.seed_block_hash = get_block_id_by_height(randomx_context.seed_height);
        }

        result.proof_of_work = get_altblock_longhash(m_nettype, randomx_context, blk, blk_height);
    } else {
        // Formerly the code below contained an if loop with the following condition
        // !m_checkpoints.is_in_checkpoint_zone(get_current_blockchain_height())
        // however, this caused the daemon to not bother checking PoW for blocks
        // before checkpoints, which is very dangerous behaviour. We moved the PoW
        // validation out of the next chunk of code to make sure that we correctly
        // check PoW now.
        // FIXME: height parameter is not used...should it be used or should it not
        // be a parameter?
        // validate proof_of_work versus difficulty target
#if defined(PER_BLOCK_CHECKPOINT)
        if (chain_height < m_blocks_hash_check.size()) {
            const auto& expected_hash = m_blocks_hash_check[chain_height];
            if (expected_hash) {
                if (blk_hash != expected_hash) {
                    log::error(
                            log::Cat("verify"),
                            "Block with id is INVALID: {}, expected {}",
                            blk_hash,
                            expected_hash);
                    result.valid = false;
                    return result;
                }

                result.per_block_checkpointed = true;
            } else {
                log::info(
                        log::Cat("verify"),
                        "No pre-validated hash at height {}, verifying fully",
                        chain_height);
            }
        }
#endif

        if (!result.per_block_checkpointed) {
            auto it = m_blocks_longhash_table.find(blk_hash);
            if (it != m_blocks_longhash_table.end()) {
                result.precomputed = true;
                result.proof_of_work = it->second;
            } else
                result.proof_of_work =
                        get_block_longhash_w_blockchain(m_nettype, this, blk, chain_height, 0);
        }
    }

    if (result.per_block_checkpointed) {
        result.valid = true;
    } else {
        // validate proof_of_work versus difficulty target
        result.valid = check_hash(result.proof_of_work, difficulty);
        if (!result.valid)
            log::error(
                    globallogcat,
                    fg(fmt::terminal_color::red) | fmt::emphasis::bold,
                    "{} with id: {}\n does not have enough proof of work: {} at height {}, "
                    "required difficulty: {}",
                    (alt_block ? "Alternative block" : "Block"),
                    blk_hash,
                    result.proof_of_work,
                    blk_height,
                    difficulty);
    }

    return result;
}

bool Blockchain::basic_block_checks(cryptonote::block const& blk, bool alt_block) {
    const crypto::hash blk_hash = cryptonote::get_block_hash(blk);
    const uint64_t blk_height = blk.get_height();
    const uint64_t chain_height = get_current_blockchain_height();
    const auto hf_version = get_network_version();

    if (alt_block) {
        if (blk.get_height() == 0) {
            log::error(
                    log::Cat("verify"),
                    "Block with id: {} (as alternative), but miner tx says height is 0.",
                    blk_hash);
            return false;
        }

        if (!m_checkpoints.is_alternative_block_allowed(chain_height, blk_height, nullptr)) {
            log::error(
                    log::Cat("verify"),
                    "Block with id: {} can't be accepted for alternative chain, block height: {}, "
                    "chain height: {}",
                    blk_hash,
                    blk_height,
                    chain_height);
            return false;
        }

        // this is a cheap test
        // HF19 TODO: after hardfork 19 occurs we can remove the second line of this test:
        if (auto v = get_network_version(blk_height);
            blk.major_version != v ||
            (v < hf::hf19_reward_batching && blk.minor_version < static_cast<uint8_t>(v))) {
            log::info(
                    logcat,
                    "Block with id: {}, has invalid version {}.{}; current: {}.{} for height {}",
                    blk_hash,
                    static_cast<int>(blk.major_version),
                    +blk.minor_version,
                    static_cast<int>(v),
                    static_cast<int>(v),
                    blk_height);
            return false;
        }
    } else {
        crypto::hash top_hash = get_tail_id().second;
        if (blk.prev_id != top_hash) {
            log::error(
                    globallogcat,
                    fg(fmt::terminal_color::red) | fmt::emphasis::bold,
                    "Block with id: {}, has wrong prev_id: {}, expected: {}",
                    blk_hash,
                    blk.prev_id,
                    top_hash);
            return false;
        }

        auto required_major_version = get_network_version();
        if (blk.major_version > required_major_version) {
            // Show a warning at most once every 5 minutes if we are receiving future hf blocks
            std::lock_guard lock{last_outdated_warning_mutex};
            if (auto now = std::chrono::steady_clock::now(); now > last_outdated_warning + 5min) {
                last_outdated_warning = now;
                log::warning(
                        globallogcat,
                        fg(fmt::terminal_color::red) | fmt::emphasis::bold,
                        "\n"
                        "**********************************************************************\n"
                        "A block was seen on the network with a version higher than the last\n"
                        "known one. This may be an old version of the daemon, and a software\n"
                        "update may be required to sync further.\n"
                        "**********************************************************************\n");
            }
        }

        // HF19 TODO: after hardfork 19 occurs we can remove the second line of this test:
        if (blk.major_version != required_major_version ||
            (blk.major_version < hf::hf19_reward_batching &&
             blk.minor_version < static_cast<uint8_t>(required_major_version))) {
            log::warning(
                    globallogcat,
                    fg(fmt::terminal_color::red),
                    "Block with id: {}, has invalid version {}.{}; current: {}.{} for height {}",
                    blk_hash,
                    static_cast<int>(blk.major_version),
                    +blk.minor_version,
                    static_cast<int>(required_major_version),
                    static_cast<int>(required_major_version),
                    blk_height);
            return false;
        }

        // If we're at a checkpoint, ensure that our hardcoded checkpoint hash
        // is correct.
        if (m_checkpoints.is_in_checkpoint_zone(chain_height)) {
            bool service_node_checkpoint = false;
            if (!m_checkpoints.check_block(
                        chain_height, blk_hash, nullptr, &service_node_checkpoint)) {
                if (!service_node_checkpoint ||
                    (service_node_checkpoint &&
                     blk.major_version >= hf::hf13_enforce_checkpoints)) {
                    log::info(logcat, fg(fmt::terminal_color::red), "CHECKPOINT VALIDATION FAILED");
                    return false;
                }
            }
        }

        // make sure block timestamp is not less than the median timestamp of a set
        // number of the most recent blocks.
        if (!check_block_timestamp(blk)) {
            log::info(
                    logcat,
                    fg(fmt::terminal_color::red),
                    "Block with id: {}, has invalid timestamp: {}",
                    blk_hash,
                    blk.timestamp);
            return false;
        }
    }

    if (blk.major_version >= feature::ETH_BLS) {
        if (blk.tx_eth_count > blk.tx_hashes.size()) {
            log::warning(
                    globallogcat,
                    fg(fmt::terminal_color::red) | fmt::emphasis::bold,
                    "Block with id: {}, has invalid eth state change count {} > tx count {}",
                    blk_hash,
                    blk.tx_eth_count,
                    blk.tx_hashes.size());
            return false;
        }
    }

    // When verifying an alt block, we're replacing the blk at blk_height, not
    // adding a new block to the chain
    // sanity check basic miner tx properties;
    if (!prevalidate_miner_transaction(blk, alt_block ? blk_height : chain_height, hf_version)) {
        log::info(
                logcat,
                fg(fmt::terminal_color::red),
                "Block with id: {} failed to pass prevalidation",
                blk_hash);
        return false;
    }

    return true;
}
//------------------------------------------------------------------
//      Needs to validate the block and acquire each transaction from the
//      transaction mem_pool, then pass the block and transactions to
//      m_db->add_block()
bool Blockchain::handle_block_to_main_chain(
        const block& bl,
        const crypto::hash& id,
        block_verification_context& bvc,
        checkpoint_t const* checkpoint,
        bool notify) {
    log::trace(logcat, "Blockchain::{}", __func__);

    auto block_processing_start = std::chrono::steady_clock::now();
    std::unique_lock lock{*this};
    db_rtxn_guard rtxn_guard{*m_db};

    auto t1 = std::chrono::steady_clock::now();
    if (!basic_block_checks(bl, false /*alt_block*/)) {
        bvc.m_verifivation_failed = true;
        return false;
    }
    auto t1_elapsed = std::chrono::steady_clock::now() - t1;

    struct {
        std::chrono::nanoseconds verify_pow_time;
        block_pow_verified blk_pow = {};
    } miner = {};

    bool const pulse_block = bl.has_pulse();
    uint64_t const chain_height = get_current_blockchain_height();
    uint64_t current_diffic = get_difficulty_for_next_block(pulse_block);

    if (pulse_block) {
        // NOTE: Pulse blocks don't use PoW. They use Service Node signatures.
        // Delay signature verification until Service Node List adds the block in
        // the block_add hook.
    } else  // check proof of work
    {
        auto verify_pow_start = std::chrono::steady_clock::now();
        miner.blk_pow = verify_block_pow(bl, current_diffic, chain_height, false /*alt_block*/);
        miner.verify_pow_time = std::chrono::steady_clock::now() - verify_pow_start;

        if (!miner.blk_pow.valid) {
            bvc.m_verifivation_failed = true;
            return false;
        }

        if (miner.blk_pow.precomputed)
            miner.verify_pow_time += m_fake_pow_calc_time;
    }

    size_t const coinbase_weight = get_transaction_weight(bl.miner_tx);
    size_t cumulative_block_weight = coinbase_weight;

    std::vector<std::pair<transaction, std::string>> txs;
    key_images_container keys;

    uint64_t fee_summary = 0;
    auto t_checktx = 0ns;
    auto t_exists = 0ns;
    auto t_pool = 0ns;
    auto t_dblspnd = 0ns;

    size_t tx_index = 0;
    // Iterate over the block's transaction hashes, grabbing each
    // from the tx_pool and validating them.  Each is then added
    // to txs.  Keys spent in each are added to <keys> by the double spend check.
    txs.reserve(bl.tx_hashes.size());
    auto fail_handler = oxen::defer([this, &bvc, &txs] {
        bvc.m_verifivation_failed = true;
        return_tx_to_pool(txs);
    });

    auto hf_version = bl.major_version;

    for (size_t i = 0; i < bl.tx_hashes.size(); i++) {
        const crypto::hash& tx_id = bl.tx_hashes[i];
        const bool require_eth_state_tx = hf_version >= feature::ETH_BLS && i < bl.tx_eth_count;
        transaction tx_tmp;
        std::string txblob;
        size_t tx_weight = 0;
        uint64_t fee = 0;
        bool relayed = false, do_not_relay = false, double_spend_seen = false;
        auto aa = std::chrono::steady_clock::now();

        if (m_db->tx_exists(tx_id)) {
            log::info(
                    logcat,
                    fg(fmt::terminal_color::red),
                    "Block with id: {} attempting to add transaction already in blockchain with "
                    "id: {}",
                    id,
                    tx_id);
            return false;
        }

        auto bb = std::chrono::steady_clock::now();
        t_exists += bb - aa;

        // get transaction with hash <tx_id> from tx_pool
        if (!tx_pool.take_tx(
                    tx_id,
                    tx_tmp,
                    txblob,
                    tx_weight,
                    fee,
                    relayed,
                    do_not_relay,
                    double_spend_seen)) {
            log::info(
                    logcat,
                    fg(fmt::terminal_color::red),
                    "Block with id: {} has at least one unknown transaction with id: {}",
                    id,
                    tx_id);
            return false;
        }

        auto dd = std::chrono::steady_clock::now();
        t_pool += dd - bb;
        // add the transaction to the temp list of transactions, so we can either
        // store the list of transactions all at once or return the ones we've
        // taken from the tx_pool back to it if the block fails verification.
        txs.push_back(std::make_pair(std::move(tx_tmp), std::move(txblob)));
        transaction& tx = txs.back().first;

        if (require_eth_state_tx != is_l2_event_tx(tx.type)) {
            log::info(
                    logcat,
                    fg(fmt::terminal_color::red),
                    "Block with id: {} has invalid {}state change at tx index {} ({})",
                    id,
                    require_eth_state_tx ? "non-" : "",
                    i,
                    tx_id);
            return false;
        }

        // FIXME: the storage should not be responsible for validation.
        //        If it does any, it is merely a sanity check.
        //        Validation is the purview of the Blockchain class
        //        - TW
        //
        // ND: this is not needed, db->add_block() checks for duplicate k_images and fails
        // accordingly. if (!check_for_double_spend(tx, keys))
        // {
        //     log::warning(logcat, "Double spend detected in transaction (id: {}", tx_id);
        //     bvc.m_verifivation_failed = true;
        //     break;
        // }

        auto cc = std::chrono::steady_clock::now();
        t_dblspnd += cc - dd;

#if defined(PER_BLOCK_CHECKPOINT)
        if (!miner.blk_pow.per_block_checkpointed)
#endif
        {
            // validate that transaction inputs and the keys spending them are correct.
            tx_verification_context tvc{};
            if (!check_tx_inputs(tx, tvc)) {
                log::info(
                        logcat,
                        fg(fmt::terminal_color::red),
                        "Block with id: {} has at least one transaction (id: {}) with wrong "
                        "inputs.",
                        id,
                        tx_id);

                add_block_as_invalid(bl);
                log::info(
                        logcat,
                        fg(fmt::terminal_color::red),
                        "Block with id {} added as invalid because of wrong inputs in transactions",
                        id);
                log::info(
                        logcat,
                        fg(fmt::terminal_color::red),
                        "tx_index {}, m_blocks_txs_check {}:",
                        tx_index,
                        m_blocks_txs_check.size());
                for (const auto& h : m_blocks_txs_check)
                    log::error(log::Cat("verify"), "  {}", h);
                return false;
            }
        }
#if defined(PER_BLOCK_CHECKPOINT)
        else {
            // ND: if fast_check is enabled for blocks, there is no need to check
            // the transaction inputs, but do some sanity checks anyway.
            if (tx_index >= m_blocks_txs_check.size() ||
                memcmp(&m_blocks_txs_check[tx_index++], &tx_id, sizeof(tx_id)) != 0) {
                log::error(
                        log::Cat("verify"),
                        "Block with id: {} has at least one transaction (id: {}) with wrong "
                        "inputs.",
                        id,
                        tx_id);
                add_block_as_invalid(bl);
                log::error(
                        log::Cat("verify"),
                        "Block with id {} added as invalid because of wrong inputs in transactions",
                        id);
                return false;
            }
        }
#endif
        t_checktx += std::chrono::steady_clock::now() - cc;
        fee_summary += fee;
        cumulative_block_weight += tx_weight;
    }

    m_blocks_txs_check.clear();

    auto vmt = std::chrono::steady_clock::now();
    uint64_t base_reward = 0;
    uint64_t already_generated_coins =
            chain_height ? m_db->get_block_already_generated_coins(chain_height - 1) : 0;

    if (bl.major_version < feature::ETH_BLS && !validate_miner_transaction(
                                                       bl,
                                                       cumulative_block_weight,
                                                       fee_summary,
                                                       base_reward,
                                                       already_generated_coins,
                                                       get_network_version())) {
        log::info(
                logcat,
                fg(fmt::terminal_color::red),
                "Block {} with id: {} has incorrect miner transaction",
                chain_height,
                id);
        return false;
    }
    // Otherwise (ETH_BLS+) we've already checked that there is no miner tx in
    // prevalidate_miner_transaction

    auto vmt_elapsed = std::chrono::steady_clock::now() - vmt;
    // populate various metadata about the block to be stored alongside it.
    size_t block_weight = cumulative_block_weight;
    difficulty_type cumulative_difficulty = current_diffic;

    // In the "tail" state when the minimum subsidy (implemented in get_block_reward) is in effect,
    // the number of coins will eventually exceed MONEY_SUPPLY and overflow a uint64. To prevent
    // overflow, cap already_generated_coins at MONEY_SUPPLY. already_generated_coins is only used
    // to compute the block subsidy and MONEY_SUPPLY yields a subsidy of 0 under the base formula
    // and therefore the minimum subsidy >0 in the tail state.
    already_generated_coins = base_reward < (oxen::MONEY_SUPPLY - already_generated_coins)
                                    ? already_generated_coins + base_reward
                                    : oxen::MONEY_SUPPLY;
    if (chain_height)
        cumulative_difficulty += m_db->get_block_cumulative_difficulty(chain_height - 1);

    auto block_processing_time = std::chrono::steady_clock::now() - block_processing_start;
    if (miner.blk_pow.precomputed)
        block_processing_time += m_fake_pow_calc_time;

    rtxn_guard.stop();
    auto addblock = std::chrono::steady_clock::now();
    uint64_t new_height = 0;
    if (!bvc.m_verifivation_failed) {
        try {
            uint64_t long_term_block_weight = get_next_long_term_block_weight(block_weight);
            std::string bd = cryptonote::block_to_blob(bl);
            new_height = m_db->add_block(
                    std::make_pair(bl, std::move(bd)),
                    block_weight,
                    long_term_block_weight,
                    cumulative_difficulty,
                    already_generated_coins,
                    txs);
        } catch (const KEY_IMAGE_EXISTS& e) {
            log::info(
                    logcat,
                    fg(fmt::terminal_color::red),
                    "Error adding block with hash: {} to blockchain, what = {}",
                    id,
                    e.what());
            m_batch_success = false;
            return false;
        } catch (const std::exception& e) {
            // TODO: figure out the best way to deal with this failure
            log::info(
                    logcat,
                    fg(fmt::terminal_color::red),
                    "Error adding block with hash: {} to blockchain, what = {}",
                    id,
                    e.what());
            m_batch_success = false;
            return false;
        }
    } else {
        log::info(
                logcat,
                fg(fmt::terminal_color::red),
                "Blocks that failed verification should not reach here");
    }

    fail_handler.cancel();  // We've added the block now, so need a new failure handler that
                            // properly removes it if it fail beyond here:
    auto abort_block = oxen::defer([this]() {
        pop_block_from_blockchain();
        detached_info hook_data{m_db->height(), false /*by_pop_blocks*/};
        for (const auto& hook : m_blockchain_detached_hooks)
            hook(hook_data);
    });

    // TODO(oxen): Not nice, making the hook take in a vector of pair<transaction,
    // std::string> messes with service_node_list::init which only constructs
    // a vector of transactions and then subsequently calls block_add, so the
    // init step would have to intentionally allocate the blobs or retrieve them
    // from the DB.
    // Secondly we don't use the blobs at all in the hooks, so passing it in
    // doesn't seem right.
    std::vector<transaction> only_txs;
    only_txs.reserve(txs.size());
    for (std::pair<transaction, std::string> const& tx_pair : txs)
        only_txs.push_back(tx_pair.first);

    try {
        service_node_list.block_add(bl, only_txs, checkpoint);
    } catch (const std::exception& e) {
        log::info(
                logcat,
                fg(fmt::terminal_color::red),
                "Failed to add block to Service Node List: {}",
                e.what());
        bvc.m_verifivation_failed = true;
        return false;
    }

    if (!m_ons_db.add_block(bl, only_txs)) {
        log::info(logcat, fg(fmt::terminal_color::red), "Failed to add block to ONS DB.");
        bvc.m_verifivation_failed = true;
        return false;
    }
    if (m_sqlite_db) {
        // This takes the block that is already validated and records the rewards that should be
        // paid to the service nodes into the batching database
        if (!service_node_list.process_batching_rewards(bl)) {
            log::error(logcat, "Failed to add block to batch rewards DB.");
            bvc.m_verifivation_failed = true;
            return false;
        }
    } else {
        if (m_nettype != network_type::FAKECHAIN)
            throw oxen::traced<std::logic_error>("Blockchain missing SQLite Database");
    }

    block_add_info hook_data{bl, only_txs, checkpoint};
    for (const auto& hook : m_block_add_hooks) {
        try {
            hook(hook_data);
        } catch (const std::exception& e) {
            log::error(logcat, fg(fmt::terminal_color::red), "Failed to add block: {}", e.what());
            bvc.m_verifivation_failed = true;
            return false;
        }
    }
    auto addblock_elapsed = std::chrono::steady_clock::now() - addblock;

    // do this after updating the hard fork state since the weight limit may change due to fork
    if (!update_next_cumulative_weight_limit()) {
        log::info(
                logcat,
                fg(fmt::terminal_color::red),
                "Failed to update next cumulative weight limit");
        return false;
    }

    abort_block.cancel();
    uint64_t const fee_after_penalty = get_outs_money_amount(bl.miner_tx) - base_reward;
    if (bl.signatures.size() == service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES) {
        log::info(
                logcat,
                "\n+++++ PULSE BLOCK SUCCESSFULLY ADDED\n\tid: {}\n\tHEIGHT: {}, v{}.{}\n\tblock "
                "reward: {}({} + {}) , coinbase_weight: {}, cumulative weight: {}, {}ms",
                id,
                new_height - 1,
                static_cast<int>(bl.major_version),
                +bl.minor_version,
                print_money(fee_after_penalty + base_reward),
                print_money(base_reward),
                print_money(fee_after_penalty),
                coinbase_weight,
                cumulative_block_weight,
                tools::friendly_duration(block_processing_time));
    } else {
        assert(bl.signatures.empty() &&
               "Signatures were supposed to be checked in Service Node List already.");
        log::info(
                logcat,
                "\n+++++ MINER BLOCK SUCCESSFULLY ADDED\n\n\tid:  {}\n\tPoW: {}\n\tHEIGHT: {}, "
                "v{}.{}, difficulty: {}\n\tblock reward: {}({} + {}), coinbase_weight: {}, "
                "cumulative weight: {}, {}({})",
                id,
                miner.blk_pow.proof_of_work,
                new_height - 1,
                static_cast<int>(bl.major_version),
                +bl.minor_version,
                current_diffic,
                print_money(fee_after_penalty + base_reward),
                print_money(base_reward),
                print_money(fee_after_penalty),
                coinbase_weight,
                cumulative_block_weight,
                tools::friendly_duration(block_processing_time),
                tools::friendly_duration(miner.verify_pow_time));
    }
    if (m_show_time_stats) {
        log::info(
                logcat,
                "Height: {} coinbase weight: {} cumm: {} p/t: {} ({}/{}/{}/{}/{}/{}/{}/{})",
                new_height,
                coinbase_weight,
                cumulative_block_weight,
                tools::friendly_duration(block_processing_time),
                tools::friendly_duration(miner.verify_pow_time),
                tools::friendly_duration(t1_elapsed),
                tools::friendly_duration(t_exists),
                tools::friendly_duration(t_pool),
                tools::friendly_duration(t_checktx),
                tools::friendly_duration(t_dblspnd),
                tools::friendly_duration(vmt_elapsed),
                tools::friendly_duration(addblock_elapsed));
    }

    bvc.m_added_to_main_chain = true;
    ++m_sync_counter;
    tx_pool.on_blockchain_inc(bl);
    invalidate_block_template_cache();

    if (notify) {
        block_post_add_info hook_data{bl, /*reorg=*/false};
        for (const auto& hook : m_block_post_add_hooks)
            hook(hook_data);
    }
    return true;
}
//------------------------------------------------------------------
bool Blockchain::prune_blockchain(uint32_t pruning_seed) {
    auto lock = tools::unique_locks(tx_pool, *this);
    return m_db->prune_blockchain(pruning_seed);
}
//------------------------------------------------------------------
bool Blockchain::update_blockchain_pruning() {
    auto lock = tools::unique_locks(tx_pool, *this);
    return m_db->update_pruning();
}
//------------------------------------------------------------------
bool Blockchain::check_blockchain_pruning() {
    auto lock = tools::unique_locks(tx_pool, *this);
    return m_db->check_pruning();
}
//------------------------------------------------------------------
uint64_t Blockchain::get_next_long_term_block_weight(uint64_t block_weight) const {

    const uint64_t db_height = m_db->height();
    const uint64_t nblocks = std::min<uint64_t>(m_long_term_block_weights_window, db_height);

    if (!is_hard_fork_at_least(
                m_nettype, feature::LONG_TERM_BLOCK_WEIGHT, get_current_blockchain_height()))
        return block_weight;

    uint64_t long_term_median = get_long_term_block_weight_median(db_height - nblocks, nblocks);
    uint64_t long_term_effective_median_block_weight =
            std::max<uint64_t>(BLOCK_GRANTED_FULL_REWARD_ZONE_V5, long_term_median);

    uint64_t short_term_constraint = long_term_effective_median_block_weight +
                                     long_term_effective_median_block_weight * 2 / 5;
    uint64_t long_term_block_weight = std::min<uint64_t>(block_weight, short_term_constraint);

    return long_term_block_weight;
}
//------------------------------------------------------------------
bool Blockchain::update_next_cumulative_weight_limit(
        uint64_t* long_term_effective_median_block_weight) {

    log::trace(logcat, "Blockchain::{}", __func__);

    // when we reach this, the last hf version is not yet written to the db
    const uint64_t db_height = m_db->height();
    const auto hf_version = get_network_version();
    uint64_t full_reward_zone = get_min_block_weight(hf_version);

    if (hf_version < feature::LONG_TERM_BLOCK_WEIGHT) {
        std::vector<uint64_t> weights;
        get_last_n_blocks_weights(weights, REWARD_BLOCKS_WINDOW);
        m_current_block_cumul_weight_median = tools::median(std::move(weights));
    } else {
        const uint64_t block_weight = m_db->get_block_weight(db_height - 1);

        uint64_t long_term_median;
        if (db_height == 1) {
            long_term_median = BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
        } else {
            uint64_t nblocks = std::min<uint64_t>(m_long_term_block_weights_window, db_height);
            if (nblocks == db_height)
                --nblocks;
            long_term_median = get_long_term_block_weight_median(db_height - nblocks - 1, nblocks);
        }

        m_long_term_effective_median_block_weight =
                std::max<uint64_t>(BLOCK_GRANTED_FULL_REWARD_ZONE_V5, long_term_median);

        uint64_t short_term_constraint = m_long_term_effective_median_block_weight +
                                         m_long_term_effective_median_block_weight * 2 / 5;
        uint64_t long_term_block_weight = std::min<uint64_t>(block_weight, short_term_constraint);

        if (db_height == 1) {
            long_term_median = long_term_block_weight;
        } else {
            m_long_term_block_weights_cache_tip_hash =
                    m_db->get_block_hash_from_height(db_height - 1);
            m_long_term_block_weights_cache_rolling_median.insert(long_term_block_weight);
            long_term_median = m_long_term_block_weights_cache_rolling_median.median();
        }
        m_long_term_effective_median_block_weight =
                std::max<uint64_t>(BLOCK_GRANTED_FULL_REWARD_ZONE_V5, long_term_median);

        std::vector<uint64_t> weights;
        get_last_n_blocks_weights(weights, REWARD_BLOCKS_WINDOW);

        uint64_t short_term_median = tools::median(std::move(weights));
        uint64_t effective_median_block_weight = std::min<uint64_t>(
                std::max<uint64_t>(BLOCK_GRANTED_FULL_REWARD_ZONE_V5, short_term_median),
                SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR * m_long_term_effective_median_block_weight);

        m_current_block_cumul_weight_median = effective_median_block_weight;
    }

    if (m_current_block_cumul_weight_median <= full_reward_zone)
        m_current_block_cumul_weight_median = full_reward_zone;

    m_current_block_cumul_weight_limit = m_current_block_cumul_weight_median * 2;

    if (long_term_effective_median_block_weight)
        *long_term_effective_median_block_weight = m_long_term_effective_median_block_weight;

    if (!m_db->is_read_only())
        m_db->add_max_block_size(m_current_block_cumul_weight_limit);

    return true;
}
//------------------------------------------------------------------
bool Blockchain::add_new_block(
        const block& bl, block_verification_context& bvc, checkpoint_t const* checkpoint) {

    log::trace(logcat, "Blockchain::{}", __func__);
    crypto::hash id = get_block_hash(bl);
    auto lock = tools::unique_locks(tx_pool, *this);
    db_rtxn_guard rtxn_guard{*m_db};
    if (have_block(id)) {
        log::trace(logcat, "block with id = {} already exists", id);
        bvc.m_already_exists = true;
        m_blocks_txs_check.clear();
        return false;
    }

    if (checkpoint) {
        checkpoint_t existing_checkpoint;
        uint64_t block_height = bl.get_height();
        try {
            if (get_checkpoint(block_height, existing_checkpoint)) {
                if (checkpoint->signatures.size() < existing_checkpoint.signatures.size())
                    checkpoint = nullptr;
            }
        } catch (const std::exception& e) {
            log::error(
                    logcat,
                    "Get block checkpoint from DB failed at height: {}, what = {}",
                    block_height,
                    e.what());
        }
    }

    bool result = false;
    rtxn_guard.stop();
    if (bl.prev_id == get_tail_id().second)  // check that block refers to chain tail
    {
        result = handle_block_to_main_chain(bl, id, bvc, checkpoint);
    } else {
        // chain switching or wrong block
        bvc.m_added_to_main_chain = false;
        result = handle_alternative_block(bl, id, bvc, checkpoint);
        m_blocks_txs_check.clear();
        // never relay alternative blocks
    }

    return result;
}
//------------------------------------------------------------------
// returns false if any of the checkpoints loading returns false.
// That should happen only if a checkpoint is added that conflicts
// with an existing checkpoint.
bool Blockchain::update_checkpoints_from_json_file(const fs::path& file_path) {
    std::vector<height_to_hash> checkpoint_hashes;
    if (!cryptonote::load_checkpoints_from_json(file_path, checkpoint_hashes))
        return false;

    std::vector<height_to_hash>::const_iterator first_to_check = checkpoint_hashes.end();
    std::vector<height_to_hash>::const_iterator one_past_last_to_check = checkpoint_hashes.end();

    uint64_t prev_max_height = m_checkpoints.get_max_height();
    log::info(logcat, "Adding checkpoints from blockchain hashfile: {}", file_path);
    log::info(logcat, "Hard-coded max checkpoint height is {}", prev_max_height);
    for (std::vector<height_to_hash>::const_iterator it = checkpoint_hashes.begin();
         it != one_past_last_to_check;
         it++) {
        uint64_t height;
        height = it->height;
        if (height <= prev_max_height) {
            log::info(logcat, "ignoring checkpoint height {}", height);
        } else {
            if (first_to_check == checkpoint_hashes.end())
                first_to_check = it;

            std::string blockhash = it->hash;
            log::info(logcat, "Adding checkpoint height {}, hash={}", height, blockhash);

            if (!m_checkpoints.add_checkpoint(height, blockhash)) {
                one_past_last_to_check = it;
                log::info(
                        logcat,
                        "Failed to add checkpoint at height {}, hash={}",
                        height,
                        blockhash);
                break;
            }
        }
    }

    /*
     * If a block fails a checkpoint the blockchain
     * will be rolled back to two blocks prior to that block.
     */
    // TODO: Refactor, consider returning a failure height and letting
    //       caller decide course of action.
    bool result = true;
    {
        std::unique_lock lock{*this};
        bool stop_batch = m_db->batch_start();

        for (std::vector<height_to_hash>::const_iterator it = first_to_check;
             it != one_past_last_to_check;
             it++) {
            uint64_t block_height = it->height;
            if (block_height >=
                m_db->height())  // if the checkpoint is for a block we don't have yet, move on
                break;

            if (!m_checkpoints.check_block(
                        block_height, m_db->get_block_hash_from_height(block_height), nullptr)) {
                // roll back to a couple of blocks before the checkpoint
                log::error(logcat, "Local blockchain failed to pass a checkpoint, rolling back!");
                std::list<block_and_checkpoint> empty;
                rollback_blockchain_switching(empty, block_height - 2);
                result = false;
            }
        }

        if (stop_batch)
            m_db->batch_stop();
    }

    return result;
}
//------------------------------------------------------------------
bool Blockchain::update_checkpoint(cryptonote::checkpoint_t const& checkpoint) {
    std::unique_lock lock{*this};
    bool result = m_checkpoints.update_checkpoint(checkpoint);
    return result;
}
//------------------------------------------------------------------
bool Blockchain::get_checkpoint(uint64_t height, checkpoint_t& checkpoint) const {
    std::unique_lock lock{*this};
    return m_checkpoints.get_checkpoint(height, checkpoint);
}
//------------------------------------------------------------------
void Blockchain::block_longhash_worker(
        uint64_t height,
        const epee::span<const block>& blocks,
        std::unordered_map<crypto::hash, crypto::hash>& map) const {
    for (const auto& block : blocks) {
        if (m_cancel)
            break;
        crypto::hash id = get_block_hash(block);
        crypto::hash pow = get_block_longhash_w_blockchain(m_nettype, this, block, height++, 0);
        map.emplace(id, pow);
    }
}

//------------------------------------------------------------------
bool Blockchain::cleanup_handle_incoming_blocks(bool force_sync) {
    bool success = false;
    log::trace(logcat, "Blockchain::{}", __func__);

    try {
        if (m_batch_success)
            m_db->batch_stop();
        else
            m_db->batch_abort();
        success = true;
    } catch (const std::exception& e) {
        log::error(logcat, "Exception in cleanup_handle_incoming_blocks: {}", e.what());
    }

    if (success && m_sync_counter > 0) {
        if (force_sync) {
            if (m_db_sync_mode != db_nosync)
                store_blockchain();
            m_sync_counter = 0;
        } else if (
                m_db_sync_threshold &&
                ((m_db_sync_on_blocks && m_sync_counter >= m_db_sync_threshold) ||
                 (!m_db_sync_on_blocks && m_bytes_to_sync >= m_db_sync_threshold))) {
            log::debug(logcat, "Sync threshold met, syncing");
            if (m_db_sync_mode == db_async) {
                m_sync_counter = 0;
                m_bytes_to_sync = 0;
                m_async_service.dispatch([this] { return store_blockchain(); });
            } else if (m_db_sync_mode == db_sync) {
                store_blockchain();
            } else  // db_nosync
            {
                // DO NOTHING, not required to call sync.
            }
        }
    }

    m_blocks_longhash_table.clear();
    m_scan_table.clear();
    m_blocks_txs_check.clear();

    // when we're well clear of the precomputed hashes, free the memory
    if (!m_blocks_hash_check.empty() && m_db->height() > m_blocks_hash_check.size() + 4096) {
        log::info(logcat, "Dumping block hashes, we're now 4k past {}", m_blocks_hash_check.size());
        m_blocks_hash_check.clear();
        m_blocks_hash_check.shrink_to_fit();
    }

    unlock();
    tx_pool.unlock();

    update_blockchain_pruning();

    return success;
}

uint64_t Blockchain::prevalidate_block_hashes(
        uint64_t height, const std::vector<crypto::hash>& hashes) {
    // new: . . . . . X X X X X . . . . . .
    // pre: A A A A B B B B C C C C D D D D

    // easy case: height >= hashes
    if (height >= m_blocks_hash_of_hashes.size() * HASH_OF_HASHES_STEP)
        return hashes.size();

    // if we're getting old blocks, we might have jettisoned the hashes already
    if (m_blocks_hash_check.empty())
        return hashes.size();

    // find hashes encompassing those block
    size_t first_index = height / HASH_OF_HASHES_STEP;
    size_t last_index = (height + hashes.size() - 1) / HASH_OF_HASHES_STEP;
    log::debug(
            logcat,
            "Blocks {} - {} start at {} and end at {}",
            height,
            (height + hashes.size() - 1),
            first_index,
            last_index);

    // case of not enough to calculate even a single hash
    if (first_index == last_index && hashes.size() < HASH_OF_HASHES_STEP &&
        (height + hashes.size()) % HASH_OF_HASHES_STEP)
        return hashes.size();

    // build hashes vector to hash hashes together
    std::vector<crypto::hash> data;
    data.reserve(hashes.size() + HASH_OF_HASHES_STEP - 1);  // may be a bit too much

    // we expect height to be either equal or a bit below db height
    bool disconnected = (height > m_db->height());
    size_t pop;
    if (disconnected && height % HASH_OF_HASHES_STEP) {
        ++first_index;
        pop = HASH_OF_HASHES_STEP - height % HASH_OF_HASHES_STEP;
    } else {
        // we might need some already in the chain for the first part of the first hash
        for (uint64_t h = first_index * HASH_OF_HASHES_STEP; h < height; ++h) {
            data.push_back(m_db->get_block_hash_from_height(h));
        }
        pop = 0;
    }

    // push the data to check
    for (const auto& h : hashes) {
        if (pop)
            --pop;
        else
            data.push_back(h);
    }

    // hash and check
    uint64_t usable = first_index * HASH_OF_HASHES_STEP -
                      height;  // may start negative, but unsigned under/overflow is not UB
    for (size_t n = first_index; n <= last_index; ++n) {
        if (n < m_blocks_hash_of_hashes.size()) {
            // if the last index isn't fully filled, we can't tell if valid
            if (data.size() < (n - first_index) * HASH_OF_HASHES_STEP + HASH_OF_HASHES_STEP)
                break;

            crypto::hash hash;
            cn_fast_hash(
                    data.data() + (n - first_index) * HASH_OF_HASHES_STEP,
                    HASH_OF_HASHES_STEP * sizeof(crypto::hash),
                    hash);
            bool valid = hash == m_blocks_hash_of_hashes[n];

            // add to the known hashes array
            if (!valid) {
                log::debug(
                        logcat,
                        "invalid hash for blocks {} - {}",
                        n * HASH_OF_HASHES_STEP,
                        (n * HASH_OF_HASHES_STEP + HASH_OF_HASHES_STEP - 1));
                break;
            }

            size_t end = n * HASH_OF_HASHES_STEP + HASH_OF_HASHES_STEP;
            for (size_t i = n * HASH_OF_HASHES_STEP; i < end; ++i) {
                CHECK_AND_ASSERT_MES(
                        !m_blocks_hash_check[i] ||
                                m_blocks_hash_check[i] ==
                                        data[i - first_index * HASH_OF_HASHES_STEP],
                        0,
                        "Consistency failure in m_blocks_hash_check construction");
                m_blocks_hash_check[i] = data[i - first_index * HASH_OF_HASHES_STEP];
            }
            usable += HASH_OF_HASHES_STEP;
        } else {
            // if after the end of the precomputed blocks, accept anything
            usable += HASH_OF_HASHES_STEP;
            if (usable > hashes.size())
                usable = hashes.size();
        }
    }
    log::debug(logcat, "usable: {} / {}", usable, hashes.size());
    CHECK_AND_ASSERT_MES(
            usable < std::numeric_limits<uint64_t>::max() / 2, 0, "usable is negative");
    return usable;
}

bool Blockchain::calc_batched_governance_reward(uint64_t height, uint64_t& reward) const {
    reward = 0;
    auto hard_fork_version = get_network_version(height);
    if (hard_fork_version <= hf::hf9_service_nodes) {
        return true;
    }

    if (!height_has_governance_output(nettype(), hard_fork_version, height)) {
        return true;
    }

    // Constant reward every block at HF19 and batched through service node batching
    if (hard_fork_version >= hf::hf19_reward_batching) {
        reward = cryptonote::governance_reward_formula(hard_fork_version);
        return true;
    }

    // Ignore governance reward and payout instead the last
    // GOVERNANCE_BLOCK_REWARD_INTERVAL number of blocks governance rewards.  We
    // come back for this height's rewards in the next interval. The reward is
    // 0 if it's not time to pay out the batched payments (in which case we
    // already returned, above).

    auto& conf = get_config(m_nettype);
    size_t num_blocks = conf.BLOCKS_IN(conf.GOVERNANCE_REWARD_INTERVAL);

    // Fixed reward starting at HF15
    if (hard_fork_version >= hf::hf15_ons) {
        reward = num_blocks *
                 (hard_fork_version >= hf::hf17 ? oxen::FOUNDATION_REWARD_HF17
                  : hard_fork_version >= hf::hf16_pulse
                          ? oxen::FOUNDATION_REWARD_HF15 + oxen::CHAINFLIP_LIQUIDITY_HF16
                          : oxen::FOUNDATION_REWARD_HF15);
        return true;
    }

    uint64_t start_height = height - num_blocks;
    if (height < num_blocks) {
        start_height = 0;
        num_blocks = height;
    }

    std::vector<cryptonote::block> blocks;
    if (!get_blocks(start_height, num_blocks, blocks)) {
        log::error(
                logcat, "Unable to get historical blocks to calculated batched governance payment");
        return false;
    }

    for (const auto& block : blocks) {
        if (block.major_version >= hf::hf10_bulletproofs)
            reward += derive_governance_from_block_reward(nettype(), block, hard_fork_version);
    }

    return true;
}

//------------------------------------------------------------------
// ND: Speedups:
// 1. Thread long_hash computations if possible (m_max_prepare_blocks_threads = nthreads, default =
// 4)
// 2. Group all amounts (from txs) and related absolute offsets and form a table of tx_prefix_hash
//    vs [k_image, output_keys] (m_scan_table). This is faster because it takes advantage of bulk
//    queries and is threaded if possible. The table (m_scan_table) will be used later when querying
//    output keys.
bool Blockchain::prepare_handle_incoming_blocks(
        const std::vector<block_complete_entry>& blocks_entry, std::vector<block>& blocks) {
    log::trace(logcat, "Blockchain::{}", __func__);
    auto prepare = std::chrono::steady_clock::now();
    uint64_t bytes = 0;
    size_t total_txs = 0;
    blocks.clear();

    // Order of locking must be:
    //  m_incoming_tx_lock (optional)
    //  tx_pool lock
    //  blockchain lock
    //
    //  Something which takes the blockchain lock may never take the txpool lock
    //  if it has not provably taken the txpool lock earlier
    //
    //  The txpool lock and blockchain lock are now taken here
    //  and released in cleanup_handle_incoming_blocks. This avoids issues
    //  when something uses the pool, which now uses the blockchain and
    //  needs a batch, since a batch could otherwise be active while the
    //  txpool and blockchain locks were not held

    std::lock(tx_pool, *this);

    if (blocks_entry.size() == 0)
        return false;

    for (const auto& entry : blocks_entry) {
        bytes += entry.block.size();
        bytes += entry.checkpoint.size();
        for (const auto& tx_blob : entry.txs) {
            bytes += tx_blob.size();
        }
        total_txs += entry.txs.size();
    }
    m_bytes_to_sync += bytes;
    while (!m_db->batch_start(blocks_entry.size(), bytes)) {
        unlock();
        tx_pool.unlock();
        std::this_thread::sleep_for(100ms);
        std::lock(tx_pool, *this);
    }
    m_batch_success = true;

    const uint64_t height = m_db->height();
    if ((height + blocks_entry.size()) < m_blocks_hash_check.size())
        return true;

    bool blocks_exist = false;
    tools::threadpool& tpool = tools::threadpool::getInstance();
    unsigned threads = tpool.get_max_concurrency();
    blocks.resize(blocks_entry.size());

    {
        // limit threads, default limit = 4
        if (threads > m_max_prepare_blocks_threads)
            threads = m_max_prepare_blocks_threads;

        unsigned int batches = blocks_entry.size() / threads;
        unsigned int extra = blocks_entry.size() % threads;
        log::debug(logcat, "block_batches: {}", batches);
        std::vector<std::unordered_map<crypto::hash, crypto::hash>> maps(threads);
        auto it = blocks_entry.begin();
        unsigned blockidx = 0;

        const crypto::hash tophash = m_db->top_block_hash();
        for (unsigned i = 0; i < threads; i++) {
            for (unsigned int j = 0; j < batches; j++, ++blockidx) {
                block& block = blocks[blockidx];
                crypto::hash block_hash;

                if (!parse_and_validate_block_from_blob(it->block, block, block_hash))
                    return false;

                // check first block and skip all blocks if its not chained properly
                if (blockidx == 0) {
                    if (block.prev_id != tophash) {
                        log::debug(
                                logcat,
                                "Skipping prepare blocks. New blocks don't belong to chain.");
                        blocks.clear();
                        return true;
                    }
                }
                if (have_block(block_hash))
                    blocks_exist = true;

                std::advance(it, 1);
            }
        }

        for (unsigned i = 0; i < extra && !blocks_exist; i++, blockidx++) {
            block& block = blocks[blockidx];
            crypto::hash block_hash;

            if (!parse_and_validate_block_from_blob(it->block, block, block_hash))
                return false;

            if (have_block(block_hash))
                blocks_exist = true;

            std::advance(it, 1);
        }

        if (!blocks_exist && blocks[0].major_version < feature::PULSE) {
            // This code multi-threads the pow hash cache (m_blocks_longhash_table), but in pulse we
            // rarely use those values (and if isn't set all that happens is that the pow hash gets
            // computed later), so skip this entirely post-pulse.
            m_blocks_longhash_table.clear();
            uint64_t thread_height = height;
            tools::threadpool::waiter waiter;
            m_prepare_height = height;
            m_prepare_nblocks = blocks_entry.size();
            m_prepare_blocks = &blocks;
            for (unsigned int i = 0; i < threads; i++) {
                unsigned nblocks = batches;
                if (i < extra)
                    ++nblocks;
                tpool.submit(
                        &waiter,
                        [this,
                         thread_height,
                         blocks = epee::span<const block>(&blocks[thread_height - height], nblocks),
                         &map = maps[i]] { block_longhash_worker(thread_height, blocks, map); },
                        true);
                thread_height += nblocks;
            }

            waiter.wait(&tpool);
            m_prepare_height = 0;

            if (m_cancel)
                return false;

            for (const auto& map : maps) {
                m_blocks_longhash_table.insert(map.begin(), map.end());
            }
        }
    }

    if (m_cancel)
        return false;

    if (blocks_exist) {
        log::debug(logcat, "Skipping remainder of prepare blocks. Blocks exist.");
        return true;
    }

    m_fake_scan_time = 0ns;
    m_fake_pow_calc_time = 0ns;

    m_scan_table.clear();

    auto prepare_elapsed = std::chrono::steady_clock::now() - prepare;
    m_fake_pow_calc_time = prepare_elapsed / blocks_entry.size();

    if (blocks_entry.size() > 1 && threads > 1 && m_show_time_stats)
        log::debug(logcat, "Prepare blocks took: {}", tools::friendly_duration(prepare_elapsed));

    auto scantable = std::chrono::steady_clock::now();

    // [input] stores all absolute_offsets for each amount
    std::vector<uint64_t> offsets;
    // [output] stores all output_data_t for each absolute_offset
    std::vector<output_data_t> txs;
    std::vector<std::pair<cryptonote::transaction, crypto::hash>> txes(total_txs);

    // generate absolute offsets
    size_t tx_index = 0;
    for (const auto& entry : blocks_entry) {
        if (m_cancel)
            return false;

        for (const auto& tx_blob : entry.txs) {
            if (tx_index >= txes.size()) {
                log::error(log::Cat("verify"), "tx_index is out of sync");
                m_scan_table.clear();
                return false;
            }
            transaction& tx = txes[tx_index].first;
            crypto::hash& tx_prefix_hash = txes[tx_index].second;
            ++tx_index;

            if (!parse_and_validate_tx_base_from_blob(tx_blob, tx)) {
                log::error(log::Cat("verify"), "Could not parse tx from incoming blocks");
                m_scan_table.clear();
                return false;
            }
            cryptonote::get_transaction_prefix_hash(tx, tx_prefix_hash);

            auto its = m_scan_table.find(tx_prefix_hash);
            if (its != m_scan_table.end()) {
                log::error(log::Cat("verify"), "Duplicate tx found from incoming blocks.");
                m_scan_table.clear();
                return false;
            }

            m_scan_table.emplace(
                    tx_prefix_hash,
                    std::unordered_map<crypto::key_image, std::vector<output_data_t>>());
            its = m_scan_table.find(tx_prefix_hash);
            assert(its != m_scan_table.end());

            // check all tx.vin(s)
            if (!tx.is_miner_tx()) {
                for (const auto& txin : tx.vin) {
                    const auto& in_to_key = var::get<txin_to_key>(txin);

                    // check for duplicate
                    auto it = its->second.find(in_to_key.k_image);
                    if (it != its->second.end()) {
                        log::error(
                                log::Cat("verify"),
                                "Duplicate key_image found from incoming blocks.");
                        m_scan_table.clear();
                        return false;
                    }
                }

                // add new absolute offsets to offsets
                if (!tx.is_miner_tx())
                    for (const auto& txin : tx.vin)
                        for (auto off : relative_output_offsets_to_absolute(
                                     var::get<txin_to_key>(txin).key_offsets))
                            offsets.push_back(off);
            }
        }
    }

    // sort and remove duplicate absolute_offsets in offset_map
    std::sort(offsets.begin(), offsets.end());
    auto last = std::unique(offsets.begin(), offsets.end());
    offsets.erase(last, offsets.end());

    try {
        constexpr uint64_t amount{0};
        m_db->get_output_key(epee::span<const uint64_t>(&amount, 1), offsets, txs, true);
    } catch (const std::exception& e) {
        log::error(log::Cat("verify"), "EXCEPTION: {}", e.what());
    } catch (...) {
    }

    // now generate a table for each tx_prefix and k_image hashes
    tx_index = 0;
    for (const auto& entry : blocks_entry) {
        if (m_cancel)
            return false;

        for (const auto& tx_blob : entry.txs) {
            if (tx_index >= txes.size()) {
                log::error(log::Cat("verify"), "tx_index is out of sync");
                m_scan_table.clear();
                return false;
            }
            const transaction& tx = txes[tx_index].first;
            const crypto::hash& tx_prefix_hash = txes[tx_index].second;
            ++tx_index;

            auto its = m_scan_table.find(tx_prefix_hash);
            if (its == m_scan_table.end()) {
                log::error(log::Cat("verify"), "Tx not found on scan table from incoming blocks.");
                m_scan_table.clear();
                return false;
            }

            if (!tx.is_miner_tx()) {
                for (const auto& txin : tx.vin) {
                    const txin_to_key& in_to_key = var::get<txin_to_key>(txin);
                    auto needed_offsets =
                            relative_output_offsets_to_absolute(in_to_key.key_offsets);

                    std::vector<output_data_t> outputs;
                    for (const uint64_t& offset_needed : needed_offsets) {
                        size_t pos = 0;
                        bool found = false;

                        for (const uint64_t& offset_found : offsets) {
                            if (offset_needed == offset_found) {
                                found = true;
                                break;
                            }

                            ++pos;
                        }

                        if (found && pos < txs.size())
                            outputs.push_back(txs.at(pos));
                        else
                            break;
                    }

                    its->second.emplace(in_to_key.k_image, outputs);
                }
            }
        }
    }

    if (total_txs > 0) {
        auto scantable_elapsed = std::chrono::steady_clock::now() - scantable;
        m_fake_scan_time = scantable_elapsed / total_txs;
        if (m_show_time_stats)
            log::debug(
                    logcat,
                    "Prepare scantable took: {}",
                    tools::friendly_duration(scantable_elapsed));
    }

    return true;
}

uint64_t Blockchain::get_immutable_height() const {
    std::unique_lock lock{*this};
    checkpoint_t checkpoint;
    if (m_db->get_immutable_checkpoint(&checkpoint, get_current_blockchain_height()))
        return checkpoint.height;
    return 0;
}

void Blockchain::set_user_options(
        uint64_t maxthreads,
        bool sync_on_blocks,
        uint64_t sync_threshold,
        blockchain_db_sync_mode sync_mode,
        bool fast_sync) {
    if (sync_mode == db_defaultsync) {
        m_db_default_sync = true;
        sync_mode = db_async;
    }
    m_db_sync_mode = sync_mode;
    m_fast_sync = fast_sync;
    m_db_sync_on_blocks = sync_on_blocks;
    m_db_sync_threshold = sync_threshold;
    m_max_prepare_blocks_threads = maxthreads;
}

void Blockchain::safesyncmode(const bool onoff) {
    /* all of this is no-op'd if the user set a specific
     * --db-sync-mode at startup.
     */
    if (m_db_default_sync) {
        m_db->safesyncmode(onoff);
        m_db_sync_mode = onoff ? db_nosync : db_async;
    }
}

std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> Blockchain::get_output_histogram(
        const std::vector<uint64_t>& amounts,
        bool unlocked,
        uint64_t recent_cutoff,
        uint64_t min_count) const {
    return m_db->get_output_histogram(amounts, unlocked, recent_cutoff, min_count);
}

std::vector<std::pair<Blockchain::block_extended_info, std::vector<crypto::hash>>>
Blockchain::get_alternative_chains() const {
    std::vector<std::pair<Blockchain::block_extended_info, std::vector<crypto::hash>>> chains;

    blocks_ext_by_hash alt_blocks;
    alt_blocks.reserve(m_db->get_alt_block_count());
    m_db->for_all_alt_blocks(
            [&alt_blocks](
                    const crypto::hash& /*blkid*/,
                    const cryptonote::alt_block_data_t& data,
                    const std::string* block_blob,
                    const std::string* checkpoint_blob) {
                if (!block_blob) {
                    log::error(logcat, "No blob, but blobs were requested");
                    return false;
                }

                checkpoint_t checkpoint = {};
                if (data.checkpointed && checkpoint_blob) {
                    if (!t_serializable_object_from_blob(checkpoint, *checkpoint_blob))
                        log::error(logcat, "Failed to parse checkpoint from blob");
                }

                cryptonote::block block;
                if (cryptonote::parse_and_validate_block_from_blob(*block_blob, block)) {
                    block_extended_info bei(
                            data, std::move(block), data.checkpointed ? &checkpoint : nullptr);
                    alt_blocks.insert(
                            std::make_pair(cryptonote::get_block_hash(bei.bl), std::move(bei)));
                } else
                    log::error(logcat, "Failed to parse block from blob");
                return true;
            },
            true);

    for (const auto& i : alt_blocks) {
        const crypto::hash top = cryptonote::get_block_hash(i.second.bl);
        bool found = false;
        for (const auto& j : alt_blocks) {
            if (j.second.bl.prev_id == top) {
                found = true;
                break;
            }
        }
        if (!found) {
            std::vector<crypto::hash> chain;
            auto h = i.second.bl.prev_id;
            chain.push_back(top);
            blocks_ext_by_hash::const_iterator prev;
            while ((prev = alt_blocks.find(h)) != alt_blocks.end()) {
                chain.push_back(h);
                h = prev->second.bl.prev_id;
            }
            chains.push_back(std::make_pair(i.second, chain));
        }
    }
    return chains;
}

void Blockchain::cancel() {
    m_cancel = true;
}

#if defined(PER_BLOCK_CHECKPOINT)
void Blockchain::load_compiled_in_block_hashes(const GetCheckpointsCallback& get_checkpoints) {
    if (!get_checkpoints || !m_fast_sync) {
        return;
    }
    std::string_view checkpoints = get_checkpoints(m_nettype);
    if (!checkpoints.empty()) {
        log::info(logcat, "Loading precomputed blocks ({} bytes)", checkpoints.size());
        if (m_nettype == network_type::MAINNET) {
            // first check hash
            crypto::hash hash;
            if (!tools::sha256sum_str(checkpoints, hash)) {
                log::error(logcat, "Failed to hash precomputed blocks data");
                return;
            }

            constexpr auto EXPECTED_SHA256_HASH =
                    "d5772a74dadb64a439b60312f9dc3e5243157c5477037a318840b8c36da9644b"sv;
            log::info(
                    logcat, "Precomputed blocks hash: {}, expected {}", hash, EXPECTED_SHA256_HASH);

            assert(EXPECTED_SHA256_HASH.size() == 2 * sizeof(crypto::hash) &&
                   oxenc::is_hex(EXPECTED_SHA256_HASH));
            auto expected_hash = tools::make_from_hex_guts<crypto::hash>(EXPECTED_SHA256_HASH);

            if (hash != expected_hash) {
                log::error(logcat, "Block hash data does not match expected hash");
                return;
            }
        }

        if (checkpoints.size() > 4) {
            auto nblocks = oxenc::load_little_to_host<uint32_t>(checkpoints.data());
            if (nblocks > (std::numeric_limits<uint32_t>::max() - 4) / sizeof(hash)) {
                log::error(logcat, "Block hash data is too large");
                return;
            }
            const size_t size_needed = 4 + (nblocks * sizeof(crypto::hash));
            if (checkpoints.size() != size_needed) {
                log::error(
                        logcat,
                        "Failed to load hashes - unexpected data size {}, expected {}",
                        checkpoints.size(),
                        size_needed);
                return;
            } else if (
                    nblocks > 0 &&
                    nblocks > (m_db->height() + HASH_OF_HASHES_STEP - 1) / HASH_OF_HASHES_STEP) {
                checkpoints.remove_prefix(4);
                m_blocks_hash_of_hashes.reserve(nblocks);
                for (uint32_t i = 0; i < nblocks; i++) {
                    crypto::hash& hash = m_blocks_hash_of_hashes.emplace_back();
                    std::memcpy(hash.data(), checkpoints.data(), hash.size());
                    checkpoints.remove_prefix(hash.size());
                }
                m_blocks_hash_check.resize(
                        m_blocks_hash_of_hashes.size() * HASH_OF_HASHES_STEP, null<hash>);
                log::info(logcat, "{} block hashes loaded", nblocks);

                // FIXME: clear tx_pool because the process might have been
                // terminated and caused it to store txs kept by blocks.
                // The core will not call check_tx_inputs(..) for these
                // transactions in this case. Consequently, the sanity check
                // for tx hashes will fail in handle_block_to_main_chain(..)
                std::unique_lock lock{tx_pool};

                std::vector<transaction> txs;
                tx_pool.get_transactions(txs);

                size_t tx_weight;
                uint64_t fee;
                bool relayed, do_not_relay, double_spend_seen;
                transaction pool_tx;
                std::string txblob;
                for (const transaction& tx : txs) {
                    crypto::hash tx_hash = get_transaction_hash(tx);
                    tx_pool.take_tx(
                            tx_hash,
                            pool_tx,
                            txblob,
                            tx_weight,
                            fee,
                            relayed,
                            do_not_relay,
                            double_spend_seen);
                }
            }
        }
    }
}
#endif

bool Blockchain::is_within_compiled_block_hash_area(uint64_t height) const {
#if defined(PER_BLOCK_CHECKPOINT)
    return height < m_blocks_hash_of_hashes.size() * HASH_OF_HASHES_STEP;
#else
    return false;
#endif
}

bool Blockchain::for_all_key_images(std::function<bool(const crypto::key_image&)> f) const {
    return m_db->for_all_key_images(f);
}

bool Blockchain::for_blocks_range(
        const uint64_t& h1,
        const uint64_t& h2,
        std::function<bool(uint64_t, const crypto::hash&, const block&)> f) const {
    return m_db->for_blocks_range(h1, h2, f);
}

bool Blockchain::for_all_transactions(
        std::function<bool(const crypto::hash&, const cryptonote::transaction&)> f,
        bool pruned) const {
    return m_db->for_all_transactions(f, pruned);
}

bool Blockchain::for_all_outputs(
        std::function<bool(
                uint64_t amount, const crypto::hash& tx_hash, uint64_t height, size_t tx_idx)> f)
        const {
    return m_db->for_all_outputs(f);
}

bool Blockchain::for_all_outputs(uint64_t amount, std::function<bool(uint64_t height)> f) const {
    return m_db->for_all_outputs(amount, f);
}

void Blockchain::invalidate_block_template_cache() {
    log::debug(logcat, "Invalidating block template cache");
    m_btc_valid = false;
}

void Blockchain::cache_block_template(
        const block& b,
        const cryptonote::account_public_address& address,
        const std::string& nonce,
        const difficulty_type& /*diff*/,
        uint64_t height,
        uint64_t expected_reward,
        uint64_t pool_cookie) {
    log::debug(logcat, "Setting block template cache");
    m_btc = b;
    m_btc_address = address;
    m_btc_nonce = nonce;
    m_btc_height = height;
    m_btc_expected_reward = expected_reward;
    m_btc_pool_cookie = pool_cookie;
    m_btc_valid = true;
}
