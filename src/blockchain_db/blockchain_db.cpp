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

#include "blockchain_db.h"

#include <chrono>
#include <cpptrace/cpptrace.hpp>

#include "checkpoints/checkpoints.h"
#include "common/string_util.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_core/service_node_rules.h"
#include "epee/string_tools.h"
#include "lmdb/db_lmdb.h"
#include "ringct/rctOps.h"

namespace cryptonote {

static auto logcat = log::Cat("blockchain.db");

const command_line::arg_descriptor<std::string> arg_db_sync_mode = {
        "db-sync-mode",
        "Specify sync option, using format "
        "[safe|fast|fastest]:[sync|async]:[<nblocks_per_sync>[blocks]|<nbytes_per_sync>[bytes]].",
        "fast:async:250000000bytes"};
const command_line::arg_descriptor<bool> arg_db_salvage = {
        "db-salvage", "Try to salvage a blockchain database if it seems corrupted", false};

BlockchainDB* new_db() {
    return new BlockchainLMDB();
}

void BlockchainDB::init_options(boost::program_options::options_description& desc) {
    command_line::add_arg(desc, arg_db_sync_mode);
    command_line::add_arg(desc, arg_db_salvage);
}

void BlockchainDB::pop_block() {
    block blk;
    std::vector<transaction> txs;
    pop_block(blk, txs);
}

void BlockchainDB::add_transaction(
        const crypto::hash& blk_hash,
        const std::pair<transaction, std::string>& txp,
        const crypto::hash* tx_hash_ptr,
        const crypto::hash* tx_prunable_hash_ptr) {
    const transaction& tx = txp.first;

    bool miner_tx = false;
    crypto::hash tx_hash, tx_prunable_hash;
    if (!tx_hash_ptr) {
        // should only need to compute hash for miner transactions
        tx_hash = get_transaction_hash(tx);
        log::trace(logcat, "null tx_hash_ptr - needed to compute: {}", tx_hash);
    } else {
        tx_hash = *tx_hash_ptr;
    }

    bool has_blacklisted_outputs = false;
    if (tx.version >= cryptonote::txversion::v2_ringct) {
        if (!tx_prunable_hash_ptr)
            tx_prunable_hash = get_transaction_prunable_hash(tx, &txp.second);
        else
            tx_prunable_hash = *tx_prunable_hash_ptr;

        crypto::secret_key secret_tx_key;
        cryptonote::account_public_address address;
        if (get_tx_secret_key_from_tx_extra(tx.extra, secret_tx_key) &&
            get_service_node_contributor_from_tx_extra(tx.extra, address))
            has_blacklisted_outputs = true;
    }

    for (const txin_v& tx_input : tx.vin) {
        if (std::holds_alternative<txin_to_key>(tx_input)) {
            add_spent_key(var::get<txin_to_key>(tx_input).k_image);
        } else if (std::holds_alternative<txin_gen>(tx_input)) {
            /* nothing to do here */
            miner_tx = true;
        } else {
            log::info(
                    logcat,
                    "Unsupported input type, removing key images and aborting transaction "
                    "addition");
            for (const txin_v& tx_input : tx.vin) {
                if (std::holds_alternative<txin_to_key>(tx_input)) {
                    remove_spent_key(var::get<txin_to_key>(tx_input).k_image);
                }
            }
            return;
        }
    }

    uint64_t tx_id = add_transaction_data(blk_hash, txp, tx_hash, tx_prunable_hash);

    std::vector<uint64_t> amount_output_indices(tx.vout.size());

    // iterate tx.vout using indices instead of C++11 foreach syntax because
    // we need the index
    for (uint64_t i = 0; i < tx.vout.size(); ++i) {
        uint64_t unlock_time = 0;
        if (tx.version >= cryptonote::txversion::v3_per_output_unlock_times) {
            unlock_time = tx.output_unlock_times[i];
        } else {
            unlock_time = tx.unlock_time;
        }

        // miner v2 txes have their coinbase output in one single out to save space,
        // and we store them as rct outputs with an identity mask
        if (miner_tx && tx.version >= cryptonote::txversion::v2_ringct) {
            cryptonote::tx_out vout = tx.vout[i];
            const rct::key commitment = rct::zeroCommit(vout.amount);
            vout.amount = 0;
            amount_output_indices[i] = add_output(tx_hash, vout, i, unlock_time, &commitment);
        } else {
            amount_output_indices[i] = add_output(
                    tx_hash,
                    tx.vout[i],
                    i,
                    unlock_time,
                    tx.version >= cryptonote::txversion::v2_ringct
                            ? &tx.rct_signatures.outPk[i].mask
                            : NULL);
        }
    }

    if (has_blacklisted_outputs)
        add_output_blacklist(amount_output_indices);

    add_tx_amount_output_indices(tx_id, amount_output_indices);
}

uint64_t BlockchainDB::add_block(
        const std::pair<block, std::string>& blck,
        size_t block_weight,
        uint64_t long_term_block_weight,
        const difficulty_type& cumulative_difficulty,
        const uint64_t& coins_generated,
        const std::vector<std::pair<transaction, std::string>>& txs) {
    const block& blk = blck.first;

    // sanity
    if (blk.tx_hashes.size() != txs.size())
        throw cpptrace::runtime_error("Inconsistent tx/hashes sizes");

    auto started = std::chrono::steady_clock::now();
    crypto::hash blk_hash = get_block_hash(blk);
    time_blk_hash += std::chrono::steady_clock::now() - started;

    uint64_t prev_height = height();

    // call out to add the transactions

    started = std::chrono::steady_clock::now();

    uint64_t num_rct_outs = 0;
    add_transaction(blk_hash, std::make_pair(blk.miner_tx, tx_to_blob(blk.miner_tx)));
    if (blk.miner_tx.version >= cryptonote::txversion::v2_ringct)
        num_rct_outs += blk.miner_tx.vout.size();

    int tx_i = 0;
    crypto::hash tx_hash{};
    for (const std::pair<transaction, std::string>& tx : txs) {
        tx_hash = blk.tx_hashes[tx_i];
        add_transaction(blk_hash, tx, &tx_hash);
        for (const auto& vout : tx.first.vout) {
            if (vout.amount == 0)
                ++num_rct_outs;
        }
        ++tx_i;
    }
    time_add_transaction += std::chrono::steady_clock::now() - started;

    // call out to subclass implementation to add the block & metadata
    started = std::chrono::steady_clock::now();
    add_block(
            blk,
            block_weight,
            long_term_block_weight,
            cumulative_difficulty,
            coins_generated,
            num_rct_outs,
            blk_hash);
    time_add_block1 += std::chrono::steady_clock::now() - started;

    ++num_calls;

    return prev_height;
}

void BlockchainDB::pop_block(block& blk, std::vector<transaction>& txs) {
    blk = get_top_block();

    remove_block();

    for (auto it = blk.tx_hashes.rbegin(); it != blk.tx_hashes.rend(); ++it) {
        auto& h = *it;
        cryptonote::transaction tx;
        if (!get_tx(h, tx) && !get_pruned_tx(h, tx))
            throw DB_ERROR("Failed to get pruned or unpruned transaction from the db");
        txs.push_back(std::move(tx));
        remove_transaction(h);
    }
    remove_transaction(get_transaction_hash(blk.miner_tx));
}

void BlockchainDB::remove_transaction(const crypto::hash& tx_hash) {
    transaction tx = get_pruned_tx(tx_hash);

    for (const txin_v& tx_input : tx.vin) {
        if (std::holds_alternative<txin_to_key>(tx_input)) {
            remove_spent_key(var::get<txin_to_key>(tx_input).k_image);
        }
    }

    // need tx as tx.vout has the tx outputs, and the output amounts are needed
    remove_transaction_data(tx_hash, tx);
}

block_header BlockchainDB::get_block_header(const crypto::hash& h) const {
    block_header b = get_block_header_from_height(get_block_height(h));
    return b;
}

block BlockchainDB::get_block(const crypto::hash& h) const {
    block b = get_block_from_height(get_block_height(h));
    return b;
}

bool BlockchainDB::get_tx(const crypto::hash& h, cryptonote::transaction& tx) const {
    std::string bd;
    if (!get_tx_blob(h, bd))
        return false;
    if (!parse_and_validate_tx_from_blob(bd, tx))
        throw DB_ERROR("Failed to parse transaction from blob retrieved from the db");

    return true;
}

bool BlockchainDB::get_pruned_tx(const crypto::hash& h, cryptonote::transaction& tx) const {
    std::string bd;
    if (!get_pruned_tx_blob(h, bd))
        return false;
    if (!parse_and_validate_tx_base_from_blob(bd, tx)) {
        throw DB_ERROR("Failed to parse transaction base from blob retrieved from the db");
    }

    return true;
}

transaction BlockchainDB::get_tx(const crypto::hash& h) const {
    transaction tx;
    if (!get_tx(h, tx))
        throw TX_DNE("tx with hash {} not found in db"_format(h));
    return tx;
}

uint64_t BlockchainDB::get_output_unlock_time(
        const uint64_t amount, const uint64_t amount_index) const {
    output_data_t odata = get_output_key(amount, amount_index);
    return odata.unlock_time;
}

transaction BlockchainDB::get_pruned_tx(const crypto::hash& h) const {
    transaction tx;
    if (!get_pruned_tx(h, tx))
        throw TX_DNE("pruned tx with hash {} not found in db"_format(h));
    return tx;
}

void BlockchainDB::reset_stats() {
    num_calls = 0;
    time_blk_hash = 0ns;
    time_tx_exists = 0ns;
    time_add_block1 = 0ns;
    time_add_transaction = 0ns;
    time_commit1 = 0ns;
}

void BlockchainDB::show_stats() {
    log::info(
            logcat,
            "\n*********************************\n \
      num_calls: {}\n \
      time_blk_hash: {}\n \
      time_tx_exists: {}\n \
      time_add_block1: {}\n \
      time_add_transaction: {}\n \
      time_commit1: {}\n \
      *********************************\n",
            num_calls,
            tools::friendly_duration(time_blk_hash),
            tools::friendly_duration(time_tx_exists),
            tools::friendly_duration(time_add_block1),
            tools::friendly_duration(time_add_transaction),
            tools::friendly_duration(time_commit1));
}

void BlockchainDB::fixup(cryptonote::network_type) {
    if (is_read_only()) {
        log::info(logcat, "Database is opened read only - skipping fixup check");
        return;
    }

    set_batch_transactions(true);
}

bool BlockchainDB::get_immutable_checkpoint(
        checkpoint_t* immutable_checkpoint, uint64_t block_height) const {
    size_t constexpr NUM_CHECKPOINTS = service_nodes::CHECKPOINT_NUM_CHECKPOINTS_FOR_CHAIN_FINALITY;
    static_assert(
            NUM_CHECKPOINTS == 2,
            "Expect checkpoint finality to be 2, otherwise the immutable logic needs to check for "
            "any hardcoded "
            "checkpoints inbetween");

    std::vector<checkpoint_t> checkpoints = get_checkpoints_range(block_height, 0, NUM_CHECKPOINTS);

    if (checkpoints.empty())
        return false;

    checkpoint_t* checkpoint_ptr = nullptr;
    if (checkpoints[0].type != checkpoint_type::service_node)  // checkpoint[0] is the first closest
                                                               // checkpoint that is <= my height
    {
        checkpoint_ptr = &checkpoints[0];  // Must be hard-coded then, always immutable
    } else if (checkpoints.size() == NUM_CHECKPOINTS) {
        // NOTE: The first checkpoint is a service node checkpoint. Go back
        // 1 checkpoint, which will either be another service node checkpoint or
        // a predefined one.
        checkpoint_ptr = &checkpoints[1];
    } else {
        return false;  // NOTE: Only one service node checkpoint recorded, we can override this
                       // checkpoint.
    }

    if (immutable_checkpoint)
        *immutable_checkpoint = std::move(*checkpoint_ptr);

    return true;
}

uint64_t BlockchainDB::get_tx_block_height(const crypto::hash& h) const {
    auto result = get_tx_block_heights({{h}}).front();
    if (result == std::numeric_limits<uint64_t>::max()) {
        std::string err = "tx_data_t with hash {} not found in db"_format(h);
        log::info(logcat, "{}", err);
        throw TX_DNE(std::move(err));
    }
    return result;
}

bool BlockchainDB::get_alt_block_header(
        const crypto::hash& blkid,
        alt_block_data_t* data,
        cryptonote::block_header* header,
        std::string* checkpoint) const {
    std::string blob;
    if (!get_alt_block(blkid, data, &blob, checkpoint)) {
        throw BLOCK_DNE("Alt-block with hash {} not found in db"_format(blkid));
        return false;
    }

    try {
        serialization::binary_string_unarchiver ba{blob};
        serialization::value(ba, *header);
    } catch (std::exception& e) {
        return false;
    }

    return true;
}

void BlockchainDB::fill_timestamps_and_difficulties_for_pow(
        cryptonote::network_type nettype,
        std::vector<uint64_t>& timestamps,
        std::vector<uint64_t>& difficulties,
        uint64_t chain_height,
        uint64_t timestamps_difficulty_height) const {
    constexpr uint64_t MIN_CHAIN_HEIGHT = 2;
    if (chain_height < MIN_CHAIN_HEIGHT)
        return;

    uint64_t const top_block_height = chain_height - 1;
    bool const before_hf16 = !is_hard_fork_at_least(nettype, hf::hf16_pulse, chain_height);
    uint64_t const block_count = old::DIFFICULTY_BLOCKS_COUNT(before_hf16);

    timestamps.reserve(block_count);
    difficulties.reserve(block_count);

    if (timestamps_difficulty_height == 0 || (chain_height - timestamps_difficulty_height) != 1 ||
        timestamps.size() > block_count || difficulties.size() > block_count) {
        // Cache invalidated.
        timestamps.clear();
        difficulties.clear();

        // Fill missing timestamps/difficulties, up to one before the latest (latest is added
        // below).
        uint64_t start_height = chain_height - std::min<size_t>(chain_height, block_count);
        start_height = std::max<uint64_t>(start_height, 1);

        for (uint64_t block_height = start_height;
             block_height < (chain_height - 1) /*skip latest block*/;
             block_height++) {
            timestamps.push_back(get_block_timestamp(block_height));
            difficulties.push_back(get_block_cumulative_difficulty(block_height));
        }
    }

    // Add latest timestamp/difficulty
    add_timestamp_and_difficulty(
            nettype,
            chain_height,
            timestamps,
            difficulties,
            get_block_timestamp(top_block_height),
            get_block_cumulative_difficulty(top_block_height));
}

}  // namespace cryptonote
