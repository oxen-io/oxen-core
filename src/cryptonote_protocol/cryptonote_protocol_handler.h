/// @file
/// @author rfree (current maintainer/user in monero.cc project - most of code is from CryptoNote)
/// @brief This is the original cryptonote protocol network-events handler, modified by us

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

#include <boost/circular_buffer.hpp>
#include <boost/program_options/variables_map.hpp>
#include <chrono>
#include <deque>
#include <map>
#include <mutex>
#include <oxen/quic/utils.hpp>
#include <string>
#include <unordered_map>

#include "block_queue.h"
#include "common/meta.h"
#include "common/periodic_task.h"
#include "cryptonote_basic/connection_context.h"
#include "cryptonote_protocol_defs.h"
#include "cryptonote_protocol_handler_common.h"
#include "p2p/levin/messages.h"
#include "peer_history.h"

#define CURRENCY_PROTOCOL_MAX_OBJECT_REQUEST_COUNT 500
#define CURRENCY_PROTOCOL_MAX_TXS_REQUEST_COUNT 5000

namespace cryptonote {
class core;

class protocol_handler : public i_cryptonote_protocol {
  public:
    using connection_context = cryptonote_connection_context;

    protocol_handler(core& rcore, bool offline = false);

    virtual ~protocol_handler() = default;

    // Handles a notify from a peer; returns ERROR_HANDLER_NOT_DEFINED for a command that isn't one
    // of ours.
    int notify(int command, std::span<const uint8_t> in, cryptonote_connection_context& context);

    bool on_idle();
    bool init(const boost::program_options::variables_map& vm);
    bool deinit();
    void set_p2p_endpoint(nodetool::i_p2p_endpoint* p2p);
    // bool process_handshake_data(const std::string& data, cryptonote_connection_context& context);
    bool process_payload_sync_data(
            CORE_SYNC_DATA&& hshd, cryptonote_connection_context& context, bool is_inital);
    // Our view of the chain (and of our blinks) as of its last change, which takes no chain locks
    // to get, so it can be read from anywhere.
    struct chain_state {
        // What we send peers in handshakes and timed syncs
        CORE_SYNC_DATA sync_data;
        uint64_t immutable_height = 0;
        std::map<uint64_t, crypto::hash> blink_checksums;
        // For NOTIFY_REQUEST_CHAIN (see Blockchain::get_short_chain_history)
        std::list<crypto::hash> short_history;
    };
    std::shared_ptr<const chain_state> get_chain_state() const;
    CORE_SYNC_DATA get_payload_sync_data() const { return get_chain_state()->sync_data; }
    // Our chain's height, from our chain state
    uint64_t chain_height() const { return get_chain_state()->sync_data.current_height; }
    bool on_callback(cryptonote_connection_context& context);
    core& get_core() { return m_core; }
    bool is_synchronized() { return m_synchronized; }
    void log_connections();
    std::list<connection_info> get_connections();
    const block_queue& get_block_queue() const { return m_block_queue; }
    void stop();
    void on_connection_close(cryptonote_connection_context& context);
    void set_max_out_peers(unsigned int max) { m_max_out_peers = max; }
    bool no_sync() const { return m_no_sync; }
    void set_no_sync(bool value) { m_no_sync = value; }
    std::string get_peers_overview() const;
    bool needs_new_sync_connections() const;
    // What we still need from peers while syncing, or nullopt if we aren't syncing (so any peer
    // will do).  Syncing ends for good when we first reach the network's height: from then on the
    // target is only briefly ahead of us, as each new block arrives.
    std::optional<sync_need> get_sync_need() const;

  private:
    // Puts a peer that has had the blocks the sync needs next, but no longer keeps them, in
    // standby, and returns true if it did: asking it for spans would get nothing, and then we would
    // ask it for its chain over and over.  The standby checker keeps trying it, and it is of use as
    // soon as what the sync needs moves up into what it keeps.  (A peer that just hasn't got the
    // blocks yet is left to go on as usual: to get its chain, then wait for it in the normal
    // state.)
    bool wait_for_history(
            cryptonote_connection_context& context, const std::optional<sync_need>& need);

    static const nodetool::levin::notify_table<protocol_handler, cryptonote_connection_context>
            notify_handlers;

    //----------------- commands handlers ----------------------------------------------
    int handle_notify_new_transactions(
            NOTIFY_NEW_TRANSACTIONS::request& arg, cryptonote_connection_context& context);
    int handle_request_get_blocks(
            NOTIFY_REQUEST_GET_BLOCKS::request& arg, cryptonote_connection_context& context);
    int handle_response_get_blocks(
            NOTIFY_RESPONSE_GET_BLOCKS::request& arg, cryptonote_connection_context& context);
    int handle_request_get_txs(
            NOTIFY_REQUEST_GET_TXS::request& arg, cryptonote_connection_context& context);
    int handle_request_chain(
            NOTIFY_REQUEST_CHAIN::request& arg, cryptonote_connection_context& context);
    int handle_response_chain_entry(
            NOTIFY_RESPONSE_CHAIN_ENTRY::request& arg, cryptonote_connection_context& context);
    int handle_notify_new_fluffy_block(
            NOTIFY_NEW_FLUFFY_BLOCK::request& arg, cryptonote_connection_context& context);
    int handle_request_fluffy_missing_tx(
            NOTIFY_REQUEST_FLUFFY_MISSING_TX::request& arg, cryptonote_connection_context& context);
    int handle_uptime_proof(
            NOTIFY_BTENCODED_UPTIME_PROOF::request& arg, cryptonote_connection_context& context);
    int handle_notify_new_service_node_vote(
            NOTIFY_NEW_SERVICE_NODE_VOTE::request& arg, cryptonote_connection_context& context);
    int handle_request_block_blinks(
            NOTIFY_REQUEST_BLOCK_BLINKS::request& arg, cryptonote_connection_context& context);
    int handle_response_block_blinks(
            NOTIFY_RESPONSE_BLOCK_BLINKS::request& arg, cryptonote_connection_context& context);

    //----------------- i_bc_protocol_layout ---------------------------------------
    template <class T>
    bool relay_to_synchronized_peers(
            typename T::request& arg, const std::optional<connection_id_t>& exclude) {
        log::debug(globallogcat, "post relay {} -->", tools::type_name<T>());
        std::vector<connection_id_t> connections;
        m_p2p->for_each_connection(
                [&exclude, &connections](
                        connection_context& context, nodetool::peerid_type peer_id) {
                    if (context.m_state > cryptonote_connection_context::state_synchronizing &&
                        peer_id && context.m_connection_id != exclude)
                        connections.push_back(context.m_connection_id);
                    return true;
                });

        if (connections.size()) {
            const auto body = nodetool::levin::encode(arg);
            return m_p2p->relay_notify_to_list(
                    T::ID,
                    oxen::quic::reinterpret_span<const uint8_t>(std::span{body}),
                    connections);
        }

        return true;
    }

    bool relay_block(
            NOTIFY_NEW_FLUFFY_BLOCK::request& arg, std::optional<connection_id_t> exclude) override;
    bool relay_transactions(
            NOTIFY_NEW_TRANSACTIONS::request& arg, std::optional<connection_id_t> exclude) override;
    bool relay_uptime_proof(
            NOTIFY_BTENCODED_UPTIME_PROOF::request& arg,
            std::optional<connection_id_t> exclude) override;
    bool relay_service_node_votes(
            NOTIFY_NEW_SERVICE_NODE_VOTE::request& arg,
            std::optional<connection_id_t> exclude) override;
    //----------------------------------------------------------------------------------
    // `caller` says where the request comes from, for logging.
    bool request_missing_objects(
            cryptonote_connection_context& context,
            bool check_having_blocks,
            bool force_next_span,
            std::string_view caller);
    size_t get_synchronizing_connections_count();
    bool on_connection_synchronized();
    bool should_download_next_span(cryptonote_connection_context& context, bool standby);
    void drop_connection(
            cryptonote_connection_context& context, bool add_fail, bool flush_all_spans);
    // The chain job of handle_notify_new_transactions(): verifies and adds the txes (and blinks)
    // from connection `id`, and relays the new ones.
    void add_new_transactions(
            NOTIFY_NEW_TRANSACTIONS::request& arg, const connection_id_t& id, bool syncing);
    // The chain job of handle_notify_new_fluffy_block(): adds the block's txes we haven't got, then
    // the block if we have all its txes, or else asks connection `id` for those we are missing.
    // `tx_hashes` are those of `arg`'s txes.
    void add_fluffy_block(
            NOTIFY_NEW_FLUFFY_BLOCK::request& arg,
            const block& new_block,
            const std::vector<crypto::hash>& tx_hashes,
            const connection_id_t& id);
    // For chain jobs: drops the connection from the thread that has its context.
    void drop_connection(const connection_id_t& id, bool add_fail, bool flush_all_spans);
    // Queues `f` on the chain thread, after the chain work already queued there.  A chain job has
    // no connection context: it addresses a connection by id, with post_notify() or
    // drop_connection().
    void chain_job(std::function<void()> f);
    bool kick_idle_peers();
    bool check_standby_peers();
    bool update_sync_search();

    // Has the peer carry on syncing: gets the chain thread adding spans, if the span the chain
    // needs next is ready, and requests what more the peer can give us.  `after_adding` is for
    // when it was the peer's blocks that got spans added: it may then download the next span even
    // if it would otherwise wait.
    void continue_sync(cryptonote_connection_context& context, bool after_adding);
    // Queues add_spans() on the chain thread, unless it is already queued (or running), if the
    // span the chain needs next is ready.
    void start_adding_spans(const connection_id_t& peer);
    // The chain job adding spans from the block queue: adds one, then queues itself again while
    // it added one, so that other chain work runs between spans.  `peer`, whose blocks got it
    // going, carries on syncing after each.
    void add_spans(const connection_id_t& peer);
    enum class span_result {
        added,
        none,             // nothing in the queue
        waiting,          // for the span's parent, which has been requested
        unknown_parent,   // that wasn't requested, and the peer doesn't have
        rerequest_chain,  // the span's parent is unknown: ask the peer for its chain again
        failed,           // and the span's peer dropped, if it was at fault
    };
    span_result add_next_span();
    void log_sync_progress(uint64_t previous_height, std::chrono::steady_clock::time_point start);

    void skip_unneeded_hashes(cryptonote_connection_context& context, bool check_block_queue) const;

    core& m_core;

    nodetool::p2p_endpoint_stub m_p2p_stub;
    nodetool::i_p2p_endpoint* m_p2p;
    std::atomic<uint32_t> m_syncronized_connections_count;
    std::atomic<bool> m_synchronized;
    std::atomic<bool> m_stopping;
    std::atomic<bool> m_no_sync;
    // Whether add_spans() is queued or running on the chain thread
    std::atomic<bool> m_adding_spans{false};
    block_queue m_block_queue;
    tools::periodic_task m_idle_peer_kicker{"idle peer cleanup", 30s};
    tools::periodic_task m_standby_checker{"standby checker", 100ms};
    tools::periodic_task m_sync_search_checker{"sync search check", 101s};
    std::atomic<unsigned int> m_max_out_peers;
    std::chrono::steady_clock::time_point m_last_add_end_time;
    uint64_t m_sync_spans_downloaded, m_sync_old_spans_downloaded, m_sync_bad_spans_downloaded;
    uint64_t m_sync_download_chain_size, m_sync_download_objects_size;
    size_t m_block_download_max_size;

    // When and at what height the current sync started (see process_payload_sync_data for what
    // counts as a start): the sync time estimates, the sync rate and the "Synced N blocks" summary
    // are all measured from here.
    std::chrono::steady_clock::time_point m_sync_start_time;
    uint64_t m_sync_start_height = 0;
    std::chrono::steady_clock::time_point m_period_start_time;
    uint64_t get_estimated_remaining_sync_seconds(
            uint64_t current_blockchain_height, uint64_t target_blockchain_height);
    std::string get_periodic_sync_estimate(
            uint64_t current_blockchain_height, uint64_t target_blockchain_height);

    // Blocks per second synced since the sync started.
    double average_sync_rate(uint64_t current_blockchain_height) const;
    // Records the current height and returns the blocks per second synced over (roughly) the last
    // minute, falling back to average_sync_rate until there is enough history for that.
    double sync_rate(uint64_t current_blockchain_height);
    // (time, height) samples for sync_rate; reset whenever a sync (re)starts.
    std::deque<std::pair<std::chrono::steady_clock::time_point, uint64_t>> m_sync_rate_samples;
    std::mutex m_sync_rate_mutex;

    // Recomputes our chain state from the chain and mempool, whose locks it takes.  Called only
    // from the chain's and mempool's hooks, as they change.
    void refresh_chain_state();
    // Set while we add a span of blocks, so that the hooks leave the refresh to the end of the span
    // rather than doing it for every block.  Nothing else can change the chain meanwhile, as adding
    // a span holds the chain lock throughout.
    std::atomic<bool> m_defer_chain_refresh{false};
    mutable std::mutex m_chain_state_mutex;
    std::shared_ptr<const chain_state> m_chain_state = std::make_shared<chain_state>();

    std::mutex m_buffer_mutex;
    boost::circular_buffer<size_t> m_avg_buffer = boost::circular_buffer<size_t>(10);

    template <class t_parameter>
    bool post_notify(typename t_parameter::request& arg, cryptonote_connection_context& context) {
        log::debug(
                globallogcat,
                "[{}] post {} -->",
                epee::net_utils::print_connection_context_short(context),
                tools::type_name<t_parameter>());
        return post_notify<t_parameter>(arg, context.m_connection_id);
    }
    // For chain jobs, which have only the connection's id
    template <class t_parameter>
    bool post_notify(typename t_parameter::request& arg, const connection_id_t& id) {
        const auto body = nodetool::levin::encode(arg);
        return m_p2p->invoke_notify_to_peer(
                t_parameter::ID, oxen::quic::reinterpret_span<const uint8_t>(std::span{body}), id);
    }
};

}  // namespace cryptonote
