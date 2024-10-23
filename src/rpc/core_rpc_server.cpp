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

#include "core_rpc_server.h"

#include <fmt/color.h>
#include <fmt/core.h>
#include <oxenc/base64.h>

#include <algorithm>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <cstring>
#include <iterator>
#include <type_traits>
#include <variant>

#include "blockchain_db/sqlite/db_sqlite.h"
#include "common/command_line.h"
#include "common/guts.h"
#include "common/json_binary_proxy.h"
#include "common/oxen.h"
#include "common/random.h"
#include "common/sha256sum.h"
#include "common/string_util.h"
#include "core_rpc_server_binary_commands.h"
#include "core_rpc_server_command_parser.h"
#include "core_rpc_server_error_codes.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_basic/tx_extra.h"
#include "cryptonote_config.h"
#include "cryptonote_core/oxen_name_system.h"
#include "cryptonote_core/pulse.h"
#include "cryptonote_core/service_node_rules.h"
#include "cryptonote_core/tx_sanity_check.h"
#include "cryptonote_core/uptime_proof.h"
#include "epee/net/network_throttle.hpp"
#include "epee/string_tools.h"
#include "l2_tracker/events.h"
#include "logging/oxen_logger.h"
#include "net/parse.h"
#include "oxen/log.hpp"
#include "oxen_economy.h"
#include "p2p/net_node.h"
#include "rpc/common/json_bt.h"
#include "rpc/common/rpc_args.h"
#include "rpc/common/rpc_command.h"
#include "serialization/json_archive.h"
#include "version.h"

namespace cryptonote::rpc {

using nlohmann::json;
using tools::json_binary_proxy;

static auto logcat = log::Cat("daemon.rpc");

namespace {

    template <typename RPC>
    void register_rpc_command(
            std::unordered_map<std::string, std::shared_ptr<const rpc_command>>& regs) {
        static_assert(std::is_base_of_v<RPC_COMMAND, RPC> && !std::is_base_of_v<BINARY, RPC>);
        auto cmd = std::make_shared<rpc_command>();
        cmd->is_public = std::is_base_of_v<PUBLIC, RPC>;
        cmd->is_legacy = std::is_base_of_v<LEGACY, RPC>;

        // Temporary: remove once RPC conversion is complete
        static_assert(!FIXME_has_nested_response_v<RPC>);

        cmd->invoke = make_invoke<RPC, core_rpc_server, rpc_command>();

        for (const auto& name : RPC::names())
            regs.emplace(name, cmd);
    }

    template <typename RPC>
    void register_binary_rpc_command(
            std::unordered_map<std::string, std::shared_ptr<const rpc_command>>& regs) {
        static_assert(std::is_base_of_v<BINARY, RPC> && !std::is_base_of_v<LEGACY, RPC>);
        auto cmd = std::make_shared<rpc_command>();
        cmd->is_public = std::is_base_of_v<PUBLIC, RPC>;
        cmd->is_binary = true;

        // Legacy binary request; these still use epee serialization, and should be considered
        // deprecated (tentatively to be removed in Oxen 11).
        cmd->invoke = [](rpc_request&& request,
                         core_rpc_server& server) -> rpc_command::result_type {
            typename RPC::request req{};
            std::string_view data;
            if (auto body = request.body_view())
                data = *body;
            else
                throw oxen::traced<std::runtime_error>{
                        "Internal error: can't load binary a RPC command with non-string body"};
            if (!epee::serialization::load_t_from_binary(req, data))
                throw parse_error{"Failed to parse binary data parameters"};

            auto res = server.invoke(std::move(req), std::move(request.context));

            std::string response;
            epee::serialization::store_t_to_binary(res, response);
            return response;
        };

        for (const auto& name : RPC::names())
            regs.emplace(name, cmd);
    }

    template <typename... RPC, typename... BinaryRPC>
    std::unordered_map<std::string, std::shared_ptr<const rpc_command>> register_rpc_commands(
            tools::type_list<RPC...>, tools::type_list<BinaryRPC...>) {
        std::unordered_map<std::string, std::shared_ptr<const rpc_command>> regs;

        (register_rpc_command<RPC>(regs), ...);
        (register_binary_rpc_command<BinaryRPC>(regs), ...);

        return regs;
    }

    constexpr uint64_t OUTPUT_HISTOGRAM_RECENT_CUTOFF_RESTRICTION =
            3 * 86400;  // 3 days max, the wallet requests 1.8 days
    constexpr uint64_t round_up(uint64_t value, uint64_t quantum) {
        return (value + quantum - 1) / quantum * quantum;
    }

    void rename_key(nlohmann::json& obj, std::string_view old_key, std::string_view new_key) {
        if (auto it = obj.find(old_key); it != obj.end()) {
            auto val = std::move(*it);
            obj.erase(it);
            obj[std::string{new_key}] = std::move(val);
        }
    }
}  // namespace

const std::unordered_map<std::string, std::shared_ptr<const rpc_command>> rpc_commands =
        register_rpc_commands(rpc::core_rpc_types{}, rpc::core_rpc_binary_types{});

//-----------------------------------------------------------------------------------
void core_rpc_server::init_options(
        boost::program_options::options_description& desc,
        boost::program_options::options_description& hidden) {
    cryptonote::rpc_args::init_options(desc, hidden);
}
//------------------------------------------------------------------------------------------------------------------------------
core_rpc_server::core_rpc_server(
        core& cr,
        nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>>& p2p) :
        m_core(cr), m_p2p(p2p) {}
//------------------------------------------------------------------------------------------------------------------------------
bool core_rpc_server::check_core_ready() {
    return m_p2p.get_payload_object().is_synchronized();
}

#define CHECK_CORE_READY()            \
    do {                              \
        if (!check_core_ready()) {    \
            res.status = STATUS_BUSY; \
            return res;               \
        }                             \
    } while (0)

//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_HEIGHT& get_height, rpc_context) {
    auto [height, hash] = m_core.blockchain.get_tail_id();

    ++height;  // block height to chain height
    get_height.response["status"] = STATUS_OK;
    get_height.response["height"] = height;
    get_height.response_hex["hash"] = hash;

    cryptonote::checkpoint_t checkpoint;
    if (m_core.blockchain.db().get_immutable_checkpoint(&checkpoint, height - 1)) {
        get_height.response["immutable_height"] = checkpoint.height;
        get_height.response_hex["immutable_hash"] = checkpoint.block_hash;
    }
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_INFO& info, rpc_context context) {

    auto& bs = m_core.blockchain;
    auto& db = bs.db();
    const cryptonote::block top_block = db.get_top_block();
    auto top_height = top_block.get_height();
    auto height = top_height + 1;  // turn top block height into blockchain height

    info.response["height"] = height;
    info.response["l2_height"] = top_block.l2_height;
    info.response_hex["top_block_hash"] = get_block_hash(top_block);
    info.response["target_height"] = m_core.get_target_blockchain_height();

    info.response["hard_fork"] = m_core.blockchain.get_network_version();

    bool next_block_is_pulse = false;
    if (pulse::timings t; pulse::get_round_timings(bs, height, top_block.timestamp, t)) {
        info.response["pulse_ideal_timestamp"] =
                tools::to_seconds(t.ideal_timestamp.time_since_epoch());
        info.response["pulse_target_timestamp"] =
                tools::to_seconds(t.r0_timestamp.time_since_epoch());
        next_block_is_pulse = pulse::clock::now() < t.miner_fallback_timestamp;
    }

    if (cryptonote::checkpoint_t checkpoint; db.get_immutable_checkpoint(&checkpoint, top_height)) {
        info.response["immutable_height"] = checkpoint.height;
        info.response_hex["immutable_block_hash"] = checkpoint.block_hash;
    }

    if (next_block_is_pulse)
        info.response["pulse"] = true;
    else
        info.response["difficulty"] = bs.get_difficulty_for_next_block(next_block_is_pulse);

    info.response["target"] = tools::to_seconds(m_core.get_net_config().TARGET_BLOCK_TIME);
    // This count seems broken: blocks with no outputs (after batching) shouldn't be subtracted, and
    // 0-output txes (SN state changes) arguably shouldn't be, either.
    info.response["tx_count"] =
            m_core.blockchain.get_total_transactions() - height;  // without coinbase
    info.response["tx_pool_size"] = m_core.mempool.get_transactions_count();
    if (context.admin) {
        info.response["alt_blocks_count"] = bs.get_alternative_blocks_count();
        auto total_conn = m_p2p.get_public_connections_count();
        auto outgoing_conns = m_p2p.get_public_outgoing_connections_count();
        info.response["outgoing_connections_count"] = outgoing_conns;
        info.response["incoming_connections_count"] = total_conn - outgoing_conns;
        info.response["white_peerlist_size"] = m_p2p.get_public_white_peers_count();
        info.response["grey_peerlist_size"] = m_p2p.get_public_gray_peers_count();
    }

    cryptonote::network_type nettype = m_core.get_nettype();
    info.response["mainnet"] = nettype == network_type::MAINNET;
    info.response["nettype"] = network_type_to_string(nettype);

    try {
        auto cd = db.get_block_cumulative_difficulty(top_height);
        info.response["cumulative_difficulty"] = cd;
    } catch (std::exception const& e) {
        info.response["status"] =
                "Error retrieving cumulative difficulty at height {}"_format(top_height);
        return;
    }

    info.response["block_size_limit"] = bs.get_current_cumulative_block_weight_limit();
    info.response["block_size_median"] = bs.get_current_cumulative_block_weight_median();

    auto ons_counts = bs.name_system_db().get_mapping_counts(height);
    info.response["ons_counts"] = std::array{
            ons_counts[ons::mapping_type::session],
            ons_counts[ons::mapping_type::wallet],
            ons_counts[ons::mapping_type::lokinet]};

    if (context.admin) {
        bool sn = m_core.service_node();
        info.response["service_node"] = sn;
        info.response["start_time"] = m_core.get_start_time();
        if (sn) {
            info.response["last_storage_server_ping"] = m_core.m_last_storage_server_ping.load();
            info.response["last_lokinet_ping"] = m_core.m_last_lokinet_ping.load();
        }
        info.response["free_space"] = m_core.get_free_space();
    }

    if (m_core.offline())
        info.response["offline"] = true;
    auto db_size = db.get_database_size();
    info.response["database_size"] = context.admin ? db_size : round_up(db_size, 1'000'000'000);
    info.response["version"] = context.admin ? OXEN_VERSION_FULL : std::to_string(OXEN_VERSION[0]);
    info.response["status_line"] = context.admin ? m_core.get_status_string()
                                                 : "v" + std::to_string(OXEN_VERSION[0]) +
                                                           "; Height: " + std::to_string(height);

    uint64_t staking_requirement = m_core.service_node_list.get_staking_requirement();
    info.response["staking_requirement"] = staking_requirement;
    info.response["max_contributors"] = oxen::MAX_CONTRIBUTORS_HF19;
    info.response["min_operator_contribution"] =
            oxen::MINIMUM_OPERATOR_CONTRIBUTION(staking_requirement);
    info.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_NET_STATS& get_net_stats, rpc_context) {
    get_net_stats.response["start_time"] = m_core.get_start_time();
    {
        std::lock_guard lock{
                epee::net_utils::network_throttle_manager::m_lock_get_global_throttle_in};
        auto [packets, bytes] =
                epee::net_utils::network_throttle_manager::get_global_throttle_in().get_stats();
        get_net_stats.response["total_packets_in"] = packets;
        get_net_stats.response["total_bytes_in"] = bytes;
    }
    {
        std::lock_guard lock{
                epee::net_utils::network_throttle_manager::m_lock_get_global_throttle_out};
        auto [packets, bytes] =
                epee::net_utils::network_throttle_manager::get_global_throttle_out().get_stats();
        get_net_stats.response["total_packets_out"] = packets;
        get_net_stats.response["total_bytes_out"] = bytes;
    }
    get_net_stats.response["status"] = STATUS_OK;
}
namespace {
    //------------------------------------------------------------------------------------------------------------------------------
    class pruned_transaction {
        transaction& tx;

      public:
        pruned_transaction(transaction& tx) : tx(tx) {}
        template <class Archive>
        void serialize_value(Archive& ar) {
            tx.serialize_base(ar);
        }
    };
}  // namespace
//------------------------------------------------------------------------------------------------------------------------------
GET_BLOCKS_BIN::response core_rpc_server::invoke(GET_BLOCKS_BIN::request&& req, rpc_context) {
    GET_BLOCKS_BIN::response res{};

    std::vector<Blockchain::BlockData> bs;

    if (!m_core.blockchain.find_blockchain_supplement(
                req.start_height,
                req.block_ids,
                bs,
                res.current_height,
                res.start_height,
                req.prune,
                !req.no_miner_tx,
                GET_BLOCKS_BIN::MAX_COUNT)) {
        res.status = "Failed";
        return res;
    }

    size_t size = 0, ntxes = 0;
    res.blocks.reserve(bs.size());
    res.output_indices.reserve(bs.size());
    for (auto& bd : bs) {
        auto& res_b = res.blocks.emplace_back();
        res_b.block = std::move(bd.block_blob);
        size += res_b.block.size();
        auto& out_ind = res.output_indices.emplace_back().indices;
        ntxes += bd.txs.size();
        out_ind.reserve(1 + bd.txs.size());
        if (req.no_miner_tx || !bd.miner_tx_hash)
            out_ind.emplace_back();
        res_b.txs.reserve(bd.txs.size());
        for (auto& [txhash, txdata] : bd.txs)
            size += res_b.txs.emplace_back(std::move(txdata)).size();

        const bool miner_tx = bd.miner_tx_hash && !req.no_miner_tx;
        const size_t n_txes_to_lookup = bd.txs.size() + miner_tx;
        if (n_txes_to_lookup > 0) {
            std::vector<std::vector<uint64_t>> indices;
            bool r = m_core.blockchain.get_tx_outputs_gindexs(
                    miner_tx ? bd.miner_tx_hash : bd.txs.front().first, n_txes_to_lookup, indices);
            if (!r || indices.size() != n_txes_to_lookup) {
                res.status = "Failed";
                return res;
            }
            for (size_t i = 0; i < indices.size(); ++i)
                out_ind.emplace_back(std::move(indices[i]));
        }
    }

    log::debug(logcat, "on_get_blocks: {} blocks, {} txes, size {}", bs.size(), ntxes, size);
    res.status = STATUS_OK;
    return res;
}
GET_ALT_BLOCKS_HASHES_BIN::response core_rpc_server::invoke(
        GET_ALT_BLOCKS_HASHES_BIN::request&&, rpc_context) {
    GET_ALT_BLOCKS_HASHES_BIN::response res{};

    std::vector<block> blks;

    if (!m_core.blockchain.get_alternative_blocks(blks)) {
        res.status = "Failed";
        return res;
    }

    res.blks_hashes.reserve(blks.size());

    for (auto const& blk : blks) {
        res.blks_hashes.push_back(tools::hex_guts(get_block_hash(blk)));
    }

    log::debug(logcat, "on_get_alt_blocks_hashes: {} blocks ", blks.size());
    res.status = STATUS_OK;
    return res;
}
//------------------------------------------------------------------------------------------------------------------------------
GET_BLOCKS_BY_HEIGHT_BIN::response core_rpc_server::invoke(
        GET_BLOCKS_BY_HEIGHT_BIN::request&& req, rpc_context) {
    GET_BLOCKS_BY_HEIGHT_BIN::response res{};

    res.status = "Failed";
    res.blocks.clear();
    res.blocks.reserve(req.heights.size());
    for (uint64_t height : req.heights) {
        block blk;
        try {
            blk = m_core.blockchain.db().get_block_from_height(height);
        } catch (...) {
            res.status = "Error retrieving block at height " + std::to_string(height);
            return res;
        }
        std::vector<transaction> txs;
        m_core.blockchain.get_transactions(blk.tx_hashes, txs);
        res.blocks.resize(res.blocks.size() + 1);
        res.blocks.back().block = block_to_blob(blk);
        for (auto& tx : txs)
            res.blocks.back().txs.push_back(tx_to_blob(tx));
    }
    res.status = STATUS_OK;
    return res;
}
//------------------------------------------------------------------------------------------------------------------------------
GET_HASHES_BIN::response core_rpc_server::invoke(GET_HASHES_BIN::request&& req, rpc_context) {
    GET_HASHES_BIN::response res{};

    res.start_height = req.start_height;
    if (!m_core.blockchain.find_blockchain_supplement(
                req.block_ids, res.m_block_ids, res.start_height, res.current_height, false)) {
        res.status = "Failed";
        return res;
    }

    res.status = STATUS_OK;
    return res;
}
//------------------------------------------------------------------------------------------------------------------------------
GET_OUTPUTS_BIN::response core_rpc_server::invoke(
        GET_OUTPUTS_BIN::request&& req, rpc_context context) {
    GET_OUTPUTS_BIN::response res{};

    if (!context.admin && req.outputs.size() > GET_OUTPUTS_BIN::MAX_COUNT)
        res.status = "Too many outs requested";
    else if (m_core.blockchain.get_outs(req, res))
        res.status = STATUS_OK;
    else
        res.status = "Failed";

    return res;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_OUTPUTS& get_outputs, rpc_context context) {
    if (!context.admin && get_outputs.request.output_indices.size() > GET_OUTPUTS::MAX_COUNT) {
        get_outputs.response["status"] = "Too many outs requested";
        return;
    }

    // This is nasty.  WTF are core methods taking *local rpc* types?
    // FIXME: make core methods take something sensible, like a std::vector<uint64_t>.  (We really
    // don't need the pair since amount is also 0 for Oxen since the beginning of the chain; only in
    // ancient Monero blocks was it non-zero).
    GET_OUTPUTS_BIN::request req_bin{};
    req_bin.get_txid = get_outputs.request.get_txid;
    req_bin.outputs.reserve(get_outputs.request.output_indices.size());
    for (auto oi : get_outputs.request.output_indices)
        req_bin.outputs.push_back({0, oi});

    GET_OUTPUTS_BIN::response res_bin{};
    if (!m_core.blockchain.get_outs(req_bin, res_bin)) {
        get_outputs.response["status"] = STATUS_FAILED;
        return;
    }

    auto binary_format =
            get_outputs.is_bt() ? json_binary_proxy::fmt::bt : json_binary_proxy::fmt::hex;

    auto& outs = (get_outputs.response["outs"] = json::array());
    if (!get_outputs.request.as_tuple) {
        for (auto& outkey : res_bin.outs) {
            json o;
            json_binary_proxy b{o, binary_format};
            b["key"] = std::move(outkey.key);
            b["mask"] = std::move(outkey.mask);
            o["unlocked"] = outkey.unlocked;
            o["height"] = outkey.height;
            if (get_outputs.request.get_txid)
                b["txid"] = std::move(outkey.txid);
            outs.push_back(std::move(o));
        }
    } else {
        for (auto& outkey : res_bin.outs) {
            auto o = json::array();
            json_binary_proxy b{o, binary_format};
            b.push_back(std::move(outkey.key));
            b.push_back(std::move(outkey.mask));
            o.push_back(outkey.unlocked);
            o.push_back(outkey.height);
            if (get_outputs.request.get_txid)
                b.push_back(std::move(outkey.txid));
            outs.push_back(o);
        }
    }

    get_outputs.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN::response core_rpc_server::invoke(
        GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN::request&& req, rpc_context) {
    GET_TX_GLOBAL_OUTPUTS_INDEXES_BIN::response res{};

    bool r = m_core.blockchain.get_tx_outputs_gindexs(req.txid, res.o_indexes);
    if (!r) {
        res.status = "Failed";
        return res;
    }
    res.status = STATUS_OK;
    log::debug(logcat, "GET_TX_GLOBAL_OUTPUTS_INDEXES: [{}]", res.o_indexes.size());
    return res;
}

namespace {
    constexpr uint64_t half_microportion =
            9223372036855ULL;  // half of 1/1'000'000 of a full portion
    constexpr uint32_t microportion(uint64_t portion) {
        // Rounding integer division to convert our [0, ..., 2^64-4] portion value into [0, ...,
        // 1000000]:
        return portion < half_microportion
                     ? 0
                     : (portion - half_microportion) / (2 * half_microportion) + 1;
    }
    template <typename T>
    std::vector<std::string> hexify(const std::vector<T>& v) {
        std::vector<std::string> hexes;
        hexes.reserve(v.size());
        for (auto& x : v)
            hexes.push_back(tools::hex_guts(x));
        return hexes;
    }

    struct extra_extractor {
        nlohmann::json& entry;
        const network_type nettype;
        json_binary_proxy::fmt format;

        // If we encounter duplicate values then we want to produce an array of values, but with
        // just a single one we want just the value itself; this does that.  Returns a reference to
        // the assigned value (whether as a top-level value or array element).
        template <typename T>
        json& set(
                const std::string& key,
                T&& value,
                [[maybe_unused]] bool binary = tools::json_is_binary<T> ||
                                               tools::json_is_binary_container<T>) {
            auto* x = &entry[key];
            if (!x->is_null() && !x->is_array())
                x = &(entry[key] = json::array({std::move(*x)}));
            if (x->is_array())
                x = &x->emplace_back();
            if constexpr (
                    tools::json_is_binary<T> || tools::json_is_binary_container<T> ||
                    std::is_convertible_v<T, std::string_view>) {
                if (binary)
                    return json_binary_proxy{*x, format} = std::forward<T>(value);
            }
            assert(!binary);
            return *x = std::forward<T>(value);
        }

        void operator()(const tx_extra_pub_key& x) {
            set("type", "pub_key");
            set("pubkey", x.pub_key);
        }
        void operator()(const tx_extra_nonce& x) {
            set("type", "nonce");
            if ((x.nonce.size() == sizeof(crypto::hash) + 1 &&
                 x.nonce[0] == TX_EXTRA_NONCE_PAYMENT_ID) ||
                (x.nonce.size() == sizeof(crypto::hash8) + 1 &&
                 x.nonce[0] == TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID))
                set("payment_id", std::string_view{x.nonce.data() + 1, x.nonce.size() - 1}, true);
            else
                set("extra_nonce", x.nonce, true);
        }
        void operator()(const tx_extra_merge_mining_tag& x) {
            set("type", "merge_mining_tag");
            set("mm_depth", x.depth);
            set("mm_root", x.merkle_root);
        }
        void operator()(const tx_extra_additional_pub_keys& x) {
            set("type", "additional_pub_keys");
            set("additional_pubkeys", x.data);
        }
        void operator()(const tx_extra_burn& x) { set("burn_amount", x.amount); }
        void operator()(const tx_extra_service_node_winner& x) {
            set("type", "service_node_winner");
            set("sn_winner", x.m_service_node_key);
        }
        void operator()(const tx_extra_service_node_pubkey& x) {
            set("type", "service_node_pubkey");
            set("sn_pubkey", x.m_service_node_key);
        }
        void operator()(const tx_extra_service_node_register& x) {
            // MERGEFIX: confirm this is correct
            set("type", "service_node_register");
            json new_reg{};
            if (x.hf_or_expiration <= 255) {  // hard fork value
                new_reg["hardfork"] = static_cast<hf>(x.hf_or_expiration);
                new_reg["fee"] = x.fee * 1'000'000 / STAKING_FEE_BASIS;
            } else {  // timestamp
                new_reg["hardfork"] = hf::none;
                new_reg["expiry"] = x.hf_or_expiration;
                new_reg["fee"] = microportion(x.fee);
            }
            hf reg_hf = new_reg["hardfork"];

            new_reg["contributors"] = json::array();
            for (size_t i = 0; i < x.amounts.size(); i++) {
                auto wallet = get_account_address_as_str(
                        nettype, false, {x.public_spend_keys[i], x.public_view_keys[i]});
                uint64_t amount;
                uint32_t portion;
                if (reg_hf >= hf::hf19_reward_batching) {
                    amount = x.amounts[i];
                    // We aren't given info on whether this is testnet/mainnet, but we can guess by
                    // looking at the operator amount, which has to be <= 100 on testnet, but >=
                    // 3750 on mainnet.
                    auto nettype = x.amounts[0] > oxen::SENT_STAKING_REQUIREMENT_TESTNET
                                         ? network_type::MAINNET
                                         : network_type::TESTNET;
                    portion = std::lround(
                            amount /
                            (double)service_nodes::get_default_staking_requirement(
                                    nettype, reg_hf) *
                            1'000'000.0);
                } else {
                    amount = 0;
                    portion = microportion(x.amounts[i]);
                }
                new_reg["contributors"].push_back(json{
                        {"wallet", std::move(wallet)}, {"amount", amount}, {"portion", portion}});
            }
            set("sn_registration", std::move(new_reg));
        }
        void operator()(const tx_extra_service_node_contributor& x) {
            set("type", "service_node_contributor");
            set("sn_contributor",
                get_account_address_as_str(
                        nettype, false, {x.m_spend_public_key, x.m_view_public_key}));
        }
        template <typename T>
        auto& _state_change(const T& x) {
            // Common loading code for nearly-identical state_change and deregister_old variables:
            auto voters = json::array();
            for (auto& v : x.votes)
                voters.push_back(v.validator_index);

            json sc{{"height", x.block_height},
                    {"index", x.service_node_index},
                    {"voters", std::move(voters)}};
            return set("sn_state_change", std::move(sc));
        }
        void operator()(const tx_extra_service_node_deregister_old& x) {
            set("type", "service_node_deregister_old");
            auto& sc = _state_change(x);
            sc["old_dereg"] = true;
            sc["type"] = "dereg";
        }
        void operator()(const tx_extra_service_node_state_change& x) {
            set("type", "service_node_state_change");
            auto& sc = _state_change(x);
            if (x.reason_consensus_all)
                sc["reasons"] = cryptonote::coded_reasons(x.reason_consensus_all);
            // If `any` has reasons not included in all then list the extra ones separately:
            if (uint16_t reasons_maybe = x.reason_consensus_any & ~x.reason_consensus_all)
                sc["reasons_maybe"] = cryptonote::coded_reasons(reasons_maybe);
            switch (x.state) {
                case service_nodes::new_state::decommission: sc["type"] = "decom"; break;
                case service_nodes::new_state::recommission: sc["type"] = "recom"; break;
                case service_nodes::new_state::deregister: sc["type"] = "dereg"; break;
                case service_nodes::new_state::ip_change_penalty: sc["type"] = "ip"; break;
                case service_nodes::new_state::_count: /*leave blank*/ break;
            }
        }
        void operator()(const tx_extra_tx_secret_key& x) {
            set("type", "tx_secret_key");
            set("tx_secret_key", tools::view_guts(x.key), true);
        }
        void operator()(const tx_extra_tx_key_image_proofs& x) {
            set("type", "tx_key_image_proofs");
            std::vector<crypto::key_image> kis;
            kis.reserve(x.proofs.size());
            for (auto& proof : x.proofs)
                kis.push_back(proof.key_image);
            set("locked_key_images", std::move(kis));
        }
        void operator()(const tx_extra_tx_key_image_unlock& x) {
            set("type", "key_image_unlock");
            set("key_image_unlock", x.key_image);
        }
        void _load_owner(json& parent, const std::string& key, const ons::generic_owner& owner) {
            if (!owner)
                return;
            if (owner.type == ons::generic_owner_sig_type::monero)
                parent[key] = get_account_address_as_str(
                        nettype, owner.wallet.is_subaddress, owner.wallet.address);
            else if (owner.type == ons::generic_owner_sig_type::ed25519)
                json_binary_proxy{parent[key], format} = owner.ed25519;
        }
        void operator()(const tx_extra_oxen_name_system& x) {
            set("type", "oxen_name_system");
            json ons{};
            if (auto maybe_exp = ons::expiry_blocks(nettype, x.type))
                ons["blocks"] = *maybe_exp;
            switch (x.type) {
                case ons::mapping_type::lokinet: [[fallthrough]];
                case ons::mapping_type::lokinet_2years: [[fallthrough]];
                case ons::mapping_type::lokinet_5years: [[fallthrough]];
                case ons::mapping_type::lokinet_10years: ons["type"] = "lokinet"; break;

                case ons::mapping_type::session: ons["type"] = "session"; break;
                case ons::mapping_type::wallet: ons["type"] = "wallet"; break;

                case ons::mapping_type::update_record_internal: [[fallthrough]];
                case ons::mapping_type::_count: break;
            }
            if (x.is_buying())
                ons["buy"] = true;
            else if (x.is_updating())
                ons["update"] = true;
            else if (x.is_renewing())
                ons["renew"] = true;
            auto ons_bin = json_binary_proxy{ons, format};
            ons_bin["name_hash"] = x.name_hash;
            if (!x.encrypted_value.empty())
                ons_bin["value"] = x.encrypted_value;
            _load_owner(ons, "owner", x.owner);
            _load_owner(ons, "backup_owner", x.backup_owner);
        }
        void operator()(const eth::event::NewServiceNodeV2& x) {
            set("type", "ethereum_new_service_node_v2");
            set("l2_height", x.l2_height);
            set("bls_pubkey", x.bls_pubkey);
            set("service_node_pubkey", x.sn_pubkey);
            set("signature", x.ed_signature);
            set("fee", x.fee);
            auto contributors = json::array();
            for (auto& contributor : x.contributors) {
                auto& c = contributors.emplace_back();
                c["address"] = "{}"_format(contributor.address);
                c["beneficiary"] = "{}"_format(contributor.beneficiary);
                c["amount"] = contributor.amount;
            }
            set("contributors", contributors);
        }
        void operator()(const eth::event::ServiceNodeExitRequest& x) {
            set("type", "ethereum_service_node_exit_request");
            set("l2_height", x.l2_height);
            set("bls_pubkey", x.bls_pubkey);
        }
        void operator()(const eth::event::ServiceNodeExit& x) {
            set("type", "ethereum_service_node_exit");
            set("l2_height", x.l2_height);
            set("bls_pubkey", x.bls_pubkey);
            set("returned_amount", x.returned_amount);
        }
        void operator()(const eth::event::StakingRequirementUpdated& x) {
            set("type", "ethereum_staking_requirement_update");
            set("l2_height", x.l2_height);
            set("staking_requirement", x.staking_requirement);
        }
        void operator()(const eth::event::ServiceNodePurge& x) {
            set("type", "ethereum_service_node_purge");
            set("l2_height", x.l2_height);
            set("bls_pubkey", x.bls_pubkey);
        }

        // Ignore these fields:
        void operator()(const tx_extra_padding&) {}
        void operator()(const tx_extra_mysterious_minergate&) {}
    };

    void load_tx_extra_data(
            nlohmann::json& e, const transaction& tx, network_type nettype, bool is_bt) {
        e = json::object();
        std::vector<tx_extra_field> extras;
        if (!parse_tx_extra(tx.extra, extras))
            return;
        extra_extractor visitor{
                e, nettype, is_bt ? json_binary_proxy::fmt::bt : json_binary_proxy::fmt::hex};
        for (const auto& extra : extras)
            var::visit(visitor, extra);
    }
}  // namespace

struct tx_info {
    txpool_tx_meta_t meta;
    std::string tx_blob;  // Blob containing the transaction data.
    bool blink;           // True if this is a signed blink transaction
};

static std::unordered_map<crypto::hash, tx_info> get_pool_txs_impl(cryptonote::core& core) {
    auto& db = core.blockchain.db();
    auto& pool = core.mempool;

    std::unordered_map<crypto::hash, tx_info> tx_infos;
    tx_infos.reserve(db.get_txpool_tx_count());

    db.for_all_txpool_txes(
            [&tx_infos, &pool](
                    const crypto::hash& txid, const txpool_tx_meta_t& meta, const std::string* bd) {
                transaction tx;
                if (!parse_and_validate_tx_from_blob(*bd, tx)) {
                    log::error(logcat, "Failed to parse tx from txpool");
                    // continue
                    return true;
                }
                auto& txi = tx_infos[txid];
                txi.meta = meta;
                txi.tx_blob = *bd;
                tx.set_hash(txid);
                txi.blink = pool.has_blink(txid);
                return true;
            },
            true);

    return tx_infos;
}

static auto pool_locks(cryptonote::core& core) {
    auto& pool = core.mempool;
    std::unique_lock tx_lock{pool, std::defer_lock};
    std::unique_lock bc_lock{core.blockchain, std::defer_lock};
    auto blink_lock = pool.blink_shared_lock(std::defer_lock);
    std::lock(tx_lock, bc_lock, blink_lock);
    return std::make_tuple(std::move(tx_lock), std::move(bc_lock), std::move(blink_lock));
}

static std::pair<std::unordered_map<crypto::hash, tx_info>, tx_memory_pool::key_images_container>
get_pool_txs_kis(cryptonote::core& core) {
    auto locks = pool_locks(core);
    return {get_pool_txs_impl(core), core.mempool.get_spent_key_images(true)};
}

static tx_memory_pool::key_images_container get_pool_kis(cryptonote::core& core) {
    auto locks = pool_locks(core);
    return core.mempool.get_spent_key_images(true);
}

//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_TRANSACTIONS& get, rpc_context) {
    // NB: this also handles the deprecated GET_TRANSACTION_POOL
    std::unordered_set<crypto::hash> missed_txs;
    using split_tx = std::tuple<crypto::hash, std::string, crypto::hash, std::string>;
    std::vector<split_tx> txs;
    if (!get.request.tx_hashes.empty()) {
        if (!m_core.blockchain.get_split_transactions_blobs(
                    get.request.tx_hashes, txs, &missed_txs)) {
            get.response["status"] = STATUS_FAILED;
            return;
        }
        log::debug(
                logcat,
                "Found {}/{} transactions on the blockchain",
                txs.size(),
                get.request.tx_hashes.size());
    }

    // try the pool for any missing txes
    auto& pool = m_core.mempool;
    std::unordered_map<crypto::hash, tx_info> found_in_pool;
    if (!missed_txs.empty() || get.request.memory_pool) {
        try {
            auto [pool_txs, pool_kis] = get_pool_txs_kis(m_core);

            auto split_mempool_tx = [](std::pair<const crypto::hash, tx_info>& info) {
                cryptonote::transaction tx;
                if (!cryptonote::parse_and_validate_tx_from_blob(info.second.tx_blob, tx))
                    throw oxen::traced<std::runtime_error>{
                            "Unable to parse and validate tx from blob"};
                serialization::binary_string_archiver ba;
                try {
                    tx.serialize_base(ba);
                } catch (const std::exception& e) {
                    throw oxen::traced<std::runtime_error>{
                            "Failed to serialize transaction base: "s + e.what()};
                }
                std::string pruned = ba.str();
                std::string pruned2{info.second.tx_blob, pruned.size()};
                return split_tx{
                        info.first,
                        std::move(pruned),
                        get_transaction_prunable_hash(tx),
                        std::move(pruned2)};
            };

            if (!get.request.tx_hashes.empty()) {
                // sort to match original request
                std::vector<split_tx> sorted_txs;
                unsigned txs_processed = 0;
                for (const auto& h : get.request.tx_hashes) {
                    if (auto missed_it = missed_txs.find(h); missed_it == missed_txs.end()) {
                        if (txs.size() == txs_processed) {
                            get.response["status"] = "Failed: internal error - txs is empty";
                            return;
                        }
                        // core returns the ones it finds in the right order
                        if (std::get<0>(txs[txs_processed]) != h) {
                            get.response["status"] = "Failed: internal error - tx hash mismatch";
                            return;
                        }
                        sorted_txs.push_back(std::move(txs[txs_processed]));
                        ++txs_processed;
                    } else if (auto ptx_it = pool_txs.find(h); ptx_it != pool_txs.end()) {
                        sorted_txs.push_back(split_mempool_tx(*ptx_it));
                        missed_txs.erase(missed_it);
                        found_in_pool.emplace(h, std::move(ptx_it->second));
                    }
                }
                txs = std::move(sorted_txs);
                get.response_hex["missed_tx"] =
                        missed_txs;  // non-plural here intentional to not break existing clients
                log::debug(
                        logcat,
                        "Found {}/{} transactions in the pool",
                        found_in_pool.size(),
                        get.request.tx_hashes.size());
            } else if (get.request.memory_pool) {
                txs.reserve(pool_txs.size());
                std::transform(
                        pool_txs.begin(),
                        pool_txs.end(),
                        std::back_inserter(txs),
                        split_mempool_tx);
                found_in_pool = std::move(pool_txs);

                auto mki = get.response_hex["mempool_key_images"];
                for (auto& [ki, txids] : pool_kis) {
                    // The *key* is also binary (hex for json):
                    std::string key{get.is_bt() ? tools::view_guts(ki) : tools::hex_guts(ki)};
                    mki[key] = txids;
                }
            }
        } catch (const std::exception& e) {
            log::error(logcat, "{}", e.what());
            get.response["status"] = "Failed: "s + e.what();
            return;
        }
    }

    uint64_t immutable_height = m_core.blockchain.get_immutable_height();
    auto blink_lock =
            pool.blink_shared_lock(std::defer_lock);  // Defer until/unless we actually need it

    auto& txs_out = get.response["txs"];
    txs_out = json::array();

    for (const auto& [tx_hash, unprunable_data, prunable_hash, prunable_data] : txs) {
        auto& e = txs_out.emplace_back();
        auto e_bin = get.response_hex["txs"].back();
        e_bin["tx_hash"] = tx_hash;
        e["size"] = unprunable_data.size() + prunable_data.size();

        // If the transaction was pruned then the prunable part will be empty but the prunable hash
        // will be non-null.  (Some txes, like coinbase txes, are non-prunable and will have empty
        // *and* null prunable hash).
        bool prunable = (bool)prunable_hash;
        bool pruned = prunable && prunable_data.empty();

        if (pruned || (prunable && (get.request.split || get.request.prune)))
            e_bin["prunable_hash"] = prunable_hash;

        std::string tx_data = unprunable_data;
        if (!get.request.prune)
            tx_data += prunable_data;

        if (get.request.split || get.request.prune) {
            e_bin["pruned"] = unprunable_data;
            if (get.request.split)
                e_bin["prunable"] = prunable_data;
        }

        if (get.request.data) {
            if (pruned || get.request.prune) {
                if (!e.count("pruned"))
                    e_bin["pruned"] = unprunable_data;
            } else {
                e_bin["data"] = tx_data;
            }
        }

        cryptonote::transaction tx;
        if (get.request.prune || pruned) {
            if (!cryptonote::parse_and_validate_tx_base_from_blob(tx_data, tx)) {
                get.response["status"] = "Failed to parse and validate base tx data";
                return;
            }
        } else {
            if (!cryptonote::parse_and_validate_tx_from_blob(tx_data, tx)) {
                get.response["status"] = "Failed to parse and validate tx data";
                return;
            }
        }

        std::optional<json> extra;
        if (get.request.tx_extra)
            load_tx_extra_data(extra.emplace(), tx, nettype(), get.is_bt());
        if (get.request.tx_extra_raw)
            e_bin["tx_extra_raw"] = std::string_view{
                    reinterpret_cast<const char*>(tx.extra.data()), tx.extra.size()};

        {
            // Serialize *without* extra because we don't want/care about it in the RPC output (we
            // already have all the extra info in more useful form from the other bits of this
            // code).
            std::vector<uint8_t> saved_extra;
            std::swap(tx.extra, saved_extra);

            serialization::json_archiver ja{
                    get.is_bt() ? json_binary_proxy::fmt::bt : json_binary_proxy::fmt::hex};

            serialize(ja, tx);
            auto dumped = std::move(ja).json();
            e.update(dumped);

            std::swap(saved_extra, tx.extra);
        }

        if (extra)
            e["extra"] = std::move(*extra);
        else
            e.erase("extra");

        auto ptx_it = found_in_pool.find(tx_hash);
        bool in_pool = ptx_it != found_in_pool.end();
        auto height = std::numeric_limits<uint64_t>::max();

        auto hf_version = get_network_version(
                nettype(), in_pool ? m_core.blockchain.get_current_blockchain_height() : height);
        if (uint64_t fee, burned;
            get_tx_miner_fee(tx, fee, hf_version >= feature::FEE_BURNING, &burned)) {
            e["fee"] = fee;
            e["burned"] = burned;
        }

        if (in_pool) {
            e["in_pool"] = true;
            const auto& meta = ptx_it->second.meta;
            e["weight"] = meta.weight;
            e["relayed"] = (bool)ptx_it->second.meta.relayed;
            e["received_timestamp"] = ptx_it->second.meta.receive_time;
            e["blink"] = ptx_it->second.blink;
            if (meta.double_spend_seen)
                e["double_spend_seen"] = true;
            if (meta.do_not_relay)
                e["do_not_relay"] = true;
            if (meta.last_relayed_time)
                e["last_relayed_time"] = meta.last_relayed_time;
            if (meta.kept_by_block)
                e["kept_by_block"] = (bool)meta.kept_by_block;
            if (meta.last_failed_id)
                e_bin["last_failed_block"] = meta.last_failed_id;
            if (meta.last_failed_height)
                e["last_failed_height"] = meta.last_failed_height;
            if (meta.max_used_block_id)
                e_bin["max_used_block"] = meta.max_used_block_id;
            if (meta.max_used_block_height)
                e["max_used_height"] = meta.max_used_block_height;
        } else {
            height = m_core.blockchain.db().get_tx_block_height(tx_hash);
            e["block_height"] = height;
            e["block_timestamp"] = m_core.blockchain.db().get_block_timestamp(height);
            if (height > immutable_height) {
                if (!blink_lock)
                    blink_lock.lock();
                e["blink"] = pool.has_blink(tx_hash);
            }
        }

        if (service_nodes::staking_components sc;
            service_nodes::tx_get_staking_components_and_amounts(
                    nettype(), hf_version, tx, height, &sc) &&
            sc.transferred > 0)
            e["stake_amount"] = sc.transferred;

        // output indices too if not in pool
        if (!in_pool) {
            std::vector<uint64_t> indices;
            if (m_core.blockchain.get_tx_outputs_gindexs(tx_hash, indices))
                e["output_indices"] = std::move(indices);
            else {
                get.response["status"] = STATUS_FAILED;
                return;
            }
        }
    }

    log::debug(
            logcat,
            "{} transactions found, {} not found",
            get.response["txs"].size(),
            missed_txs.size());
    get.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(IS_KEY_IMAGE_SPENT& spent, rpc_context) {
    spent.response["status"] = STATUS_FAILED;

    std::vector<bool> blockchain_spent;
    if (!m_core.are_key_images_spent(spent.request.key_images, blockchain_spent))
        return;
    std::optional<tx_memory_pool::key_images_container> kis;
    auto spent_status = json::array();
    for (size_t n = 0; n < spent.request.key_images.size(); n++) {
        if (blockchain_spent[n])
            spent_status.push_back(IS_KEY_IMAGE_SPENT::SPENT::BLOCKCHAIN);
        else {
            if (!kis) {
                try {
                    kis = get_pool_kis(m_core);
                } catch (const std::exception& e) {
                    log::error(logcat, "Failed to get pool key images: {}", e.what());
                    return;
                }
            }
            spent_status.push_back(
                    kis->count(spent.request.key_images[n]) ? IS_KEY_IMAGE_SPENT::SPENT::POOL
                                                            : IS_KEY_IMAGE_SPENT::SPENT::UNSPENT);
        }
    }

    spent.response["status"] = STATUS_OK;
    spent.response["spent_status"] = std::move(spent_status);
}

static constexpr auto BLINK_TIMEOUT = "Blink quorum timeout"sv;
static constexpr auto BLINK_REJECTED = "Transaction rejected by blink quorum"sv;

//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(SUBMIT_TRANSACTION& tx, rpc_context) {
    if (!check_core_ready()) {
        tx.response["status"] = STATUS_BUSY;
        return;
    }

    if (tx.request.blink) {
        auto future = m_core.handle_blink_tx(tx.request.tx);
        // FIXME: blocking here for 10s is nasty; we need to stash this request and come back to it
        // when the blink tx result comes back, and wait for longer (maybe 30s).
        //
        // FIXME 2: on timeout, we should check the mempool to see if it arrived that way so that we
        // return success if it got out to the network, even if we didn't get the blink quorum reply
        // for some reason.
        auto status = future.wait_for(10s);
        if (status != std::future_status::ready) {
            tx.response["status"] = STATUS_FAILED;
            tx.response["reason"] = BLINK_TIMEOUT;
            tx.response["blink_status"] = blink_result::timeout;
            return;
        }

        try {
            auto result = future.get();
            tx.response["blink_status"] = result.first;
            if (result.first == blink_result::accepted) {
                tx.response["status"] = STATUS_OK;
            } else {
                tx.response["status"] = STATUS_FAILED;
                tx.response["reason"] = !result.second.empty()                ? result.second
                                      : result.first == blink_result::timeout ? BLINK_TIMEOUT
                                                                              : BLINK_REJECTED;
            }
        } catch (const std::exception& e) {
            tx.response["blink_status"] = blink_result::rejected;
            tx.response["status"] = STATUS_FAILED;
            tx.response["reason"] = "Transaction failed: "s + e.what();
        }
        return;
    }

    tx_verification_context tvc{};
    if (!m_core.handle_incoming_tx(tx.request.tx, tvc, tx_pool_options::new_tx()) ||
        tvc.m_verifivation_failed || !tvc.m_should_be_relayed) {
        tx.response["status"] = STATUS_FAILED;
        auto reason = print_tx_verification_context(tvc);
        log::warning(
                logcat,
                "[on_send_raw_tx]: {} {}",
                (tvc.m_verifivation_failed ? "tx verification failed" : "Failed to process tx"),
                reason);
        tx.response["reason"] = std::move(reason);
        tx.response["reason_codes"] = tx_verification_failure_codes(tvc);
        return;
    }

    // Why is is the RPC handler's responsibility to tell the p2p protocol to relay a transaction?!
    NOTIFY_NEW_TRANSACTIONS::request r{};
    r.txs.push_back(std::move(tx.request.tx));
    cryptonote_connection_context fake_context{};
    m_core.get_protocol()->relay_transactions(r, fake_context);

    tx.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(START_MINING& start_mining, rpc_context) {
    // CHECK_CORE_READY();
    if (!check_core_ready()) {
        start_mining.response["status"] = STATUS_BUSY;
        return;
    }

    cryptonote::address_parse_info info{};
    if (start_mining.request.miner_address == "none") {
        // use null address
    } else if (!get_account_address_from_str(
                       info, m_core.get_nettype(), start_mining.request.miner_address)) {
        start_mining.response["status"] = "Failed, invalid address";
        log::warning(logcat, "{}", start_mining.response["status"].get<std::string_view>());
        return;
    }
    if (info.is_subaddress) {
        start_mining.response["status"] = "Mining to subaddress isn't supported yet";
        log::warning(logcat, "{}", start_mining.response["status"].get<std::string_view>());
        return;
    }

    int max_concurrency_count = std::thread::hardware_concurrency() * 4;

    // if we couldn't detect threads, set it to a ridiculously high number
    if (max_concurrency_count == 0)
        max_concurrency_count = 257;

    // if there are more threads requested than the hardware supports
    // then we fail and log that.
    if (start_mining.request.threads_count > max_concurrency_count) {
        start_mining.response["status"] = "Failed, too many threads relative to CPU cores.";
        log::warning(logcat, "{}", start_mining.response["status"].get<std::string_view>());
        return;
    }

    if (m_core.miner.is_mining()) {
        start_mining.response["status"] = "Already mining";
        return;
    }

    if (!m_core.miner.start(
                info.address,
                start_mining.request.threads_count,
                start_mining.request.num_blocks,
                start_mining.request.slow_mining)) {
        start_mining.response["status"] = "Failed, mining not started";
        log::warning(logcat, "{}", start_mining.response["status"].get<std::string_view>());
        return;
    }

    start_mining.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(STOP_MINING& stop_mining, rpc_context) {
    if (!m_core.miner.is_mining()) {
        stop_mining.response["status"] = "Mining never started";
        log::warning(logcat, "{}", stop_mining.response["status"].get<std::string_view>());
        return;
    }
    if (!m_core.miner.stop()) {
        stop_mining.response["status"] = "Failed, mining not stopped";
        log::warning(logcat, "{}", stop_mining.response["status"].get<std::string_view>());
        return;
    }

    stop_mining.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(MINING_STATUS& mining_status, rpc_context) {
    mining_status.response["active"] = m_core.miner.is_mining();
    mining_status.response["block_target"] =
            tools::to_seconds(m_core.get_net_config().TARGET_BLOCK_TIME);
    mining_status.response["difficulty"] =
            m_core.blockchain.get_difficulty_for_next_block(false /*pulse*/);
    if (m_core.miner.is_mining()) {
        mining_status.response["speed"] = std::lround(m_core.miner.get_speed());
        mining_status.response["threads_count"] = m_core.miner.get_threads_count();
        mining_status.response["block_reward"] = m_core.miner.get_block_reward();
    }
    const account_public_address& lMiningAdr = m_core.miner.get_mining_address();
    if (m_core.miner.is_mining())
        mining_status.response["address"] =
                get_account_address_as_str(nettype(), false, lMiningAdr);
    const auto major_version = m_core.blockchain.get_network_version();

    mining_status.response["pow_algorithm"] = major_version >= hf::hf12_checkpointing ? "RandomX "
                                                                                        "(OXEN "
                                                                                        "variant)"
                                            : major_version == hf::hf11_infinite_staking
                                                    ? "Cryptonight Turtle Light (Variant 2)"
                                                    : "Cryptonight Heavy (Variant 2)";

    mining_status.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(SAVE_BC& save_bc, rpc_context) {
    if (!m_core.blockchain.store_blockchain()) {
        save_bc.response["status"] = "Error while storing blockchain";
        log::warning(logcat, "{}", save_bc.response["status"].get<std::string_view>());
        return;
    }
    save_bc.response["status"] = STATUS_OK;
}

static nlohmann::json json_peer_info(const nodetool::peerlist_entry& peer) {
    nlohmann::json p{
            {"id", peer.id},
            {"host", peer.adr.host_str()},
            {"port", peer.adr.port()},
            {"last_seen", peer.last_seen}};
    if (peer.pruning_seed)
        p["pruning_seed"] = peer.pruning_seed;
    return p;
}

//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_PEER_LIST& pl, rpc_context) {
    std::vector<nodetool::peerlist_entry> white_list, gray_list;
    if (pl.request.public_only)
        m_p2p.get_public_peerlist(gray_list, white_list);
    else
        m_p2p.get_peerlist(gray_list, white_list);

    std::transform(
            white_list.begin(),
            white_list.end(),
            std::back_inserter(pl.response["white_list"]),
            json_peer_info);
    std::transform(
            gray_list.begin(),
            gray_list.end(),
            std::back_inserter(pl.response["gray_list"]),
            json_peer_info);

    pl.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(SET_LOG_LEVEL& set_log_level, rpc_context) {
    auto cats = oxen::logging::extract_categories(set_log_level.request.categories);
    if (cats.empty()) {
        log::error(
                logcat,
                "Invalid log level/categories string for set_log_level: {}",
                set_log_level.request.categories);
        set_log_level.response["status"] = "Error: invalid log level/categories string";
        return;
    }

    auto applied = cats.apply();

    set_log_level.response["applied"] = std::move(applied);
    set_log_level.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
GET_TRANSACTION_POOL_HASHES_BIN::response core_rpc_server::invoke(
        GET_TRANSACTION_POOL_HASHES_BIN::request&& req, rpc_context context) {
    GET_TRANSACTION_POOL_HASHES_BIN::response res{};

    std::vector<crypto::hash> tx_pool_hashes;
    m_core.mempool.get_transaction_hashes(tx_pool_hashes, context.admin, req.blinked_txs_only);

    res.tx_hashes = std::move(tx_pool_hashes);
    res.status = STATUS_OK;
    return res;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(
        GET_TRANSACTION_POOL_HASHES& get_transaction_pool_hashes, rpc_context context) {
    std::vector<crypto::hash> tx_hashes;
    m_core.mempool.get_transaction_hashes(tx_hashes, context.admin);
    get_transaction_pool_hashes.response_hex["tx_hashes"] = tx_hashes;
    get_transaction_pool_hashes.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_TRANSACTION_POOL_STATS& stats, rpc_context) {
    auto txpool = m_core.mempool.get_transaction_stats(stats.request.include_unrelayed);
    json pool_stats{
            {"bytes_total", txpool.bytes_total},
            {"bytes_min", txpool.bytes_min},
            {"bytes_max", txpool.bytes_max},
            {"bytes_med", txpool.bytes_med},
            {"fee_total", txpool.fee_total},
            {"oldest", txpool.oldest},
            {"txs_total", txpool.txs_total},
            {"num_failing", txpool.num_failing},
            {"num_10m", txpool.num_10m},
            {"num_not_relayed", txpool.num_not_relayed},
            {"histo", std::move(txpool.histo)},
            {"num_double_spends", txpool.num_double_spends}};

    if (txpool.histo_98pc)
        pool_stats["histo_98pc"] = txpool.histo_98pc;
    else
        pool_stats["histo_max"] = std::time(nullptr) - txpool.oldest;

    stats.response["pool_stats"] = std::move(pool_stats);
    stats.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(STOP_DAEMON& stop_daemon, rpc_context) {
    m_p2p.send_stop_signal();
    stop_daemon.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
//
// Oxen
//
GET_OUTPUT_BLACKLIST_BIN::response core_rpc_server::invoke(
        GET_OUTPUT_BLACKLIST_BIN::request&&, rpc_context) {
    GET_OUTPUT_BLACKLIST_BIN::response res{};

    try {
        m_core.blockchain.get_output_blacklist(res.blacklist);
    } catch (const std::exception& e) {
        res.status = std::string("Failed to get output blacklist: ") + e.what();
        return res;
    }

    res.status = STATUS_OK;
    return res;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_BLOCK_COUNT& get, rpc_context) {
    get.response["count"] = m_core.blockchain.get_current_blockchain_height();
    get.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_BLOCK_HASH& get, rpc_context) {
    auto curr_height = m_core.blockchain.get_current_blockchain_height();
    for (auto h : get.request.heights) {
        if (h >= curr_height)
            throw rpc_error{
                    ERROR_TOO_BIG_HEIGHT,
                    "Requested block height {} greater than current top block height {}"_format(
                            h, curr_height - 1)};
        get.response_hex["{}"_format(h)] = m_core.blockchain.get_block_id_by_height(h);
    }
    get.response["height"] = curr_height;
    get.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
static uint64_t get_block_coinbase_payouts(const block& blk) {
    uint64_t reward = 0;
    if (blk.miner_tx)
        for (const tx_out& out : blk.miner_tx->vout)
            reward += out.amount;
    return reward;
}
//------------------------------------------------------------------------------------------------------------------------------
static void fill_block_header_response(
        const block& blk,
        size_t block_size,
        bool orphan_status,
        std::optional<uint64_t> maybe_height,
        const crypto::hash& hash,
        bool fill_pow_hash,
        bool get_tx_hashes,
        nlohmann::json& response,
        bool is_bt,
        cryptonote::core& core) {

    auto& db = core.blockchain.db();

    tools::json_binary_proxy response_hex{
            response,
            is_bt ? tools::json_binary_proxy::fmt::bt : tools::json_binary_proxy::fmt::hex};

    uint64_t height = maybe_height ? *maybe_height : blk.get_height();

    response["major_version"] = static_cast<uint8_t>(blk.major_version);
    response["minor_version"] = static_cast<uint8_t>(blk.minor_version);
    response["timestamp"] = blk.timestamp;
    response_hex["prev_hash"] = blk.prev_id;
    response["nonce"] = blk.nonce;
    response["orphan_status"] = orphan_status;
    response["height"] = height;
    response["depth"] = core.blockchain.get_current_blockchain_height() - height - 1;
    response_hex["hash"] = hash;
    response["difficulty"] = core.blockchain.block_difficulty(height);
    response["cumulative_difficulty"] = db.get_block_cumulative_difficulty(height);
    auto weight = db.get_block_weight(height);
    response["block_weight"] = weight;
    response["block_size"] = block_size + weight;
    auto coinbase = get_block_coinbase_payouts(blk);
    response["coinbase_payouts"] = coinbase;
    response["reward"] =
            blk.major_version >= cryptonote::hf::hf19_reward_batching ? blk.reward : coinbase;
    response["num_txes"] = blk.tx_hashes.size();
    if (fill_pow_hash)
        response_hex["pow_hash"] = get_block_longhash_w_blockchain(
                core.get_nettype(), &core.blockchain, blk, height, 0);
    response["long_term_weight"] = db.get_block_long_term_weight(height);
    if (blk.major_version < feature::ETH_BLS)
        response_hex["service_node_winner"] =
                cryptonote::get_service_node_winner_from_tx_extra(blk.miner_tx.value().extra);
    else
        response_hex["service_node_winner_tail"] = blk.sn_winner_tail;
    if (blk.major_version >= cryptonote::feature::ETH_BLS) {
        response["l2_height"] = blk.l2_height;
        response["l2_reward"] = blk.l2_reward;
        response["l2_votes"] = blk.l2_votes;
    }
    if (blk.miner_tx) {
        response_hex["miner_tx_hash"] = cryptonote::get_transaction_hash(*blk.miner_tx);
        response["miner_tx_outs"] = blk.miner_tx->vout.size();
    }
    if (get_tx_hashes)
        for (const auto& tx_hash : blk.tx_hashes)
            response_hex["tx_hashes"].push_back(tx_hash);
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_LAST_BLOCK_HEADER& get_last_block_header, rpc_context context) {
    if (!check_core_ready()) {
        get_last_block_header.response["status"] = STATUS_BUSY;
        return;
    }

    auto [last_block_height, last_block_hash] = m_core.blockchain.get_tail_id();
    block last_block;
    size_t block_size;
    bool have_last_block =
            m_core.blockchain.get_block_by_height(last_block_height, last_block, &block_size);
    if (!have_last_block)
        throw rpc_error{ERROR_INTERNAL, "Internal error: can't get last block."};
    fill_block_header_response(
            last_block,
            block_size,
            false,
            last_block_height,
            last_block_hash,
            get_last_block_header.request.fill_pow_hash && context.admin,
            get_last_block_header.request.get_tx_hashes,
            get_last_block_header.response["block_header"],
            get_last_block_header.is_bt(),
            m_core);

    get_last_block_header.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------

void core_rpc_server::invoke(GET_BLOCK_HEADER_BY_HASH& gbh, rpc_context context) {
    auto get = [this, &gbh, admin = context.admin](
                       const std::string& hash, nlohmann::json& response) {
        crypto::hash block_hash;
        if (!tools::try_load_from_hex_guts(hash, block_hash))
            throw rpc_error{
                    ERROR_WRONG_PARAM,
                    "Failed to parse hex representation of block hash. Hex = " + hash + '.'};
        block blk;
        size_t block_size;
        bool orphan = false;
        bool have_block =
                m_core.blockchain.get_block_by_hash(block_hash, blk, &block_size, &orphan);
        if (!have_block)
            throw rpc_error{
                    ERROR_INTERNAL,
                    "Internal error: can't get block by hash. Hash = " + hash + '.'};
        fill_block_header_response(
                blk,
                block_size,
                orphan,
                std::nullopt,
                block_hash,
                gbh.request.fill_pow_hash && admin,
                gbh.request.get_tx_hashes,
                response,
                gbh.is_bt(),
                m_core);
    };

    if (!gbh.request.hash.empty())
        get(gbh.request.hash, gbh.response["block_header"]);

    if (!gbh.request.hashes.empty()) {
        auto& out_headers = gbh.response["block_headers"];
        out_headers = json::array();
        for (const std::string& hash : gbh.request.hashes)
            get(hash, out_headers.emplace_back());
    }

    gbh.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(
        GET_BLOCK_HEADERS_RANGE& get_block_headers_range, rpc_context context) {
    const uint64_t bc_height = m_core.blockchain.get_current_blockchain_height();
    uint64_t start_height = get_block_headers_range.request.start_height;
    uint64_t end_height = get_block_headers_range.request.end_height;
    if (start_height >= bc_height || end_height >= bc_height || start_height > end_height)
        throw rpc_error{ERROR_TOO_BIG_HEIGHT, "Invalid start/end heights."};
    for (uint64_t h = start_height; h <= end_height; ++h) {
        block blk;
        size_t block_size;
        bool have_block = m_core.blockchain.get_block_by_height(h, blk, &block_size);
        if (!have_block)
            throw rpc_error{
                    ERROR_INTERNAL,
                    "Internal error: can't get block by height. Height = {}."_format(h)};
        fill_block_header_response(
                blk,
                block_size,
                false,
                std::nullopt,
                get_block_hash(blk),
                get_block_headers_range.request.fill_pow_hash && context.admin,
                get_block_headers_range.request.get_tx_hashes,
                get_block_headers_range.response["headers"].emplace_back(),
                get_block_headers_range.is_bt(),
                m_core);
    }
    get_block_headers_range.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_BLOCK_HEADER_BY_HEIGHT& gbh, rpc_context context) {
    auto get = [this,
                &gbh,
                curr_height = m_core.blockchain.get_current_blockchain_height(),
                pow = gbh.request.fill_pow_hash && context.admin](
                       uint64_t height, nlohmann::json& bhr) {
        if (height >= curr_height)
            throw rpc_error{
                    ERROR_TOO_BIG_HEIGHT,
                    "Requested block height: " + std::to_string(height) +
                            " greater than current top block height: " +
                            std::to_string(curr_height - 1)};
        block blk;
        size_t blk_size = 0;
        bool have_block = m_core.blockchain.get_block_by_height(height, blk, &blk_size);
        if (!have_block)
            throw rpc_error{
                    ERROR_INTERNAL,
                    "Internal error: can't get block by height. Height = " +
                            std::to_string(height) + '.'};
        fill_block_header_response(
                blk,
                blk_size,
                false,
                height,
                get_block_hash(blk),
                pow,
                gbh.request.get_tx_hashes,
                bhr,
                gbh.is_bt(),
                m_core);
    };

    if (gbh.request.height)
        get(*gbh.request.height, gbh.response["block_header"]);

    if (!gbh.request.heights.empty())
        for (auto height : gbh.request.heights)
            get(height, gbh.response["block_headers"].emplace_back());

    gbh.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_BLOCK& get_block, rpc_context context) {
    block blk;
    std::optional<uint64_t> block_height;
    bool orphan = false;
    crypto::hash block_hash;
    size_t block_size = 0;
    if (!get_block.request.hash.empty()) {
        if (!tools::try_load_from_hex_guts(get_block.request.hash, block_hash))
            throw rpc_error{
                    ERROR_WRONG_PARAM,
                    "Failed to parse hex representation of block hash. Hex = {}."_format(
                            get_block.request.hash)};
        if (!m_core.blockchain.get_block_by_hash(block_hash, blk, &block_size, &orphan))
            throw rpc_error{
                    ERROR_INTERNAL,
                    "Internal error: can't get block by hash. Hash = {}."_format(
                            get_block.request.hash)};
    } else {
        if (auto curr_height = m_core.blockchain.get_current_blockchain_height();
            get_block.request.height >= curr_height)
            throw rpc_error{
                    ERROR_TOO_BIG_HEIGHT,
                    "Requested block height: {} greater than current top block height: {}"_format(
                            get_block.request.height, curr_height - 1)};
        if (!m_core.blockchain.get_block_by_height(get_block.request.height, blk, &block_size))
            throw rpc_error{
                    ERROR_INTERNAL,
                    "Internal error: can't get block by height. Height = {}."_format(
                            get_block.request.height)};
        block_hash = get_block_hash(blk);
        block_height = get_block.request.height;
    }
    fill_block_header_response(
            blk,
            block_size,
            orphan,
            block_height,
            block_hash,
            get_block.request.fill_pow_hash && context.admin,
            false /*tx hashes*/,
            get_block.response["block_header"],
            get_block.is_bt(),
            m_core);
    get_block.response_hex["tx_hashes"] = blk.tx_hashes;
    get_block.response_hex["blob"] = t_serializable_object_to_blob(blk);
    get_block.response["json"] = obj_to_json_str(blk);
    get_block.response["status"] = STATUS_OK;
}

static json json_connection_info(const connection_info& ci) {
    json info{
            {"incoming", ci.incoming},
            {"ip", ci.ip},
            {"address_type", ci.address_type},
            {"peer_id", ci.peer_id},
            {"recv_count", ci.recv_count},
            {"recv_idle_ms", ci.recv_idle_time.count()},
            {"send_count", ci.send_count},
            {"send_idle_ms", ci.send_idle_time.count()},
            {"state", ci.state},
            {"live_ms", ci.live_time.count()},
            {"avg_download", ci.avg_download},
            {"current_download", ci.current_download},
            {"avg_upload", ci.avg_upload},
            {"current_upload", ci.current_upload},
            {"connection_id", ci.connection_id},
            {"height", ci.height},
    };
    if (ci.ip != ci.host)
        info["host"] = ci.host;
    if (ci.localhost)
        info["localhost"] = true;
    if (ci.local_ip)
        info["local_ip"] = true;
    if (uint16_t port; tools::parse_int(ci.port, port) && port > 0)
        info["port"] = port;
    // Included for completeness, but undocumented as this is not currently actually used or
    // supported on Oxen:
    if (ci.pruning_seed)
        info["pruning_seed"] = ci.pruning_seed;
    return info;
}

//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_CONNECTIONS& get_connections, rpc_context) {
    auto& c = get_connections.response["connections"];
    c = json::array();
    for (auto& ci : m_p2p.get_payload_object().get_connections())
        c.push_back(json_connection_info(ci));
    get_connections.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(HARD_FORK_INFO& hfinfo, rpc_context) {
    const auto& blockchain = m_core.blockchain;
    auto version =
            hfinfo.request.version > 0
                    ? hard_fork_ceil(m_core.get_nettype(), static_cast<hf>(hfinfo.request.version))
            : hfinfo.request.height > 0 ? blockchain.get_network_version(hfinfo.request.height)
                                        : blockchain.get_network_version();
    hfinfo.response["version"] = static_cast<std::underlying_type_t<hf>>(version);
    hfinfo.response["enabled"] = blockchain.get_network_version() >= version;
    auto heights = get_hard_fork_heights(m_core.get_nettype(), version);
    if (heights.first)
        hfinfo.response["earliest_height"] = *heights.first;
    if (heights.second)
        hfinfo.response["latest_height"] = *heights.second;
    hfinfo.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_BANS& get_bans, rpc_context) {
    get_bans.response["bans"] = nlohmann::json::array();
    auto now = time(nullptr);
    std::map<std::string, time_t> blocked_hosts = m_p2p.get_blocked_hosts();
    for (std::map<std::string, time_t>::const_iterator i = blocked_hosts.begin();
         i != blocked_hosts.end();
         ++i) {
        if (i->second > now) {
            ban b;
            b.host = i->first;
            b.seconds = i->second - now;
            get_bans.response["bans"].push_back(b);
        }
    }
    std::map<epee::net_utils::ipv4_network_subnet, time_t> blocked_subnets =
            m_p2p.get_blocked_subnets();
    for (std::map<epee::net_utils::ipv4_network_subnet, time_t>::const_iterator i =
                 blocked_subnets.begin();
         i != blocked_subnets.end();
         ++i) {
        if (i->second > now) {
            ban b;
            b.host = i->first.host_str();
            b.seconds = i->second - now;
            get_bans.response["bans"].push_back(b);
        }
    }

    get_bans.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(BANNED& banned, rpc_context) {
    auto na_parsed = net::get_network_address(banned.request.address, 0);
    if (!na_parsed)
        throw rpc_error{ERROR_WRONG_PARAM, "Unsupported host type"};
    epee::net_utils::network_address na = std::move(*na_parsed);

    time_t seconds;
    if (m_p2p.is_host_blocked(na, &seconds)) {
        banned.response["banned"] = true;
        banned.response["seconds"] = seconds;
    } else {
        banned.response["banned"] = false;
        banned.response["seconds"] = 0;
    }

    banned.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(SET_BANS& set_bans, rpc_context) {
    epee::net_utils::network_address na;
    // try subnet first
    auto ns_parsed = net::get_ipv4_subnet_address(set_bans.request.host);
    if (ns_parsed) {
        if (set_bans.request.ban)
            m_p2p.block_subnet(*ns_parsed, set_bans.request.seconds);
        else
            m_p2p.unblock_subnet(*ns_parsed);
        set_bans.response["status"] = STATUS_OK;
        return;
    }

    // then host
    auto na_parsed = net::get_network_address(set_bans.request.host, 0);
    if (!na_parsed)
        throw rpc_error{ERROR_WRONG_PARAM, "Unsupported host/subnet type"};
    na = std::move(*na_parsed);
    if (set_bans.request.ban)
        m_p2p.block_host(na, set_bans.request.seconds);
    else
        m_p2p.unblock_host(na);

    set_bans.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(FLUSH_TRANSACTION_POOL& flush_transaction_pool, rpc_context) {
    bool failed = false;
    std::vector<crypto::hash> txids;
    if (flush_transaction_pool.request.txids.empty()) {
        std::vector<transaction> pool_txs;
        m_core.mempool.get_transactions(pool_txs);
        for (const auto& tx : pool_txs) {
            txids.push_back(cryptonote::get_transaction_hash(tx));
        }
    } else {
        for (const auto& txid_hex : flush_transaction_pool.request.txids) {
            std::string txid_data;
            if (!tools::try_load_from_hex_guts(txid_hex, txids.emplace_back())) {
                failed = true;
                txids.pop_back();
            }
        }
    }
    if (!m_core.blockchain.flush_txes_from_pool(txids)) {
        flush_transaction_pool.response["status"] = "Failed to remove one or more tx(es)";
        return;
    }

    flush_transaction_pool.response["status"] =
            failed ? txids.empty() ? "Failed to parse txid" : "Failed to parse some of the txids"
                   : STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_OUTPUT_HISTOGRAM& get_output_histogram, rpc_context context) {
    if (!context.admin && get_output_histogram.request.recent_cutoff > 0 &&
        get_output_histogram.request.recent_cutoff <
                (uint64_t)time(NULL) - OUTPUT_HISTOGRAM_RECENT_CUTOFF_RESTRICTION) {
        get_output_histogram.response["status"] = "Recent cutoff is too old";
        return;
    }

    std::map<uint64_t, std::tuple<uint64_t, uint64_t, uint64_t>> histogram;
    try {
        histogram = m_core.blockchain.get_output_histogram(
                get_output_histogram.request.amounts,
                get_output_histogram.request.unlocked,
                get_output_histogram.request.recent_cutoff,
                get_output_histogram.request.min_count);
    } catch (const std::exception& e) {
        get_output_histogram.response["status"] = "Failed to get output histogram";
        return;
    }

    std::vector<GET_OUTPUT_HISTOGRAM::entry> response_histogram;
    response_histogram.reserve(histogram.size());
    for (const auto& [amount, histogram_tuple] : histogram) {
        auto& [total_instances, unlocked_instances, recent_instances] = histogram_tuple;

        if (total_instances >= get_output_histogram.request.min_count &&
            (total_instances <= get_output_histogram.request.max_count ||
             get_output_histogram.request.max_count == 0))
            response_histogram.push_back(GET_OUTPUT_HISTOGRAM::entry{
                    amount, total_instances, unlocked_instances, recent_instances});
    }

    get_output_histogram.response["histogram"] = response_histogram;
    get_output_histogram.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_VERSION& version, rpc_context) {
    version.response["version"] = pack_version(VERSION);
    version.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_SERVICE_NODE_STATUS& sns, rpc_context) {
    auto [top_height, top_hash] = m_core.blockchain.get_tail_id();
    sns.response["height"] = top_height;
    sns.response_hex["block_hash"] = top_hash;
    const auto& keys = m_core.get_service_keys();
    if (!keys.pub) {
        sns.response["status"] = "Not a service node";
        return;
    }
    sns.response["status"] = STATUS_OK;

    auto sn_infos = m_core.service_node_list.get_service_node_list_state({{keys.pub}});
    if (!sn_infos.empty())
        fill_sn_response_entry(
                sns.response["service_node_state"] = json::object(),
                sns.is_bt(),
                {} /*all fields*/,
                sn_infos.front(),
                top_height);
    else {
        sns.response["service_node_state"] = json{
                {"public_ip", epee::string_tools::get_ip_string_from_int32(m_core.sn_public_ip())},
                {"storage_port", m_core.storage_https_port()},
                {"storage_lmq_port", m_core.storage_omq_port()},
                {"quorumnet_port", m_core.quorumnet_port()},
                {"service_node_version", OXEN_VERSION}};
        auto rhex = sns.response_hex["service_node_state"];
        rhex["service_node_pubkey"] = keys.pub;
        rhex["pubkey_ed25519"] = keys.pub_ed25519;
        rhex["pubkey_x25519"] = keys.pub_x25519;
        rhex["pubkey_bls"] = keys.pub_bls;
    }
}

//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_COINBASE_TX_SUM& get_coinbase_tx_sum, rpc_context) {
    if (auto sums = m_core.get_coinbase_tx_sum(
                get_coinbase_tx_sum.request.height, get_coinbase_tx_sum.request.count)) {
        std::tie(
                get_coinbase_tx_sum.response["emission_amount"],
                get_coinbase_tx_sum.response["fee_amount"],
                get_coinbase_tx_sum.response["burn_amount"]) = *sums;
        get_coinbase_tx_sum.response["status"] = STATUS_OK;
    } else {
        get_coinbase_tx_sum.response["status"] =
                STATUS_BUSY;  // some other request is already calculating it
    }
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_FEE_ESTIMATE& get_fee_estimate, rpc_context) {
    auto fees =
            m_core.blockchain.get_dynamic_base_fee_estimate(get_fee_estimate.request.grace_blocks);
    get_fee_estimate.response["fee_per_byte"] = fees.first;
    get_fee_estimate.response["fee_per_output"] = fees.second;
    get_fee_estimate.response["blink_fee_fixed"] = oxen::BLINK_BURN_FIXED;
    constexpr auto blink_percent =
            oxen::BLINK_MINER_TX_FEE_PERCENT + oxen::BLINK_BURN_TX_FEE_PERCENT_V18;
    get_fee_estimate.response["blink_fee_per_byte"] = fees.first * blink_percent / 100;
    get_fee_estimate.response["blink_fee_per_output"] = fees.second * blink_percent / 100;
    get_fee_estimate.response["quantization_mask"] = Blockchain::get_fee_quantization_mask();
    get_fee_estimate.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_ALTERNATE_CHAINS& get_alternate_chains, rpc_context) {
    try {
        std::vector<GET_ALTERNATE_CHAINS::chain_info> chains;
        std::vector<std::pair<Blockchain::block_extended_info, std::vector<crypto::hash>>>
                alt_chains = m_core.blockchain.get_alternative_chains();
        for (const auto& i : alt_chains) {
            chains.push_back(GET_ALTERNATE_CHAINS::chain_info{
                    tools::hex_guts(get_block_hash(i.first.bl)),
                    i.first.height,
                    i.second.size(),
                    i.first.cumulative_difficulty,
                    {},
                    std::string()});
            chains.back().block_hashes.reserve(i.second.size());
            for (const crypto::hash& block_id : i.second)
                chains.back().block_hashes.push_back(tools::hex_guts(block_id));
            if (i.first.height < i.second.size()) {
                get_alternate_chains.response["status"] =
                        "Error finding alternate chain attachment point";
                return;
            }
            cryptonote::block main_chain_parent_block;
            try {
                main_chain_parent_block = m_core.blockchain.db().get_block_from_height(
                        i.first.height - i.second.size());
            } catch (const std::exception& e) {
                get_alternate_chains.response["status"] =
                        "Error finding alternate chain attachment point";
                return;
            }
            chains.back().main_chain_parent_block =
                    tools::hex_guts(get_block_hash(main_chain_parent_block));
        }
        get_alternate_chains.response["chains"] = chains;
        get_alternate_chains.response["status"] = STATUS_OK;
    } catch (...) {
        get_alternate_chains.response["status"] = "Error retrieving alternate chains";
    }
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_LIMIT& limit, rpc_context) {
    limit.response = {
            {"limit_down", epee::net_utils::connection_basic::get_rate_down_limit()},
            {"limit_up", epee::net_utils::connection_basic::get_rate_up_limit()},
            {"status", STATUS_OK}};
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(SET_LIMIT& limit, rpc_context) {
    // -1 = reset to default
    //  0 = do not modify
    if (limit.request.limit_down != 0)
        epee::net_utils::connection_basic::set_rate_down_limit(
                limit.request.limit_down == -1 ? p2p::DEFAULT_LIMIT_RATE_DOWN
                                               : limit.request.limit_down);

    if (limit.request.limit_up != 0)
        epee::net_utils::connection_basic::set_rate_up_limit(
                limit.request.limit_up == -1 ? p2p::DEFAULT_LIMIT_RATE_UP : limit.request.limit_up);

    limit.response = {
            {"limit_down", epee::net_utils::connection_basic::get_rate_down_limit()},
            {"limit_up", epee::net_utils::connection_basic::get_rate_up_limit()},
            {"status", STATUS_OK}};
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(OUT_PEERS& out_peers, rpc_context) {
    if (out_peers.request.set)
        m_p2p.change_max_out_public_peers(out_peers.request.out_peers);
    out_peers.response["out_peers"] = m_p2p.get_max_out_public_peers();
    out_peers.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(IN_PEERS& in_peers, rpc_context) {
    if (in_peers.request.set)
        m_p2p.change_max_in_public_peers(in_peers.request.in_peers);
    in_peers.response["in_peers"] = m_p2p.get_max_in_public_peers();
    in_peers.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(POP_BLOCKS& pop_blocks, rpc_context) {
    m_core.blockchain.pop_blocks(pop_blocks.request.nblocks);

    pop_blocks.response["height"] = m_core.blockchain.get_current_blockchain_height();
    pop_blocks.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(RELAY_TX& relay_tx, rpc_context) {
    std::string status = "";
    for (const auto& txid_hex : relay_tx.request.txids) {
        crypto::hash txid;
        if (!tools::try_load_from_hex_guts(txid_hex, txid)) {
            if (!status.empty())
                status += ", ";
            status += "invalid transaction id: " + txid_hex;
            continue;
        }

        if (std::string txblob; m_core.mempool.get_transaction(txid, txblob)) {
            cryptonote_connection_context fake_context{};
            NOTIFY_NEW_TRANSACTIONS::request r{};
            r.txs.push_back(txblob);
            m_core.get_protocol()->relay_transactions(r, fake_context);
            // TODO: make sure that tx has reached other nodes here, probably wait to receive
            // reflections from other nodes
        } else {
            if (!status.empty())
                status += ", ";
            status += "transaction not found in pool: " + txid_hex;
        }
    }

    if (status.empty())
        status = STATUS_OK;

    relay_tx.response["status"] = status;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(SYNC_INFO& sync, rpc_context) {
    auto [top_height, top_hash] = m_core.blockchain.get_tail_id();
    sync.response["height"] = top_height + 1;  // turn top block height into blockchain height
    if (auto target_height = m_core.get_target_blockchain_height(); target_height > top_height + 1)
        sync.response["target_height"] = target_height;
    // Don't put this into the response until it actually does something on Oxen:
    if (false)
        sync.response["next_needed_pruning_seed"] =
                m_p2p.get_payload_object().get_next_needed_pruning_stripe().second;

    auto& peers = sync.response["peers"];
    peers = json{};
    for (auto& ci : m_p2p.get_payload_object().get_connections())
        peers[ci.connection_id] = json_connection_info(ci);
    const auto& block_queue = m_p2p.get_payload_object().get_block_queue();
    auto spans = json::array();
    block_queue.foreach ([&spans, &block_queue](const auto& span) {
        uint32_t speed = (uint32_t)(100.0f * block_queue.get_speed(span.connection_id) + 0.5f);
        spans.push_back(
                json{{"start_block_height", span.start_block_height},
                     {"nblocks", span.nblocks},
                     {"connection_id", tools::hex_guts(span.connection_id)},
                     {"rate", std::lround(span.rate)},
                     {"speed", speed},
                     {"size", span.size}});
        return true;
    });
    sync.response["overview"] = block_queue.get_overview(top_height + 1);
    sync.response["status"] = STATUS_OK;
}

namespace {
    output_distribution_data process_distribution(
            bool cumulative,
            std::uint64_t start_height,
            std::vector<std::uint64_t> distribution,
            std::uint64_t base) {
        if (!cumulative && !distribution.empty()) {
            for (std::size_t n = distribution.size() - 1; 0 < n; --n)
                distribution[n] -= distribution[n - 1];
            distribution[0] -= base;
        }

        return {std::move(distribution), start_height, base};
    }

    static struct {
        std::mutex mutex;
        std::vector<std::uint64_t> cached_distribution;
        std::uint64_t cached_from = 0, cached_to = 0, cached_start_height = 0, cached_base = 0;
        crypto::hash cached_m10_hash{};
        crypto::hash cached_top_hash{};
        bool cached = false;
    } output_dist_cache;
}  // namespace

namespace detail {
    std::optional<output_distribution_data> get_output_distribution(
            const std::function<bool(
                    uint64_t, uint64_t, uint64_t, uint64_t&, std::vector<uint64_t>&, uint64_t&)>& f,
            uint64_t amount,
            uint64_t from_height,
            uint64_t to_height,
            const std::function<crypto::hash(uint64_t)>& get_hash,
            bool cumulative,
            uint64_t blockchain_height) {
        auto& d = output_dist_cache;
        const std::unique_lock lock{d.mutex};

        crypto::hash top_hash{};
        if (d.cached_to < blockchain_height)
            top_hash = get_hash(d.cached_to);
        if (d.cached && amount == 0 && d.cached_from == from_height && d.cached_to == to_height &&
            d.cached_top_hash == top_hash)
            return process_distribution(
                    cumulative, d.cached_start_height, d.cached_distribution, d.cached_base);

        std::vector<std::uint64_t> distribution;
        std::uint64_t start_height, base;

        // see if we can extend the cache - a common case
        bool can_extend = d.cached && amount == 0 && d.cached_from == from_height &&
                          to_height > d.cached_to && top_hash == d.cached_top_hash;
        if (!can_extend) {
            // we kept track of the hash 10 blocks below, if it exists, so if it matches,
            // we can still pop the last 10 cached slots and try again
            if (d.cached && amount == 0 && d.cached_from == from_height &&
                d.cached_to - d.cached_from >= 10 && to_height > d.cached_to - 10) {
                crypto::hash hash10 = get_hash(d.cached_to - 10);
                if (hash10 == d.cached_m10_hash) {
                    d.cached_to -= 10;
                    d.cached_top_hash = hash10;
                    d.cached_m10_hash = crypto::null<crypto::hash>;
                    CHECK_AND_ASSERT_MES(
                            d.cached_distribution.size() >= 10,
                            std::nullopt,
                            "Cached distribution size does not match cached bounds");
                    for (int p = 0; p < 10; ++p)
                        d.cached_distribution.pop_back();
                    can_extend = true;
                }
            }
        }
        if (can_extend) {
            std::vector<std::uint64_t> new_distribution;
            if (!f(amount, d.cached_to + 1, to_height, start_height, new_distribution, base))
                return std::nullopt;
            distribution = d.cached_distribution;
            distribution.reserve(distribution.size() + new_distribution.size());
            for (const auto& e : new_distribution)
                distribution.push_back(e);
            start_height = d.cached_start_height;
            base = d.cached_base;
        } else {
            if (!f(amount, from_height, to_height, start_height, distribution, base))
                return std::nullopt;
        }

        if (to_height > 0 && to_height >= from_height) {
            const std::uint64_t offset = std::max(from_height, start_height);
            if (offset <= to_height && to_height - offset + 1 < distribution.size())
                distribution.resize(to_height - offset + 1);
        }

        if (amount == 0) {
            d.cached_from = from_height;
            d.cached_to = to_height;
            d.cached_top_hash = get_hash(d.cached_to);
            d.cached_m10_hash =
                    d.cached_to >= 10 ? get_hash(d.cached_to - 10) : crypto::null<crypto::hash>;
            d.cached_distribution = distribution;
            d.cached_start_height = start_height;
            d.cached_base = base;
            d.cached = true;
        }

        return process_distribution(cumulative, start_height, std::move(distribution), base);
    }
}  // namespace detail

//------------------------------------------------------------------------------------------------------------------------------
GET_OUTPUT_DISTRIBUTION::response core_rpc_server::invoke(
        GET_OUTPUT_DISTRIBUTION::request&& req, rpc_context, bool binary) {
    GET_OUTPUT_DISTRIBUTION::response res{};
    try {
        // 0 is placeholder for the whole chain
        const uint64_t req_to_height =
                req.to_height ? req.to_height
                              : (m_core.blockchain.get_current_blockchain_height() - 1);
        for (uint64_t amount : req.amounts) {
            auto data = detail::get_output_distribution(
                    [this](auto&&... args) {
                        return m_core.blockchain.get_output_distribution(
                                std::forward<decltype(args)>(args)...);
                    },
                    amount,
                    req.from_height,
                    req_to_height,
                    [this](uint64_t height) {
                        return m_core.blockchain.db().get_block_hash_from_height(height);
                    },
                    req.cumulative,
                    m_core.blockchain.get_current_blockchain_height());
            if (!data)
                throw rpc_error{ERROR_INTERNAL, "Failed to get output distribution"};

            // Force binary & compression off if this is a JSON request because trying to pass
            // binary data through JSON explodes it in terms of size (most values under 0x20 have to
            // be encoded using 6 chars such as "\u0002").
            res.distributions.push_back(
                    {std::move(*data), amount, "", binary && req.binary, binary && req.compress});
        }
    } catch (const std::exception& e) {
        throw rpc_error{ERROR_INTERNAL, "Failed to get output distribution"};
    }

    res.status = STATUS_OK;
    return res;
}
//------------------------------------------------------------------------------------------------------------------------------
GET_OUTPUT_DISTRIBUTION_BIN::response core_rpc_server::invoke(
        GET_OUTPUT_DISTRIBUTION_BIN::request&& req, rpc_context context) {
    GET_OUTPUT_DISTRIBUTION_BIN::response res{};

    if (!req.binary) {
        res.status = "Binary only call";
        return res;
    }

    return invoke(std::move(static_cast<GET_OUTPUT_DISTRIBUTION::request&>(req)), context, true);
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(PRUNE_BLOCKCHAIN& prune_blockchain, rpc_context) {
    try {
        if (!(prune_blockchain.request.check ? m_core.blockchain.check_blockchain_pruning()
                                             : m_core.blockchain.prune_blockchain()))
            throw rpc_error{
                    ERROR_INTERNAL,
                    prune_blockchain.request.check ? "Failed to check blockchain pruning"
                                                   : "Failed to prune blockchain"};
        auto pruning_seed = m_core.blockchain.get_blockchain_pruning_seed();
        prune_blockchain.response["pruning_seed"] = pruning_seed;
        prune_blockchain.response["pruned"] = pruning_seed != 0;
    } catch (const std::exception& e) {
        throw rpc_error{ERROR_INTERNAL, "Failed to prune blockchain"};
    }

    prune_blockchain.response["status"] = STATUS_OK;
}

//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_QUORUM_STATE& get_quorum_state, rpc_context context) {
    const auto& quorum_type = get_quorum_state.request.quorum_type;

    auto is_requested_type = [&quorum_type](service_nodes::quorum_type type) {
        return !quorum_type || quorum_type == static_cast<uint8_t>(type);
    };

    bool latest = false;
    uint64_t latest_ob = 0, latest_cp = 0, latest_bl = 0;
    auto& start = get_quorum_state.request.start_height;
    auto& end = get_quorum_state.request.end_height;
    uint64_t curr_height = m_core.blockchain.get_current_blockchain_height();
    if (!start && !end) {
        latest = true;
        // Our start block for the latest quorum of each type depends on the type being requested:
        // obligations: top block
        // checkpoint: last block with height divisible by CHECKPOINT_INTERVAL (=4)
        // blink: last block with height divisible by BLINK_QUORUM_INTERVAL (=5)
        // pulse: current height (i.e. top block height + 1)
        uint64_t top_height = curr_height - 1;
        latest_ob = top_height;
        latest_cp = top_height - top_height % service_nodes::CHECKPOINT_INTERVAL;
        latest_bl = top_height - top_height % service_nodes::BLINK_QUORUM_INTERVAL;
        if (is_requested_type(service_nodes::quorum_type::checkpointing))
            start = latest_cp;
        if (is_requested_type(service_nodes::quorum_type::blink))
            start = start ? std::min(*start, latest_bl) : latest_bl;
        end = curr_height;
    } else if (!start)
        start = (*end)++;
    else if (!end)
        end = *start + 1;
    else if (*end > *start)
        ++*end;
    else if (end > 0)
        --*end;

    if (!start || *start > curr_height)
        start = curr_height;

    // We can also provide the pulse quorum for the current block being produced, so if asked for
    // that make a note.
    bool add_curr_pulse =
            (latest || end > curr_height) && is_requested_type(service_nodes::quorum_type::pulse);
    if (!end || *end > curr_height)
        end = curr_height;

    uint64_t count = (*start > *end) ? *start - *end : *end - *start;
    if (!context.admin && count > GET_QUORUM_STATE::MAX_COUNT)
        throw rpc_error{
                ERROR_WRONG_PARAM,
                "Number of requested quorums greater than the allowed limit: " +
                        std::to_string(GET_QUORUM_STATE::MAX_COUNT) +
                        ", requested: " + std::to_string(count)};

    bool at_least_one_succeeded = false;
    std::vector<GET_QUORUM_STATE::quorum_for_height> quorums;
    quorums.reserve(std::min((uint64_t)16, count));
    auto net = nettype();
    for (size_t height = *start; height < *end; height++) {
        auto hf_version = get_network_version(net, height);
        auto start_quorum_iterator = static_cast<service_nodes::quorum_type>(0);
        auto end_quorum_iterator = service_nodes::max_quorum_type_for_hf(hf_version);

        if (quorum_type) {
            start_quorum_iterator = static_cast<service_nodes::quorum_type>(*quorum_type);
            end_quorum_iterator = start_quorum_iterator;
        }

        for (int quorum_int = (int)start_quorum_iterator; quorum_int <= (int)end_quorum_iterator;
             quorum_int++) {
            auto type = static_cast<service_nodes::quorum_type>(quorum_int);
            if (latest) {  // Latest quorum requested, so skip if this is isn't the latest height
                           // for *this* quorum type
                if (type == service_nodes::quorum_type::obligations && height != latest_ob)
                    continue;
                if (type == service_nodes::quorum_type::checkpointing && height != latest_cp)
                    continue;
                if (type == service_nodes::quorum_type::blink && height != latest_bl)
                    continue;
                if (type == service_nodes::quorum_type::pulse)
                    continue;
            }
            if (std::shared_ptr<const service_nodes::quorum> quorum =
                        m_core.service_node_list.get_quorum(type, height, true /*include_old*/)) {
                auto& entry = quorums.emplace_back();
                entry.height = height;
                entry.quorum_type = static_cast<uint8_t>(quorum_int);
                entry.quorum.validators = hexify(quorum->validators);
                entry.quorum.workers = hexify(quorum->workers);

                at_least_one_succeeded = true;
            }
        }
    }

    if (auto hf_version = get_network_version(nettype(), curr_height);
        add_curr_pulse && hf_version >= hf::hf16_pulse) {
        const auto& blockchain = m_core.blockchain;
        const auto& top_header = blockchain.db().get_block_header_from_height(curr_height - 1);

        pulse::timings next_timings{};
        uint8_t pulse_round = 0;
        if (pulse::get_round_timings(blockchain, curr_height, top_header.timestamp, next_timings) &&
            pulse::convert_time_to_round(
                    nettype(), pulse::clock::now(), next_timings.r0_timestamp, &pulse_round)) {
            auto entropy =
                    service_nodes::get_pulse_entropy_for_next_block(blockchain.db(), pulse_round);
            auto& sn_list = m_core.service_node_list;
            auto quorum = generate_pulse_quorum(
                    m_core.get_nettype(),
                    sn_list.get_next_block_leader().key,
                    hf_version,
                    sn_list.active_service_nodes_infos(),
                    entropy,
                    pulse_round);
            if (verify_pulse_quorum_sizes(quorum)) {
                auto& entry = quorums.emplace_back();
                entry.height = curr_height;
                entry.quorum_type = static_cast<uint8_t>(service_nodes::quorum_type::pulse);

                entry.quorum.validators = hexify(quorum.validators);
                entry.quorum.workers = hexify(quorum.workers);

                at_least_one_succeeded = true;
            }
        }
    }

    if (!at_least_one_succeeded)
        throw rpc_error{ERROR_WRONG_PARAM, "Failed to query any quorums at all"};

    get_quorum_state.response["quorums"] = quorums;
    get_quorum_state.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(FLUSH_CACHE& flush_cache, rpc_context) {
    if (flush_cache.request.bad_txs)
        m_core.flush_bad_txs_cache();
    if (flush_cache.request.bad_blocks)
        m_core.flush_invalid_blocks();
    flush_cache.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(
        GET_SERVICE_NODE_REGISTRATION_CMD_RAW& get_service_node_registration_cmd_raw, rpc_context) {
    if (!m_core.service_node())
        throw rpc_error{
                ERROR_WRONG_PARAM,
                "Daemon has not been started in service node mode, please relaunch with "
                "--service-node flag."};

    auto hf_version =
            get_network_version(nettype(), m_core.blockchain.get_current_blockchain_height());
    std::string registration_cmd;
    if (!service_nodes::make_registration_cmd(
                m_core.get_nettype(),
                hf_version,
                get_service_node_registration_cmd_raw.request.staking_requirement,
                get_service_node_registration_cmd_raw.request.args,
                m_core.get_service_keys(),
                registration_cmd,
                get_service_node_registration_cmd_raw.request.make_friendly))
        throw rpc_error{ERROR_INTERNAL, "Failed to make registration command"};

    get_service_node_registration_cmd_raw.response["registration_cmd"] = registration_cmd;
    get_service_node_registration_cmd_raw.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(
        GET_SERVICE_NODE_REGISTRATION_CMD& get_service_node_registration_cmd, rpc_context) {
    if (!m_core.service_node())
        throw rpc_error{
                ERROR_WRONG_PARAM,
                "Daemon has not been started in service node mode, please relaunch with "
                "--service-node flag."};

    std::vector<std::string> args;

    auto height = m_core.blockchain.get_current_blockchain_height();
    auto hf_version = get_network_version(nettype(), height);
    uint64_t staking_requirement = m_core.service_node_list.get_staking_requirement();

    {
        try {
            args.emplace_back(std::to_string(service_nodes::percent_to_basis_points(
                    get_service_node_registration_cmd.request.operator_cut)));
        } catch (const std::exception& e) {
            get_service_node_registration_cmd.response["status"] = "Invalid value: "s + e.what();
            log::error(
                    logcat,
                    "{}",
                    get_service_node_registration_cmd.response["status"].get<std::string_view>());
            return;
        }
    }

    auto& addresses = get_service_node_registration_cmd.request.contributor_addresses;
    auto& amounts = get_service_node_registration_cmd.request.contributor_amounts;

    if (addresses.size() != amounts.size()) {
        throw oxen::traced<std::runtime_error>("Mismatch in sizes of addresses and amounts");
    }

    for (size_t i = 0; i < addresses.size(); ++i) {
        args.push_back(addresses[i]);
        args.push_back(std::to_string(amounts[i]));
    }

    std::string registration_cmd;
    if (!service_nodes::make_registration_cmd(
                m_core.get_nettype(),
                hf_version,
                staking_requirement,
                args,
                m_core.get_service_keys(),
                registration_cmd,
                false /*Make friendly*/))
        throw rpc_error{ERROR_INTERNAL, "Failed to make registration command"};

    get_service_node_registration_cmd.response["registration_cmd"] = registration_cmd;
    get_service_node_registration_cmd.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(
        GET_SERVICE_NODE_BLACKLISTED_KEY_IMAGES& get_service_node_blacklisted_key_images,
        rpc_context) {
    auto& blacklist = m_core.service_node_list.get_blacklisted_key_images();

    get_service_node_blacklisted_key_images.response["status"] = STATUS_OK;
    get_service_node_blacklisted_key_images.response["blacklist"] = blacklist;
}

void set_contract_signature(
        nlohmann::json& response,
        tools::json_binary_proxy& response_hex,
        const eth::bls_aggregate_signed& sig,
        eth::L2Tracker& l2_tracker) {
    response_hex["msg_to_sign"] = std::string_view(
            reinterpret_cast<const char*>(sig.msg_to_sign.data()), sig.msg_to_sign.size());
    response_hex["signature"] = sig.signature;
    response["non_signer_indices"] = l2_tracker.get_non_signers(
            sig.signers_bls_pubkeys.begin(), sig.signers_bls_pubkeys.end());
}

//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(BLS_REWARDS_REQUEST& rpc, rpc_context) {
    try {
        if (!m_core.have_l2_tracker())
            throw std::invalid_argument{
                    "Unable to process request: this RPC node is not configured with an ETH L2 "
                    "provider"};

        if (rpc.request.height <= 0)
            rpc.request.height += m_core.blockchain.get_current_blockchain_height() - 1;

        const auto response = m_core.bls_rewards_request(
                rpc.request.address, static_cast<uint64_t>(rpc.request.height));
        set_contract_signature(rpc.response, rpc.response_hex, response, m_core.l2_tracker());
        rpc.response["status"] = STATUS_OK;
        rpc.response["address"] = "{}"_format(response.addr);
        rpc.response["amount"] = response.amount;
        rpc.response["height"] = response.height;
    } catch (const std::exception& e) {
        throw rpc_error{ERROR_BLS_SIG, e.what()};
    }
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(BLS_EXIT_LIQUIDATION_LIST& rpc, rpc_context) {
    auto list = nlohmann::json::array();
    using node_t = service_nodes::service_node_list::recently_removed_node;
    m_core.service_node_list.for_each_recently_removed_node([&list](const node_t& elem) {
        // NOTE: Serialise to JSON
        serialization::json_archiver ar;
        serialize(ar, const_cast<node_t&>(elem));
        nlohmann::json serialized = std::move(ar).json();
        nlohmann::json& sn_info = serialized["info"];

        // NOTE: Remove implementation details from the contributor JSON
        for (auto& contrib_it : sn_info["contributors"]) {
            constexpr std::string_view ERASE_FIELDS_CONTRIBUTOR[] = {
                    "address",  // Cryptonote address  (not used in L2, use ETH addresses)
                    "locked_contributions",  // $OXEN contributions (not used in L2, use $SENT)
            };

            for (const auto& field : ERASE_FIELDS_CONTRIBUTOR) {
                auto it = contrib_it.find(field);
                assert(it != contrib_it.end());
                contrib_it.erase(it);
            }

            // NOTE: Remove operator cryptonote address and replace with ethereum address
            rename_key(contrib_it, "ethereum_address", "address");
        }

        // NOTE: Remove operator cryptonote address and replace with ethereum address
        rename_key(sn_info, "operator_ethereum_address", "operator_address");

        // NOTE: Remove implementation details from the output JSON
        constexpr std::string_view ERASE_FIELDS[] = {
                "public_ip",
                "qnet_port",
                "type",
        };

        for (const auto& field : ERASE_FIELDS) {
            auto it = serialized.find(field);
            assert(it != serialized.end());
            serialized.erase(it);
        }

        // NOTE: Assign the type
        switch (elem.type) {
            case node_t::type_t::voluntary_exit: serialized["type"] = "exit"; break;
            case node_t::type_t::deregister: serialized["type"] = "deregister"; break;
            case node_t::type_t::purged:
                assert(!"Internal error: found invalid purged node in recently_removed_nodes");
        }

        // NOTE: Store the object into the RPC response array
        list.push_back(std::move(serialized));
    });

    rpc.response = std::move(list);
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(BLS_EXIT_LIQUIDATION_REQUEST& rpc, rpc_context) {
    try {
        if (!m_core.have_l2_tracker())
            throw std::invalid_argument{
                    "Unable to process request: this RPC node is not configured with an ETH L2 "
                    "provider"};

        const auto response =
                m_core.bls_exit_liquidation_request(rpc.request.pubkey, rpc.request.liquidate);
        set_contract_signature(rpc.response, rpc.response_hex, response, m_core.l2_tracker());
        rpc.response["status"] = STATUS_OK;
        rpc.response["timestamp"] = response.timestamp;
        rpc.response_hex["bls_pubkey"] = response.remove_pubkey;
    } catch (const std::exception& e) {
        throw rpc_error{ERROR_BLS_SIG, e.what()};
    }
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(BLS_REGISTRATION_REQUEST& rpc, rpc_context) {
    const auto response = m_core.bls_registration(rpc.request.address);
    rpc.response["status"] = STATUS_OK;
    rpc.response["address"] = "{}"_format(response.addr);
    rpc.response_hex["bls_pubkey"] = response.bls_pubkey;
    rpc.response_hex["proof_of_possession"] = response.proof_of_possession;
    rpc.response_hex["service_node_pubkey"] = response.sn_pubkey;
    rpc.response_hex["service_node_signature"] = response.ed_signature;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_SERVICE_KEYS& get_service_keys, rpc_context) {
    const auto& keys = m_core.get_service_keys();
    if (keys.pub)
        get_service_keys.response_hex["service_node_pubkey"] = keys.pub;
    get_service_keys.response_hex["service_node_ed25519_pubkey"] = keys.pub_ed25519;
    get_service_keys.response_hex["service_node_x25519_pubkey"] = keys.pub_x25519;
    if (keys.pub_bls)
        get_service_keys.response_hex["service_node_bls_pubkey"] = keys.pub_bls;
    get_service_keys.response["is_service_node"] = m_core.service_node();
    get_service_keys.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_SERVICE_PRIVKEYS& get_service_privkeys, rpc_context) {
    const auto& keys = m_core.get_service_keys();
    if (keys.key)
        get_service_privkeys.response_hex["service_node_privkey"] =
                tools::view_guts<std::byte>(keys.key);
    get_service_privkeys.response_hex["service_node_ed25519_privkey"] =
            tools::view_guts<std::byte>(keys.key_ed25519);
    get_service_privkeys.response_hex["service_node_x25519_privkey"] =
            tools::view_guts<std::byte>(keys.key_x25519);
    get_service_privkeys.response["status"] = STATUS_OK;
}

static time_t reachable_to_time_t(
        std::chrono::steady_clock::time_point t,
        std::chrono::system_clock::time_point system_now,
        std::chrono::steady_clock::time_point steady_now) {
    if (t == service_nodes::NEVER)
        return 0;
    return std::chrono::system_clock::to_time_t(
            std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    system_now + (t - steady_now)));
}

static bool requested(const std::unordered_set<std::string>& requested, const std::string& key) {
    return requested.empty() ||
           (requested.count("all") ? !requested.count("-" + key) : requested.count(key));
}

template <typename Dict, typename T, typename... More>
static void set_if_requested(
        const std::unordered_set<std::string>& reqed,
        Dict& dict,
        const std::string& key,
        T&& value,
        More&&... more) {
    if (requested(reqed, key))
        dict[key] = std::forward<T>(value);
    if constexpr (sizeof...(More) > 0)
        set_if_requested(reqed, dict, std::forward<More>(more)...);
}

//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::fill_sn_response_entry(
        json& entry,
        bool is_bt,
        const std::unordered_set<std::string>& reqed,
        const service_nodes::service_node_pubkey_info& sn_info,
        uint64_t top_height) {

    auto binary_format = is_bt ? json_binary_proxy::fmt::bt : json_binary_proxy::fmt::hex;
    json_binary_proxy binary{entry, binary_format};

    const auto& info = *sn_info.info;
    set_if_requested(reqed, binary, "service_node_pubkey", sn_info.pubkey);
    if (info.bls_public_key) {
        set_if_requested(reqed, binary, "pubkey_bls", info.bls_public_key);
        // FIXME: these calls are failing, but also we can't do this in the middle of an rpc
        // request, so we either need to pre-cache the info, or else just leave it off (and you can
        // fetch it via arbitrum calls instead).
        /*
        set_if_requested(
                reqed,
                entry,
                "is_removable",
                m_core.is_node_removable(info.bls_public_key),
                "is_liquidatable",
                m_core.is_node_liquidatable(info.bls_public_key));
        */
    }
    set_if_requested(
            reqed,
            entry,
            "registration_height",
            info.registration_height,
            "requested_unlock_height",
            info.requested_unlock_height,
            "last_reward_block_height",
            info.last_reward_block_height,
            "last_reward_transaction_index",
            info.last_reward_transaction_index,
            "active",
            info.is_active(),
            "payable",
            info.is_payable(top_height, nettype()),
            "funded",
            info.is_fully_funded(),
            "state_height",
            info.is_fully_funded() ? (info.is_decommissioned() ? info.last_decommission_height
                                                               : info.active_since_height)
                                   : info.last_reward_block_height,
            "earned_downtime_blocks",
            service_nodes::quorum_cop::calculate_decommission_credit(nettype(), info, top_height),
            "decommission_count",
            info.decommission_count,
            "total_contributed",
            info.total_contributed,
            "staking_requirement",
            info.staking_requirement,
            "portions_for_operator",
            info.portions_for_operator,
            "operator_fee",
            microportion(info.portions_for_operator),
            "swarm_id",
            info.swarm_id,
            "swarm",
            "{:x}"_format(info.swarm_id),
            "registration_hf_version",
            info.registration_hf_version);

    if (requested(reqed, "operator_address")) {
        if (info.operator_ethereum_address)
            entry["operator_address"] = "{}"_format(info.operator_ethereum_address);
        else
            entry["operator_address"] = cryptonote::get_account_address_as_str(
                    m_core.get_nettype(), false /*subaddress*/, info.operator_address);
    }

    if (requested(reqed, "total_reserved") && info.total_reserved != info.total_contributed)
        entry["total_reserved"] = info.total_reserved;

    if (info.last_decommission_reason_consensus_any) {
        set_if_requested(
                reqed,
                entry,
                "last_decommission_reason_consensus_all",
                info.last_decommission_reason_consensus_all,
                "last_decommission_reason_consensus_any",
                info.last_decommission_reason_consensus_any);

        if (requested(reqed, "last_decomm_reasons")) {
            auto& reasons =
                    (entry["last_decomm_reasons"] =
                             json{{"all",
                                   cryptonote::coded_reasons(
                                           info.last_decommission_reason_consensus_all)}});
            if (auto some = cryptonote::coded_reasons(
                        info.last_decommission_reason_consensus_any &
                        ~info.last_decommission_reason_consensus_all);
                !some.empty())
                reasons["some"] = std::move(some);
        }
    }

    auto& netconf = m_core.get_net_config();
    auto [hf, snode_rev] = get_network_version_revision(nettype(), top_height);

    if (hf >= feature::SN_PK_IS_ED25519) {
        set_if_requested(reqed, binary, "pubkey_ed25519", sn_info.pubkey);

        if (requested(reqed, "pubkey_x25519"))
            binary["pubkey_x25519"] = service_nodes::snpk_to_xpk(sn_info.pubkey);
    }

    // FIXME: accessing proofs one-by-one like this is kind of gross.
    m_core.service_node_list.access_proof(sn_info.pubkey, [&](const auto& proof) {
        if (m_core.service_node() && m_core.get_service_keys().pub == sn_info.pubkey) {
            // When returning our own info we always want to return the most current data because
            // the data from the SN list could be stale (it only gets updated when we get
            // verification of acceptance of our proof from the network).  The rest of the network
            // might not get the updated data until the next proof, but local callers like SS and
            // Lokinet want it updated immediately.
            set_if_requested(
                    reqed,
                    entry,
                    "service_node_version",
                    OXEN_VERSION,
                    "lokinet_version",
                    m_core.lokinet_version,
                    "storage_server_version",
                    m_core.ss_version,
                    "public_ip",
                    epee::string_tools::get_ip_string_from_int32(m_core.sn_public_ip()),
                    "storage_port",
                    m_core.storage_https_port(),
                    "storage_lmq_port",
                    m_core.storage_omq_port(),
                    "quorumnet_port",
                    m_core.quorumnet_port());
            set_if_requested(
                    reqed,
                    binary,
                    "pubkey_ed25519",
                    m_core.get_service_keys().pub_ed25519,
                    "pubkey_x25519",
                    m_core.get_service_keys().pub_x25519);
            set_if_requested(reqed, binary, "pubkey_bls", m_core.get_service_keys().pub_bls);
        } else {
            if (proof.proof->public_ip != 0)
                set_if_requested(
                        reqed,
                        entry,
                        "service_node_version",
                        proof.proof->version,
                        "lokinet_version",
                        proof.proof->lokinet_version,
                        "storage_server_version",
                        proof.proof->storage_server_version,
                        "public_ip",
                        epee::string_tools::get_ip_string_from_int32(proof.proof->public_ip),
                        "storage_port",
                        proof.proof->storage_https_port,
                        "storage_lmq_port",
                        proof.proof->storage_omq_port,
                        "quorumnet_port",
                        proof.proof->qnet_port);
            if (hf < feature::SN_PK_IS_ED25519 && proof.proof->pubkey_ed25519)
                set_if_requested(
                        reqed,
                        binary,
                        "pubkey_ed25519",
                        proof.proof->pubkey_ed25519,
                        "pubkey_x25519",
                        proof.pubkey_x25519);
            // During HF20 the BLS pubkey isn't in info, but is in the proof:
            if (info.bls_public_key) {
                set_if_requested(reqed, binary, "pubkey_bls", info.bls_public_key);
            } else if (proof.proof->pubkey_bls) {
                set_if_requested(reqed, binary, "pubkey_bls", proof.proof->pubkey_bls);
            }
        }

        auto system_now = std::chrono::system_clock::now();
        auto steady_now = std::chrono::steady_clock::now();
        set_if_requested(reqed, entry, "last_uptime_proof", proof.timestamp);
        if (m_core.service_node()) {
            set_if_requested(
                    reqed,
                    entry,
                    "storage_server_reachable",
                    !proof.ss_reachable.unreachable_for(
                            netconf.UPTIME_PROOF_VALIDITY - netconf.UPTIME_PROOF_FREQUENCY,
                            steady_now),
                    "lokinet_reachable",
                    !proof.lokinet_reachable.unreachable_for(
                            netconf.UPTIME_PROOF_VALIDITY - netconf.UPTIME_PROOF_FREQUENCY,
                            steady_now));
            if (proof.ss_reachable.first_unreachable != service_nodes::NEVER &&
                requested(reqed, "storage_server_first_unreachable"))
                entry["storage_server_first_unreachable"] = reachable_to_time_t(
                        proof.ss_reachable.first_unreachable, system_now, steady_now);
            if (proof.ss_reachable.last_unreachable != service_nodes::NEVER &&
                requested(reqed, "storage_server_last_unreachable"))
                entry["storage_server_last_unreachable"] = reachable_to_time_t(
                        proof.ss_reachable.last_unreachable, system_now, steady_now);
            if (proof.ss_reachable.last_reachable != service_nodes::NEVER &&
                requested(reqed, "storage_server_last_reachable"))
                entry["storage_server_last_reachable"] = reachable_to_time_t(
                        proof.ss_reachable.last_reachable, system_now, steady_now);
            if (proof.lokinet_reachable.first_unreachable != service_nodes::NEVER &&
                requested(reqed, "lokinet_first_unreachable"))
                entry["lokinet_first_unreachable"] = reachable_to_time_t(
                        proof.lokinet_reachable.first_unreachable, system_now, steady_now);
            if (proof.lokinet_reachable.last_unreachable != service_nodes::NEVER &&
                requested(reqed, "lokinet_last_unreachable"))
                entry["lokinet_last_unreachable"] = reachable_to_time_t(
                        proof.lokinet_reachable.last_unreachable, system_now, steady_now);
            if (proof.lokinet_reachable.last_reachable != service_nodes::NEVER &&
                requested(reqed, "lokinet_last_reachable"))
                entry["lokinet_last_reachable"] = reachable_to_time_t(
                        proof.lokinet_reachable.last_reachable, system_now, steady_now);
        }

        if (requested(reqed, "checkpoint_votes") && !proof.checkpoint_participation.empty()) {
            std::vector<uint64_t> voted, missed;
            for (auto& cpp : proof.checkpoint_participation)
                (cpp.pass() ? voted : missed).push_back(cpp.height);
            std::sort(voted.begin(), voted.end());
            std::sort(missed.begin(), missed.end());
            entry["checkpoint_votes"] = json{{"voted", voted}, {"missed", missed}};
        }
        if (requested(reqed, "pulse_votes") && !proof.pulse_participation.empty()) {
            std::vector<std::pair<uint64_t, uint8_t>> voted, missed;
            for (auto& ppp : proof.pulse_participation)
                (ppp.pass() ? voted : missed).emplace_back(ppp.height, ppp.round);
            std::sort(voted.begin(), voted.end());
            std::sort(missed.begin(), missed.end());
            entry["pulse_votes"]["voted"] = voted;
            entry["pulse_votes"]["missed"] = missed;
        }
        if (requested(reqed, "quorumnet_tests") && !proof.timestamp_participation.empty()) {
            auto fails = proof.timestamp_participation.failures();
            entry["quorumnet_tests"] =
                    json::array({proof.timestamp_participation.size() - fails, fails});
        }
        if (requested(reqed, "timesync_tests") && !proof.timesync_status.empty()) {
            auto fails = proof.timesync_status.failures();
            entry["timesync_tests"] = json::array({proof.timesync_status.size() - fails, fails});
        }
    });

    if (requested(reqed, "contributors")) {
        bool want_locked_c = requested(reqed, "locked_contributions");
        auto& contributors = (entry["contributors"] = json::array());
        for (const auto& contributor : info.contributors) {
            auto& c = contributors.emplace_back(json{{"amount", contributor.amount}});
            if (contributor.ethereum_address) {
                c["address"] = "{}"_format(contributor.ethereum_address);
                c["beneficiary"] = "{}"_format(contributor.ethereum_beneficiary);
            } else
                c["address"] = cryptonote::get_account_address_as_str(
                        m_core.get_nettype(), false /*subaddress*/, contributor.address);
            if (contributor.reserved != contributor.amount)
                c["reserved"] = contributor.reserved;
            if (want_locked_c) {
                auto& locked = (c["locked_contributions"] = json::array());
                for (const auto& src : contributor.locked_contributions) {
                    auto& lc = locked.emplace_back(json{{"amount", src.amount}});
                    json_binary_proxy lc_binary{lc, binary_format};
                    lc_binary["key_image"] = src.key_image;
                    lc_binary["key_image_pub_key"] = src.key_image_pub_key;
                }
            }
        }
    }
}

//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_SERVICE_NODES& sns, rpc_context) {
    auto& req = sns.request;
    sns.response["status"] = STATUS_OK;
    auto [top_height, top_hash] = m_core.blockchain.get_tail_id();
    auto [hf, snode_rev] = get_network_version_revision(nettype(), top_height);
    set_if_requested(
            req.fields,
            sns.response,
            "height",
            top_height,
            "target_height",
            m_core.get_target_blockchain_height(),
            "hardfork",
            hf,
            "snode_revision",
            snode_rev);
    set_if_requested(req.fields, sns.response_hex, "block_hash", top_hash);

    if (req.poll_block_hash) {
        bool unchanged = req.poll_block_hash == top_hash;
        sns.response["unchanged"] = unchanged;
        if (unchanged)
            return;
        if (!requested(req.fields, "block_hash"))
            sns.response_hex["block_hash"] =
                    top_hash;  // Force it on a poll request even if it wasn't a requested field
    }

    auto sn_infos = m_core.service_node_list.get_service_node_list_state(req.service_node_pubkeys);

    if (req.active_only)
        sn_infos.erase(
                std::remove_if(
                        sn_infos.begin(),
                        sn_infos.end(),
                        [](const service_nodes::service_node_pubkey_info& snpk_info) {
                            return !snpk_info.info->is_active();
                        }),
                sn_infos.end());

    const int top_sn_index = (int)sn_infos.size() - 1;
    if (req.limit < 0 || req.limit > top_sn_index) {
        // We asked for -1 (no limit but shuffle) or a value >= the count, so just shuffle the
        // entire list
        std::shuffle(sn_infos.begin(), sn_infos.end(), tools::rng);
    } else if (req.limit > 0) {
        // We need to select N random elements, in random order, from yyyyyyyy.  We could (and used
        // to) just shuffle the entire list and return the first N, but that is quite inefficient
        // when the list is large and N is small.  So instead this algorithm is going to select a
        // random element from yyyyyyyy, swap it to position 0, so we get: [x]yyyyyyyy where one of
        // the new y's used to be at element 0.  Then we select a random element from the new y's
        // (i.e. all the elements beginning at position 1), and swap it into element 1, to get
        // [xx]yyyyyy, then keep repeating until our set of x's is big enough, say [xxx]yyyyy.  At
        // that point we chop of the y's to just be left with [xxx], and only required N swaps in
        // total.
        for (int i = 0; i < req.limit; i++) {
            int j = std::uniform_int_distribution<int>{i, top_sn_index}(tools::rng);
            using std::swap;
            if (i != j)
                swap(sn_infos[i], sn_infos[j]);
        }

        sn_infos.resize(req.limit);
    }

    auto& sn_states = (sns.response["service_node_states"] = json::array());
    for (auto& pubkey_info : sn_infos)
        fill_sn_response_entry(
                sn_states.emplace_back(json::object()),
                sns.is_bt(),
                req.fields,
                pubkey_info,
                top_height);
}

//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_PENDING_EVENTS& sns, rpc_context) {
    sns.response["status"] = STATUS_OK;

    sns.response["registrations"] = json::array();
    sns.response["unlocks"] = json::array();
    sns.response["exits"] = json::array();
    m_core.service_node_list.for_each_pending_l2_state([&sns]<typename Event>(
                                                               const Event& e, const auto& info) {
        json entry{
                {"l2_height", e.l2_height},
                {"chain_id", e.chain_id},
                {"height", info.height_added},
                {"confirmations", info.confirmations / (double)info.FULL_SCORE},
                {"denials", info.denials / (double)info.FULL_SCORE},
                {"required",
                 (std::max(info.denials * 2, info.denials + 5 * info.FULL_SCORE) -
                  info.confirmations) /
                         (double)info.FULL_SCORE}};

        if constexpr (std::is_same_v<Event, eth::event::NewServiceNodeV2>) {
            sns.response["registrations"].push_back(std::move(entry));
            auto& res = sns.response["registrations"].back();
            auto res_hex = sns.response_hex["registrations"].back();
            res_hex["sn_pubkey"] = e.sn_pubkey;
            res_hex["bls_pubkey"] = e.bls_pubkey;
            res_hex["signature"] = e.ed_signature;
            res["fee"] = e.fee * 0.01;
            res["contributors"] = json::array();
            auto& contr = res["contributors"];
            for (const auto& it : e.contributors)
                contr.push_back(json{
                        {"amount", it.amount},
                        {"address", "{}"_format(it.address)},
                        {"beneficiary", "{}"_format(it.beneficiary)},
                });
        } else if constexpr (std::is_same_v<Event, eth::event::ServiceNodeExitRequest>) {
            sns.response["unlocks"].push_back(std::move(entry));
            sns.response_hex["unlocks"].back()["bls_pubkey"] = e.bls_pubkey;
        } else if constexpr (std::is_same_v<Event, eth::event::ServiceNodeExit>) {
            sns.response["exits"].push_back(std::move(entry));
            sns.response_hex["exits"].back()["bls_pubkey"] = e.bls_pubkey;
            sns.response["returned_amount"] = e.returned_amount;
        } else {
            log::error(logcat, "Got unknown event type in rpc GET_PENDING_EVENTS handler!");
        }
    });
}

namespace {
    // Handles a ping.  Returns true if the ping was significant (i.e. first ping after startup, or
    // after the ping had expired).  `Success` is a callback that is invoked with a single boolean
    // argument: true if this ping should trigger an immediate proof send (i.e. first ping after
    // startup or after a ping expiry), false for an ordinary ping.
    template <typename Success>
    std::string handle_ping(
            core& core,
            std::array<uint16_t, 3> cur_version,
            std::array<uint16_t, 3> required,
            std::string_view ed25519_pubkey,
            std::string_view error,
            std::string_view name,
            std::atomic<std::time_t>& update,
            std::chrono::seconds lifetime,
            Success success) {
        std::string status{};
        std::string our_ed25519_pubkey = tools::hex_guts(core.get_service_keys().pub_ed25519);
        if (!error.empty()) {
            status = fmt::format("Error: {}", error);
            log::error(
                    logcat,
                    "{0} reported an error: {1}. Check {0} logs for more details.",
                    name,
                    error);
            update = 0;  // Reset our last ping time to 0 so that we won't send a ping until we get
                         // success back again (even if we had an earlier acceptable ping within the
                         // cutoff time).
        } else if (cur_version < required) {
            status = "Outdated {}. Current: {} Required: {}"_format(
                    name, fmt::join(cur_version, "."), fmt::join(required, "."));
            log::error(logcat, "{}", status);
        } else if (ed25519_pubkey != our_ed25519_pubkey) {
            status = "Invalid {} pubkey: expected {}, received {}"_format(
                    name, our_ed25519_pubkey, ed25519_pubkey);
            log::error(logcat, "{}", status);
        } else {
            auto now = std::time(nullptr);
            auto old = update.exchange(now);
            bool significant = std::chrono::seconds{now - old} >
                               lifetime;  // Print loudly for the first ping after startup/expiry
            auto msg = "Received ping from {} {}"_format(name, fmt::join(cur_version, "."));
            if (significant)
                log::info(
                        globallogcat,
                        fg(fmt::terminal_color::green) | fmt::emphasis::bold,
                        "{}",
                        msg);
            else
                log::debug(logcat, "{}", msg);
            success(significant);
            status = STATUS_OK;
        }
        return status;
    }
}  // namespace

//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(STORAGE_SERVER_PING& storage_server_ping, rpc_context) {
    m_core.ss_version = storage_server_ping.request.version;
    storage_server_ping.response["status"] = handle_ping(
            m_core,
            storage_server_ping.request.version,
            service_nodes::MIN_STORAGE_SERVER_VERSION,
            storage_server_ping.request.pubkey_ed25519,
            storage_server_ping.request.error,
            "Storage Server",
            m_core.m_last_storage_server_ping,
            m_core.get_net_config().UPTIME_PROOF_FREQUENCY,
            [this, &storage_server_ping](bool significant) {
                m_core.m_storage_https_port = storage_server_ping.request.https_port;
                m_core.m_storage_omq_port = storage_server_ping.request.omq_port;
                if (significant)
                    m_core.reset_proof_interval();
            });
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(LOKINET_PING& lokinet_ping, rpc_context) {
    m_core.lokinet_version = lokinet_ping.request.version;
    lokinet_ping.response["status"] = handle_ping(
            m_core,
            lokinet_ping.request.version,
            service_nodes::MIN_LOKINET_VERSION,
            lokinet_ping.request.pubkey_ed25519,
            lokinet_ping.request.error,
            "Lokinet",
            m_core.m_last_lokinet_ping,
            m_core.get_net_config().UPTIME_PROOF_FREQUENCY,
            [this](bool significant) {
                if (significant)
                    m_core.reset_proof_interval();
            });
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_STAKING_REQUIREMENT& get, rpc_context) {
    get.response = {
            {"height", m_core.blockchain.get_current_blockchain_height()},
            {"staking_requirement", m_core.service_node_list.get_staking_requirement()},
            {"status", STATUS_OK}};
    return;
}

template <typename T>
static void check_quantity_limit(T count, T max, const char* container_name = "input") {
    if (count > max)
        throw rpc_error{
                ERROR_WRONG_PARAM,
                "Number of requested entries ({}) in {} is greater than the allowed limit ({})"_format(
                        count, container_name, max)};
}

template <typename T>
static void check_quantity_limit(std::optional<T> count, T max, const char* name = "input") {
    if (count)
        check_quantity_limit(*count, max, name);
}

//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_CHECKPOINTS& get_checkpoints, rpc_context context) {
    if (!context.admin)
        check_quantity_limit(get_checkpoints.request.count, GET_CHECKPOINTS::MAX_COUNT);

    auto& start = get_checkpoints.request.start_height;
    auto& end = get_checkpoints.request.end_height;
    auto count = get_checkpoints.request.count.value_or(
            GET_CHECKPOINTS::NUM_CHECKPOINTS_TO_QUERY_BY_DEFAULT);

    get_checkpoints.response["status"] = STATUS_OK;
    const auto& db = m_core.blockchain.db();

    std::vector<checkpoint_t> checkpoints;
    if (!start && !end) {
        if (checkpoint_t top_checkpoint; db.get_top_checkpoint(top_checkpoint))
            checkpoints = db.get_checkpoints_range(top_checkpoint.height, 0, count);
    } else if (!start)
        checkpoints = db.get_checkpoints_range(*end, 0, count);
    else if (!end)
        checkpoints = db.get_checkpoints_range(*start, UINT64_MAX, count);
    else
        checkpoints = context.admin
                            ? db.get_checkpoints_range(*start, *end)
                            : db.get_checkpoints_range(*start, *end, GET_CHECKPOINTS::MAX_COUNT);

    get_checkpoints.response["checkpoints"] = std::move(checkpoints);
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(GET_SN_STATE_CHANGES& get_sn_state_changes, rpc_context) {
    using blob_t = std::string;
    using block_pair_t = std::pair<blob_t, block>;
    std::vector<block_pair_t> blocks;

    const auto& db = m_core.blockchain;

    auto start_height = get_sn_state_changes.request.start_height;
    auto end_height = get_sn_state_changes.request.end_height.value_or(
            db.get_current_blockchain_height() - 1);

    if (end_height < start_height)
        throw rpc_error{
                ERROR_WRONG_PARAM, "The provided end_height needs to be higher than start_height"};

    if (!db.get_blocks(start_height, end_height - start_height + 1, blocks))
        throw rpc_error{
                ERROR_INTERNAL,
                "Could not query blocks at requested height {}"_format(start_height)};

    get_sn_state_changes.response["start_height"] = start_height;
    get_sn_state_changes.response["end_height"] = end_height;

    std::vector<blob_t> blobs;
    int total_deregister = 0, total_decommission = 0, total_recommission = 0,
        total_ip_change_penalty = 0, total_unlock = 0;
    for (const auto& block : blocks) {
        blobs.clear();
        if (!db.get_transactions_blobs(block.second.tx_hashes, blobs)) {
            log::error(
                    logcat,
                    "Could not query block at requested height: {}",
                    block.second.get_height());
            continue;
        }
        const auto hard_fork_version = block.second.major_version;
        for (const auto& blob : blobs) {
            cryptonote::transaction tx;
            if (!cryptonote::parse_and_validate_tx_from_blob(blob, tx)) {
                log::error(
                        logcat, "tx could not be validated from blob, possibly corrupt blockchain");
                continue;
            }
            if (tx.type == cryptonote::txtype::state_change) {
                cryptonote::tx_extra_service_node_state_change state_change;
                if (!cryptonote::get_service_node_state_change_from_tx_extra(
                            tx.extra, state_change, hard_fork_version)) {
                    log::error(
                            logcat,
                            "Could not get state change from tx, possibly corrupt tx, hf_version "
                            "{}",
                            static_cast<int>(hard_fork_version));
                    continue;
                }

                switch (state_change.state) {
                    case service_nodes::new_state::deregister: total_deregister++; break;

                    case service_nodes::new_state::decommission: total_decommission++; break;

                    case service_nodes::new_state::recommission: total_recommission++; break;

                    case service_nodes::new_state::ip_change_penalty:
                        total_ip_change_penalty++;
                        break;

                    default:
                        log::error(logcat, "Unhandled state in on_get_service_nodes_state_changes");
                        break;
                }
            }

            if (tx.type == cryptonote::txtype::key_image_unlock) {
                total_unlock++;
            }
        }
    }

    get_sn_state_changes.response["total_deregister"] = total_deregister;
    get_sn_state_changes.response["total_decommission"] = total_decommission;
    get_sn_state_changes.response["total_recommission"] = total_recommission;
    get_sn_state_changes.response["total_ip_change_penalty"] = total_ip_change_penalty;
    get_sn_state_changes.response["total_unlock"] = total_unlock;
    get_sn_state_changes.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(REPORT_PEER_STATUS& report_peer_status, rpc_context) {
    crypto::public_key pubkey;
    if (!tools::try_load_from_hex_guts(report_peer_status.request.pubkey, pubkey)) {
        log::error(logcat, "Could not parse public key: {}", report_peer_status.request.pubkey);
        throw rpc_error{ERROR_WRONG_PARAM, "Could not parse public key"};
    }

    bool success = false;
    if (report_peer_status.request.type == "lokinet")
        success = m_core.service_node_list.set_lokinet_peer_reachable(
                pubkey, report_peer_status.request.passed);
    else if (
            report_peer_status.request.type == "storage" ||
            report_peer_status.request.type ==
                    "reachability" /* TODO: old name, can be removed once SS no longer uses it */)
        success = m_core.service_node_list.set_storage_server_peer_reachable(
                pubkey, report_peer_status.request.passed);
    else
        throw rpc_error{ERROR_WRONG_PARAM, "Unknown status type"};
    if (!success)
        throw rpc_error{ERROR_WRONG_PARAM, "Pubkey not found"};

    report_peer_status.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(TEST_TRIGGER_P2P_RESYNC& test_trigger_p2p_resync, rpc_context) {
    m_p2p.reset_peer_handshake_timer();
    test_trigger_p2p_resync.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(TEST_TRIGGER_UPTIME_PROOF& test_trigger_uptime_proof, rpc_context) {
    if (m_core.get_nettype() != cryptonote::network_type::MAINNET)
        m_core.submit_uptime_proof();

    test_trigger_uptime_proof.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(ONS_NAMES_TO_OWNERS& ons_names_to_owners, rpc_context context) {

    if (!context.admin) {
        check_quantity_limit(
                ons_names_to_owners.request.name_hash.size(),
                ONS_NAMES_TO_OWNERS::MAX_REQUEST_ENTRIES);
        check_quantity_limit(
                ons_names_to_owners.request.type.size(),
                ONS_NAMES_TO_OWNERS::MAX_TYPE_REQUEST_ENTRIES,
                "types");
    }

    std::optional<uint64_t> height = m_core.blockchain.get_current_blockchain_height();
    std::vector<ons::mapping_type> types;
    types.clear();
    if (types.capacity() < ons_names_to_owners.request.type.size())
        types.reserve(ons_names_to_owners.request.type.size());
    for (const auto type_str : ons_names_to_owners.request.type) {
        const auto maybe_type = ons::parse_ons_type(type_str);
        if (!maybe_type.has_value()) {
            ons_names_to_owners.response["status"] = "invalid type provided";
            return;
        }
        types.push_back(*maybe_type);
    }
    ons_names_to_owners.response["type"] = ons_names_to_owners.request.type;

    auto binary_format =
            ons_names_to_owners.is_bt() ? json_binary_proxy::fmt::bt : json_binary_proxy::fmt::hex;

    ons::name_system_db& db = m_core.blockchain.name_system_db();
    for (size_t request_index = 0; request_index < ons_names_to_owners.request.name_hash.size();
         request_index++) {
        const auto& request = ons_names_to_owners.request.name_hash[request_index];
        // This also takes 32 raw bytes, but that is undocumented (because it is painful to pass
        // through json).
        auto name_hash = ons::name_hash_input_to_base64(request);
        if (!name_hash)
            throw rpc_error{
                    ERROR_WRONG_PARAM,
                    "Invalid name_hash: expected hash as 64 hex digits or 43/44 base64 characters"};

        std::vector<ons::mapping_record> record = db.get_mappings(types, *name_hash, height);
        for (size_t type_index = 0; type_index < ons_names_to_owners.request.type.size();
             type_index++) {
            auto& elem = ons_names_to_owners.response["result"].emplace_back();
            elem["type"] = record[type_index].type;
            elem["name_hash"] = record[type_index].name_hash;
            elem["owner"] = record[type_index].owner.to_string(nettype());
            if (record[type_index].backup_owner)
                elem["backup_owner"] = record[type_index].backup_owner.to_string(nettype());

            json_binary_proxy elem_hex{elem, binary_format};
            elem_hex["encrypted_value"] = record[type_index].encrypted_value.to_view();
            if (record[0].expiration_height)
                elem["expiration_height"] = *(record[type_index].expiration_height);
            elem["update_height"] = record[type_index].update_height;
            elem_hex["txid"] = record[type_index].txid;
        }
    }

    ons_names_to_owners.response["status"] = STATUS_OK;
}
//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(ONS_OWNERS_TO_NAMES& ons_owners_to_names, rpc_context context) {
    if (!context.admin)
        check_quantity_limit(
                ons_owners_to_names.request.entries.size(),
                ONS_OWNERS_TO_NAMES::MAX_REQUEST_ENTRIES);

    std::unordered_map<ons::generic_owner, size_t> owner_to_request_index;
    std::vector<ons::generic_owner> owners;

    owners.reserve(ons_owners_to_names.request.entries.size());
    for (size_t request_index = 0; request_index < ons_owners_to_names.request.entries.size();
         request_index++) {
        std::string const& owner = ons_owners_to_names.request.entries[request_index];
        ons::generic_owner ons_owner = {};
        std::string errmsg;
        if (!ons::parse_owner_to_generic_owner(m_core.get_nettype(), owner, ons_owner, &errmsg))
            throw rpc_error{ERROR_WRONG_PARAM, std::move(errmsg)};

        // TODO(oxen): We now serialize both owner and backup_owner, since if
        // we specify an owner that is backup owner, we don't show the (other)
        // owner. For RPC compatibility we keep the request_index around until the
        // next hard fork (16)
        owners.push_back(ons_owner);
        owner_to_request_index[ons_owner] = request_index;
    }

    ons::name_system_db& db = m_core.blockchain.name_system_db();
    std::optional<uint64_t> height;
    if (!ons_owners_to_names.request.include_expired)
        height = m_core.blockchain.get_current_blockchain_height();

    std::vector<ONS_OWNERS_TO_NAMES::response_entry> entries;
    std::vector<ons::mapping_record> records = db.get_mappings_by_owners(owners, height);
    for (auto& record : records) {
        auto it = owner_to_request_index.end();
        if (record.owner)
            it = owner_to_request_index.find(record.owner);
        if (it == owner_to_request_index.end() && record.backup_owner)
            it = owner_to_request_index.find(record.backup_owner);
        if (it == owner_to_request_index.end())
            throw rpc_error{
                    ERROR_INTERNAL,
                    (record.owner ? ("Owner=" + record.owner.to_string(nettype()) + " ") : ""s) +
                            (record.backup_owner ? ("BackupOwner=" +
                                                    record.backup_owner.to_string(nettype()) + " ")
                                                 : ""s) +
                            " could not be mapped back a index in the request 'entries' array"};

        auto& entry = entries.emplace_back();
        entry.request_index = it->second;
        entry.type = record.type;
        entry.name_hash = std::move(record.name_hash);
        if (record.owner)
            entry.owner = record.owner.to_string(nettype());
        if (record.backup_owner)
            entry.backup_owner = record.backup_owner.to_string(nettype());
        // FIXME: binary proxy
        entry.encrypted_value = oxenc::to_hex(record.encrypted_value.to_view());
        entry.update_height = record.update_height;
        entry.expiration_height = record.expiration_height;
        // FIXME: binary proxy
        entry.txid = tools::hex_guts(record.txid);
    }

    // FIXME: this seems broken; how can this vector of some random struct magically become json?
    ons_owners_to_names.response["entries"] = entries;
    ons_owners_to_names.response["status"] = STATUS_OK;
}

//------------------------------------------------------------------------------------------------------------------------------
void core_rpc_server::invoke(ONS_RESOLVE& resolve, rpc_context) {
    auto& req = resolve.request;
    if (req.type < 0 || req.type >= tools::enum_count<ons::mapping_type>)
        throw rpc_error{
                ERROR_WRONG_PARAM, "Unable to resolve ONS address: 'type' parameter not specified"};

    auto name_hash = ons::name_hash_input_to_base64(req.name_hash);
    if (!name_hash)
        throw rpc_error{
                ERROR_WRONG_PARAM,
                "Unable to resolve ONS address: invalid 'name_hash' value '" + req.name_hash + "'"};

    auto hf_version = m_core.blockchain.get_network_version();
    auto type = static_cast<ons::mapping_type>(req.type);
    if (!ons::mapping_type_allowed(hf_version, type))
        throw rpc_error{
                ERROR_WRONG_PARAM, "Invalid lokinet type '" + std::to_string(req.type) + "'"};

    if (auto mapping = m_core.blockchain.name_system_db().resolve(
                type, *name_hash, m_core.blockchain.get_current_blockchain_height())) {
        auto [val, nonce] = mapping->value_nonce(type);
        resolve.response_hex["encrypted_value"] = val;
        if (val.size() < mapping->to_view().size())
            resolve.response_hex["nonce"] = nonce;
    }
}

void core_rpc_server::invoke(GET_ACCRUED_REWARDS& rpc, rpc_context) {
    auto& balances = rpc.response["balances"];
    balances = json::object();

    const auto& req = rpc.request;
    auto net = nettype();
    BlockchainSQLite& sql_db = m_core.blockchain.sqlite_db();

    if (req.addresses.size() > 0) {
        for (const auto& address : req.addresses) {
            uint64_t amount = 0;
            if (eth::address eth_address{};
                tools::try_load_from_hex_guts<eth::address>(address, eth_address)) {
                std::tie(std::ignore, amount) = sql_db.get_accrued_rewards(eth_address);
            } else if (address_parse_info parse_info{};
                       get_account_address_from_str(parse_info, net, address)) {
                std::tie(std::ignore, amount) = sql_db.get_accrued_rewards(parse_info.address);
            }
            balances[address] = amount;
        }
    } else {
        auto [addresses, amounts] = sql_db.get_all_accrued_rewards();
        for (size_t i = 0; i < addresses.size(); i++) {
            balances[addresses[i]] = amounts[i];
        }
    }

    rpc.response["status"] = STATUS_OK;
}

}  // namespace cryptonote::rpc
