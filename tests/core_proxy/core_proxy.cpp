// Copyright (c) 2014-2018, The Monero Project
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

// node.cpp : Defines the entry point for the console application.
//

#include <boost/program_options.hpp>
#include <iostream>
#include <sstream>

#include "common/command_line.h"
#include "epee/console_handler.h"
#include "p2p/net_node.h"
#include "p2p/net_node.inl"
#include "version.h"
// #include "cryptonote_core/cryptonote_core.h"
#include "core_proxy.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.inl"
#include "version.h"

#if defined(WIN32)
#include <crtdbg.h>
#endif

namespace po = boost::program_options;
using namespace cryptonote;
using namespace crypto;

BOOST_CLASS_VERSION(
        nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<tests::proxy_core>>, 1);

int main(int argc, char* argv[]) {

#ifdef WIN32
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

    TRY_ENTRY();

    tools::on_startup();
    epee::string_tools::set_module_name_and_folder(argv[0]);

    // set up logging options
    oxen::logging::init("core_proxy.log", "*=debug");

    po::options_description desc("Allowed options");
    po::options_description hidden("Hidden options");
    command_line::add_arg(desc, cryptonote::arg_data_dir);
    nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<tests::proxy_core>>::
            init_options(desc, hidden);

    po::variables_map vm;
    bool r = command_line::handle_error_helper(desc, [&]() {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
        return true;
    });
    if (!r)
        return 1;

    oxen::log::info(logcat, "Module folder: {}", argv[0]);
    oxen::log::info(logcat, "Node starting ...");

    // create objects and link them
    tests::proxy_core pr_core;
    cryptonote::t_cryptonote_protocol_handler<tests::proxy_core> cprotocol(pr_core);
    nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<tests::proxy_core>> p2psrv{
            cprotocol};
    cprotocol.set_p2p_endpoint(&p2psrv);
    // pr_core.set_cryptonote_protocol(&cprotocol);
    // daemon_cmmands_handler dch(p2psrv);

    // initialize objects

    oxen::log::info(logcat, "Initializing p2p server...");
    bool res = p2psrv.init(vm);
    CHECK_AND_ASSERT_MES(res, 1, "Failed to initialize p2p server.");
    oxen::log::info(logcat, "P2p server initialized OK");

    oxen::log::info(logcat, "Initializing cryptonote protocol...");
    res = cprotocol.init(vm);
    CHECK_AND_ASSERT_MES(res, 1, "Failed to initialize cryptonote protocol.");
    oxen::log::info(logcat, "Cryptonote protocol initialized OK");

    // initialize core here
    oxen::log::info(logcat, "Initializing proxy core...");
    res = pr_core.init(vm);
    CHECK_AND_ASSERT_MES(res, 1, "Failed to initialize core");
    oxen::log::info(logcat, "Core initialized OK");

    oxen::log::info(logcat, "Starting p2p net loop...");
    p2psrv.run();
    oxen::log::info(logcat, "p2p net loop stopped");

    // deinitialize components
    oxen::log::info(logcat, "Deinitializing core...");
    pr_core.deinit();
    oxen::log::info(logcat, "Deinitializing cryptonote_protocol...");
    cprotocol.deinit();
    oxen::log::info(logcat, "Deinitializing p2p...");
    p2psrv.deinit();

    // pr_core.set_cryptonote_protocol(NULL);
    cprotocol.set_p2p_endpoint(NULL);

    oxen::log::info(logcat, "Node stopped.");
    return 0;

    CATCH_ENTRY("main", 1);
}

/*
string tx2str(const cryptonote::transaction& tx, const cryptonote::hash256& tx_hash, const
cryptonote::hash256& tx_prefix_hash, const std::string& blob) { stringstream ss;

    ss << "{";
    ss << "\n\tversion:" << tx.version;
    ss << "\n\tunlock_time:" << tx.unlock_time;
    ss << "\t"

    return ss.str();
}*/

std::vector<cryptonote::tx_verification_batch_info> tests::proxy_core::parse_incoming_txs(
        const std::vector<std::string>& tx_blobs, const tx_pool_options& opts) {

    std::vector<cryptonote::tx_verification_batch_info> tx_info(tx_blobs.size());

    for (size_t i = 0; i < tx_blobs.size(); i++) {
        auto& txi = tx_info[i];
        crypto::hash tx_prefix_hash{};
        if (opts.kept_by_block) {
            txi.result = txi.parsed = true;
        } else if (parse_and_validate_tx_from_blob(
                           tx_blobs[i], txi.tx, txi.tx_hash, tx_prefix_hash)) {
            fmt::print(
                    "TX\n\n{}\n{}\n{}\n{}\n\nENDTX\n",
                    txi.tx_hash,
                    tx_prefix_hash,
                    tx_blobs[i].size(),
                    obj_to_json_str(txi.tx));
            txi.result = txi.parsed = true;
            txi.blob = &tx_blobs[i];
        } else {
            txi.tvc.m_verifivation_failed = true;
            std::cerr << "WRONG TRANSACTION BLOB, Failed to parse, rejected\n";
        }
    }

    return tx_info;
}

bool tests::proxy_core::handle_parsed_txs(
        std::vector<cryptonote::tx_verification_batch_info>& parsed_txs,
        const tx_pool_options& opts,
        uint64_t* blink_rollback_height) {

    if (blink_rollback_height)
        *blink_rollback_height = 0;

    bool ok = true;
    for (auto& i : parsed_txs)
        ok &= i.result;

    return ok;
}

std::vector<tx_verification_batch_info> tests::proxy_core::handle_incoming_txs(
        const std::vector<std::string>& tx_blobs, const tx_pool_options& opts) {
    auto parsed = parse_incoming_txs(tx_blobs, opts);
    handle_parsed_txs(parsed, opts);
    return parsed;
}

bool tests::proxy_core::handle_incoming_tx(
        const std::string& tx_blob, tx_verification_context& tvc, const tx_pool_options& opts) {
    const std::vector<std::string> tx_blobs{{tx_blob}};
    auto parsed = handle_incoming_txs(tx_blobs, opts);
    parsed[0].blob = &tx_blob;  // Update pointer to the input rather than the copy in case the
                                // caller wants to use it for some reason
    tvc = parsed[0].tvc;
    return parsed[0].result;
}

std::pair<std::vector<std::shared_ptr<blink_tx>>, std::unordered_set<crypto::hash>>
tests::proxy_core::parse_incoming_blinks(const std::vector<serializable_blink_metadata>& blinks) {
    return {};
}

bool tests::proxy_core::handle_incoming_block(
        const std::string& block_blob,
        const cryptonote::block* block_,
        cryptonote::block_verification_context& bvc,
        cryptonote::checkpoint_t* checkpoint,
        bool update_miner_blocktemplate) {
    block b{};

    if (!parse_and_validate_block_from_blob(block_blob, b)) {
        std::cerr << "Failed to parse and validate new block\n";
        return false;
    }

    crypto::hash h = get_block_hash(b);
    crypto::hash lh = get_block_longhash_w_blockchain(network_type::FAKECHAIN, NULL, b, 0, 0);
    fmt::print(
            "BLOCK\n\n{}\n{}\n{}\n{}\n{}\n\nENDBLOCK\n\n",
            h,
            lh,
            b.miner_tx ? get_transaction_hash(*b.miner_tx) : crypto::null<crypto::hash>,
            b.miner_tx ? get_object_blobsize(*b.miner_tx) : 0,
            obj_to_json_str(b));

    if (!blockchain.add_block(h, lh, b, block_blob, checkpoint))
        return false;

    return true;
}

bool tests::proxy_core::handle_uptime_proof(
        const cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request& proof,
        bool& my_uptime_proof_confirmation) {
    // TODO: add tests for core uptime proof checking.
    return false;  // never relay these for tests.
}

bool tests::proxy_core::fake_blockchain::get_short_chain_history(std::list<crypto::hash>& ids) {
    build_short_history(ids, m_lastblk);
    return true;
}

std::pair<uint64_t, crypto::hash> tests::proxy_core::fake_blockchain::get_tail_id() const {
    return std::make_pair(0, get_block_hash(m_genesis));
}

bool tests::proxy_core::init(const boost::program_options::variables_map& /*vm*/) {
    generate_genesis_block(blockchain.m_genesis, network_type::MAINNET);
    crypto::hash h = get_block_hash(blockchain.m_genesis);
    blockchain.add_block(
            h,
            get_block_longhash(
                    network_type::FAKECHAIN,
                    randomx_longhash_context(NULL, blockchain.m_genesis, 0),
                    blockchain.m_genesis,
                    0,
                    0),
            blockchain.m_genesis,
            block_to_blob(blockchain.m_genesis),
            nullptr /*checkpoint*/);
    return true;
}

bool tests::proxy_core::fake_blockchain::have_block(const crypto::hash& id) {
    if (m_hash2blkidx.end() == m_hash2blkidx.find(id))
        return false;
    return true;
}

void tests::proxy_core::fake_blockchain::build_short_history(
        std::list<crypto::hash>& m_history, const crypto::hash& m_start) {
    m_history.push_front(get_block_hash(m_genesis));
    /*std::unordered_map<crypto::hash, tests::block_index>::const_iterator cit =
    m_hash2blkidx.find(m_lastblk);

    do {
        m_history.push_front(cit->first);

        size_t n = 1 << m_history.size();
        while (m_hash2blkidx.end() != cit && cit->second.blk.prev_id && n > 0) {
            n--;
            cit = m_hash2blkidx.find(cit->second.blk.prev_id);
        }
    } while (m_hash2blkidx.end() != cit && get_block_hash(cit->second.blk) != cit->first);*/
}

bool tests::proxy_core::fake_blockchain::add_block(
        const crypto::hash& _id,
        const crypto::hash& _longhash,
        const cryptonote::block& _blk,
        const std::string& _blob,
        cryptonote::checkpoint_t const*) {
    size_t height = 0;

    if (_blk.prev_id) {
        std::unordered_map<crypto::hash, tests::block_index>::const_iterator cit =
                m_hash2blkidx.find(_blk.prev_id);
        if (m_hash2blkidx.end() == cit) {
            fmt::print(stderr, "ERROR: can't find previous block with id \"{}\"\n", _blk.prev_id);
            return false;
        }

        height = cit->second.height + 1;
    }

    m_known_block_list.push_back(_id);

    block_index bi(height, _id, _longhash, _blk, _blob, txes);
    m_hash2blkidx.insert(std::make_pair(_id, bi));
    txes.clear();
    m_lastblk = _id;

    return true;
}
