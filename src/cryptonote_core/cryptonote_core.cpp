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

#include <fmt/color.h>
#include <fmt/std.h>
#include <oxenc/base32z.h>
#include <oxenmq/fmt.h>
#include <sodium.h>
#include <sqlite3.h>

#include <boost/algorithm/string.hpp>
#include <csignal>
#include <iomanip>
#include <unordered_set>

#include "common/exception.h"
#include "common/guts.h"

extern "C" {
#ifdef ENABLE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif
}

#include "blockchain_db/blockchain_db.h"
#include "blockchain_db/sqlite/db_sqlite.h"
#include "bls/bls_signer.h"
#include "checkpoints/checkpoints.h"
#include "common/base58.h"
#include "common/command_line.h"
#include "common/file.h"
#include "common/i18n.h"
#include "common/notify.h"
#include "common/sha256sum.h"
#include "common/threadpool.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/hardfork.h"
#include "cryptonote_config.h"
#include "cryptonote_core.h"
#include "epee/memwipe.h"
#include "epee/net/local_ip.h"
#include "epee/string_tools.h"
#include "epee/warnings.h"
#include "ethyl/utils.hpp"
#include "logging/oxen_logger.h"
#include "ringct/rctSigs.h"
#include "ringct/rctTypes.h"
#include "uptime_proof.h"
#include "version.h"

DISABLE_VS_WARNINGS(4355)

#define BAD_SEMANTICS_TXES_MAX_SIZE 100

// basically at least how many bytes the block itself serializes to without the miner tx
#define BLOCK_SIZE_SANITY_LEEWAY 100

namespace cryptonote {

static auto logcat = log::Cat("cn");
static auto omqlogcat = log::Cat("omq");

const command_line::arg_flag arg_keep_fakechain{
        "keep-fakechain", "Don't delete any existing database when in fakechain mode."};
const command_line::arg_descriptor<difficulty_type> arg_fixed_difficulty = {
        "fixed-difficulty", "Fixed difficulty used for testing.", 0};
const command_line::arg_flag arg_dev_allow_local{
        "dev-allow-local-ips",
        "Allow a local IPs for local and received service node public IP (for local testing only)"};
const command_line::arg_descriptor<std::string> arg_data_dir{
        "data-dir", "Specify data directory"s, [](network_type nettype) {
            fs::path base = tools::get_default_data_dir();
            if (auto subdir = cryptonote::network_config_subdir(nettype); !subdir.empty())
                base /= subdir;
            return tools::convert_str<char>(base.u8string());
        }};
const command_line::arg_flag arg_offline = {
        "offline", "Do not listen for peers, nor connect to any"};
const command_line::arg_descriptor<size_t> arg_block_download_max_size = {
        "block-download-max-size",
        "Set maximum size of block download queue in bytes (0 for default)",
        0};

static const command_line::arg_flag arg_test_drop_download = {
        "test-drop-download",
        "For net tests: in download, discard ALL blocks instead checking/saving them (very fast)"};
static const command_line::arg_descriptor<uint64_t> arg_test_drop_download_height = {
        "test-drop-download-height",
        "Like test-drop-download but discards only after around certain height",
        0};
static const command_line::arg_descriptor<uint64_t> arg_fast_block_sync = {
        "fast-block-sync", "Sync up most of the way by using embedded, known block hashes.", 1};
static const command_line::arg_descriptor<uint64_t> arg_prep_blocks_threads = {
        "prep-blocks-threads",
        "Max number of threads to use when preparing block hashes in groups.",
        4};
static const command_line::arg_flag arg_show_time_stats = {
        "show-time-stats", "Show time-stats when processing blocks/txs and disk synchronization."};
static const command_line::arg_descriptor<size_t> arg_block_sync_size = {
        "block-sync-size",
        "How many blocks to sync at once during chain synchronization (0 = adaptive).",
        0};
static const command_line::arg_flag arg_pad_transactions = {
        "pad-transactions",
        "Pad relayed transactions to help defend against traffic volume analysis"};
static const command_line::arg_descriptor<size_t> arg_max_txpool_weight = {
        "max-txpool-weight", "Set maximum txpool weight in bytes.", DEFAULT_MEMPOOL_MAX_WEIGHT};
static const command_line::arg_flag arg_service_node = {
        "service-node", "Run as a service node, option 'service-node-public-ip' must be set"};
static const command_line::arg_descriptor<std::string> arg_public_ip = {
        "service-node-public-ip",
        "Public IP address on which this service node's services (such as the Loki "
        "storage server) are accessible. This IP address will be advertised to the "
        "network via the service node uptime proofs. Required if operating as a "
        "service node."};
static const command_line::arg_descriptor<uint16_t> arg_storage_server_port = {
        "storage-server-port", "Deprecated option, ignored.", 0};
static const command_line::arg_descriptor<uint16_t> arg_quorumnet_port = {
        "quorumnet-port",
        "The port on which this service node listen for direct connections from other "
        "service nodes for quorum messages.  The port must be publicly reachable "
        "on the `--service-node-public-ip' address and binds to the p2p IP address."
        " Only applies when running as a service node.",
        [](cryptonote::network_type nettype) { return get_config(nettype).QNET_DEFAULT_PORT; }};
static const command_line::arg_flag arg_omq_quorumnet_public{
        "lmq-public-quorumnet",
        "Allow the curve-enabled quorumnet address (for a Service Node) to be used for public RPC "
        "commands as if passed to --lmq-curve-public. "
        "Note that even without this option the quorumnet port can be used for RPC commands by "
        "--lmq-admin and --lmq-user pubkeys."};
static const command_line::arg_descriptor<std::vector<std::string>> arg_l2_provider = {
        "l2-provider",
        "Specify a provider HTTP or HTTPS URL to which this service node will query the Ethereum "
        "L2 blockchain when tracking the rewards smart contract. Required if operating as a "
        "service node. Can be specified multiple times to add backup providers."};

// Floating point duration, to which all integer durations are implicitly convertible
using dseconds = std::chrono::duration<double>;

static const command_line::arg_descriptor<double> arg_l2_refresh = {
        "l2-refresh",
        "Specify the time (in seconds) between refreshes of the Ethereum L2 provider current state",
        dseconds{ETH_L2_DEFAULT_REFRESH}.count()};
static const command_line::arg_descriptor<double> arg_l2_timeout = {
        "l2-timeout",
        "Specify the timeout (in seconds) for requests to the L2 provider current state; if "
        "multiple providers are configured then after a timeout the next provider will be tried.",
        dseconds{ETH_L2_DEFAULT_REQUEST_TIMEOUT}.count()};
static const command_line::arg_descriptor<int> arg_l2_max_logs = {
        "l2-max-logs",
        "Specify the maximum number of logs we will request at once in a single request to the L2 "
        "provider.  If more logs are needed than this at once then multiple requests will be used.",
        ETH_L2_DEFAULT_MAX_LOGS};
static const command_line::arg_descriptor<double> arg_l2_check_interval = {
        "l2-check-interval",
        "When multiple L2 providers are specified, this specifies how often (in seconds) all of "
        "them should be checked to see if they are synced and, if not, switch to a backup "
        "provider. Earlier L2 providers will be preferred when all providers are reasonably close",
        dseconds{ETH_L2_DEFAULT_CHECK_INTERVAL}.count()};
static const command_line::arg_descriptor<int> arg_l2_check_threshold = {
        "l2-check-threshold",
        "When multiple L2 providers are specified, this is the threshold (in number of blocks) "
        "behind the best provider height before we consider a given provider out of sync",
        ETH_L2_DEFAULT_CHECK_THRESHOLD};
static const command_line::arg_flag arg_l2_skip_chainid = {
        "l2-skip-chainid",
        "Skips the oxend startup chainId check that ensures the configured L2 provider(s) are "
        "providing data for the the correct L2 chain."};
static const command_line::arg_descriptor<std::string> arg_block_notify = {
        "block-notify",
        "Run a program for each new block, '%s' will be replaced by the block hash",
        ""};
static const command_line::arg_flag arg_prune_blockchain = {"prune-blockchain", "Prune blockchain"};
static const command_line::arg_descriptor<std::string> arg_reorg_notify = {
        "reorg-notify",
        "Run a program for each reorg, '%s' will be replaced by the split height, "
        "'%h' will be replaced by the new blockchain height, and '%n' will be "
        "replaced by the number of new blocks in the new chain",
        ""};
static const command_line::arg_flag arg_keep_alt_blocks{
        "keep-alt-blocks", "Keep alternative blocks on restart"};

static const command_line::arg_descriptor<uint64_t> arg_store_quorum_history = {
        "store-quorum-history",
        "Store the service node quorum history for the last N blocks to allow historic quorum "
        "lookups "
        "(e.g. by a block explorer).  Specify the number of blocks of history to store, or 1 to "
        "store "
        "the entire history.  Requires considerably more memory and block chain storage.",
        0};

// Loads stubs that fail if invoked.  The stubs are replaced in the
// cryptonote_protocol/quorumnet.cpp glue code.
[[noreturn]] static void need_core_init(std::string_view stub_name) {
    throw oxen::traced<std::logic_error>(
            "Internal error: core callback initialization was not performed for "s +
            std::string(stub_name));
}

void (*long_poll_trigger)(tx_memory_pool& pool) = [](tx_memory_pool&) {
    need_core_init("long_poll_trigger"sv);
};
quorumnet_new_proc* quorumnet_new = [](core&) -> void* { need_core_init("quorumnet_new"sv); };
quorumnet_init_proc* quorumnet_init = [](core&, void*) { need_core_init("quorumnet_init"sv); };
quorumnet_delete_proc* quorumnet_delete = [](void*&) { need_core_init("quorumnet_delete"sv); };
quorumnet_relay_obligation_votes_proc* quorumnet_relay_obligation_votes =
        [](void*, const std::vector<service_nodes::quorum_vote_t>&) {
            need_core_init("quorumnet_relay_obligation_votes"sv);
        };
quorumnet_send_blink_proc* quorumnet_send_blink =
        [](core&, const std::string&) -> std::future<std::pair<blink_result, std::string>> {
    need_core_init("quorumnet_send_blink"sv);
};
quorumnet_pulse_relay_message_to_quorum_proc* quorumnet_pulse_relay_message_to_quorum =
        [](void*, pulse::message const&, service_nodes::quorum const&, bool) -> void {
    need_core_init("quorumnet_pulse_relay_message_to_quorum"sv);
};

//-----------------------------------------------------------------------------------------------
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuninitialized"
core::core() :
        mempool(blockchain),
        service_node_list(blockchain),
        blockchain(mempool, service_node_list),
        m_quorum_cop(*this),
        miner{[this](const cryptonote::block& b,
                     uint64_t height,
                     unsigned int threads,
                     crypto::hash& hash) {
                  hash = cryptonote::get_block_longhash_w_blockchain(
                          m_nettype, &blockchain, b, height, threads);
                  return true;
              },
              [this](block& b, block_verification_context& bvc) {
                  return handle_block_found(b, bvc);
              },
              [this]<typename... Args>(Args&&... args) {
                  return blockchain.create_next_miner_block_template(std::forward<Args>(args)...);
              }},
        m_pprotocol(&m_protocol_stub),
        m_starter_message_showed(false),
        m_target_blockchain_height(0),
        m_last_json_checkpoints_update(0),
        m_nettype(network_type::UNDEFINED),
        m_last_storage_server_ping(0),
        m_last_lokinet_ping(0),
        m_pad_transactions(false),
        ss_version{0},
        lokinet_version{0} {
#pragma GCC diagnostic pop
    m_checkpoints_updating.clear();
}
void core::set_cryptonote_protocol(i_cryptonote_protocol* pprotocol) {
    if (pprotocol)
        m_pprotocol = pprotocol;
    else
        m_pprotocol = &m_protocol_stub;
}
//-----------------------------------------------------------------------------------------------
bool core::update_checkpoints_from_json_file() {
    if (m_checkpoints_updating.test_and_set())
        return true;

    // load json checkpoints every 10min and verify them with respect to what blocks we already have
    bool res = true;
    if (time(NULL) - m_last_json_checkpoints_update >= 600) {
        res = blockchain.update_checkpoints_from_json_file(m_checkpoints_path);
        m_last_json_checkpoints_update = time(NULL);
    }
    m_checkpoints_updating.clear();

    // if anything fishy happened getting new checkpoints, bring down the house
    if (!res) {
        graceful_exit();
    }
    return res;
}
//-----------------------------------------------------------------------------------
void core::stop() {
    miner.stop();
    blockchain.cancel();
}
//-----------------------------------------------------------------------------------
void core::init_options(boost::program_options::options_description& desc) {
    command_line::add_arg(desc, arg_data_dir);

    command_line::add_arg(desc, arg_test_drop_download);
    command_line::add_arg(desc, arg_test_drop_download_height);
    command_line::add_network_args(desc);
    command_line::add_arg(desc, arg_keep_fakechain);
    command_line::add_arg(desc, arg_fixed_difficulty);
    command_line::add_arg(desc, arg_dev_allow_local);
    command_line::add_arg(desc, arg_prep_blocks_threads);
    command_line::add_arg(desc, arg_fast_block_sync);
    command_line::add_arg(desc, arg_show_time_stats);
    command_line::add_arg(desc, arg_block_sync_size);
    command_line::add_arg(desc, arg_offline);
    command_line::add_arg(desc, arg_block_download_max_size);
    command_line::add_arg(desc, arg_max_txpool_weight);
    command_line::add_arg(desc, arg_service_node);
    command_line::add_arg(desc, arg_public_ip);
    command_line::add_arg(desc, arg_l2_provider);
    command_line::add_arg(desc, arg_l2_refresh);
    command_line::add_arg(desc, arg_l2_timeout);
    command_line::add_arg(desc, arg_l2_max_logs);
    command_line::add_arg(desc, arg_l2_check_interval);
    command_line::add_arg(desc, arg_l2_check_threshold);
    command_line::add_arg(desc, arg_l2_skip_chainid);
    command_line::add_arg(desc, arg_storage_server_port);
    command_line::add_arg(desc, arg_quorumnet_port);

    command_line::add_arg(desc, arg_pad_transactions);
    command_line::add_arg(desc, arg_block_notify);
#if 0  // TODO(oxen): Pruning not supported because of Service Node List
    command_line::add_arg(desc, arg_prune_blockchain);
#endif
    command_line::add_arg(desc, arg_reorg_notify);
    command_line::add_arg(desc, arg_keep_alt_blocks);

    command_line::add_arg(desc, arg_store_quorum_history);
    command_line::add_arg(desc, arg_omq_quorumnet_public);

    miner::init_options(desc);
    BlockchainDB::init_options(desc);
}
//-----------------------------------------------------------------------------------------------
bool core::handle_command_line(const boost::program_options::variables_map& vm) {
    if (m_nettype != network_type::FAKECHAIN)
        m_nettype = command_line::get_network(vm);

    m_check_uptime_proof_interval.interval(get_net_config().UPTIME_PROOF_CHECK_INTERVAL);

    m_config_folder = tools::utf8_path(command_line::get_arg(vm, arg_data_dir));

    test_drop_download_height(command_line::get_arg(vm, arg_test_drop_download_height));
    m_pad_transactions = get_arg(vm, arg_pad_transactions);
    m_offline = get_arg(vm, arg_offline);
    if (command_line::get_arg(vm, arg_test_drop_download) == true)
        test_drop_download();

    if (command_line::get_arg(vm, arg_dev_allow_local))
        service_node_list.debug_allow_local_ips = true;

    m_service_node = command_line::get_arg(vm, arg_service_node);

    if (m_service_node) {
        /// TODO: parse these options early, before we start p2p server etc?
        m_quorumnet_port = command_line::get_arg(vm, arg_quorumnet_port);

        bool args_okay = true;
        if (m_quorumnet_port == 0) {
            log::error(
                    logcat,
                    "Quorumnet port cannot be 0; please specify a valid port to listen on with: "
                    "'--{} <port>'",
                    arg_quorumnet_port.name);
            args_okay = false;
        }

        const std::string pub_ip = command_line::get_arg(vm, arg_public_ip);
        if (pub_ip.size()) {
            if (!epee::string_tools::get_ip_int32_from_string(m_sn_public_ip, pub_ip)) {
                log::error(logcat, "Unable to parse IPv4 public address from: {}", pub_ip);
                args_okay = false;
            }

            if (!epee::net_utils::is_ip_public(m_sn_public_ip)) {
                if (service_node_list.debug_allow_local_ips) {
                    log::warning(
                            logcat,
                            "Address given for public-ip is not public; allowing it because "
                            "dev-allow-local-ips was specified. This service node WILL NOT WORK ON "
                            "THE PUBLIC OXEN NETWORK!");
                } else {
                    log::error(
                            logcat,
                            "Address given for public-ip is not public: {}",
                            epee::string_tools::get_ip_string_from_int32(m_sn_public_ip));
                    args_okay = false;
                }
            }
        } else {
            log::error(
                    logcat,
                    "Please specify an IPv4 public address which the service node & storage server "
                    "is accessible from with: '--{} <ip address>'",
                    arg_public_ip.name);
            args_okay = false;
        }

        if (command_line::get_arg(vm, arg_l2_provider).empty()) {
            log::error(
                    logcat,
                    "At least one ethereum L2 provider must be specified for a service node");
            args_okay = false;
        }

        if (!args_okay) {
            log::error(
                    logcat,
                    "IMPORTANT: One or more required service node-related configuration "
                    "settings/options were omitted or invalid please fix them and restart oxend.");
            return false;
        }
    }

    return true;
}
//-----------------------------------------------------------------------------------------------

static std::string time_ago_str(time_t now, time_t then) {
    if (then >= now)
        return "now"s;
    if (then == 0)
        return "never"s;
    int seconds = now - then;
    if (seconds >= 60)
        return std::to_string(seconds / 60) + "m" + std::to_string(seconds % 60) + "s";
    return std::to_string(seconds % 60) + "s";
}

// Returns a bool on whether the service node is currently active
bool core::is_active_sn() const {
    auto info = get_my_sn_info();
    return (info && info->is_active());
}

// Returns the service nodes info
std::shared_ptr<const service_nodes::service_node_info> core::get_my_sn_info() const {
    const auto& pubkey = get_service_keys().pub;
    auto states = service_node_list.get_service_node_list_state({pubkey});
    if (states.empty())
        return nullptr;
    else {
        return states[0].info;
    }
}

// Returns a string for systemd status notifications such as:
// Height: 1234567, SN: active, proof: 55m12s, storage: 4m48s, lokinet: 47s
std::string core::get_status_string() const {
    std::string s;
    s.reserve(128);
    s += 'v';
    s += OXEN_VERSION_STR;
    s += "; Height: ";
    s += std::to_string(blockchain.get_current_blockchain_height());
    s += ", SN: ";
    if (!service_node())
        s += "no";
    else {
        const auto& pubkey = get_service_keys().pub;
        auto states = service_node_list.get_service_node_list_state({pubkey});
        if (states.empty())
            s += "not registered";
        else {
            auto& info = *states[0].info;
            if (!info.is_fully_funded())
                s += "awaiting contr.";
            else if (info.is_active())
                s += "active";
            else if (info.is_decommissioned())
                s += "decomm.";

            uint64_t last_proof = 0;
            service_node_list.access_proof(
                    pubkey, [&](auto& proof) { last_proof = proof.timestamp; });
            s += ", proof: ";
            time_t now = std::time(nullptr);
            s += time_ago_str(now, last_proof);
            s += ", storage: ";
            s += time_ago_str(now, m_last_storage_server_ping);
            s += ", lokinet: ";
            s += time_ago_str(now, m_last_lokinet_ping);
        }
    }
    return s;
}

template <typename Duration>
static Duration as_duration(double seconds) {
    return std::chrono::duration_cast<Duration>(dseconds(seconds));
}

//-----------------------------------------------------------------------------------------------
bool core::init(
        const boost::program_options::variables_map& vm,
        const cryptonote::test_options* test_options,
        const GetCheckpointsCallback& get_checkpoints /* = nullptr */,
        const std::atomic<bool>* abort) {
    start_time = std::time(nullptr);

    if (test_options != NULL)
        m_nettype = network_type::FAKECHAIN;

    bool r = handle_command_line(vm);
    /// Currently terminating before blockchain is initialized results in a crash
    /// during deinitialization... TODO: fix that
    CHECK_AND_ASSERT_MES(r, false, "Failed to apply command line options.");

    size_t max_txpool_weight = command_line::get_arg(vm, arg_max_txpool_weight);
    bool const prune_blockchain = false; /* command_line::get_arg(vm, arg_prune_blockchain); */
    bool keep_alt_blocks = command_line::get_arg(vm, arg_keep_alt_blocks);

    r = init_service_keys();
    CHECK_AND_ASSERT_MES(r, false, "Failed to create or load service keys");
    if (m_service_node) {
        // Only use our service keys for our service node if we are running in SN mode:
        service_node_list.set_my_service_node_keys(&m_service_keys);
    }

    auto folder = m_config_folder;
    if (m_nettype == network_type::FAKECHAIN)
        folder /= "fake";

    auto db = init_blockchain_db(folder, vm);
    if (!db)
        return false;

    auto ons_db_file_path = folder / "ons.db";
    if (fs::exists(folder / "lns.db"))
        ons_db_file_path = folder / "lns.db";

    if (m_nettype == network_type::FAKECHAIN && !command_line::get_arg(vm, arg_keep_fakechain))
        fs::remove(ons_db_file_path);

    auto sqlite_db_file_path = folder / "sqlite.db";
    if (m_nettype == network_type::FAKECHAIN) {
        sqlite_db_file_path = ":memory:";
    }

    if (m_nettype == network_type::STAGENET && db->height() > 1) {
        // Hack to handle stagenet reboot by seeing if we have the old stagenet block at height 1:
        // if we do, we need to delete the blockchain database files and reinitialize the database.
        // (We can't properly pop blocks in such a case because the reboot changed the serialized
        // blockchain format, and even if we could, it's not worth the time because it'll pop all
        // the way back to empty anyway).
        auto block1_hash = get_block_hash(db->get_block_from_height(1));
        constexpr auto STAGENET_V1_BLOCK1_HASH =
                "13633f8335998fe174f12752ea86d25636c9f777f441e9fa205ae4b8868e1f03"sv;
        if (tools::hex_guts(block1_hash) == STAGENET_V1_BLOCK1_HASH) {
            log::warning(globallogcat, "Detected old stagenet data; resetting databases...");

            db->close();
            log::warning(globallogcat, "Removing blockchain database");
            db->remove_data_file(folder / db->get_db_name());
            db.reset();
            log::warning(globallogcat, "Removing sqlite.db");
            fs::remove(sqlite_db_file_path);
            log::warning(globallogcat, "Removing ons.db");
            fs::remove(ons_db_file_path);

            db = init_blockchain_db(folder, vm);
            if (!db)
                return false;
        }
    }

    auto sqliteDB = std::make_unique<cryptonote::BlockchainSQLite>(m_nettype, sqlite_db_file_path);

    // We need this hook to get added before the block hook below, so that it fires first and
    // catches the start of a reorg before the block hook fires for the block in the reorg.
    try {
        if (!command_line::is_arg_defaulted(vm, arg_reorg_notify))
            blockchain.hook_block_post_add([this,
                                            notify = tools::Notify(command_line::get_arg(
                                                    vm, arg_reorg_notify))](const auto& info) {
                if (!info.reorg)
                    return;
                auto h = blockchain.get_current_blockchain_height();
                notify.notify("%s", info.split_height, "%h", h, "%n", h - info.split_height);
            });
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to parse reorg notify spec");
    }

    try {
        if (!command_line::is_arg_defaulted(vm, arg_block_notify))
            blockchain.hook_block_post_add([notify = tools::Notify(command_line::get_arg(
                                                    vm, arg_block_notify))](const auto& info) {
                notify.notify("%s", tools::hex_guts(get_block_hash(info.block)));
            });
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to parse block rate notify spec");
    }

    cryptonote::test_options regtest_test_options{};
    for (auto& hf : get_hard_forks(network_type::MAINNET)) {
        regtest_test_options.hard_forks.push_back(hard_fork{
                hf.version,
                hf.snode_revision,
                regtest_test_options.hard_forks.size(),
                std::time(nullptr)});
    }

    // Service Nodes
    service_node_list.set_quorum_history_storage(
            command_line::get_arg(vm, arg_store_quorum_history));

    // NOTE: Implicit dependency. Service node list needs to be hooked before checkpoints.
    blockchain.hook_blockchain_detached(
            [this](const auto& info) { service_node_list.blockchain_detached(info.height); });
    blockchain.hook_init([this] { service_node_list.init(); });
    blockchain.hook_validate_miner_tx(
            [this](const auto& info) { service_node_list.validate_miner_tx(info); });
    blockchain.hook_alt_block_add(
            [this](const auto& info) { service_node_list.alt_block_add(info); });

    blockchain.hook_blockchain_detached(
            [this](const auto& info) { blockchain.sqlite_db().blockchain_detached(info.height); });

    // NOTE: There is an implicit dependency on service node lists being hooked first!
    blockchain.hook_init([this] { m_quorum_cop.init(); });
    blockchain.hook_block_add(
            [this](const auto& info) { m_quorum_cop.block_add(info.block, info.txs); });
    blockchain.hook_blockchain_detached([this](const auto& info) {
        m_quorum_cop.blockchain_detached(info.height, info.by_pop_blocks);
    });

    blockchain.hook_block_post_add([this](const auto&) { update_omq_sns(); });

    // Checkpoints
    m_checkpoints_path = m_config_folder / JSON_HASH_FILE_NAME;

    sqlite3* ons_db = ons::init_oxen_name_system(ons_db_file_path, db->is_read_only());
    if (!ons_db)
        return false;

    init_oxenmq(vm);
    m_bls_aggregator = std::make_unique<eth::bls_aggregator>(*this);

    // FIXME: this is optional if we aren't a service node
    m_l2_tracker = std::make_unique<eth::L2Tracker>(
            *this,
            as_duration<std::chrono::milliseconds>(command_line::get_arg(vm, arg_l2_refresh)));
    m_l2_tracker->provider.setTimeout(as_duration<std::chrono::milliseconds>(
            1000 * command_line::get_arg(vm, arg_l2_timeout)));
    m_l2_tracker->GETLOGS_MAX_BLOCKS = command_line::get_arg(vm, arg_l2_max_logs);
    m_l2_tracker->PROVIDERS_CHECK_INTERVAL = as_duration<std::chrono::milliseconds>(
            command_line::get_arg(vm, arg_l2_check_interval));
    m_l2_tracker->PROVIDERS_CHECK_THRESHOLD = command_line::get_arg(vm, arg_l2_check_threshold);

    const auto l2_provider = command_line::get_arg(vm, arg_l2_provider);
    if (!l2_provider.empty()) {
        size_t provider_count = 0;
        for (auto provider : l2_provider) {
            auto provider_urls = tools::split_any(provider, ", \t\n", /*trim=*/true);

            try {
                for (const auto& url : provider_urls) {
                    m_l2_tracker->provider.addClient(
                            provider_count == 0 ? "Primary L2 provider"s
                                                : "Backup L2 provider #{}"_format(provider_count),
                            std::string{url});
                    provider_count++;
                }
            } catch (const std::exception& e) {
                log::critical(logcat, "Invalid l2-provider argument '{}': {}", tools::trim_url(provider), e.what());
                return false;
            }
        }
    }
    if (!command_line::get_arg(vm, arg_l2_skip_chainid) && !m_l2_tracker->check_chain_id())
        return false;  // the above already logs critical on failure

    r = blockchain.init(
            std::move(db),
            m_nettype,
            ons_db,
            sqliteDB.release(),
            m_l2_tracker.get(),
            m_offline,
            m_nettype == network_type::FAKECHAIN ? &regtest_test_options : test_options,
            command_line::get_arg(vm, arg_fixed_difficulty),
            get_checkpoints,
            abort);
    CHECK_AND_ASSERT_MES(r, false, "Failed to initialize blockchain storage");

    r = mempool.init(max_txpool_weight);
    CHECK_AND_ASSERT_MES(r, false, "Failed to initialize memory pool");

    // now that we have a valid `blockchain`, we can clean out any
    // transactions in the pool that do not conform to the current fork
    mempool.validate(blockchain.get_network_version());

    bool show_time_stats = command_line::get_arg(vm, arg_show_time_stats) != 0;
    blockchain.set_show_time_stats(show_time_stats);

    block_sync_size = command_line::get_arg(vm, arg_block_sync_size);
    if (block_sync_size > BLOCKS_SYNCHRONIZING_MAX_COUNT)
        log::error(
                logcat,
                "Error --block-sync-size cannot be greater than {}",
                BLOCKS_SYNCHRONIZING_MAX_COUNT);

    log::info(globallogcat, "Loading checkpoints");
    CHECK_AND_ASSERT_MES(
            update_checkpoints_from_json_file(),
            false,
            "One or more checkpoints loaded from json conflicted with existing checkpoints.");

    r = miner.init(vm, m_nettype);
    CHECK_AND_ASSERT_MES(r, false, "Failed to initialize miner instance");

    if (!keep_alt_blocks && !blockchain.db().is_read_only())
        blockchain.db().drop_alt_blocks();

    if (prune_blockchain) {
        // display a message if the blockchain is not pruned yet
        if (!blockchain.get_blockchain_pruning_seed()) {
            log::info(globallogcat, "Pruning blockchain...");
            CHECK_AND_ASSERT_MES(
                    blockchain.prune_blockchain(), false, "Failed to prune blockchain");
        } else {
            CHECK_AND_ASSERT_MES(
                    blockchain.update_blockchain_pruning(),
                    false,
                    "Failed to update blockchain pruning");
        }
    }

    return true;
}

std::unique_ptr<BlockchainDB> core::init_blockchain_db(
        fs::path folder, const boost::program_options::variables_map& vm) {

    std::string db_sync_mode = command_line::get_arg(vm, cryptonote::arg_db_sync_mode);
    bool fast_sync = command_line::get_arg(vm, arg_fast_block_sync) != 0;
    uint64_t blocks_threads = command_line::get_arg(vm, arg_prep_blocks_threads);
    bool db_salvage = command_line::get_arg(vm, cryptonote::arg_db_salvage) != 0;

    // make sure the data directory exists, and try to lock it
    if (std::error_code ec;
        !fs::is_directory(folder, ec) && !fs::create_directories(folder, ec) && ec) {
        log::error(logcat, "Failed to create directory {}: {}", folder, ec.message());
        return nullptr;
    }

    auto db = new_db();
    if (!db) {
        log::error(logcat, "Failed to initialize a database");
        return nullptr;
    }

    folder /= db->get_db_name();
    log::info(globallogcat, "Loading blockchain from folder {} ...", folder);

    if (m_nettype == network_type::FAKECHAIN && !command_line::get_arg(vm, arg_keep_fakechain)) {
        // reset the db by removing the database file before opening it
        if (!db->remove_data_file(folder)) {
            log::error(logcat, "Failed to remove data file in {}", folder);
            return nullptr;
        }
    }

    // default to fast:async:1 if overridden
    blockchain_db_sync_mode sync_mode = db_defaultsync;
    bool sync_on_blocks = true;
    uint64_t sync_threshold = 1;

    try {
        uint64_t db_flags = 0;

        std::vector<std::string> options;
        boost::trim(db_sync_mode);
        boost::split(options, db_sync_mode, boost::is_any_of(" :"));
        const bool db_sync_mode_is_default =
                command_line::is_arg_defaulted(vm, cryptonote::arg_db_sync_mode);

        for (const auto& option : options)
            log::debug(logcat, "option: {}", option);

        // default to fast:async:1
        uint64_t DEFAULT_FLAGS = DBF_FAST;

        if (options.size() == 0) {
            // default to fast:async:1
            db_flags = DEFAULT_FLAGS;
        }

        bool safemode = false;
        if (options.size() >= 1) {
            if (options[0] == "safe") {
                safemode = true;
                db_flags = DBF_SAFE;
                sync_mode = db_sync_mode_is_default ? db_defaultsync : db_nosync;
            } else if (options[0] == "fast") {
                db_flags = DBF_FAST;
                sync_mode = db_sync_mode_is_default ? db_defaultsync : db_async;
            } else if (options[0] == "fastest") {
                db_flags = DBF_FASTEST;
                sync_threshold = 1000;  // default to fastest:async:1000
                sync_mode = db_sync_mode_is_default ? db_defaultsync : db_async;
            } else
                db_flags = DEFAULT_FLAGS;
        }

        if (options.size() >= 2 && !safemode) {
            if (options[1] == "sync")
                sync_mode = db_sync_mode_is_default ? db_defaultsync : db_sync;
            else if (options[1] == "async")
                sync_mode = db_sync_mode_is_default ? db_defaultsync : db_async;
        }

        if (options.size() >= 3 && !safemode) {
            char* endptr;
            uint64_t threshold = strtoull(options[2].c_str(), &endptr, 0);
            if (*endptr == '\0' || !strcmp(endptr, "blocks")) {
                sync_on_blocks = true;
                sync_threshold = threshold;
            } else if (!strcmp(endptr, "bytes")) {
                sync_on_blocks = false;
                sync_threshold = threshold;
            } else {
                log::error(logcat, "Invalid db sync mode: {}", options[2]);
                return nullptr;
            }
        }

        if (db_salvage)
            db_flags |= DBF_SALVAGE;

        db->open(folder, m_nettype, db_flags);
        if (!db->m_open)
            return nullptr;
    } catch (const DB_ERROR& e) {
        log::error(logcat, "Error opening database: {}", e.what());
        return nullptr;
    }

    blockchain.set_user_options(
            blocks_threads, sync_on_blocks, sync_threshold, sync_mode, fast_sync);

    return db;
}

/// Loads a key from disk, if it exists, otherwise generates a new key pair and saves it to disk.
///
/// The existing key can be encoded as raw bytes; or hex (with or without a 0x prefix and/or \n
/// suffix).
///
/// get_pubkey - a function taking (privkey &, pubkey &) that sets the pubkey from the privkey;
///              returns true for success/false for failure
/// generate_pair - a void function taking (privkey &, pubkey &) that sets them to the generated
/// values; can throw on error.
///
/// Any extra arguments (passed in `extra...`) are appended to the get_pubkey or generate_pair
/// function calls.
template <
        typename Privkey,
        typename Pubkey,
        typename... Extra,
        std::invocable<const Privkey&, Pubkey&, Extra&...> GetPubkey,
        std::invocable<Privkey&, Pubkey&, Extra&...> GeneratePair>
bool init_key(
        const fs::path& keypath,
        Privkey& privkey,
        Pubkey& pubkey,
        GetPubkey get_pubkey,
        GeneratePair generate_pair,
        Extra&... extra) {
    std::error_code ec;
    if (fs::exists(keypath, ec)) {
        std::string keystr;
        bool r = tools::slurp_file(keypath, keystr);
        CHECK_AND_ASSERT_MES(r, false, "failed to load service node key from {}", keypath);

        OXEN_DEFER {
            memwipe(keystr.data(), keystr.size());
        };

        if (keystr.size() == sizeof(privkey))
            // raw bytes:
            memcpy(&unwrap(unwrap(privkey)), keystr.data(), sizeof(privkey));
        else {
            // Try to load as hex with a 0x prefix and optional \n suffix
            std::string_view keyv{keystr};
            if (keyv.starts_with("0x"))
                keyv.remove_prefix(2);
            if (keyv.ends_with('\n'))
                keyv.remove_suffix(1);
            if (keyv.size() == 2 * sizeof(privkey) && oxenc::is_hex(keyv))
                oxenc::from_hex(keyv.begin(), keyv.end(), privkey.data());
            else {
                log::error(logcat, "service node key file {} is invalid", keypath);
                return false;
            }
        }

        r = get_pubkey(privkey, pubkey, extra...);
        CHECK_AND_ASSERT_MES(r, false, "failed to generate pubkey from secret key");
    } else {
        try {
            generate_pair(privkey, pubkey, extra...);
        } catch (const std::exception& e) {
            log::error(logcat, "failed to generate keypair {}", e.what());
            return false;
        }

        std::string privkey_hex;
        OXEN_DEFER {
            memwipe(privkey_hex.data(), privkey_hex.size());
        };
        privkey_hex.reserve(2 * sizeof(privkey) + 3);
        privkey_hex += "0x";
        auto guts = tools::view_guts(privkey);
        oxenc::to_hex(guts.begin(), guts.end(), std::back_inserter(privkey_hex));
        privkey_hex += '\n';
        bool r = tools::dump_file(keypath, privkey_hex);
        CHECK_AND_ASSERT_MES(r, false, "failed to save service node key to {}", keypath);

        fs::permissions(keypath, fs::perms::owner_read, ec);
    }
    return true;
}

//-----------------------------------------------------------------------------------------------
bool core::init_service_keys() {
    auto& keys = m_service_keys;

    static_assert(
            sizeof(crypto::ed25519_public_key) == crypto_sign_ed25519_PUBLICKEYBYTES &&
                    sizeof(crypto::ed25519_secret_key) == crypto_sign_ed25519_SECRETKEYBYTES &&
                    sizeof(crypto::ed25519_signature) == crypto_sign_BYTES &&
                    sizeof(crypto::x25519_public_key) == crypto_scalarmult_curve25519_BYTES &&
                    sizeof(crypto::x25519_secret_key) == crypto_scalarmult_curve25519_BYTES,
            "Invalid ed25519/x25519 sizes");

    // <data>/key_ed25519: Standard ed25519 secret key.  We always have this, and generate one if it
    // doesn't exist.
    //
    // As of Loki 8.x, if this exists and `key` doesn't, we use this key for everything.  For
    // compatibility with earlier versions we also allow `key` to contain a separate monero privkey
    // for the SN keypair.  (The main difference is that the Monero keypair is unclamped and that it
    // only contains the private key value but not the secret key value that we need for full
    // Ed25519 signing).
    //
    if (!init_key(
                m_config_folder / "key_ed25519",
                keys.key_ed25519,
                keys.pub_ed25519,
                [](const crypto::ed25519_secret_key& sk, crypto::ed25519_public_key& pk) {
                    crypto_sign_ed25519_sk_to_pk(pk.data(), sk.data());
                    return true;
                },
                [](crypto::ed25519_secret_key& sk, crypto::ed25519_public_key& pk) {
                    crypto_sign_ed25519_keypair(pk.data(), sk.data());
                }))
        return false;

    // Standard x25519 keys generated from the ed25519 keypair, used for encrypted communication
    // between SNs
    int rc = crypto_sign_ed25519_pk_to_curve25519(keys.pub_x25519.data(), keys.pub_ed25519.data());
    CHECK_AND_ASSERT_MES(rc == 0, false, "failed to convert ed25519 pubkey to x25519");
    crypto_sign_ed25519_sk_to_curve25519(keys.key_x25519.data(), keys.key_ed25519.data());

    // BLS pubkey, used by service nodes when interacting with the Ethereum smart contract
    if (m_service_node &&
        !init_key(
                m_config_folder / "key_bls",
                keys.key_bls,
                keys.pub_bls,
                [this](const auto& sk, auto& pk, auto& bls_signer) {
                    // Load from existing

                    try {
                        bls_signer = eth::BLSSigner{m_nettype, &sk};
                    } catch (const std::exception& e) {
                        log::critical(logcat, "Invalid BLS key: {}", e.what());
                        return false;
                    }
                    pk = bls_signer->getCryptoPubkey();
                    return true;
                },
                [this](eth::bls_secret_key& sk, eth::bls_public_key& pk, auto& bls_signer) {
                    // Generate new one
                    bls_signer = eth::BLSSigner{m_nettype};
                    sk = bls_signer->getCryptoSeckey();
                    pk = bls_signer->getCryptoPubkey();
                },
                m_bls_signer))
        return false;

    // Legacy primary SN key file; we only load this if it exists, otherwise we use `key_ed25519`
    // for the primary SN keypair.  (This key predates the Ed25519 keys and so is needed for
    // backwards compatibility with existing active service nodes.)  The legacy key consists of
    // *just* the private point, but not the seed, and so cannot be used for full Ed25519 signatures
    // (which rely on the seed for signing).
    if (m_service_node) {
        if (std::error_code ec; !fs::exists(m_config_folder / "key", ec)) {
            epee::wipeable_string privkey_signhash;
            privkey_signhash.resize(crypto_hash_sha512_BYTES);
            unsigned char* pk_sh_data = reinterpret_cast<unsigned char*>(privkey_signhash.data());
            crypto_hash_sha512(pk_sh_data, keys.key_ed25519.data(), 32 /* first 32 bytes are the seed to be SHA512 hashed (the last 32 are just the pubkey) */);
            // Clamp private key (as libsodium does and expects -- see
            // https://www.jcraige.com/an-explainer-on-ed25519-clamping if you want the broader
            // reasons)
            pk_sh_data[0] &= 248;
            pk_sh_data[31] &= 63;  // (some implementations put 127 here, but with the |64 in the
                                   // next line it is the same thing)
            pk_sh_data[31] |= 64;
            // Monero crypto requires a pointless check that the secret key is < basepoint, so
            // calculate it mod basepoint to make it happy:
            sc_reduce32(pk_sh_data);
            std::memcpy(keys.key.data(), pk_sh_data, 32);
            if (!crypto::secret_key_to_public_key(keys.key, keys.pub))
                throw oxen::traced<std::runtime_error>{
                        "Failed to derive primary key from ed25519 key"};
            if (std::memcmp(keys.pub.data(), keys.pub_ed25519.data(), 32))
                throw oxen::traced<std::runtime_error>{
                        "Internal error: unexpected primary pubkey and ed25519 pubkey mismatch"};
        } else if (!init_key(
                           m_config_folder / "key",
                           keys.key,
                           keys.pub,
                           crypto::secret_key_to_public_key,
                           [](crypto::secret_key&, crypto::public_key&) {
                               throw oxen::traced<std::runtime_error>{
                                       "Internal error: old-style public keys are no longer "
                                       "generated"};
                           }))
            return false;
    } else {
        keys.key.zero();
        keys.pub.zero();
        keys.key_bls.zero();
        keys.pub_bls.zero();
    }

    auto style = fg(fmt::terminal_color::yellow) | fmt::emphasis::bold;
    if (m_service_node) {
        log::info(
                globallogcat,
                fg(fmt::terminal_color::cyan) | fmt::emphasis::bold,
                "Service node public keys:");
        log::info(globallogcat, style, "- primary: {:x}", keys.pub);
        log::info(globallogcat, style, "- ed25519: {:x}", keys.pub_ed25519);
        // .snode address is the ed25519 pubkey, encoded with base32z and with .snode appended:
        log::info(globallogcat, style, "- lokinet: {:a}.snode", keys.pub_ed25519);
        log::info(globallogcat, style, "- x25519: {:x}", keys.pub_x25519);
        log::info(globallogcat, style, "- bls: {:x}", keys.pub_bls);

    } else {
        // Only print the x25519 version because it's the only thing useful for a non-SN (for
        // encrypted OMQ RPC connections).
        log::info(globallogcat, style, "x25519 public key: {:x}", keys.pub_x25519);
    }

    return true;
}

oxenmq::AuthLevel core::omq_check_access(const crypto::x25519_public_key& pubkey) const {
    auto it = m_omq_auth.find(pubkey);
    if (it != m_omq_auth.end())
        return it->second;
    return oxenmq::AuthLevel::denied;
}

// Builds an allow function; takes `*this`, the default auth level, and whether this connection
// should allow incoming SN connections.
//
// default_auth should be AuthLevel::denied if only pre-approved connections may connect,
// AuthLevel::basic for public RPC, AuthLevel::admin for a (presumably localhost) unrestricted
// port, and AuthLevel::none for a super restricted mode (generally this is useful when there are
// also SN-restrictions on commands, i.e. for quorumnet).
//
// check_sn is whether we check an incoming key against known service nodes (and thus return
// "true" for the service node access if it checks out).
//
oxenmq::AuthLevel core::omq_allow(
        std::string_view ip, std::string_view x25519_pubkey_str, oxenmq::AuthLevel default_auth) {
    using namespace oxenmq;
    AuthLevel auth = default_auth;
    if (x25519_pubkey_str.size() == sizeof(crypto::x25519_public_key)) {
        auto x25519_pubkey = tools::make_from_guts<crypto::x25519_public_key>(x25519_pubkey_str);
        auto user_auth = omq_check_access(x25519_pubkey);
        if (user_auth >= AuthLevel::basic) {
            if (user_auth > auth)
                auth = user_auth;
            log::info(log::Cat("omq"), "Incoming {}-authenticated connection", auth);
        }

        log::debug(
                log::Cat("omq"),
                "Incoming [{}] curve connection from {}/{}",
                auth,
                ip,
                x25519_pubkey);
    } else {
        log::info(log::Cat("omq"), "Incoming [{}] plain connection from {}", auth, ip);
    }
    return auth;
}

void core::init_oxenmq(const boost::program_options::variables_map& vm) {
    using namespace oxenmq;
    m_omq = std::make_shared<OxenMQ>(
            tools::copy_guts(m_service_keys.pub_x25519),
            tools::copy_guts(m_service_keys.key_x25519),
            m_service_node,
            [this](std::string_view x25519_pk) {
                return service_node_list.remote_lookup(x25519_pk);
            },
            [](LogLevel omqlevel, const char* file, int line, std::string msg) {
                auto level = *oxen::logging::parse_level(omqlevel);
                if (omqlogcat->should_log(level))
                    omqlogcat->log({file, line, "omq"}, level, "{}", msg);
            },
            oxenmq::LogLevel::trace);

    // ping.ping: a simple debugging target for pinging the omq listener
    m_omq->add_category("ping", Access{AuthLevel::none})
            .add_request_command("ping", [](Message& m) {
                log::info(log::Cat("omq"), "Received ping from {}", m.conn);
                m.send_reply("pong");
            });

    if (m_service_node) {

        // Service nodes always listen for quorumnet data on the p2p IP, quorumnet port
        std::string listen_ip = vm["p2p-bind-ip"].as<std::string>();
        if (listen_ip.empty())
            listen_ip = "0.0.0.0";
        std::string qnet_listen = "tcp://" + listen_ip + ":" + std::to_string(m_quorumnet_port);
        log::info(globallogcat, "OxenMQ/quorumnet listening on {} (quorumnet)", qnet_listen);
        m_omq->listen_curve(
                qnet_listen,
                [this, public_ = command_line::get_arg(vm, arg_omq_quorumnet_public)](
                        std::string_view ip, std::string_view pk, bool) {
                    return omq_allow(ip, pk, public_ ? AuthLevel::basic : AuthLevel::none);
                });

        m_quorumnet_state = quorumnet_new(*this);
    }

    quorumnet_init(*this, m_quorumnet_state);
}

bool core::is_node_removable(const eth::bls_public_key& node_bls_pubkey) {
    auto removable_nodes = blockchain.get_removable_nodes();
    return std::find(removable_nodes.begin(), removable_nodes.end(), node_bls_pubkey) !=
           removable_nodes.end();
}

bool core::is_node_liquidatable(const eth::bls_public_key& node_bls_pubkey) {
    if (!is_node_removable(node_bls_pubkey))
        return false;

    // NOTE: Node exists in the smart contract but not the oxen service node
    // list, it's been deregistered from _OR_ it voluntarily exited the SNL.
    uint64_t height = blockchain.get_current_blockchain_height();
    for (const service_nodes::service_node_list::recently_removed_node& it : service_node_list.recently_removed_nodes()) {
        assert(it.bls_pubkey && "Invalid null key got inserted into the recently removed list");
        if (it.bls_pubkey == node_bls_pubkey) {
            bool result = height >= it.liquidation_height;
            return result;
        }
    }

    return false;
}

void core::start_oxenmq() {
    update_omq_sns();  // Ensure we have SNs set for the current block before starting

    if (m_service_node) {
        m_pulse_thread_id = m_omq->add_tagged_thread("pulse");
        m_omq->add_timer(
                [this]() { pulse::main(m_quorumnet_state, *this); },
                std::chrono::milliseconds(500),
                false,
                m_pulse_thread_id);
        m_omq->add_timer([this]() { this->check_service_node_time(); }, 5s, false);
        m_omq->add_timer([this]() { this->check_service_node_ip_address(); }, 15min, false);
    }
    m_omq->start();
}

//-----------------------------------------------------------------------------------------------
void core::deinit() {
#ifdef ENABLE_SYSTEMD
    sd_notify(0, "STOPPING=1\nSTATUS=Shutting down");
#endif
    if (m_quorumnet_state)
        quorumnet_delete(m_quorumnet_state);
    m_omq.reset();
    service_node_list.store();
    miner.stop();
    mempool.deinit();
    blockchain.deinit();
}
//-----------------------------------------------------------------------------------------------
void core::test_drop_download() {
    m_test_drop_download = false;
}
//-----------------------------------------------------------------------------------------------
void core::test_drop_download_height(uint64_t height) {
    m_test_drop_download_height = height;
}
//-----------------------------------------------------------------------------------------------
bool core::get_test_drop_download() const {
    return m_test_drop_download;
}
//-----------------------------------------------------------------------------------------------
bool core::get_test_drop_download_height() const {
    if (m_test_drop_download_height == 0)
        return true;

    if (blockchain.get_current_blockchain_height() <= m_test_drop_download_height)
        return true;

    return false;
}
//-----------------------------------------------------------------------------------------------
void core::parse_incoming_tx_pre(tx_verification_batch_info& tx_info) {
    if (tx_info.blob->size() > MAX_TX_SIZE) {
        log::info(
                logcat, "WRONG TRANSACTION BLOB, too big size {}, rejected", tx_info.blob->size());
        tx_info.tvc.m_verifivation_failed = true;
        tx_info.tvc.m_too_big = true;
        return;
    } else if (tx_info.blob->empty()) {
        log::info(logcat, "WRONG TRANSACTION BLOB, blob is empty, rejected");
        tx_info.tvc.m_verifivation_failed = true;
        return;
    }

    tx_info.parsed = parse_and_validate_tx_from_blob(*tx_info.blob, tx_info.tx, tx_info.tx_hash);
    if (!tx_info.parsed) {
        log::info(logcat, "WRONG TRANSACTION BLOB, Failed to parse, rejected");
        tx_info.tvc.m_verifivation_failed = true;
        return;
    }
    // std::cout << "!"<< tx.vin.size() << std::endl;

    std::lock_guard lock{bad_semantics_txes_lock};
    for (int idx = 0; idx < 2; ++idx) {
        if (bad_semantics_txes[idx].find(tx_info.tx_hash) != bad_semantics_txes[idx].end()) {
            log::info(logcat, "Transaction already seen with bad semantics, rejected");
            tx_info.tvc.m_verifivation_failed = true;
            return;
        }
    }
    tx_info.result = true;
}
//-----------------------------------------------------------------------------------------------
void core::set_semantics_failed(const crypto::hash& tx_hash) {
    log::info(logcat, "WRONG TRANSACTION BLOB, Failed to check tx {} semantic, rejected", tx_hash);
    bad_semantics_txes_lock.lock();
    bad_semantics_txes[0].insert(tx_hash);
    if (bad_semantics_txes[0].size() >= BAD_SEMANTICS_TXES_MAX_SIZE) {
        std::swap(bad_semantics_txes[0], bad_semantics_txes[1]);
        bad_semantics_txes[0].clear();
    }
    bad_semantics_txes_lock.unlock();
}
//-----------------------------------------------------------------------------------------------
static bool is_canonical_bulletproof_layout(const std::vector<rct::Bulletproof>& proofs) {
    if (proofs.size() != 1)
        return false;
    const size_t sz = proofs[0].V.size();
    if (sz == 0 || sz > TX_BULLETPROOF_MAX_OUTPUTS)
        return false;
    return true;
}
//-----------------------------------------------------------------------------------------------
void core::parse_incoming_tx_accumulated_batch(
        std::vector<tx_verification_batch_info>& tx_info, bool kept_by_block) {
    if (kept_by_block && blockchain.is_within_compiled_block_hash_area()) {
        log::trace(logcat, "Skipping semantics check for txs kept by block in embedded hash area");
        return;
    }

    std::vector<const rct::rctSig*> rvv;
    for (size_t n = 0; n < tx_info.size(); ++n) {
        if (!tx_info[n].result || tx_info[n].already_have)
            continue;

        if (!check_tx_semantic(tx_info[n].tx, kept_by_block)) {
            set_semantics_failed(tx_info[n].tx_hash);
            tx_info[n].tvc.m_verifivation_failed = true;
            tx_info[n].result = false;
            continue;
        }

        if (!tx_info[n].tx.is_transfer())
            continue;
        const rct::rctSig& rv = tx_info[n].tx.rct_signatures;
        switch (rv.type) {
            case rct::RCTType::Null:
                // coinbase should not come here, so we reject for all other types
                log::error(log::Cat("verify"), "Unexpected Null rctSig type");
                set_semantics_failed(tx_info[n].tx_hash);
                tx_info[n].tvc.m_verifivation_failed = true;
                tx_info[n].result = false;
                break;
            case rct::RCTType::Simple:
                if (!rct::verRctSemanticsSimple(rv)) {
                    log::error(log::Cat("verify"), "rct signature semantics check failed");
                    set_semantics_failed(tx_info[n].tx_hash);
                    tx_info[n].tvc.m_verifivation_failed = true;
                    tx_info[n].result = false;
                    break;
                }
                break;
            case rct::RCTType::Full:
                if (!rct::verRct(rv, true)) {
                    log::error(log::Cat("verify"), "rct signature semantics check failed");
                    set_semantics_failed(tx_info[n].tx_hash);
                    tx_info[n].tvc.m_verifivation_failed = true;
                    tx_info[n].result = false;
                    break;
                }
                break;
            case rct::RCTType::Bulletproof:
            case rct::RCTType::Bulletproof2:
            case rct::RCTType::CLSAG:
                if (!is_canonical_bulletproof_layout(rv.p.bulletproofs)) {
                    log::error(log::Cat("verify"), "Bulletproof does not have canonical form");
                    set_semantics_failed(tx_info[n].tx_hash);
                    tx_info[n].tvc.m_verifivation_failed = true;
                    tx_info[n].result = false;
                    break;
                }
                rvv.push_back(&rv);  // delayed batch verification
                break;
            default:
                log::error(log::Cat("verify"), "Unknown rct type: {}", (int)rv.type);
                set_semantics_failed(tx_info[n].tx_hash);
                tx_info[n].tvc.m_verifivation_failed = true;
                tx_info[n].result = false;
                break;
        }
    }
    if (!rvv.empty() && !rct::verRctSemanticsSimple(rvv)) {
        log::info(
                logcat,
                "One transaction among this group has bad semantics, verifying one at a time");
        const bool assumed_bad = rvv.size() == 1;  // if there's only one tx, it must be the bad one
        for (size_t n = 0; n < tx_info.size(); ++n) {
            if (!tx_info[n].result || tx_info[n].already_have)
                continue;
            if (!rct::is_rct_bulletproof(tx_info[n].tx.rct_signatures.type))
                continue;
            if (assumed_bad || !rct::verRctSemanticsSimple(tx_info[n].tx.rct_signatures)) {
                set_semantics_failed(tx_info[n].tx_hash);
                tx_info[n].tvc.m_verifivation_failed = true;
                tx_info[n].result = false;
            }
        }
    }
}
//-----------------------------------------------------------------------------------------------
std::vector<cryptonote::tx_verification_batch_info> core::parse_incoming_txs(
        const std::vector<std::string>& tx_blobs, const tx_pool_options& opts) {
    // Caller needs to do this around both this *and* handle_parsed_txs
    // auto lock = incoming_tx_lock();
    std::vector<cryptonote::tx_verification_batch_info> tx_info(tx_blobs.size());

    tools::threadpool& tpool = tools::threadpool::getInstance();
    tools::threadpool::waiter waiter;
    for (size_t i = 0; i < tx_blobs.size(); i++) {
        tx_info[i].blob = &tx_blobs[i];
        tpool.submit(&waiter, [this, &info = tx_info[i]] {
            try {
                parse_incoming_tx_pre(info);
            } catch (const std::exception& e) {
                log::error(log::Cat("verify"), "Exception in handle_incoming_tx_pre: {}", e.what());
                info.tvc.m_verifivation_failed = true;
            }
        });
    }
    waiter.wait(&tpool);

    for (auto& info : tx_info) {
        if (!info.result)
            continue;

        if (mempool.have_tx(info.tx_hash)) {
            log::debug(logcat, "tx {} already has a transaction in tx_pool", info.tx_hash);
            info.already_have = true;
        } else if (blockchain.have_tx(info.tx_hash)) {
            log::debug(logcat, "tx {} already has a transaction in tx_pool", info.tx_hash);
            info.already_have = true;
        }
    }

    parse_incoming_tx_accumulated_batch(tx_info, opts.kept_by_block);

    return tx_info;
}

bool core::handle_parsed_txs(
        std::vector<tx_verification_batch_info>& parsed_txs,
        const tx_pool_options& opts,
        uint64_t* blink_rollback_height) {
    // Caller needs to do this around both this *and* parse_incoming_txs
    // auto lock = incoming_tx_lock();
    auto version = blockchain.get_network_version();
    bool ok = true;
    if (blink_rollback_height)
        *blink_rollback_height = 0;
    tx_pool_options tx_opts;
    for (size_t i = 0; i < parsed_txs.size(); i++) {
        auto& info = parsed_txs[i];
        if (!info.result) {
            ok = false;  // Propagate failures (so this can be chained with parse_incoming_txs
                         // without an intermediate check)
            continue;
        }
        if (opts.kept_by_block)
            blockchain.on_new_tx_from_block(info.tx);
        if (info.already_have)
            continue;  // Not a failure

        const size_t weight = get_transaction_weight(info.tx, info.blob->size());
        const tx_pool_options* local_opts = &opts;
        if (blink_rollback_height && info.approved_blink) {
            // If this is an approved blink then pass a copy of the options with the flag added
            tx_opts = opts;
            tx_opts.approved_blink = true;
            local_opts = &tx_opts;
        }
        if (mempool.add_tx(
                    info.tx,
                    info.tx_hash,
                    *info.blob,
                    weight,
                    info.tvc,
                    *local_opts,
                    version,
                    blink_rollback_height)) {
            log::debug(logcat, "tx added: {}", info.tx_hash);
        } else {
            ok = false;
            if (info.tvc.m_duplicate_nonstandard)
                log::debug(
                        log::Cat("verify"),
                        "Transaction is a duplicate non-standard tx (e.g. state change)");
            else if (info.tvc.m_verifivation_failed)
                log::error(log::Cat("verify"), "Transaction verification failed: {}", info.tx_hash);
            else if (info.tvc.m_verifivation_impossible)
                log::error(
                        log::Cat("verify"),
                        "Transaction verification impossible: {}",
                        info.tx_hash);
        }
    }

    return ok;
}
//-----------------------------------------------------------------------------------------------
std::vector<cryptonote::tx_verification_batch_info> core::handle_incoming_txs(
        const std::vector<std::string>& tx_blobs, const tx_pool_options& opts) {
    auto lock = incoming_tx_lock();
    auto parsed = parse_incoming_txs(tx_blobs, opts);
    handle_parsed_txs(parsed, opts);
    return parsed;
}
//-----------------------------------------------------------------------------------------------
bool core::handle_incoming_tx(
        const std::string& tx_blob, tx_verification_context& tvc, const tx_pool_options& opts) {
    const std::vector<std::string> tx_blobs{{tx_blob}};
    auto parsed = handle_incoming_txs(tx_blobs, opts);
    parsed[0].blob = &tx_blob;  // Update pointer to the input rather than the copy in case the
                                // caller wants to use it for some reason
    tvc = parsed[0].tvc;
    return parsed[0].result && (parsed[0].already_have || tvc.m_added_to_pool);
}
//-----------------------------------------------------------------------------------------------
std::pair<std::vector<std::shared_ptr<blink_tx>>, std::unordered_set<crypto::hash>>
core::parse_incoming_blinks(const std::vector<serializable_blink_metadata>& blinks) {
    std::pair<std::vector<std::shared_ptr<blink_tx>>, std::unordered_set<crypto::hash>> results;
    auto& new_blinks = results.first;
    auto& missing_txs = results.second;

    if (blockchain.get_network_version() < feature::BLINK)
        return results;

    std::vector<uint8_t> want(
            blinks.size(), false);  // Really bools, but std::vector<bool> is broken.
    size_t want_count = 0;
    // Step 1: figure out which referenced transactions we want to keep:
    // - unknown tx (typically an incoming blink)
    // - in mempool without blink sigs (it's possible to get the tx before the blink signatures)
    // - in a recent, still-mutable block with blink sigs (can happen when syncing blocks before
    // retrieving blink signatures)
    {
        std::vector<crypto::hash> hashes;
        hashes.reserve(blinks.size());
        for (auto& bm : blinks)
            hashes.emplace_back(bm.tx_hash);

        std::unique_lock<Blockchain> lock(blockchain);

        auto tx_block_heights = blockchain.get_transactions_heights(hashes);
        auto immutable_height = blockchain.get_immutable_height();
        for (size_t i = 0; i < blinks.size(); i++) {
            if (tx_block_heights[i] == 0 /*mempool or unknown*/ ||
                tx_block_heights[i] > immutable_height /*mined but not yet immutable*/) {
                want[i] = true;
                want_count++;
            }
        }
    }

    log::debug(
            logcat,
            "Want {} of {} incoming blink signature sets after filtering out immutable txes",
            want_count,
            blinks.size());
    if (!want_count)
        return results;

    // Step 2: filter out any transactions for which we already have a blink signature
    {
        auto mempool_lock = mempool.blink_shared_lock();
        for (size_t i = 0; i < blinks.size(); i++) {
            if (want[i] && mempool.has_blink(blinks[i].tx_hash)) {
                log::debug(
                        logcat,
                        "Ignoring blink data for {}: already have blink signatures",
                        blinks[i].tx_hash);
                want[i] = false;  // Already have it, move along
                want_count--;
            }
        }
    }

    log::debug(
            logcat,
            "Want {} of {} incoming blink signature sets after filtering out existing blink sigs",
            want_count,
            blinks.size());
    if (!want_count)
        return results;

    // Step 3: create new blink_tx objects for txes and add the blink signatures.  We can do all of
    // this without a lock since these are (for now) just local instances.
    new_blinks.reserve(want_count);

    std::unordered_map<uint64_t, std::shared_ptr<const service_nodes::quorum>> quorum_cache;
    for (size_t i = 0; i < blinks.size(); i++) {
        if (!want[i])
            continue;
        auto& bdata = blinks[i];
        new_blinks.push_back(std::make_shared<blink_tx>(bdata.height, bdata.tx_hash));
        auto& blink = *new_blinks.back();

        // Data structure checks (we have more stringent checks for validity later, but if these
        // fail now then there's no point of even trying to do signature validation.
        if (bdata.signature.size() !=
                    bdata.position
                            .size() ||  // Each signature must have an associated quorum position
            bdata.signature.size() != bdata.quorum.size() ||  // and quorum index
            bdata.signature.size() <
                    service_nodes::BLINK_MIN_VOTES *
                            tools::enum_count<blink_tx::subquorum> ||  // too few signatures for
                                                                       // possible validity
            bdata.signature.size() >
                    service_nodes::BLINK_SUBQUORUM_SIZE *
                            tools::enum_count<blink_tx::subquorum> ||  // too many signatures
            blink_tx::quorum_height(bdata.height, blink_tx::subquorum::base) ==
                    0 ||  // Height is too early (no blink quorum height)
            std::any_of(
                    bdata.position.begin(),
                    bdata.position.end(),
                    [](const auto& p) {
                        return p >= service_nodes::BLINK_SUBQUORUM_SIZE;
                    }) ||  // invalid position
            std::any_of(
                    bdata.quorum.begin(),
                    bdata.quorum.end(),
                    [](const auto& qi) {
                        return qi >= tools::enum_count<blink_tx::subquorum>;
                    })  // invalid quorum index
        ) {
            log::info(logcat, "Invalid blink tx {}: invalid signature data", bdata.tx_hash);
            continue;
        }

        bool no_quorum = false;
        std::array<const std::vector<crypto::public_key>*, tools::enum_count<blink_tx::subquorum>>
                validators;
        for (uint8_t qi = 0; qi < tools::enum_count<blink_tx::subquorum>; qi++) {
            auto q_height = blink.quorum_height(static_cast<blink_tx::subquorum>(qi));
            auto& q = quorum_cache[q_height];
            if (!q)
                q = service_node_list.get_quorum(service_nodes::quorum_type::blink, q_height);
            if (!q) {
                log::trace(
                        logcat,
                        "Don't have a quorum for height {} (yet?), ignoring this blink",
                        q_height);
                no_quorum = true;
                break;
            }
            validators[qi] = &q->validators;
        }
        if (no_quorum)
            continue;

        std::vector<std::pair<size_t, std::string>> failures;
        for (size_t s = 0; s < bdata.signature.size(); s++) {
            try {
                blink.add_signature(
                        static_cast<blink_tx::subquorum>(bdata.quorum[s]),
                        bdata.position[s],
                        true /*approved*/,
                        bdata.signature[s],
                        validators[bdata.quorum[s]]->at(bdata.position[s]));
            } catch (const std::exception& e) {
                failures.emplace_back(s, e.what());
            }
        }
        if (blink.approved()) {
            log::info(
                    logcat,
                    "Blink tx {} blink signatures approved with {} signature validation failures",
                    bdata.tx_hash,
                    failures.size());
            for (auto& f : failures)
                log::debug(
                        logcat,
                        "- failure for quorum {}, position {}: {}",
                        int(bdata.quorum[f.first]),
                        int(bdata.position[f.first]),
                        f.second);
        } else {
            std::string blink_error = "Blink validation failed:";
            auto append = std::back_inserter(blink_error);
            for (auto& f : failures)
                fmt::format_to(
                        append,
                        " [{}:{}]: {}",
                        int(bdata.quorum[f.first]),
                        int(bdata.position[f.first]),
                        f.second);
            log::info(logcat, "Invalid blink tx {}: {}", bdata.tx_hash, blink_error);
        }
    }

    return results;
}

int core::add_blinks(const std::vector<std::shared_ptr<blink_tx>>& blinks) {
    int added = 0;
    if (blinks.empty())
        return added;

    auto lock = mempool.blink_unique_lock();

    for (auto& b : blinks)
        if (b->approved())
            if (mempool.add_existing_blink(b))
                added++;

    if (added) {
        log::info(logcat, "Added blink signatures for {} blinks", added);
        long_poll_trigger(mempool);
    }

    return added;
}

//-----------------------------------------------------------------------------------------------
std::future<std::pair<blink_result, std::string>> core::handle_blink_tx(
        const std::string& tx_blob) {
    return quorumnet_send_blink(*this, tx_blob);
}
//-----------------------------------------------------------------------------------------------
bool core::check_tx_semantic(const transaction& tx, bool keeped_by_block) const {
    if (tx.is_transfer()) {
        if (tx.vin.empty()) {
            log::error(
                    log::Cat("verify"),
                    "tx with empty inputs, rejected for tx id= {}",
                    get_transaction_hash(tx));
            return false;
        }
    } else {
        if (tx.vin.size() != 0) {
            log::error(
                    log::Cat("verify"),
                    "tx type: {} must have 0 inputs, received: {}, rejected for tx id = {}",
                    tx.type,
                    tx.vin.size(),
                    get_transaction_hash(tx));
            return false;
        }
    }

    if (!check_inputs_types_supported(tx)) {
        log::error(
                log::Cat("verify"),
                "unsupported input types for tx id= {}",
                get_transaction_hash(tx));
        return false;
    }

    if (!check_outs_valid(tx)) {
        log::error(
                log::Cat("verify"),
                "tx with invalid outputs, rejected for tx id= {}",
                get_transaction_hash(tx));
        return false;
    }

    if (tx.version >= txversion::v2_ringct) {
        if (tx.rct_signatures.outPk.size() != tx.vout.size()) {
            log::error(
                    log::Cat("verify"),
                    "tx with mismatched vout/outPk count, rejected for tx id= {}",
                    get_transaction_hash(tx));
            return false;
        }
    }

    if (!check_money_overflow(tx)) {
        log::error(
                log::Cat("verify"),
                "tx has money overflow, rejected for tx id= {}",
                get_transaction_hash(tx));
        return false;
    }

    if (tx.version == txversion::v1) {
        uint64_t amount_in = 0;
        get_inputs_money_amount(tx, amount_in);
        uint64_t amount_out = get_outs_money_amount(tx);

        if (amount_in <= amount_out) {
            log::error(
                    log::Cat("verify"),
                    "tx with wrong amounts: ins {}, outs {}, rejected for tx id= {}",
                    amount_in,
                    amount_out,
                    get_transaction_hash(tx));
            return false;
        }
    }

    if (!keeped_by_block &&
        get_transaction_weight(tx) >= blockchain.get_current_cumulative_block_weight_limit() -
                                              COINBASE_BLOB_RESERVED_SIZE) {
        log::error(
                log::Cat("verify"),
                "tx is too large {}, expected not bigger than {}",
                get_transaction_weight(tx),
                blockchain.get_current_cumulative_block_weight_limit() -
                        COINBASE_BLOB_RESERVED_SIZE);
        return false;
    }

    if (!check_tx_inputs_keyimages_diff(tx)) {
        log::error(log::Cat("verify"), "tx uses a single key image more than once");
        return false;
    }

    if (!check_tx_inputs_ring_members_diff(tx)) {
        log::error(log::Cat("verify"), "tx uses duplicate ring members");
        return false;
    }

    if (!check_tx_inputs_keyimages_domain(tx)) {
        log::error(log::Cat("verify"), "tx uses key image not in the valid domain");
        return false;
    }

    return true;
}
//-----------------------------------------------------------------------------------------------
void core::check_service_node_ip_address() {
    if (!is_active_sn()) {
        return;
    }

    auto service_node_pubkey = m_service_keys.pub;
    std::array<uint16_t, 3> proof_version{};

    service_node_list.access_proof(service_node_pubkey, [&](auto& proof) {
        proof_version = proof.proof->version;
    });

    constexpr std::array<uint16_t, 3> MIN_TIMESTAMP_VERSION{9, 1, 0};

    if (proof_version < MIN_TIMESTAMP_VERSION) {
        return;
    }

    m_omq->request(
            tools::view_guts(m_service_keys.pub_x25519),
            "ping.ping",
            [](bool success, const std::vector<std::string>& data) {
                if (!success || data.empty())
                    log::warning(
                            logcat, "Unable to reach configured service node IP!");
            });
}
//-----------------------------------------------------------------------------------------------
bool core::check_service_node_time() {
    if (!is_active_sn()) {
        return true;
    }

    crypto::public_key pubkey = service_node_list.get_random_pubkey();
    crypto::x25519_public_key x_pkey{0};
    constexpr std::array<uint16_t, 3> MIN_TIMESTAMP_VERSION{9, 1, 0};
    std::array<uint16_t, 3> proofversion;
    service_node_list.access_proof(pubkey, [&](auto& proof) {
        x_pkey = proof.pubkey_x25519;
        proofversion = proof.proof->version;
    });

    if (proofversion >= MIN_TIMESTAMP_VERSION && x_pkey) {
        m_omq->request(
                tools::view_guts(x_pkey),
                "quorum.timestamp",
                [this, pubkey](bool success, std::vector<std::string> data) {
                    const time_t local_seconds = time(nullptr);
                    log::debug(
                            logcat,
                            "Timestamp message received: {}, local time is: ",
                            data[0],
                            local_seconds);
                    if (success) {
                        int64_t received_seconds;
                        if (tools::parse_int(data[0], received_seconds)) {
                            uint16_t variance;
                            if (received_seconds > local_seconds + 65535 ||
                                received_seconds < local_seconds - 65535) {
                                variance = 65535;
                            } else {
                                variance = std::abs(local_seconds - received_seconds);
                            }
                            std::lock_guard<std::mutex> lk(m_sn_timestamp_mutex);
                            // Records the variance into the record of our performance (m_sn_times)
                            service_nodes::timesync_entry entry{
                                    variance <= service_nodes::THRESHOLD_SECONDS_OUT_OF_SYNC};
                            m_sn_times.add(entry);

                            // Counts the number of times we have been out of sync
                            if (m_sn_times.failures() >
                                (m_sn_times.size() * service_nodes::MAXIMUM_EXTERNAL_OUT_OF_SYNC /
                                 100)) {
                                log::warning(logcat, "service node time might be out of sync");
                                // If we are out of sync record the other service node as in sync
                                service_node_list.record_timesync_status(pubkey, true);
                            } else {
                                service_node_list.record_timesync_status(
                                        pubkey,
                                        variance <= service_nodes::THRESHOLD_SECONDS_OUT_OF_SYNC);
                            }
                        } else {
                            success = false;
                        }
                    }
                    service_node_list.record_timestamp_participation(pubkey, success);
                });
    }
    return true;
}
//-----------------------------------------------------------------------------------------------
bool core::is_key_image_spent(const crypto::key_image& key_image) const {
    return blockchain.have_tx_keyimg_as_spent(key_image);
}
//-----------------------------------------------------------------------------------------------
bool core::are_key_images_spent(
        const std::vector<crypto::key_image>& key_im, std::vector<bool>& spent) const {
    spent.clear();
    for (auto& ki : key_im) {
        spent.push_back(blockchain.have_tx_keyimg_as_spent(ki));
    }
    return true;
}
//-----------------------------------------------------------------------------------------------
size_t core::get_block_sync_size(uint64_t height) const {
    return block_sync_size > 0 ? block_sync_size : BLOCKS_SYNCHRONIZING_DEFAULT_COUNT;
}
//-----------------------------------------------------------------------------------------------
bool core::are_key_images_spent_in_pool(
        const std::vector<crypto::key_image>& key_im, std::vector<bool>& spent) const {
    spent.clear();

    return mempool.check_for_key_images(key_im, spent);
}
//-----------------------------------------------------------------------------------------------
std::optional<std::tuple<int64_t, int64_t, int64_t>> core::get_coinbase_tx_sum(
        uint64_t start_offset, size_t count) {
    std::optional<std::tuple<int64_t, int64_t, int64_t>> result{{0, 0, 0}};
    if (count == 0)
        return result;

    auto& [emission_amount, total_fee_amount, burnt_oxen] = *result;

    // Caching.
    //
    // Requesting this value from the beginning of the chain is very slow, so we cache it.  That
    // still means the first request will be slow, but that's okay.  To prevent a bunch of threads
    // getting backed up trying to calculate this, we lock out more than one thread building the
    // cache at a time if we're requesting a large number of block values at once.  Any other thread
    // requesting will get a nullopt back.

    constexpr uint64_t CACHE_LAG = 30;  // We cache the values up to this many blocks ago; we lag so
                                        // that we don't have to worry about small reorgs
    constexpr uint64_t CACHE_EXCLUSIVE =
            1000;  // If we need to load more than this, we block out other threads

    // Check if we have a cacheable from-the-beginning result
    uint64_t cache_to = 0;
    std::chrono::steady_clock::time_point cache_build_started;
    if (start_offset == 0) {
        uint64_t height = blockchain.get_current_blockchain_height();
        if (count > height)
            count = height;
        cache_to = height - std::min(CACHE_LAG, height);
        {
            std::shared_lock lock{m_coinbase_cache.mutex};
            if (m_coinbase_cache.height && count >= m_coinbase_cache.height) {
                emission_amount = m_coinbase_cache.emissions;
                total_fee_amount = m_coinbase_cache.fees;
                burnt_oxen = m_coinbase_cache.burnt;
                start_offset = m_coinbase_cache.height + 1;
                count -= m_coinbase_cache.height;
            }
            // else don't change anything; we need a subset of blocks that ends before the cache.

            if (cache_to <= m_coinbase_cache.height)
                cache_to = 0;  // Cache doesn't need updating
        }

        // If we're loading a lot then acquire an exclusive lock, recheck our variables, and block
        // out other threads until we're done.  (We don't do this if we're only loading a few
        // because even if we have some competing cache updates they don't hurt anything).
        if (cache_to > 0 && count > CACHE_EXCLUSIVE) {
            std::unique_lock lock{m_coinbase_cache.mutex};
            if (m_coinbase_cache.building)
                return std::nullopt;  // Another thread is already updating the cache

            if (m_coinbase_cache.height && m_coinbase_cache.height >= start_offset) {
                // Someone else updated the cache while we were acquiring the unique lock, so update
                // our variables
                if (m_coinbase_cache.height >= start_offset + count) {
                    // The cache is now *beyond* us, which means we can't use it, so reset
                    // start/count back to what they were originally.
                    count += start_offset - 1;
                    start_offset = 0;
                    cache_to = 0;
                } else {
                    // The cache is updated and we can still use it, so update our variables.
                    emission_amount = m_coinbase_cache.emissions;
                    total_fee_amount = m_coinbase_cache.fees;
                    burnt_oxen = m_coinbase_cache.burnt;
                    count -= m_coinbase_cache.height - start_offset + 1;
                    start_offset = m_coinbase_cache.height + 1;
                }
            }
            if (cache_to > 0 && count > CACHE_EXCLUSIVE) {
                cache_build_started = std::chrono::steady_clock::now();
                m_coinbase_cache.building = true;  // Block out other threads until we're done
                log::info(
                        logcat,
                        "Starting slow cache build request for get_coinbase_tx_sum({}, {})",
                        start_offset,
                        count);
            }
        }
    }

    const uint64_t end = start_offset + count - 1;
    blockchain.for_blocks_range(
            start_offset,
            end,
            [this, &cache_to, &result, &cache_build_started](
                    uint64_t height, const crypto::hash& hash, const block& b) {
                auto& [emission_amount, total_fee_amount, burnt_oxen] = *result;
                std::vector<transaction> txs;
                auto coinbase_amount = static_cast<int64_t>(get_outs_money_amount(b.miner_tx));
                blockchain.get_transactions(b.tx_hashes, txs);
                int64_t tx_fee_amount = 0;
                for (const auto& tx : txs) {
                    tx_fee_amount += static_cast<int64_t>(
                            get_tx_miner_fee(tx, b.major_version >= feature::FEE_BURNING));
                    if (b.major_version >= feature::FEE_BURNING) {
                        burnt_oxen +=
                                static_cast<int64_t>(get_burned_amount_from_tx_extra(tx.extra));
                    }
                }

                emission_amount += coinbase_amount - tx_fee_amount;
                total_fee_amount += tx_fee_amount;
                if (cache_to && cache_to == height) {
                    std::unique_lock lock{m_coinbase_cache.mutex};
                    if (m_coinbase_cache.height < height) {
                        m_coinbase_cache.height = height;
                        m_coinbase_cache.emissions = emission_amount;
                        m_coinbase_cache.fees = total_fee_amount;
                        m_coinbase_cache.burnt = burnt_oxen;
                    }
                    if (m_coinbase_cache.building) {
                        m_coinbase_cache.building = false;
                        log::info(
                                logcat,
                                "Finishing cache build for get_coinbase_tx_sum in {} s",
                                dseconds{std::chrono::steady_clock::now() - cache_build_started}
                                        .count());
                    }
                    cache_to = 0;
                }
                return true;
            });

    return result;
}
//-----------------------------------------------------------------------------------------------
bool core::check_tx_inputs_keyimages_diff(const transaction& tx) const {
    std::unordered_set<crypto::key_image> ki;
    for (const auto& in : tx.vin) {
        CHECKED_GET_SPECIFIC_VARIANT(in, txin_to_key, tokey_in, false);
        if (!ki.insert(tokey_in.k_image).second)
            return false;
    }
    return true;
}
//-----------------------------------------------------------------------------------------------
bool core::check_tx_inputs_ring_members_diff(const transaction& tx) const {
    const auto version = blockchain.get_network_version();
    for (const auto& in : tx.vin) {
        CHECKED_GET_SPECIFIC_VARIANT(in, txin_to_key, tokey_in, false);
        for (size_t n = 1; n < tokey_in.key_offsets.size(); ++n)
            if (tokey_in.key_offsets[n] == 0)
                return false;
    }
    return true;
}
//-----------------------------------------------------------------------------------------------
bool core::check_tx_inputs_keyimages_domain(const transaction& tx) const {
    std::unordered_set<crypto::key_image> ki;
    for (const auto& in : tx.vin) {
        CHECKED_GET_SPECIFIC_VARIANT(in, txin_to_key, tokey_in, false);
        if (!(rct::scalarmultKey(rct::ki2rct(tokey_in.k_image), rct::curveOrder()) ==
              rct::identity()))
            return false;
    }
    return true;
}
//-----------------------------------------------------------------------------------------------
bool core::relay_txpool_transactions() {
    // we attempt to relay txes that should be relayed, but were not
    std::vector<std::pair<crypto::hash, std::string>> txs;
    if (mempool.get_relayable_transactions(txs) && !txs.empty()) {
        cryptonote_connection_context fake_context{};
        tx_verification_context tvc{};
        NOTIFY_NEW_TRANSACTIONS::request r{};
        for (auto it = txs.begin(); it != txs.end(); ++it) {
            r.txs.push_back(it->second);
        }
        get_protocol()->relay_transactions(r, fake_context);
        mempool.set_relayed(txs);
    }
    return true;
}
//-----------------------------------------------------------------------------------------------
bool core::submit_uptime_proof() {
    if (!m_service_node)
        return true;

    assert(m_bls_signer && "Service Nodes have a BLS signer defined");
    try {
        cryptonote_connection_context fake_context{};
        bool relayed;
        auto height = blockchain.get_current_blockchain_height();
        auto hf_version = get_network_version(m_nettype, height);

        auto proof = service_node_list.generate_uptime_proof(
                hf_version,
                m_sn_public_ip,
                storage_https_port(),
                storage_omq_port(),
                ss_version,
                m_quorumnet_port,
                lokinet_version,
                *m_bls_signer);
        auto req = proof.generate_request(hf_version);
        relayed = get_protocol()->relay_uptime_proof(req, fake_context);

        if (relayed)
            log::info(
                    globallogcat,
                    fg(fmt::terminal_color::cyan),
                    "Submitted uptime-proof for Service Node (yours): {}",
                    m_service_keys.pub);
    } catch (const std::exception& e) {
        log::error(logcat, "Failed to generate/submit uptime proof: {}", e.what());
        return false;
    }
    return true;
}
//-----------------------------------------------------------------------------------------------
bool core::handle_uptime_proof(
        const NOTIFY_BTENCODED_UPTIME_PROOF::request& req, bool& my_uptime_proof_confirmation) {
    std::unique_ptr<uptime_proof::Proof> proof;
    try {
        proof = std::make_unique<uptime_proof::Proof>(
                get_network_version(m_nettype, blockchain.get_current_blockchain_height()),
                req.proof);

        // devnet/stagenet don't have storage server or lokinet, so these should be 0; everywhere
        // else they should be non-zero.
        if (!get_config(m_nettype).HAVE_STORAGE_AND_LOKINET) {
            if (proof->storage_omq_port != 0 || proof->storage_https_port != 0)
                throw oxen::traced<std::runtime_error>{
                        "Invalid storage port(s) in proof: devnet storage ports must be 0"};
        } else {
            if (proof->storage_omq_port == 0 || proof->storage_https_port == 0)
                throw oxen::traced<std::runtime_error>{
                        "Invalid storage port(s) in proof: storage ports cannot be 0"};
        }

    } catch (const std::exception& e) {
        log::warning(logcat, "Service node proof deserialization failed: {}", e.what());
        return false;
    }

    if (req.sig)
        proof->sig = tools::make_from_guts<crypto::signature>(*req.sig);
    else
        proof->sig = crypto::null<crypto::signature>;
    proof->sig_ed25519 = tools::make_from_guts<crypto::ed25519_signature>(req.ed_sig);
    auto pubkey = proof->pubkey;
    crypto::x25519_public_key x_pkey{};
    bool result = service_node_list.handle_uptime_proof(
            std::move(proof), my_uptime_proof_confirmation, x_pkey);
    if (result && service_node_list.is_service_node(pubkey, true /*require_active*/) && x_pkey) {
        oxenmq::pubkey_set added;
        added.insert(tools::copy_guts(x_pkey));
        m_omq->update_active_sns(added, {} /*removed*/);
    }
    return result;
}
//-----------------------------------------------------------------------------------------------
crypto::hash core::on_transaction_relayed(const std::string& tx_blob) {
    std::vector<std::pair<crypto::hash, std::string>> txs;
    cryptonote::transaction tx;
    crypto::hash tx_hash;
    if (!parse_and_validate_tx_from_blob(tx_blob, tx, tx_hash)) {
        log::error(logcat, "Failed to parse relayed transaction");
        return crypto::null<crypto::hash>;
    }
    txs.push_back(std::make_pair(tx_hash, std::move(tx_blob)));
    mempool.set_relayed(txs);
    return tx_hash;
}
//-----------------------------------------------------------------------------------------------
bool core::relay_service_node_votes() {
    auto height = blockchain.get_current_blockchain_height();
    auto hf_version = get_network_version(m_nettype, height);

    auto quorum_votes = m_quorum_cop.get_relayable_votes(height, hf_version, true);
    auto p2p_votes = m_quorum_cop.get_relayable_votes(height, hf_version, false);
    if (!quorum_votes.empty() && m_quorumnet_state && m_service_node)
        quorumnet_relay_obligation_votes(m_quorumnet_state, quorum_votes);

    if (!p2p_votes.empty()) {
        NOTIFY_NEW_SERVICE_NODE_VOTE::request req{};
        req.votes = std::move(p2p_votes);
        cryptonote_connection_context fake_context{};
        get_protocol()->relay_service_node_votes(req, fake_context);
    }

    return true;
}
void core::set_service_node_votes_relayed(const std::vector<service_nodes::quorum_vote_t>& votes) {
    m_quorum_cop.set_votes_relayed(votes);
}
//-----------------------------------------------------------------------------------------------
block_complete_entry get_block_complete_entry(block& b, tx_memory_pool& pool) {
    block_complete_entry bce = {};
    bce.block = cryptonote::block_to_blob(b);
    for (const auto& tx_hash : b.tx_hashes) {
        std::string txblob;
        if (!pool.get_transaction(tx_hash, txblob) || txblob.size() == 0) {
            oxen::log::error(logcat, "Transaction {} not found in pool", tx_hash);
            throw oxen::traced<std::runtime_error>("Transaction not found in pool");
        }
        bce.txs.push_back(txblob);
    }
    return bce;
}
//-----------------------------------------------------------------------------------------------
bool core::handle_block_found(block& b, block_verification_context& bvc) {
    bvc = {};
    std::vector<block_complete_entry> blocks;
    miner.pause();
    {
        OXEN_DEFER {
            miner.resume();
        };
        try {
            blocks.push_back(get_block_complete_entry(b, mempool));
        } catch (const std::exception& e) {
            return false;
        }
        std::vector<block> pblocks;
        if (!prepare_handle_incoming_blocks(blocks, pblocks)) {
            log::error(logcat, "Block found, but failed to prepare to add");
            return false;
        }
        // add_new_block will verify block and set bvc.m_verification_failed accordingly
        add_new_block(b, bvc, nullptr /*checkpoint*/);
        cleanup_handle_incoming_blocks(true);
        miner.on_block_chain_update();
    }

    if (bvc.m_verifivation_failed) {
        bool pulse = b.has_pulse();
        log::error(
                log::Cat("verify"),
                "{} block failed verification\n{}",
                (pulse ? "Pulse" : "Mined"),
                cryptonote::obj_to_json_str(b));
        return false;
    } else if (bvc.m_added_to_main_chain) {
        std::unordered_set<crypto::hash> missed_txs;
        std::vector<std::string> txs;
        blockchain.get_transactions_blobs(b.tx_hashes, txs, &missed_txs);
        if (missed_txs.size() &&
            blockchain.get_block_id_by_height(b.get_height()) != get_block_hash(b)) {
            log::info(
                    logcat,
                    "Block found but, seems that reorganize just happened after that, do not relay "
                    "this block");
            return true;
        }
        CHECK_AND_ASSERT_MES(
                txs.size() == b.tx_hashes.size() && !missed_txs.size(),
                false,
                "can't find some transactions in found block:{} txs.size()={}, "
                "b.tx_hashes.size()={}, missed_txs.size()={}",
                get_block_hash(b),
                txs.size(),
                b.tx_hashes.size(),
                missed_txs.size());

        cryptonote_connection_context exclude_context{};
        NOTIFY_NEW_FLUFFY_BLOCK::request arg{};
        arg.current_blockchain_height = blockchain.get_current_blockchain_height();
        arg.b = blocks[0];

        m_pprotocol->relay_block(arg, exclude_context);
    }
    return true;
}
//-----------------------------------------------------------------------------------------------
void core::on_synchronized() {
    miner.on_synchronized();
}
//-----------------------------------------------------------------------------------------------
void core::safesyncmode(const bool onoff) {
    blockchain.safesyncmode(onoff);
}
//-----------------------------------------------------------------------------------------------
bool core::add_new_block(
        const block& b, block_verification_context& bvc, checkpoint_t const* checkpoint) {
    bool result = blockchain.add_new_block(b, bvc, checkpoint);
    if (result)
        relay_service_node_votes();  // NOTE: nop if synchronising due to not accepting votes whilst
                                     // syncing
    return result;
}
//-----------------------------------------------------------------------------------------------
bool core::prepare_handle_incoming_blocks(
        const std::vector<block_complete_entry>& blocks_entry, std::vector<block>& blocks) {
    m_incoming_tx_lock.lock();
    if (!blockchain.prepare_handle_incoming_blocks(blocks_entry, blocks)) {
        cleanup_handle_incoming_blocks(false);
        return false;
    }
    return true;
}

//-----------------------------------------------------------------------------------------------
bool core::cleanup_handle_incoming_blocks(bool force_sync) {
    bool success = false;
    try {
        success = blockchain.cleanup_handle_incoming_blocks(force_sync);
    } catch (...) {
    }
    m_incoming_tx_lock.unlock();
    return success;
}

//-----------------------------------------------------------------------------------------------
bool core::handle_incoming_block(
        const std::string& block_blob,
        const block* b,
        block_verification_context& bvc,
        checkpoint_t* checkpoint,
        bool update_miner_blocktemplate) {
    TRY_ENTRY();
    bvc = {};

    // note: we assume block weight is always >= block blob size, so we check incoming
    // blob size against the block weight limit, which acts as a sanity check without
    // having to parse/weigh first; in fact, since the block blob is the block header
    // plus the tx hashes, the weight will typically be much larger than the blob size
    if (block_blob.size() >
        blockchain.get_current_cumulative_block_weight_limit() + BLOCK_SIZE_SANITY_LEEWAY) {
        log::info(
                logcat,
                "WRONG BLOCK BLOB, sanity check failed on size {}, rejected",
                block_blob.size());
        bvc.m_verifivation_failed = true;
        return false;
    }

    if (((size_t)-1) <= 0xffffffff && block_blob.size() >= 0x3fffffff)
        log::warning(
                logcat, "This block's size is {}, closing on the 32 bit limit", block_blob.size());

    CHECK_AND_ASSERT_MES(
            update_checkpoints_from_json_file(),
            false,
            "One or more checkpoints loaded from json conflicted with existing checkpoints.");

    block lb;
    if (!b) {
        crypto::hash block_hash;
        if (!parse_and_validate_block_from_blob(block_blob, lb, block_hash)) {
            log::info(logcat, "Failed to parse and validate new block");
            bvc.m_verifivation_failed = true;
            return false;
        }
        b = &lb;
    }

    add_new_block(*b, bvc, checkpoint);
    if (update_miner_blocktemplate && bvc.m_added_to_main_chain)
        miner.on_block_chain_update();
    return true;

    CATCH_ENTRY("core::handle_incoming_block()", false);
}

void core::update_omq_sns() {
    // TODO: let callers (e.g. lokinet, ss) subscribe to callbacks when this fires
    oxenmq::pubkey_set active_sns;
    service_node_list.copy_x25519_pubkeys(std::inserter(active_sns, active_sns.end()), m_nettype);
    m_omq->set_active_sns(std::move(active_sns));
}

static bool check_external_ping(
        time_t last_ping, std::chrono::seconds lifetime, std::string_view what) {
    const std::chrono::seconds elapsed{std::time(nullptr) - last_ping};
    if (elapsed > lifetime) {
        log::warning(
                logcat,
                "Have not heard from {} {}",
                what,
                (!last_ping ? "since starting"
                            : "since more than " + tools::get_human_readable_timespan(elapsed) +
                                      " ago"));
        return false;
    }
    return true;
}
void core::reset_proof_interval() {
    m_check_uptime_proof_interval.reset();
}
//-----------------------------------------------------------------------------------------------
void core::do_uptime_proof_call() {
    std::vector<service_nodes::service_node_pubkey_info> const states =
            service_node_list.get_service_node_list_state({m_service_keys.pub});

    // wait one block before starting uptime proofs (but not on testnet/devnet, where we sometimes
    // have mass registrations/deregistrations where the waiting causes problems).
    uint64_t delay_blocks = m_nettype == network_type::MAINNET ? 1 : 0;
    if (!states.empty() && (states[0].info->registration_height + delay_blocks) <
                                   blockchain.get_current_blockchain_height()) {
        m_check_uptime_proof_interval.do_call([this]() {
            // This timer is not perfectly precise and can leak seconds slightly, so send the uptime
            // proof if we are within half a tick of the target time.  (Essentially our target proof
            // window becomes the first time this triggers in the 59.75-60.25 minute window).
            uint64_t next_proof_time = 0;
            service_node_list.access_proof(
                    m_service_keys.pub, [&](auto& proof) { next_proof_time = proof.timestamp; });
            auto& netconf = get_net_config();
            next_proof_time +=
                    std::chrono::seconds{
                            netconf.UPTIME_PROOF_FREQUENCY -
                            netconf.UPTIME_PROOF_CHECK_INTERVAL / 2}
                            .count();

            if ((uint64_t)std::time(nullptr) < next_proof_time)
                return;

            auto pubkey = service_node_list.get_pubkey_from_x25519(m_service_keys.pub_x25519);
            if (pubkey && pubkey != m_service_keys.pub &&
                service_node_list.is_service_node(pubkey, false /*don't require active*/)) {
                log::error(
                        globallogcat,
                        fg(fmt::terminal_color::red) | fmt::emphasis::bold,
                        "Failed to submit uptime proof: another service node on the network is "
                        "using the same ed/x25519 keys as this service node. This typically means "
                        "both have the same 'key_ed25519' private key file.");
                return;
            }

            {
                std::vector<crypto::public_key> sn_pks;
                auto sns = service_node_list.get_service_node_list_state();
                sn_pks.reserve(sns.size());
                for (const auto& sni : sns)
                    sn_pks.push_back(sni.pubkey);

                service_node_list.for_each_service_node_info_and_proof(
                        sn_pks.begin(), sn_pks.end(), [&](auto& pk, auto& sni, auto& proof) {
                            if (pk != m_service_keys.pub &&
                                proof.proof->public_ip == m_sn_public_ip &&
                                (proof.proof->qnet_port == m_quorumnet_port ||
                                 (netconf.HAVE_STORAGE_AND_LOKINET &&
                                  (proof.proof->storage_https_port == storage_https_port() ||
                                   proof.proof->storage_omq_port == storage_omq_port()))))
                                log::error(
                                        globallogcat,
                                        fg(fmt::terminal_color::red) | fmt::emphasis::bold,
                                        "Another service node ({}) is broadcasting the same public "
                                        "IP and ports as this service node ({}:{}[qnet], "
                                        ":{}[SS-HTTP], :{}[SS-OMQ]). This will lead to "
                                        "deregistration of one or both service nodes if not "
                                        "corrected. (Do both service nodes have the correct IP for "
                                        "the service-node-public-ip setting?)",
                                        pk,
                                        epee::string_tools::get_ip_string_from_int32(
                                                m_sn_public_ip),
                                        proof.proof->qnet_port,
                                        proof.proof->storage_https_port,
                                        proof.proof->storage_omq_port);
                        });
            }

            if (netconf.HAVE_STORAGE_AND_LOKINET) {
                if (!check_external_ping(
                            m_last_storage_server_ping,
                            get_net_config().UPTIME_PROOF_FREQUENCY,
                            "the storage server")) {
                    log::error(
                            globallogcat,
                            fg(fmt::terminal_color::red) | fmt::emphasis::bold,
                            "Failed to submit uptime proof: have not heard from the storage server "
                            "recently. Make sure that it is running! It is required to run "
                            "alongside the Loki daemon");
                    return;
                }
                if (!check_external_ping(
                            m_last_lokinet_ping,
                            get_net_config().UPTIME_PROOF_FREQUENCY,
                            "Lokinet")) {
                    log::error(
                            globallogcat,
                            fg(fmt::terminal_color::red) | fmt::emphasis::bold,
                            "Failed to submit uptime proof: have not heard from lokinet recently. "
                            "Make sure that it is running! It is required to run alongside the "
                            "Loki daemon");
                    return;
                }
            }

            submit_uptime_proof();
        });
    } else {
        // reset the interval so that we're ready when we register, OR if we get deregistered this
        // primes us up for re-registration in the same session
        m_check_uptime_proof_interval.reset();
    }
}
//-----------------------------------------------------------------------------------------------
bool core::on_idle() {
    if (!m_starter_message_showed) {
        std::string main_message;
        if (m_offline)
            main_message =
                    "The daemon is running offline and will not attempt to sync to the Loki "
                    "network.";
        else
            main_message =
                    "The daemon will start synchronizing with the network. This may take a long "
                    "time to complete.";
        log::info(
                globallogcat,
                fg(fmt::terminal_color::yellow),
                R"(
**********************************************************************
{}

You can set the level of process detailization through "set_log <level|categories>" command,
where <level> is between 0 (no details) and 4 (very verbose), or custom category based levels (eg, *:WARNING).

Use the "help" command to see the list of available commands.
Use "help <command>" to see a command's documentation.
**********************************************************************
)",
                main_message);
        m_starter_message_showed = true;
    }

    m_txpool_auto_relayer.do_call([this] { return relay_txpool_transactions(); });
    m_service_node_vote_relayer.do_call([this] { return relay_service_node_votes(); });
    m_check_disk_space_interval.do_call([this] { return check_disk_space(); });
    m_sn_proof_cleanup_interval.do_call([&snl = service_node_list] {
        snl.cleanup_proofs();
        return true;
    });

    std::chrono::seconds lifetime{time(nullptr) - get_start_time()};
    if (m_service_node &&
        lifetime > get_net_config().UPTIME_PROOF_STARTUP_DELAY)  // Give us some time to connect to
                                                                 // peers before sending uptimes
    {
        do_uptime_proof_call();
    }

    m_blockchain_pruning_interval.do_call(
            [this] { return blockchain.update_blockchain_pruning(); });
    miner.on_idle();
    mempool.on_idle();

#ifdef ENABLE_SYSTEMD
    m_systemd_notify_interval.do_call(
            [this] { sd_notify(0, ("WATCHDOG=1\nSTATUS=" + get_status_string()).c_str()); });
#endif

    return true;
}
//-----------------------------------------------------------------------------------------------
bool core::check_disk_space() {
    uint64_t free_space = get_free_space();
    if (free_space < 1ull * 1024 * 1024 * 1024)  // 1 GB
        log::warning(
                logcat,
                fg(fmt::terminal_color::red),
                "Free space is below 1 GB on {}",
                m_config_folder);
    return true;
}
//-----------------------------------------------------------------------------------------------
void core::flush_bad_txs_cache() {
    bad_semantics_txes_lock.lock();
    for (int idx = 0; idx < 2; ++idx)
        bad_semantics_txes[idx].clear();
    bad_semantics_txes_lock.unlock();
}
//-----------------------------------------------------------------------------------------------
void core::flush_invalid_blocks() {
    blockchain.flush_invalid_blocks();
}
//-----------------------------------------------------------------------------------------------
void core::set_target_blockchain_height(uint64_t target_blockchain_height) {
    m_target_blockchain_height = target_blockchain_height;
}
//-----------------------------------------------------------------------------------------------
uint64_t core::get_target_blockchain_height() const {
    return m_target_blockchain_height;
}
//-----------------------------------------------------------------------------------------------
uint64_t core::get_free_space() const {
    return fs::space(m_config_folder).available;
}
//-----------------------------------------------------------------------------------------------
eth::bls_rewards_response core::bls_rewards_request(const eth::address& address, uint64_t height) {
    return m_bls_aggregator->rewards_request(address, height);
}
//-----------------------------------------------------------------------------------------------
eth::bls_exit_liquidation_response core::bls_exit_liquidation_request(
        const crypto::public_key& pubkey, bool liquidate) {
    eth::bls_exit_type type =
            liquidate ? eth::bls_exit_type::liquidate : eth::bls_exit_type::normal;
    return m_bls_aggregator->exit_liquidation_request(pubkey, type);
}
//-----------------------------------------------------------------------------------------------
eth::bls_registration_response core::bls_registration(const eth::address& address) const {
    const auto& keys = get_service_keys();
    auto resp = m_bls_aggregator->registration(address, keys.pub);

    service_nodes::registration_details reg{};
    reg.service_node_pubkey = keys.pub;
    reg.bls_pubkey = m_bls_signer->getCryptoPubkey();

    // If we're constructing a BLS registration then dual keys should have been unified in our own
    // keys:
    assert(tools::view_guts(keys.pub) == tools::view_guts(keys.pub_ed25519));

    auto reg_msg = get_eth_registration_message_for_signing(reg);
    crypto_sign_ed25519_detached(
            resp.ed_signature.data(),
            nullptr,
            reg_msg.data(),
            reg_msg.size(),
            keys.key_ed25519.data());

    return resp;
}
//-----------------------------------------------------------------------------------------------
bool core::add_service_node_vote(
        const service_nodes::quorum_vote_t& vote, vote_verification_context& vvc) {
    return m_quorum_cop.handle_vote(vote, vvc);
}
//-----------------------------------------------------------------------------------------------
std::time_t core::get_start_time() const {
    return start_time;
}
//-----------------------------------------------------------------------------------------------
void core::graceful_exit() {
    raise(SIGTERM);
}
}  // namespace cryptonote
