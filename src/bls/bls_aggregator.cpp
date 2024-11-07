#include "bls_aggregator.h"

#include <blockchain_db/sqlite/db_sqlite.h>
#include <common/bigint.h>
#include <common/exception.h>
#include <common/guts.h>
#include <common/string_util.h>
#include <crypto/crypto.h>
#include <cryptonote_core/cryptonote_core.h>
#include <l2_tracker/contracts.h>
#include <logging/oxen_logger.h>
#include <oxenc/bt_producer.h>
#include <oxenmq/oxenmq.h>

#include <chrono>
#include <ethyl/utils.hpp>
#include <memory>

#include "bls_crypto.h"
#include "crypto/eth.h"

namespace eth {

// Debugging option: if defined then we deliberately break the aggregate signature of any node with
// a BLS pubkey with a last byte >= this value.  E.g. 0xf0 breaks about 1/16 of signatures:
// #define OXEN_DEBUG_BREAK_AGGREGATE_SIGNATURES 0xf0
#ifdef OXEN_DEBUG_BREAK_AGGREGATE_SIGNATURES
static const auto DEBUG_BROKEN_SIGNATURE = tools::make_from_hex_guts<bls_signature>(
        "234bc3b62bd08bc02df4f83ec49a9599f444739e0103cd8a8d3558ea944e44b1"
        "2a398b8f109c64083ad5771b9735116cd17ac1ed4269495aa59c5329b0cb9a71"
        "12ddb30255d54d55074bafd503df0fa7f40fa18eb6c5c79d32392c78b2373bc9"
        "04be74628c96ab584bc2404b1fc2bf339b78f2fdd54bab30d07ae2b300d1f082"sv,
        false);
#endif

// When a service node receives a request to sign an exit request for a BLS node, this value
// determines the age cutoff for what we are willing to sign.
constexpr auto BLS_EXIT_REQUEST_MAX_AGE = 3min;

static constexpr std::string_view to_string(bls_exit_type type) {
    switch (type) {
        case bls_exit_type::normal: return "Exit";
        case bls_exit_type::liquidate: return "Liquidation";
    }
    return "bls_exit_type_label_ERROR";
}

std::string bytes_to_hex_dot_truncate_middle(std::span<const unsigned char> bytes) {
    size_t dot_size = 3;  // How many dots to show in the middle
    size_t head_hex = 6;  // How many hex characters to preserve from head of string
    size_t tail_hex = 6;  // How many hex characters to preserve from tail of string

    std::string hex = oxenc::to_hex(bytes.begin(), bytes.end());

    head_hex = std::min(head_hex, hex.size());
    std::string_view head = tools::string_safe_substr(hex, 0, head_hex);

    tail_hex = std::min(tail_hex, head.size());
    std::string_view tail = tools::string_safe_substr(head, head.size() - tail_hex, tail_hex);

    std::string result = fmt::format("{}{:.>{}}{}", head, "", dot_size, tail);
    return result;
}

namespace {
    auto logcat = oxen::log::Cat("bls_aggregator");
    constexpr std::string_view OMQ_BLS_CATEGORY = "bls";
    constexpr std::string_view OMQ_REWARDS_ENDPOINT = "get_rewards";
    constexpr std::string_view OMQ_LIQUIDATE_ENDPOINT = "get_liquidation";
    constexpr std::string_view OMQ_EXIT_ENDPOINT = "get_exit";
    const std::string OMQ_BLS_EXIT_ENDPOINT = "{}.{}"_format(OMQ_BLS_CATEGORY, OMQ_EXIT_ENDPOINT);
    const std::string OMQ_BLS_LIQUIDATE_ENDPOINT =
            "{}.{}"_format(OMQ_BLS_CATEGORY, OMQ_LIQUIDATE_ENDPOINT);
    const std::string OMQ_BLS_REWARDS_ENDPOINT =
            "{}.{}"_format(OMQ_BLS_CATEGORY, OMQ_REWARDS_ENDPOINT);

    std::vector<uint8_t> get_reward_balance_msg_to_sign(
            cryptonote::network_type nettype,
            const address& eth_addr,
            std::array<std::byte, 32> amount_be) {
        // TODO(doyle): See BLSSigner::proofOfPossession
        const auto tag = build_tag_hash(tag::REWARD, nettype);
        std::vector<uint8_t> result;
        result.reserve(tag.size() + eth_addr.size() + amount_be.size());
        result.insert(result.end(), tag.begin(), tag.end());
        result.insert(result.end(), eth_addr.begin(), eth_addr.end());
        result.insert(
                result.end(),
                reinterpret_cast<uint8_t*>(amount_be.begin()),
                reinterpret_cast<uint8_t*>(amount_be.end()));
        return result;
    }

    std::vector<uint8_t> get_exit_msg_to_sign(
            cryptonote::network_type nettype,
            bls_exit_type type,
            const bls_public_key& remove_pk,
            uint64_t unix_ts) {
        auto unix_ts_be = tools::encode_integer_be<32>(unix_ts);
        crypto::hash tag{};

        if (type == bls_exit_type::normal) {
            tag = build_tag_hash(tag::EXIT, nettype);
        } else {
            assert(type == bls_exit_type::liquidate);
            tag = build_tag_hash(tag::LIQUIDATE, nettype);
        }

        // TODO(doyle): See BLSSigner::proofOfPossession
        std::vector<uint8_t> result;
        result.reserve(tag.size() + remove_pk.size() + unix_ts_be.size());
        result.insert(result.end(), tag.begin(), tag.end());
        result.insert(result.end(), remove_pk.begin(), remove_pk.end());
        auto* ts_ptr = reinterpret_cast<uint8_t*>(unix_ts_be.data());
        result.insert(result.end(), ts_ptr, ts_ptr + unix_ts_be.size());
        return result;
    }

    struct bls_exit_request {
        bool good;
        bls_public_key remove_pk;
        std::chrono::seconds timestamp;
    };

    bls_exit_request extract_exit_request(oxenmq::Message& m) {
        bls_exit_request result{};
        if (m.data.size() != 1) {
            m.send_reply(
                    "400",
                    "Bad request: BLS exit command should have one data part; received {}"_format(
                            m.data.size()));
            return result;
        }

        try {
            oxenc::bt_dict_consumer d{m.data[0]};
            result.remove_pk =
                    tools::make_from_guts<bls_public_key>(d.require<std::string_view>("bls_"
                                                                                      "pubke"
                                                                                      "y"));
            result.timestamp = std::chrono::seconds{d.require<uint64_t>("timestamp")};
        } catch (const std::exception& e) {
            m.send_reply(
                    "400",
                    "Bad request: BLS exit command specified bad bls pubkey or timestamp: {}"_format(
                            e.what()));
            return result;
        }

        // NOTE: Check if the request is too old. If it's too old we will reject it
        auto unix_now = std::chrono::system_clock::now().time_since_epoch();
        auto time_since_initial_request = result.timestamp > unix_now ? result.timestamp - unix_now
                                                                      : unix_now - result.timestamp;
        if (time_since_initial_request > BLS_EXIT_REQUEST_MAX_AGE) {
            m.send_reply(
                    "400",
                    "Bad request: BLS exit was too old ({}) to sign"_format(
                            tools::friendly_duration(time_since_initial_request)));
            return result;
        }

        result.good = true;
        return result;
    }

#ifndef NDEBUG
    // Redo the BLS aggregation steps given the list of signers and:
    //
    //   - Calculate the full aggregate bls public key (e.g. all signers)
    //   - Aggregate bls public key w/ the given signers
    //   - Detect if there's a session node that's in oxen but not in the smart
    //     contract
    //   - Detect if there's a session node that's in the smart contract but not
    //     in oxen
    //
    // Using this node's list of session nodes and their BLS public keys as well
    // as a snapshot of the rewards contract's 'allServiceNodeIDs' issued
    // at the invocation of this call.
    //
    // This method only does something if debug logging is enabled (and this is a debug build), and
    // runs/logs asynchronously (once the L2 request comes back).
    void debug_redo_bls_aggregation_steps_locally(
            cryptonote::core& core,
            const std::unordered_map<bls_public_key, bls_signature>& signatures) {

        if (log::get_level(logcat) <= log::Level::debug)
            core.l2_tracker().get_all_service_node_ids(
                    std::nullopt, [&core, signatures](std::optional<ServiceNodeIDs> maybe_snids) {
                        if (!maybe_snids) {
                            log::warning(
                                    logcat,
                                    "Failed to fetch service node IDs from rewards contract for "
                                    "aggregation debugging");
                            return;
                        }

                        const auto& contract_ids = *maybe_snids;

                        // NOTE: Detect if the smart contract state has diverged.
                        {
                            // NOTE: Check if key is in Oxen but not the smart contract
                            std::vector<service_nodes::service_node_pubkey_info> sn_list_info =
                                    core.service_node_list.get_service_node_list_state();
                            size_t missing_count = 0;
                            for (const auto& sn_info : sn_list_info) {
                                bool found = false;
                                for (const auto& [id, contract_bls_pkey] : contract_ids) {
                                    if (sn_info.info->bls_public_key == contract_bls_pkey) {
                                        found = true;
                                        break;
                                    }
                                }

                                if (!found) {
                                    missing_count++;
                                    oxen::log::warning(
                                            logcat,
                                            "Service node {} exists in Oxen but not in the "
                                            "contract",
                                            sn_info.pubkey);
                                }
                            }

                            // NOTE: Check if key is in smart contract but not in Oxen
                            for (const auto& [contract_id, contract_bls_pkey] : contract_ids) {
                                bool found = false;
                                for (const auto& sn_info : sn_list_info) {
                                    if (sn_info.info->bls_public_key == contract_bls_pkey) {
                                        found = true;
                                        break;
                                    }
                                }

                                if (!found) {
                                    missing_count++;
                                    oxen::log::warning(
                                            logcat,
                                            "Session node {} {} exists in contract but not in oxen",
                                            contract_id,
                                            contract_bls_pkey);
                                }
                            }

                            if (missing_count == 0)
                                oxen::log::debug(logcat, "No missing nodes detected!");
                        }

                        // NOTE: Re-derive the BLS aggregate key and the key subtraction step

                        // NOTE: Aggregate all keys
                        eth::pubkey_aggregator cpp_agg_pubkey;
                        for (const auto& [id, blspk] : contract_ids)
                            cpp_agg_pubkey.add(blspk);

                        oxen::log::debug(
                                logcat, "Full BLS aggregate public key {}", cpp_agg_pubkey.get());

                        // NOTE: Subtract non-signers
                        for (const auto& [id, contract_bls_pkey] : contract_ids) {
                            if (!signatures.count(contract_bls_pkey)) {
                                oxen::log::debug(
                                        logcat,
                                        "  Subtracting BLS key from Session Node {} {}",
                                        id,
                                        contract_bls_pkey);
                                cpp_agg_pubkey.subtract(contract_bls_pkey);
                            }
                        }

                        // NOTE: Dump the key we re-derived (e.g. includes the non-signers)
                        oxen::log::debug(
                                logcat,
                                "Re-derived (via subtraction) BLS aggregate public key {}",
                                cpp_agg_pubkey.get());
                    });
    }
#endif

    struct agg_log {
        service_nodes::service_node_address addr;
        std::string msg;
    };

    struct agg_log_list {
        std::vector<agg_log> success;
        std::vector<agg_log> error;
        std::mutex mutex;
    };

    void dump_agg_log_list(const agg_log_list& lister) {
        size_t total_aggs = lister.error.size() + lister.success.size();
        fmt::memory_buffer buffer;
        fmt::format_to(
                std::back_inserter(buffer),
                "{} results {}/{} sigs ({:.1f}% success, {} failures):\n",
                OMQ_BLS_REWARDS_ENDPOINT,
                lister.success.size(),
                total_aggs,
                lister.success.size() * 100.f / total_aggs,
                lister.error.size());

        std::pair<std::span<const agg_log>, bool> array[] = {
                {lister.success, true},
                {lister.error, false},
        };

        for (auto [list, success] : array) {
            if (list.empty())
                continue;

            fmt::format_to(
                    std::back_inserter(buffer), "{} runs:\n", success ? "Successful" : "Failed");
            for (const auto& item : list) {
                fmt::format_to(
                        std::back_inserter(buffer),
                        "  - SN {} BLS {} XKEY {} @ {:<21} => {}\n",
                        bytes_to_hex_dot_truncate_middle(item.addr.sn_pubkey),
                        bytes_to_hex_dot_truncate_middle(item.addr.bls_pubkey),
                        bytes_to_hex_dot_truncate_middle(item.addr.x_pubkey),
                        "{}:{}"_format(
                                epee::string_tools::get_ip_string_from_int32(item.addr.ip),
                                item.addr.port),
                        item.msg);
            }
        }
        oxen::log::debug(logcat, "{}", fmt::to_string(buffer));
    }

    void log_aggregation_result(
            std::string_view agg_type,
            const std::unordered_map<bls_public_key, bls_signature>& signatures,
            std::chrono::high_resolution_clock::time_point started,
            const bls_public_key& agg_pub,
            const bls_signature& sig,
            const std::optional<agg_log_list>& agg_log_lister,
            // Used only in a debug build:
            [[maybe_unused]] cryptonote::core& core,
            std::span<const uint8_t> msg) {

        if (oxen::log::get_level(logcat) <= oxen::log::Level::debug && agg_log_lister)
            dump_agg_log_list(*agg_log_lister);

        auto elapsed = std::chrono::duration_cast<std::chrono::duration<float>>(
                               std::chrono::high_resolution_clock::now() - started)
                               .count();
        oxen::log::debug(
                logcat,
                "BLS {} aggregation result ({} aggregations) in {:.2f}s:"
                "\n    ‣ signed msg: {:02x}"
                "\n    ‣ agg pubkey: {}"
                "\n    ‣  signature: {}",
                agg_type,
                signatures.size(),
                elapsed,
                fmt::join(msg, ""),
                agg_pub,
                sig);

#ifndef NDEBUG
        debug_redo_bls_aggregation_steps_locally(core, signatures);
#endif
    }
}  // namespace

std::string bls_exit_liquidation_response::to_string() const {
    std::string result =
            "BLS exit response was:\n"
            "\n"
            "  - type:          {}\n"
            "  - remove_pubkey: {}\n"
            "  - timestamp:     {}\n"
            "  - agg_pubkey:    {}\n"
            "  - signature:     {}\n"
            "  - msg_to_sign:   {}\n"_format(
                    type,
                    remove_pubkey,
                    timestamp,
                    aggregate_pubkey,
                    signature,
                    oxenc::to_hex(msg_to_sign.begin(), msg_to_sign.end()));
    return result;
}

std::string bls_rewards_response::to_string() const {
    std::string result =
            "BLS rewards response was:\n"
            "\n"
            "  - address:     {}\n"
            "  - amount:      {}\n"
            "  - height:      {}\n"
            "  - agg_pubkey:  {}\n"
            "  - signature:   {}\n"
            "  - msg_to_sign: {}\n"_format(
                    addr,
                    amount,
                    height,
                    aggregate_pubkey,
                    signature,
                    oxenc::to_hex(msg_to_sign.begin(), msg_to_sign.end()));
    return result;
}

bls_aggregator::bls_aggregator(cryptonote::core& _core) : core{_core} {
    if (!core.service_node())
        return;

    // NOTE: Register endpoints contactable by OMQ for BLS aggregation
    auto& omq = core.omq();
    omq.add_category(std::string(OMQ_BLS_CATEGORY), oxenmq::Access{oxenmq::AuthLevel::none})
            .add_request_command(
                    std::string(OMQ_REWARDS_ENDPOINT), [this](auto& m) { get_rewards(m); })
            .add_request_command(
                    std::string(OMQ_EXIT_ENDPOINT),
                    [this](auto& m) { get_exit_liquidation(m, bls_exit_type::normal); })
            .add_request_command(std::string(OMQ_LIQUIDATE_ENDPOINT), [this](auto& m) {
                get_exit_liquidation(m, bls_exit_type::liquidate);
            });

    // NOTE: Add timers to cull the cached responses that have gone stale peroidically
    omq.add_timer(
            [this] {
                {
                    // NOTE: Handle overflow if STORE_RECENT_REWARDS is large or you're on some
                    // fresh network that has hardly any blocks (e.g. localdev).
                    uint64_t top_height = core.blockchain.get_current_blockchain_height() - 1;
                    uint64_t cutoff = top_height - core.get_net_config().STORE_RECENT_REWARDS;
                    if (cutoff < top_height) {
                        std::lock_guard lock{rewards_response_cache_mutex};
                        std::erase_if(rewards_response_cache, [&cutoff](const auto& item) {
                            return item.second->height < cutoff;
                        });
                    }
                }
                {
                    const uint64_t cutoff =
                            std::chrono::duration_cast<std::chrono::seconds>(
                                    std::chrono::system_clock::now().time_since_epoch() -
                                    contract::REWARDS_EXIT_SIGNATURE_EXPIRY)
                                    .count();

                    std::lock_guard lock{exit_liquidation_response_cache_mutex};
                    std::erase_if(exit_liquidation_response_cache, [&cutoff](const auto& item) {
                        return item.second->timestamp < cutoff;
                    });
                }
            },
            5min);
}

bls_registration_response bls_aggregator::registration(
        const address& operator_addr, const crypto::public_key& sn_pubkey) const {

    auto& blspk = core.get_service_keys().pub_bls;
    return bls_registration_response{
            .bls_pubkey = blspk,
            .proof_of_possession = eth::proof_of_possession(
                    core.get_nettype(),
                    operator_addr,
                    sn_pubkey,
                    core.get_service_keys().key_bls,
                    &blspk),
            .addr = operator_addr,
            .sn_pubkey = sn_pubkey,
            .ed_signature = crypto::null<crypto::ed25519_signature>};
}

namespace {

    // Recursive object held in OMQ response lambdas that puts itself into new request lambdas as
    // long as there are more requests to make.  Once all the requests are finished and the
    // individual response callbacks fired (whether successful or not), a final_callback gets fired,
    // after which there will be no remaining outstanding OMQ callbacks sharing the pointer and it
    // gets destroyed.
    class nodes_request_data : public std::enable_shared_from_this<nodes_request_data> {
        // Private constructor: we must always hold this in a shared pointer (for
        // enable_shared_from_this to work properly), and so you must construct such a shared
        // pointer by passing constructor arguments through make(...).
        nodes_request_data(
                cryptonote::core& core,
                std::string request_name,
                std::string message,
                request_callback callback,
                std::function<void(int total_requests)> final_callback,
                std::chrono::milliseconds timeout) :
                core{core},
                timeout{timeout},
                request_name{std::move(request_name)},
                message{std::move(message)},
                single_callback{std::move(callback)},
                final_callback{std::move(final_callback)} {

            core.service_node_list.copy_reachable_service_node_addresses(
                    std::back_inserter(snodes), core.get_nettype());
        }

      public:
        cryptonote::core& core;
        std::mutex connection_mutex;
        std::vector<service_nodes::service_node_address> snodes;
        size_t next_snode = 0;
        size_t active_connections = 0;
        size_t failures = 0;
        oxenmq::send_option::request_timeout timeout;
        inline constexpr static size_t MAX_CONNECTIONS = 900;

        const std::string request_name;
        const std::string message;

        const request_callback single_callback;
        std::function<void(int)> final_callback;

        void callback(
                const service_nodes::service_node_address& snode,
                bool success,
                std::vector<std::string> data) {
            try {
                single_callback(snode, success, std::move(data));
            } catch (const std::exception& e) {
                log::warning(logcat, "request callback raised an uncaught exception: {}", e.what());
            }
        }

        template <typename... Args>
        static std::shared_ptr<nodes_request_data> make(Args&&... args) {
            return std::shared_ptr<nodes_request_data>{
                    new nodes_request_data{std::forward<Args>(args)...}};
        }

        // Kicks off the requests, initiating an initial wave of connections up to the request
        // limit, and then recursively calling itself (until there are no more requests) as requests
        // finish.  You must call this for this class to do anything, and may not touch any of the
        // struct's members after calling it.
        void establish() {
            std::lock_guard lock{connection_mutex};

            while (active_connections < MAX_CONNECTIONS && next_snode < snodes.size()) {
                auto& snode = snodes[next_snode++];
                ++active_connections;

                oxenmq::ConnectionID connid;
                bool is_sn_conn = core.service_node_list.is_service_node(
                        snode.sn_pubkey, /*require_active*/ true);
                if (is_sn_conn) {
                    connid = tools::view_guts(snode.x_pubkey);
                } else {

// TODO: This appears to work now that we currently generate the endpoint to contact the
// node on (and actually use their xkey for authenticated comms). The localdev script
// fails though but it progresses further than it did before when this was last enabled.
#if 0

                    auto addr = oxenmq::address{"curve://{}:{}/{:x}"_format(
                            epee::string_tools::get_ip_string_from_int32(snode.ip), snode.port, snode.x_pubkey)};
                    connid = core.omq().connect_remote(
                            addr,
                            [](oxenmq::ConnectionID) { /* Successfully connected */ },
                            [](oxenmq::ConnectionID, std::string_view) { /* Failed to connect */ });
#else
                    callback(
                            snode,
                            /*success=*/false,
                            {{"Non-active node connections unimplemented"s}});
                    --active_connections;
                    continue;
#endif
                }

                log::debug(logcat, "Initiating {} request to {}", request_name, connid.to_string());
                core.omq().request(
                        connid,
                        request_name,
                        [this,
                         self = shared_from_this(),
                         disconnect = !is_sn_conn ? connid : oxenmq::ConnectionID{},
                         &snode](bool success, std::vector<std::string> data) {
                            log::debug(
                                    logcat,
                                    "{} from {}",
                                    success ? "Successful response" : "Failure",
                                    snode.sn_pubkey);
                            callback(snode, success, std::move(data));
                            {
                                std::lock_guard lock{connection_mutex};
                                assert(active_connections);
                                --active_connections;
                                if (disconnect)
                                    core.omq().disconnect(disconnect);
                            }

                            establish();
                        },
                        message,
                        oxenmq::send_option::request_timeout{timeout});
            }

            if (active_connections == 0 && final_callback)
                // If this is true here then it means we were called from the callback of the last
                // request to come back to us (or there simply were no requests at all), so it's
                // time to call the final callback because we're done.
                try {
                    final_callback(snodes.size());
                } catch (const std::exception& e) {
                    log::warning(
                            logcat,
                            "Final nodes request callback raised an uncaught exception: {}",
                            e.what());
                }
        }
    };

    // See aggregate_result<R>::finalize_signature() below.
    void aggregate_signature_finalize(
            cryptonote::network_type nettype,
            bls_aggregate_signed& result,
            eth::signature_aggregator& agg_sig,
            eth::pubkey_aggregator& agg_pub) {
        if (result.signatures.empty()) {
            result.signature = crypto::null<bls_signature>;
            result.aggregate_pubkey = crypto::null<bls_public_key>;
            return;
        }

        result.signature = agg_sig.get();
        result.aggregate_pubkey = agg_pub.get();
        if (eth::verify(nettype, result.signature, result.aggregate_pubkey, result.msg_to_sign)) {
            log::debug(
                    logcat,
                    "Aggregate signature {} verified with agg. pubkey {}",
                    result.signature,
                    result.aggregate_pubkey);
            return;
        }

        log::warning(
                logcat,
                "Aggregate signature failed validation; recomputing with full verification");

        int removed = 0;
        for (auto it = result.signatures.begin(); it != result.signatures.end();) {
            auto& [blspk, sig] = *it;
            if (eth::verify(nettype, sig, blspk, result.msg_to_sign))
                ++it;
            else {
                log::warning(
                        logcat,
                        "BLS signer {} signature invalid ({}); removing from aggregate",
                        blspk,
                        sig);
                agg_sig.subtract(sig);
                agg_pub.subtract(blspk);

                result.signature = agg_sig.get();
                result.aggregate_pubkey = agg_pub.get();
                removed++;
                it = result.signatures.erase(it);

                // In a pathologically bad case this means we could do two verifications for every
                // bad pubkey, but if there's just one bad key this could save a lot.
                if (eth::verify(
                            nettype,
                            result.signature,
                            result.aggregate_pubkey,
                            result.msg_to_sign)) {
                    log::info(
                            logcat,
                            "Aggregate signature now verifying with {} removals "
                            "(now: {} signatures)",
                            removed,
                            result.signatures.size());
                    break;
                }
            }
        }
    }

    template <std::derived_from<bls_aggregate_signed> Result>
    struct aggregate_result {
        std::shared_ptr<Result> result = std::make_shared<Result>();
        std::optional<agg_log_list> agg_log_lister = log::get_level(logcat) <= log::Level::debug
                                                           ? std::make_optional<agg_log_list>()
                                                           : std::nullopt;
        std::mutex sig_mutex;
        eth::signature_aggregator agg_sig;
        eth::pubkey_aggregator agg_pub;

        // Sets `result.signature` and `result.aggregate_pubkey` from the agg_sig/agg_pub
        // aggregates, but first verifies that that pair is a valid pubkey/signature for
        // `result.msg_to_sign`; if it isn't, then a full verification of all signatures in
        // `result.signatures` is performed and any failing individual signatures are subtracted
        // from the final signature and deleted from `signatures`.
        //
        // This is an optimization: in the typical case all signatures are correct and this allows
        // doing just only one (costly) verification of the aggregate signature, but with a more
        // expensive per-signature verification fallback to recalculate only in the case where that
        // fails.
        void finalize_signature(cryptonote::network_type nettype) {
            aggregate_signature_finalize(nettype, *result, agg_sig, agg_pub);
        }

        template <typename... T>
        void success(
                const service_nodes::service_node_address& addr,
                fmt::format_string<T...> format,
                T&&... args) {
            if (agg_log_lister) {
                std::lock_guard lock{agg_log_lister->mutex};
                agg_log_lister->success.emplace_back(
                        addr, fmt::format(format, std::forward<T>(args)...));
            }
        }
        template <typename... T>
        void error(
                const service_nodes::service_node_address& addr,
                fmt::format_string<T...> format,
                T&&... args) {
            if (agg_log_lister) {
                std::lock_guard lock{agg_log_lister->mutex};
                agg_log_lister->error.emplace_back(
                        addr, fmt::format(format, std::forward<T>(args)...));
            }
        }
    };
}  // namespace

uint64_t bls_aggregator::nodes_request(
        std::string request_name,
        std::string message,
        request_callback callback,
        std::function<void(int total_requests)> final_callback) {

    log::debug(logcat, "Initiating nodes request for {}", request_name);
    assert(callback);

    auto reqdata = nodes_request_data::make(
            core,
            std::move(request_name),
            std::move(message),
            std::move(callback),
            std::move(final_callback),
            5s /* per-request timeout */);

    size_t n_snodes = reqdata->snodes.size();

    log::debug(logcat, "Establishing initial connections ({} reachable snodes total)", n_snodes);

    reqdata->establish();

    return n_snodes;
}

void bls_aggregator::get_rewards(oxenmq::Message& m) const {
    oxen::log::trace(logcat, "Received omq rewards signature request");

    if (m.data.size() != 1) {
        m.send_reply(
                "400",
                "Bad request: BLS rewards signature request should have one data part; received {}"_format(
                        m.data.size()));
        return;
    }

    eth::address eth_addr;
    uint64_t height;
    try {
        oxenc::bt_dict_consumer d{m.data[0]};
        eth_addr = tools::make_from_guts<eth::address>(d.require<std::string_view>("address"));
        height = d.require<uint64_t>("height");
    } catch (const std::exception& e) {
        m.send_reply(
                "400",
                "Bad request: BLS rewards signature request had address or height: {}"_format(
                        e.what()));
        return;
    }

    auto maybe_amount = core.blockchain.sqlite_db().get_accrued_rewards(eth_addr, height);
    if (!maybe_amount) {
        m.send_reply("410", "Balances for height {} are not available"_format(height));
        return;
    }
    auto amount = *maybe_amount;

    // We sign H(H(rewardTag || chainid || contract) || recipientAddress ||
    // recipientAmount),
    // where everything is in bytes, and recipientAmount is a 32-byte big
    // endian integer value.
    std::array<std::byte, 32> amount_be = tools::encode_integer_be<32>(amount);

    std::vector<uint8_t> msg =
            get_reward_balance_msg_to_sign(core.get_nettype(), eth_addr, amount_be);
    bls_signature sig = eth::sign(core.get_nettype(), core.get_service_keys().key_bls, msg);

    oxenc::bt_dict_producer d;
    d.append("address", tools::view_guts(eth_addr));  // Address requesting balance
    d.append("amount", amount);                       // Balance
    d.append("height", height);                       // Height of balance
    d.append("signature", tools::view_guts(sig));     // Signature of addr + balance

    m.send_reply("200", std::move(d).str());
}

void bls_aggregator::rewards_request(
        const address& addr,
        uint64_t height,
        std::function<void(std::shared_ptr<const bls_rewards_response>)> callback) {

    auto maybe_amount = core.blockchain.sqlite_db().get_accrued_rewards(addr, height);
    auto amount = maybe_amount.value_or(0);

    // FIXME: make this async
    oxen::log::trace(
            logcat,
            "Initiating rewards request of {} SENT for {} at height {}",
            amount,
            addr,
            height);

    if (!maybe_amount)
        throw oxen::traced<std::invalid_argument>(fmt::format(
                "Aggregating a rewards request for '{}' at height {} is invalid because "
                "reward data is not available for that height. Request rejected.",
                addr,
                height));

    // NOTE: Validate the arguments
    if (!addr) {
        throw oxen::traced<std::invalid_argument>(
                "Aggregating a rewards request for the zero address for {} SENT at height {} is "
                "invalid. Request rejected"_format(
                        addr, amount, height, core.service_node_list.height()));
    }

    if (amount == 0) {
        throw oxen::traced<std::invalid_argument>(
                "Aggregating a rewards request for '{}' for 0 SENT at height {} is invalid because "
                "no rewards are available. Request rejected."_format(addr, height));
    }

    // NOTE: Serve the response from our cache if it's a repeated request
    {
        std::lock_guard lock{rewards_response_cache_mutex};
        auto cache_it = rewards_response_cache.find(addr);
        if (cache_it != rewards_response_cache.end()) {
            auto cache_response = cache_it->second;
            if (cache_response->height == height && cache_response->amount == amount) {
                log::trace(
                        logcat,
                        "Serving rewards request from cache for address {} at height {} with "
                        "rewards {} amount",
                        addr,
                        height,
                        amount);
                callback(cache_response);
                return;
            }
        }
    }

    auto result_data = std::make_shared<aggregate_result<bls_rewards_response>>();
    auto& result = *result_data->result;
    result.addr = std::move(addr);
    result.amount = amount;
    result.height = height;
    result.msg_to_sign = get_reward_balance_msg_to_sign(
            core.get_nettype(), result.addr, tools::encode_integer_be<32>(amount));

    oxenc::bt_dict_producer d;
    d.append("address", tools::view_guts(result.addr));
    d.append("height", height);

    // NOTE: Initiate aggregate rewards request to the remainder of the network.
    uint64_t total_requests = nodes_request(
            OMQ_BLS_REWARDS_ENDPOINT,
            std::move(d).str(),
            // Single result handler:
            [result_data, nettype = core.get_nettype()](
                    const service_nodes::service_node_address& sn,
                    bool success,
                    std::vector<std::string> data) {
                bls_rewards_response rewards_response = {};
                if (!success || data.size() != 2 || data[0] != "200")
                    return result_data->error(
                            sn, "Request returned an error: {}", fmt::join(data, " "));

                // NOTE: Extract parameters
                oxenc::bt_dict_consumer d{data[1]};
                try {
                    rewards_response.addr =
                            tools::make_from_guts<address>(d.require<std::string_view>("address"));
                } catch (const std::exception& e) {
                    return result_data->error(
                            sn,
                            "Address was not {} bytes, {}",
                            sizeof(address),
                            fmt::join(data, " "));
                }

                try {
                    rewards_response.amount = d.require<uint64_t>("amount");
                } catch (const std::exception& e) {
                    return result_data->error(
                            sn, "Amount was not a valid U64, {}", fmt::join(data, " "));
                }

                try {
                    rewards_response.height = d.require<uint64_t>("height");
                } catch (const std::exception& e) {
                    return result_data->error(
                            sn, "Height was not a valid U64, {}", fmt::join(data, " "));
                }

                try {
                    rewards_response.signature = tools::make_from_guts<bls_signature>(
                            d.require<std::string_view>("signature"sv));
                } catch (const std::exception& e) {
                    return result_data->error(
                            sn, "Signature was not a valid U64, {}", fmt::join(data, " "));
                }

                rewards_response.msg_to_sign = get_reward_balance_msg_to_sign(
                        nettype,
                        rewards_response.addr,
                        tools::encode_integer_be<32>(rewards_response.amount));

                // NOTE: Verify parameters
                auto& result = *result_data->result;
                if (rewards_response.addr != result.addr)
                    return result_data->error(
                            sn,
                            "Response ETH address {} does not match the request address {}",
                            rewards_response.addr,
                            result.addr);

                if (rewards_response.amount != result.amount ||
                    rewards_response.height != result.height)
                    return result_data->error(
                            sn,
                            "Balance/height mismatch: expected {:L}/{:L}, got {:L}/{:L}",
                            result.amount,
                            result.height,
                            rewards_response.amount,
                            rewards_response.height);

                // NOTE: Aggregate parameters
                {
                    std::lock_guard lock{result_data->sig_mutex};
#ifdef OXEN_DEBUG_BREAK_AGGREGATE_SIGNATURES
                    if (sn.bls_pubkey.data_.back() >= OXEN_DEBUG_BREAK_AGGREGATE_SIGNATURES) {
                        log::error(logcat, "DEBUG: sabotaging signature from {}", sn.bls_pubkey);
                        rewards_response.signature = DEBUG_BROKEN_SIGNATURE;
                    }
#endif
                    result_data->agg_sig.add(rewards_response.signature);
                    result_data->agg_pub.add(sn.bls_pubkey);
                    [[maybe_unused]] auto [it, inserted] =
                            result.signatures.emplace(sn.bls_pubkey, rewards_response.signature);
                    assert(inserted ||
                           !"Duplicate BLS pubkey signature response should not be possible");
                }

                result_data->success(
                        sn, "Success (unverified), sig: {}", rewards_response.signature);
            },

            // Final result handler (after all individual result processed):
            [this,
             result_data,
             callback = std::move(callback),
             begin_ts = std::chrono::high_resolution_clock::now()](int total_requests) {
                result_data->finalize_signature(core.get_nettype());

                auto& result = *result_data->result;

                // NOTE: Dump the aggregate pubkey and other info that was generated
                log_aggregation_result(
                        "rewards",
                        result.signatures,
                        begin_ts,
                        result.aggregate_pubkey,
                        result.signature,
                        result_data->agg_log_lister,
                        core,
                        result.msg_to_sign);

                callback(result_data->result);

                // NOTE: Store the response in to the cache if the number of non-signers is small
                // enough to constitute a valid signature.
                uint64_t non_signers_count = total_requests - result.signatures.size();
                if (non_signers_count <=
                    contract::rewards_bls_non_signer_threshold(total_requests)) {
                    std::lock_guard lock{rewards_response_cache_mutex};
                    rewards_response_cache[result.addr] = std::move(result_data->result);
                }
            });

    log::debug(logcat, "Initiated {} service node rewards signing requests", total_requests);
}

void bls_aggregator::get_exit_liquidation(oxenmq::Message& m, bls_exit_type type) const {
    oxen::log::trace(logcat, "Received omq {} signature request", type);
    bls_exit_request request = extract_exit_request(m);
    if (!request.good)
        return;

    bool removable = false;
    switch (type) {
        case bls_exit_type::normal: {
            removable = core.blockchain.is_node_removable(request.remove_pk);
        } break;
        case bls_exit_type::liquidate: {
            removable = core.blockchain.is_node_liquidatable(request.remove_pk);
        } break;
    }

    if (!removable) {
        m.send_reply(
                "403",
                "Forbidden: The BLS pubkey {} is not currently {}."_format(
                        request.remove_pk, type));
        return;
    }

    std::vector<uint8_t> msg = get_exit_msg_to_sign(
            core.get_nettype(), type, request.remove_pk, request.timestamp.count());
    bls_signature sig = eth::sign(core.get_nettype(), core.get_service_keys().key_bls, msg);

    oxenc::bt_dict_producer d;
    d.append("remove", tools::view_guts(request.remove_pk));  // BLS pubkey to remove
    d.append("signature", tools::view_guts(sig));  // Signs over the exit key and timestamp
    m.send_reply("200", std::move(d).str());
}

// Common code for exit and liquidation requests, which only differ in three ways:
// - the endpoint they go to;
// - the tag that gets used in the msg_to_sign hash; and
// - the key under which the signed pubkey gets confirmed back to us.
void bls_aggregator::exit_liquidation_request(
        const std::variant<crypto::public_key, eth::bls_public_key>& pubkey,
        bls_exit_type type,
        std::function<void(std::shared_ptr<const bls_exit_liquidation_response>)> callback) {

    const auto* sn_pubkey = std::get_if<crypto::public_key>(&pubkey);
    const auto* bls_pubkey = std::get_if<eth::bls_public_key>(&pubkey);

    // NOTE: Trace entry into function
    if (sn_pubkey)
        oxen::log::debug(logcat, "Initiating {} request for SN {}", type, *sn_pubkey);
    else
        oxen::log::debug(logcat, "Initiating {} request for BLS pubkey {}", type, *bls_pubkey);

    // NOTE: Lookup the BLS pubkey associated with the Ed25519 pubkey.
    std::optional<eth::bls_public_key> maybe_bls_pubkey{};
    core.service_node_list.for_each_recently_removed_node([&](const auto& node) {
        if (sn_pubkey ? node.service_node_pubkey == *sn_pubkey
                      : node.info.bls_public_key == *bls_pubkey) {
            maybe_bls_pubkey = node.info.bls_public_key;
            return true;
        }
        return false;
    });

    auto format_pk = [&] {
        return sn_pubkey ? bls_pubkey ? "SN {} (BLS {})"_format(*sn_pubkey, *bls_pubkey)
                                      : "SN {}"_format(*sn_pubkey)
                         : "SN with BLS pubkey {}"_format(*bls_pubkey);
    };

    if (maybe_bls_pubkey)
        bls_pubkey = &*maybe_bls_pubkey;
    else if (!bls_pubkey || type == bls_exit_type::normal)
        // Either a normal exit or a liquidate by SN pubkey, and we did not find the requested
        // pubkey
        throw oxen::traced<std::invalid_argument>(
                "{} request for {} at height {} is invalid, node is not in the list of recently"
                " exited nodes. Request rejected"_format(
                        type, format_pk(), core.blockchain.get_current_blockchain_height()));

    // NOTE: Validate the arguments
    if (!*bls_pubkey) {
        throw oxen::traced<std::invalid_argument>(
                "{} request for SN {} w/ the zero BLS pkey at height {} is invalid. Request "
                "rejected"_format(
                        type, format_pk(), core.blockchain.get_current_blockchain_height()));
    }

    // NOTE: Serve the response from our cache if it's a repeated request
    {
        std::lock_guard lock{exit_liquidation_response_cache_mutex};
        auto it = exit_liquidation_response_cache.find(*bls_pubkey);
        if (it != exit_liquidation_response_cache.end()) {
            auto& resp_ptr = it->second;
            const bls_exit_liquidation_response& response = *resp_ptr;
            auto now_unix_ts = std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch());
            auto cache_ts = std::chrono::seconds(response.timestamp);
            if (response.type == type && now_unix_ts >= cache_ts) {
                std::chrono::seconds cache_age = now_unix_ts - cache_ts;
                if (cache_age <= contract::REWARDS_EXIT_SIGNATURE_EXPIRY) {
                    log::debug(
                            logcat,
                            "Serving {} response from cache for {} (cached {})\n{}",
                            type,
                            format_pk(),
                            tools::get_human_readable_timespan(cache_age),
                            response);
                    callback(resp_ptr);
                    return;
                }
            }
        }
    }

    // NOTE: The OMQ endpoint to hit
    bool removable = false;
    std::string endpoint;
    switch (type) {
        case bls_exit_type::normal: {
            endpoint = OMQ_BLS_EXIT_ENDPOINT;
            removable = core.blockchain.is_node_removable(*bls_pubkey);
        } break;
        case bls_exit_type::liquidate: {
            endpoint = OMQ_BLS_LIQUIDATE_ENDPOINT;
            removable = core.blockchain.is_node_liquidatable(*bls_pubkey);
        } break;
    }

    if (!removable) {
        throw oxen::traced<std::invalid_argument>(
                "{} request for {} at height {} is invalid: node is not currently eligible to be "
                "removed. Request rejected"_format(
                        type, format_pk(), core.blockchain.get_current_blockchain_height()));
    }

    auto result_data = std::make_shared<aggregate_result<bls_exit_liquidation_response>>();
    auto& result = *result_data->result;
    result.remove_pubkey = *bls_pubkey;
    result.type = type;
    result.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
    result.msg_to_sign =
            get_exit_msg_to_sign(core.get_nettype(), type, *bls_pubkey, result.timestamp);

    oxenc::bt_dict_producer message_dict;
    message_dict.append("bls_pubkey", tools::view_guts(*bls_pubkey));
    message_dict.append("timestamp", result.timestamp);

    uint64_t total_requests = nodes_request(
            std::move(endpoint),
            std::move(message_dict).str(),
            // Single result callback:
            [result_data, nettype = core.get_nettype()](
                    const service_nodes::service_node_address& sn,
                    bool success,
                    std::vector<std::string> data) {
                bls_exit_liquidation_response exit_response = {};
                if (!success || data.size() != 2 || data[0] != "200")
                    return result_data->error(
                            sn, "Request returned an error: {}", fmt::join(data, " "));

                oxenc::bt_dict_consumer d{data[1]};

                // NOTE: Extract parameters
                try {
                    exit_response.remove_pubkey = tools::make_from_guts<bls_public_key>(
                            d.require<std::string_view>("remove"sv));
                } catch (const std::exception& e) {
                    return result_data->error(
                            sn,
                            "Remove (pubkey) was not {} bytes, {}",
                            sizeof(bls_public_key),
                            fmt::join(data, " "));
                }

                try {
                    exit_response.signature = tools::make_from_guts<bls_signature>(
                            d.require<std::string_view>("signature"sv));
                } catch (const std::exception& e) {
                    return result_data->error(
                            sn,
                            "Signature was not {} bytes, {}",
                            sizeof(bls_signature),
                            fmt::join(data, " "));
                }

                // NOTE: Verify parameters
                auto& result = *result_data->result;
                if (exit_response.remove_pubkey != result.remove_pubkey)
                    return result_data->error(
                            sn,
                            "BLS response pubkey {} does not match the request pubkey {}",
                            exit_response.remove_pubkey,
                            result.remove_pubkey);

                // NOTE: Aggregate parameters
                {
                    std::lock_guard<std::mutex> lock(result_data->sig_mutex);
#ifdef OXEN_DEBUG_BREAK_AGGREGATE_SIGNATURES
                    if (sn.bls_pubkey.data_.back() >= OXEN_DEBUG_BREAK_AGGREGATE_SIGNATURES) {
                        log::error(logcat, "DEBUG: sabotaging signature from {}", sn.bls_pubkey);
                        exit_response.signature = DEBUG_BROKEN_SIGNATURE;
                    }
#endif
                    result_data->agg_sig.add(exit_response.signature);
                    result_data->agg_pub.add(sn.bls_pubkey);
                    [[maybe_unused]] auto [it, inserted] =
                            result.signatures.emplace(sn.bls_pubkey, exit_response.signature);
                    assert(inserted ||
                           !"Duplicate BLS pubkey signature response should not be possible");
                }

                result_data->success(sn, "Success (unverified), sig: {}", exit_response.signature);
            },

            // Final handling after all results processed:
            [this,
             result_data,
             type,
             callback = std::move(callback),
             begin_ts = std::chrono::high_resolution_clock::now()](int total_requests) {
                result_data->finalize_signature(core.get_nettype());

                auto& result = *result_data->result;

                // NOTE: Dump the aggregate pubkey and other info that was generated
                log_aggregation_result(
                        type == bls_exit_type::normal ? "exit" : "liquidation",
                        result.signatures,
                        begin_ts,
                        result.aggregate_pubkey,
                        result.signature,
                        result_data->agg_log_lister,
                        core,
                        result.msg_to_sign);

                callback(result_data->result);

                // NOTE: Store the response in to the cache if the number of non-signers is small
                // enough to constitute a valid signature.
                uint64_t non_signers_count = total_requests - result.signatures.size();
                if (non_signers_count <=
                    contract::rewards_bls_non_signer_threshold(total_requests)) {
                    std::lock_guard lock{exit_liquidation_response_cache_mutex};
                    exit_liquidation_response_cache[result.remove_pubkey] =
                            std::move(result_data->result);
                }
            });

    log::debug(logcat, "Initiated {} service node rewards signing requests", total_requests);
}

}  // namespace eth
