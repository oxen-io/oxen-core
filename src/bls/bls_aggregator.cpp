#include "bls_aggregator.h"

#include <blockchain_db/sqlite/db_sqlite.h>
#include <bls/bls_signer.h>
#include <bls/bls_utils.h>
#include <common/bigint.h>
#include <common/exception.h>
#include <common/guts.h>
#include <common/string_util.h>
#include <crypto/crypto.h>
#include <cryptonote_core/cryptonote_core.h>
#include <logging/oxen_logger.h>
#include <oxenc/bt_producer.h>
#include <oxenmq/oxenmq.h>

#include <chrono>
#include <ethyl/utils.hpp>

#define BLS_ETH
#define MCLBN_FP_UNIT_SIZE 4
#define MCLBN_FR_UNIT_SIZE 4

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <bls/bls.hpp>
#include <mcl/bn.hpp>
#undef MCLBN_NO_AUTOLINK
#pragma GCC diagnostic pop

namespace eth {

namespace {
    auto logcat = oxen::log::Cat("bls_aggregator");

    // Takes a oxenmq::Message expected to contain a single argument extractable to a `T` that must
    // be encoded as raw bytes, hex, or 0x-prefixed hex.  Sends an appropriate reply and returns
    // false on error, otherwise sets `val` and returns true.
    template <tools::safe_to_memcpy T>
    bool extract_1part_msg(
            oxenmq::Message& m, T& val, std::string_view cmd_name, std::string_view value_name) {
        if (m.data.size() != 1) {
            m.send_reply(
                    "400",
                    "Bad request: {} command should have one {} data part; received {}"_format(
                            cmd_name, value_name, m.data.size()));
            return false;
        }
        if (m.data[0].size() == sizeof(T)) {
            val = tools::make_from_guts<T>(m.data[0]);
            return true;
        }
        if (tools::try_load_from_hex_guts(m.data[0], val))
            return true;

        m.send_reply(
                "400",
                "Bad request: {} command data should be a {}-byte {}; got {} bytes"_format(
                        cmd_name, sizeof(T), value_name, m.data[0].size()));
        return false;
    }

    std::vector<uint8_t> get_reward_balance_msg_to_sign(
            cryptonote::network_type nettype,
            const address& eth_addr,
            std::array<std::byte, 32> amount_be) {
        // TODO(doyle): See BLSSigner::proofOfPossession
        const auto tag = BLSSigner::buildTagHash(BLSSigner::rewardTag, nettype);
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

    std::string dump_bls_rewards_response(const bls_rewards_response& item) {
        std::string result =
                "BLS rewards response was:\n"
                "\n"
                "  - address:     {}\n"
                "  - amount:      {}\n"
                "  - height:      {}\n"
                "  - signature:   {}\n"
                "  - msg_to_sign: {}\n"_format(
                        item.addr,
                        item.amount,
                        item.height,
                        item.signature,
                        oxenc::to_hex(item.msg_to_sign.begin(), item.msg_to_sign.end()));
        return result;
    }

    std::vector<uint8_t> get_removal_msg_to_sign(
            cryptonote::network_type nettype,
            bls_aggregator::removal_type type,
            const bls_public_key& remove_pk,
            uint64_t unix_timestamp) {
        // TODO(doyle): See BLSSigner::proofOfPossession
        crypto::hash tag{};
        std::vector<uint8_t> result;
        if (type == bls_aggregator::removal_type::normal) {
            tag = BLSSigner::buildTagHash(BLSSigner::removalTag, nettype);
            result.reserve(tag.size() + remove_pk.size() + sizeof(unix_timestamp));
            result.insert(result.end(), tag.begin(), tag.end());
            result.insert(result.end(), remove_pk.begin(), remove_pk.end());
            auto unix_timestamp_it = reinterpret_cast<uint8_t*>(&unix_timestamp);
            result.insert(
                    result.end(), unix_timestamp_it, unix_timestamp_it + sizeof(unix_timestamp));
        } else {
            assert(type == bls_aggregator::removal_type::liquidate);
            tag = BLSSigner::buildTagHash(BLSSigner::liquidateTag, nettype);
            result.reserve(tag.size() + remove_pk.size());
            result.insert(result.end(), tag.begin(), tag.end());
            result.insert(result.end(), remove_pk.begin(), remove_pk.end());
        }
        return result;
    }

    struct bls_removal_request {
        bool good;
        bls_public_key remove_pk;
        std::chrono::seconds timestamp;
    };

    bls_removal_request extract_removal_request(oxenmq::Message& m) {
        bls_removal_request result{};
        if (m.data.size() != 1) {
            m.send_reply(
                    "400",
                    "Bad request: BLS removal command should have one data part; received {}"_format(
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
                    "Bad request: BLS removal command specified bad bls pubkey or timestamp: {}"_format(
                            e.what()));
            return result;
        }

        // NOTE: Check if the request is too old. If it's too old we will reject it
        auto unix_now = std::chrono::system_clock::now().time_since_epoch();
        auto time_since_initial_request = result.timestamp > unix_now ? result.timestamp - unix_now
                                                                      : unix_now - result.timestamp;
        if (time_since_initial_request > service_nodes::BLS_MAX_TIME_ALLOWED_FOR_REMOVAL_REQUEST) {
            m.send_reply(
                    "400",
                    "Bad request: BLS removal was too old ({}) to sign"_format(
                            tools::friendly_duration(time_since_initial_request)));
            return result;
        }

        result.good = true;
        return result;
    }

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
    void debug_redo_bls_aggregation_steps_locally(
            const service_nodes::service_node_list& service_node_list,
            L2Tracker& l2_tracker,
            std::span<const bls_public_key> signature_signers) {
        const RewardsContract::ServiceNodeIDs contract_ids =
                l2_tracker.get_all_service_node_ids(std::nullopt);

        // NOTE: Detect if the smart contract state has diverged.
        {
            // NOTE: Check if key is in Oxen but not the smart contract
            std::vector<service_nodes::service_node_pubkey_info> sn_list_info =
                    service_node_list.get_service_node_list_state();
            size_t missing_count = 0;
            for (const auto& sn_info : sn_list_info) {
                bool found = false;
                for (size_t index = 0; index < contract_ids.ids.size(); index++) {
                    const bls_public_key& contract_bls_pkey = contract_ids.bls_pubkeys[index];
                    if (sn_info.info->bls_public_key == contract_bls_pkey) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    missing_count++;
                    oxen::log::warning(
                            logcat,
                            "Session node {} exists in Oxen but not in the contract",
                            sn_info.pubkey);
                }
            }

            // NOTE: Check if key is in smart contract but not in Oxen
            for (size_t index = 0; index < contract_ids.ids.size(); index++) {
                uint64_t contract_id = contract_ids.ids[index];
                const bls_public_key& contract_bls_pkey = contract_ids.bls_pubkeys[index];
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
        {
            // NOTE: Aggregate all keys
            bls::PublicKey cpp_agg_pubkey = {};
            blsPublicKey* agg_pub = const_cast<blsPublicKey*>(cpp_agg_pubkey.getPtr());
            for (size_t index = 0; index < contract_ids.ids.size(); index++) {
                const bls_public_key& contract_bls_pkey = contract_ids.bls_pubkeys[index];
                const bls::PublicKey contract_key =
                        bls_utils::from_crypto_pubkey(contract_bls_pkey);
                blsPublicKeyAdd(agg_pub, contract_key.getPtr());
            }
            oxen::log::debug(
                    logcat,
                    "Full BLS aggregate public key {}",
                    bls_utils::to_crypto_pubkey(cpp_agg_pubkey));

            // NOTE: Subtract non-signers
            for (size_t index = 0; index < contract_ids.ids.size(); index++) {
                bool found = false;
                const bls_public_key& contract_bls_pkey = contract_ids.bls_pubkeys[index];
                for (const bls_public_key& pkey : signature_signers) {
                    if (pkey == contract_bls_pkey) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    oxen::log::debug(
                            logcat,
                            "  Subtracting BLS key from Session Node {} {}",
                            contract_ids.ids[index],
                            contract_bls_pkey);
                    const bls::PublicKey contract_key =
                            bls_utils::from_crypto_pubkey(contract_bls_pkey);
                    blsPublicKeySub(agg_pub, contract_key.getPtr());
                }
            }

            // NOTE: Dump the key we re-derived (e.g. includes the non-signers)
            oxen::log::debug(
                    logcat,
                    "Re-derived BLS aggregate public key {}",
                    bls_utils::to_crypto_pubkey(cpp_agg_pubkey));
        }
    }

}  // namespace

bls_aggregator::bls_aggregator(cryptonote::core& _core) : core{_core} {

    if (core.service_node()) {
        auto& omq = core.omq();
        omq.add_category("bls", oxenmq::Access{oxenmq::AuthLevel::none})
                .add_request_command(
                        "get_reward_balance", [this](auto& m) { get_reward_balance(m); })
                .add_request_command("get_removal", [this](auto& m) { get_removal(m); })
                .add_request_command("get_liquidation", [this](auto& m) { get_liquidation(m); });
    }
}

bls_registration_response bls_aggregator::registration(
        const address& sender, const crypto::public_key& sn_pubkey) const {
    auto& signer = core.bls_signer();
    return bls_registration_response{
            .bls_pubkey = signer.getCryptoPubkey(),
            .proof_of_possession = signer.proofOfPossession(sender, sn_pubkey),
            .addr = sender,
            .sn_pubkey = sn_pubkey,
            .ed_signature = crypto::null<crypto::ed25519_signature>};
}

uint64_t bls_aggregator::nodes_request(
        std::string_view request_name, std::string_view message, const request_callback& callback) {
    std::mutex connection_mutex;
    std::condition_variable cv;
    size_t active_connections = 0;
    const size_t MAX_CONNECTIONS = 900;

    // FIXME: make this function async rather than blocking

    std::vector<service_nodes::service_node_address> snodes;
    core.service_node_list.copy_reachable_active_service_node_addresses(
            std::back_inserter(snodes), core.get_nettype());

    auto& omq = core.omq();
    for (size_t i = 0; i < snodes.size(); i++) {
        auto& snode = snodes[i];
        if (1) {
            std::lock_guard connection_lock(connection_mutex);
            ++active_connections;
        } else {
            // TODO(doyle): Rate limit
            std::unique_lock connection_lock(connection_mutex);
            cv.wait(connection_lock,
                    [&active_connections] { return active_connections < MAX_CONNECTIONS; });
        }

        // NOTE:  Connect to the SN. Note that we do a request directly to the public key, this
        // should allow OMQ to re-use a connection (for potential subsequent calls) but also
        // automatically kill connections on our behalf.
        omq.request(
                tools::view_guts(snode.x_pubkey),
                request_name,
                [i, &snodes, &connection_mutex, &active_connections, &cv, &callback](
                        bool success, std::vector<std::string> data) {
                    callback(bls_response{snodes[i], success}, data);
                    std::lock_guard connection_lock{connection_mutex};
                    assert(active_connections);
                    if (--active_connections == 0)
                        cv.notify_all();
                },
                message);
    }

    std::unique_lock connection_lock{connection_mutex};
    cv.wait(connection_lock, [&active_connections] { return active_connections == 0; });
    return snodes.size();
}

void bls_aggregator::get_reward_balance(oxenmq::Message& m) {
    oxen::log::trace(logcat, "Received omq rewards signature request");

    address eth_addr;
    if (!extract_1part_msg(m, eth_addr, "BLS rewards", "ETH address"))
        return;

    auto [batchdb_height, amount] =
            core.blockchain.sqlite_db().get_accrued_rewards(eth_addr);
    if (amount == 0) {
        m.send_reply("400", "Address '{}' has a zero balance in the database"_format(eth_addr));
        return;
    }

    // We sign H(H(rewardTag || chainid || contract) || recipientAddress ||
    // recipientAmount),
    // where everything is in bytes, and recipientAmount is a 32-byte big
    // endian integer value.
    auto& signer = core.bls_signer();
    std::array<std::byte, 32> amount_be = tools::encode_integer_be<32>(amount);

    std::vector<uint8_t> msg =
            get_reward_balance_msg_to_sign(core.get_nettype(), eth_addr, amount_be);
    bls_signature sig = signer.signMsg(msg);

    oxenc::bt_dict_producer d;
    // Address requesting balance
    d.append("address", tools::view_guts(eth_addr));
    // Balance
    d.append("amount", amount);
    // Height of balance
    d.append("height", batchdb_height);
    // Signature of addr + balance
    d.append("signature", tools::view_guts(sig));

    m.send_reply("200", std::move(d).str());
}

bls_rewards_response bls_aggregator::rewards_request(const address& addr) {

    auto begin_ts = std::chrono::high_resolution_clock::now();
    auto [height, amount] = core.blockchain.sqlite_db().get_accrued_rewards(addr);

    // FIXME: make this async
    oxen::log::trace(
            logcat,
            "Initiating rewards request of {} SENT for {} at height {}",
            amount,
            addr,
            height);

    const auto& service_node_list = core.service_node_list;

    // NOTE: Validate the arguments
    if (!addr) {
        throw oxen::traced<std::invalid_argument>(fmt::format(
                "Aggregating a rewards request for the zero address for {} SENT at height {} is "
                "invalid because address is invalid. Request rejected",
                addr,
                amount,
                height,
                service_node_list.height()));
    }

    if (amount == 0) {
        throw oxen::traced<std::invalid_argument>(fmt::format(
                "Aggregating a rewards request for '{}' for 0 SENT at height {} is invalid because "
                "no rewards are available. Request rejected.",
                addr,
                height));
    }

    if (height > service_node_list.height()) {
        throw oxen::traced<std::invalid_argument>(fmt::format(
                "Aggregating a rewards request for '{}' for {} SENT at height {} is invalid "
                "because the height is greater than the blockchain height {}. Request rejected",
                addr,
                amount,
                height,
                service_node_list.height()));
    }

    // NOTE: Serve the response from our cache if it's a repeated request
    {
        std::lock_guard lock{mutex};
        auto cache_it = rewards_response_cache.find(addr);
        if (cache_it != rewards_response_cache.end()) {
            const bls_rewards_response& cache_response = cache_it->second;
            if (cache_response.height == height && cache_response.amount == amount) {
                log::trace(
                        logcat,
                        "Serving rewards request from cache for address {} at height {} with "
                        "rewards "
                        "{} amount",
                        addr,
                        height,
                        amount);
                return cache_response;
            }
        }
    }

    bls_rewards_response result{};
    result.addr = addr;
    result.amount = amount;
    result.height = height;
    result.msg_to_sign = get_reward_balance_msg_to_sign(
            core.get_nettype(), result.addr, tools::encode_integer_be<32>(amount));

    // `nodesRequest` dispatches to a threadpool hence we require synchronisation:
    std::mutex sig_mutex;
    bls::Signature agg_sig;
    agg_sig.clear();

    // NOTE: Send aggregate rewards request to the remainder of the network. This is a blocking
    // call (FIXME -- it should not be!)
    uint64_t total_requests = nodes_request(
            "bls.get_reward_balance",
            tools::view_guts(addr),
            [&agg_sig, &result, &sig_mutex, nettype = core.get_nettype()](
                    const bls_response& response, const std::vector<std::string>& data) {
                bls_rewards_response rewards_response = {};
                bool partially_parsed = true;
                try {
                    if (!response.success || data.size() != 2 || data[0] != "200")
                        throw oxen::traced<std::runtime_error>{
                                "Error retrieving reward balance: {}"_format(fmt::join(data, " "))};

                    oxenc::bt_dict_consumer d{data[1]};

                    rewards_response.addr =
                            tools::make_from_guts<address>(d.require<std::string_view>("address"));
                    rewards_response.amount = d.require<uint64_t>("amount");
                    rewards_response.height = d.require<uint64_t>("height");
                    rewards_response.signature =
                            tools::make_from_guts<bls_signature>(d.require<std::string_view>("signa"
                                                                                             "tur"
                                                                                             "e"));
                    rewards_response.msg_to_sign = get_reward_balance_msg_to_sign(
                            nettype,
                            rewards_response.addr,
                            tools::encode_integer_be<32>(rewards_response.amount));

                    if (rewards_response.addr != result.addr)
                        throw oxen::traced<std::runtime_error>{
                                "Response ETH address {} does not match the request address {}"_format(
                                        rewards_response.addr, result.addr)};
                    if (rewards_response.amount != result.amount ||
                        rewards_response.height != result.height)
                        throw oxen::traced<std::runtime_error>{
                                "Balance/height mismatch: expected {}/{}, got {}/{}"_format(
                                        result.amount,
                                        result.height,
                                        rewards_response.amount,
                                        rewards_response.height)};

                    if (!BLSSigner::verifyMsg(
                                nettype,
                                rewards_response.signature,
                                response.sn.bls_pubkey,
                                result.msg_to_sign)) {
                        throw oxen::traced<std::runtime_error>{
                                "Invalid BLS signature for BLS pubkey {}."_format(
                                        response.sn.bls_pubkey)};
                    }

                    {
                        std::lock_guard lock{sig_mutex};
                        bls::Signature bls_sig =
                                bls_utils::from_crypto_signature(rewards_response.signature);
                        agg_sig.add(bls_sig);
                        result.signers_bls_pubkeys.push_back(response.sn.bls_pubkey);
                    }

                    partially_parsed = false;

                    oxen::log::trace(
                            logcat,
                            "Reward balance response accepted from {} (BLS {} XKEY {} {}:{})\nWe "
                            "requested: {}\nThe response had: {}",
                            response.sn.sn_pubkey,
                            response.sn.bls_pubkey,
                            response.sn.x_pubkey,
                            response.sn.ip,
                            response.sn.port,
                            dump_bls_rewards_response(result),
                            dump_bls_rewards_response(rewards_response));

                } catch (const std::exception& e) {
                    oxen::log::debug(
                            logcat,
                            "Reward balance response rejected from {}: {}\nWe requested: {}\nThe "
                            "response had{}: {}",
                            response.sn.sn_pubkey,
                            e.what(),
                            dump_bls_rewards_response(result),
                            partially_parsed ? " (partially parsed)" : "",
                            dump_bls_rewards_response(rewards_response));
                }
            });

    result.signature = bls_utils::to_crypto_signature(agg_sig);

    // NOTE: Dump the aggregate pubkey that was generated
    {
#if !defined(NDEBUG)
        bls::PublicKey agg_pub;
        agg_pub.clear();
        for (const auto& blspk : result.signers_bls_pubkeys)
            agg_pub.add(bls_utils::from_crypto_pubkey(blspk));
#endif

        auto elapsed_ts = std::chrono::high_resolution_clock::now() - begin_ts;
        oxen::log::debug(
                logcat,
                "BLS aggregate pubkey for reward requests: {} ({} aggregations) with signature {} "
                "in {:.1f}s",
#if defined(NDEBUG)
                "",
#else
                bls_utils::to_crypto_pubkey(agg_pub),
#endif
                result.signers_bls_pubkeys.size(),
                result.signature,
                (std::chrono::duration_cast<std::chrono::milliseconds>(elapsed_ts).count() /
                 1000.f));
    }

#if defined(NDEBUG)
    const bool debug_redo_bls_aggregation = false;
#else
    const bool debug_redo_bls_aggregation = true;
#endif
    if (debug_redo_bls_aggregation) {
        debug_redo_bls_aggregation_steps_locally(
                service_node_list, core.l2_tracker(), result.signers_bls_pubkeys);
    }

    // NOTE: Store the response in to the cache if the number of non-signers was less than 1/3rd.
    uint64_t non_signers_count = total_requests - result.signers_bls_pubkeys.size();
    if (non_signers_count < (total_requests / 3)) {
        std::lock_guard lock{mutex};
        rewards_response_cache[addr] = result;
    }

    return result;
}

void bls_aggregator::get_removal(oxenmq::Message& m) {
    oxen::log::trace(logcat, "Received omq removal signature request");
    bls_removal_request removal_request = extract_removal_request(m);
    if (!removal_request.good)
        return;

    // right not its approving everything
    if (!core.is_node_removable(removal_request.remove_pk)) {
        m.send_reply(
                "403",
                "Forbidden: The BLS pubkey {} is not currently removable."_format(
                        removal_request.remove_pk));
        return;
    }

    auto& signer = core.bls_signer();

    std::vector<uint8_t> msg = get_removal_msg_to_sign(
            core.get_nettype(),
            bls_aggregator::removal_type::normal,
            removal_request.remove_pk,
            removal_request.timestamp.count());
    bls_signature sig = signer.signMsg(msg);

    oxenc::bt_dict_producer d;
    // BLS pubkey to remove:
    d.append("remove", tools::view_guts(removal_request.remove_pk));
    // signature of *this* snode of the removing pubkey:
    d.append("signature", tools::view_guts(sig));

    m.send_reply("200", std::move(d).str());
}

void bls_aggregator::get_liquidation(oxenmq::Message& m) {
    oxen::log::trace(logcat, "Received omq liquidation signature request");
    bls_removal_request removal_request = extract_removal_request(m);
    if (!removal_request.good)
        return;

    if (!core.is_node_liquidatable(removal_request.remove_pk)) {
        m.send_reply(
                "403",
                "Forbidden: The BLS key {} is not currently liquidatable"_format(
                        removal_request.remove_pk));
        return;
    }

    auto& signer = core.bls_signer();
    std::vector<uint8_t> msg = get_removal_msg_to_sign(
            core.get_nettype(),
            bls_aggregator::removal_type::liquidate,
            removal_request.remove_pk,
            removal_request.timestamp.count());
    bls_signature sig = signer.signMsg(msg);

    oxenc::bt_dict_producer d;
    // BLS key of the node being liquidated:
    d.append("liquidate", tools::view_guts(removal_request.remove_pk));
    // signature of *this* snode of the liquidating pubkey:
    d.append("signature", tools::view_guts(sig));

    m.send_reply("200", std::move(d).str());
}

// Common code for removal and liquidation requests, which only differ in three ways:
// - the endpoint they go to;
// - the tag that gets used in the msg_to_sign hash; and
// - the key under which the signed pubkey gets confirmed back to us.
bls_removal_liquidation_response bls_aggregator::removal_liquidation_request(const bls_public_key& bls_pubkey, removal_type type) {
    // NOTE: The key in which the pubkey is inserted into the response which is a dictionary that is
    // serialised onto OMQ with by all the service nodes we contacted.
    std::string_view pubkey_key = "";

    // NOTE: The OMQ endpoint to hit
    std::string_view endpoint = "";
    switch (type) {
        case removal_type::normal: {
            endpoint = "bls.get_removal";
            pubkey_key = "removal";
        } break;
        case removal_type::liquidate: {
            endpoint = "bls.get_liqudation";
            pubkey_key = "liquidate";
        } break;
    }

    // FIXME: make this async
    assert(pubkey_key < "signature");  // response dict keys must be processed in sorted order, and
                                       // we expect the pubkey to be in a key that comes first.

    bls_removal_liquidation_response result;
    result.remove_pubkey = bls_pubkey;
    result.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
    result.msg_to_sign =
            get_removal_msg_to_sign(core.get_nettype(), type, bls_pubkey, result.timestamp);

    std::mutex signers_mutex;
    bls::Signature aggSig;
    aggSig.clear();

    oxenc::bt_dict_producer message_dict;
    message_dict.append("bls_pubkey", tools::view_guts(bls_pubkey));
    message_dict.append("timestamp", result.timestamp);

    nodes_request(
            endpoint,
            std::move(message_dict).str(),
            [endpoint, pubkey_key, &aggSig, &result, &signers_mutex, nettype = core.get_nettype()](
                    const bls_response& response, const std::vector<std::string>& data) {
                try {
                    if (!response.success || data.size() != 2 || data[0] != "200")
                        throw oxen::traced<std::runtime_error>{
                                "Request returned an error: {}"_format(fmt::join(data, " "))};

                    oxenc::bt_dict_consumer d{data[1]};
                    if (result.remove_pubkey != tools::make_from_guts<bls_public_key>(
                                                        d.require<std::string_view>(pubkey_key)))
                        throw oxen::traced<std::runtime_error>{
                                "BLS pubkey does not match the request"};

                    auto sig =
                            tools::make_from_guts<bls_signature>(d.require<std::string_view>("signa"
                                                                                             "tur"
                                                                                             "e"));

                    if (!BLSSigner::verifyMsg(
                                nettype, sig, response.sn.bls_pubkey, result.msg_to_sign)) {
                        throw oxen::traced<std::runtime_error>{
                                "Invalid BLS signature for BLS pubkey {}"_format(
                                        response.sn.bls_pubkey)};
                    }

                    {
                        std::lock_guard<std::mutex> lock(signers_mutex);
                        bls::Signature bls_sig = bls_utils::from_crypto_signature(sig);
                        aggSig.add(bls_sig);
                        result.signers_bls_pubkeys.push_back(response.sn.bls_pubkey);
                    }
                } catch (const std::exception& e) {
                    oxen::log::warning(
                            logcat,
                            "{} signature response rejected from {}: {}",
                            endpoint,
                            response.sn.sn_pubkey,
                            e.what());
                }
            });

    result.signature = bls_utils::to_crypto_signature(aggSig);

#ifndef NDEBUG
    bls::PublicKey aggPub;
    aggPub.clear();

    for (const auto& blspk : result.signers_bls_pubkeys)
        aggPub.add(bls_utils::from_crypto_pubkey(blspk));

    oxen::log::trace(
            logcat,
            "BLS agg pubkey for {} requests: {} ({} aggregations) with signature {}",
            endpoint,
            bls_utils::to_crypto_pubkey(aggPub),
            result.signers_bls_pubkeys.size(),
            result.signature);
#endif

    return result;
}
}  // namespace eth
