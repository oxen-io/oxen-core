#include "bls_aggregator.h"

#include <oxenc/bt_producer.h>

#include "bls/bls_utils.h"
#include "common/exception.h"
#include "common/bigint.h"
#include "common/guts.h"
#include "common/string_util.h"
#include "crypto/crypto.h"
#include "cryptonote_core/cryptonote_core.h"
#include "ethyl/utils.hpp"
#include "logging/oxen_logger.h"


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

static auto logcat = oxen::log::Cat("bls_aggregator");

BLSAggregator::BLSAggregator(cryptonote::core& _core) : core{_core} {

    if (core.service_node()) {
        auto& omq = core.get_omq();
        omq.add_category("bls", oxenmq::Access{oxenmq::AuthLevel::none})
                .add_request_command(
                        "get_reward_balance", [this](auto& m) { get_reward_balance(m); })
                .add_request_command("get_exit", [this](auto& m) { get_exit(m); })
                .add_request_command("get_liquidation", [this](auto& m) { get_liquidation(m); });
    }
}

BLSRegistrationResponse BLSAggregator::registration(
        const crypto::eth_address& sender, const crypto::public_key& serviceNodePubkey) const {
    auto& signer = core.get_bls_signer();
    return BLSRegistrationResponse{
            .bls_pubkey = signer.getCryptoPubkey(),
            .proof_of_possession = signer.proofOfPossession(sender, serviceNodePubkey),
            .address = sender,
            .sn_pubkey = serviceNodePubkey,
            .ed_signature = crypto::null<crypto::ed25519_signature>};
}

void BLSAggregator::nodesRequest(
        std::string_view request_name,
        std::string_view message,
        const request_callback& callback) {
    std::mutex connection_mutex;
    std::condition_variable cv;
    size_t active_connections = 0;
    const size_t MAX_CONNECTIONS = 900;

    // FIXME: make this function async rather than blocking

    std::vector<service_nodes::service_node_address> snodes;
    core.get_service_node_list().copy_reachable_active_service_node_addresses(
            std::back_inserter(snodes));

    auto& omq = core.get_omq();
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
                    callback(BLSRequestResult{snodes[i], success}, data);
                    std::lock_guard connection_lock{connection_mutex};
                    assert(active_connections);
                    if (--active_connections == 0)
                        cv.notify_all();
                },
                message);
    }

    std::unique_lock connection_lock{connection_mutex};
    cv.wait(connection_lock, [&active_connections] { return active_connections == 0; });
}

// Takes a oxenmq::Message expected to contain a single argument extractable to a `T` that must be
// encoded as raw bytes, hex, or 0x-prefixed hex.  Sends an appropriate reply and returns false on
// error, otherwise sets `val` and returns true.
template <tools::safe_to_memcpy T>
static bool extract_1part_msg(
        oxenmq::Message& m, T& val, std::string_view cmd_name, std::string_view value_name) {
    if (m.data.size() != 1) {
        m.send_reply(
                "400",
                "Bad request: {} command should have one {} data part; received {}"_format(
                        cmd_name, value_name, m.data.size()));
        return false;
    }
    if (m.data[0].size() == 2 + 2 * sizeof(T) &&
        (m.data[0].starts_with("0x") || m.data[0].starts_with("0X")) && oxenc::is_hex(m.data[0])) {
        std::string_view hex{m.data[0]};
        hex.remove_prefix(2);
        val = tools::make_from_hex_guts<T>(hex, false);
        return true;
    }
    if (m.data[0].size() == 2 * sizeof(T) && oxenc::is_hex(m.data[0])) {
        val = tools::make_from_hex_guts<T>(m.data[0], false);
        return true;
    }
    if (m.data[0].size() == sizeof(T)) {
        val = tools::make_from_guts<T>(m.data[0]);
        return true;
    }

    m.send_reply(
            "400",
            "Bad request: {} command data should be a {}-byte {}; got {} bytes"_format(
                    cmd_name, sizeof(T), value_name, m.data[0].size()));
    return false;
}

void BLSAggregator::get_reward_balance(oxenmq::Message& m) {
    oxen::log::trace(logcat, "Received omq rewards signature request");

    crypto::eth_address eth_addr;
    if (!extract_1part_msg(m, eth_addr, "BLS rewards", "ETH address"))
        return;

    auto [batchdb_height, amount] =
            core.get_blockchain_storage().sqlite_db()->get_accrued_earnings(eth_addr);
    if (amount == 0) {
        m.send_reply("400", "Address '{}' has a zero balance in the database"_format(eth_addr));
        return;
    }

    // We sign H(H(rewardTag || chainid || contract) || recipientAddress ||
    // recipientAmount),
    // where everything is in bytes, and recipientAmount is a 32-byte big
    // endian integer value.
    auto& signer = core.get_bls_signer();
    const auto tag = signer.buildTagHash(signer.rewardTag);

    // TODO(doyle): Pass in a array of spans to avoid having to do this allocation.
    std::array<std::byte, 32> amount_be = tools::encode_integer_be<32>(amount);

    std::vector<uint8_t> msg;
    msg.reserve(tag.size() + eth_addr.size() + amount_be.size());
    msg.insert(msg.end(), tag.begin(), tag.end());
    msg.insert(msg.end(), eth_addr.begin(), eth_addr.end());
    msg.insert(msg.end(), reinterpret_cast<uint8_t *>(amount_be.begin()), reinterpret_cast<uint8_t *>(amount_be.end()));
    crypto::bls_signature sig = bls_utils::to_crypto_signature(signer.signSig2(msg));

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

static std::string dump_bls_rewards_response(const BLSRewardsResponse &item)
{
    std::string result =
            "BLS rewards response was:\n"
            "\n"
            "  - address:     {}\n"
            "  - amount:      {}\n"
            "  - height:      {}\n"
            "  - signature:   {}\n"
            "  - signed_hash: {}\n"_format(
                    item.address, item.amount, item.height, item.signature, item.signed_hash);
    return result;
}

BLSRewardsResponse BLSAggregator::rewards_request(
        const crypto::eth_address& address) {

    auto [height, amount] =
            core.get_blockchain_storage().sqlite_db()->get_accrued_earnings(address);

    // FIXME: make this async

    oxen::log::trace(
            logcat,
            "Initiating rewards request of {} SENT for {} at height {}",
            amount,
            address,
            height);

    const auto& service_node_list = core.get_service_node_list();

    // NOTE: Validate the arguments
    if (address == crypto::null<crypto::eth_address>) {
        throw oxen::invalid_argument(fmt::format(
                "Aggregating a rewards request for the zero address for {} SENT at height {} is "
                "invalid because address is invalid. Request rejected",
                address,
                amount,
                height,
                service_node_list.height()));
    }

    if (amount == 0) {
        throw oxen::invalid_argument(fmt::format(
                "Aggregating a rewards request for '{}' for 0 SENT at height {} is invalid because "
                "no rewards are available. Request rejected.",
                address,
                height));
    }

    if (height > service_node_list.height()) {
        throw oxen::invalid_argument(fmt::format(
                "Aggregating a rewards request for '{}' for {} SENT at height {} is invalid "
                "because the height is greater than the blockchain height {}. Request rejected",
                address,
                amount,
                height,
                service_node_list.height()));
    }

    BLSRewardsResponse result{};
    result.address = address;
    result.amount = amount;
    result.height = height;
    result.signed_hash = keccak(
            BLSSigner::buildTagHash(BLSSigner::rewardTag, core.get_nettype()),
            result.address, tools::encode_integer_be<32>(amount));

    // `nodesRequest` dispatches to a threadpool hence we require synchronisation:
    std::mutex sig_mutex;
    bls::Signature aggSig;
    aggSig.clear();

    // NOTE: Send aggregate rewards request to the remainder of the network. This is a blocking
    // call (FIXME -- it should not be!)
    nodesRequest(
            "bls.get_reward_balance",
            tools::view_guts(address),
            [&aggSig, &result, &sig_mutex, nettype = core.get_nettype()](
                    const BLSRequestResult& request_result, const std::vector<std::string>& data) {

                BLSRewardsResponse response = {};
                bool partially_parsed = true;
                try {
                    if (!request_result.success || data.size() != 2 || data[0] != "200")
                        throw oxen::runtime_error{
                                "Error retrieving reward balance: {}"_format(fmt::join(data, " "))};

                    oxenc::bt_dict_consumer d{data[1]};

                    response.address = tools::make_from_guts<crypto::eth_address>(
                            d.require<std::string_view>("address"));
                    response.amount = d.require<uint64_t>("amount");
                    response.height = d.require<uint64_t>("height");
                    response.signature = tools::make_from_guts<crypto::bls_signature>(
                            d.require<std::string_view>("signature"));

                    if (response.address != result.address)
                        throw oxen::runtime_error{"Response ETH address {} does not match the request address {}"_format(response.address, result.address)};
                    if (response.amount != result.amount || response.height != result.height)
                        throw oxen::runtime_error{
                                    "Balance/height mismatch: expected {}/{}, got {}/{}"_format(
                                            result.amount, result.height, response.amount, response.height)};

                    bls::Signature bls_sig = bls_utils::from_crypto_signature(response.signature);

                    // TODO(doyle): Fix this
                    // if (!BLSSigner::verifyHash(nettype,
                    //             bls_sig,
                    //             bls_utils::from_crypto_pubkey(request_result.sn.bls_pubkey),
                    //             result.signed_hash))
                    //     throw oxen::runtime_error{"Invalid BLS signature for BLS pubkey {}."_format(
                    //             request_result.sn.bls_pubkey)};

                    {
                        std::lock_guard lock{sig_mutex};
                        aggSig.add(bls_sig);
                        result.signers_bls_pubkeys.push_back(request_result.sn.bls_pubkey);
                    }

                    partially_parsed = false;

                    oxen::log::trace(
                            logcat,
                            "Reward balance response accepted from {} (BLS {} XKEY {} {}:{})\nWe requested: {}\nThe response had: {}",
                            request_result.sn.sn_pubkey,
                            request_result.sn.bls_pubkey,
                            request_result.sn.x_pubkey,
                            request_result.sn.ip,
                            request_result.sn.port,
                            dump_bls_rewards_response(result),
                            dump_bls_rewards_response(response));

                } catch (const std::exception& e) {
                    std::string what_msg;
                    if (const auto* oxen_exception = dynamic_cast<const oxen::exception*>(&e))
                        what_msg = oxen_exception->what();
                    else
                        what_msg = e.what();

                    oxen::log::warning(
                            logcat,
                            "Reward balance response rejected from {}: {}\nWe requested: {}\nThe response had{}: {}",
                            request_result.sn.sn_pubkey,
                            what_msg,
                            dump_bls_rewards_response(result),
                            partially_parsed ? " (partially parsed)" : "",
                            dump_bls_rewards_response(response));
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
            "BLS aggregate pubkey for reward requests: {} ({} aggregations) with signature {}",
            bls_utils::to_crypto_pubkey(aggPub),
            result.signers_bls_pubkeys.size(),
            result.signature
            );
#endif

    return result;
}

void BLSAggregator::get_exit(oxenmq::Message& m) {
    oxen::log::trace(logcat, "Received omq exit signature request");

    crypto::bls_public_key exiting_pk;
    if (!extract_1part_msg(m, exiting_pk, "BLS exit", "BLS pubkey"))
        return;

    // right not its approving everything
    if (!core.is_node_removable(exiting_pk)) {
        m.send_reply(
                "403",
                "Forbidden: The BLS pubkey {} is not currently removable."_format(exiting_pk));
        return;
    }

    auto& signer = core.get_bls_signer();
    const auto tag = signer.buildTagHash(signer.removalTag);

    // TODO(doyle): Pass in a array of spans to avoid having to do this allocation.
    std::vector<uint8_t> msg;
    msg.reserve(tag.size() + exiting_pk.size());
    msg.insert(msg.end(), tag.begin(), tag.end());
    msg.insert(msg.end(), exiting_pk.begin(), exiting_pk.end());
    crypto::bls_signature sig = bls_utils::to_crypto_signature(signer.signSig2(msg));

    oxenc::bt_dict_producer d;
    // exiting BLS pubkey:
    d.append("exit", tools::view_guts(exiting_pk));
    // signature of *this* snode of the exiting pubkey:
    d.append("signature", tools::view_guts(sig));

    m.send_reply("200", std::move(d).str());
}

void BLSAggregator::get_liquidation(oxenmq::Message& m) {
    oxen::log::trace(logcat, "Received omq liquidation signature request");

    crypto::bls_public_key liquidating_pk;
    if (!extract_1part_msg(m, liquidating_pk, "BLS exit", "BLS pubkey"))
        return;

    if (!core.is_node_liquidatable(liquidating_pk)) {
        m.send_reply(
                "403",
                "Forbidden: The BLS key {} is not currently liquidatable"_format(liquidating_pk));
        return;
    }

    auto& signer = core.get_bls_signer();
    const auto tag = signer.buildTagHash(signer.liquidateTag);

    // TODO(doyle): Pass in a array of spans to avoid having to do this allocation.
    std::vector<uint8_t> msg;
    msg.reserve(tag.size() + liquidating_pk.size());
    msg.insert(msg.end(), tag.begin(), tag.end());
    msg.insert(msg.end(), liquidating_pk.begin(), liquidating_pk.end());
    crypto::bls_signature sig = bls_utils::to_crypto_signature(signer.signSig2(msg));

    oxenc::bt_dict_producer d;
    // BLS key of the node being liquidated:
    d.append("liquidate", tools::view_guts(liquidating_pk));
    // signature of *this* snode of the liquidating pubkey:
    d.append("signature", tools::view_guts(sig));

    m.send_reply("200", std::move(d).str());
}

// Common code for exit and liquidation requests, which only differ in three ways:
// - the endpoint they go to;
// - the tag that gets used in the signed hash; and
// - the key under which the signed pubkey gets confirmed back to us.
AggregateExitResponse BLSAggregator::aggregateExitOrLiquidate(
        const crypto::bls_public_key& bls_pubkey,
        std::string_view hash_tag,
        std::string_view endpoint,
        std::string_view pubkey_key) {

    // FIXME: make this async

    assert(pubkey_key < "signature");  // response dict keys must be processed in sorted order, and
                                       // we expect the pubkey to be in a key that comes first.

    AggregateExitResponse result;
    result.exit_pubkey = bls_pubkey;
    result.signed_hash =
            crypto::keccak(BLSSigner::buildTagHash(hash_tag, core.get_nettype()), bls_pubkey);

    std::mutex signers_mutex;
    bls::Signature aggSig;
    aggSig.clear();

    nodesRequest(
            endpoint,
            tools::view_guts(bls_pubkey),
            [endpoint, pubkey_key, &aggSig, &result, &signers_mutex](
                    const BLSRequestResult& request_result, const std::vector<std::string>& data) {

                try {
                    if (!request_result.success || data.size() != 2 || data[0] != "200")
                        throw oxen::runtime_error{
                                "Request returned an error: {}"_format(fmt::join(data, " "))};

                    oxenc::bt_dict_consumer d{data[1]};
                    if (result.exit_pubkey != tools::make_from_guts<crypto::bls_public_key>(
                                                      d.require<std::string_view>(pubkey_key)))
                        throw oxen::runtime_error{"BLS pubkey does not match the request"};

                    auto sig = tools::make_from_guts<crypto::bls_signature>(
                            d.require<std::string_view>("signature"));

                    auto bls_sig = bls_utils::from_crypto_signature(sig);

                    if (!bls_sig.verifyHash(
                                bls_utils::from_crypto_pubkey(request_result.sn.bls_pubkey),
                                result.signed_hash.data(),
                                result.signed_hash.size()))
                        throw oxen::runtime_error{"Invalid BLS signature for BLS pubkey {}"_format(
                                request_result.sn.bls_pubkey)};

                    std::lock_guard<std::mutex> lock(signers_mutex);
                    aggSig.add(bls_sig);
                    result.signers_bls_pubkeys.push_back(request_result.sn.bls_pubkey);
                } catch (const std::exception& e) {
                    oxen::log::warning(
                            logcat,
                            "{} signature response rejected from {}: {}",
                            endpoint,
                            request_result.sn.sn_pubkey,
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
            result.signature
            );
#endif

    return result;
}

AggregateExitResponse BLSAggregator::aggregateExit(const crypto::bls_public_key& bls_pubkey) {
    return aggregateExitOrLiquidate(bls_pubkey, BLSSigner::removalTag, "bls.get_exit", "exit");
}

AggregateExitResponse BLSAggregator::aggregateLiquidation(
        const crypto::bls_public_key& bls_pubkey) {
    return aggregateExitOrLiquidate(
            bls_pubkey, BLSSigner::liquidateTag, "bls.get_liquidation", "liquidate");
}
