#include "bls_aggregator.h"

#include "bls/bls_utils.h"
#include "common/guts.h"
#include "common/string_util.h"
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

BLSAggregator::BLSAggregator(
        service_nodes::service_node_list& _snl,
        std::shared_ptr<oxenmq::OxenMQ> _omq,
        std::shared_ptr<BLSSigner> _bls_signer) :
        bls_signer(std::move(_bls_signer)), omq(std::move(_omq)), service_node_list(_snl) {}

std::vector<std::pair<std::string, std::string>> BLSAggregator::getPubkeys() {
    std::vector<std::pair<std::string, std::string>> pubkeys;
    std::mutex pubkeys_mutex;

    processNodes(
            "bls.pubkey_request",
            [&pubkeys, &pubkeys_mutex](
                    const BLSRequestResult& request_result, const std::vector<std::string>& data) {
                if (request_result.success) {
                    std::lock_guard<std::mutex> lock(pubkeys_mutex);
                    pubkeys.emplace_back(data[0], data[1]);
                }
            });

    return pubkeys;
}

blsRegistrationResponse BLSAggregator::registration(
        const std::string& senderEthAddress, const std::string& serviceNodePubkey) const {
    return blsRegistrationResponse{
            bls_signer->getPublicKeyHex(),
            bls_signer->proofOfPossession(senderEthAddress, serviceNodePubkey),
            senderEthAddress,
            serviceNodePubkey,
            ""};
}

static void logNetworkRequestFailedWarning(
        const BLSRequestResult& result, std::string_view omq_cmd) {
    std::string ip_string = epee::string_tools::get_ip_string_from_int32(result.sn_address.ip);
    oxen::log::warning(
            logcat,
            "OMQ network request to {}:{} failed when executing '{}'",
            ip_string,
            std::to_string(result.sn_address.port),
            omq_cmd);
}

void BLSAggregator::processNodes(
        std::string_view request_name,
        std::function<void(const BLSRequestResult&, const std::vector<std::string>&)> callback,
        const std::optional<std::string>& message) {
    std::mutex connection_mutex;
    std::condition_variable cv;
    size_t active_connections = 0;
    const size_t MAX_CONNECTIONS = 900;

    std::vector<service_nodes::service_node_address> sn_nodes = {};
    service_node_list.copy_active_service_node_addresses(std::back_inserter(sn_nodes));

    for (const service_nodes::service_node_address& sn_address : sn_nodes) {
        if (1) {
            std::lock_guard<std::mutex> connection_lock(connection_mutex);
            ++active_connections;
        } else {
            // TODO(doyle): Rate limit
            std::unique_lock<std::mutex> connection_lock(connection_mutex);
            cv.wait(connection_lock,
                    [&active_connections] { return active_connections < MAX_CONNECTIONS; });
        }

        BLSRequestResult request_result = {};
        request_result.sn_address = sn_address;
        auto conn = omq->connect_sn(tools::view_guts(sn_address.x_pkey), oxenmq::AuthLevel::basic);
        if (message) {
            omq->request(
                    conn,
                    request_name,
                    [&connection_mutex, &active_connections, &cv, callback, &request_result](
                            bool success, std::vector<std::string> data) {
                        request_result.success = success;
                        callback(request_result, data);
                        std::lock_guard<std::mutex> connection_lock(connection_mutex);
                        --active_connections;
                        cv.notify_all();
                        // omq->disconnect(c);
                    },
                    *message);
        } else {
            omq->request(
                    conn,
                    request_name,
                    [&connection_mutex, &active_connections, &cv, callback, &request_result](
                            bool success, std::vector<std::string> data) {
                        request_result.success = success;
                        callback(request_result, data);
                        std::lock_guard<std::mutex> connection_lock(connection_mutex);
                        --active_connections;
                        cv.notify_all();
                        // omq->disconnect(c);
                    });
        }
    }

    std::unique_lock<std::mutex> connection_lock(connection_mutex);
    cv.wait(connection_lock, [&active_connections] { return active_connections == 0; });
}

aggregateWithdrawalResponse BLSAggregator::aggregateRewards(const std::string& address) {
    bls::Signature aggSig;
    aggSig.clear();
    std::vector<std::string> signers;
    std::mutex signers_mutex;
    uint64_t amount = 0;
    uint64_t height = 0;
    std::string signed_message = "";
    bool initial_data_set = false;
    std::string lower_eth_address = address;
    if (lower_eth_address.substr(0, 2) != "0x") {
        lower_eth_address = "0x" + lower_eth_address;
    }
    std::transform(
            lower_eth_address.begin(),
            lower_eth_address.end(),
            lower_eth_address.begin(),
            [](unsigned char c) { return std::tolower(c); });

    std::string_view cmd = "bls.get_reward_balance";
    processNodes(
            cmd,
            [&aggSig,
             &signers,
             &signers_mutex,
             &lower_eth_address,
             &amount,
             &height,
             &signed_message,
             &initial_data_set,
             cmd](const BLSRequestResult& request_result, const std::vector<std::string>& data) {
                if (request_result.success) {
                    if (data[0] == "200") {

                        // Data contains -> status, address, amount, height, bls_pubkey, signed
                        // message, signature
                        uint64_t current_amount = std::stoull(data[2]);
                        uint64_t current_height = std::stoull(data[3]);

                        signers_mutex.lock();
                        if (!initial_data_set) {
                            amount = current_amount;
                            height = current_height;
                            signed_message = data[5];
                            initial_data_set = true;
                        }
                        signers_mutex.unlock();

                        if (data[1] != lower_eth_address || current_amount != amount ||
                            current_height != height || data[5] != signed_message) {
                            // Log if the current data doesn't match the first set
                            oxen::log::warning(
                                    logcat,
                                    "Mismatch in data from node with bls pubkey {}. Expected "
                                    "address: {}, amount: {}, height: {} signed message: {}. "
                                    "Received address: {} amount: {}, height: {} signed_message: "
                                    "{}.",
                                    data[4],
                                    lower_eth_address,
                                    amount,
                                    height,
                                    signed_message,
                                    data[1],
                                    current_amount,
                                    current_height,
                                    data[5]);
                        } else {
                            bls::Signature external_signature;
                            external_signature.setStr(data[6]);
                            std::lock_guard<std::mutex> lock(signers_mutex);
                            aggSig.add(external_signature);
                            signers.push_back(data[4]);
                        }
                    } else {
                        oxen::log::warning(
                                logcat,
                                "Error message received when getting reward balance {} : {}",
                                data[0],
                                data[1]);
                    }
                } else {
                    logNetworkRequestFailedWarning(request_result, cmd);
                }
            },
            lower_eth_address);
    const auto sig_str = bls_utils::SignatureToHex(aggSig);
    return aggregateWithdrawalResponse{
            lower_eth_address, amount, height, signed_message, signers, sig_str};
}

aggregateExitResponse BLSAggregator::aggregateExit(const std::string& bls_key) {
    bls::Signature aggSig;
    aggSig.clear();
    std::vector<std::string> signers;
    std::mutex signers_mutex;
    std::string signed_message = "";
    bool initial_data_set = false;

    std::string_view cmd = "bls.get_exit";
    processNodes(
            cmd,
            [&aggSig, &signers, &signers_mutex, &bls_key, &signed_message, &initial_data_set, cmd](
                    const BLSRequestResult& request_result, const std::vector<std::string>& data) {
                if (request_result.success) {
                    if (data[0] == "200") {

                        // Data contains -> status, bls_pubkey (signer), bls_pubkey (node being
                        // removed), signed message, signature
                        signers_mutex.lock();
                        if (!initial_data_set) {
                            signed_message = data[3];
                            initial_data_set = true;
                        }
                        signers_mutex.unlock();
                        if (data[1] != bls_key || data[3] != signed_message) {
                            // Log if the current data doesn't match the first set
                            oxen::log::warning(
                                    logcat,
                                    "Mismatch in data from node with bls pubkey {}. Expected "
                                    "bls_key: {}, signed message: {}. Received bls_key: {}, "
                                    "signed_message: {}.",
                                    data[2],
                                    bls_key,
                                    signed_message,
                                    data[1],
                                    data[3]);
                        } else {
                            bls::Signature external_signature;
                            external_signature.setStr(data[4]);
                            std::lock_guard<std::mutex> lock(signers_mutex);
                            aggSig.add(external_signature);
                            signers.push_back(data[2]);
                        }
                    } else {
                        oxen::log::warning(
                                logcat,
                                "Error message received when requesting exit {} : {}",
                                data[0],
                                data[1]);
                    }
                } else {
                    logNetworkRequestFailedWarning(request_result, cmd);
                }
            },
            bls_key);
    const auto sig_str = bls_utils::SignatureToHex(aggSig);
    return aggregateExitResponse{bls_key, signed_message, signers, sig_str};
}

aggregateExitResponse BLSAggregator::aggregateLiquidation(const std::string& bls_key) {
    bls::Signature aggSig;
    aggSig.clear();
    std::vector<std::string> signers;
    std::mutex signers_mutex;
    std::string signed_message = "";
    bool initial_data_set = false;

    std::string_view cmd = "bls.get_liquidation";
    processNodes(
            cmd,
            [&aggSig, &signers, &signers_mutex, &bls_key, &signed_message, &initial_data_set, cmd](
                    const BLSRequestResult& request_result, const std::vector<std::string>& data) {
                if (request_result.success) {
                    if (data[0] == "200") {

                        // Data contains -> status, bls_pubkey (signer), bls_pubkey (node being
                        // removed), signed message, signature
                        signers_mutex.lock();
                        if (!initial_data_set) {
                            signed_message = data[3];
                            initial_data_set = true;
                        }
                        signers_mutex.unlock();

                        if (data[1] != bls_key || data[3] != signed_message) {
                            // Log if the current data doesn't match the first set
                            oxen::log::warning(
                                    logcat,
                                    "Mismatch in data from node with bls pubkey {}. Expected "
                                    "bls_key: {}, signed message: {}. Received bls_key: {}, "
                                    "signed_message: {}.",
                                    data[2],
                                    bls_key,
                                    signed_message,
                                    data[1],
                                    data[3]);
                        } else {
                            bls::Signature external_signature;
                            external_signature.setStr(data[4]);
                            std::lock_guard<std::mutex> lock(signers_mutex);
                            aggSig.add(external_signature);
                            signers.push_back(data[2]);
                        }
                    } else {
                        oxen::log::warning(
                                logcat,
                                "Error message received when requesting liquidation {} : {}",
                                data[0],
                                data[1]);
                    }
                } else {
                    logNetworkRequestFailedWarning(request_result, cmd);
                }
            },
            bls_key);
    const auto sig_str = bls_utils::SignatureToHex(aggSig);
    return aggregateExitResponse{bls_key, signed_message, signers, sig_str};
}
