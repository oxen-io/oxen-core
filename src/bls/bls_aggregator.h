#pragma once

#include <oxenmq/oxenmq.h>

#include <string>
#include <vector>

#include "bls_signer.h"
#include "cryptonote_core/service_node_list.h"

struct aggregateExitResponse {
    std::string bls_key;
    std::string signed_message;
    std::vector<std::string> signers_bls_pubkeys;
    std::string signature;
};

struct aggregateWithdrawalResponse {
    std::string address;
    uint64_t amount;
    uint64_t height;
    std::string signed_message;
    std::vector<std::string> signers_bls_pubkeys;
    std::string signature;
};

struct blsRegistrationResponse {
    std::string bls_pubkey;
    std::string proof_of_possession;
    std::string address;
    std::string service_node_pubkey;
    std::string service_node_signature;
};

struct BLSRequestResult {
    service_nodes::service_node_address sn_address;
    bool success;
};

class BLSAggregator {
  private:
    std::shared_ptr<BLSSigner> bls_signer;
    std::shared_ptr<oxenmq::OxenMQ> omq;
    service_nodes::service_node_list& service_node_list;

  public:
    BLSAggregator(
            service_nodes::service_node_list& _snl,
            std::shared_ptr<oxenmq::OxenMQ> _omq,
            std::shared_ptr<BLSSigner> _bls_signer);

    std::vector<std::pair<std::string, std::string>> getPubkeys();
    aggregateWithdrawalResponse aggregateRewards(const std::string& address);
    aggregateExitResponse aggregateExit(const std::string& bls_key);
    aggregateExitResponse aggregateLiquidation(const std::string& bls_key);
    blsRegistrationResponse registration(
            const std::string& senderEthAddress, const std::string& serviceNodePubkey) const;

  private:
    // Goes out to the nodes on the network and makes oxenmq requests to all of them, when getting
    // the reply `callback` will be called to process their reply
    void processNodes(
            std::string_view request_name,
            std::function<void(
                    const BLSRequestResult& request_result, const std::vector<std::string>& data)>
                    callback,
            const std::optional<std::string>& message = std::nullopt);
};
