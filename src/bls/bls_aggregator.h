#pragma once

#include <string>
#include <vector>

#include "crypto/crypto.h"
#include "cryptonote_core/service_node_list.h"

namespace oxenmq {
class OxenMq;
}

namespace eth {
struct bls_aggregate_signed {
    std::vector<uint8_t> msg_to_sign;
    std::vector<bls_public_key> signers_bls_pubkeys;
    bls_signature signature;
};

struct bls_removal_liquidation_response : bls_aggregate_signed {
    bls_public_key remove_pubkey;
    uint64_t timestamp;
};

struct bls_rewards_response : bls_aggregate_signed {
    address addr;
    uint64_t amount;
    uint64_t height;
};

struct bls_registration_response {
    bls_public_key bls_pubkey;
    bls_signature proof_of_possession;
    address addr;
    crypto::public_key sn_pubkey;
    crypto::ed25519_signature ed_signature;
};

struct bls_response {
    service_nodes::service_node_address sn;
    bool success;
};

class bls_aggregator {
  public:
    using request_callback =
            std::function<void(const bls_response& response, const std::vector<std::string>& data)>;

    explicit bls_aggregator(cryptonote::core& core);

    // Request the service node network to sign the requested amount of
    // 'rewards' for the given Ethereum 'address' if by consensus they agree
    // that the amount is valid. This node (the aggregator) will aggregate the
    // signatures into the response.
    //
    // This function throws an `invalid_argument` exception if `address` is zero or, the `rewards`
    // amount is `0` or height is greater than the current blockchain height.
    bls_rewards_response rewards_request(const address& addr, uint64_t height);

    enum class removal_type {
        normal,
        liquidate,
    };

    // Request the service node network to sign a request to remove the node specified by
    // `bls_pubkey` from the network. The nature of this removal is set by `type`. This node (the
    // aggregator) will aggregate the signatures into the response.
    bls_removal_liquidation_response removal_liquidation_request(
            const bls_public_key& bls_pubkey, removal_type type);

    bls_registration_response registration(
            const address& sender, const crypto::public_key& sn_pubkey) const;

  private:
    void get_reward_balance(oxenmq::Message& m);
    void get_removal(oxenmq::Message& m);
    void get_liquidation(oxenmq::Message& m);

    // Goes out to the nodes on the network and makes oxenmq requests to all of them, when getting
    // the reply `callback` will be called to process their reply
    // Returns the number of nodes that we dispatched a request to
    uint64_t nodes_request(
            std::string_view request_name,
            std::string_view message,
            const request_callback& callback);

  private:
    cryptonote::core& core;

    // The BLS aggregator can be called from multiple threads via the RPC server. Since we have a
    // cache that can be concurrently written to, we guard that around a lock.
    std::mutex mutex;
    std::unordered_map<address, bls_rewards_response> rewards_response_cache;
};
}  // namespace eth
