#pragma once

#include <common/formattable.h>
#include <crypto/crypto.h>
#include <cryptonote_core/service_node_list.h>

#include <string>
#include <vector>

#include "bls/bls_crypto.h"
#include "crypto/eth.h"

namespace oxenmq {
class OxenMq;
}

namespace eth {
struct bls_aggregate_signed {
    std::vector<uint8_t> msg_to_sign;
    std::unordered_map<bls_public_key, bls_signature> signatures;  // Individual signatures
    bls_public_key aggregate_pubkey;  // Aggregate pubkey of the pubkeys in `signatures`
    bls_signature signature;          // Aggregate of all the signatures in `signatures`
};

enum class bls_exit_type {
    normal,
    liquidate,
};

struct bls_exit_liquidation_response : bls_aggregate_signed {
    bls_exit_type type;
    bls_public_key remove_pubkey;
    uint64_t timestamp;

    std::string to_string() const;
};

struct bls_rewards_response : bls_aggregate_signed {
    address addr;
    uint64_t amount;
    uint64_t height;

    std::string to_string() const;
};

struct bls_registration_response {
    bls_public_key bls_pubkey;
    bls_signature proof_of_possession;
    address addr;
    crypto::public_key sn_pubkey;
    crypto::ed25519_signature ed_signature;
};

using request_callback = std::function<void(
        const service_nodes::service_node_address& sn,
        bool success,
        std::vector<std::string> data)>;

class bls_aggregator {
  public:
    explicit bls_aggregator(cryptonote::core& core);

    // Request the service node network to sign the requested amount of `rewards` for the given
    // Ethereum `address` if by consensus they agree that the amount is valid. Once all requests
    // finish, this node (the aggregator) will aggregate the signatures into the response and pass
    // it to `callback`.
    //
    // This function is asychronous: it returns immediately, calling `callback` once the final
    // aggregate response is available.
    //
    // This function throws an `invalid_argument` exception if `address` is zero or, the `rewards`
    // amount is `0` or height is greater than the current blockchain height.
    void rewards_request(
            const address& addr,
            uint64_t height,
            std::function<void(std::shared_ptr<const bls_rewards_response>)> callback);

    // Request the service node network to sign a request to remove the node specified by `pubkey`
    // (either SN pubkey or BLS pubkey) from the network. The nature of this exit is set by `type`.
    // This node (the aggregator) will aggregate the signatures into the response, and call
    // `callback` with it once available.
    //
    // For normal (non-liqudiation) exits, the pubkey must exist in the recently removed nodes list.
    // For liquidations via bls pubkey, this is not required (that is: liquidations can be issued
    // for BLS pubkeys that oxend does not know about, to be able to remove bad registrations that
    // oxend doesn't accept for whatever reason from the contract side).
    //
    // This function is asychronous: it returns immediately, later calling `callback` once the
    // final aggregate response is available.
    void exit_liquidation_request(
            const std::variant<crypto::public_key, eth::bls_public_key>& pubkey,
            bls_exit_type type,
            std::function<void(std::shared_ptr<const bls_exit_liquidation_response>)> callback);

    bls_registration_response registration(
            const address& sender, const crypto::public_key& sn_pubkey) const;

  private:
    void get_rewards(oxenmq::Message& m) const;

    void get_exit_liquidation(oxenmq::Message& m, bls_exit_type type) const;

    template <typename Result>
    struct node_req_data {
        Result result;
        size_t remaining;
        std::mutex signers_mutex;
        eth::signature_aggregator agg_sig;
    };

    // Initiates asynchronous requests to service nodes on the network, making oxenmq requests to
    // each of them; as each reply is returned the the reply `callback` will be called to process
    // the reply.  Once the callback has been invoked for all requests (successful or failed) the
    // `final_callback` is invoked (if non-null).
    //
    // Returns the total number of nodes to which requests will be sent.
    //
    // Note that this function is asychronous: it returns immediately without waiting for replies.
    uint64_t nodes_request(
            std::string request_name,
            std::string message,
            request_callback callback,
            std::function<void(int total_requests)> final_callback);

    cryptonote::core& core;

    // The BLS aggregator can be called from multiple threads via the RPC server. Since we have a
    // cache that can be concurrently written to, we guard each cache by a lock
    std::mutex rewards_response_cache_mutex;

    // See `rewards_response_cache_mutex`
    std::mutex exit_liquidation_response_cache_mutex;

    // Cache the aggregate signature response for updating rewards to avoid requerying the network
    std::unordered_map<address, std::shared_ptr<bls_rewards_response>> rewards_response_cache;

    // The cache for exits and liquidation signature aggregations. See `rewards_response_cache`
    std::unordered_map<bls_public_key, std::shared_ptr<bls_exit_liquidation_response>>
            exit_liquidation_response_cache;
};
}  // namespace eth

template <>
inline constexpr bool formattable::via_to_string<eth::bls_exit_type> = true;

template <std::derived_from<eth::bls_aggregate_signed> T>
inline constexpr bool ::formattable::via_to_string<T> = true;
