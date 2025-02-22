#pragma once
#include <common/formattable.h>
#include <crypto/crypto.h>
#include <crypto/eth.h>
#include <cryptonote_config.h>
#include <oxen_economy.h>  // oxen::MAX_CONTRIBUTORS_HF19

#include <functional>
#include <string>
#include <unordered_set>

#include "events.h"

namespace ethyl {
struct Provider;
struct LogEntry;
};  // namespace ethyl

namespace eth {

event::StateChangeVariant get_log_event(uint64_t chain_id, const ethyl::LogEntry& log);
inline bool is_state_change(const event::StateChangeVariant& v) {
    return v.index() > 0;
}

struct ContractServiceNode {
    bool good;
    uint64_t next;
    uint64_t prev;
    address operatorAddr;
    bls_public_key pubkey;
    uint64_t addedTimestamp;
    uint64_t leaveRequestTimestamp;
    uint64_t deposit;
    std::array<event::ContributorV2, oxen::MAX_CONTRIBUTORS_HF19> contributors;
    size_t contributorsSize;
};

struct NonSigners {
    // List of non-signer contract IDs to submit with the contract
    std::vector<uint64_t> missing_ids;

    // List of provided BLS pubkeys that are *not* in the contract and so should be removed
    // before submitting to the contract.
    std::unordered_set<bls_public_key> unwanted;
};

using ServiceNodeIDs = std::vector<std::pair<uint64_t, bls_public_key>>;

class RewardsContract {
  public:
    // Constructor
    RewardsContract(cryptonote::network_type nettype, ethyl::Provider& provider);

    std::string_view address() const { return contract_address; }

    // Initiates a L2 request for all current service nodes and, when the request completes, fires
    // the callback with two vectors: the first is the contract ID of any contract nodes not present
    // in `bls_public_keys` (i.e. missing signatures) to be submitted as part of the contract call;
    // the second is the set of input pubkeys that were not found in the contract (i.e. proposed
    // signers that shouldn't be signers at all) that should be removed from the aggregate signature
    // before submission to the contract.
    void get_non_signers(
            std::unordered_set<bls_public_key> bls_public_keys,
            std::function<void(std::optional<NonSigners>)> callback);

    static ServiceNodeIDs parse_all_service_node_ids(std::string_view call_result_hex);

    // Executes `allServiceNodeIDs` on the smart contract and retrieve all the BLS public keys and
    // the ID allocated for each key in the contract.  Asynchronous; invokes the given callback when
    // the result completes (or with nullopt on error).
    void all_service_node_ids(
            std::optional<uint64_t> block_number,
            std::function<void(std::optional<ServiceNodeIDs>)> callback);

  private:
    std::string contract_address;
    ethyl::Provider& provider;
};

}  // namespace eth
