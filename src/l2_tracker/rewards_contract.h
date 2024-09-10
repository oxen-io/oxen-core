#pragma once
#include <common/formattable.h>
#include <crypto/crypto.h>
#include <crypto/eth.h>
#include <cryptonote_config.h>
#include <oxen_economy.h>  // oxen::MAX_CONTRIBUTORS_HF19

#include <string>
#include <unordered_set>

#include "events.h"

namespace ethyl {
struct Provider;
struct LogEntry;
};

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
    std::array<event::Contributor, oxen::MAX_CONTRIBUTORS_HF19> contributors;
    size_t contributorsSize;
};

class RewardsContract {
  public:
    // Constructor
    RewardsContract(cryptonote::network_type nettype, ethyl::Provider& provider);

    std::string_view address() const { return contract_address; }

    ContractServiceNode service_nodes(
            uint64_t index, std::optional<uint64_t> block_number = std::nullopt);
    std::vector<uint64_t> get_non_signers(
            const std::unordered_set<bls_public_key>& bls_public_keys);

    std::vector<bls_public_key> get_all_bls_pubkeys(uint64_t block_number);

    struct ServiceNodeIDs
    {
        bool success;
        std::vector<uint64_t> ids;
        std::vector<bls_public_key> bls_pubkeys;
    };

    // Executes `allServiceNodeIDs` on the smart contract and retrieve all the BLS public keys and
    // the ID allocated for each key in the contract
    ServiceNodeIDs all_service_node_ids(std::optional<uint64_t> block_number = std::nullopt);

  private:
    std::string contract_address;
    ethyl::Provider& provider;
};

}  // namespace eth
