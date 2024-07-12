#pragma once
#include <crypto/crypto.h>
#include <oxen_economy.h>

#include <ethyl/logs.hpp>
#include <ethyl/provider.hpp>
#include <string>
#include <unordered_set>
#include <variant>

#include "common/formattable.h"
#include "crypto/crypto.h"
#include "crypto/eth.h"
#include "cryptonote_config.h"

namespace eth {

enum class TransactionType {
    NewServiceNode,
    ServiceNodeRemovalRequest,
    ServiceNodeRemoval,
    Other
};

struct Contributor {
    eth::address addr;
    uint64_t amount;
};

struct L2StateChange {};

struct NewServiceNodeTx : L2StateChange {
    bls_public_key bls_pubkey;
    eth::address eth_address;
    crypto::public_key sn_pubkey;
    crypto::ed25519_signature ed_signature;
    uint64_t fee;
    std::vector<Contributor> contributors;
    std::string to_string() const;
};

struct ServiceNodeRemovalRequestTx : L2StateChange {
    bls_public_key bls_pubkey;

    std::string to_string() const;
};

struct ServiceNodeRemovalTx : L2StateChange {
    eth::address eth_address;
    uint64_t amount;
    bls_public_key bls_pubkey;

    std::string to_string() const;
};

template <std::derived_from<L2StateChange> Tx>
constexpr std::string_view state_change_name() = delete;
template <> inline constexpr std::string_view state_change_name<NewServiceNodeTx>() { return "new service node"sv; }
template <> inline constexpr std::string_view state_change_name<ServiceNodeRemovalRequestTx>() { return "removal request"sv; }
template <> inline constexpr std::string_view state_change_name<ServiceNodeRemovalTx>() { return "SN removal"sv; }

using TransactionStateChangeVariant = std::variant<
        std::monostate,
        NewServiceNodeTx,
        ServiceNodeRemovalRequestTx,
        ServiceNodeRemovalTx>;

TransactionStateChangeVariant getLogTransaction(const ethyl::LogEntry& log);
inline bool is_state_change(const TransactionStateChangeVariant& v) {
    return v.index() > 0;
}

struct ContractServiceNode {
    bool good;
    uint64_t next;
    uint64_t prev;
    eth::address operatorAddr;
    bls_public_key pubkey;
    uint64_t leaveRequestTimestamp;
    uint64_t deposit;
    std::array<Contributor, oxen::MAX_CONTRIBUTORS_HF19> contributors;
    size_t contributorsSize;
};

class RewardsContract {
  public:
    // Constructor
    RewardsContract(cryptonote::network_type nettype, ethyl::Provider& provider);

    std::string_view address() { return contractAddress; }

    ContractServiceNode serviceNodes(
            uint64_t index, std::optional<uint64_t> blockNumber = std::nullopt);
    std::vector<uint64_t> getNonSigners(const std::unordered_set<bls_public_key>& bls_public_keys);
    std::vector<bls_public_key> getAllBLSPubkeys(uint64_t blockNumber);

  private:
    std::string contractAddress;
    ethyl::Provider& provider;
};

}  // namespace eth

template <std::derived_from<eth::L2StateChange> T>
inline constexpr bool ::formattable::via_to_string<T> = true;
