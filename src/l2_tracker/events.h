#pragma once
#include <compare>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "common/formattable.h"
#include "crypto/crypto.h"
#include "crypto/eth.h"
#include "cryptonote_basic/txtypes.h"

using namespace std::literals;

namespace eth::event {

struct L2StateChange {
    uint64_t chain_id;
    uint64_t l2_height;

    std::strong_ordering operator<=>(const L2StateChange&) const = default;

  protected:
    L2StateChange(uint64_t chain_id, uint64_t l2_height) :
            chain_id{chain_id}, l2_height{l2_height} {}
};

struct Contributor {
    eth::address address;
    uint64_t amount;

    auto operator<=>(const Contributor& o) const = default;

    template <class Archive>
    void serialize_object(Archive& ar) {
        field(ar, "address", address);
        field_varint(ar, "amount", amount);
    }
};

struct NewServiceNode : L2StateChange {
    crypto::public_key sn_pubkey = crypto::null<crypto::public_key>;
    bls_public_key bls_pubkey = crypto::null<bls_public_key>;
    crypto::ed25519_signature ed_signature = crypto::null<crypto::ed25519_signature>;
    uint64_t fee = 0;
    std::vector<Contributor> contributors;

    explicit NewServiceNode(uint64_t chain_id = 0, uint64_t l2_height = 0) :
            L2StateChange{chain_id, l2_height} {}

    std::string to_string() const {
        return "{} [sn_pubkey={}, bls_pubkey={}]"_format(description, sn_pubkey, bls_pubkey);
    }

    template <class Archive>
    void serialize_object(Archive& ar) {
        [[maybe_unused]] uint8_t version = 0;
        field_varint(ar, "version", version);
        field_varint(ar, "chain_id", chain_id);
        field_varint(ar, "l2_height", l2_height);
        field(ar, "service_node_pubkey", sn_pubkey);
        field(ar, "bls_pubkey", bls_pubkey);
        field(ar, "signature", ed_signature);
        field_varint(ar, "fee", fee);
        field(ar, "contributors", contributors);
    }

    std::strong_ordering operator<=>(const NewServiceNode& o) const = default;

    static constexpr cryptonote::txtype txtype = cryptonote::txtype::ethereum_new_service_node;
    static constexpr std::string_view description = "new SN"sv;
};

struct ServiceNodeExitRequest : L2StateChange {
    bls_public_key bls_pubkey = crypto::null<bls_public_key>;

    explicit ServiceNodeExitRequest(uint64_t chain_id = 0, uint64_t l2_height = 0) :
            L2StateChange{chain_id, l2_height} {}

    std::string to_string() const { return "{} [bls_pubkey={}]"_format(description, bls_pubkey); }

  public:
    std::strong_ordering operator<=>(const ServiceNodeExitRequest& o) const = default;

    template <class Archive>
    void serialize_object(Archive& ar) {
        [[maybe_unused]] uint8_t version = 0;
        field_varint(ar, "version", version);
        field_varint(ar, "chain_id", chain_id);
        field_varint(ar, "l2_height", l2_height);
        field(ar, "bls_pubkey", bls_pubkey);
    }

    static constexpr cryptonote::txtype txtype =
            cryptonote::txtype::ethereum_service_node_exit_request;
    static constexpr std::string_view description = "SN exit request"sv;
};

struct ServiceNodeExit : L2StateChange {
    bls_public_key bls_pubkey = crypto::null<bls_public_key>;
    uint64_t returned_amount = 0;

    explicit ServiceNodeExit(uint64_t chain_id = 0, uint64_t l2_height = 0) :
            L2StateChange{chain_id, l2_height} {}

    std::string to_string() const {
        return "{} [bls_pubkey={}, returned={}]"_format(description, bls_pubkey, returned_amount);
    }

    std::strong_ordering operator<=>(const ServiceNodeExit& o) const = default;

    template <class Archive>
    void serialize_object(Archive& ar) {
        [[maybe_unused]] uint8_t version = 0;
        field_varint(ar, "version", version);
        field_varint(ar, "chain_id", chain_id);
        field_varint(ar, "l2_height", l2_height);
        field(ar, "bls_pubkey", bls_pubkey);
        field_varint(ar, "returned_amount", returned_amount);
    }

    static constexpr cryptonote::txtype txtype = cryptonote::txtype::ethereum_service_node_exit;
    static constexpr std::string_view description = "SN exit"sv;
};

struct StakingRequirementUpdated : L2StateChange {
    uint64_t staking_requirement = 0;

    explicit StakingRequirementUpdated(uint64_t chain_id = 0, uint64_t l2_height = 0) :
            L2StateChange{chain_id, l2_height} {}

    std::string to_string() const { return "{} [{}]"_format(description, staking_requirement); }

    std::strong_ordering operator<=>(const StakingRequirementUpdated& o) const = default;

    template <class Archive>
    void serialize_object(Archive& ar) {
        [[maybe_unused]] uint8_t version = 0;
        field_varint(ar, "version", version);
        field_varint(ar, "chain_id", chain_id);
        field_varint(ar, "l2_height", l2_height);
        field_varint(ar, "staking_requirement", staking_requirement);
    }

    static constexpr cryptonote::txtype txtype =
            cryptonote::txtype::ethereum_staking_requirement_updated;
    static constexpr std::string_view description = "staking requirement update"sv;
};

using StateChangeVariant = std::variant<
        std::monostate,
        NewServiceNode,
        ServiceNodeExitRequest,
        ServiceNodeExit,
        StakingRequirementUpdated>;

}  // namespace eth::event

template <std::derived_from<eth::event::L2StateChange> T>
inline constexpr bool ::formattable::via_to_string<T> = true;
