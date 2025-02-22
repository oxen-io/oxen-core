#pragma once
#include <compare>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "common/formattable.h"
#include "common/util.h"
#include "crypto/crypto.h"
#include "crypto/eth.h"
#include "cryptonote_basic/txtypes.h"
#include "serialization/optional.h"

using namespace std::literals;

namespace eth::event {

struct L2StateChange {
    uint64_t chain_id;
    uint64_t l2_height;

    std::strong_ordering operator<=>(const L2StateChange&) const = default;

  protected:
    L2StateChange(uint64_t chain_id, uint64_t l2_height) :
            chain_id{chain_id}, l2_height{l2_height} {}

    template <class Archive>
    void serialize_base_fields(Archive& ar, uint8_t* version) {
        // if version is nullptr then serialize a 0 version with a throwaway value
        [[maybe_unused]] uint8_t version_zero = 0;
        if (!version)
            version = &version_zero;
        field_varint(ar, "version", *version);
        field_varint(ar, "chain_id", chain_id);
        field_varint(ar, "l2_height", l2_height);
    }
};

struct ContributorV2 {
    enum class Version {
        version_invalid,
        version_0,
        _count,
    };

    eth::address address;
    eth::address beneficiary;
    uint64_t amount;

    auto operator<=>(const ContributorV2& o) const = default;

    template <class Archive>
    void serialize_object(Archive& ar) {
        auto version = tools::enum_top<Version>;
        field_varint(ar, "version", version, [](auto v) {
            return v > Version::version_invalid && v < Version::_count;
        });
        field(ar, "address", address);

        std::optional<eth::address> serialized_beneficiary;
        if (Archive::is_serializer && beneficiary != address)
            serialized_beneficiary = beneficiary;
        field(ar, "beneficiary", serialized_beneficiary);
        if (Archive::is_deserializer)
            beneficiary = serialized_beneficiary ? *serialized_beneficiary : address;

        field_varint(ar, "amount", amount);
    }
};

struct NewServiceNodeV2 : L2StateChange {
    enum class Version { invalid = -1, v0, _count };
    Version version = Version::v0;
    crypto::public_key sn_pubkey = crypto::null<crypto::public_key>;
    bls_public_key bls_pubkey = crypto::null<bls_public_key>;
    crypto::ed25519_signature ed_signature = crypto::null<crypto::ed25519_signature>;
    uint64_t fee = 0;
    std::vector<ContributorV2> contributors;

    explicit NewServiceNodeV2(uint64_t chain_id = 0, uint64_t l2_height = 0) :
            L2StateChange{chain_id, l2_height} {}

    std::string to_string() const {
        return "{} [sn_pubkey={}, bls_pubkey={}]"_format(description, sn_pubkey, bls_pubkey);
    }

    template <class Archive>
    void serialize_object(Archive& ar) {
        field_varint(ar, "version", version);
        field_varint(ar, "chain_id", chain_id);
        field_varint(ar, "l2_height", l2_height);
        field(ar, "service_node_pubkey", sn_pubkey);
        field(ar, "bls_pubkey", bls_pubkey);
        field(ar, "signature", ed_signature);
        field_varint(ar, "fee", fee);
        field(ar, "contributors", contributors);
    }

    std::strong_ordering operator<=>(const NewServiceNodeV2& o) const = default;

    static constexpr cryptonote::txtype txtype = cryptonote::txtype::ethereum_new_service_node_v2;
    static constexpr std::string_view description = "new SNv2"sv;
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
        serialize_base_fields(ar, nullptr);
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
        serialize_base_fields(ar, nullptr);
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
        serialize_base_fields(ar, nullptr);
        field_varint(ar, "staking_requirement", staking_requirement);
    }

    static constexpr cryptonote::txtype txtype =
            cryptonote::txtype::ethereum_staking_requirement_updated;
    static constexpr std::string_view description = "staking requirement update"sv;
};

// This "event" isn't directly emitted by the contract, but rather is an implied event generated by
// oxend nodes in response to observing that the contract is missing service nodes that are
// registered on the oxend side but should not be.  `l2_height` will be the height of the list fetch
// at which the absence was apparent.
//
// Note that this is an exceptional case to deal with a major L2 disruption or contract state
// problem: in normal operation it should never be hit.
//
struct ServiceNodePurge : L2StateChange {
    bls_public_key bls_pubkey = crypto::null<bls_public_key>;

    explicit ServiceNodePurge(uint64_t chain_id = 0, uint64_t l2_height = 0) :
            L2StateChange{chain_id, l2_height} {}

    std::string to_string() const { return "{} [{}]"_format(description, bls_pubkey); }

    std::strong_ordering operator<=>(const ServiceNodePurge&) const = default;

    template <class Archive>
    void serialize_object(Archive& ar) {
        serialize_base_fields(ar, nullptr);
        field(ar, "bls_pubkey", bls_pubkey);
    }

    static constexpr cryptonote::txtype txtype =
            cryptonote::txtype::ethereum_purge_missing_service_node;
    static constexpr std::string_view description = "purge missing service node"sv;
};

using StateChangeVariant = std::variant<
        std::monostate,
        NewServiceNodeV2,
        ServiceNodeExitRequest,
        ServiceNodeExit,
        StakingRequirementUpdated,
        ServiceNodePurge>;

}  // namespace eth::event

template <std::derived_from<eth::event::L2StateChange> T>
inline constexpr bool ::formattable::via_to_string<T> = true;
