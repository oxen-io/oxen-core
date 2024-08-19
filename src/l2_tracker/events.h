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
    void serialize_value(Archive& ar) {
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
    void serialize_value(Archive& ar) {
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
    static constexpr std::string_view description = "new service node"sv;
};

struct ServiceNodeRemovalRequest : L2StateChange {
    bls_public_key bls_pubkey = crypto::null<bls_public_key>;

    explicit ServiceNodeRemovalRequest(uint64_t chain_id = 0, uint64_t l2_height = 0) :
            L2StateChange{chain_id, l2_height} {}

    std::string to_string() const { return "{} [bls_pubkey={}]"_format(description, bls_pubkey); }

  public:
    std::strong_ordering operator<=>(const ServiceNodeRemovalRequest& o) const = default;

    template <class Archive>
    void serialize_value(Archive& ar) {
        [[maybe_unused]] uint8_t version = 0;
        field_varint(ar, "version", version);
        field_varint(ar, "chain_id", chain_id);
        field_varint(ar, "l2_height", l2_height);
        field(ar, "bls_pubkey", bls_pubkey);
    }

    static constexpr cryptonote::txtype txtype =
            cryptonote::txtype::ethereum_service_node_removal_request;
    static constexpr std::string_view description = "removal request"sv;
};

struct ServiceNodeRemoval : L2StateChange {
    bls_public_key bls_pubkey = crypto::null<bls_public_key>;
    uint64_t returned_amount = 0;

    explicit ServiceNodeRemoval(uint64_t chain_id = 0, uint64_t l2_height = 0) :
            L2StateChange{chain_id, l2_height} {}

    std::string to_string() const {
        return "{} [bls_pubkey={}, returned={}]"_format(description, bls_pubkey, returned_amount);
    }

    std::strong_ordering operator<=>(const ServiceNodeRemoval& o) const = default;

    template <class Archive>
    void serialize_value(Archive& ar) {
        [[maybe_unused]] uint8_t version = 0;
        field_varint(ar, "version", version);
        field_varint(ar, "chain_id", chain_id);
        field_varint(ar, "l2_height", l2_height);
        field(ar, "bls_pubkey", bls_pubkey);
        field_varint(ar, "returned_amount", returned_amount);
    }

    static constexpr cryptonote::txtype txtype = cryptonote::txtype::ethereum_service_node_removal;
    static constexpr std::string_view description = "SN removal"sv;
};

using StateChangeVariant =
        std::variant<std::monostate, NewServiceNode, ServiceNodeRemovalRequest, ServiceNodeRemoval>;

}  // namespace eth::event

template <std::derived_from<eth::event::L2StateChange> T>
inline constexpr bool ::formattable::via_to_string<T> = true;
