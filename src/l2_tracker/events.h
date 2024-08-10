#pragma once
#include <compare>
#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <variant>
#include <vector>

#include "common/formattable.h"
#include "crypto/crypto.h"
#include "crypto/eth.h"
#include "cryptonote_basic/txtypes.h"

using namespace std::literals;

namespace eth::event {

struct L2StateChange {};

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

// TODO FIXME: these events are problematic when embedding into a transaction because if you attempt
// to submit the same details again (i.e. re-registering an expired SN at a later point with same
// keys/signature/fee/contributors) you'll have identical data and serialization and thus an
// identical (and duplicate!) tx hash.
//
// Perhaps including the l2_height in L2StateChange & serialization to address this?

struct NewServiceNode : L2StateChange {
    crypto::public_key sn_pubkey;
    bls_public_key bls_pubkey;
    crypto::ed25519_signature ed_signature;
    uint64_t fee;
    std::vector<Contributor> contributors;

    std::string to_string() const {
        return "{} [sn_pubkey={}, bls_pubkey={}]"_format(description, sn_pubkey, bls_pubkey);
    }

    template <class Archive>
    void serialize_value(Archive& ar) {
        uint8_t version = 0;
        field_varint(ar, "v", version);
        field(ar, "service_node_pubkey", sn_pubkey);
        field(ar, "bls_pubkey", bls_pubkey);
        field(ar, "signature", ed_signature);
        field_varint(ar, "fee", fee);
        field(ar, "contributors", contributors);
    }

  private:
    auto compare_tuple() const {
        return std::tie(bls_pubkey, sn_pubkey, ed_signature, fee, contributors);
    }

  public:
    std::strong_ordering operator<=>(const NewServiceNode& o) const {
        return compare_tuple() <=> o.compare_tuple();
    }
    bool operator==(const NewServiceNode& o) const { return *this <=> o == 0; }

    static constexpr cryptonote::txtype txtype = cryptonote::txtype::ethereum_new_service_node;
    static constexpr std::string_view description = "new service node"sv;
};

struct ServiceNodeRemovalRequest : L2StateChange {
    bls_public_key bls_pubkey;

    std::string to_string() const { return "{} [bls_pubkey={}]"_format(description, bls_pubkey); }

    std::strong_ordering operator<=>(const ServiceNodeRemovalRequest& o) const {
        return bls_pubkey <=> o.bls_pubkey;
    }
    bool operator==(const ServiceNodeRemovalRequest& o) const { return *this <=> o == 0; }

    template <class Archive>
    void serialize_value(Archive& ar) {
        uint8_t version = 0;
        field(ar, "v", version);
        field(ar, "bls_pubkey", bls_pubkey);
    }

    static constexpr cryptonote::txtype txtype =
            cryptonote::txtype::ethereum_service_node_removal_request;
    static constexpr std::string_view description = "removal request"sv;
};

struct ServiceNodeRemoval : L2StateChange {
    bls_public_key bls_pubkey;
    uint64_t returned_amount;

    std::string to_string() const {
        return "{} [bls_pubkey={}, returned={}]"_format(description, bls_pubkey, returned_amount);
    }

    std::strong_ordering operator<=>(const ServiceNodeRemoval& o) const {
        return std::tie(bls_pubkey, returned_amount) <=> std::tie(o.bls_pubkey, o.returned_amount);
    }
    bool operator==(const ServiceNodeRemoval& o) const { return *this <=> o == 0; }

    template <class Archive>
    void serialize_value(Archive& ar) {
        uint8_t version = 0;
        field_varint(ar, "v", version);
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
