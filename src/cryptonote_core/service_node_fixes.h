#pragma once
#include <crypto/crypto.h>
#include <crypto/eth.h>
#include <cryptonote_config.h>

#include <cstdint>

namespace service_nodes {

enum struct HF22Fix {
    Purge,
    Reg,
    Exit,
};

struct hf22_fixup {
    HF22Fix type;
    uint64_t block;
    uint64_t tx_index;
    uint64_t contributor_index;
    crypto::ed25519_public_key sn_pubkey;
    eth::address addr;
    uint64_t amount;
};

// Returns HF22 fixups for stuck funds following HF21.  `.first` are various funding fixups, and
// `.second` are pubkeys stuck in recently_removed_nodes that need to be deleted.  This should only
// be called on the very first HF22 block.
std::pair<std::vector<hf22_fixup>, std::vector<crypto::public_key>> get_hf22_fixups(
        cryptonote::network_type nettype);

}  // namespace service_nodes
