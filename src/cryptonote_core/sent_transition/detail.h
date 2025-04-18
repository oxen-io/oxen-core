#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

#include "crypto/crypto.h"
#include "crypto/eth.h"
#include "cryptonote_config.h"

namespace oxen::sent::devnet {
extern const std::unordered_map<std::string, eth::address> addresses;
extern const std::unordered_map<crypto::public_key, crypto::ed25519_public_key> proper_ed_keys;
extern const std::unordered_map<crypto::ed25519_public_key, eth::bls_public_key> bls_keys;
extern const std::pair<std::uint64_t, std::uint64_t> conv_ratio;
extern const std::unordered_map<eth::address, std::uint64_t> transition_bonus;
}  // namespace oxen::sent::devnet

namespace oxen::sent::testnet {
extern const std::unordered_map<std::string, eth::address> addresses;
extern const std::unordered_map<crypto::public_key, crypto::ed25519_public_key> proper_ed_keys;
extern const std::unordered_map<crypto::ed25519_public_key, eth::bls_public_key> bls_keys;
extern const std::pair<std::uint64_t, std::uint64_t> conv_ratio;
extern const std::unordered_map<eth::address, std::uint64_t> transition_bonus;
}  // namespace oxen::sent::testnet

namespace oxen::sent::localdev {
extern const std::unordered_map<std::string, eth::address> addresses;
extern const std::unordered_map<crypto::public_key, crypto::ed25519_public_key> proper_ed_keys;
extern const std::unordered_map<crypto::ed25519_public_key, eth::bls_public_key> bls_keys;
extern const std::pair<std::uint64_t, std::uint64_t> conv_ratio;
extern const std::unordered_map<eth::address, std::uint64_t> transition_bonus;
}  // namespace oxen::sent::localdev

namespace oxen::sent::mainnet {
extern const std::unordered_map<std::string, eth::address> addresses;
extern const std::unordered_map<crypto::public_key, crypto::ed25519_public_key> proper_ed_keys;
extern const std::unordered_map<crypto::ed25519_public_key, eth::bls_public_key> bls_keys;
extern const std::pair<std::uint64_t, std::uint64_t> conv_ratio;
extern const std::unordered_map<eth::address, std::uint64_t> transition_bonus;
}  // namespace oxen::sent::mainnet

namespace oxen::sent {
using cryptonote::network_type;

/// Returns the mapping of OXEN -> SENT addresses for the given network type.
const std::unordered_map<std::string, eth::address>& addresses(network_type net);

/// Returns the OXEN -> SENT conversion ratio to apply to conversion-registered wallets at the
/// SENT hardfork.  The first value is the numerator, second is the denominator (e.g. a return
/// of [2, 3] means 1 OXEN becomes 0.666666666 SENT.  (This is a ratio because the conversion is
/// performed precisely, avoiding floating point math).
const std::pair<uint8_t, uint8_t>& conversion_ratio(network_type net);

/// Returns SENT SN contributor transition bonus amounts (from the SN bonus program) as a map of eth
/// address -> atomic (1e-9) value.
const std::unordered_map<eth::address, uint64_t>& transition_bonus(network_type net);

/// Returns old not-quite-ed-key to proper ed key mapping, for nodes which were registered before
/// we switched to proper ed25519.
const std::unordered_map<crypto::public_key, crypto::ed25519_public_key> proper_ed_keys(
        network_type net);

const std::unordered_map<crypto::ed25519_public_key, eth::bls_public_key> bls_keys(
        network_type net);
}  // namespace oxen::sent
