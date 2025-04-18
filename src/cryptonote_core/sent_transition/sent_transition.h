#pragma once

#include <limits>
#include <string_view>
#include <unordered_map>

#include "blockchain_db/sqlite/db_sqlite.h"
#include "crypto/eth.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_config.h"
#include "cryptonote_core/service_node_list.h"

namespace oxen::sent {

using cryptonote::network_type;

using addrmap_t = std::unordered_map<std::string, eth::address>;
using conv_ratio_t = std::pair<std::uint64_t, std::uint64_t>;
using bonus_map_t = std::unordered_map<eth::address, std::uint64_t>;
using proper_ed_keys_t = std::unordered_map<crypto::public_key, crypto::ed25519_public_key>;
using bls_keys_t = std::unordered_map<crypto::ed25519_public_key, eth::bls_public_key>;

struct transition_context {
    /// Mapping of OXEN -> SENT addresses for the given network type.
    const addrmap_t* addresses;

    /// Old not-quite-ed-key to proper ed key mapping, for nodes which were registered before
    /// we switched to proper ed25519.
    const proper_ed_keys_t* proper_ed_keys;
    const bls_keys_t* bls_keys;

    /// OXEN -> SENT conversion ratio to apply to conversion-registered wallets at the
    /// SENT hardfork.  The first value is the numerator, second is the denominator (e.g. a return
    /// of [2, 3] means 1 OXEN becomes 0.666666666 SENT.  (This is a ratio because the conversion is
    /// performed precisely, avoiding floating point math).
    conv_ratio_t conv_ratio;

    /// SENT SN contributor transition bonus amounts (from the SN bonus program) as a map of eth
    /// address -> atomic (1e-9) value.
    const bonus_map_t* transition_bonus;
    uint64_t staking_requirement;
    uint64_t oxen_staking_requirement;

    /// Produce CSV's of the transition outcome to the current work directory if this is flag is
    // set.
    bool dump_csv;
};

/// Get the parameters for the token transition
transition_context get_transition_context(network_type net, uint64_t top_block_height);

/// Performs the SENT service node transition, updating the service node list to replace OXEN
/// addresses with ETH addresses, updating stakes to reflect the SENT staking requirement, and
/// converting any pending batched rewards to SENT.  After this is called, all services nodes will
/// be updated to contain only ETH address, and service nodes that cannot survive (due to
/// insufficient stakes or unregistered contributors) will be turned into a "zombie" state of 0
/// contributions; such zombie SNs earn no rewards and will be evicted from the network via quorum
/// testing.
///
/// Any converted SENT funds that are not staked (e.g. because a contributor has more than needed,
/// or has some nodes that are being disbanded or some combination of both) are added to the
/// batching database as a one-time transition "reward" that can be redeemed by the wallet.
///
/// Any OXEN staked to nodes which are being kept (i.e. not "zombies") will be permanently locked.
///
/// Non-converting pending OXEN rewards balances (i.e. unregistered wallets) are not updated by
/// this; they will be paid in final batching reward calculations over the regular 3.5-day payout
/// schedule following the fork.
///
/// Additionally we replace the primary pubkey of any old Oxen nodes with differing "pubkey" and
/// "ed25519_pubkey" values (generally: SNs set up before Oxen 8) with the ed25519 pubkey; as of the
/// SENT HF these are unifed, and SNs will start ignoring a non-ed25519 service node pubkey.
void transition(
        const transition_context& context,
        service_nodes::service_node_list::state_t& sns,
        cryptonote::BlockchainSQLite& sql,
        network_type net);

}  // namespace oxen::sent
