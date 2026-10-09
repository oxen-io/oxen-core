#pragma once

#include <crypto/eth.h>
#include <cryptonote_basic/cryptonote_basic.h>

#include <array>
#include <cstdint>
#include <functional>
#include <limits>
#include <map>
#include <optional>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace cryptonote {

// How many heights (the current one included) the rewards keep the accrued values of in memory.
// The bls_rewards_request RPC documents that nodes keep balances for 5 blocks back; the rest is
// slack.
inline constexpr uint64_t REWARDS_HISTORY = 8;

// An address that rewards accrue to: an ETH address from HF21 on, an OXEN address before then (and,
// on localdev, for nodes without an ETH address).
using rewards_address = std::variant<eth::address, account_public_address>;

// Orders addresses the way SQLite orders their blobs: bytewise, with a prefix before anything it is
// a prefix of.  Pre-HF21 batch payments are paid in this order, so it is consensus-relevant.
struct rewards_address_less {
    bool operator()(const rewards_address& a, const rewards_address& b) const;
};

// The values accrued to one address, as the rewards store them: `amount` and `lifetime_rewards` in
// milli-atomic units before HF22 and atomic units from HF22 on; the stake amounts always atomic.
struct accrued_row {
    int64_t amount = 0;  // Claimable amount (lifetime rewards and unlocked stakes)
    // For OXEN addresses, the block (modulo the batching interval) whose batch payment pays them.
    std::optional<int32_t> payout_offset;
    int64_t lifetime_locked_stakes = 0;
    int64_t lifetime_unlocked_stakes = 0;
    int64_t lifetime_liquidated_stakes = 0;
    int64_t lifetime_rewards = 0;  // Lifetime accumulated rewards (not including unlocked stakes)

    bool operator==(const accrued_row&) const = default;
};

using accrued_rows = std::vector<std::pair<rewards_address, accrued_row>>;

// The changes one block makes to the accrued rows: the new row of each address that it changes, or
// nullopt for one whose row it removes.
using accrued_changes = std::map<rewards_address, std::optional<accrued_row>, rewards_address_less>;

// The result of an accrued_history lookup
struct accrued_lookup {
    // False if the height isn't held (or if, which would be a bug, the slot for it holds another
    // height's values); the values there are then unknown.
    bool known = false;
    // The address's row at the height, if known and it has one.
    std::optional<accrued_row> row;
};

// The accrued rows at each of the REWARDS_HISTORY most recent heights: the BLS rewards signing is
// asked for balances at those, and a rewind within them restores without a replay.
//
// Each address has a ring of slots, indexed by height modulo REWARDS_HISTORY, each holding the
// address's values at one height along with that height.  Invariants:
// - The held heights are [oldest(), newest()], at most REWARDS_HISTORY of them; held() is false
//   (nothing is held) after a rewind below oldest(), until a reset.
// - advance() only ever adds newest() + 1, and writes the slot of that height for every address
//   (copying the previous slot forward for those the block doesn't change), so an address has a
//   slot for every held height from the one it first appeared at.
// - A slot is valid only for a held height, at or after the address's first height, and only if the
//   height stored in it is that height.  Every read checks all three; a slot holding another
//   height is a bug, which reads report (loudly) rather than ever returning its values.
// - A rewind invalidates every slot above the height it rewinds to, and drops the addresses that
//   first appeared above it, so nothing from the abandoned heights can be read as a value at a
//   lower height.
//
// Not thread-safe: RewardsDB serialises access to it.
class accrued_history {
  public:
    // Starts over with only `height` held, whose rows are `rows` (in any order).
    void reset(uint64_t height, const accrued_rows& rows);

    // Adds `height`, which must be newest() + 1, as the newest rows with `changes` applied; the
    // oldest height drops out once REWARDS_HISTORY are held.
    void advance(uint64_t height, const accrued_changes& changes);

    // Drops the heights above `height`.  If `height` is below oldest(), nothing is held any more.
    void rewind(uint64_t height);

    bool held() const { return !nothing_held; }
    bool contains(uint64_t height) const {
        return !nothing_held && height >= min_height && height <= current;
    }
    uint64_t newest() const { return current; }
    uint64_t oldest() const { return min_height; }

    accrued_lookup lookup(const rewards_address& addr, uint64_t height) const;

    // Calls `f` with each row at `height`, which must be contained, in no particular order.  Throws
    // if a slot for the height holds another height's values.
    void for_each(
            uint64_t height,
            const std::function<void(const rewards_address&, const accrued_row&)>& f) const;

    // All the rows at `height`, which must be contained, ordered by rewards_address_less.
    accrued_rows snapshot_rows(uint64_t height) const;

  private:
    static constexpr uint64_t INVALID_HEIGHT = std::numeric_limits<uint64_t>::max();

    struct slot_values {
        uint64_t height = INVALID_HEIGHT;  // The height these are the values at
        bool present = false;  // False at heights where the address has no row (e.g. after a removal)
        // Per slot (rather than per address) because an address's row can be removed and then
        // added again with a different one, as on localdev when the HF21 transition removes the
        // OXEN rows and its block then credits nodes without ETH addresses by their OXEN ones.
        std::optional<int32_t> payout_offset;
        int64_t amount = 0;
        int64_t lifetime_rewards = 0;
        int64_t lifetime_locked_stakes = 0;
        int64_t lifetime_unlocked_stakes = 0;
        int64_t lifetime_liquidated_stakes = 0;
    };

    struct wallet {
        uint64_t first_height = 0;
        // The height it was removed at (e.g. by the HF21 transition, or a pre-HF21 payout leaving
        // nothing), while it still has no row: lookups below it still find its earlier rows, and a
        // rewind below it un-removes it.  Once it is at or below min_height, the wallet has no row
        // at any height held, and is dropped.
        std::optional<uint64_t> removed_height;
        std::array<slot_values, REWARDS_HISTORY> ring{};
    };

    std::unordered_map<rewards_address, wallet> wallets;
    uint64_t min_height = 0;
    uint64_t current = 0;
    bool nothing_held = false;

    static size_t slot(uint64_t height) { return height % REWARDS_HISTORY; }

    // The row of `w` at `height`, which must be contained; unknown only if the slot for it holds
    // another height (which it logs, and asserts on).
    accrued_lookup row_at(const rewards_address& addr, const wallet& w, uint64_t height) const;

    friend struct accrued_history_test_access;
};

}  // namespace cryptonote
