#pragma once

#include <chrono>

#include "cryptonote_config.h"
#include "oxen_economy.h"
#include "service_node_voting.h"

namespace service_nodes {

// validate_registration* and convert_registration_args functions throws this on error:
struct invalid_registration : std::invalid_argument {
    using std::invalid_argument::invalid_argument;
};

inline constexpr size_t PULSE_QUORUM_ENTROPY_LAG =
        21;  // How many blocks back from the tip of the Blockchain to source entropy for the Pulse
             // quorums.

inline constexpr size_t PULSE_QUORUM_NUM_VALIDATORS = 11;
inline constexpr size_t PULSE_QUORUM_SIZE = PULSE_QUORUM_NUM_VALIDATORS + 1 /*Leader*/;
inline constexpr size_t PULSE_BLOCK_REQUIRED_SIGNATURES =
        7;  // A block must have exactly N signatures to be considered properly

static_assert(PULSE_QUORUM_NUM_VALIDATORS >= PULSE_BLOCK_REQUIRED_SIGNATURES);
static_assert(
        PULSE_QUORUM_ENTROPY_LAG >= PULSE_QUORUM_SIZE,
        "We need to pull atleast PULSE_QUORUM_SIZE number of blocks from the Blockchain, we can't "
        "if the amount of blocks to go back from the tip of the Blockchain is less than the blocks "
        "we need.");

constexpr uint16_t pulse_validator_bit_mask() {
    uint16_t result = 0;
    for (size_t validator_index = 0; validator_index < PULSE_QUORUM_NUM_VALIDATORS;
         validator_index++)
        result |= 1 << validator_index;
    return result;
}

// Service node decommissioning: as service nodes stay up they earn "credits" (measured in blocks)
// towards a future outage.  A new service node starts out with INITIAL_CREDIT, and then builds up 1
// block every CREDIT_TIME worth of blocks as long as the service node remains active up to a
// maximum of DECOMMISSION_MAX_CREDIT.
//
// If a service node stops sending uptime proofs, a quorum will consider whether the service node
// has built up enough credits (at least MINIMUM): if so, instead of submitting a deregistration,
// it instead submits a decommission.  This removes the service node from the list of active
// service nodes both for rewards and for any active network duties.  If the service node comes
// back online (i.e. starts sending the required performance proofs again) before the credits run
// out then a quorum will reinstate the service node using a recommission transaction, which adds
// the service node back to the bottom of the service node reward list, and resets its accumulated
// credits to RECOMMISSION_CREDIT (see below).  If it does not come back online within the
// required number of blocks (i.e. the accumulated credit at the point of decommissioning) then a
// quorum will send a permanent deregistration transaction to the network, starting a 30-day
// deregistration count down.  (Note that it is possible for a server to slightly exceed its
// decommission time: the first quorum test after the credit expires determines whether the server
// gets recommissioned or decommissioned).
inline constexpr auto DECOMMISSION_CREDIT_PER_DAY = 24 * 60min / 30;  // 24h credit per 30 days
inline constexpr auto DECOMMISSION_INITIAL_CREDIT = 2h;
inline constexpr auto DECOMMISSION_MAX_CREDIT = 48h;
inline constexpr auto DECOMMISSION_MINIMUM = 2h;

static_assert(
        DECOMMISSION_INITIAL_CREDIT <= DECOMMISSION_MAX_CREDIT,
        "Initial registration decommission credit cannot be larger than the maximum decommission "
        "credit");

// This determines how many credits a node gets when being recommissioned after being
// decommissioned.  It gets passed two values: the credit at the time the node was decomissioned,
// and the number of blocks the decommission lasted.  Note that it is possible for decomm_blocks
// to be *larger* than credit_at_decomm: in particularl
//
// The default, starting in Loki 8, subtracts two blocks for every block you were decomissioned,
// or returns 0 if that value would be negative.  So, for example, if you had 1000 blocks of
// credit and got decomissioned for 100 blocks, you will be recommissioned with 800 blocks of
// credit.  If you got decomissioned for 500 or more you will be recommissioned with 0 blocks of
// credit.
//
// Before Loki 8 (when this configuration was added) recomissioning would always reset your credit
// to 0, which is what happens if this function always returns 0.
inline constexpr int64_t RECOMMISSION_CREDIT(int64_t credit_at_decomm, int64_t decomm_blocks) {
    return std::max<int64_t>(0, credit_at_decomm - 2 * decomm_blocks);
}

inline constexpr uint64_t CHECKPOINT_NUM_CHECKPOINTS_FOR_CHAIN_FINALITY =
        2;  // Number of consecutive checkpoints before, blocks preceeding the N checkpoints are
            // locked in
inline constexpr uint64_t CHECKPOINT_INTERVAL =
        4;  // Checkpoint every 4 blocks and prune when too old except if (height %
            // CHECKPOINT_STORE_PERSISTENTLY_INTERVAL == 0)
inline constexpr uint64_t CHECKPOINT_STORE_PERSISTENTLY_INTERVAL =
        60;  // Persistently store the checkpoints at these intervals
inline constexpr uint64_t CHECKPOINT_VOTE_LIFETIME =
        CHECKPOINT_STORE_PERSISTENTLY_INTERVAL;  // Keep the last 60 blocks worth of votes

inline constexpr int16_t QUORUM_VOTE_CHECK_COUNT = 8;
inline constexpr int16_t PULSE_MAX_MISSABLE_VOTES = 4;
inline constexpr int16_t CHECKPOINT_MAX_MISSABLE_VOTES = 4;
inline constexpr int16_t TIMESTAMP_MAX_MISSABLE_VOTES = 4;
inline constexpr int16_t TIMESYNC_MAX_UNSYNCED_VOTES = 4;
static_assert(
        CHECKPOINT_MAX_MISSABLE_VOTES < QUORUM_VOTE_CHECK_COUNT,
        "The maximum number of votes a service node can miss cannot be greater than the amount of "
        "checkpoint "
        "quorums they must participate in before we check if they should be deregistered or not.");

inline constexpr int BLINK_QUORUM_INTERVAL =
        5;  // We generate a new sub-quorum every N blocks (two consecutive quorums are needed for a
            // blink signature)
inline constexpr int BLINK_QUORUM_LAG =
        7 * BLINK_QUORUM_INTERVAL;  // The lag (which must be a multiple of BLINK_QUORUM_INTERVAL)
                                    // in determining the base blink quorum height
inline constexpr int BLINK_EXPIRY_BUFFER =
        BLINK_QUORUM_LAG + 10;  // We don't select any SNs that have a scheduled unlock within this
                                // many blocks (measured from the lagged height)
static_assert(
        BLINK_QUORUM_LAG % BLINK_QUORUM_INTERVAL == 0,
        "BLINK_QUORUM_LAG must be an integral multiple of BLINK_QUORUM_INTERVAL");
static_assert(
        BLINK_EXPIRY_BUFFER > BLINK_QUORUM_LAG + BLINK_QUORUM_INTERVAL,
        "BLINK_EXPIRY_BUFFER is too short to cover a blink quorum height range");

// State change quorums are in charge of policing the network by changing the state of a service
// node on the network: temporary decommissioning, recommissioning, and permanent deregistration.
inline constexpr size_t STATE_CHANGE_NTH_OF_THE_NETWORK_TO_TEST = 100;
inline constexpr size_t STATE_CHANGE_MIN_NODES_TO_TEST = 50;
inline constexpr auto VOTE_LIFETIME = 60;  // blocks

inline constexpr size_t STATE_CHANGE_MIN_VOTES_TO_CHANGE_STATE = 7;
inline constexpr size_t STATE_CHANGE_QUORUM_SIZE = 10;
inline constexpr size_t CHECKPOINT_QUORUM_SIZE = 20;
inline constexpr size_t CHECKPOINT_MIN_VOTES = 13;
inline constexpr int BLINK_SUBQUORUM_SIZE = 10;
inline constexpr int BLINK_MIN_VOTES = 7;

static_assert(
        STATE_CHANGE_MIN_VOTES_TO_CHANGE_STATE <= STATE_CHANGE_QUORUM_SIZE,
        "The number of votes required to kick can't exceed the actual quorum size, otherwise we "
        "never kick.");
static_assert(
        CHECKPOINT_MIN_VOTES <= CHECKPOINT_QUORUM_SIZE,
        "The number of votes required to add a checkpoint can't exceed the actual quorum size, "
        "otherwise we never add checkpoints.");
static_assert(
        BLINK_MIN_VOTES <= BLINK_SUBQUORUM_SIZE,
        "The number of votes required can't exceed the actual blink subquorum size, otherwise we "
        "never approve.");
static_assert(
        BLINK_MIN_VOTES > BLINK_SUBQUORUM_SIZE / 2,
        "Blink approvals must require a majority of quorum members to prevent conflicting, signed "
        "blinks.");

// NOTE: We can reorg up to last 2 checkpoints + the number of extra blocks before the next
// checkpoint is set
inline constexpr uint64_t REORG_SAFETY_BUFFER_BLOCKS_POST_HF12 =
        (CHECKPOINT_INTERVAL * CHECKPOINT_NUM_CHECKPOINTS_FOR_CHAIN_FINALITY) +
        (CHECKPOINT_INTERVAL - 1);
inline constexpr uint64_t REORG_SAFETY_BUFFER_BLOCKS_PRE_HF12 = 20;
static_assert(
        REORG_SAFETY_BUFFER_BLOCKS_POST_HF12 < VOTE_LIFETIME,
        "Safety buffer should always be less than the vote lifetime");
static_assert(
        REORG_SAFETY_BUFFER_BLOCKS_PRE_HF12 < VOTE_LIFETIME,
        "Safety buffer should always be less than the vote lifetime");

inline constexpr auto IP_CHANGE_WINDOW =
        24h;  // How far back an obligations quorum looks for multiple IPs (unless the following
              // buffer is more recent)
inline constexpr auto IP_CHANGE_BUFFER = 2h;  // After we bump a SN for an IP change we don't bump
                                              // again for changes within this time period

inline constexpr size_t MAX_SWARM_SIZE = 10;
// We never create a new swarm unless there are SWARM_BUFFER extra nodes
// available in the queue.
inline constexpr size_t SWARM_BUFFER = 5;
// if a swarm has strictly less nodes than this, it is considered unhealthy
// and nearby swarms will mirror it's data. It will disappear, and is already considered gone.
inline constexpr size_t MIN_SWARM_SIZE = 5;
inline constexpr size_t IDEAL_SWARM_MARGIN = 2;
inline constexpr size_t IDEAL_SWARM_SIZE = MIN_SWARM_SIZE + IDEAL_SWARM_MARGIN;
inline constexpr size_t EXCESS_BASE = MIN_SWARM_SIZE;
inline constexpr size_t NEW_SWARM_SIZE = IDEAL_SWARM_SIZE;
// The lower swarm percentile that will be randomly filled with new service nodes
inline constexpr size_t FILL_SWARM_LOWER_PERCENTILE = 25;
// Redistribute snodes from decommissioned swarms to the smallest swarms
inline constexpr size_t DECOMMISSIONED_REDISTRIBUTION_LOWER_PERCENTILE = 0;
// The upper swarm percentile that will be randomly selected during stealing
inline constexpr size_t STEALING_SWARM_UPPER_PERCENTILE = 75;

inline constexpr uint64_t STATE_CHANGE_TX_LIFETIME_IN_BLOCKS = VOTE_LIFETIME;

// If we get an incoming vote of state change tx that is outside the acceptable range by this many
// blocks then ignore it but don't trigger a connection drop; the sending side could be a couple
// blocks out of sync and sending something that it thinks is legit.
inline constexpr uint64_t VOTE_OR_TX_VERIFY_HEIGHT_BUFFER = 5;

// The minimum versions that we accept for local oxend pings from our *own* companion services:
inline constexpr std::array<uint16_t, 3> MIN_STORAGE_SERVER_VERSION{{2, 8, 0}};
inline constexpr std::array<uint16_t, 3> MIN_LOKINET_VERSION{{0, 9, 11}};

// The minimum accepted version number, broadcasted by Service Nodes via uptime proofs for each
// hardfork
struct proof_version {
    std::pair<cryptonote::hf, uint8_t> hardfork_revision;
    std::array<uint16_t, 3> oxend;
    std::array<uint16_t, 3> lokinet;
    std::array<uint16_t, 3> storage_server;
};

inline constexpr std::array MIN_UPTIME_PROOF_VERSIONS = {
        proof_version{{cryptonote::hf::hf19_reward_batching, 6}, {10, 6, 0}, {0, 9, 11}, {2, 8, 0}},
        proof_version{{cryptonote::hf::hf21_eth, 2}, {11, 0, 6}, {0, 9, 11}, {2, 8, 0}},
};

using swarm_id_t = uint64_t;
inline constexpr swarm_id_t UNASSIGNED_SWARM_ID = UINT64_MAX;

constexpr size_t min_votes_for_quorum_type(quorum_type q) {
    return q == quorum_type::obligations   ? STATE_CHANGE_MIN_VOTES_TO_CHANGE_STATE
         : q == quorum_type::checkpointing ? CHECKPOINT_MIN_VOTES
         : q == quorum_type::blink         ? BLINK_MIN_VOTES
                                           : std::numeric_limits<size_t>::max();
};

constexpr quorum_type max_quorum_type_for_hf(cryptonote::hf version) {
    return version <= cryptonote::hf::hf12_checkpointing ? quorum_type::obligations
         : version < cryptonote::hf::hf14_blink          ? quorum_type::checkpointing
         : version < cryptonote::hf::hf16_pulse          ? quorum_type::blink
                                                         : quorum_type::pulse;
}

// The number of blocks a stake lasts for, for pre-HF11 infinite staking when stakes were fixed
// length.
uint64_t staking_num_lock_blocks(cryptonote::network_type nettype);

// If a nodes timestamp varies by this amount of seconds they will be considered out of sync
inline constexpr uint8_t THRESHOLD_SECONDS_OUT_OF_SYNC = 30;

// If the below percentage of service nodes are out of sync we will consider our clock out of sync
inline constexpr uint8_t MAXIMUM_EXTERNAL_OUT_OF_SYNC = 80;

// The SN operator must contribute at least 25% of the node's requirement, expressed as portions
// (for pre-HF19 registrations).
inline constexpr uint64_t MINIMUM_OPERATOR_PORTION =
        cryptonote::old::STAKING_PORTIONS / oxen::MAX_CONTRIBUTORS_V1;

// Small Stake prevented from unlocking stake until a certain number of blocks have passed
constexpr auto SMALL_CONTRIBUTOR_UNLOCK_TIMER = 30 * 24h;
using SMALL_CONTRIBUTOR_THRESHOLD = std::ratio<2499, 10000>;

static_assert(
        cryptonote::old::STAKING_PORTIONS != UINT64_MAX,
        "UINT64_MAX is used as the invalid value for failing to calculate the "
        "min_node_contribution");
// return: UINT64_MAX if (num_contributions > the max number of contributions), otherwise the amount
// in oxen atomic units
uint64_t get_min_node_contribution(
        cryptonote::hf version,
        uint64_t staking_requirement,
        uint64_t total_reserved,
        size_t num_contributions);
uint64_t get_min_node_contribution_in_portions(
        cryptonote::hf version,
        uint64_t staking_requirement,
        uint64_t total_reserved,
        size_t num_contributions);

// Gets the maximum allowed stake amount.  This is used to prevent significant overstaking.  The
// wallet tries to avoid this when submitting a stake, but it can still happen when competing stakes
// get submitted into the mempool -- for example, with 10k of contribution room, two contributions
// of 8k could get submitted and both would be accepted, but the second one would only count as 2k
// of stake despite locking 8k.
// Starting in HF16, we disallow a stake if it is more than MAXIMUM_ACCEPTABLE_STAKE ratio of the
// available contribution room, which allows slight overstaking but disallows larger overstakes.
uint64_t get_max_node_contribution(
        cryptonote::hf version, uint64_t staking_requirement, uint64_t total_reserved);

// Returns the default staking requirement at the given height.  Generally you should not call this
// directly if you need compatibility with HF21+ staking requirement, but instead use
// service_node_list.get_staking_requirement() which calls this when needed.
uint64_t get_default_staking_requirement(cryptonote::network_type nettype, uint64_t height);
uint64_t get_default_staking_requirement(cryptonote::network_type nettype, cryptonote::hf hardfork);

uint64_t portions_to_amount(uint64_t portions, uint64_t staking_requirement);

/// Check if portions (for pre-HF19 regisrations) are sufficiently large (provided the contributions
/// are made in the specified order) and don't exceed the required amount.  Note that this *always*
/// enforces a limit of 4 contributors, even when under HF19+; registrations with more spots must
/// use HF19+ registrations with amounts instead of portions.
bool check_service_node_portions(
        cryptonote::hf version,
        const std::vector<std::pair<cryptonote::account_public_address, uint64_t>>& portions);

/// Check service node contribution amounts, for HF19+ registrations
bool check_service_node_stakes(
        cryptonote::hf hf_version,
        uint64_t staking_requirement,
        const std::vector<uint64_t>& stakes);

crypto::hash generate_request_stake_unlock_hash(uint32_t nonce);

// Returns lowest x such that (staking_requirement * x/STAKING_PORTIONS) >= amount
uint64_t get_portions_to_make_amount(
        uint64_t staking_requirement,
        uint64_t amount,
        uint64_t max_portions = cryptonote::old::STAKING_PORTIONS);

std::optional<double> parse_fee_percent(std::string_view fee);

uint16_t percent_to_basis_points(std::string percent_string);

}  // namespace service_nodes
