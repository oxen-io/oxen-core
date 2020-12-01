#pragma once

#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "service_node_voting.h"
#include <chrono>

namespace service_nodes {
  constexpr size_t PULSE_QUORUM_ENTROPY_LAG    = 21; // How many blocks back from the tip of the Blockchain to source entropy for the Pulse quorums.
#if defined(LOKI_ENABLE_INTEGRATION_TEST_HOOKS)
  constexpr auto PULSE_ROUND_TIME                                   = 20s;
  constexpr auto PULSE_WAIT_FOR_HANDSHAKES_DURATION                 = 3s;
  constexpr auto PULSE_WAIT_FOR_OTHER_VALIDATOR_HANDSHAKES_DURATION = 3s;
  constexpr auto PULSE_WAIT_FOR_BLOCK_TEMPLATE_DURATION             = 3s;
  constexpr auto PULSE_WAIT_FOR_RANDOM_VALUE_HASH_DURATION          = 3s;
  constexpr auto PULSE_WAIT_FOR_RANDOM_VALUE_DURATION               = 3s;
  constexpr auto PULSE_WAIT_FOR_SIGNED_BLOCK_DURATION               = 5s;

  constexpr size_t PULSE_QUORUM_NUM_VALIDATORS     = 7;
  constexpr size_t PULSE_BLOCK_REQUIRED_SIGNATURES = 6;  // A block must have exactly N signatures to be considered properly
#else
  constexpr auto PULSE_ROUND_TIME                                   = 60s;
  constexpr auto PULSE_WAIT_FOR_HANDSHAKES_DURATION                 = 10s;
  constexpr auto PULSE_WAIT_FOR_OTHER_VALIDATOR_HANDSHAKES_DURATION = 10s;
  constexpr auto PULSE_WAIT_FOR_BLOCK_TEMPLATE_DURATION             = 10s;
  constexpr auto PULSE_WAIT_FOR_RANDOM_VALUE_HASH_DURATION          = 10s;
  constexpr auto PULSE_WAIT_FOR_RANDOM_VALUE_DURATION               = 10s;
  constexpr auto PULSE_WAIT_FOR_SIGNED_BLOCK_DURATION               = 10s;

  constexpr size_t PULSE_QUORUM_NUM_VALIDATORS     = 11;
  constexpr size_t PULSE_BLOCK_REQUIRED_SIGNATURES = 7;  // A block must have exactly N signatures to be considered properly
#endif

  constexpr auto PULSE_MIN_TARGET_BLOCK_TIME = TARGET_BLOCK_TIME - 30s;
  constexpr auto PULSE_MAX_TARGET_BLOCK_TIME = TARGET_BLOCK_TIME + 30s;
  constexpr size_t PULSE_QUORUM_SIZE = PULSE_QUORUM_NUM_VALIDATORS + 1 /*Leader*/;

  static_assert(PULSE_ROUND_TIME >=
                PULSE_WAIT_FOR_HANDSHAKES_DURATION +
                PULSE_WAIT_FOR_OTHER_VALIDATOR_HANDSHAKES_DURATION +
                PULSE_WAIT_FOR_BLOCK_TEMPLATE_DURATION +
                PULSE_WAIT_FOR_RANDOM_VALUE_HASH_DURATION +
                PULSE_WAIT_FOR_RANDOM_VALUE_DURATION +
                PULSE_WAIT_FOR_SIGNED_BLOCK_DURATION);

  static_assert(PULSE_QUORUM_NUM_VALIDATORS >= PULSE_BLOCK_REQUIRED_SIGNATURES);
  static_assert(PULSE_QUORUM_ENTROPY_LAG >= PULSE_QUORUM_SIZE, "We need to pull atleast PULSE_QUORUM_SIZE number of blocks from the Blockchain, we can't if the amount of blocks to go back from the tip of the Blockchain is less than the blocks we need.");
  
  constexpr size_t pulse_min_service_nodes(cryptonote::network_type nettype)
  {
    return (nettype == cryptonote::MAINNET) ? 50 : PULSE_QUORUM_SIZE;
  }
  static_assert(pulse_min_service_nodes(cryptonote::MAINNET) >= PULSE_QUORUM_SIZE);
  static_assert(pulse_min_service_nodes(cryptonote::TESTNET) >= PULSE_QUORUM_SIZE);

  constexpr uint16_t pulse_validator_bit_mask()
  {
    uint16_t result = 0;
    for (size_t validator_index = 0; validator_index < PULSE_QUORUM_NUM_VALIDATORS; validator_index++)
      result |= 1 << validator_index;
    return result;
  }

  // Service node decommissioning: as service nodes stay up they earn "credits" (measured in blocks)
  // towards a future outage.  A new service node starts out with INITIAL_CREDIT, and then builds up
  // CREDIT_PER_DAY for each day the service node remains active up to a maximum of
  // DECOMMISSION_MAX_CREDIT.
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
  constexpr int64_t DECOMMISSION_CREDIT_PER_DAY = BLOCKS_EXPECTED_IN_HOURS(24) / 30;
  constexpr int64_t DECOMMISSION_INITIAL_CREDIT = BLOCKS_EXPECTED_IN_HOURS(2);
  constexpr int64_t DECOMMISSION_MAX_CREDIT     = BLOCKS_EXPECTED_IN_HOURS(48);
  constexpr int64_t DECOMMISSION_MINIMUM        = BLOCKS_EXPECTED_IN_HOURS(2);

  static_assert(DECOMMISSION_INITIAL_CREDIT <= DECOMMISSION_MAX_CREDIT, "Initial registration decommission credit cannot be larger than the maximum decommission credit");

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
      return std::max<int64_t>(0, credit_at_decomm - 2*decomm_blocks);
  }

  // Some sanity checks on the recommission credit value:
  static_assert(RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, 0) <= DECOMMISSION_MAX_CREDIT,
          "Max recommission credit should not be higher than DECOMMISSION_MAX_CREDIT");

  // These are by no means exhaustive, but will at least catch simple mistakes
  static_assert(
          RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, DECOMMISSION_MAX_CREDIT) <= RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, DECOMMISSION_MAX_CREDIT/2) &&
          RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, DECOMMISSION_MAX_CREDIT/2) <= RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, 0) &&
          RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT/2, DECOMMISSION_MAX_CREDIT/2) <= RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT/2, 0),
          "Recommission credit should be (weakly) decreasing in the length of decommissioning");
  static_assert(
          RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT/2, 1) <= RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, 1) &&
          RECOMMISSION_CREDIT(0, 1) <= RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT/2, 1),
          "Recommission credit should be (weakly) increasing in initial credit blocks");

  // This one actually could be supported (i.e. you can have negative credit and half to crawl out
  // of that hole), but the current code is entirely untested as to whether or not that actually
  // works.
  static_assert(
          RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, 0) >= 0 &&
          RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, DECOMMISSION_MAX_CREDIT) >= 0 &&
          RECOMMISSION_CREDIT(DECOMMISSION_MAX_CREDIT, 2*DECOMMISSION_MAX_CREDIT) >= 0, // delayed recommission that overhangs your time
          "Recommission credit should not be negative");

  constexpr uint64_t  CHECKPOINT_NUM_CHECKPOINTS_FOR_CHAIN_FINALITY = 2;  // Number of consecutive checkpoints before, blocks preceeding the N checkpoints are locked in
  constexpr uint64_t  CHECKPOINT_INTERVAL                           = 4;  // Checkpoint every 4 blocks and prune when too old except if (height % CHECKPOINT_STORE_PERSISTENTLY_INTERVAL == 0)
  constexpr uint64_t  CHECKPOINT_STORE_PERSISTENTLY_INTERVAL        = 60; // Persistently store the checkpoints at these intervals
  constexpr uint64_t  CHECKPOINT_VOTE_LIFETIME                      = CHECKPOINT_STORE_PERSISTENTLY_INTERVAL; // Keep the last 60 blocks worth of votes

  constexpr int16_t QUORUM_VOTE_CHECK_COUNT       = 8;
  constexpr int16_t PULSE_MAX_MISSABLE_VOTES      = 4;
  constexpr int16_t CHECKPOINT_MAX_MISSABLE_VOTES = 4;
  constexpr int16_t TIMESTAMP_MAX_MISSABLE_VOTES  = 4;
  constexpr int16_t TIMESYNC_MAX_UNSYNCED_VOTES   = 4;
  static_assert(CHECKPOINT_MAX_MISSABLE_VOTES < QUORUM_VOTE_CHECK_COUNT,
                "The maximum number of votes a service node can miss cannot be greater than the amount of checkpoint "
                "quorums they must participate in before we check if they should be deregistered or not.");

  constexpr int BLINK_QUORUM_INTERVAL = 5; // We generate a new sub-quorum every N blocks (two consecutive quorums are needed for a blink signature)
  constexpr int BLINK_QUORUM_LAG      = 7 * BLINK_QUORUM_INTERVAL; // The lag (which must be a multiple of BLINK_QUORUM_INTERVAL) in determining the base blink quorum height
  constexpr int BLINK_EXPIRY_BUFFER   = BLINK_QUORUM_LAG + 10; // We don't select any SNs that have a scheduled unlock within this many blocks (measured from the lagged height)
  static_assert(BLINK_QUORUM_LAG % BLINK_QUORUM_INTERVAL == 0, "BLINK_QUORUM_LAG must be an integral multiple of BLINK_QUORUM_INTERVAL");
  static_assert(BLINK_EXPIRY_BUFFER > BLINK_QUORUM_LAG + BLINK_QUORUM_INTERVAL, "BLINK_EXPIRY_BUFFER is too short to cover a blink quorum height range");

  // State change quorums are in charge of policing the network by changing the state of a service
  // node on the network: temporary decommissioning, recommissioning, and permanent deregistration.
  constexpr size_t   STATE_CHANGE_NTH_OF_THE_NETWORK_TO_TEST = 100;
  constexpr size_t   STATE_CHANGE_MIN_NODES_TO_TEST          = 50;
  constexpr uint64_t VOTE_LIFETIME                           = BLOCKS_EXPECTED_IN_HOURS(2);

#if defined(LOKI_ENABLE_INTEGRATION_TEST_HOOKS)
  constexpr size_t STATE_CHANGE_QUORUM_SIZE               = 5;
  constexpr size_t STATE_CHANGE_MIN_VOTES_TO_CHANGE_STATE = 1;
  constexpr int    MIN_TIME_IN_S_BEFORE_VOTING            = 0;
  constexpr size_t CHECKPOINT_QUORUM_SIZE                 = 5;
  constexpr size_t CHECKPOINT_MIN_VOTES                   = 1;
  constexpr int    BLINK_SUBQUORUM_SIZE                   = 5;
  constexpr int    BLINK_MIN_VOTES                        = 1;
#else
  constexpr size_t STATE_CHANGE_MIN_VOTES_TO_CHANGE_STATE = 7;
  constexpr size_t STATE_CHANGE_QUORUM_SIZE               = 10;
  constexpr int    MIN_TIME_IN_S_BEFORE_VOTING            = UPTIME_PROOF_MAX_TIME_IN_SECONDS;
  constexpr size_t CHECKPOINT_QUORUM_SIZE                 = 20;
  constexpr size_t CHECKPOINT_MIN_VOTES                   = 13;
  constexpr int    BLINK_SUBQUORUM_SIZE                   = 10;
  constexpr int    BLINK_MIN_VOTES                        = 7;
#endif

  static_assert(STATE_CHANGE_MIN_VOTES_TO_CHANGE_STATE <= STATE_CHANGE_QUORUM_SIZE, "The number of votes required to kick can't exceed the actual quorum size, otherwise we never kick.");
  static_assert(CHECKPOINT_MIN_VOTES <= CHECKPOINT_QUORUM_SIZE, "The number of votes required to add a checkpoint can't exceed the actual quorum size, otherwise we never add checkpoints.");
  static_assert(BLINK_MIN_VOTES <= BLINK_SUBQUORUM_SIZE, "The number of votes required can't exceed the actual blink subquorum size, otherwise we never approve.");
#ifndef LOKI_ENABLE_INTEGRATION_TEST_HOOKS
  static_assert(BLINK_MIN_VOTES > BLINK_SUBQUORUM_SIZE / 2, "Blink approvals must require a majority of quorum members to prevent conflicting, signed blinks.");
#endif

  // NOTE: We can reorg up to last 2 checkpoints + the number of extra blocks before the next checkpoint is set
  constexpr uint64_t  REORG_SAFETY_BUFFER_BLOCKS_POST_HF12 = (CHECKPOINT_INTERVAL * CHECKPOINT_NUM_CHECKPOINTS_FOR_CHAIN_FINALITY) + (CHECKPOINT_INTERVAL - 1);
  constexpr uint64_t  REORG_SAFETY_BUFFER_BLOCKS_PRE_HF12  = 20;
  static_assert(REORG_SAFETY_BUFFER_BLOCKS_POST_HF12 < VOTE_LIFETIME, "Safety buffer should always be less than the vote lifetime");
  static_assert(REORG_SAFETY_BUFFER_BLOCKS_PRE_HF12  < VOTE_LIFETIME, "Safety buffer should always be less than the vote lifetime");

  constexpr uint64_t  IP_CHANGE_WINDOW_IN_SECONDS     = 24*60*60; // How far back an obligations quorum looks for multiple IPs (unless the following buffer is more recent)
  constexpr uint64_t  IP_CHANGE_BUFFER_IN_SECONDS     = 2*60*60; // After we bump a SN for an IP change we don't bump again for changes within this time period

  constexpr size_t   MAX_SWARM_SIZE                   = 10;
  // We never create a new swarm unless there are SWARM_BUFFER extra nodes
  // available in the queue.
  constexpr size_t   SWARM_BUFFER                     = 5;
  // if a swarm has strictly less nodes than this, it is considered unhealthy
  // and nearby swarms will mirror it's data. It will disappear, and is already considered gone.
  constexpr size_t   MIN_SWARM_SIZE                   = 5;
  constexpr size_t   IDEAL_SWARM_MARGIN               = 2;
  constexpr size_t   IDEAL_SWARM_SIZE                 = MIN_SWARM_SIZE + IDEAL_SWARM_MARGIN;
  constexpr size_t   EXCESS_BASE                      = MIN_SWARM_SIZE;
  constexpr size_t   NEW_SWARM_SIZE                   = IDEAL_SWARM_SIZE;
  // The lower swarm percentile that will be randomly filled with new service nodes
  constexpr size_t   FILL_SWARM_LOWER_PERCENTILE      = 25;
  // Redistribute snodes from decommissioned swarms to the smallest swarms
  constexpr size_t   DECOMMISSIONED_REDISTRIBUTION_LOWER_PERCENTILE = 0;
  // The upper swarm percentile that will be randomly selected during stealing
  constexpr size_t   STEALING_SWARM_UPPER_PERCENTILE  = 75;
  constexpr uint64_t KEY_IMAGE_AWAITING_UNLOCK_HEIGHT = 0;

  constexpr uint64_t STATE_CHANGE_TX_LIFETIME_IN_BLOCKS = VOTE_LIFETIME;

  // If we get an incoming vote of state change tx that is outside the acceptable range by this many
  // blocks then ignore it but don't trigger a connection drop; the sending side could be a couple
  // blocks out of sync and sending something that it thinks is legit.
  constexpr uint64_t VOTE_OR_TX_VERIFY_HEIGHT_BUFFER    = 5;

  constexpr std::array<int, 3> MIN_STORAGE_SERVER_VERSION{{2, 0, 7}};
  constexpr std::array<int, 3> MIN_LOKINET_VERSION{{0, 8, 0}};

  // The minimum accepted version number, broadcasted by Service Nodes via uptime proofs for each hardfork
  struct proof_version
  {
    uint8_t hardfork;
    std::array<uint16_t, 3> version;
  };

  constexpr proof_version MIN_UPTIME_PROOF_VERSIONS[] = {
    {cryptonote::network_version_16_pulse,                {8,1,0}},
    {cryptonote::network_version_15_lns,                  {7,1,2}},
    {cryptonote::network_version_14_blink,                {6,1,0}},
    {cryptonote::network_version_13_enforce_checkpoints,  {5,1,0}},
    {cryptonote::network_version_12_checkpointing,        {4,0,3}},
  };

  using swarm_id_t                         = uint64_t;
  constexpr swarm_id_t UNASSIGNED_SWARM_ID = UINT64_MAX;

  constexpr size_t min_votes_for_quorum_type(quorum_type q) {
    return
      q == quorum_type::obligations     ? STATE_CHANGE_MIN_VOTES_TO_CHANGE_STATE :
      q == quorum_type::checkpointing   ? CHECKPOINT_MIN_VOTES :
      q == quorum_type::blink           ? BLINK_MIN_VOTES :
      std::numeric_limits<size_t>::max();
  };

  constexpr quorum_type max_quorum_type_for_hf(uint8_t hf_version)
  {
    return
        hf_version <= cryptonote::network_version_12_checkpointing ? quorum_type::obligations :
        hf_version <  cryptonote::network_version_14_blink         ? quorum_type::checkpointing :
        hf_version <  cryptonote::network_version_16_pulse         ? quorum_type::blink :
        quorum_type::pulse;
  }

  constexpr uint64_t staking_num_lock_blocks(cryptonote::network_type nettype)
  {
    switch (nettype)
    {
      case cryptonote::FAKECHAIN: return 30;
      case cryptonote::TESTNET:   return BLOCKS_EXPECTED_IN_DAYS(2);
      default:                    return BLOCKS_EXPECTED_IN_DAYS(30);
    }
  }

  //If a nodes timestamp varies by this amount of seconds they will be considered out of sync
  constexpr uint8_t THRESHOLD_SECONDS_OUT_OF_SYNC = 30;

  //If the below percentage of service nodes are out of sync we will consider our clock out of sync
  constexpr uint8_t MAXIMUM_EXTERNAL_OUT_OF_SYNC = 80;

static_assert(STAKING_PORTIONS != UINT64_MAX, "UINT64_MAX is used as the invalid value for failing to calculate the min_node_contribution");
// return: UINT64_MAX if (num_contributions > the max number of contributions), otherwise the amount in loki atomic units
uint64_t get_min_node_contribution            (uint8_t version, uint64_t staking_requirement, uint64_t total_reserved, size_t num_contributions);
uint64_t get_min_node_contribution_in_portions(uint8_t version, uint64_t staking_requirement, uint64_t total_reserved, size_t num_contributions);

// Gets the maximum allowed stake amount.  This is used to prevent significant overstaking.  The
// wallet tries to avoid this when submitting a stake, but it can still happen when competing stakes
// get submitted into the mempool -- for example, with 10k of contribution room, two contributions
// of 8k could get submitted and both would be accepted, but the second one would only count as 2k
// of stake despite locking 8k.
// Starting in HF16, we disallow a stake if it is more than MAXIMUM_ACCEPTABLE_STAKE ratio of the
// available contribution room, which allows slight overstaking but disallows larger overstakes.
uint64_t get_max_node_contribution(uint8_t version, uint64_t staking_requirement, uint64_t total_reserved);

uint64_t get_staking_requirement(cryptonote::network_type nettype, uint64_t height, uint8_t hf_version);

uint64_t portions_to_amount(uint64_t portions, uint64_t staking_requirement);

/// Check if portions are sufficiently large (provided the contributions
/// are made in the specified order) and don't exceed the required amount
bool check_service_node_portions(uint8_t version, const std::vector<uint64_t>& portions);

crypto::hash generate_request_stake_unlock_hash(uint32_t nonce);
uint64_t     get_locked_key_image_unlock_height(cryptonote::network_type nettype, uint64_t node_register_height, uint64_t curr_height);

// Returns lowest x such that (staking_requirement * x/STAKING_PORTIONS) >= amount
uint64_t get_portions_to_make_amount(uint64_t staking_requirement, uint64_t amount, uint64_t max_portions = STAKING_PORTIONS);

bool get_portions_from_percent_str(std::string cut_str, uint64_t& portions);

}
