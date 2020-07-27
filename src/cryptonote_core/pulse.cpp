#include <array>
#include <mutex>
#include <chrono>

#include "misc_log_ex.h"

#include "cryptonote_core.h"
#include "cryptonote_basic/hardfork.h"
#include "service_node_list.h"
#include "service_node_quorum_cop.h"
#include "service_node_rules.h"

enum struct round_state
{
  wait_next_block,
  wait_for_round,
  wait_for_handshakes,
  wait_for_other_validator_handshake_bitsets,
  submit_block_template,
};

struct round_context
{
  struct
  {
    pulse::time_point round_0_start_time;
    uint8_t round;
  } wait_next_block;

  struct
  {
    service_nodes::quorum quorum;
    bool producer;
  } wait_for_round;

  struct
  {
    uint16_t validator_bits;
    pulse::time_point end_time;
    bool all_received() { return validator_bits == service_nodes::pulse_validator_bit_mask(); }
  } wait_for_handshakes;

  struct
  {
    std::array<uint16_t, service_nodes::PULSE_QUORUM_NUM_VALIDATORS> received_bitsets;
    int received_bitsets_count;
    pulse::time_point end_time;
    bool all_received() { return received_bitsets_count == service_nodes::PULSE_QUORUM_NUM_VALIDATORS; }
  } wait_for_other_validator_handshake_bitsets;

  struct
  {
    uint16_t validator_bitset;
  } submit_block_template;
};

namespace
{
round_state sleep_until_next_block_or_round(cryptonote::Blockchain const &blockchain, round_context &context, std::condition_variable &cv, std::mutex &mutex, uint64_t curr_height)
{
  // TODO(doyle): Handle this error better
  // assert(context.wait_next_block.round <= static_cast<uint8_t>(-1));
  context.wait_next_block.round++;

  pulse::time_point const start_time = context.wait_next_block.round_0_start_time +
                                       (context.wait_next_block.round * service_nodes::PULSE_TIME_PER_BLOCK);

  if (auto now = pulse::clock::now(); now < start_time)
  {
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(start_time - now).count();
    MGINFO("Pulse: Sleeping " << duration << "s until pulse round " << +context.wait_next_block.round << " commences for block " << curr_height);

    uint64_t height = 0;
    {
      std::unique_lock lock{mutex};
      cv.wait_until(lock, start_time, [&blockchain, start_time, &height, curr_height]() {
        bool wakeup_time = pulse::clock::now() >= start_time;
        height           = blockchain.get_current_blockchain_height(true /*lock*/);
        return wakeup_time || (height != curr_height);
      });
    }

    if (height != curr_height)
    {
      MGINFO("Pulse: Blockchain height changed during sleep from " << curr_height << " to " << height << ", re-evaluating pulse block");
      return round_state::wait_next_block;
    }
  }

  return round_state::wait_for_round;
}

} // anonymous namespace

bool pulse::state::block_added(const cryptonote::block& block, const std::vector<cryptonote::transaction>&, cryptonote::checkpoint_t const *)
{
  // TODO(doyle): Better check than heuristics.
  cryptonote::pulse_header null_header = {};
  if (block.signatures.size() != service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES || std::memcmp(&block.pulse, &null_header, sizeof(null_header) == 0))
    last_miner_block = cryptonote::get_block_height(block);

  block_added_cv.notify_one();
  return true;
}

/*
  'round_state' State Machine Flow Graph

  +-----------------+
  | Wait Next Block | <-----+
  +-----------------+       |
   |                        |
   |                        |
   V                      +-|-+
  +----------------+      | | |
  | Wait For Round |<-----+ | +------------------------------+
  +----------------+        |                                |
   |                        |                                |
  [Enough SN's for Pulse?]--+ No                             |
   |                        |                                |
   | Yes                    |                                |
   |                        |                                |
  [Block Height Changed?]---+ Yes                            |
   |                                                         |
   | No                                                      |
   |                                                         | No
  [Are we a Block Validator?]------[Are we a Block Leader?]--+
   |                                        |                |
   | Yes                                    | Yes            |
   |                                        |                |
   V                                        |                |
  +---------------------+                   |                |
  | Wait For Handshakes |                   |                |
  +---------------------+                   |                |
   |                                        |                |
  [Quorumnet Comms Fail?]------------------------------------+
   |                      Yes               |                |
   | No                                     |                |
   |                                        |                |
   V                                        V                |
  +--------------------------------------------+             |
  | Wait For Other Validator Handshake Bitsets |             |
  +--------------------------------------------+             |
   |                                                         |
  [Quorumnet Comms Fail?]------------------------------------+
   |                      Yes
   | No
   |
   V
  +-----------------------+
  | Submit Block Template |
  +-----------------------+


  Wait Next Block:
    - Sleeps until Blockchain is at HF16
    - Sleeps until the timestamp of the next block has arrived.

      Next Block Timestamp = G.Timestamp + (height * 2min)

      Where 'G' is the base Pulse genesis block. That is determined by the
      following

      Genesis Block = max(HF16 block height, latest block height produced by Miner).

      In case of the Service Node network failing, i.e. (pulse round > 255) or
      insufficient Service Nodes for Pulse, mining is re-activated and accepted
      as the next block in the blockchain. This resets the genesis block in
      which future Pulse block timestamps are based off.

      This prevents a situation where a long time could elapse between the next
      miner block at a chain halt. Upon receiving the miner block, overdue
      Pulse blocks would rapidly be generated in the chain to catch up to the
      supposed timestamp the chain should be at.

  Wait For Round:
    - Generate Pulse quorum, if there are insufficient Service Nodes, we sleep
      until the next Proof-of-Work block arrives.
    - If not participating, the node waits until the next block or round and
      re-checks participation.
    - Block Validators handshake to confirm participation in the round and collect other handshakes.
    - The Block Producer skips to waiting for the handshake bitsets from each validator

  Wait For Handshakes:
    - Validators will each individually collect handshakes and build up a
      bitset of validators perceived to be participating.
    - Block on the pulse message queue which receives the individual handshake
      bits from Quorumnet until timeout or all handshakes received.

  Wait For Handshake Bitset:
    - Validators will each individually collect the handshake bitsets similar
      to Wait For Handshakes.
    - Upon receipt, the most common agreed upon bitset is used to lock in
      participation for the round. The round proceeds if more than 60% of the
      validators are participating, the round fails otherwise.

  Submit Block Template:
    - TBD

*/

void pulse::main(pulse::state &state, void *quorumnet_state, cryptonote::core &core)
{
  cryptonote::Blockchain &blockchain          = core.get_blockchain_storage();
  service_nodes::service_node_keys const &key = core.get_service_keys();

  bool base_block_initialized        = false;
  cryptonote::block base_pulse_block = {};

  crypto::hash top_hash = {};
  uint64_t pulse_height = 0;
  std::mutex pulse_mutex;

  round_context context      = {};
  uint64_t const hf16_height = cryptonote::HardFork::get_hardcoded_hard_fork_height(blockchain.nettype(), cryptonote::network_version_16);

  if (hf16_height == cryptonote::HardFork::INVALID_HF_VERSION_HEIGHT)
    return;

  for (auto round_state = round_state::wait_next_block;;)
  {
    switch (round_state)
    {
      default:
        break;

      case round_state::wait_next_block:
      {
        uint64_t curr_height     = blockchain.get_current_blockchain_height(true /*lock*/);
#if 0
        uint64_t starting_height = std::max(hf16_height, state.last_miner_block.load());
#else
        uint64_t starting_height = curr_height - 1; // (DEBUG): Make next block timestamps relative to previous block.
#endif
        context                  = {};

        //
        // NOTE: Sleep until Blockchain is ready to produce Pulse Blocks
        //
        if (curr_height < starting_height)
        {
          MGINFO("Pulse: Network at block " << curr_height << " is not ready for Pulse until block " << starting_height << ", worker going to sleep");
          std::unique_lock lock{pulse_mutex};
          state.block_added_cv.wait(lock, [&state, &blockchain, hf16_height, &curr_height, &starting_height]() {
            curr_height     = blockchain.get_current_blockchain_height(true /*lock*/);
            starting_height = std::max(hf16_height, state.last_miner_block.load());
            return curr_height >= starting_height;
          });
        }

        //
        // NOTE: If already processing pulse for height, wait for next height
        //
        if (pulse_height == curr_height)
        {
          MGINFO("Pulse: Network is currently producing block " << pulse_height << ", sleeping until next block");
          std::unique_lock lock{pulse_mutex};
          state.block_added_cv.wait(lock, [&blockchain, &curr_height, pulse_height]() {
            curr_height = blockchain.get_current_blockchain_height(true /*lock*/);
            return curr_height != pulse_height;
          });
        }

        pulse_height = curr_height;
        top_hash     = blockchain.get_block_id_by_height(pulse_height - 1);

        if (top_hash == crypto::null_hash)
        {
          MERROR("Pulse: Block hash for height " << pulse_height << " does not exist!");
          continue;
        }

        //
        // NOTE: Get the round start time
        //
        if (!base_block_initialized || (cryptonote::get_block_height(base_pulse_block) != starting_height))
        {
          std::vector<std::pair<cryptonote::blobdata, cryptonote::block>> block;
          if (!blockchain.get_blocks(starting_height, 1, block))
          {
            MERROR("Pulse: Could not query block " << starting_height << " from the DB, unable to continue with Pulse");
            continue;
          }

          base_block_initialized = true;
          base_pulse_block       = std::move(block[0].second);
        }

        auto base_timestamp   = pulse::time_point(std::chrono::seconds(base_pulse_block.timestamp));
        uint64_t delta_height = curr_height - cryptonote::get_block_height(base_pulse_block);
        context.wait_next_block.round_0_start_time = base_timestamp + (delta_height * service_nodes::PULSE_TIME_PER_BLOCK);

        //
        // NOTE: Determine Pulse Round
        //
        if (auto now = pulse::clock::now(); now < context.wait_next_block.round_0_start_time)
        {
          context.wait_next_block.round = 0;
        }
        else
        {
          auto const time_since_block = pulse::clock::now() - context.wait_next_block.round_0_start_time;
          size_t pulse_round_usize    = time_since_block / service_nodes::PULSE_TIME_PER_BLOCK;

          // TODO(doyle): We need to handle this error better.
          // assert(pulse_round_usize < static_cast<uint8_t>(-1));
          context.wait_next_block.round = static_cast<uint8_t>(pulse_round_usize);
        }

        round_state = round_state::wait_for_round;
      }
      break;

      case round_state::wait_for_round:
      {
        context.wait_for_round = {};

        pulse::time_point const start_time = context.wait_next_block.round_0_start_time +
                                             (context.wait_next_block.round * service_nodes::PULSE_TIME_PER_BLOCK);
        context.wait_for_handshakes.end_time = start_time + std::chrono::seconds(10);
        context.wait_for_other_validator_handshake_bitsets.end_time = context.wait_for_handshakes.end_time + std::chrono::seconds(10);

        //
        // NOTE: Derive quorum for pulse round
        //
        {
          context.wait_for_round.quorum =
              service_nodes::generate_pulse_quorum(blockchain.nettype(),
                                                   blockchain.get_db(),
                                                   pulse_height - 1,
                                                   blockchain.get_service_node_list().get_block_leader().key,
                                                   blockchain.get_current_hard_fork_version(),
                                                   blockchain.get_service_node_list().active_service_nodes_infos(),
                                                   context.wait_next_block.round);

          if (!service_nodes::verify_pulse_quorum_sizes(context.wait_for_round.quorum)) // Insufficient Service Nodes for quorum
          {
            MGINFO("Pulse: Insufficient Service Nodes to execute Pulse on height " << pulse_height << ", we require a PoW miner block. Sleeping until next block.");
            round_state = round_state::wait_next_block;
            continue;
          }
        }

        //
        // NOTE: Determine quorum participation
        //
        if (key.pub == context.wait_for_round.quorum.workers[0])
        {
          MGINFO("Pulse: We are the block producer for height " << pulse_height << " in round " << +context.wait_next_block.round << ", awaiting validator handshake bitsets.");
          context.wait_for_round.producer = true;
          round_state                     = round_state::wait_for_other_validator_handshake_bitsets;
        }
        else
        {
          bool validator = false;
          for (crypto::public_key const &validator_key : context.wait_for_round.quorum.validators)
          {
            validator = (validator_key == key.pub);
            if (validator) break;
          }

          if (!validator)
          {
            MGINFO("Pulse: We are not a pulse validator for height " << pulse_height << " in round " << +context.wait_next_block.round << ". Waiting for next pulse round or block.");
            round_state = sleep_until_next_block_or_round(blockchain, context, state.block_added_cv, pulse_mutex, pulse_height);
            break;
          }
        }

        //
        // NOTE: Sleep until round starts or block added
        //
        // TODO(doyle): DRY sleep code
        if (auto now = pulse::clock::now(); now < start_time)
        {
          auto duration = std::chrono::duration_cast<std::chrono::seconds>(start_time - now).count();
          MGINFO("Pulse: Sleeping " << duration << "s until pulse round " << +context.wait_next_block.round << " commences for block " << pulse_height);

          uint64_t height = 0;
          {
            std::unique_lock lock{pulse_mutex};
            state.block_added_cv.wait_until(lock, start_time, [&blockchain, start_time, &height, pulse_height]() {
              bool wakeup_time = pulse::clock::now() >= start_time;
              height           = blockchain.get_current_blockchain_height(true /*lock*/);
              return wakeup_time || (height != pulse_height);
            });
          }

          if (height != pulse_height)
          {
            MGINFO("Pulse: Blockchain height changed during sleep from " << pulse_height << " to " << height << ", re-evaluating pulse block");
            round_state = round_state::wait_next_block;
            break;
          }
        }

        if (!context.wait_for_round.producer)
        {
          try
          {
            MGINFO("Pulse: We are a pulse validator for height " << pulse_height << " in round " << +context.wait_next_block.round << ", sending handshake bit to quorum and collecting other validator handshakes.");
            cryptonote::quorumnet_send_pulse_validator_handshake_bit(quorumnet_state, context.wait_for_round.quorum, top_hash);
            round_state = round_state::wait_for_handshakes;
          }
          catch (std::exception const &e)
          {
            MERROR("Attempting to invoke and send a Pulse participation handshake unexpectedly failed. " << e.what());
            round_state = sleep_until_next_block_or_round(blockchain, context, state.block_added_cv, pulse_mutex, pulse_height);
          }
        }
      }
      break;

      case round_state::wait_for_handshakes:
      {
        bool timed_out      = pulse::clock::now() >= context.wait_for_handshakes.end_time;
        bool all_handshakes = context.wait_for_handshakes.all_received();

        if (all_handshakes || timed_out)
        {
          std::bitset<8 * sizeof(context.wait_for_handshakes.validator_bits)> bitset = context.wait_for_handshakes.validator_bits;
          bool missing_handshakes = timed_out && !all_handshakes;
          MGINFO("Pulse: Collected validator handshakes " << bitset << (missing_handshakes ? ", we timed out and some handshakes were not seen! " : ". ") << "Sending handshake bitset and collecting other validator bitsets.");
          try
          {
            cryptonote::quorumnet_send_pulse_validator_handshake_bitset(quorumnet_state, context.wait_for_round.quorum, top_hash, context.wait_for_handshakes.validator_bits);
            round_state = round_state::wait_for_other_validator_handshake_bitsets;
          }
          catch(std::exception const &e)
          {
            MERROR("Attempting to invoke and send a Pulse participation handshake bitset unexpectedly failed. " << e.what());
            round_state = sleep_until_next_block_or_round(blockchain, context, state.block_added_cv, pulse_mutex, pulse_height);
          }
        }
      }
      break;

      case round_state::wait_for_other_validator_handshake_bitsets:
      {
        bool all_bitsets = context.wait_for_other_validator_handshake_bitsets.all_received();
        bool timed_out   = pulse::clock::now() >= context.wait_for_other_validator_handshake_bitsets.end_time;
        if (timed_out || all_bitsets)
        {
          bool missing_bitsets = timed_out && !all_bitsets;
          MGINFO("Pulse: Collected " << context.wait_for_other_validator_handshake_bitsets.received_bitsets_count << " handshake bitsets" << (missing_bitsets ? ", we timed out and some bitsets were not seen!" : ""));

          std::map<uint16_t, int> most_common_validator_bitset;
          for (uint16_t bits : context.wait_for_other_validator_handshake_bitsets.received_bitsets)
            most_common_validator_bitset[bits]++;

          uint16_t most_common_bitset = most_common_validator_bitset.begin()->first;
          uint16_t count              = most_common_validator_bitset.begin()->second;

          if (count < (service_nodes::PULSE_QUORUM_NUM_VALIDATORS * 6 / 10))
          {
            // Less than 60% of the validators can't come to agreement
            // about which validators are online, we wait until the
            // next round.
            MGINFO("Pulse: We heard back from less than 60% of the validators, waiting for next round.");
            round_state = sleep_until_next_block_or_round(blockchain, context, state.block_added_cv, pulse_mutex, pulse_height);
          }
          else
          {
            std::bitset<8 * sizeof(most_common_bitset)> bitset = most_common_bitset;
            MGINFO("Pulse: " << count << " validators agreed on the participating nodes in the quorum " << bitset << (context.wait_for_round.producer ? "" : "Awaiting block template from block producer"));
            context.submit_block_template.validator_bitset = most_common_bitset;
            if (context.wait_for_round.producer)
              round_state = context.wait_for_round.producer ? round_state::submit_block_template : round_state::wait_next_block;
          }
        }
      }
      break;

      case round_state::submit_block_template:
      {
        assert(context.wait_for_round.producer);
        std::vector<service_nodes::service_node_pubkey_info> list_state = blockchain.get_service_node_list().get_service_node_list_state({key.pub});

        if (list_state.empty())
        {
          MGINFO("Pulse: Block producer (us) is not available on the service node list, waiting until next round");
          round_state = round_state::wait_next_block;
          break;
        }

        // TODO(doyle): These checks can be done earlier?
        std::shared_ptr<const service_nodes::service_node_info> info = list_state[0].info;
        if (!info->is_active())
        {
          MGINFO("Pulse: Block producer (us) is not an active service node, waiting until next round");
          round_state = sleep_until_next_block_or_round(blockchain, context, state.block_added_cv, pulse_mutex, pulse_height);
          break;
        }

        MGINFO("Pulse: Validators are handshaken and ready, sending block template from producer (us) to validators.\n");
        service_nodes::payout block_producer_payouts = service_nodes::service_node_info_to_payout(key.pub, *info);
        cryptonote::block block = {};
        uint64_t expected_reward = 0;
        blockchain.create_next_pulse_block_template(block, block_producer_payouts, pulse_height, expected_reward);

        cryptonote::block_verification_context bvc = {};
        core.handle_block_found(block, bvc);

        round_state = round_state::wait_next_block;
      }
      break;
    }

    pulse::time_point pump_messages_until = {};
    switch(round_state)
    {
      default: break;

      case round_state::wait_for_handshakes:
        pump_messages_until = context.wait_for_handshakes.end_time;
        break;

      case round_state::wait_for_other_validator_handshake_bitsets:
        pump_messages_until = context.wait_for_other_validator_handshake_bitsets.end_time;
        break;
    }

    if (auto now = pulse::clock::now(); now < pump_messages_until)
    {
      auto duration = std::chrono::duration_cast<std::chrono::seconds>(pump_messages_until - now);
      MGINFO("Pulse: Pumping messages from quorumnet for " << duration.count() << "s or until all messages received.");
    }

    pulse::message msg = {};
    while (cryptonote::quorumnet_pulse_pump_messages(quorumnet_state, msg, pump_messages_until))
    {
      bool relay_message  = false;
      bool finish_pumping = false;

      if (msg.quorum_position >= static_cast<int>(context.wait_for_round.quorum.validators.size()))
      {
        MERROR("Quorum position " << msg.quorum_position << " in Pulse message indexes oob");
        continue;
      }

      crypto::public_key const &validator_key = context.wait_for_round.quorum.validators[msg.quorum_position];
      if (msg.type == pulse::message_type::handshake)
      {
        if (round_state != round_state::wait_for_handshakes)
          continue;

        // TODO(doyle): DRY
        // NOTE: Validate Signature
        {
          auto buf = tools::memcpy_le(top_hash.data, msg.quorum_position);
          crypto::hash hash;
          crypto::cn_fast_hash(buf.data(), buf.size(), hash);

          if (!crypto::check_signature(hash, validator_key, msg.signature))
          {
            MERROR("Signature from pulse handshake bit does not validate with node " << msg.quorum_position << ":" << lokimq::to_hex(tools::view_guts(validator_key)) << ", at height " << pulse_height << "; Validator signing outdated height or bad handshake data");
            continue;
          }
        }

        relay_message = ((context.wait_for_handshakes.validator_bits & msg.quorum_position) == 0);
        context.wait_for_handshakes.validator_bits |= msg.quorum_position;
        finish_pumping = context.wait_for_handshakes.all_received();
      }
      else if (msg.type == pulse::message_type::handshake_bitset)
      {
        if (round_state != round_state::wait_for_other_validator_handshake_bitsets)
          continue;

        // NOTE: Validate Signature
        {
          auto buf = tools::memcpy_le(msg.validator_bitset, top_hash.data, msg.quorum_position);
          crypto::hash hash;
          crypto::cn_fast_hash(buf.data(), buf.size(), hash);

          if (!crypto::check_signature(hash, validator_key, msg.signature))
          {
            MERROR("Signature from pulse handshake bitset does not validate with node " << msg.quorum_position << ":" << lokimq::to_hex(tools::view_guts(validator_key)) << ", at height " << pulse_height << "; Validator signing outdated height or bad handshake data");
            continue;
          }
        }

        uint16_t prev_bitset = context.wait_for_other_validator_handshake_bitsets.received_bitsets[msg.quorum_position];
        relay_message        = prev_bitset != msg.validator_bitset;

        context.wait_for_other_validator_handshake_bitsets.received_bitsets[msg.quorum_position] = msg.validator_bitset;
        if (prev_bitset == 0)
          context.wait_for_other_validator_handshake_bitsets.received_bitsets_count++;

        finish_pumping = context.wait_for_other_validator_handshake_bitsets.all_received();
      }
      else
      {
        assert(msg.type == pulse::message_type::invalid);
      }

      if (relay_message)
        cryptonote::quorumnet_pulse_relay_message_to_quorum(quorumnet_state, msg, context.wait_for_round.quorum);

      if (finish_pumping)
        break;
    }
  }
}
