#include <array>
#include <mutex>
#include <chrono>

#include "misc_log_ex.h"

#include "cryptonote_core.h"
#include "cryptonote_basic/hardfork.h"
#include "service_node_list.h"
#include "service_node_quorum_cop.h"
#include "service_node_rules.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "pulse"

enum struct round_state
{
  wait_next_block,
  wait_for_round,
  round_starts,
  wait_for_handshakes,
  wait_for_handshake_bitsets,
  submit_block_template,
  wait_for_block_template,
  terminate,
};

constexpr std::string_view round_state_string(round_state state)
{
  switch(state)
  {
    case round_state::wait_next_block: return "Wait Next Block"sv;
    case round_state::wait_for_round: return "Wait For Round"sv;
    case round_state::round_starts: return "Round Starts"sv;
    case round_state::wait_for_handshakes: return "Wait For Handshakes"sv;
    case round_state::wait_for_handshake_bitsets: return "Wait For Validator Handshake Bitsets"sv;
    case round_state::submit_block_template: return "Submit Block Template"sv;
    case round_state::wait_for_block_template: return "Wait For Block Template"sv;
    case round_state::terminate: return "Terminate"sv;
  }

  return "Invalid2"sv;
}

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
  } wait_for_round;

  struct
  {
    bool is_producer;
    size_t my_quorum_position;
    std::string node_name;
  } round_starts;

  struct
  {
    uint16_t validator_bits;
    pulse::time_point start_time;
    pulse::time_point end_time;
    bool all_received() { return validator_bits == service_nodes::pulse_validator_bit_mask(); }
  } wait_for_handshakes;

  struct
  {
    std::array<uint16_t, service_nodes::PULSE_QUORUM_NUM_VALIDATORS> bitsets;
    int bitsets_count;
    pulse::time_point end_time;
    bool all_received() { return bitsets_count == service_nodes::PULSE_QUORUM_NUM_VALIDATORS; }
  } wait_for_handshake_bitsets;

  struct
  {
    uint16_t validator_bitset;
  } submit_block_template;

  struct
  {
    bool received;
    cryptonote::block block;
    pulse::time_point end_time;
  } wait_for_block_template;

  uint64_t height;
};

namespace
{

enum sleep_until
{
  next_block,
  next_block_or_round,
  round_starts
};

round_state thread_sleep(sleep_until until,
                         pulse::state &state,
                         cryptonote::Blockchain const &blockchain,
                         round_context &context,
                         std::mutex &mutex)
{
  switch(until)
  {
    case sleep_until::next_block:
    {
      std::unique_lock lock{mutex};
      state.wakeup_cv.wait(lock, [&state, &blockchain, height = context.height]() {
        return state.shutdown || height != blockchain.get_current_blockchain_height(true /*lock*/);
      });

      return state.shutdown ? round_state::terminate : round_state::wait_next_block;
    }

    default:
    {
      if (until == sleep_until::next_block_or_round)
      {
        // TODO(doyle): Handle this error better
        // assert(context.wait_next_block.round <= static_cast<uint8_t>(-1));
        context.wait_next_block.round++;
      }

      pulse::time_point const start_time = context.wait_next_block.round_0_start_time +
                                           (context.wait_next_block.round * service_nodes::PULSE_TIME_PER_BLOCK);

      uint64_t curr_height = context.height;
      if (auto now = pulse::clock::now(); now < start_time)
      {
        MINFO("Pulse: Sleeping " << tools::get_human_readable_timespan(start_time - now) << " until pulse round " << +context.wait_next_block.round << " commences for block " << context.height);

        std::unique_lock lock{mutex};
        state.wakeup_cv.wait_until(lock, start_time, [&state, &blockchain, start_time, height = context.height, &curr_height]() {
          bool wakeup_time = pulse::clock::now() >= start_time;
          curr_height      = blockchain.get_current_blockchain_height(true /*lock*/);
          return wakeup_time || (height != curr_height) || state.shutdown;
        });

        if (state.shutdown)
          return round_state::terminate;

      }

      if (context.height != curr_height)
      {
        MINFO("Pulse: Blockchain height changed during sleep from " << context.height << " to " << curr_height << ", re-evaluating pulse block");
        return round_state::wait_next_block;
      }

      assert(until == sleep_until::next_block_or_round || until == sleep_until::round_starts);
      return until == sleep_until::next_block_or_round ? round_state::wait_for_round : round_state::round_starts;
    }
  }
}

std::string log_prefix(round_context const &context)
{
  std::stringstream result;
  result << "Pulse B" << context.height << " R" << +context.wait_next_block.round << ": ";
  if (context.round_starts.node_name.size()) result << context.round_starts.node_name << " ";
  return result.str();
}

bool msg_time_check(round_context const &context, pulse::message const &msg, pulse::time_point now, pulse::time_point start, pulse::time_point end)
{
  if (now < start || now >= end)
  {
    std::stringstream stream;
    stream << log_prefix(context) << "Dropping " << pulse::message_type_string(msg.type) << " message from validator " << msg.handshakes.quorum_position << ", message arrived ";

    if (now < start)
      stream << tools::get_human_readable_timespan(context.wait_for_handshakes.end_time - now) << " early";
    else
      stream << tools::get_human_readable_timespan(now - context.wait_for_handshakes.end_time) << " late";

    MINFO(stream.str());
    return false;
  }

  return true;
}

} // anonymous namespace

bool pulse::state::block_added(const cryptonote::block& block, const std::vector<cryptonote::transaction>&, cryptonote::checkpoint_t const *)
{
  // TODO(doyle): Better check than heuristics.
  constexpr cryptonote::pulse_header null_header = {};
  if (block.signatures.size() != service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES || block.pulse == null_header)
    last_miner_block = cryptonote::get_block_height(block);

  wakeup_cv.notify_one();
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
   |                                                         |
  +---------------------+                                    |
  | Round Starts        |                                    |
  +---------------------+                                    |
   |                          No                             |
  [Are we a Block Validator?]------[Are we a Block Leader?]--+ No
   |                                        |                |
   | Yes                                    | Yes            |
   |                                        |                |
  [Send Handshakes Fail?]------------------------------------+
   |                                        |                |
   | No                                     |                |
   |                                        |                |
   V                                        |                |
  +---------------------+                   |                |
  | Wait For Handshakes |                   |                |
  +---------------------+                   |                |
   |                                        |                |
  [Send Handshake Bitsets Fails?]----------------------------+
   |                                        |                |
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
    - Sleep until the round should start.

  Start Handshaking:
    - The Block Producer skips to waiting for the handshake bitsets from each validator
    - If not participating, the node waits until the next block or round and
      re-checks participation.
    - Block Validators handshake to confirm participation in the round and collect other handshakes.

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

void pump_messages_from_quorumnet(void *quorumnet_state, round_state round_state, round_context &context, crypto::hash const &top_hash)
{
  //
  // NOTE: Determine how long to pump messages from the queue
  //
  pulse::time_point pump_messages_until = {};
  switch(round_state)
  {
    default: break;

    case round_state::wait_for_handshakes:
      pump_messages_until = context.wait_for_handshakes.end_time;
      break;

    case round_state::wait_for_handshake_bitsets:
      pump_messages_until = context.wait_for_handshake_bitsets.end_time;
      break;

    case round_state::wait_for_block_template:
      pump_messages_until = context.wait_for_block_template.end_time;
      break;
  }

  if (auto now = pulse::clock::now(); now < pump_messages_until)
  {
    MINFO(log_prefix(context) << "Pumping messages for '" << round_state_string(round_state) << "' from quorumnet for "
                              << tools::get_human_readable_timespan(pump_messages_until - now)
                              << " or until all messages received.");
  }

  //
  // NOTE: Retrieve messages sent on Quorumnet from message queue
  //
  pulse::message msg = {};
  while (cryptonote::quorumnet_pulse_pump_messages(quorumnet_state, msg, pump_messages_until))
  {
    bool relay_message  = false;
    bool finish_pumping = false;

    if (msg.type == pulse::message_type::handshake || msg.type == pulse::message_type::handshake_bitset)
    {
      if (msg.handshakes.quorum_position >= static_cast<int>(context.wait_for_round.quorum.validators.size()))
      {
        MERROR(log_prefix(context) << "Quorum position " << msg.handshakes.quorum_position << " in Pulse message indexes oob");
        continue;
      }

      crypto::public_key const &validator_key = context.wait_for_round.quorum.validators[msg.handshakes.quorum_position];
      crypto::hash hash = {};

      if (msg.type == pulse::message_type::handshake)
      {
        auto buf = tools::memcpy_le(top_hash.data, msg.handshakes.quorum_position);
        hash     = crypto::cn_fast_hash(buf.data(), buf.size());
      }
      else
      {
        auto buf = tools::memcpy_le(msg.handshakes.validator_bitset, top_hash.data, msg.handshakes.quorum_position);
        hash     = crypto::cn_fast_hash(buf.data(), buf.size());
      }

      if (!crypto::check_signature(hash, validator_key, msg.handshakes.signature))
      {
        MERROR(log_prefix(context) << "Signature from pulse handshake bit does not validate with node " << msg.handshakes.quorum_position << ":" << lokimq::to_hex(tools::view_guts(validator_key)) << ", at height " << context.height << "; Validator signing outdated height or bad handshake data");
        continue;
      }
    }

    switch(msg.type)
    {
      default: assert(msg.type == pulse::message_type::invalid); break;

      case pulse::message_type::handshake:
      {
        // TODO(doyle): We need some lenience in time for accepting early
        // handshakes in case clocks are slightly out of sync.
        if (!msg_time_check(context, msg, pulse::clock::now(), context.wait_for_handshakes.start_time, context.wait_for_handshakes.end_time))
          continue;

        uint16_t quorum_position_bit = 1 << msg.handshakes.quorum_position;
        relay_message = ((context.wait_for_handshakes.validator_bits & quorum_position_bit) == 0);
        context.wait_for_handshakes.validator_bits |= quorum_position_bit;
        finish_pumping = context.wait_for_handshakes.all_received();

        if (relay_message) // First time seen handshake
        {
          auto position_bitset  = std::bitset<sizeof(quorum_position_bit) * 8>(quorum_position_bit);
          auto validator_bitset = std::bitset<sizeof(quorum_position_bit) * 8>(context.wait_for_handshakes.validator_bits);
          MINFO(log_prefix(context) << "Received handshake with quorum position bit (" << msg.handshakes.quorum_position <<") " << position_bitset << " saved to bitset " << validator_bitset);
        }
      }
      break;

      case pulse::message_type::handshake_bitset:
      {
        if (!msg_time_check(context, msg, pulse::clock::now(), context.wait_for_handshakes.start_time, context.wait_for_handshake_bitsets.end_time))
          continue;

        uint16_t prev_bitset = context.wait_for_handshake_bitsets.bitsets[msg.handshakes.quorum_position];
        if (!context.round_starts.is_producer)
          relay_message = (prev_bitset != msg.handshakes.validator_bitset);

        context.wait_for_handshake_bitsets.bitsets[msg.handshakes.quorum_position] = msg.handshakes.validator_bitset;
        if (prev_bitset == 0)
          context.wait_for_handshake_bitsets.bitsets_count++;

        finish_pumping = context.wait_for_handshake_bitsets.all_received();
      }
      break;

      case pulse::message_type::block_template:
      {
        assert(!context.round_starts.is_producer);

        if (!msg_time_check(context, msg, pulse::clock::now(), context.wait_for_handshakes.start_time, context.wait_for_block_template.end_time))
          continue;

        // TODO(doyle): Time check
        cryptonote::block block = {};
        if (!cryptonote::t_serializable_object_from_blob(block, msg.block_template.blob))
        {
          MINFO(log_prefix(context) << "Received unparsable pulse block template blob");
          continue;
        }

        crypto::public_key const &block_producer = context.wait_for_round.quorum.workers[0];
        crypto::hash hash = crypto::cn_fast_hash(msg.block_template.blob.data(), msg.block_template.blob.size());
        if (!crypto::check_signature(hash, block_producer, msg.block_template.signature))
        {
          MINFO(log_prefix(context) << "Received pulse block template not signed by the block producer");
          continue;
        }

        if (block.pulse.round != context.wait_next_block.round)
        {
          MINFO(log_prefix(context) << "Received pulse block template specifying different round " << +block.pulse.round << ", expected " << +context.wait_next_block.round);
          continue;
        }

        if (block.pulse.validator_bitset != context.submit_block_template.validator_bitset)
        {
          auto block_bitset = std::bitset<sizeof(block.pulse.validator_bitset) * 8>(block.pulse.validator_bitset);
          auto our_bitset   = std::bitset<sizeof(block.pulse.validator_bitset) * 8>(context.submit_block_template.validator_bitset);
          MINFO(log_prefix(context) << "Received pulse block template specifying different validator handshake bitsets " << block_bitset << ", expected " << our_bitset);
          continue;
        }

        if (!context.wait_for_block_template.received)
        {
          context.wait_for_block_template.received = true;
          context.wait_for_block_template.block    = std::move(block);
          relay_message                            = true;
        }

        finish_pumping = true;
      }
      break;
    }

    if (relay_message)
      cryptonote::quorumnet_pulse_relay_message_to_quorum(quorumnet_state, msg, context.wait_for_round.quorum, context.round_starts.is_producer);

    if (finish_pumping)
      break;
  }
}

void pulse::main(pulse::state &state, void *quorumnet_state, cryptonote::core &core)
{
  cryptonote::Blockchain &blockchain          = core.get_blockchain_storage();
  service_nodes::service_node_keys const &key = core.get_service_keys();

  bool base_block_initialized        = false;
  cryptonote::block base_pulse_block = {};

  crypto::hash top_hash = {};
  std::mutex pulse_mutex;

  round_context context = {};

  //
  // NOTE: Sleep until Blockchain is ready to produce Pulse Blocks
  //
  uint64_t const hf16_height = cryptonote::HardFork::get_hardcoded_hard_fork_height(blockchain.nettype(), cryptonote::network_version_16);
  {
    if (hf16_height == cryptonote::HardFork::INVALID_HF_VERSION_HEIGHT)
    {
      MERROR("Pulse: HF16 is not defined, pulse worker exiting.");
      return;
    }

    uint64_t height = blockchain.get_current_blockchain_height(true /*lock*/);
    if (height < hf16_height)
      MINFO("Pulse: Network at block " << height << " is not ready for Pulse until block " << hf16_height << ", worker going to sleep");

    for (; height < hf16_height; height = blockchain.get_current_blockchain_height(true /*lock*/))
    {
      auto result = thread_sleep(sleep_until::next_block, state, blockchain, context, pulse_mutex);
      if (result == round_state::terminate) return;
    }
  }

  for (auto round_state = round_state::wait_next_block; !state.shutdown;)
  {
    switch (round_state)
    {
      case round_state::terminate:
        return;

      case round_state::wait_next_block:
      {
        context = {};

        //
        // NOTE: If already processing pulse for height, wait for next height
        //
        if (context.height == blockchain.get_current_blockchain_height(true /*lock*/))
        {
          MINFO(log_prefix(context) << "Network is currently producing block " << context.height << ", sleeping until next block");
          round_state = thread_sleep(sleep_until::next_block, state, blockchain, context, pulse_mutex);
        }

        context.height = blockchain.get_current_blockchain_height(true /*lock*/);
        top_hash       = blockchain.get_block_id_by_height(context.height - 1);

        if (top_hash == crypto::null_hash)
        {
          MERROR(log_prefix(context) << "Block hash for height " << context.height << " does not exist!");
          continue;
        }

        //
        // NOTE: Get the round start time
        //
#if 0
        uint64_t base_height = std::max(hf16_height, state.last_miner_block.load());
#else
        uint64_t base_height = std::max(hf16_height, context.height - 1); // (DEBUG): Make next block timestamps relative to previous block.
#endif
        if (!base_block_initialized || (cryptonote::get_block_height(base_pulse_block) != base_height))
        {
          std::vector<std::pair<cryptonote::blobdata, cryptonote::block>> block;
          if (!blockchain.get_blocks(base_height, 1, block))
          {
            MERROR(log_prefix(context) << " Could not query block " << base_height << " from the DB, unable to continue with Pulse");
            continue;
          }

          base_block_initialized = true;
          base_pulse_block       = std::move(block[0].second);
        }

        auto base_timestamp   = pulse::time_point(std::chrono::seconds(base_pulse_block.timestamp));
        uint64_t delta_height = context.height - cryptonote::get_block_height(base_pulse_block);
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
          auto const time_since_block   = now - context.wait_next_block.round_0_start_time;
          size_t pulse_round_usize      = time_since_block / service_nodes::PULSE_TIME_PER_BLOCK;
          context.wait_next_block.round = static_cast<uint8_t>(pulse_round_usize);
        }

        round_state = round_state::wait_for_round;
      }
      break;

      case round_state::wait_for_round:
      {
        context.wait_for_round = {};

        //
        // NOTE: Timings
        //
        pulse::time_point const start_time = context.wait_next_block.round_0_start_time +
                                             (context.wait_next_block.round * service_nodes::PULSE_TIME_PER_BLOCK);
        context.wait_for_handshakes.end_time        = start_time                                  + service_nodes::PULSE_WAIT_FOR_HANDSHAKES_DURATION;
        context.wait_for_handshake_bitsets.end_time = context.wait_for_handshakes.end_time        + service_nodes::PULSE_WAIT_FOR_OTHER_VALIDATOR_HANDSHAKES_DURATION;
        context.wait_for_block_template.end_time    = context.wait_for_handshake_bitsets.end_time + service_nodes::PULSE_WAIT_FOR_BLOCK_TEMPLATE_DURATION;

        //
        // NOTE: Quorum
        //
        context.wait_for_round.quorum =
            service_nodes::generate_pulse_quorum(blockchain.nettype(),
                                                 blockchain.get_db(),
                                                 context.height - 1,
                                                 blockchain.get_service_node_list().get_block_leader().key,
                                                 blockchain.get_current_hard_fork_version(),
                                                 blockchain.get_service_node_list().active_service_nodes_infos(),
                                                 context.wait_next_block.round);

        if (service_nodes::verify_pulse_quorum_sizes(context.wait_for_round.quorum))
        {
          round_state = thread_sleep(sleep_until::round_starts, state, blockchain, context, pulse_mutex);
        }
        else
        {
          MINFO(log_prefix(context) << "Insufficient Service Nodes to execute Pulse on height " << context.height << ", we require a PoW miner block. Sleeping until next block.");
          round_state = thread_sleep(sleep_until::next_block, state, blockchain, context, pulse_mutex);
        }
      }
      break;

      case round_state::round_starts:
      {
        context.round_starts = {};

        //
        // NOTE: Quorum participation
        //
        bool validator = false;
        if (key.pub == context.wait_for_round.quorum.workers[0])
        {
          // NOTE: Producer doesn't send handshakes, they only collect the
          // handshake bitsets from the other validators to determine who to
          // lock in for this round in the block template.
          context.round_starts.is_producer = true;
        }
        else
        {
          for (size_t index = 0; index < context.wait_for_round.quorum.validators.size(); index++)
          {
            auto const &validator_key = context.wait_for_round.quorum.validators[index];
            validator                 = (validator_key == key.pub);
            if (validator)
            {
              context.round_starts.my_quorum_position = index;
              break;
            }
          }
        }

        if (validator || context.round_starts.is_producer)
        {
          if (validator)
          {
            context.round_starts.node_name = "V[" + std::to_string(context.round_starts.my_quorum_position) + "]";
            try
            {
              context.wait_for_handshakes.validator_bits |= (1 << context.round_starts.my_quorum_position); // Add myself

              MINFO(log_prefix(context) << "We are a pulse validator, sending handshake bit to quorum and collecting other validator handshakes.");
              cryptonote::quorumnet_send_pulse_validator_handshake_bit(quorumnet_state, context.wait_for_round.quorum, top_hash);
              round_state = round_state::wait_for_handshakes;
            }
            catch (std::exception const &e)
            {
              MERROR(log_prefix(context) << "Attempting to invoke and send a Pulse participation handshake unexpectedly failed. " << e.what());
              round_state = thread_sleep(sleep_until::next_block_or_round, state, blockchain, context, pulse_mutex);
            }
          }
          else
          {
            context.round_starts.node_name = "W[0]";
            MINFO(log_prefix(context) << "We are the block producer for height " << context.height << " in round " << +context.wait_next_block.round << ", awaiting validator handshake bitsets.");
            round_state = round_state::wait_for_handshake_bitsets;
          }
        }
        else
        {
          MINFO(log_prefix(context) << "We are not a pulse validator. Waiting for next pulse round or block.");
          round_state = thread_sleep(sleep_until::next_block_or_round, state, blockchain, context, pulse_mutex);
        }

      }
      break;

      case round_state::wait_for_handshakes:
      {
        assert(!context.round_starts.is_producer);
        assert(context.round_starts.my_quorum_position < context.wait_for_handshake_bitsets.bitsets.size());

        bool timed_out      = pulse::clock::now() >= context.wait_for_handshakes.end_time;
        bool all_handshakes = context.wait_for_handshakes.all_received();

        if (all_handshakes || timed_out)
        {
          assert(context.round_starts.my_quorum_position < context.wait_for_handshake_bitsets.bitsets.size());
          std::bitset<8 * sizeof(context.wait_for_handshakes.validator_bits)> bitset = context.wait_for_handshakes.validator_bits;

          context.wait_for_handshake_bitsets.bitsets[context.round_starts.my_quorum_position] = context.wait_for_handshakes.validator_bits;
          context.wait_for_handshake_bitsets.bitsets_count++;

          bool missing_handshakes = timed_out && !all_handshakes;
          MINFO(log_prefix(context) << "Collected validator handshakes " << bitset << (missing_handshakes ? ", we timed out and some handshakes were not seen! " : ". ") << "Sending handshake bitset and collecting other validator bitsets.");
          try
          {
            cryptonote::quorumnet_send_pulse_validator_handshake_bitset(quorumnet_state, context.wait_for_round.quorum, top_hash, context.wait_for_handshakes.validator_bits);
            round_state = round_state::wait_for_handshake_bitsets;
          }
          catch(std::exception const &e)
          {
            MERROR(log_prefix(context) << "Attempting to invoke and send a Pulse validator bitset unexpectedly failed. " << e.what());
            round_state = thread_sleep(sleep_until::next_block_or_round, state, blockchain, context, pulse_mutex);
          }
        }
      }
      break;

      case round_state::wait_for_handshake_bitsets:
      {
        size_t const max_bitsets   = context.wait_for_handshake_bitsets.bitsets.size();
        size_t const bitsets_count = context.wait_for_handshake_bitsets.bitsets_count;

        bool all_bitsets = context.wait_for_handshake_bitsets.all_received();
        bool timed_out   = pulse::clock::now() >= context.wait_for_handshake_bitsets.end_time;
        if (timed_out || all_bitsets)
        {
          bool missing_bitsets = timed_out && !all_bitsets;
          MINFO(log_prefix(context)
                 << "Collected " << bitsets_count << "/" << max_bitsets << " handshake bitsets"
                 << (missing_bitsets ? ", we timed out and some bitsets were not seen!" : ""));

          std::map<uint16_t, int> most_common_validator_bitset;
          uint16_t most_common_bitset = 0;
          int count                   = 0;
          for (size_t validator_index = 0; validator_index < max_bitsets; validator_index++)
          {
            uint16_t bits = context.wait_for_handshake_bitsets.bitsets[validator_index];
            uint16_t num = ++most_common_validator_bitset[bits];
            if (num > count)
            {
              most_common_bitset = bits;
              count              = num;
            }

            MINFO(log_prefix(context) << "Collected from V[" << validator_index << "], handshake bitset " << std::bitset<8 * sizeof(bits)>(bits));
          }

          int count_threshold = (service_nodes::PULSE_QUORUM_NUM_VALIDATORS * 6 / 10);
          if (count < count_threshold || most_common_bitset == 0)
          {
            // Less than 60% of the validators can't come to agreement
            // about which validators are online, we wait until the
            // next round.
            if (most_common_bitset == 0)
            {
              MINFO(log_prefix(context) << count << "/" << max_bitsets << " validators did not send any handshake bitset or sent an empty handshake bitset");
            }
            else
            {
              MINFO(log_prefix(context)
                     << "We heard back from less than " << count_threshold << " of the validators (" << count << "/"
                     << max_bitsets << ", waiting for next round.");
            }

            round_state = thread_sleep(sleep_until::next_block_or_round, state, blockchain, context, pulse_mutex);
          }
          else
          {
            std::bitset<8 * sizeof(most_common_bitset)> bitset = most_common_bitset;
            MINFO(log_prefix(context) << count << "/" << max_bitsets << " validators agreed on the participating nodes in the quorum " << bitset << (context.round_starts.is_producer ? "" : ". Awaiting block template from block producer"));
            context.submit_block_template.validator_bitset = most_common_bitset;

            if (context.round_starts.is_producer)
              round_state = round_state::submit_block_template;
            else
              round_state = round_state::wait_for_block_template;
          }
        }
      }
      break;

      case round_state::submit_block_template:
      {
        assert(context.round_starts.is_producer);
        std::vector<service_nodes::service_node_pubkey_info> list_state = blockchain.get_service_node_list().get_service_node_list_state({key.pub});

        if (list_state.empty())
        {
          MINFO(log_prefix(context) << "Block producer (us) is not available on the service node list, waiting until next round");
          round_state = round_state::wait_next_block;
          break;
        }

        // TODO(doyle): These checks can be done earlier?
        std::shared_ptr<const service_nodes::service_node_info> info = list_state[0].info;
        if (!info->is_active())
        {
          MINFO(log_prefix(context) << "Block producer (us) is not an active service node, waiting until next round");
          round_state = thread_sleep(sleep_until::next_block_or_round, state, blockchain, context, pulse_mutex);
          break;
        }

        MINFO(log_prefix(context) << "Validators are handshaken and ready, sending block template from producer (us) to validators.\n");
        service_nodes::payout block_producer_payouts = service_nodes::service_node_info_to_payout(key.pub, *info);

        cryptonote::block block = {};
        uint64_t expected_reward = 0;
        blockchain.create_next_pulse_block_template(block, block_producer_payouts, context.height, expected_reward);

        block.pulse.round            = context.wait_next_block.round;
        block.pulse.validator_bitset = context.submit_block_template.validator_bitset;

        std::string block_blob = cryptonote::t_serializable_object_to_blob(block);
        crypto::hash hash      = crypto::cn_fast_hash(block_blob.data(), block_blob.size());

        crypto::signature block_signature = {};
        crypto::generate_signature(hash, core.get_service_keys().pub, core.get_service_keys().key, block_signature);

        cryptonote::quorumnet_send_pulse_block_template(quorumnet_state, std::move(block_blob), block_signature, context.wait_for_round.quorum);
        round_state = thread_sleep(sleep_until::next_block, state, blockchain, context, pulse_mutex);
      }
      break;

      case round_state::wait_for_block_template:
      {
        assert(!context.round_starts.is_producer);
        bool timed_out = pulse::clock::now() >= context.wait_for_block_template.end_time;
        if (timed_out || context.wait_for_block_template.received)
        {
          if (context.wait_for_block_template.received)
            MINFO(log_prefix(context) << "Valid block received: " << cryptonote::obj_to_json_str(context.wait_for_block_template.block));
          else
            MINFO(log_prefix(context) << "Block template not received");

          round_state = thread_sleep(sleep_until::next_block, state, blockchain, context, pulse_mutex);
        }
      }
      break;
    }

    pump_messages_from_quorumnet(quorumnet_state, round_state, context, top_hash);
  }
}
