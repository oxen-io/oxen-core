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
  wait_for_next_block,

  prepare_for_round,
  wait_for_round,

  submit_handshakes,
  wait_for_handshakes_then_submit_bitset,

  wait_for_handshake_bitsets,
  submit_block_template,

  wait_for_block_template,
};

constexpr std::string_view round_state_string(round_state state)
{
  switch(state)
  {
    case round_state::wait_for_next_block: return "Wait For Next Block"sv;

    case round_state::prepare_for_round: return "Prepare For Round"sv;
    case round_state::wait_for_round: return "Wait For Round"sv;

    case round_state::submit_handshakes: return "Submit Handshakes"sv;
    case round_state::wait_for_handshakes_then_submit_bitset: return "Wait For Handshakes Then Submit Bitset"sv;

    case round_state::wait_for_handshake_bitsets: return "Wait For Validator Handshake Bitsets"sv;
    case round_state::submit_block_template: return "Submit Block Template"sv;

    case round_state::wait_for_block_template: return "Wait For Block Template"sv;
  }

  return "Invalid2"sv;
}

enum struct sn_type
{
  none,
  producer,
  validator,
};

struct round_context
{
  struct
  {
    uint64_t          height;
    crypto::hash      top_hash;
    uint64_t          top_block_timestamp;
    pulse::time_point round_0_start_time;
  } wait_for_next_block;

  struct
  {
    bool                  queue_for_next_round;
    uint8_t               round;
    service_nodes::quorum quorum;
    sn_type               participant;
    size_t                my_quorum_position;
    std::string           node_name;
  } prepare_for_round;

  struct
  {
    uint16_t          validator_bits;
    pulse::time_point start_time;
    pulse::time_point end_time;
    bool all_received() { return validator_bits == service_nodes::pulse_validator_bit_mask(); }
  } wait_for_handshakes_then_submit_bitset;

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

  round_state state;
};

static round_context context;
namespace
{

std::string log_prefix(round_context const &context)
{
  std::stringstream result;
  result << "Pulse B" << context.wait_for_next_block.height << " R";
  if (context.state >= round_state::prepare_for_round)
    result << +context.prepare_for_round.round;
  else
    result << "0";
  result << ": ";

  if (context.prepare_for_round.node_name.size()) result << context.prepare_for_round.node_name << " ";
  return result.str();
}

bool msg_time_check(round_context const &context, pulse::message const &msg, pulse::time_point now, pulse::time_point start, pulse::time_point end)
{
  if (now < start || now >= end)
  {
    std::stringstream stream;
    stream << log_prefix(context) << "Dropping " << pulse::message_type_string(msg.type) << " message from validator " << msg.quorum_position << ", message arrived ";

    if (now < start)
      stream << tools::get_human_readable_timespan(context.wait_for_handshakes_then_submit_bitset.end_time - now) << " early";
    else
      stream << tools::get_human_readable_timespan(now - context.wait_for_handshakes_then_submit_bitset.end_time) << " late";

    MINFO(stream.str());
    return false;
  }

  return true;
}

bool message_signature_check(pulse::message const &msg, service_nodes::quorum const &quorum)
{
  // Generate hash that was signed to a signature
  crypto::public_key const *key = nullptr;
  crypto::hash hash             = {};

  switch (msg.type)
  {
    case pulse::message_type::invalid:
    {
      assert("Invalid Code Path" == nullptr);
      MERROR(log_prefix(context) << "Unhandled message type '" << pulse::message_type_string(msg.type) << "' can not verify signature.");
      return false;
    }
    break;

    case pulse::message_type::handshake: /* FALLTHRU */
    case pulse::message_type::handshake_bitset:
    {
      if (msg.quorum_position >= static_cast<int>(quorum.validators.size()))
      {
        MERROR(log_prefix(context) << "Quorum position " << msg.quorum_position << " in Pulse message indexes oob");
        return false;
      }

      key = &quorum.validators[msg.quorum_position];
      if (msg.type == pulse::message_type::handshake)
      {
        auto buf = tools::memcpy_le(context.wait_for_next_block.top_hash.data, msg.quorum_position);
        hash     = crypto::cn_fast_hash(buf.data(), buf.size());
      }
      else
      {
        auto buf = tools::memcpy_le(msg.handshakes.validator_bitset, context.wait_for_next_block.top_hash.data, msg.quorum_position);
        hash     = crypto::cn_fast_hash(buf.data(), buf.size());
      }
    }
    break;

    case pulse::message_type::block_template:
    {
      if (msg.quorum_position != 0)
      {
        MERROR(log_prefix(context) << "Quorum position " << msg.quorum_position << " in Pulse message indexes oob");
        return false;
      }

      key  = &context.prepare_for_round.quorum.workers[0];
      hash = crypto::cn_fast_hash(msg.block_template.blob.data(), msg.block_template.blob.size());
    }
    break;
  }

  // Verify hash with signature
  if (!crypto::check_signature(hash, *key, msg.signature))
  {
    MERROR(log_prefix(context) << "Signature from pulse handshake bit does not validate with node " << msg.quorum_position << ":" << lokimq::to_hex(tools::view_guts(*key)) << ", at height " << context.wait_for_next_block.height << "; Node signing outdated height or bad handshake data");
    return false;
  }

  return true;
}

} // anonymous namespace

void pulse::handle_message(void *quorumnet_state, pulse::message const &msg)
{
  if (!message_signature_check(msg, context.prepare_for_round.quorum))
    return;

  bool relay_message = false;
  switch(msg.type)
  {
    case pulse::message_type::invalid:
      assert("Invalid Code Path" != nullptr);
      break;

    case pulse::message_type::handshake:
    {
      // TODO(doyle): We need some lenience in time for accepting early
      // handshakes in case clocks are slightly out of sync.
      if (!msg_time_check(context, msg, pulse::clock::now(), context.wait_for_handshakes_then_submit_bitset.start_time, context.wait_for_handshakes_then_submit_bitset.end_time))
        return;

      uint16_t quorum_position_bit = 1 << msg.quorum_position;
      relay_message = ((context.wait_for_handshakes_then_submit_bitset.validator_bits & quorum_position_bit) == 0);
      context.wait_for_handshakes_then_submit_bitset.validator_bits |= quorum_position_bit;

      if (relay_message) // First time seen handshake
      {
        auto position_bitset  = std::bitset<sizeof(quorum_position_bit) * 8>(quorum_position_bit);
        auto validator_bitset = std::bitset<sizeof(quorum_position_bit) * 8>(context.wait_for_handshakes_then_submit_bitset.validator_bits);
        MINFO(log_prefix(context) << "Received handshake with quorum position bit (" << msg.quorum_position <<") " << position_bitset << " saved to bitset " << validator_bitset);
      }
    }
    break;

    case pulse::message_type::handshake_bitset:
    {
      if (!msg_time_check(context, msg, pulse::clock::now(), context.wait_for_handshakes_then_submit_bitset.start_time, context.wait_for_handshake_bitsets.end_time))
        return;

      uint16_t prev_bitset = context.wait_for_handshake_bitsets.bitsets[msg.quorum_position];
      if (context.prepare_for_round.participant == sn_type::validator)
        relay_message = (prev_bitset != msg.handshakes.validator_bitset);

      context.wait_for_handshake_bitsets.bitsets[msg.quorum_position] = msg.handshakes.validator_bitset;
      if (prev_bitset == 0)
        context.wait_for_handshake_bitsets.bitsets_count++;
    }
    break;

    case pulse::message_type::block_template:
    {
      assert(context.prepare_for_round.participant == sn_type::validator);
      if (context.wait_for_block_template.received)
        return;

      if (!msg_time_check(context, msg, pulse::clock::now(), context.wait_for_handshakes_then_submit_bitset.start_time, context.wait_for_block_template.end_time))
        return;

      cryptonote::block block = {};
      if (!cryptonote::t_serializable_object_from_blob(block, msg.block_template.blob))
      {
        MINFO(log_prefix(context) << "Received unparsable pulse block template blob");
        return;
      }

      if (block.pulse.round != context.prepare_for_round.round)
      {
        MINFO(log_prefix(context) << "Received pulse block template specifying different round " << +block.pulse.round << ", expected " << +context.prepare_for_round.round);
        return;
      }

      context.wait_for_block_template.received = true;
      context.wait_for_block_template.block    = std::move(block);
      relay_message                            = true;

    }
    break;
  }

  if (relay_message)
    cryptonote::quorumnet_pulse_relay_message_to_quorum(quorumnet_state, msg, context.prepare_for_round.quorum, context.prepare_for_round.participant == sn_type::producer);
}

/*
  Pulse progresses via a state-machine that is iterated through job submissions
  to 1 dedicated Pulse thread, started by LMQ.

  Iterating the state-machine is done by a periodic invocation of
  pulse::main(...) and messages received via Quorumnet for Pulse, which are
  queued in the thread's job queue.

  Using 1 dedicated thread via LMQ avoids any synchronization required in the
  user code when implementing Pulse.

  Skip control flow graph for textual description of stages.

          +---------------------+
          | Wait For Next Block |<--------+-------+
          +---------------------+         |       |
           |                              |       |
           +-[Blocks for round acquired]--+ No    |
           |                              |       |
           | Yes                          |       |
           |                              |       |
          +---------------------+         |       |
    +---->| Prepare For Round   |         |       |
    |     +---------------------+         |       |
    |      |                              |       |
    |     [Enough SN's for Pulse]---------+ No    |
    |      |                                      |
    |     Yes                                     |
    |      |                                      |
 No +-----[Participating in Quorum?]              |
    |      |                                      |
    |      | Yes                                  |
    |      |                                      |
    |     +---------------------+                 |
    |     | Wait For Round      |                 |
    |     +---------------------+                 |
    |      |                                      |
    |     [Block Height Changed?]-----------------+ Yes
    |      |
    |      | No
    |      |
    |     [Validator?]------------------+ No (We are Block Producer)
    |      |                            |
    |      | Yes                        |
    |      |                            |
    |     +---------------------+       |
    |     | Submit Handshakes   |       |
    |     +---------------------+       |
    |      |                            +-----------------+
Yes +-----[Quorumnet Comm Failure]                        |
    |      |                                              |
    |      | Yes                                          |
    |      |                                              |
    |     +----------------------------------------+      |
    |     | Wait For Handshakes Then Submit Bitset |      |
    |     +----------------------------------------+      |
    |      |                                              |
Yes +-----[Quorumnet Comm Failure]                        |
    |      |                                              |
    |      | No                                           |
    |      |                                              |
    |     +----------------------------+                  |
    |     | Wait For Handshake Bitsets |<-----------------+
    |     +----------------------------+
    |      |
Yes +-----[Insufficient Bitsets]
    |      |
    |      | No
    |      |
    |     +-----------------------+
    |     | Submit Block Template |
    |     +-----------------------+
    |      |
 No +-----[Block Producer Passes SN List Checks]
           |
           | Yes
           |
          +-------------------------+
          | Wait For Block Template |
          +-------------------------+
           |
           | TODO(loki): TBD
           |
           V

  Wait For Next Block:
    - Checks for the next block in the blockchain to arrive. If it hasn't
      arrived yet, return to the caller.

    - Retrieves the blockchain metadata for starting a Pulse Round including the
      Genesis Pulse Block for the base timestamp and the top block hash and
      height for signatures.

    - // TODO(loki): After the Genesis Pulse Block is checkpointed, we can
      // remove it from the event loop. Right now we recheck every block incase
      // of (the very unlikely event) reorgs that might change the block at the
      // hardfork.

    - The next block timestamp is determined by

      G.Timestamp + (height * TARGET_BLOCK_TIME)

      Where 'G' is the base Pulse genesis block, i.e. the hardforking block
      activating Pulse (HF16).

      In case of the Service Node network failing, i.e. (pulse round > 255) or
      insufficient Service Nodes for Pulse, mining is re-activated and accepted
      as the next block in the blockchain.

      // TODO(loki): Activating mining on (Pulse Round > 255) needs to be
      // implemented.

  Prepare For Round:
    - Generate data for executing the round such as the Quorum and stage
      durations depending on the round Pulse is at by comparing the clock with
      the ideal block timestamp.

    - The state machine *always* reverts to 'Prepare For Round' when any
      subsequent stage fails, except in the cases where Pulse can not proceed
      because of an insufficient Service Node network.

  Wait For Round:
    - Checks clock against the next expected Pulse timestamps has elapsed,
      otherwise returns to caller.

    - If we are a validator we 'Submit Handshakes' with other Validators
      If we are a block producer we skip to 'Wait For Handshake Bitset' and
      await the final handshake bitsets from all the Validators

  Submit Handshakes:
    - Block Validators handshake to confirm participation in the round and collect other handshakes.

  Wait For Handshakes Then Submit Bitset:
    - Validators will each individually collect handshakes and build up a
      bitset of validators perceived to be participating.

    - When all handshakes are received we submit our bitset and progress to
      'Wait For Handshake Bitsets'

  Wait For Handshake Bitset:
    - Validators will each individually collect the handshake bitsets similar
      to Wait For Handshakes.

    - Upon receipt, the most common agreed upon bitset is used to lock in
      participation for the round. The round proceeds if more than 60% of the
      validators are participating, the round fails otherwise and reverts to
      'Prepare For Round'.

    - If we are a validator we go to 'Wait For Block Template'
    - If we are a block producer we go to 'Submit Block Template'

  Submit Block Template:
    - Block producer signs the block template with the validator bitset and
      pulse round applied to the block and submits it the Validators

  Wait For Block Template:
    - TODO(loki): TBD

*/

enum struct event_loop
{
  keep_running,
  return_to_caller,
};

event_loop wait_for_next_block(uint64_t hf16_height, round_context &context, cryptonote::Blockchain const &blockchain)
{
  //
  // NOTE: If already processing pulse for height, wait for next height
  //
  uint64_t curr_height = blockchain.get_current_blockchain_height(true /*lock*/);
  if (context.wait_for_next_block.height == curr_height)
  {
    for (static uint64_t last_height = 0; last_height != curr_height; last_height = curr_height)
      MINFO(log_prefix(context) << "Network is currently producing block " << curr_height << ", waiting until next block");
    return event_loop::return_to_caller;
  }

  uint64_t top_height   = curr_height - 1;
  crypto::hash top_hash = blockchain.get_block_id_by_height(top_height);
  if (top_hash == crypto::null_hash)
  {
    for (static uint64_t last_height = 0; last_height != top_height; last_height = top_height)
      MERROR(log_prefix(context) << "Block hash for height " << top_height << " does not exist!");
    return event_loop::return_to_caller;
  }

  cryptonote::block top_block = {};
  if (bool orphan = false;
      !blockchain.get_block_by_hash(top_hash, top_block, &orphan) || orphan)
  {
    for (static uint64_t last_height = 0; last_height != top_height; last_height = top_height)
      MERROR(log_prefix(context) << "Failed to query previous block in blockchain at height " << top_height);
    return event_loop::return_to_caller;
  }

  //
  // NOTE: Query Pulse Genesis
  // TODO(loki): After HF16 genesis block is checkpointed, move this out of the loop/hardcode this as it can't change.
  //
  crypto::hash genesis_hash       = blockchain.get_block_id_by_height(hf16_height - 1);
  cryptonote::block genesis_block = {};
  if (bool orphaned = false; !blockchain.get_block_by_hash(genesis_hash, genesis_block, &orphaned) || orphaned)
  {
    for (static bool once = true; once; once = !once)
      MINFO(log_prefix(context) << "Failed to query the genesis block for Pulse at height " << hf16_height - 1);
    return event_loop::return_to_caller;
  }

  //
  // NOTE: Block Timing
  //
  uint64_t const delta_height = context.wait_for_next_block.height - cryptonote::get_block_height(genesis_block);
#if 0
  auto genesis_timestamp      = pulse::time_point(std::chrono::seconds(genesis_block.timestamp));
  pulse::time_point ideal_timestamp = genesis_timestamp + (TARGET_BLOCK_TIME * delta_height);
  pulse::time_point prev_timestamp  = pulse::time_point(std::chrono::seconds(top_block.timestamp));
  context.wait_for_next_block.round_0_start_time =
      std::clamp(ideal_timestamp,
                 prev_timestamp + service_nodes::PULSE_MIN_TARGET_BLOCK_TIME,
                 prev_timestamp + service_nodes::PULSE_MAX_TARGET_BLOCK_TIME);
#else // NOTE: Debug, make next block start relatively soon
  pulse::time_point prev_timestamp               = pulse::time_point(std::chrono::seconds(top_block.timestamp));
  context.wait_for_next_block.round_0_start_time = prev_timestamp + service_nodes::PULSE_ROUND_TIME;
#endif

  context.wait_for_next_block.height              = curr_height;
  context.wait_for_next_block.top_hash            = top_hash;
  context.wait_for_next_block.top_block_timestamp = top_block.timestamp;

  context.state             = round_state::prepare_for_round;
  context.prepare_for_round = {};

  return event_loop::keep_running;
}

event_loop prepare_for_round(round_context &context, service_nodes::service_node_keys const &key, cryptonote::Blockchain const &blockchain)
{
  context.wait_for_handshakes_then_submit_bitset        = {};
  context.wait_for_handshake_bitsets = {};
  context.submit_block_template      = {};
  context.wait_for_block_template    = {};

  if (context.prepare_for_round.queue_for_next_round)
  {
    // Set when an intermediate Pulse stage has failed and we wait on the
    // next round to occur.
    context.prepare_for_round.queue_for_next_round = false;
    context.prepare_for_round.round++; //TODO: Overflow check

    // Also check if the blockchain has changed, in which case we stop and
    // restart Pulse stages.
    if (context.wait_for_next_block.height != blockchain.get_current_blockchain_height(true /*lock*/))
      context.state = round_state::wait_for_next_block;
  }

  //
  // NOTE: Check Current Round
  //
  {
    auto now                     = pulse::clock::now();
    auto const time_since_block  = now <= context.wait_for_next_block.round_0_start_time ? std::chrono::seconds(0) : (now - context.wait_for_next_block.round_0_start_time);
    size_t round_usize           = time_since_block / service_nodes::PULSE_ROUND_TIME;
    uint8_t curr_round           = static_cast<uint8_t>(round_usize); // TODO: Overflow check

    if (curr_round > context.prepare_for_round.round)
      context.prepare_for_round.round = curr_round;
  }

  auto start_time = context.wait_for_next_block.round_0_start_time + (context.prepare_for_round.round * service_nodes::PULSE_ROUND_TIME);
  context.wait_for_handshakes_then_submit_bitset.start_time      = start_time;
  context.wait_for_handshakes_then_submit_bitset.end_time        = start_time                                  + service_nodes::PULSE_WAIT_FOR_HANDSHAKES_DURATION;
  context.wait_for_handshake_bitsets.end_time = context.wait_for_handshakes_then_submit_bitset.end_time        + service_nodes::PULSE_WAIT_FOR_OTHER_VALIDATOR_HANDSHAKES_DURATION;
  context.wait_for_block_template.end_time    = context.wait_for_handshake_bitsets.end_time + service_nodes::PULSE_WAIT_FOR_BLOCK_TEMPLATE_DURATION;

  context.prepare_for_round.quorum =
      service_nodes::generate_pulse_quorum(blockchain.nettype(),
                                           blockchain.get_db(),
                                           context.wait_for_next_block.height - 1,
                                           blockchain.get_service_node_list().get_block_leader().key,
                                           blockchain.get_current_hard_fork_version(),
                                           blockchain.get_service_node_list().active_service_nodes_infos(),
                                           context.prepare_for_round.round);

  if (!service_nodes::verify_pulse_quorum_sizes(context.prepare_for_round.quorum))
  {
    MINFO(log_prefix(context) << "Insufficient Service Nodes to execute Pulse on height " << context.wait_for_next_block.height << ", we require a PoW miner block. Sleeping until next block.");
    context.state = round_state::wait_for_next_block;
    return event_loop::keep_running;
  }

  //
  // NOTE: Quorum participation
  //
  if (key.pub == context.prepare_for_round.quorum.workers[0])
  {
    // NOTE: Producer doesn't send handshakes, they only collect the
    // handshake bitsets from the other validators to determine who to
    // lock in for this round in the block template.
    context.prepare_for_round.participant = sn_type::producer;
    context.prepare_for_round.node_name   = "W[0]";
  }
  else
  {
    for (size_t index = 0; index < context.prepare_for_round.quorum.validators.size(); index++)
    {
      auto const &validator_key = context.prepare_for_round.quorum.validators[index];
      if (validator_key == key.pub)
      {
        context.prepare_for_round.participant        = sn_type::validator;
        context.prepare_for_round.my_quorum_position = index;
        context.prepare_for_round.node_name = "V[" + std::to_string(context.prepare_for_round.my_quorum_position) + "]";
        break;
      }
    }
  }

  if (context.prepare_for_round.participant == sn_type::none)
  {
    MINFO(log_prefix(context) << "We are not a pulse validator. Waiting for next pulse round or block.");
    context.state                                  = round_state::prepare_for_round;
    context.prepare_for_round.queue_for_next_round = true;
  }
  else
  {
    context.state = round_state::wait_for_round;
  }

  return event_loop::keep_running;
}

event_loop wait_for_round(round_context &context, cryptonote::Blockchain const &blockchain)
{
  if (context.wait_for_next_block.height != blockchain.get_current_blockchain_height(true /*lock*/))
  {
    MINFO(log_prefix(context) << "Block height changed whilst waiting for round " << +context.prepare_for_round.round << ", restarting Pulse stages");
    context.state = round_state::wait_for_next_block;
    return event_loop::keep_running;
  }

  auto start_time = context.wait_for_next_block.round_0_start_time + (context.prepare_for_round.round * service_nodes::PULSE_ROUND_TIME);
  if (auto now = pulse::clock::now(); now < start_time)
  {
    for (static uint64_t last_height = 0; last_height != context.wait_for_next_block.height; last_height = context.wait_for_next_block.height)
      MINFO(log_prefix(context) << "Waiting for Pulse round " << +context.prepare_for_round.round << " to start in " << tools::get_human_readable_timespan(start_time - now));
    return event_loop::return_to_caller;
  }

  if (context.prepare_for_round.participant == sn_type::validator)
  {
    MINFO(log_prefix(context) << "We are a pulse validator, sending handshake bit to quorum and collecting other validator handshakes.");
    context.state = round_state::submit_handshakes;
  }
  else
  {
    MINFO(log_prefix(context) << "We are the block producer for height " << context.wait_for_next_block.height << " in round " << +context.prepare_for_round.round << ", awaiting validator handshake bitsets.");
    context.state = round_state::wait_for_handshake_bitsets;
  }

  return event_loop::keep_running;
}

event_loop submit_handshakes(round_context &context, void *quorumnet_state)
{
  assert(context.prepare_for_round.participant == sn_type::validator);
  try
  {
    context.wait_for_handshakes_then_submit_bitset.validator_bits |= (1 << context.prepare_for_round.my_quorum_position); // Add myself
    cryptonote::quorumnet_send_pulse_validator_handshake_bit(quorumnet_state, context.prepare_for_round.quorum, context.wait_for_next_block.top_hash);
    context.state = round_state::wait_for_handshakes_then_submit_bitset;
  }
  catch (std::exception const &e)
  {
    MERROR(log_prefix(context) << "Attempting to invoke and send a Pulse participation handshake unexpectedly failed. " << e.what());
    context.state                                  = round_state::prepare_for_round;
    context.prepare_for_round.queue_for_next_round = true;
  }

  return event_loop::return_to_caller;
}

event_loop wait_for_handshakes_then_submit_bitset(round_context &context, void *quorumnet_state)
{
  assert(context.prepare_for_round.participant == sn_type::validator);
  assert(context.prepare_for_round.my_quorum_position < context.wait_for_handshake_bitsets.bitsets.size());

  bool timed_out      = pulse::clock::now() >= context.wait_for_handshakes_then_submit_bitset.end_time;
  bool all_handshakes = context.wait_for_handshakes_then_submit_bitset.all_received();

  if (all_handshakes || timed_out)
  {
    assert(context.prepare_for_round.my_quorum_position < context.wait_for_handshake_bitsets.bitsets.size());
    std::bitset<8 * sizeof(context.wait_for_handshakes_then_submit_bitset.validator_bits)> bitset = context.wait_for_handshakes_then_submit_bitset.validator_bits;

    context.wait_for_handshake_bitsets.bitsets[context.prepare_for_round.my_quorum_position] = context.wait_for_handshakes_then_submit_bitset.validator_bits;
    context.wait_for_handshake_bitsets.bitsets_count++;

    bool missing_handshakes = timed_out && !all_handshakes;
    MINFO(log_prefix(context) << "Collected validator handshakes " << bitset << (missing_handshakes ? ", we timed out and some handshakes were not seen! " : ". ") << "Sending handshake bitset and collecting other validator bitsets.");
    try
    {
      cryptonote::quorumnet_send_pulse_validator_handshake_bitset(quorumnet_state, context.prepare_for_round.quorum, context.wait_for_next_block.top_hash, context.wait_for_handshakes_then_submit_bitset.validator_bits);
      context.state = round_state::wait_for_handshake_bitsets;
    }
    catch(std::exception const &e)
    {
      MERROR(log_prefix(context) << "Attempting to invoke and send a Pulse validator bitset unexpectedly failed. " << e.what());
      context.state                                  = round_state::prepare_for_round;
      context.prepare_for_round.queue_for_next_round = true;
      return event_loop::keep_running;
    }

    return event_loop::keep_running;
  }

  return event_loop::return_to_caller;
}

event_loop wait_for_handshake_bitsets(round_context &context)
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

      context.state                                  = round_state::prepare_for_round;
      context.prepare_for_round.queue_for_next_round = true;
    }
    else
    {
      std::bitset<8 * sizeof(most_common_bitset)> bitset = most_common_bitset;
      context.submit_block_template.validator_bitset = most_common_bitset;

      MINFO(log_prefix(context) << count << "/" << max_bitsets << " validators agreed on the participating nodes in the quorum " << bitset << (context.prepare_for_round.participant == sn_type::producer ? "" : ". Awaiting block template from block producer"));

      if (context.prepare_for_round.participant == sn_type::producer)
        context.state = round_state::submit_block_template;
      else
        context.state = round_state::wait_for_block_template;
    }

    return event_loop::keep_running;
  }

  return event_loop::return_to_caller;
}

event_loop submit_block_template(round_context &context, service_nodes::service_node_keys const &key, cryptonote::Blockchain &blockchain, void *quorumnet_state)
{
  assert(context.prepare_for_round.participant == sn_type::producer);
  std::vector<service_nodes::service_node_pubkey_info> list_state = blockchain.get_service_node_list().get_service_node_list_state({key.pub});

  if (list_state.empty())
  {
    MINFO(log_prefix(context) << "Block producer (us) is not available on the service node list, waiting until next round");
    context.state                                  = round_state::prepare_for_round;
    context.prepare_for_round.queue_for_next_round = true;
    return event_loop::keep_running;
  }

  // TODO(doyle): These checks can be done earlier?
  std::shared_ptr<const service_nodes::service_node_info> info = list_state[0].info;
  if (!info->is_active())
  {
    MINFO(log_prefix(context) << "Block producer (us) is not an active service node, waiting until next round");
    context.state                                  = round_state::prepare_for_round;
    context.prepare_for_round.queue_for_next_round = true;
    return event_loop::keep_running;
  }

  service_nodes::payout block_producer_payouts = service_nodes::service_node_info_to_payout(key.pub, *info);

  cryptonote::block block = {};
  uint64_t expected_reward = 0;
  blockchain.create_next_pulse_block_template(block, block_producer_payouts, context.wait_for_next_block.height, expected_reward);

  block.pulse.round            = context.prepare_for_round.round;
  block.pulse.validator_bitset = context.submit_block_template.validator_bitset;

  std::string block_blob = cryptonote::t_serializable_object_to_blob(block);
  crypto::hash hash      = crypto::cn_fast_hash(block_blob.data(), block_blob.size());

  crypto::signature block_signature = {};
  crypto::generate_signature(hash, key.pub, key.key, block_signature);

  MINFO(log_prefix(context) << "Validators are handshaken and ready, sending block template from producer (us) to validators.\n" << cryptonote::obj_to_json_str(block));
  cryptonote::quorumnet_send_pulse_block_template(quorumnet_state, std::move(block_blob), block_signature, context.prepare_for_round.quorum);
  context.state = round_state::wait_for_next_block;

  return event_loop::keep_running;
}

event_loop wait_for_block_template(round_context &context)
{
  assert(context.prepare_for_round.participant == sn_type::validator);
  bool timed_out = pulse::clock::now() >= context.wait_for_block_template.end_time;
  if (timed_out || context.wait_for_block_template.received)
  {
    if (context.wait_for_block_template.received)
    {
      // Check validator bitset after message is received incase we're abit
      // behind and still waiting to receive the bitsets from other
      // validators.
      cryptonote::block const &block = context.wait_for_block_template.block;
      if (block.pulse.validator_bitset == context.submit_block_template.validator_bitset)
      {
        MINFO(log_prefix(context) << "Valid block received: " << cryptonote::obj_to_json_str(context.wait_for_block_template.block));
      }
      else
      {
        auto block_bitset = std::bitset<sizeof(block.pulse.validator_bitset) * 8>(block.pulse.validator_bitset);
        auto our_bitset   = std::bitset<sizeof(block.pulse.validator_bitset) * 8>(context.submit_block_template.validator_bitset);
        MINFO(log_prefix(context) << "Received pulse block template specifying different validator handshake bitsets " << block_bitset << ", expected " << our_bitset);
      }
    }
    else
    {
      MINFO(log_prefix(context) << "Timed out, block template was not received");
    }

    context.state = round_state::wait_for_next_block;
    return event_loop::keep_running;
  }

  return event_loop::return_to_caller;
}

void pulse::main(void *quorumnet_state, cryptonote::core &core)
{
  cryptonote::Blockchain &blockchain          = core.get_blockchain_storage();
  service_nodes::service_node_keys const &key = core.get_service_keys();
  std::mutex pulse_mutex;

  //
  // NOTE: Early exit if too early
  //
  static uint64_t const hf16_height = cryptonote::HardFork::get_hardcoded_hard_fork_height(blockchain.nettype(), cryptonote::network_version_16);
  if (hf16_height == cryptonote::HardFork::INVALID_HF_VERSION_HEIGHT)
  {
    for (static bool once = true; once; once = !once)
      MERROR("Pulse: HF16 is not defined, pulse worker waiting");
    return;
  }

  if (uint64_t height = blockchain.get_current_blockchain_height(true /*lock*/); height < hf16_height)
  {
    for (static bool once = true; once; once = !once)
      MINFO("Pulse: Network at block " << height << " is not ready for Pulse until block " << hf16_height << ", waiting");
    return;
  }

  for (auto loop = event_loop::keep_running; loop == event_loop::keep_running;)
  {
    switch (context.state)
    {
      case round_state::wait_for_next_block:
        loop = wait_for_next_block(hf16_height, context, blockchain);
        break;

      case round_state::prepare_for_round:
        loop = prepare_for_round(context, key, blockchain);
        break;

      case round_state::wait_for_round:
        loop = wait_for_round(context, blockchain);
        break;

      case round_state::submit_handshakes:
        loop = submit_handshakes(context, quorumnet_state);
        break;

      case round_state::wait_for_handshakes_then_submit_bitset:
        loop = wait_for_handshakes_then_submit_bitset(context, quorumnet_state);
        break;

      case round_state::wait_for_handshake_bitsets:
        loop = wait_for_handshake_bitsets(context);
        break;

      case round_state::submit_block_template:
        loop = submit_block_template(context, key, blockchain, quorumnet_state);
        break;

      case round_state::wait_for_block_template:
        loop = wait_for_block_template(context);
        break;
    }
  }
}

