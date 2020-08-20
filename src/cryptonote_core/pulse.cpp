#include <array>
#include <mutex>
#include <chrono>

#include "wipeable_string.h"
#include "memwipe.h"
#include "misc_log_ex.h"
#include "common/random.h"

#include "cryptonote_core.h"
#include "cryptonote_basic/hardfork.h"
#include "service_node_list.h"
#include "service_node_quorum_cop.h"
#include "service_node_rules.h"

extern "C"
{
#include <sodium/crypto_generichash.h>
};

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "pulse"

enum struct round_state
{
  null_state,
  wait_for_next_block,

  prepare_for_round,
  wait_for_round,

  send_and_wait_for_handshakes,

  send_handshake_bitsets,
  wait_for_handshake_bitsets,

  send_block_template,
  wait_for_block_template,

  send_and_wait_for_random_value_hashes,
  send_and_wait_for_random_value,
  send_and_wait_for_signed_blocks,
};

constexpr std::string_view round_state_string(round_state state)
{
  switch(state)
  {
    case round_state::null_state: return "XX Null State"sv;
    case round_state::wait_for_next_block: return "Wait For Next Block"sv;

    case round_state::prepare_for_round: return "Prepare For Round"sv;
    case round_state::wait_for_round: return "Wait For Round"sv;

    case round_state::send_and_wait_for_handshakes: return "Send & Wait For Handshakes"sv;

    case round_state::send_handshake_bitsets: return "Send Validator Handshake Bitsets"sv;
    case round_state::wait_for_handshake_bitsets: return "Wait For Validator Handshake Bitsets"sv;

    case round_state::send_block_template: return "Send Block Template"sv;
    case round_state::wait_for_block_template: return "Wait For Block Template"sv;

    case round_state::send_and_wait_for_random_value_hashes: return "Send & Wait For Random Value Hash"sv;
    case round_state::send_and_wait_for_random_value: return "Send & Wait For Random Value"sv;
    case round_state::send_and_wait_for_signed_blocks: return "Send & Wait For Signed Blocks"sv;
  }

  return "Invalid2"sv;
}

enum struct sn_type
{
  none,
  producer,
  validator,
};

enum struct queueing_state
{
  empty,
  received,
  processed,
};

template <typename T>
using quorum_array = std::array<T, service_nodes::PULSE_QUORUM_NUM_VALIDATORS>;

// Stores message for quorumnet per stage. Some validators may reach later
// stages before we arrive at that stage. To properly validate messages we also
// need to wait until we arrive at the same stage such that we have received all
// the necessary information to do so on Quorumnet.
struct message_queue
{
  quorum_array<std::pair<pulse::message, queueing_state>> buffer;
  size_t count;
};

struct pulse_wait_stage
{
  message_queue     queue;         // For messages from later stages that arrived before we reached that stage
  uint16_t          bitset;        // Bitset of validators that we received a message from for this stage
  uint16_t          msgs_received; // Number of unique messages received in the stage
  pulse::time_point end_time;      // Time at which the stage ends
};

template <typename T>
struct pulse_send_stage
{
  T    data; // Data that must be sent to Nodes via Quorumnet
  bool sent; // When true, data has been sent via Quorumnet once already.

  bool one_time_only()
  {
    if (sent) return false;
    sent = true;
    return true;
  }
};

struct round_context
{
  struct
  {
    uint64_t          height;              // Current blockchain height that Pulse wants to generate a block for
    crypto::hash      top_hash;            // Latest block hash included in signatures for rejecting out of date nodes
    pulse::time_point round_0_start_time;  // When round 0 should start and subsequent round timings are derived from.
  } wait_for_next_block;

  struct
  {
    bool                  queue_for_next_round; // When set to true, invoking prepare_for_round(...) will wait for (round + 1)
    uint8_t               round;                // The next round the Pulse ceremony will generate a block for
    service_nodes::quorum quorum;               // The block producer/validator participating in the next round
    sn_type               participant;          // Is this daemon a block producer, validator or non participant.
    size_t                my_quorum_position;   // Position in the quorum, 0 if producer or neither, or [0, PULSE_QUORUM_NUM_VALIDATORS) if a validator
    std::string           node_name;            // Short-hand string for describing the node in logs, i.e. V[0] for validator 0 or W[0] for the producer.
    pulse::time_point     start_time;           // When the round starts
  } prepare_for_round;

  struct
  {
    struct
    {
      bool sent;               // When true, handshake sent and waiting for other handshakes
      quorum_array<bool> data; // Received data from messages from Quorumnet
      pulse_wait_stage stage;
    } send_and_wait_for_handshakes;

    struct
    {
      quorum_array<std::optional<uint16_t>> data;
      pulse_wait_stage stage;

      uint16_t best_bitset; // The most agreed upon validators for participating in rounds. Value is set when all handshake bitsets are received.
      uint16_t best_count;  // How many validators agreed upon the best bitset.
    } wait_for_handshake_bitsets;

    struct
    {
      cryptonote::block block; // The block template with the best validator bitset and Pulse round applied to it.
      pulse_wait_stage stage;
    } wait_for_block_template;

    struct
    {
      pulse_send_stage<crypto::hash> send;
      struct
      {
        quorum_array<std::optional<crypto::hash>> data;
        pulse_wait_stage stage;
      } wait;
    } random_value_hashes;

    struct
    {
      pulse_send_stage<cryptonote::pulse_random_value> send;

      struct
      {
        quorum_array<std::optional<cryptonote::pulse_random_value>> data;
        pulse_wait_stage stage;
      } wait;
    } random_value;

    struct
    {
      pulse_send_stage<cryptonote::block> send;

      struct
      {
        quorum_array<std::optional<crypto::signature>> data;
        pulse_wait_stage stage;
      } wait;
    } signed_block;
  } transient;

  round_state state;
};

static round_context context;
namespace
{

crypto::hash blake2b_hash(void const *data, size_t size)
{
  crypto::hash result = {};
  static_assert(sizeof(result) == crypto_generichash_BYTES);
  crypto_generichash(reinterpret_cast<unsigned char *>(result.data), sizeof(result), reinterpret_cast<unsigned char const *>(data), size, nullptr /*key*/, 0 /*key length*/);
  return result;
}

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
  result << "'" << round_state_string(context.state) << "' ";
  return result.str();
}

std::bitset<sizeof(uint16_t) * 8> bitset_view16(uint16_t val)
{
  std::bitset<sizeof(uint16_t) * 8> result = val;
  return result;
}

//
// NOTE: pulse::message Utiliities
//
pulse::message msg_init_from_context(round_context const &context)
{
  pulse::message result  = {};
  result.quorum_position = context.prepare_for_round.my_quorum_position;
  result.round           = context.prepare_for_round.round;
  return result;
}

// Generate the hash necessary for signing a message. All fields of the message
// must have been set for that message type except the signature.
crypto::hash msg_signature_hash(round_context const &context, pulse::message const &msg)
{
  assert(context.state >= round_state::wait_for_next_block);
  crypto::hash result = {};
  switch(msg.type)
  {
    case pulse::message_type::invalid:
      assert("Invalid Code Path" == nullptr);
    break;

    case pulse::message_type::handshake:
    {
      auto buf = tools::memcpy_le(context.wait_for_next_block.top_hash.data, msg.quorum_position, msg.round);
      result   = blake2b_hash(buf.data(), buf.size());
    }
    break;

    case pulse::message_type::handshake_bitset:
    {
      auto buf = tools::memcpy_le(msg.handshakes.validator_bitset, context.wait_for_next_block.top_hash.data, msg.quorum_position, msg.round);
      result   = blake2b_hash(buf.data(), buf.size());
    }
    break;

    case pulse::message_type::block_template:
      result = blake2b_hash(msg.block_template.blob.data(), msg.block_template.blob.size());
    break;

    case pulse::message_type::random_value_hash:
    {
      auto buf = tools::memcpy_le(context.wait_for_next_block.top_hash.data, msg.quorum_position, msg.round, msg.random_value_hash.hash.data);
      result   = blake2b_hash(buf.data(), buf.size());
    }
    break;

    case pulse::message_type::random_value:
    {
      auto buf = tools::memcpy_le(context.wait_for_next_block.top_hash.data, msg.quorum_position, msg.round, msg.random_value.value.data);
      result   = blake2b_hash(buf.data(), buf.size());
    }
    break;

    case pulse::message_type::signed_block:
      result = cryptonote::get_block_hash(context.transient.signed_block.send.data);
    break;
  }

  return result;
}

// Generate a helper string that describes the origin of the message, i.e.
// 'Signed Block' from 6:f9337ffc8bc30baf3fca92a13fa5a3a7ab7c93e69acb7136906e7feae9d3e769
//   or
// <Message Type> from <Validator Index>:<Validator Public Key>
std::string msg_source_string(round_context const &context, pulse::message const &msg)
{
  if (msg.quorum_position >= context.prepare_for_round.quorum.validators.size()) return "XX";

  std::stringstream stream;
  stream << "'" << message_type_string(msg.type) << "' from " << msg.quorum_position << ", round " << +msg.round;
  if (context.state >= round_state::prepare_for_round)
  {
    if (msg.quorum_position < context.prepare_for_round.quorum.validators.size())
    {
      crypto::public_key const &key = context.prepare_for_round.quorum.validators[msg.quorum_position];
      stream << ":" << key;
    }
  }

  return stream.str();
}

bool msg_signature_check(pulse::message const &msg, service_nodes::quorum const &quorum)
{
  // Get Service Node Key
  crypto::public_key const *key = nullptr;
  switch (msg.type)
  {
    case pulse::message_type::invalid:
    {
      assert("Invalid Code Path" == nullptr);
      MERROR(log_prefix(context) << "Unhandled message type '" << pulse::message_type_string(msg.type) << "' can not verify signature.");
      return false;
    }
    break;

    case pulse::message_type::handshake: [[fallthrough]];
    case pulse::message_type::handshake_bitset: [[fallthrough]];
    case pulse::message_type::random_value_hash: [[fallthrough]];
    case pulse::message_type::random_value: [[fallthrough]];
    case pulse::message_type::signed_block:
    {
      if (msg.quorum_position >= static_cast<int>(quorum.validators.size()))
      {
        MERROR(log_prefix(context) << "Quorum position " << msg.quorum_position << " in Pulse message indexes oob");
        return false;
      }

      key = &quorum.validators[msg.quorum_position];
    }
    break;

    case pulse::message_type::block_template:
    {
      if (msg.quorum_position != 0)
      {
        MERROR(log_prefix(context) << "Quorum position " << msg.quorum_position << " in Pulse message indexes oob");
        return false;
      }

      key = &context.prepare_for_round.quorum.workers[0];
    }
    break;
  }

  if (!crypto::check_signature(msg_signature_hash(context, msg), *key, msg.signature))
  {
    MERROR(log_prefix(context) << "Signature for " << msg_source_string(context, msg) << " at height " << context.wait_for_next_block.height << "; is invalid");
    return false;
  }

  return true;
}

//
// NOTE: round_context Utilities
//
// Construct a pulse::message for sending the handshake bit or bitset.
void relay_validator_handshake_bit_or_bitset(round_context const &context, void *quorumnet_state, service_nodes::service_node_keys const &key, bool sending_bitset)
{
  assert(context.prepare_for_round.participant == sn_type::validator);

  // Message
  pulse::message msg = msg_init_from_context(context);
  if (sending_bitset)
  {
    msg.type = pulse::message_type::handshake_bitset;

    // Generate the bitset from our received handshakes.
    auto const &quorum = context.transient.send_and_wait_for_handshakes.data;
    for (size_t quorum_index = 0; quorum_index < quorum.size(); quorum_index++)
      if (bool received = quorum[quorum_index]; received)
        msg.handshakes.validator_bitset |= (1 << quorum_index);
  }
  else
  {
    msg.type = pulse::message_type::handshake;
  }
  crypto::generate_signature(msg_signature_hash(context, msg), key.pub, key.key, msg.signature);
  handle_message(quorumnet_state, msg); // Add our own. We receive our own msg for the first time which also triggers us to relay.
}

// Check the stage's queue for any messages that we received early and process
// them if any. Any messages in the queue that we haven't received yet will also
// be relayed to the quorum.
void handle_messages_received_early_for(pulse_wait_stage &stage, void *quorumnet_state)
{
  if (!stage.queue.count)
    return;

  for (auto &[msg, queued] : stage.queue.buffer)
  {
    if (queued == queueing_state::received)
    {
      pulse::handle_message(quorumnet_state, msg);
      queued = queueing_state::processed;
    }
  }
}

// In Pulse, after the block template and validators are locked in, enforce that
// all participating validators are doing their job in the stage.
bool enforce_validator_participation_and_timeouts(round_context const &context,
                                                  pulse_wait_stage const &stage,
                                                  bool timed_out,
                                                  bool all_received)
{
  assert(context.state > round_state::wait_for_handshake_bitsets);
  uint16_t const validator_bitset = context.transient.wait_for_handshake_bitsets.best_bitset;

  if (timed_out && !all_received)
  {
    MDEBUG(log_prefix(context) << "We timed out and there were insufficient hashes, required "
                               << service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES << ", received " << stage.msgs_received
                               << " from " << bitset_view16(stage.bitset));
    return false;
  }

  // NOTE: This is not technically meant to hit, internal invariant checking
  // that should have been triggered earlier.
  bool unexpected_items = (stage.bitset | validator_bitset) != validator_bitset;
  if (stage.msgs_received == 0 || unexpected_items)
  {
    if (unexpected_items)
      MERROR(log_prefix(context) << "Internal error, unexpected block validator bitset is " << bitset_view16(validator_bitset) << ", our bitset was " << bitset_view16(stage.bitset));
    else
      MERROR(log_prefix(context) << "Internal error, unexpected empty bitset received, we expected " << bitset_view16(validator_bitset));

    return false;
  }

  return true;
}

} // anonymous namespace

void pulse::handle_message(void *quorumnet_state, pulse::message const &msg)
{
  if (msg.type == pulse::message_type::signed_block)
  {
    // Signed Block is the last message in the Pulse stage. This message
    // signs the final block blob, with the final random value inserted in
    // it.

    // To avoid re-sending the blob which we already agreed upon when
    // receiving the Block Template from the leader, this message's signature
    // signs the sender's Final Block Template blob.

    // To verify this signature we verify it against our version of the Final
    // Block Template. However, this message could be received by us, before
    // we're in the final Pulse stage, so we delay signature verification until
    // this is possible.

    // The other stages are unaffected by this because they are signing the
    // contents of the message itself, of which, these messages are processed
    // when we have reached that Pulse stage (where we have all the necessary
    // information to validate the contents).
  }
  else
  {
    if (!msg_signature_check(msg, context.prepare_for_round.quorum))
      return;
  }

  pulse_wait_stage *stage = nullptr;
  switch(msg.type)
  {
    case pulse::message_type::invalid:           assert("Invalid Code Path" != nullptr);                        return;
    case pulse::message_type::handshake:         stage = &context.transient.send_and_wait_for_handshakes.stage; break;
    case pulse::message_type::handshake_bitset:  stage = &context.transient.wait_for_handshake_bitsets.stage;   break;
    case pulse::message_type::block_template:    stage = &context.transient.wait_for_block_template.stage;      break;
    case pulse::message_type::random_value_hash: stage = &context.transient.random_value_hashes.wait.stage;     break;
    case pulse::message_type::random_value:      stage = &context.transient.random_value.wait.stage;            break;
    case pulse::message_type::signed_block:      stage = &context.transient.signed_block.wait.stage;            break;
  }

  // TODO(doyle): We need to support potentially receiving messages from the future up to 1 round.
  if (msg.round != context.prepare_for_round.round)
  {
    MTRACE(log_prefix(context) << "Message received from a future round too early, " << msg_source_string(context, msg) << ", dropping the message.");
    return;
  }

  bool msg_received_early = false;
  switch(msg.type)
  {
    case pulse::message_type::invalid:           assert("Invalid Code Path" != nullptr); return;
    case pulse::message_type::handshake:         msg_received_early = (context.state < round_state::send_and_wait_for_handshakes);          break;
    case pulse::message_type::handshake_bitset:  msg_received_early = (context.state < round_state::wait_for_handshake_bitsets);            break;
    case pulse::message_type::block_template:    msg_received_early = (context.state < round_state::wait_for_block_template);               break;
    case pulse::message_type::random_value_hash: msg_received_early = (context.state < round_state::send_and_wait_for_random_value_hashes); break;
    case pulse::message_type::random_value:      msg_received_early = (context.state < round_state::send_and_wait_for_random_value);        break;
    case pulse::message_type::signed_block:      msg_received_early = (context.state < round_state::send_and_wait_for_signed_blocks);       break;
  }

  if (msg_received_early) // Enqueue the message until we're ready to process it
  {
    auto &[entry, queued] = stage->queue.buffer[msg.quorum_position];
    if (queued == queueing_state::empty)
    {
      MTRACE(log_prefix(context) << "Message received early " << msg_source_string(context, msg) << ", queueing until we're ready.");
      stage->queue.count++;
      entry  = std::move(msg);
      queued = queueing_state::received;
    }

    return;
  }

  uint16_t const validator_bit = (1 << msg.quorum_position);
  if (context.state > round_state::wait_for_handshake_bitsets &&
      msg.type > pulse::message_type::handshake_bitset)
  {
    // After the validator bitset has been set, the participating validators are
    // locked in. Any stray messages from other validators are rejected.
    if ((validator_bit & context.transient.wait_for_handshake_bitsets.best_bitset) == 0)
    {
      auto bitset_view = bitset_view16(context.transient.wait_for_handshake_bitsets.best_bitset);
      MTRACE(log_prefix(context) << "Dropping " << msg_source_string(context, msg) << ". Not a locked in participant, bitset is " << bitset_view);
      return;
    }
  }

  if (msg.quorum_position >= service_nodes::PULSE_QUORUM_NUM_VALIDATORS)
  {
    MTRACE(log_prefix(context) << "Dropping " << msg_source_string(context, msg) << ". Message quorum position indexes oob");
    return;
  }

  //
  // Add Message Data to Pulse Stage
  //
  switch(msg.type)
  {
    case pulse::message_type::invalid:
      assert("Invalid Code Path" != nullptr);
      return;

    case pulse::message_type::handshake:
    {
      auto &quorum = context.transient.send_and_wait_for_handshakes.data;
      if (quorum[msg.quorum_position]) return;
      quorum[msg.quorum_position] = true;
      MTRACE(log_prefix(context) << "Received handshake with quorum position bit (" << msg.quorum_position << ") "
                                 << bitset_view16(validator_bit) << " saved to bitset "
                                 << bitset_view16(stage->bitset));
    }
    break;

    case pulse::message_type::handshake_bitset:
    {
      auto &quorum = context.transient.wait_for_handshake_bitsets.data;
      auto &bitset = quorum[msg.quorum_position];
      if (bitset) return;
      bitset = msg.handshakes.validator_bitset;
    }
    break;

    case pulse::message_type::block_template:
    {
      if (stage->msgs_received == 1)
        return;

      cryptonote::block block = {};
      if (!cryptonote::t_serializable_object_from_blob(block, msg.block_template.blob))
      {
        MTRACE(log_prefix(context) << "Received unparsable pulse block template blob");
        return;
      }

      if (block.pulse.round != context.prepare_for_round.round)
      {
        MTRACE(log_prefix(context) << "Received pulse block template specifying different round " << +block.pulse.round
                                   << ", expected " << +context.prepare_for_round.round);
        return;
      }

      if (block.pulse.validator_bitset != context.transient.wait_for_handshake_bitsets.best_bitset)
      {
        auto block_bitset = bitset_view16(block.pulse.validator_bitset);
        auto our_bitset   = bitset_view16(context.transient.wait_for_handshake_bitsets.best_bitset);
        MTRACE(log_prefix(context) << "Received pulse block template specifying different validator handshake bitsets " << block_bitset << ", expected " << our_bitset);
        return;
      }

      context.transient.wait_for_block_template.block = std::move(block);
    }
    break;

    case pulse::message_type::random_value_hash:
    {
      auto &quorum = context.transient.random_value_hashes.wait.data;
      auto &value  = quorum[msg.quorum_position];
      if (value) return;
      value = msg.random_value_hash.hash;
    }
    break;

    case pulse::message_type::random_value:
    {
      auto &quorum = context.transient.random_value.wait.data;
      auto &value  = quorum[msg.quorum_position];
      if (value) return;

      if (auto const &hash = context.transient.random_value_hashes.wait.data[msg.quorum_position]; hash)
      {
        auto derived = blake2b_hash(msg.random_value.value.data, sizeof(msg.random_value.value.data));
        if (derived != *hash)
        {
          MTRACE(log_prefix(context) << "Dropping " << msg_source_string(context, msg)
                                    << ". Rederived random value hash " << derived << " does not match original hash "
                                    << *hash);
          return;
        }
      }

      value = msg.random_value.value;
    }
    break;

    case pulse::message_type::signed_block:
    {
      // Delayed signature verification because signature contents relies on us
      // have the Pulse data from the final stage
      if (!msg_signature_check(msg, context.prepare_for_round.quorum))
      {
        MDEBUG(log_prefix(context) << "Dropping " << msg_source_string(context, msg) << ". Sender's final block template signature does not match ours");
        return;
      }

      // Signature already verified in msg_signature_check(...)
      auto &quorum    = context.transient.signed_block.wait.data;
      auto &signature = quorum[msg.quorum_position];
      if (signature) return;
      signature = msg.signature;
    }
    break;
  }

  stage->bitset |= validator_bit;
  stage->msgs_received++;

  if (quorumnet_state)
    cryptonote::quorumnet_pulse_relay_message_to_quorum(quorumnet_state, msg, context.prepare_for_round.quorum, context.prepare_for_round.participant == sn_type::producer);
}

bool pulse::get_round_timings(cryptonote::Blockchain const &blockchain, uint64_t height, pulse::timings &times)
{
  times = {};

  crypto::hash top_hash       = blockchain.get_block_id_by_height(height - 1);
  cryptonote::block top_block = {};
  if (bool orphan = false; !blockchain.get_block_by_hash(top_hash, top_block, &orphan) || orphan)
    return false;

  static uint64_t const hf16_height = blockchain.get_earliest_ideal_height_for_version(cryptonote::network_version_16);
  if (hf16_height == std::numeric_limits<uint64_t>::max())
    return false;

  crypto::hash genesis_hash       = blockchain.get_block_id_by_height(hf16_height - 1);
  cryptonote::block genesis_block = {};
  if (bool orphaned = false; !blockchain.get_block_by_hash(genesis_hash, genesis_block, &orphaned) || orphaned)
    return false;

#if 1
  uint64_t const delta_height = height - cryptonote::get_block_height(genesis_block);
  times.genesis_timestamp     = pulse::time_point(std::chrono::seconds(genesis_block.timestamp));

  times.prev_hash      = top_hash;
  times.prev_timestamp = pulse::time_point(std::chrono::seconds(top_block.timestamp));

  times.ideal_timestamp = pulse::time_point(times.genesis_timestamp + (TARGET_BLOCK_TIME * delta_height));
  times.r0_timestamp    = std::clamp(times.ideal_timestamp,
                                  times.prev_timestamp + service_nodes::PULSE_MIN_TARGET_BLOCK_TIME,
                                  times.prev_timestamp + service_nodes::PULSE_MAX_TARGET_BLOCK_TIME);
#else // NOTE: Debug, make next block start relatively soon
  times.r0_timestamp = times.prev_timestamp + service_nodes::PULSE_ROUND_TIME;
#endif

  times.miner_fallback_timestamp = times.r0_timestamp + (service_nodes::PULSE_ROUND_TIME * 256);

  return true;
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
    |     +---------------------+                         |
    |     | Wait For Handshakes |                         |
    |     +---------------------+                         |
    |      |                                              |
    |     +-------------------------+                     |
    |     | Submit Handshake Bitset |                     |
    |     +-------------------------+                     |
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

    - When all handshakes are received we send our bitset and progress to
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
      pulse round applied to the block and sends it the Validators

  Wait For Block Template:
    - TODO(loki): TBD

*/


round_state goto_preparing_for_next_round(round_context &context)
{
  context.prepare_for_round.queue_for_next_round = true;
  return round_state::prepare_for_round;
}

round_state wait_for_next_block(uint64_t hf16_height, round_context &context, cryptonote::Blockchain const &blockchain)
{

  //
  // NOTE: If already processing pulse for height, wait for next height
  //
  uint64_t curr_height = blockchain.get_current_blockchain_height(true /*lock*/);
  if (context.wait_for_next_block.height == curr_height)
  {
    for (static uint64_t last_height = 0; last_height != curr_height; last_height = curr_height)
      MDEBUG(log_prefix(context) << "Network is currently producing block " << curr_height << ", waiting until next block");
    return round_state::wait_for_next_block;
  }

  pulse::timings times = {};
  if (!get_round_timings(blockchain, curr_height, times))
  {
    for (static bool once = true; once; once = !once)
      MERROR(log_prefix(context) << "Failed to query the block data for Pulse timings");
    return round_state::wait_for_next_block;
  }

  context.wait_for_next_block.round_0_start_time = times.r0_timestamp;
  context.wait_for_next_block.height             = curr_height;
  context.wait_for_next_block.top_hash           = times.prev_hash;
  context.prepare_for_round                      = {};

  return round_state::prepare_for_round;
}

round_state prepare_for_round(round_context &context, service_nodes::service_node_keys const &key, cryptonote::Blockchain const &blockchain)
{
  // Clear memory
  {
    context.transient = {};
    cryptonote::pulse_random_value &old_random_value = context.transient.random_value.send.data;
    auto &old_random_values_array                    = context.transient.random_value.wait.data;
    memwipe(old_random_value.data, sizeof(old_random_value));
    memwipe(old_random_values_array.data(), old_random_values_array.size() * sizeof(old_random_values_array[0]));

    // Store values
    bool queue_for_round = context.prepare_for_round.queue_for_next_round;
    uint8_t round        = context.prepare_for_round.round;

    // Blanket clear
    context.prepare_for_round = {};

    // Restore values
    context.prepare_for_round.round                = round;
    context.prepare_for_round.queue_for_next_round = queue_for_round;
  }

  if (context.prepare_for_round.queue_for_next_round)
  {
    // Set when an intermediate Pulse stage has failed and we wait on the
    // next round to occur.
    context.prepare_for_round.queue_for_next_round = false;

    if (context.prepare_for_round.round >= 255)
    {
      // If the next round overflows, we consider the network stalled. Wait for
      // the next block and allow PoW to return.
      return round_state::wait_for_next_block;
    }
    context.prepare_for_round.round++;

    // Also check if the blockchain has changed, in which case we stop and
    // restart Pulse stages.
    if (context.wait_for_next_block.height != blockchain.get_current_blockchain_height(true /*lock*/))
      return round_state::wait_for_next_block;
  }

  //
  // NOTE: Check Current Round
  //
  {
    auto now                     = pulse::clock::now();
    auto const time_since_block  = now <= context.wait_for_next_block.round_0_start_time ? std::chrono::seconds(0) : (now - context.wait_for_next_block.round_0_start_time);
    size_t round_usize           = time_since_block / service_nodes::PULSE_ROUND_TIME;

    if (round_usize > 255) // Network stalled
    {
      MINFO(log_prefix(context) << "Pulse has timed out, reverting to accepting miner blocks only.");
      return round_state::wait_for_next_block;
    }

    uint8_t curr_round = static_cast<uint8_t>(round_usize);
    if (curr_round > context.prepare_for_round.round)
      context.prepare_for_round.round = curr_round;
  }

  {
    using namespace service_nodes;
    context.prepare_for_round.start_time                          = context.wait_for_next_block.round_0_start_time                + (context.prepare_for_round.round * PULSE_ROUND_TIME);
    context.transient.send_and_wait_for_handshakes.stage.end_time = context.prepare_for_round.start_time                          + PULSE_WAIT_FOR_HANDSHAKES_DURATION;
    context.transient.wait_for_handshake_bitsets.stage.end_time   = context.transient.send_and_wait_for_handshakes.stage.end_time + PULSE_WAIT_FOR_OTHER_VALIDATOR_HANDSHAKES_DURATION;
    context.transient.wait_for_block_template.stage.end_time      = context.transient.wait_for_handshake_bitsets.stage.end_time   + PULSE_WAIT_FOR_BLOCK_TEMPLATE_DURATION;
    context.transient.random_value_hashes.wait.stage.end_time     = context.transient.wait_for_block_template.stage.end_time      + PULSE_WAIT_FOR_RANDOM_VALUE_HASH_DURATION;
    context.transient.random_value.wait.stage.end_time            = context.transient.random_value_hashes.wait.stage.end_time     + PULSE_WAIT_FOR_RANDOM_VALUE_DURATION;
    context.transient.signed_block.wait.stage.end_time            = context.transient.random_value.wait.stage.end_time            + PULSE_WAIT_FOR_SIGNED_BLOCK_DURATION;
  }

  context.prepare_for_round.quorum =
      service_nodes::generate_pulse_quorum(blockchain.nettype(),
                                           blockchain.get_db(),
                                           context.wait_for_next_block.height + 1,
                                           blockchain.get_service_node_list().get_block_leader().key,
                                           blockchain.get_current_hard_fork_version(),
                                           blockchain.get_service_node_list().active_service_nodes_infos(),
                                           context.prepare_for_round.round);

  if (!service_nodes::verify_pulse_quorum_sizes(context.prepare_for_round.quorum))
  {
    MINFO(log_prefix(context) << "Insufficient Service Nodes to execute Pulse on height " << context.wait_for_next_block.height << ", we require a PoW miner block. Sleeping until next block.");
    return round_state::wait_for_next_block;
  }

  MDEBUG(log_prefix(context) << "Generate Pulse quorum: " << context.prepare_for_round.quorum);

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

  return round_state::wait_for_round;
}

round_state wait_for_round(round_context &context, cryptonote::Blockchain const &blockchain)
{
  if (context.wait_for_next_block.height != blockchain.get_current_blockchain_height(true /*lock*/))
  {
    MDEBUG(log_prefix(context) << "Block height changed whilst waiting for round " << +context.prepare_for_round.round << ", restarting Pulse stages");
    return round_state::wait_for_next_block;
  }

  auto start_time = context.prepare_for_round.start_time;
  if (auto now = pulse::clock::now(); now < start_time)
  {
    for (static uint64_t last_height = 0; last_height != context.wait_for_next_block.height; last_height = context.wait_for_next_block.height)
      MINFO(log_prefix(context) << "Waiting for round " << +context.prepare_for_round.round << " to start in " << tools::get_human_readable_timespan(start_time - now));
    return round_state::wait_for_round;
  }

  if (context.prepare_for_round.participant == sn_type::validator)
  {
    MINFO(log_prefix(context) << "We are a pulse validator, sending handshake bit and collecting other handshakes.");
    return round_state::send_and_wait_for_handshakes;
  }
  else if (context.prepare_for_round.participant == sn_type::producer)
  {
    MINFO(log_prefix(context) << "We are the block producer for height " << context.wait_for_next_block.height << " in round " << +context.prepare_for_round.round << ", awaiting handshake bitsets.");
    return round_state::wait_for_handshake_bitsets;
  }
  else
  {
    MDEBUG(log_prefix(context) << "Non-participant for round, waiting on next round or block.");
    return goto_preparing_for_next_round(context);
  }
}

round_state send_and_wait_for_handshakes(round_context &context, void *quorumnet_state, service_nodes::service_node_keys const &key)
{
  //
  // NOTE: Send
  //
  assert(context.prepare_for_round.participant == sn_type::validator);
  if (!context.transient.send_and_wait_for_handshakes.sent)
  {
    context.transient.send_and_wait_for_handshakes.sent = true;
    try
    {
      relay_validator_handshake_bit_or_bitset(context, quorumnet_state, key, false /*sending_bitset*/);
    }
    catch (std::exception const &e)
    {
      MERROR(log_prefix(context) << "Attempting to invoke and send a Pulse participation handshake unexpectedly failed. " << e.what());
      return goto_preparing_for_next_round(context);
    }
  }

  //
  // NOTE: Wait
  //
  handle_messages_received_early_for(context.transient.send_and_wait_for_handshakes.stage, quorumnet_state);
  pulse_wait_stage const &stage = context.transient.send_and_wait_for_handshakes.stage;

  auto const &quorum            = context.transient.send_and_wait_for_handshakes.data;
  bool const timed_out          = pulse::clock::now() >= stage.end_time;
  bool const all_handshakes     = stage.msgs_received == quorum.size();

  assert(context.prepare_for_round.participant == sn_type::validator);
  assert(context.prepare_for_round.my_quorum_position < quorum.size());

  if (all_handshakes || timed_out)
  {
    bool missing_handshakes = timed_out && !all_handshakes;
    MINFO(log_prefix(context) << "Collected validator handshakes " << bitset_view16(stage.bitset) << (missing_handshakes ? ", we timed out and some handshakes were not seen! " : ". ") << "Sending handshake bitset and collecting other validator bitsets.");
    return round_state::send_handshake_bitsets;
  }
  else
  {
    return round_state::send_and_wait_for_handshakes;
  }
}

round_state send_handshake_bitsets(round_context &context, void *quorumnet_state, service_nodes::service_node_keys const &key)
{
  try
  {
    relay_validator_handshake_bit_or_bitset(context, quorumnet_state, key, true /*sending_bitset*/);
    return round_state::wait_for_handshake_bitsets;
  }
  catch(std::exception const &e)
  {
    MERROR(log_prefix(context) << "Attempting to invoke and send a Pulse validator bitset unexpectedly failed. " << e.what());
    return goto_preparing_for_next_round(context);
  }
}

round_state wait_for_handshake_bitsets(round_context &context, void *quorumnet_state, service_nodes::service_node_keys const &key)
{
  handle_messages_received_early_for(context.transient.wait_for_handshake_bitsets.stage, quorumnet_state);
  pulse_wait_stage const &stage = context.transient.wait_for_handshake_bitsets.stage;

  auto const &quorum            = context.transient.wait_for_handshake_bitsets.data;
  bool const timed_out          = pulse::clock::now() >= stage.end_time;
  bool const all_bitsets        = stage.msgs_received == quorum.size();

  if (timed_out || all_bitsets)
  {
    bool missing_bitsets = timed_out && !all_bitsets;
    MDEBUG(log_prefix(context) << "Collected " << stage.msgs_received << "/" << quorum.size() << " handshake bitsets"
                               << (missing_bitsets ? ", we timed out and some bitsets were not seen!" : ""));

    std::map<uint16_t, int> most_common_bitset;
    uint16_t best_bitset = 0;
    size_t count         = 0;
    for (size_t quorum_index = 0; quorum_index < quorum.size(); quorum_index++)
    {
      auto &bitset = quorum[quorum_index];
      if (bitset)
      {
        uint16_t num = ++most_common_bitset[*bitset];
        if (num > count)
        {
          best_bitset = *bitset;
          count       = num;
        }
        MTRACE(log_prefix(context) << "Collected from V[" << quorum_index << "], handshake bitset " << bitset_view16(*bitset));
      }

    }

    if (count < service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES || best_bitset == 0)
    {
      // Less than the threshold of the validators can't come to agreement about
      // which validators are online, we wait until the next round.
      if (best_bitset == 0)
      {
        MDEBUG(log_prefix(context) << count << "/" << quorum.size() << " validators did not send any handshake bitset or sent an empty handshake bitset");
      }
      else
      {
        MDEBUG(log_prefix(context) << "We heard back from less than " << service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES << " of the validators ("
                                  << count << "/" << quorum.size() << ", waiting for next round.");
      }

      return goto_preparing_for_next_round(context);
    }

    context.transient.wait_for_handshake_bitsets.best_bitset = best_bitset;
    context.transient.wait_for_handshake_bitsets.best_count  = count;
    MINFO(log_prefix(context) << count << "/" << quorum.size()
                              << " validators agreed on the participating nodes in the quorum " << bitset_view16(best_bitset)
                              << (context.prepare_for_round.participant == sn_type::producer
                                      ? ""
                                      : ". Awaiting block template from block producer"));

    if (context.prepare_for_round.participant == sn_type::producer)
      return round_state::send_block_template;
    else
      return round_state::wait_for_block_template;
  }

  return round_state::wait_for_handshake_bitsets;
}

round_state send_block_template(round_context &context, void *quorumnet_state, service_nodes::service_node_keys const &key, cryptonote::Blockchain &blockchain)
{
  assert(context.prepare_for_round.participant == sn_type::producer);
  std::vector<service_nodes::service_node_pubkey_info> list_state = blockchain.get_service_node_list().get_service_node_list_state({key.pub});

  // Invariants
  // TODO(doyle): These checks can be done earlier?
  if (list_state.empty())
  {
    MWARNING(log_prefix(context) << "Block producer (us) is not available on the service node list, waiting until next round");
    return goto_preparing_for_next_round(context);
  }

  std::shared_ptr<const service_nodes::service_node_info> info = list_state[0].info;
  if (!info->is_active())
  {
    MWARNING(log_prefix(context) << "Block producer (us) is not an active service node, waiting until next round");
    return goto_preparing_for_next_round(context);
  }

  // Block
  // TODO(doyle): Round and validator bitset should go into the create_next_pulse_block_template arguments
  cryptonote::block block = {};
  {
    uint64_t expected_reward = 0;
    service_nodes::payout block_producer_payouts = service_nodes::service_node_info_to_payout(key.pub, *info);
    blockchain.create_next_pulse_block_template(block, block_producer_payouts, context.wait_for_next_block.height, expected_reward);

    block.pulse.round            = context.prepare_for_round.round;
    block.pulse.validator_bitset = context.transient.wait_for_handshake_bitsets.best_bitset;
  }

  // Message
  pulse::message msg      = msg_init_from_context(context);
  msg.type                = pulse::message_type::block_template;
  msg.block_template.blob = cryptonote::t_serializable_object_to_blob(block);
  crypto::generate_signature(msg_signature_hash(context, msg), key.pub, key.key, msg.signature);

  // Send
  MINFO(log_prefix(context) << "Validators are handshaken and ready, sending block template from producer (us) to validators.\n" << cryptonote::obj_to_json_str(block));
  cryptonote::quorumnet_pulse_relay_message_to_quorum(quorumnet_state, msg, context.prepare_for_round.quorum, true /*block_producer*/);
  return goto_preparing_for_next_round(context);
}

round_state wait_for_block_template(round_context &context, void *quorumnet_state, service_nodes::service_node_keys const &key, cryptonote::Blockchain &blockchain)
{
  handle_messages_received_early_for(context.transient.wait_for_block_template.stage, quorumnet_state);
  pulse_wait_stage const &stage = context.transient.wait_for_block_template.stage;

  assert(context.prepare_for_round.participant == sn_type::validator);
  bool timed_out = pulse::clock::now() >= context.transient.wait_for_block_template.stage.end_time;
  if (timed_out || context.transient.wait_for_block_template.stage.msgs_received == 1)
  {
    if (context.transient.wait_for_block_template.stage.msgs_received == 1)
    {
      cryptonote::block const &block = context.transient.wait_for_block_template.block;
      MINFO(log_prefix(context) << "Valid block received: " << cryptonote::obj_to_json_str(context.transient.wait_for_block_template.block));

      // Generate my random value and its hash
      crypto::generate_random_bytes_thread_safe(sizeof(context.transient.random_value.send.data), context.transient.random_value.send.data.data);
      context.transient.random_value_hashes.send.data = blake2b_hash(&context.transient.random_value.send.data, sizeof(context.transient.random_value.send.data));
      return round_state::send_and_wait_for_random_value_hashes;
    }
    else
    {
      MINFO(log_prefix(context) << "Timed out, block template was not received");
      return goto_preparing_for_next_round(context);
    }
  }

  return round_state::wait_for_block_template;
}

round_state send_and_wait_for_random_value_hashes(round_context &context, void *quorumnet_state, service_nodes::service_node_keys const &key)
{
  assert(context.prepare_for_round.participant == sn_type::validator);

  //
  // NOTE: Send
  //
  if (context.transient.random_value_hashes.send.one_time_only())
  {
    // Message
    pulse::message msg         = msg_init_from_context(context);
    msg.type                   = pulse::message_type::random_value_hash;
    msg.random_value_hash.hash = context.transient.random_value_hashes.send.data;
    crypto::generate_signature(msg_signature_hash(context, msg), key.pub, key.key, msg.signature);
    handle_message(quorumnet_state, msg); // Add our own. We receive our own msg for the first time which also triggers us to relay.
  }

  //
  // NOTE: Wait
  //
  handle_messages_received_early_for(context.transient.random_value_hashes.wait.stage, quorumnet_state);
  pulse_wait_stage const &stage = context.transient.random_value_hashes.wait.stage;

  auto const &quorum    = context.transient.random_value_hashes.wait.data;
  bool const timed_out  = pulse::clock::now() >= stage.end_time;
  bool const all_hashes = stage.msgs_received == context.transient.wait_for_handshake_bitsets.best_count;

  if (timed_out || all_hashes)
  {
    if (!enforce_validator_participation_and_timeouts(context, stage, timed_out, all_hashes))
      return goto_preparing_for_next_round(context);

    MINFO(log_prefix(context) << "Received " << stage.msgs_received << " random value hashes from " << bitset_view16(stage.bitset) << (timed_out ? ". We timed out and some hashes are missing" : ""));
    return round_state::send_and_wait_for_random_value;
  }

  return round_state::send_and_wait_for_random_value_hashes;
}

round_state send_and_wait_for_random_value(round_context &context, void *quorumnet_state, service_nodes::service_node_keys const &key)
{
  //
  // NOTE: Send
  //
  assert(context.prepare_for_round.participant == sn_type::validator);
  if (context.transient.random_value.send.one_time_only())
  {
    // Message
    pulse::message msg     = msg_init_from_context(context);
    msg.type               = pulse::message_type::random_value;
    msg.random_value.value = context.transient.random_value.send.data;
    crypto::generate_signature(msg_signature_hash(context, msg), key.pub, key.key, msg.signature);
    handle_message(quorumnet_state, msg); // Add our own. We receive our own msg for the first time which also triggers us to relay.
  }

  //
  // NOTE: Wait
  //
  handle_messages_received_early_for(context.transient.random_value.wait.stage, quorumnet_state);
  pulse_wait_stage const &stage = context.transient.random_value.wait.stage;

  auto const &quorum    = context.transient.random_value.wait.data;
  bool const timed_out  = pulse::clock::now() >= stage.end_time;
  bool const all_values = stage.msgs_received == context.transient.wait_for_handshake_bitsets.best_count;

  if (timed_out || all_values)
  {
    if (!enforce_validator_participation_and_timeouts(context, stage, timed_out, all_values))
      return goto_preparing_for_next_round(context);

    // Generate Final Random Value
    crypto::hash final_hash = {};
    {
      unsigned char constexpr key[crypto_generichash_KEYBYTES] = {};
      crypto_generichash_state state = {};
      crypto_generichash_init(&state, key, sizeof(key), sizeof(final_hash));

      for (size_t index = 0; index < quorum.size(); index++)
      {
        if (auto &random_value = quorum[index]; random_value)
        {
          epee::wipeable_string string = lokimq::to_hex(tools::view_guts(random_value->data));

#if defined(NDEBUG)
          // Mask the random value generated incase someone is snooping logs
          // trying to derive the Service Node rng seed.
          for (int i = 2; i < static_cast<int>(string.size()) - 2; i++)
            string.data()[i] = '.';
#endif

          MDEBUG(log_prefix(context) << "Final random value seeding with V[" << index << "] " << string.view());
          crypto_generichash_update(&state, random_value->data, sizeof(random_value->data));
        }
      }

      crypto_generichash_final(&state, reinterpret_cast<unsigned char *>(final_hash.data), sizeof(final_hash));
    }

    cryptonote::block &block                           = context.transient.wait_for_block_template.block;
    cryptonote::pulse_random_value &final_random_value = block.pulse.random_value;

    static_assert(sizeof(final_hash) >= sizeof(final_random_value.data));
    std::memcpy(final_random_value.data, final_hash.data, sizeof(final_random_value.data));

    MINFO(log_prefix(context) << "Block final random value " << lokimq::to_hex(tools::view_guts(final_random_value.data)) << " generated from validators " << bitset_view16(stage.bitset));
    context.transient.signed_block.send.data = std::move(block);
    block                                    = {};
    return round_state::send_and_wait_for_signed_blocks;
  }

  return round_state::send_and_wait_for_random_value;
}

round_state send_and_wait_for_signed_blocks(round_context &context, void *quorumnet_state, service_nodes::service_node_keys const &key, cryptonote::core &core)
{
  assert(context.prepare_for_round.participant == sn_type::validator);

  //
  // NOTE: Send
  //
  if (context.transient.signed_block.send.one_time_only())
  {
    // Message
    pulse::message msg = msg_init_from_context(context);
    msg.type           = pulse::message_type::signed_block;
    crypto::generate_signature(msg_signature_hash(context, msg), key.pub, key.key, msg.signature);
    handle_message(quorumnet_state, msg); // Add our own. We receive our own msg for the first time which also triggers us to relay.
  }

  //
  // NOTE: Wait
  //
  handle_messages_received_early_for(context.transient.signed_block.wait.stage, quorumnet_state);
  pulse_wait_stage const &stage = context.transient.signed_block.wait.stage;

  auto const &quorum   = context.transient.signed_block.wait.data;
  bool const timed_out = pulse::clock::now() >= stage.end_time;
  bool const enough    = stage.msgs_received >= context.transient.wait_for_handshake_bitsets.best_count;

  if (timed_out || enough)
  {
    if (!enforce_validator_participation_and_timeouts(context, stage, timed_out, enough))
      return goto_preparing_for_next_round(context);

    // Select signatures randomly so we don't always just take the first N required signatures.
    // Then sort just the first N required signatures, so signatures are added
    // to the block in sorted order, but were chosen randomly.
    std::array<size_t, service_nodes::PULSE_QUORUM_NUM_VALIDATORS> indices = {};
    size_t indices_count = 0;

    // Pull out indices where we've received a signature
    for (size_t index = 0; index < quorum.size(); index++)
      if (quorum[index])
        indices[indices_count++] = index;

    // Random select from first 'N' PULSE_BLOCK_REQUIRED_SIGNATURES from indices_count entries.
    assert(indices_count >= service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES);
    std::array<size_t, service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES> selected = {};
    std::sample(indices.begin(), indices.begin() + indices_count, selected.begin(), selected.size(), tools::rng);

    // Add Signatures
    cryptonote::block &final_block = context.transient.signed_block.send.data;
    for (size_t index = 0; index < service_nodes::PULSE_BLOCK_REQUIRED_SIGNATURES; index++)
    {
      uint16_t validator_index = indices[index];
      auto const &signature    = quorum[validator_index];
      assert(signature);
      MDEBUG(log_prefix(context) << "Signature added: " << validator_index << ":" << context.prepare_for_round.quorum.validators[validator_index] << ", " << *signature);
      final_block.signatures.emplace_back(validator_index, *signature);
    }

    // Propagate Final Block
    MDEBUG(log_prefix(context) << "Final signed block constructed\n" << cryptonote::obj_to_json_str(final_block));
    cryptonote::block_verification_context bvc = {};
    if (!core.handle_block_found(final_block, bvc))
      return goto_preparing_for_next_round(context);

    return round_state::wait_for_next_block;
  }

  return round_state::send_and_wait_for_signed_blocks;
}

void pulse::main(void *quorumnet_state, cryptonote::core &core)
{
  cryptonote::Blockchain &blockchain          = core.get_blockchain_storage();
  service_nodes::service_node_keys const &key = core.get_service_keys();

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
      MDEBUG("Pulse: Network at block " << height << " is not ready for Pulse until block " << hf16_height << ", waiting");
    return;
  }

  for (auto last_state = round_state::null_state;
       last_state != context.state || last_state == round_state::null_state;)
  {
    last_state = context.state;

    switch (context.state)
    {
      case round_state::null_state:
        context.state = round_state::wait_for_next_block;
        break;

      case round_state::wait_for_next_block:
        context.state = wait_for_next_block(hf16_height, context, blockchain);
        break;

      case round_state::prepare_for_round:
        context.state = prepare_for_round(context, key, blockchain);
        break;

      case round_state::wait_for_round:
        context.state = wait_for_round(context, blockchain);
        break;

      case round_state::send_and_wait_for_handshakes:
        context.state = send_and_wait_for_handshakes(context, quorumnet_state, key);
        break;

      case round_state::send_handshake_bitsets:
        context.state = send_handshake_bitsets(context, quorumnet_state, key);
        break;

      case round_state::wait_for_handshake_bitsets:
        context.state = wait_for_handshake_bitsets(context, quorumnet_state, key);
        break;

      case round_state::wait_for_block_template:
        context.state = wait_for_block_template(context, quorumnet_state, key, blockchain);
        break;

      case round_state::send_block_template:
        context.state = send_block_template(context, quorumnet_state, key, blockchain);
        break;

      case round_state::send_and_wait_for_random_value_hashes:
        context.state = send_and_wait_for_random_value_hashes(context, quorumnet_state, key);
        break;

      case round_state::send_and_wait_for_random_value:
        context.state = send_and_wait_for_random_value(context, quorumnet_state, key);
        break;

      case round_state::send_and_wait_for_signed_blocks:
        context.state = send_and_wait_for_signed_blocks(context, quorumnet_state, key, core);
        break;
    }
  }
}

