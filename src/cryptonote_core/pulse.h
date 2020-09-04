#pragma once

#include <atomic>
#include <cstdint>
#include <condition_variable>
#include <string_view>

#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "crypto/crypto.h"

namespace cryptonote
{
class core;
class transaction;
struct block;
struct checkpoint_t;
};

namespace service_nodes
{
struct service_node_keys;
};

namespace pulse
{
using clock      = std::chrono::system_clock;
using time_point = std::chrono::time_point<clock>;

enum struct message_type : uint8_t
{
  invalid,
  handshake,
  handshake_bitset,
  block_template,
  random_value_hash,
  random_value,
  signed_block,
};

constexpr std::string_view message_type_string(message_type type)
{
  switch(type)
  {
    case message_type::invalid: return "Invalid"sv;
    case message_type::handshake: return "Handshake"sv;
    case message_type::handshake_bitset: return "Handshake Bitset"sv;
    case message_type::block_template: return "Block Template"sv;
    case message_type::random_value_hash: return "Random Value Hash"sv;
    case message_type::random_value: return "Random Value"sv;
    case message_type::signed_block: return "Signed Block"sv;
  }
  return "Invalid2"sv;
}

struct message
{
  message_type type;
  uint16_t quorum_position;
  uint8_t  round;
  crypto::signature signature;

  struct
  {
    uint16_t validator_bitset;   // Set if type is handshake_bitset, otherwise 0.
  } handshakes;

  struct
  {
    std::string blob;
  } block_template;

  struct
  {
    crypto::hash hash;
  } random_value_hash;

  struct
  {
    cryptonote::pulse_random_value value;
  } random_value;
};

void main(void *quorumnet_state, cryptonote::core &core);
void handle_message(void *quorumnet_state, pulse::message const &msg);

struct timings
{
  pulse::time_point genesis_timestamp;

  crypto::hash      prev_hash;
  pulse::time_point prev_timestamp;

  pulse::time_point ideal_timestamp;
  pulse::time_point r0_timestamp;
  pulse::time_point miner_fallback_timestamp;
};

bool get_round_timings(cryptonote::Blockchain const &blockchain, uint64_t height, timings &times);
bool get_round_timings_for_block(cryptonote::Blockchain const &blockchain, cryptonote::block const &block, pulse::timings &times);

} // namespace pulse
