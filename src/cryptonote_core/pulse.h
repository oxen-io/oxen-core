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
};

constexpr std::string_view message_type_string(message_type type)
{
  switch(type)
  {
    case message_type::invalid: return "Invalid"sv;
    case message_type::handshake: return "Handshake"sv;
    case message_type::handshake_bitset: return "Handshake Bitset"sv;
    case message_type::block_template: return "Block Template"sv;
  }
  return "Invalid2"sv;
}

struct message
{
  message_type type;
  uint16_t quorum_position;
  crypto::signature signature;

  struct
  {
    uint16_t validator_bitset;   // Set if type is handshake_bitset, otherwise 0.
  } handshakes;

  struct
  {
    std::string blob;
  } block_template;
};

void main(void *quorumnet_state, cryptonote::core &core);
void handle_message(void *quorumnet_state, pulse::message const &msg);

} // namespace pulse
