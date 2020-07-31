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
};

constexpr std::string_view message_type_string(message_type type)
{
  using namespace std::literals;
  switch(type)
  {
    default:
    case message_type::invalid: return "Invalid"sv;
    case message_type::handshake: return "Handshake"sv;
    case message_type::handshake_bitset: return "Handshake Bitset"sv;
  }
}

struct message
{
  message_type      type;
  uint16_t          quorum_position;
  uint16_t          validator_bitset;
  crypto::signature signature;
};

struct state : public cryptonote::BlockAddedHook
{
  std::condition_variable wakeup_cv;
  std::atomic<uint64_t>   last_miner_block;
  std::atomic<bool>       shutdown;
  bool block_added(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs, cryptonote::checkpoint_t const *checkpoint) override;
};

void main(pulse::state &state, void *quorumnet_state, cryptonote::core &core);

} // namespace pulse
