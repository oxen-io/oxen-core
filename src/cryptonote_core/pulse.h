#pragma once

#include <atomic>
#include <cstdint>
#include <condition_variable>

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

enum struct message_type
{
  invalid,
  handshake,
  handshake_bitset,
};

struct message
{
  message_type      type;
  int               quorum_position;
  crypto::signature signature;
  uint16_t          validator_bitset;
};

struct state : public cryptonote::BlockAddedHook
{
  std::condition_variable block_added_cv;
  std::atomic<uint64_t>   last_miner_block;
  bool block_added(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs, cryptonote::checkpoint_t const *checkpoint) override;
};

void main(pulse::state &state, void *quorumnet_state, cryptonote::core &core);

} // namespace pulse
