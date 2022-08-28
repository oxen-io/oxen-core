#pragma once

#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include <oxenc/bt_serialize.h>
#include <oxenc/bt_value.h>

namespace service_nodes {

struct service_node_keys;

}

namespace uptime_proof
{

// Keeps track of the reason why an uptime proof is not sent
// when adding more error flags double the integer so that it will
// BINARY OR properly
enum error_flag
{
    SHARED_PRIVATE_KEY = 1,
    NO_STORAGE_SERVER_PING = 2,
    NO_LOKINET_PING = 4
};

inline error_flag operator|(error_flag a, error_flag b)
{
    return static_cast<error_flag>(static_cast<int>(a) | static_cast<int>(b));
}

class uptime_state
{

public:
  std::chrono::steady_clock::time_point last_uptime_proof_check;
  bool passing_uptime_proof;
  error_flag error;

  void set_error(error_flag err);
  void set_passing();
};

class Proof
{
  
public:
  std::array<uint16_t, 3> version{};
  std::array<uint16_t, 3> storage_server_version{};
  std::array<uint16_t, 3> lokinet_version{};

  uint64_t timestamp{};
  crypto::public_key pubkey{};
  crypto::signature sig{};
  crypto::ed25519_public_key pubkey_ed25519{};
  crypto::ed25519_signature sig_ed25519{};
  uint32_t public_ip{};
  uint16_t storage_https_port{};
  uint16_t storage_omq_port{};
  uint16_t qnet_port{};

  Proof() = default;
  Proof(uint32_t sn_public_ip, uint16_t sn_storage_https_port, uint16_t sn_storage_omq_port, std::array<uint16_t, 3> ss_version, uint16_t quorumnet_port, std::array<uint16_t, 3> lokinet_version, const service_nodes::service_node_keys& keys);

  Proof(const std::string& serialized_proof);
  oxenc::bt_dict bt_encode_uptime_proof() const;

  crypto::hash hash_uptime_proof() const;

  cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request generate_request() const;
};

bool operator==(const Proof& lhs, const Proof& rhs);
bool operator!=(const Proof& lhs, const Proof& rhs);

}
