#pragma once

#include "service_node_list.h"
#include "../cryptonote_protocol/cryptonote_protocol_defs.h"
#include <oxenmq/bt_serialize.h>

namespace uptime_proof
{

class Proof
{
  
public:
  std::array<uint16_t, 3> version;
  std::array<uint16_t, 3> storage_server_version;
  std::array<uint16_t, 3> lokinet_version;

  uint64_t timestamp;
  crypto::public_key pubkey;
  crypto::signature sig;
  crypto::ed25519_public_key pubkey_ed25519;
  crypto::ed25519_signature sig_ed25519;
  uint32_t public_ip;
  uint16_t storage_port;
  uint16_t storage_lmq_port;
  uint16_t qnet_port;

  Proof() = default;
  Proof(uint32_t sn_public_ip, uint16_t sn_storage_port, uint16_t sn_storage_lmq_port, std::array<uint16_t, 3> ss_version, uint16_t quorumnet_port, std::array<uint16_t, 3> lokinet_version, const service_nodes::service_node_keys& keys);

  Proof(const std::string& serialized_proof);
  oxenmq::bt_dict bt_encode_uptime_proof() const;

  crypto::hash hash_uptime_proof() const;

  cryptonote::NOTIFY_BTENCODED_UPTIME_PROOF::request generate_request() const;
};

}
bool operator==(const uptime_proof::Proof& lhs, const uptime_proof::Proof& rhs);
bool operator!=(const uptime_proof::Proof& lhs, const uptime_proof::Proof& rhs);
