// Copyright (c) 2014-2019, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// 
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <list>
#include "serialization/keyvalue_serialization.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "net/net_utils_base.h"
#include "cryptonote_basic/blobdatatype.h"

#include "common/loki.h"

namespace service_nodes
{
  struct legacy_deregister_vote;
  struct quorum_vote_t;
  void vote_to_blob(const quorum_vote_t& vote, unsigned char blob[]);
  void blob_to_vote(const unsigned char blob[], quorum_vote_t& vote);
};

namespace cryptonote
{


#define BC_COMMANDS_POOL_BASE 2000

  /************************************************************************/
  /* P2P connection info, serializable to json                            */
  /************************************************************************/
  struct connection_info
  {
    bool incoming;
    bool localhost;
    bool local_ip;
    bool ssl;

    std::string address;
    std::string host;
    std::string ip;
    std::string port;
    uint16_t rpc_port;

    std::string peer_id;

    uint64_t recv_count;
    uint64_t recv_idle_time;

    uint64_t send_count;
    uint64_t send_idle_time;

    std::string state;

    uint64_t live_time;

	uint64_t avg_download;
	uint64_t current_download;
	
	uint64_t avg_upload;
	uint64_t current_upload;
  
	uint32_t support_flags;

	std::string connection_id;

    uint64_t height;

    uint32_t pruning_seed;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(incoming)
      KV_SERIALIZE(localhost)
      KV_SERIALIZE(local_ip)
      KV_SERIALIZE(address)
      KV_SERIALIZE(host)
      KV_SERIALIZE(ip)
      KV_SERIALIZE(port)
      KV_SERIALIZE(rpc_port)
      KV_SERIALIZE(peer_id)
      KV_SERIALIZE(recv_count)
      KV_SERIALIZE(recv_idle_time)
      KV_SERIALIZE(send_count)
      KV_SERIALIZE(send_idle_time)
      KV_SERIALIZE(state)
      KV_SERIALIZE(live_time)
      KV_SERIALIZE(avg_download)
      KV_SERIALIZE(current_download)
      KV_SERIALIZE(avg_upload)
      KV_SERIALIZE(current_upload)
      KV_SERIALIZE(support_flags)
      KV_SERIALIZE(connection_id)
      KV_SERIALIZE(height)
      KV_SERIALIZE(pruning_seed)
    END_KV_SERIALIZE_MAP()
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  LOKI_RPC_DOC_INTROSPECT
  struct serializable_blink_metadata {
    crypto::hash tx_hash;
    uint64_t height;
    std::vector<uint8_t> quorum;
    std::vector<uint8_t> position;
    std::vector<crypto::signature> signature;
    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE_VAL_POD_AS_BLOB_N(tx_hash, "#")
      KV_SERIALIZE_N(height, "h")
      KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(quorum, "q")
      KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(position, "p")
      KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(signature, "s")
    END_KV_SERIALIZE_MAP()
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  LOKI_RPC_DOC_INTROSPECT
  struct block_complete_entry
  {
    blobdata block;
    std::vector<blobdata> txs;
    blobdata checkpoint;
    std::vector<serializable_blink_metadata> blinks;
    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(block)
      KV_SERIALIZE(txs)
      KV_SERIALIZE(checkpoint)
      KV_SERIALIZE(blinks)
    END_KV_SERIALIZE_MAP()
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_NEW_TRANSACTIONS
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 2;

    struct request
    {
      std::vector<blobdata> txs;
      std::vector<serializable_blink_metadata> blinks;
      bool requested = false;
      std::string _; // padding

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(txs)
        KV_SERIALIZE(blinks)
        KV_SERIALIZE_OPT(requested, false)
        KV_SERIALIZE(_)
      END_KV_SERIALIZE_MAP()
    };
  };
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_REQUEST_GET_BLOCKS
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 3;

    struct request
    {
      std::vector<crypto::hash> blocks;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB(blocks)
      END_KV_SERIALIZE_MAP()
    };
  };

  struct NOTIFY_RESPONSE_GET_BLOCKS
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 4;

    struct request
    {
      std::vector<block_complete_entry>  blocks;
      std::vector<crypto::hash>          missed_ids;
      uint64_t                           current_blockchain_height;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(blocks)
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB(missed_ids)
        KV_SERIALIZE(current_blockchain_height)
      END_KV_SERIALIZE_MAP()
    };
  };


  struct CORE_SYNC_DATA
  {
    uint64_t current_height;
    uint64_t cumulative_difficulty;
    crypto::hash  top_id;
    uint8_t top_version;
    uint32_t pruning_seed;
    std::vector<uint64_t> blink_blocks;
    std::vector<crypto::hash> blink_hash;

    BEGIN_KV_SERIALIZE_MAP()
      KV_SERIALIZE(current_height)
      KV_SERIALIZE(cumulative_difficulty)
      KV_SERIALIZE_VAL_POD_AS_BLOB(top_id)
      KV_SERIALIZE_OPT(top_version, (uint8_t)0)
      KV_SERIALIZE_OPT(pruning_seed, (uint32_t)0)
      KV_SERIALIZE(blink_blocks)
      KV_SERIALIZE_CONTAINER_POD_AS_BLOB(blink_hash)
    END_KV_SERIALIZE_MAP()
  };

  struct NOTIFY_REQUEST_CHAIN
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 6;

    struct request
    {
      std::list<crypto::hash> block_ids; // IDs of blocks at linear then exponential drop off, ending in genesis block; see blockchain.cpp for details

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB(block_ids)
      END_KV_SERIALIZE_MAP()
    };
  };

  struct NOTIFY_RESPONSE_CHAIN_ENTRY
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 7;

    struct request
    {
      uint64_t start_height;
      uint64_t total_height;
      uint64_t cumulative_difficulty;
      std::vector<crypto::hash> m_block_ids;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(start_height)
        KV_SERIALIZE(total_height)
        KV_SERIALIZE(cumulative_difficulty)
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB(m_block_ids)
      END_KV_SERIALIZE_MAP()
    };
  };
  
  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_NEW_FLUFFY_BLOCK
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 8;

    struct request
    {
      block_complete_entry b;
      uint64_t current_blockchain_height;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(b)
        KV_SERIALIZE(current_blockchain_height)
      END_KV_SERIALIZE_MAP()
    };
  };  

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_REQUEST_FLUFFY_MISSING_TX
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 9;

    struct request
    {
      crypto::hash block_hash;
      uint64_t current_blockchain_height;      
      std::vector<uint64_t> missing_tx_indices;
      
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_VAL_POD_AS_BLOB(block_hash)
        KV_SERIALIZE(current_blockchain_height)
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB(missing_tx_indices)
      END_KV_SERIALIZE_MAP()
    };
  }; 

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_UPTIME_PROOF
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 11;

    struct request
    {
      std::array<uint16_t, 3> snode_version;

      uint64_t timestamp;
      crypto::public_key pubkey;
      crypto::signature sig;
      crypto::ed25519_public_key pubkey_ed25519;
      crypto::ed25519_signature sig_ed25519;
      uint32_t public_ip;
      uint16_t storage_port;
      uint16_t qnet_port;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_N(snode_version[0], "snode_version_major")
        KV_SERIALIZE_N(snode_version[1], "snode_version_minor")
        KV_SERIALIZE_N(snode_version[2], "snode_version_patch")
        KV_SERIALIZE(timestamp)
        KV_SERIALIZE(public_ip)
        KV_SERIALIZE(storage_port)
        KV_SERIALIZE(qnet_port)
        KV_SERIALIZE_VAL_POD_AS_BLOB(pubkey)
        KV_SERIALIZE_VAL_POD_AS_BLOB(sig)
        KV_SERIALIZE_VAL_POD_AS_BLOB(pubkey_ed25519)
        KV_SERIALIZE_VAL_POD_AS_BLOB(sig_ed25519)
      END_KV_SERIALIZE_MAP()
    };
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  // TODO(loki) - remove this after HF14
  struct NOTIFY_NEW_SERVICE_NODE_VOTE_OLD
  {
  private:
    struct alignas(8) blob { unsigned char data[120]; };
  public:
    const static int ID = BC_COMMANDS_POOL_BASE + 12;
    struct request
    {
      std::vector<service_nodes::quorum_vote_t> votes;

      BEGIN_KV_SERIALIZE_MAP()
        auto &votes = this_ref.votes;

        std::vector<blob> vote_blobs;
        if (is_store) // means: "serializing".  Hate epee 2x: this is both badly named, and gross template parameter misuse.
        {
          vote_blobs.resize(votes.size());
          for (size_t i = 0; i < votes.size(); i++)
            vote_to_blob(votes[i], vote_blobs[i].data);
        }
        // Hate epee some more: this time for deficient serialization macros:
        //KV_SERIALIZE_CONTAINER_POD_AS_BLOB_N(vote_blobs, "votes");
        epee::serialization::selector<is_store>::serialize_stl_container_pod_val_as_blob(vote_blobs, stg, hparent_section, "votes");
        if (!is_store)
        {
          // Hate epee even more:
          auto &v = const_cast<std::vector<service_nodes::quorum_vote_t>&>(votes);
          v.resize(vote_blobs.size());
          for (size_t i = 0; i < v.size(); i++)
            blob_to_vote(vote_blobs[i].data, v[i]);
        }
      END_KV_SERIALIZE_MAP()
    };
  };


  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_REQUEST_BLOCK_BLINKS
  {
    constexpr static int ID = BC_COMMANDS_POOL_BASE + 13;
    struct request
    {
      std::vector<uint64_t> heights;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(heights)
      END_KV_SERIALIZE_MAP()
    };
  };

  struct NOTIFY_RESPONSE_BLOCK_BLINKS
  {
    constexpr static int ID = BC_COMMANDS_POOL_BASE + 14;
    struct request
    {
      std::vector<crypto::hash> txs;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB(txs)
      END_KV_SERIALIZE_MAP()
    };
  };

  /************************************************************************/
  /*                                                                      */
  /************************************************************************/
  struct NOTIFY_REQUEST_GET_TXS
  {
    constexpr static int ID = BC_COMMANDS_POOL_BASE + 15;

    struct request
    {
      std::vector<crypto::hash> txs;
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE_CONTAINER_POD_AS_BLOB(txs)
      END_KV_SERIALIZE_MAP()
    };
  };

  struct NOTIFY_NEW_SERVICE_NODE_VOTE
  {
    const static int ID = BC_COMMANDS_POOL_BASE + 16;
    struct request
    {
      std::vector<service_nodes::quorum_vote_t> votes;

      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(votes)
      END_KV_SERIALIZE_MAP()
    };
  };
}
