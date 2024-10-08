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

#include "crypto/crypto.h"
#include "cryptonote_config.h"
#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "epee/net/net_utils_base.h"
#include "epee/serialization/keyvalue_serialization.h"
#include "epee/string_tools.h"
#include "net/i2p_address.h"  // needed for serialization
#include "net/tor_address.h"  // needed for serialization

namespace nodetool {
using peerid_type = uint64_t;

#pragma pack(push, 1)

struct peerlist_entry {
    epee::net_utils::network_address adr;
    peerid_type id;
    int64_t last_seen;
    uint32_t pruning_seed;

    KV_MAP_SERIALIZABLE
};

struct anchor_peerlist_entry {
    epee::net_utils::network_address adr;
    peerid_type id;
    int64_t first_seen;

    KV_MAP_SERIALIZABLE
};

struct connection_entry {
    epee::net_utils::network_address adr;
    peerid_type id;
    bool is_income;

    KV_MAP_SERIALIZABLE
};

#pragma pack(pop)

std::string print_peerlist_to_string(const std::vector<peerlist_entry>& pl);

struct network_config {
    uint32_t max_out_connection_count;
    uint32_t max_in_connection_count;
    std::chrono::milliseconds connection_timeout;
    std::chrono::milliseconds ping_connection_timeout;
    uint32_t handshake_interval;
    uint32_t packet_max_size;
    uint32_t config_id;
    uint32_t send_peerlist_sz;

    KV_MAP_SERIALIZABLE
};

struct basic_node_data {
    epee::connection_id_t network_id;
    uint32_t my_port;
    peerid_type peer_id;

    KV_MAP_SERIALIZABLE
};

inline constexpr int P2P_COMMANDS_POOL_BASE = 1000;

/************************************************************************/
/*                                                                      */
/************************************************************************/
struct COMMAND_HANDSHAKE {
    const static int ID = P2P_COMMANDS_POOL_BASE + 1;

    struct request {
        basic_node_data node_data;
        cryptonote::CORE_SYNC_DATA payload_data;

        KV_MAP_SERIALIZABLE
    };

    struct response {
        basic_node_data node_data;
        cryptonote::CORE_SYNC_DATA payload_data;
        std::vector<peerlist_entry> local_peerlist_new;

        KV_MAP_SERIALIZABLE
    };
};

/************************************************************************/
/*                                                                      */
/************************************************************************/
struct COMMAND_TIMED_SYNC {
    const static int ID = P2P_COMMANDS_POOL_BASE + 2;

    struct request {
        cryptonote::CORE_SYNC_DATA payload_data;

        KV_MAP_SERIALIZABLE
    };

    struct response {
        uint64_t local_time;
        cryptonote::CORE_SYNC_DATA payload_data;
        std::vector<peerlist_entry> local_peerlist_new;

        KV_MAP_SERIALIZABLE
    };
};

/************************************************************************/
/*                                                                      */
/************************************************************************/

struct COMMAND_PING {
    /*
      Used to make "callback" connection, to be sure that opponent node
      have accessible connection point. Only other nodes can add peer to peerlist,
      and ONLY in case when peer has accepted connection and answered to ping.
    */
    const static int ID = P2P_COMMANDS_POOL_BASE + 3;

    static constexpr auto OK_RESPONSE = "OK"sv;

    struct request {
        /*actually we don't need to send any real data*/
        KV_MAP_SERIALIZABLE
    };

    struct response {
        std::string status;
        peerid_type peer_id;

        KV_MAP_SERIALIZABLE
    };
};

/************************************************************************/
/*                                                                      */
/************************************************************************/
// TODO: remove after HF19
struct COMMAND_REQUEST_SUPPORT_FLAGS {
    const static int ID = P2P_COMMANDS_POOL_BASE + 7;

    struct request {
        KV_MAP_SERIALIZABLE
    };

    struct response {
        uint32_t support_flags;

        KV_MAP_SERIALIZABLE
    };
};
}  // namespace nodetool
