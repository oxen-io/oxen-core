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

#include <array>
#include <boost/uuid/uuid.hpp>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ratio>
#include <stdexcept>
#include <string>
#include <string_view>

using namespace std::literals;

namespace cryptonote {

/// Cryptonote protocol related constants:

inline constexpr uint64_t MAX_BLOCK_NUMBER = 500000000;
inline constexpr size_t MAX_TX_SIZE = 1000000;
inline constexpr uint64_t MAX_TX_PER_BLOCK = 0x10000000;
inline constexpr uint64_t MINED_MONEY_UNLOCK_WINDOW = 30;
inline constexpr uint64_t DEFAULT_TX_SPENDABLE_AGE = 10;
inline constexpr uint64_t TX_OUTPUT_DECOYS = 9;
inline constexpr size_t TX_BULLETPROOF_MAX_OUTPUTS = 16;

inline constexpr uint64_t BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW = 11;

inline constexpr uint64_t REWARD_BLOCKS_WINDOW = 100;
// NOTE(oxen): For testing suite, size of block (bytes) after which reward for block calculated
// using block size - before first fork:
inline constexpr uint64_t BLOCK_GRANTED_FULL_REWARD_ZONE_V1 = 20000;
// size of block (bytes) after which reward for block calculated using block size -
// second change, from v5
inline constexpr uint64_t BLOCK_GRANTED_FULL_REWARD_ZONE_V5 = 300000;
// size in blocks of the long term block weight median window
inline constexpr uint64_t LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE = 100000;
inline constexpr uint64_t SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR = 50;
inline constexpr uint64_t COINBASE_BLOB_RESERVED_SIZE = 600;

inline constexpr auto TARGET_BLOCK_TIME = 2min;
inline constexpr uint64_t BLOCKS_PER_HOUR = 1h / TARGET_BLOCK_TIME;
inline constexpr uint64_t BLOCKS_PER_DAY = 24h / TARGET_BLOCK_TIME;

inline constexpr uint64_t LOCKED_TX_ALLOWED_DELTA_BLOCKS = 1;

inline constexpr auto MEMPOOL_TX_LIVETIME = 3 * 24h;
inline constexpr auto MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME = 7 * 24h;
inline constexpr auto MEMPOOL_PRUNE_NON_STANDARD_TX_LIFETIME = 2h;
// 3 days worth of full 300kB blocks:
inline constexpr size_t DEFAULT_MEMPOOL_MAX_WEIGHT = 72h / TARGET_BLOCK_TIME * 300'000;

// Fallback used in wallet if no fee is available from RPC:
inline constexpr uint64_t FEE_PER_BYTE_V13 = 215;
// 0.005 OXEN per tx output (in addition to the per-byte fee), starting in v18:
inline constexpr uint64_t FEE_PER_OUTPUT_V18 = 5000000;
inline constexpr uint64_t DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT = 3000;
inline constexpr uint64_t FEE_QUANTIZATION_DECIMALS = 8;

// by default, blocks ids count in synchronizing
inline constexpr size_t BLOCKS_IDS_SYNCHRONIZING_DEFAULT_COUNT = 10000;
// by default, blocks count in blocks downloading
inline constexpr size_t BLOCKS_SYNCHRONIZING_DEFAULT_COUNT = 100;
// must be a power of 2, greater than 128, equal to SEEDHASH_EPOCH_BLOCKS in
// rx-slow-hash.c
inline constexpr size_t BLOCKS_SYNCHRONIZING_MAX_COUNT = 2048;

inline constexpr size_t HASH_OF_HASHES_STEP = 256;

// Hash domain separators
namespace hashkey {
    inline constexpr std::string_view BULLETPROOF_EXPONENT = "bulletproof"sv;
    inline constexpr std::string_view RINGDB = "ringdsb\0"sv;
    inline constexpr std::string_view SUBADDRESS = "SubAddr\0"sv;
    inline constexpr unsigned char ENCRYPTED_PAYMENT_ID = 0x8d;
    inline constexpr unsigned char WALLET = 0x8c;
    inline constexpr unsigned char WALLET_CACHE = 0x8d;
    inline constexpr unsigned char RPC_PAYMENT_NONCE = 0x58;
    inline constexpr unsigned char MEMORY = 'k';
    inline constexpr std::string_view MULTISIG =
            "Multisig\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00"sv;
    inline constexpr std::string_view CLSAG_ROUND = "CLSAG_round"sv;
    inline constexpr std::string_view CLSAG_AGG_0 = "CLSAG_agg_0"sv;
    inline constexpr std::string_view CLSAG_AGG_1 = "CLSAG_agg_1"sv;
}  // namespace hashkey

// Maximum allowed stake contribution, as a fraction of the available contribution room.  This
// should generally be slightly larger than 1.  This is used to disallow large overcontributions
// which can happen when there are competing stakes submitted at the same time for the same
// service node.
using MAXIMUM_ACCEPTABLE_STAKE = std::ratio<101, 100>;

// In HF19+ registrations the fee amount is a relative value out of this (for older registrations
// the fee is a portion, i.e. value out of old::STAKING_PORTIONS).  For example a registration fee
// value of 1000 corresponds to 1000/10000 = 10%.  This also implicitly defines the maximum
// precision of HF19+ registrations (i.e. to a percentage with two decimal places of precision).
inline constexpr uint64_t STAKING_FEE_BASIS = 10'000;

// We calculate and store batch rewards in thousanths of atomic OXEN, to reduce the size of errors
// from integer division of rewards.
constexpr uint64_t BATCH_REWARD_FACTOR = 1000;

// see src/cryptonote_protocol/levin_notify.cpp
inline constexpr auto NOISE_MIN_EPOCH = 5min;
inline constexpr auto NOISE_EPOCH_RANGE = 30s;
inline constexpr auto NOISE_MIN_DELAY = 10s;
inline constexpr auto NOISE_DELAY_RANGE = 5s;
inline constexpr uint64_t NOISE_BYTES = 3 * 1024;  // 3 kiB
inline constexpr size_t NOISE_CHANNELS = 2;
// ~20 * NOISE_BYTES max payload size for covert/noise send:
inline constexpr size_t MAX_FRAGMENTS = 20;

// p2p-specific constants:
namespace p2p {

    inline constexpr size_t LOCAL_WHITE_PEERLIST_LIMIT = 1000;
    inline constexpr size_t LOCAL_GRAY_PEERLIST_LIMIT = 5000;

    inline constexpr int64_t DEFAULT_CONNECTIONS_COUNT_OUT = 8;
    inline constexpr int64_t DEFAULT_CONNECTIONS_COUNT_IN = 32;
    inline constexpr auto DEFAULT_HANDSHAKE_INTERVAL = 60s;
    inline constexpr uint32_t DEFAULT_PACKET_MAX_SIZE = 50000000;
    inline constexpr uint32_t DEFAULT_PEERS_IN_HANDSHAKE = 250;
    inline constexpr auto DEFAULT_CONNECTION_TIMEOUT = 5s;
    inline constexpr auto DEFAULT_SOCKS_CONNECT_TIMEOUT = 45s;
    inline constexpr auto DEFAULT_PING_CONNECTION_TIMEOUT = 2s;
    inline constexpr auto DEFAULT_INVOKE_TIMEOUT = 2min;
    inline constexpr auto DEFAULT_HANDSHAKE_INVOKE_TIMEOUT = 5s;
    inline constexpr int DEFAULT_WHITELIST_CONNECTIONS_PERCENT = 70;
    inline constexpr size_t DEFAULT_ANCHOR_CONNECTIONS_COUNT = 2;
    inline constexpr size_t DEFAULT_SYNC_SEARCH_CONNECTIONS_COUNT = 2;
    inline constexpr int64_t DEFAULT_LIMIT_RATE_UP = 2048;    // kB/s
    inline constexpr int64_t DEFAULT_LIMIT_RATE_DOWN = 8192;  // kB/s
    inline constexpr auto FAILED_ADDR_FORGET = 1h;
    inline constexpr auto IP_BLOCK_TIME = 24h;
    inline constexpr size_t IP_FAILS_BEFORE_BLOCK = 10;
    inline constexpr auto IDLE_CONNECTION_KILL_INTERVAL = 5min;
    inline constexpr uint32_t SUPPORT_FLAG_FLUFFY_BLOCKS = 0x01;
    inline constexpr uint32_t SUPPORT_FLAGS = SUPPORT_FLAG_FLUFFY_BLOCKS;

}  // namespace p2p

// filename constants:
inline constexpr auto DATA_DIRNAME =
#ifdef _WIN32
        "oxen"sv;  // Buried in some windows filesystem maze location
#else
        ".oxen"sv;      // ~/.oxen
#endif
inline constexpr auto CONF_FILENAME = "oxen.conf"sv;
inline constexpr auto SOCKET_FILENAME = "oxend.sock"sv;
inline constexpr auto LOG_FILENAME = "oxen.log"sv;
inline constexpr auto POOLDATA_FILENAME = "poolstate.bin"sv;
inline constexpr auto BLOCKCHAINDATA_FILENAME = "data.mdb"sv;
inline constexpr auto BLOCKCHAINDATA_LOCK_FILENAME = "lock.mdb"sv;
inline constexpr auto P2P_NET_DATA_FILENAME = "p2pstate.bin"sv;
inline constexpr auto MINER_CONFIG_FILE_NAME = "miner_conf.json"sv;

inline constexpr uint64_t PRUNING_STRIPE_SIZE = 4096;    // the smaller, the smoother the increase
inline constexpr uint64_t PRUNING_LOG_STRIPES = 3;       // the higher, the more space saved
inline constexpr uint64_t PRUNING_TIP_BLOCKS = 5500;     // the smaller, the more space saved
inline constexpr bool PRUNING_DEBUG_SPOOF_SEED = false;  // For debugging only

// Constants for hardfork versions:
enum class hf : uint8_t {
    hf7 = 7,
    hf8,
    hf9_service_nodes,  // Proof Of Stake w/ Service Nodes
    hf10_bulletproofs,  // Bulletproofs, Service Node Grace Registration Period, Batched Governance
    hf11_infinite_staking,  // Infinite Staking, CN-Turtle
    hf12_checkpointing,     // Checkpointing, Relaxed Deregistration, RandomXL, Oxen Storage Server
    hf13_enforce_checkpoints,
    hf14_blink,
    hf15_ons,
    hf16_pulse,
    hf17,
    hf18,
    hf19_reward_batching,
    hf20,

    _next,
    none = 0

    // `hf` serialization is in cryptonote_basic/cryptonote_basic.h
};
constexpr auto hf_max = static_cast<hf>(static_cast<uint8_t>(hf::_next) - 1);
constexpr auto hf_prev(hf x) {
    if (x <= hf::hf7 || x > hf_max)
        return hf::none;
    return static_cast<hf>(static_cast<uint8_t>(x) - 1);
}

// This is here to make sure the numeric value of the top hf enum value is correct (i.e.
// hf20 == 20 numerically); bump this when adding a new hf.
static_assert(static_cast<uint8_t>(hf_max) == 20);

// Constants for which hardfork activates various features:
namespace feature {
    constexpr auto PER_BYTE_FEE = hf::hf10_bulletproofs;
    constexpr auto SMALLER_BP = hf::hf11_infinite_staking;
    constexpr auto LONG_TERM_BLOCK_WEIGHT = hf::hf11_infinite_staking;
    constexpr auto INCREASE_FEE = hf::hf12_checkpointing;
    constexpr auto PER_OUTPUT_FEE = hf::hf13_enforce_checkpoints;
    constexpr auto ED25519_KEY = hf::hf13_enforce_checkpoints;
    constexpr auto FEE_BURNING = hf::hf14_blink;
    constexpr auto BLINK = hf::hf14_blink;
    constexpr auto MIN_2_OUTPUTS = hf::hf16_pulse;
    constexpr auto REJECT_SIGS_IN_COINBASE = hf::hf16_pulse;
    constexpr auto ENFORCE_MIN_AGE = hf::hf16_pulse;
    constexpr auto EFFECTIVE_SHORT_TERM_MEDIAN_IN_PENALTY = hf::hf16_pulse;
    constexpr auto PULSE = hf::hf16_pulse;
    constexpr auto CLSAG = hf::hf16_pulse;
    constexpr auto PROOF_BTENC = hf::hf18;
    constexpr auto ETH_BLS = hf::hf20;
}  // namespace feature

enum class network_type : uint8_t { MAINNET = 0, TESTNET, DEVNET, FAKECHAIN, UNDEFINED = 255 };

constexpr network_type network_type_from_string(std::string_view s) {
    if (s == "mainnet")
        return network_type::MAINNET;
    if (s == "testnet")
        return network_type::TESTNET;
    if (s == "devnet")
        return network_type::DEVNET;
    if (s == "fakechain")
        return network_type::FAKECHAIN;

    return network_type::UNDEFINED;
}

constexpr std::string_view network_type_to_string(network_type t) {
    switch (t) {
        case network_type::MAINNET: return "mainnet";
        case network_type::TESTNET: return "testnet";
        case network_type::DEVNET: return "devnet";
        case network_type::FAKECHAIN: return "fakechain";
        default: return "undefined";
    }
    return "undefined";
}

// Constants for older hard-forks that are mostly irrelevant now, but are still needed to sync the
// older parts of the blockchain:
namespace old {

    // block time future time limit used in the mining difficulty algorithm:
    inline constexpr uint64_t BLOCK_FUTURE_TIME_LIMIT_V2 = 60 * 10;
    // Re-registration grace period (not used since HF11 infinite staking):
    inline constexpr uint64_t STAKING_REQUIREMENT_LOCK_BLOCKS_EXCESS = 20;
    // Before HF19, staking portions and fees (in SN registrations) are encoded as a numerator value
    // with this implied denominator:
    inline constexpr uint64_t STAKING_PORTIONS = UINT64_C(0xfffffffffffffffc);
    // Before HF19 signed registrations were only valid for two weeks:
    // TODO: After HF19 we eliminate the window-checking code entirely (as long as no expired
    // registration has ever been sent to the blockchain then it should still sync fine).
    inline constexpr std::chrono::seconds STAKING_AUTHORIZATION_EXPIRATION_WINDOW = 14 * 24h;

    // Higher fee in v12 (only, v13 switches back):
    inline constexpr uint64_t FEE_PER_BYTE_V12 = 17200;
    // 0.02 OXEN per tx output (in addition to the per-byte fee), HF13 until HF18:
    inline constexpr uint64_t FEE_PER_OUTPUT_V13 = 20000000;
    // Only v12 (v13 switches back):
    inline constexpr uint64_t DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT_V12 = 240000;
    // Dynamic fee calculations used before HF10:
    inline constexpr uint64_t DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD =
            UINT64_C(10000000000000);  // 10 * pow(10,12)
    inline constexpr uint64_t DYNAMIC_FEE_PER_KB_BASE_FEE_V5 = 400000000;

    inline constexpr uint64_t DIFFICULTY_WINDOW = 59;
    inline constexpr uint64_t DIFFICULTY_BLOCKS_COUNT(bool before_hf16) {
        // NOTE: We used to have a different setup here where,
        // DIFFICULTY_WINDOW       = 60
        // DIFFICULTY_BLOCKS_COUNT = 61
        // next_difficulty_v2's  N = DIFFICULTY_WINDOW - 1
        //
        // And we resized timestamps/difficulties to (N+1) (chopping off the latest timestamp).
        //
        // Now we re-adjust DIFFICULTY_WINDOW to 59. To preserve the old behaviour we add +2. After
        // HF16 we avoid trimming the top block and just add +1.
        //
        // Ideally, we just set DIFFICULTY_BLOCKS_COUNT to DIFFICULTY_WINDOW
        // + 1 for before and after HF16 (having one unified constant) but this requires some more
        //   investigation to get it working with pre HF16 blocks and alt chain code without bugs.
        uint64_t result = (before_hf16) ? DIFFICULTY_WINDOW + 2 : DIFFICULTY_WINDOW + 1;
        return result;
    }

    inline constexpr auto DATA_DIRNAME =
#ifdef _WIN32
            "loki"sv;  // Buried in some windows filesystem maze location
#else
            ".loki"sv;  // ~/.loki
#endif
    inline constexpr auto CONF_FILENAME = "loki.conf"sv;
    inline constexpr auto SOCKET_FILENAME = "lokid.sock"sv;

}  // namespace old

// Various configuration defaults and network-dependent settings
namespace config {
    inline constexpr uint64_t DEFAULT_DUST_THRESHOLD = 2000000000;  // 2 * pow(10, 9)

    // Used to estimate the blockchain height from a timestamp, with some grace time.  This can
    // drift slightly over time (because average block time is not typically *exactly*
    // DIFFICULTY_TARGET_V2).
    inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 582088;
    inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1595359932;

    inline constexpr uint64_t PUBLIC_ADDRESS_BASE58_PREFIX = 114;
    inline constexpr uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 115;
    inline constexpr uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX = 116;
    inline constexpr uint16_t P2P_DEFAULT_PORT = 22022;
    inline constexpr uint16_t RPC_DEFAULT_PORT = 22023;
    inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 22024;
    inline constexpr uint16_t QNET_DEFAULT_PORT = 22025;
    inline constexpr boost::uuids::uuid const NETWORK_ID = {
            {0x46,
             0x61,
             0x72,
             0x62,
             0x61,
             0x75,
             0x74,
             0x69,
             0x2a,
             0x4c,
             0x61,
             0x75,
             0x66,
             0x65,
             0x79}};  // Bender's nightmare
    inline constexpr std::string_view GENESIS_TX =
            "021e01ff000380808d93f5d771027c4fd4553bc9886f1f49e3f76d945bf71e8632a94e6c177b19cb"
            "c780e7e6bdb48080b4ccd4dfc60302c8b9f6461f58ef3f2107e577c7425d06af584a1c7482bf1906"
            "0e84059c98b4c3808088fccdbcc32302732b53b0b0db706fcc3087074fb4b786da5ab72b2065699f"
            "9453448b0db27f892101ed71f2ce3fc70d7b2036f8a4e4b3fb75c66c12184b55a908e7d1a1d69955"
            "66cf00"sv;
    inline constexpr uint32_t GENESIS_NONCE = 1022201;

    inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = 7 * cryptonote::BLOCKS_PER_DAY;
    inline constexpr std::array GOVERNANCE_WALLET_ADDRESS = {
            // hardfork v7-10:
            "LCFxT37LAogDn1jLQKf4y7aAqfi21DjovX9qyijaLYQSdrxY1U5VGcnMJMjWrD9RhjeK5Lym67wZ73uh9AujXLQ1RKmXEyL"sv,
            // hardfork v11
            "LDBEN6Ut4NkMwyaXWZ7kBEAx8X64o6YtDhLXUP26uLHyYT4nFmcaPU2Z2fauqrhTLh4Qfr61pUUZVLaTHqAdycETKM1STrz"sv,
    };

    // After a hardfork we will decommission sns but won't dereg, allowing time to update
    inline constexpr uint64_t HARDFORK_DEREGISTRATION_GRACE_PERIOD = 7 * cryptonote::BLOCKS_PER_DAY;
    // How much an uptime proof timestamp can deviate from our timestamp before we refuse it:
    inline constexpr auto UPTIME_PROOF_TOLERANCE = 5min;
    // How long to wait after startup before broadcasting a proof
    inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 30s;
    // How frequently to check whether we need to broadcast a proof
    inline constexpr auto UPTIME_PROOF_CHECK_INTERVAL = 30s;
    // How often to send proofs out to the network since the last proof we successfully sent.
    // (Approximately; this can be up to CHECK_INTERFACE/2 off in either direction).  The minimum
    // accepted time between proofs is half of this.
    inline constexpr auto UPTIME_PROOF_FREQUENCY = 1h;
    // The maximum time that we consider an uptime proof to be valid (i.e. after this time since the
    // last proof we consider the SN to be down)
    inline constexpr auto UPTIME_PROOF_VALIDITY = 2h + 5min;
    // If we don't hear any SS ping/lokinet session test failures for more than this long then we
    // start considering the SN as passing for the purpose of obligation testing until we get
    // another test result.  This should be somewhat larger than SS/lokinet's max re-test backoff
    // (2min).
    inline constexpr auto REACHABLE_MAX_FAILURE_VALIDITY = 5min;

    // Batching SN Rewards
    inline constexpr uint64_t BATCHING_INTERVAL = 2520;
    inline constexpr uint64_t MIN_BATCH_PAYMENT_AMOUNT = 1'000'000'000;  // 1 OXEN (in atomic units)
    inline constexpr uint64_t LIMIT_BATCH_OUTPUTS = 15;
    // If a node has been online for this amount of blocks they will receive SN rewards
    inline constexpr uint64_t SERVICE_NODE_PAYABLE_AFTER_BLOCKS = 720;

    // batching and SNL will save the state every STORE_LONG_TERM_STATE_INTERVAL blocks
    inline constexpr uint64_t STORE_LONG_TERM_STATE_INTERVAL = 10000;

    // Details of the ethereum smart contract managing rewards and chain its kept on
    inline constexpr uint32_t ETHEREUM_CHAIN_ID = 421614;
    inline constexpr std::string_view ETHEREUM_REWARDS_CONTRACT = "0x8E7085eEF00064D840FB69e32Ec3CC343DA98CFb";
    inline constexpr std::string_view ETHEREUM_POOL_CONTRACT = "0x7F5D426c9011Df7a98dF3Ef95C9B0dfD2bD4C191";

    namespace testnet {
        inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 339767;
        inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1595360006;
        inline constexpr uint64_t PUBLIC_ADDRESS_BASE58_PREFIX = 156;
        inline constexpr uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 157;
        inline constexpr uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX = 158;
        inline constexpr uint16_t P2P_DEFAULT_PORT = 38156;
        inline constexpr uint16_t RPC_DEFAULT_PORT = 38157;
        inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 38158;
        inline constexpr uint16_t QNET_DEFAULT_PORT = 38159;
        inline constexpr boost::uuids::uuid const NETWORK_ID = {{
                0x22,
                0x3a,
                0x78,
                0x65,
                0xe1,
                0x6f,
                0xca,
                0xb8,
                0x02,
                0xa1,
                0xdc,
                0x17,
                0x61,
                0x64,
                0x15,
                0xbe,
        }};
        inline constexpr std::string_view GENESIS_TX =
                "04011e1e01ff00018080c9db97f4fb2702fa27e905f604faa4eb084ee675faca77b0cfea9adec152"
                "6da33cae5e286f31624201dae05bf3fa1662b7fd373c92426763d921cf3745e10ee43edb510f690c"
                "656f247200000000000000000000000000000000000000000000000000000000000000000000"sv;
        inline constexpr uint32_t GENESIS_NONCE = 12345;

        inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = 1000;
        inline constexpr std::array GOVERNANCE_WALLET_ADDRESS = {
                // hardfork v7-9
                "T6Tnu9YUgVcSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M482ypm7"sv,
                // hardfork v10
                "T6Tnu9YUgVcSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M482ypm7"sv,
        };

        // Testnet uptime proofs are 6x faster than mainnet (devnet config also uses these)
        inline constexpr auto UPTIME_PROOF_FREQUENCY = 10min;
        inline constexpr auto UPTIME_PROOF_VALIDITY = 21min;
        inline constexpr uint64_t BATCHING_INTERVAL = 20;
        inline constexpr uint64_t SERVICE_NODE_PAYABLE_AFTER_BLOCKS = 4;
    }  // namespace testnet

    namespace devnet {
        inline constexpr uint64_t HEIGHT_ESTIMATE_HEIGHT = 0;
        inline constexpr time_t HEIGHT_ESTIMATE_TIMESTAMP = 1597170000;
        inline constexpr uint64_t PUBLIC_ADDRESS_BASE58_PREFIX = 3930;             // ~ dV1 .. dV3
        inline constexpr uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX = 4442;  // ~ dVA .. dVC
        inline constexpr uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX = 5850;          // ~dVa .. dVc
        inline constexpr uint16_t P2P_DEFAULT_PORT = 38856;
        inline constexpr uint16_t RPC_DEFAULT_PORT = 38857;
        inline constexpr uint16_t ZMQ_RPC_DEFAULT_PORT = 38858;
        inline constexpr uint16_t QNET_DEFAULT_PORT = 38859;
        inline constexpr boost::uuids::uuid const NETWORK_ID = {
                {0xa9,
                 0xf7,
                 0x5c,
                 0x7d,
                 0x55,
                 0x17,
                 0xcb,
                 0x6b,
                 0x5b,
                 0xf4,
                 0x63,
                 0x79,
                 0x7a,
                 0x57,
                 0xab,
                 0xd4}};
        inline constexpr std::string_view GENESIS_TX =
                "04011e1e01ff00018080c9db97f4fb2702fa27e905f604faa4eb084ee675faca77b0cfea9adec152"
                "6da33cae5e286f31624201dae05bf3fa1662b7fd373c92426763d921cf3745e10ee43edb510f690c"
                "656f247200000000000000000000000000000000000000000000000000000000000000000000"sv;
        inline constexpr uint32_t GENESIS_NONCE = 12345;

        inline constexpr uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS = 7 * BLOCKS_PER_DAY;
        inline constexpr std::array GOVERNANCE_WALLET_ADDRESS = {
                // hardfork v7-9
                "dV3EhSE1xXgSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M4A7Uimp"sv,
                // hardfork v10
                "dV3EhSE1xXgSzswBgVioqFNTfcqGopvTrcYjs4YDLHUfU64DuHxFoEmbwoyipTidGiTXx5EuYdgzZhDLMTo9uEv82M4A7Uimp"sv,
        };

        inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 5s;
    }  // namespace devnet

    namespace fakechain {
        // Fakechain uptime proofs are 60x faster than mainnet, because this really only runs on a
        // hand-crafted, typically local temporary network.
        inline constexpr auto UPTIME_PROOF_STARTUP_DELAY = 5s;
        inline constexpr auto UPTIME_PROOF_CHECK_INTERVAL = 5s;
        inline constexpr auto UPTIME_PROOF_FREQUENCY = 1min;
        inline constexpr auto UPTIME_PROOF_VALIDITY = 2min + 5s;
    }  // namespace fakechain
}  // namespace config

struct network_config {
    network_type NETWORK_TYPE;
    uint64_t HEIGHT_ESTIMATE_HEIGHT;
    time_t HEIGHT_ESTIMATE_TIMESTAMP;
    uint64_t PUBLIC_ADDRESS_BASE58_PREFIX;
    uint64_t PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
    uint64_t PUBLIC_SUBADDRESS_BASE58_PREFIX;
    uint16_t P2P_DEFAULT_PORT;
    uint16_t RPC_DEFAULT_PORT;
    uint16_t ZMQ_RPC_DEFAULT_PORT;
    uint16_t QNET_DEFAULT_PORT;
    boost::uuids::uuid NETWORK_ID;
    std::string_view GENESIS_TX;
    uint32_t GENESIS_NONCE;
    uint64_t GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS;
    std::array<std::string_view, 2> GOVERNANCE_WALLET_ADDRESS;

    std::chrono::seconds UPTIME_PROOF_TOLERANCE;
    std::chrono::seconds UPTIME_PROOF_STARTUP_DELAY;
    std::chrono::seconds UPTIME_PROOF_CHECK_INTERVAL;
    std::chrono::seconds UPTIME_PROOF_FREQUENCY;
    std::chrono::seconds UPTIME_PROOF_VALIDITY;

    uint64_t BATCHING_INTERVAL;
    uint64_t MIN_BATCH_PAYMENT_AMOUNT;
    uint64_t LIMIT_BATCH_OUTPUTS;
    uint64_t SERVICE_NODE_PAYABLE_AFTER_BLOCKS;

    uint64_t HARDFORK_DEREGISTRATION_GRACE_PERIOD;

    uint64_t STORE_LONG_TERM_STATE_INTERVAL;

    uint32_t ETHEREUM_CHAIN_ID;
    std::string_view ETHEREUM_REWARDS_CONTRACT;
    std::string_view ETHEREUM_POOL_CONTRACT;

    inline constexpr std::string_view governance_wallet_address(hf hard_fork_version) const {
        const auto wallet_switch =
                (NETWORK_TYPE == network_type::MAINNET || NETWORK_TYPE == network_type::FAKECHAIN)
                        ? hf::hf11_infinite_staking
                        : hf::hf10_bulletproofs;
        return GOVERNANCE_WALLET_ADDRESS[hard_fork_version >= wallet_switch ? 1 : 0];
    }
};
inline constexpr network_config mainnet_config{
        network_type::MAINNET,
        config::HEIGHT_ESTIMATE_HEIGHT,
        config::HEIGHT_ESTIMATE_TIMESTAMP,
        config::PUBLIC_ADDRESS_BASE58_PREFIX,
        config::PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        config::PUBLIC_SUBADDRESS_BASE58_PREFIX,
        config::P2P_DEFAULT_PORT,
        config::RPC_DEFAULT_PORT,
        config::ZMQ_RPC_DEFAULT_PORT,
        config::QNET_DEFAULT_PORT,
        config::NETWORK_ID,
        config::GENESIS_TX,
        config::GENESIS_NONCE,
        config::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
        config::GOVERNANCE_WALLET_ADDRESS,
        config::UPTIME_PROOF_TOLERANCE,
        config::UPTIME_PROOF_STARTUP_DELAY,
        config::UPTIME_PROOF_CHECK_INTERVAL,
        config::UPTIME_PROOF_FREQUENCY,
        config::UPTIME_PROOF_VALIDITY,
        config::BATCHING_INTERVAL,
        config::MIN_BATCH_PAYMENT_AMOUNT,
        config::LIMIT_BATCH_OUTPUTS,
        config::SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
        config::HARDFORK_DEREGISTRATION_GRACE_PERIOD,
        config::STORE_LONG_TERM_STATE_INTERVAL,
        config::ETHEREUM_CHAIN_ID,
        config::ETHEREUM_REWARDS_CONTRACT,
        config::ETHEREUM_POOL_CONTRACT,
};
inline constexpr network_config testnet_config{
        network_type::TESTNET,
        config::testnet::HEIGHT_ESTIMATE_HEIGHT,
        config::testnet::HEIGHT_ESTIMATE_TIMESTAMP,
        config::testnet::PUBLIC_ADDRESS_BASE58_PREFIX,
        config::testnet::PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        config::testnet::PUBLIC_SUBADDRESS_BASE58_PREFIX,
        config::testnet::P2P_DEFAULT_PORT,
        config::testnet::RPC_DEFAULT_PORT,
        config::testnet::ZMQ_RPC_DEFAULT_PORT,
        config::testnet::QNET_DEFAULT_PORT,
        config::testnet::NETWORK_ID,
        config::testnet::GENESIS_TX,
        config::testnet::GENESIS_NONCE,
        config::testnet::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
        config::testnet::GOVERNANCE_WALLET_ADDRESS,
        config::UPTIME_PROOF_TOLERANCE,
        config::UPTIME_PROOF_STARTUP_DELAY,
        config::UPTIME_PROOF_CHECK_INTERVAL,
        config::testnet::UPTIME_PROOF_FREQUENCY,
        config::testnet::UPTIME_PROOF_VALIDITY,
        config::testnet::BATCHING_INTERVAL,
        config::MIN_BATCH_PAYMENT_AMOUNT,
        config::LIMIT_BATCH_OUTPUTS,
        config::testnet::SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
        config::HARDFORK_DEREGISTRATION_GRACE_PERIOD,
        config::STORE_LONG_TERM_STATE_INTERVAL,
        config::ETHEREUM_CHAIN_ID,
        config::ETHEREUM_REWARDS_CONTRACT,
        config::ETHEREUM_POOL_CONTRACT,
};
inline constexpr network_config devnet_config{
        network_type::DEVNET,
        config::devnet::HEIGHT_ESTIMATE_HEIGHT,
        config::devnet::HEIGHT_ESTIMATE_TIMESTAMP,
        config::devnet::PUBLIC_ADDRESS_BASE58_PREFIX,
        config::devnet::PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        config::devnet::PUBLIC_SUBADDRESS_BASE58_PREFIX,
        config::devnet::P2P_DEFAULT_PORT,
        config::devnet::RPC_DEFAULT_PORT,
        config::devnet::ZMQ_RPC_DEFAULT_PORT,
        config::devnet::QNET_DEFAULT_PORT,
        config::devnet::NETWORK_ID,
        config::devnet::GENESIS_TX,
        config::devnet::GENESIS_NONCE,
        config::devnet::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
        config::devnet::GOVERNANCE_WALLET_ADDRESS,
        config::UPTIME_PROOF_TOLERANCE,
        config::UPTIME_PROOF_STARTUP_DELAY,
        config::UPTIME_PROOF_CHECK_INTERVAL,
        config::testnet::UPTIME_PROOF_FREQUENCY,
        config::testnet::UPTIME_PROOF_VALIDITY,
        config::testnet::BATCHING_INTERVAL,
        config::MIN_BATCH_PAYMENT_AMOUNT,
        config::LIMIT_BATCH_OUTPUTS,
        config::testnet::SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
        config::HARDFORK_DEREGISTRATION_GRACE_PERIOD,
        config::STORE_LONG_TERM_STATE_INTERVAL,
        config::ETHEREUM_CHAIN_ID,
        config::ETHEREUM_REWARDS_CONTRACT,
        config::ETHEREUM_POOL_CONTRACT,
};
inline constexpr network_config fakenet_config{
        network_type::FAKECHAIN,
        config::HEIGHT_ESTIMATE_HEIGHT,
        config::HEIGHT_ESTIMATE_TIMESTAMP,
        config::PUBLIC_ADDRESS_BASE58_PREFIX,
        config::PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX,
        config::PUBLIC_SUBADDRESS_BASE58_PREFIX,
        config::P2P_DEFAULT_PORT,
        config::RPC_DEFAULT_PORT,
        config::ZMQ_RPC_DEFAULT_PORT,
        config::QNET_DEFAULT_PORT,
        config::NETWORK_ID,
        config::GENESIS_TX,
        config::GENESIS_NONCE,
        100,  //::config::GOVERNANCE_REWARD_INTERVAL_IN_BLOCKS,
        config::GOVERNANCE_WALLET_ADDRESS,
        config::UPTIME_PROOF_TOLERANCE,
        config::fakechain::UPTIME_PROOF_STARTUP_DELAY,
        config::fakechain::UPTIME_PROOF_CHECK_INTERVAL,
        config::fakechain::UPTIME_PROOF_FREQUENCY,
        config::fakechain::UPTIME_PROOF_VALIDITY,
        config::testnet::BATCHING_INTERVAL,
        config::MIN_BATCH_PAYMENT_AMOUNT,
        config::LIMIT_BATCH_OUTPUTS,
        config::testnet::SERVICE_NODE_PAYABLE_AFTER_BLOCKS,
        config::HARDFORK_DEREGISTRATION_GRACE_PERIOD,
        config::STORE_LONG_TERM_STATE_INTERVAL,
        config::ETHEREUM_CHAIN_ID,
        config::ETHEREUM_REWARDS_CONTRACT,
        config::ETHEREUM_POOL_CONTRACT,
};

inline constexpr const network_config& get_config(network_type nettype) {
    switch (nettype) {
        case network_type::MAINNET: return mainnet_config;
        case network_type::TESTNET: return testnet_config;
        case network_type::DEVNET: return devnet_config;
        case network_type::FAKECHAIN: return fakenet_config;
        default: throw std::runtime_error{"Invalid network type"};
    }
}

}  // namespace cryptonote
