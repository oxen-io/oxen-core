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

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <ratio>
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

inline constexpr uint64_t DEFAULT_DUST_THRESHOLD = 2'000'000'000;  // 2 * pow(10, 9)

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

inline constexpr uint64_t LOCKED_TX_ALLOWED_DELTA_BLOCKS = 1;

inline constexpr auto MEMPOOL_TX_LIVETIME = 3 * 24h;
inline constexpr auto MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME = 7 * 24h;
inline constexpr auto MEMPOOL_PRUNE_NON_STANDARD_TX_LIFETIME = 2h;
// 3 days worth of full 300kB blocks:
inline constexpr size_t DEFAULT_MEMPOOL_MAX_WEIGHT = 72h / 2min * 300'000;

// The default L2 provider refresh parameters (these can be changed via command-line or the config
// file).
//
// How long between attempts to refresh the L2 provider state:
inline constexpr auto ETH_L2_DEFAULT_REFRESH = 1min;
// How long until we consider an L2 request to have timed out:
inline constexpr auto ETH_L2_DEFAULT_REQUEST_TIMEOUT = 5s;
// The default value for the maximum number of ethereum Logs we will request for updated smart
// contract state in a single request.  If more than this are required multiple requests will be
// used to retrieve the logs.  Can be adjusted at runtime using the --l2-max-logs command
// line/config file setting.
inline constexpr auto ETH_L2_DEFAULT_MAX_LOGS = 1000;
// When refreshing, this controls how often we get heights from *all* configured L2 providers
// (instead of just the primary one) to check whether L2 providers are in sync.  (This only applies
// when multiple L2 providers are in use).
inline constexpr auto ETH_L2_DEFAULT_CHECK_INTERVAL = 2min + 50s;
// How much an L2 provider must be behind (in blocks) the best L2 provider height before we consider
// that provider out of sync and prefer a backup.  (120 blocks as the default corresponds to being
// 30s out of sync on Arbitrum).
inline constexpr int ETH_L2_DEFAULT_CHECK_THRESHOLD = 120;

// HF21 Oxen block parameters:
//
// How many blocks are used to compute the actual block reward rate.  The smallest l2_reward from
// the last L2_REWARD_CONSENSUS_BLOCKS blocks is used for the block reward.
inline constexpr uint64_t L2_REWARD_CONSENSUS_BLOCKS = 15;

// The maximum relative increase in l2_reward allowed from one block to the next.  If the true
// l2_reward of a block is higher than this (relative to the previous block) then this cap applies
// to the value broadcast to the blockchain.  The value is the denominator, N, that determines the
// maximum increase CURRENT/N.  (And so 50000 = maximum block-to-block increase of 0.002%).
inline constexpr uint64_t L2_REWARD_MAX_INCREASE_DIVISOR = 50000;

// The maximum relative decrease in l2_reward allowed from one block to the next.  Normally the pool
// contract reward cannot drop more than 0.000057% per block (0.151 / 365 / 720), but erroneous L2
// values or a malicious node could attempt to increase it and so a larger decrease is permitted as
// a safety measure to guard the chain against such occurrences.  As with the above, this is the
// denominator N that defines the max decrease CURR/N.  (And so 25000 = maximum block-to-block
// decrease of 0.004%).
inline constexpr uint64_t L2_REWARD_MAX_DECREASE_DIVISOR = 25000;

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

// We calculate and store batch rewards in thousanths of atomic OXEN/SENT, to reduce the size of
// errors from integer division of rewards.
constexpr uint64_t BATCH_REWARD_FACTOR = 1000;

// If we don't hear any SS ping/lokinet session test failures for more than this long then we
// start considering the SN as passing for the purpose of obligation testing until we get
// another test result.  This should be somewhat larger than SS/lokinet's max re-test backoff
// (2min).
inline constexpr auto REACHABLE_MAX_FAILURE_VALIDITY = 5min;

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
inline const std::filesystem::path DATA_DIRNAME{
#ifdef _WIN32
        u8"oxen"  // Buried in some windows filesystem maze location
#else
        u8".oxen"  // ~/.oxen
#endif
};
inline const std::filesystem::path CONF_FILENAME{u8"oxen.conf"};
inline const std::filesystem::path SOCKET_FILENAME{u8"oxend.sock"};
inline const std::filesystem::path LOG_FILENAME{u8"oxen.log"};
inline const std::filesystem::path POOLDATA_FILENAME{u8"poolstate.bin"};
inline const std::filesystem::path BLOCKCHAINDATA_FILENAME{u8"data.mdb"};
inline const std::filesystem::path BLOCKCHAINDATA_LOCK_FILENAME{u8"lock.mdb"};
inline const std::filesystem::path P2P_NET_DATA_FILENAME{u8"p2pstate.bin"};
inline const std::filesystem::path MINER_CONFIG_FILE_NAME{u8"miner_conf.json"};

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
    hf20_eth_transition,  // Temp period: registrations disabled, BLS pubkeys in proofs
    hf21_eth,             // Full transition: registrations from ETH

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
// hf21_sent == 21 numerically); bump this when adding a new hf.
static_assert(static_cast<uint8_t>(hf_max) == 21);

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
    constexpr auto ETH_TRANSITION = hf::hf20_eth_transition;
    constexpr auto ETH_BLS = hf::hf21_eth;
    constexpr auto SN_PK_IS_ED25519 = hf::hf21_eth;
}  // namespace feature

enum class network_type : uint8_t {
    MAINNET = 0,
    TESTNET,
    DEVNET,
    STAGENET,
    LOCALDEV,
    FAKECHAIN,
    UNDEFINED = 255
};

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

    inline const std::filesystem::path DATA_DIRNAME{
#ifdef _WIN32
            u8"loki"  // Buried in some windows filesystem maze location
#else
            u8".loki"  // ~/.loki
#endif
    };
    inline const std::filesystem::path CONF_FILENAME{u8"loki.conf"};
    inline const std::filesystem::path SOCKET_FILENAME{u8"lokid.sock"};

}  // namespace old

}  // namespace cryptonote
