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
#include "crypto/hash.h"
#include "cryptonote_basic.h"

namespace cryptonote {
struct checkpoint_t;
struct block_add_info {
    const cryptonote::block& block;
    const std::vector<transaction>& txs;
    const checkpoint_t* const checkpoint;
};
using BlockAddHook = std::function<void(const block_add_info& info)>;
struct block_post_add_info {
    const cryptonote::block& block;
    bool reorg;
    uint64_t split_height;  // Only set when reorg is true
};
using BlockPostAddHook = std::function<void(const block_post_add_info& info)>;
struct detached_info {
    uint64_t height;
    bool by_pop_blocks;
};
using BlockchainDetachedHook = std::function<void(const detached_info& info)>;
using InitHook = std::function<void()>;
struct batch_sn_payment;
struct block_reward_parts;
struct miner_tx_info {
    const cryptonote::block& block;
    const block_reward_parts& reward_parts;
    const std::vector<cryptonote::batch_sn_payment>& batched_sn_payments;
};
using ValidateMinerTxHook = std::function<void(const miner_tx_info& info)>;

struct address_parse_info {
    account_public_address address;
    bool is_subaddress;
    bool has_payment_id;
    crypto::hash8 payment_id;

    std::string as_str(network_type nettype) const;

    KV_MAP_SERIALIZABLE
};

// Strongly-typed money amount used to calculate rewards at a higher precision by a factory of
// `BATCH_REWARD_FACTOR`. Money amounts are stored at the higher precision in the DB.
struct reward_money {

    // Construct a money value from an atomic $COIN amount.
    static reward_money coin_amount(uint64_t amount) {
        return {._amount = amount * BATCH_REWARD_FACTOR};
    }

    // Construct a money value from an atomic $COIN amount denoted with the extra precision
    // (pre-multiplied with `BATCH_REWARD_FACTOR`) suitable for storing in the DB. There is more
    // precision to minimise integer division errors in reward calculations.
    static reward_money db_amount(uint64_t amount) { return {._amount = amount}; }

    constexpr uint64_t to_coin() const { return _amount / BATCH_REWARD_FACTOR; }

    constexpr uint64_t to_db() const { return _amount; }

    constexpr auto operator<=>(const reward_money& rhs) const = default;

    constexpr reward_money operator+(const reward_money& rhs) const {
        return {._amount = _amount + rhs._amount};
    }
    constexpr reward_money operator-(const reward_money& rhs) const {
        return {._amount = _amount - rhs._amount};
    }
    constexpr reward_money& operator+=(const reward_money& rhs) {
        _amount += rhs._amount;
        return *this;
    }
    constexpr reward_money& operator-=(const reward_money& rhs) {
        _amount -= rhs._amount;
        return *this;
    }

    uint64_t _amount{0};

    std::string to_string() const;
};

struct batch_sn_payment {
    cryptonote::address_parse_info address_info{};
    eth::address eth_address{};
    reward_money amount;

    batch_sn_payment() = default;
    batch_sn_payment(const cryptonote::address_parse_info& addr_info, reward_money amt) :
            address_info{addr_info}, amount{amt} {}
    batch_sn_payment(const cryptonote::account_public_address& addr, reward_money amt) :
            address_info{addr, 0}, amount{amt} {}
    batch_sn_payment(const eth::address& addr, reward_money amt) : eth_address{addr}, amount{amt} {}

    uint64_t coin_amount() const { return amount.to_coin(); }
};

#pragma pack(push, 1)
struct public_address_outer_blob {
    uint8_t m_ver;
    account_public_address m_address;
    uint8_t check_sum;
};
struct public_integrated_address_outer_blob {
    uint8_t m_ver;
    account_public_address m_address;
    crypto::hash8 payment_id;
    uint8_t check_sum;
};
#pragma pack(pop)

/************************************************************************/
/* Cryptonote helper functions                                          */
/************************************************************************/
size_t get_min_block_weight(hf version);
uint64_t block_reward_unpenalized_formula_v7(uint64_t already_generated_coins, uint64_t height);
uint64_t block_reward_unpenalized_formula_v8(uint64_t height);
bool get_base_block_reward(
        size_t median_weight,
        size_t current_block_weight,
        uint64_t already_generated_coins,
        uint64_t& reward,
        uint64_t& reward_unpenalized,
        hf version,
        uint64_t height);
uint8_t get_account_address_checksum(const public_address_outer_blob& bl);
uint8_t get_account_integrated_address_checksum(const public_integrated_address_outer_blob& bl);

std::string get_account_address_as_str(
        network_type nettype, bool subaddress, const account_public_address& adr);

std::string get_account_integrated_address_as_str(
        network_type nettype, const account_public_address& adr, const crypto::hash8& payment_id);

inline std::string address_parse_info::as_str(network_type nettype) const {
    if (has_payment_id)
        return get_account_integrated_address_as_str(nettype, address, payment_id);
    else
        return get_account_address_as_str(nettype, is_subaddress, address);
}

bool get_account_address_from_str(
        address_parse_info& info, network_type nettype, const std::string_view str);

bool operator==(const cryptonote::transaction& a, const cryptonote::transaction& b);
bool operator==(const cryptonote::block& a, const cryptonote::block& b);
}  // namespace cryptonote

template <>
inline constexpr bool formattable::via_to_string<cryptonote::reward_money> = true;
