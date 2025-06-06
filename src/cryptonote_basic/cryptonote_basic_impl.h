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

// Strongly-typed money amount used to calculate rewards at a higher precision by a factor of
// `BATCH_REWARD_FACTOR`.  Before HF22, these money amounts are stored at the higher precision in
// the DB for some fields; starting at HF22 the higher precision values are only used for
// intermediate reward calculations (to avoid potential int64 database overflow), and the final
// amount is the rounded atomic value.
struct reward_money {

    // Construct a money value from an atomic $COIN amount.
    static constexpr reward_money from_coin(int64_t amount) { return {amount, 0}; }

    // Construct a money value from an amount value stored in the database (which will either be a
    // coin value, or an intermediate value, depending on the hard fork of the height the value
    // comes from).  This is used for fields like `batched_payments_accrued.amount` and
    // `.lifetime_rewards` that can (before HF22) have subatomic amounts.
    static constexpr reward_money from_db_amount(int64_t amount, hf hf_version) {
        int_fast16_t subatomic;
        if (hf_version >= hf::hf22_eth_fixup)
            subatomic = 0;
        else {
            subatomic = amount % BATCH_REWARD_FACTOR;
            amount /= BATCH_REWARD_FACTOR;
        }
        return {amount, subatomic};
    }

    // Construct a money value from an atomic SESH amount value stored in the database.  This is for
    // fields that are always stored as atomic (not subatomic) values such as
    // `batched_payments_accrued.lifetime_locked_stakes` and the amounts in the delayed_payments
    // table.  This is effectively the same thing as from_coin, but is more descriptive and takes an
    // sqlite-compatible signed int64 instead of unsigned.
    static constexpr reward_money from_db_atomic(int64_t amount) {
        return from_coin(static_cast<int64_t>(amount));
    }

    // Construct a money value from an intermediate amount as returned by `to_intermediate()`.  This
    // is always denominated in milli-atomics and is used for higher-precision reward calculations,
    // but is not suitable for cumulative values (which could overflow the uint64_t).
    static constexpr reward_money from_intermediate(uint64_t amount) {
        return {static_cast<int64_t>(amount / BATCH_REWARD_FACTOR),
                static_cast<int_fast16_t>(amount % BATCH_REWARD_FACTOR)};
    }

    // Returns the atomic coin amount of the value, i.e. without the extra precision, cast to
    // uint64_t.
    constexpr uint64_t to_coin() const { return static_cast<uint64_t>(_atomic); }

    // Returns an intermediate reward calculation value, which is the value computed in
    // milli-atomics (to reduce rounding error on each block's reward).  This value can overflow
    // (both negative or positive), and returns std::nullopt if the result would not fit in a
    // uint64_t: this value is intended for use only with block rewards (which will fit) but not for
    // cumulative amounts.
    constexpr std::optional<uint64_t> to_intermediate() const {
        if (negative())
            return std::nullopt;
        auto uatomic = static_cast<uint64_t>(_atomic);
        // < instead of <= here because we need room to add the subatomic amount without overflowing
        if (uatomic < std::numeric_limits<uint64_t>::max() / BATCH_REWARD_FACTOR)
            return uatomic * BATCH_REWARD_FACTOR + _subatomic;
        return std::nullopt;
    }

    // Returns a truncated money_reward, i.e. a value with the same atomic value but with any
    // subatomic value dropped.
    [[nodiscard]] constexpr reward_money truncate() const { return {_atomic, 0}; }

    // Returns a rounded money_reward, i.e. a value with no subatomic units.  If subatomic is 0-499,
    // this is the same as truncate, otherwise (500-999) the returned value is 1 atomic unit higher.
    [[nodiscard]] constexpr reward_money round() const {
        return {_subatomic >= BATCH_REWARD_FACTOR / 2    ? _atomic + 1
                : _subatomic <= -BATCH_REWARD_FACTOR / 2 ? _atomic - 1
                                                         : _atomic,
                0};
    }

    // Returns true if this value amount has sub-atomic components.
    constexpr bool has_subatomic() const { return _subatomic != 0; }

    // Returns a "db" amount value for database fields that (depending on the hardfork) sometimes
    // have extra precision (see from_db_amount).  Up to HF22, this is milli-atomics, but from HF22
    // onward we store atomic values in the db (but still compute intermediate reward values in
    // milli-atomics).  Returns the value cast as int64_t because that's what actually goes into the
    // db.
    constexpr int64_t to_db_amount(hf hf_version) const {
        return hf_version >= hf::hf22_eth_fixup ? round()._atomic
                                                : _atomic * BATCH_REWARD_FACTOR + _subatomic;
    }

    // Returns a db amount for database fields that are always stored in atomic units, such as stake
    // accounting and delayed payments.  This is effectively the same as `to_coin()`, but with a
    // more descriptive name and a static_cast to signed for sqlite API compatibility.
    constexpr int64_t to_db_atomic() const { return static_cast<int64_t>(to_coin()); }

    constexpr auto operator<=>(const reward_money& rhs) const = default;

    constexpr bool negative() const { return _atomic < 0 || _subatomic < 0; }

    constexpr reward_money operator+(const reward_money& rhs) const {
        auto result = *this;
        result += rhs;
        return result;
    }
    constexpr reward_money& operator+=(const reward_money& rhs) {
        _subatomic += rhs._subatomic;
        _atomic += rhs._atomic;
        _atomic += _subatomic / BATCH_REWARD_FACTOR;
        _subatomic %= BATCH_REWARD_FACTOR;
        if (_atomic > 0 && _subatomic < 0) {
            _atomic--;
            _subatomic += BATCH_REWARD_FACTOR;
        } else if (_atomic < 0 && _subatomic > 0) {
            _atomic++;
            _subatomic -= BATCH_REWARD_FACTOR;
        }
        return *this;
    }
    constexpr reward_money operator-() const {
        return {-_atomic, static_cast<int_fast16_t>(-_subatomic)};
    }
    constexpr reward_money operator-(const reward_money& rhs) const { return *this + -rhs; }
    constexpr reward_money& operator-=(const reward_money& rhs) { return *this += -rhs; }
    constexpr reward_money operator/(int64_t N) const {
        auto result = *this;
        result /= N;
        return result;
    }
    constexpr reward_money& operator/=(int64_t N) {
        auto remainder = _atomic % N;
        _atomic /= N;
        _subatomic = (remainder * 1000 + _subatomic) / N;
        return *this;
    }

    std::string to_string() const;

    constexpr reward_money() = default;
    constexpr reward_money(const reward_money&) = default;
    constexpr reward_money(reward_money&&) = default;
    reward_money& operator=(const reward_money&) = default;
    reward_money& operator=(reward_money&&) = default;

  private:
    // Construction with a value is private: use the from_coin/_intermediate/_db_amount/_db_atomic
    // factory functions instead.
    constexpr reward_money(int64_t atomic_, int_fast16_t subatomic) :
            _atomic{atomic_}, _subatomic{subatomic} {}

    int64_t _atomic{0};
    int_fast16_t _subatomic{0};
};

struct batch_sn_payment {
    cryptonote::account_public_address address{};
    reward_money amount{};

    batch_sn_payment() = default;
    batch_sn_payment(const cryptonote::account_public_address& addr, reward_money amt) :
            address{addr}, amount{amt} {}
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
