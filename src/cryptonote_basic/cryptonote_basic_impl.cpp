// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2018, The Loki Project
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

#include "cryptonote_basic_impl.h"

#include <cfenv>

#include "common/base58.h"
#include "common/oxen.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "cryptonote_format_utils.h"
#include "epee/int-util.h"
#include "epee/string_tools.h"
#include "logging/oxen_logger.h"
#include "networks.h"
#include "serialization/binary_utils.h"
#include "serialization/container.h"

namespace cryptonote {

static auto logcat = log::Cat("cn");

struct integrated_address {
    account_public_address adr;
    crypto::hash8 payment_id;

    BEGIN_SERIALIZE_OBJECT()
    FIELD(adr)
    FIELD(payment_id)
    END_SERIALIZE()
};

/************************************************************************/
/* Cryptonote helper functions                                          */
/************************************************************************/
//-----------------------------------------------------------------------------------------------
size_t get_min_block_weight(hf /*version*/) {
    return BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
}
//-----------------------------------------------------------------------------------------------
// TODO(oxen): Move into oxen_economy, this will require access to oxen::exp2
uint64_t block_reward_unpenalized_formula_v7(
        uint64_t already_generated_coins, uint64_t /*height*/) {
    uint64_t emission_supply_component =
            (already_generated_coins * oxen::EMISSION_SUPPLY_MULTIPLIER) /
            oxen::EMISSION_SUPPLY_DIVISOR;
    uint64_t result =
            (oxen::EMISSION_LINEAR_BASE - emission_supply_component) / oxen::EMISSION_DIVISOR;

    // Check if we just overflowed
    if (emission_supply_component > oxen::EMISSION_LINEAR_BASE)
        result = 0;
    return result;
}

uint64_t block_reward_unpenalized_formula_v8(uint64_t height) {
    std::fesetround(FE_TONEAREST);
    uint64_t result = 28'000'000'000. +
                      100'000'000'000. / oxen::exp2(height / (720. * 90));  // halve every 90 days.
    return result;
}

bool get_base_block_reward(
        size_t median_weight,
        size_t current_block_weight,
        uint64_t already_generated_coins,
        uint64_t& reward,
        uint64_t& reward_unpenalized,
        hf version,
        uint64_t height) {

    // premine reward
    if (already_generated_coins == 0) {
        reward = 22'500'000 * oxen::COIN;
        return true;
    }

    uint64_t base_reward = version >= hf::hf17     ? oxen::BLOCK_REWARD_HF17
                         : version >= hf::hf15_ons ? oxen::BLOCK_REWARD_HF15
                         : version >= hf::hf8      ? block_reward_unpenalized_formula_v8(height)
                                                   : block_reward_unpenalized_formula_v7(
                                                        already_generated_coins, height);

    uint64_t full_reward_zone = get_min_block_weight(version);

    // make it soft
    if (median_weight < full_reward_zone) {
        median_weight = full_reward_zone;
    }

    if (current_block_weight <= median_weight) {
        reward = reward_unpenalized = base_reward;
        return true;
    }

    if (current_block_weight > 2 * median_weight) {
        log::error(
                logcat,
                "Block cumulative weight is too big: {}, expected less than {}",
                current_block_weight,
                2 * median_weight);
        return false;
    }

    assert(median_weight < std::numeric_limits<uint32_t>::max());
    assert(current_block_weight < std::numeric_limits<uint32_t>::max());

    uint64_t product_hi;
    // BUGFIX: 32-bit saturation bug (e.g. ARM7), the result was being
    // treated as 32-bit by default.
    uint64_t multiplicand = 2 * median_weight - current_block_weight;
    multiplicand *= current_block_weight;
    uint64_t product_lo = mul128(base_reward, multiplicand, &product_hi);

    uint64_t reward_hi;
    uint64_t reward_lo;
    div128_32(product_hi, product_lo, static_cast<uint32_t>(median_weight), &reward_hi, &reward_lo);
    div128_32(reward_hi, reward_lo, static_cast<uint32_t>(median_weight), &reward_hi, &reward_lo);
    assert(0 == reward_hi);
    assert(reward_lo < base_reward);

    reward_unpenalized = base_reward;
    reward = reward_lo;
    return true;
}
//------------------------------------------------------------------------------------
uint8_t get_account_address_checksum(const public_address_outer_blob& bl) {
    const unsigned char* pbuf = reinterpret_cast<const unsigned char*>(&bl);
    uint8_t summ = 0;
    for (size_t i = 0; i != sizeof(public_address_outer_blob) - 1; i++)
        summ += pbuf[i];

    return summ;
}
//------------------------------------------------------------------------------------
uint8_t get_account_integrated_address_checksum(const public_integrated_address_outer_blob& bl) {
    const unsigned char* pbuf = reinterpret_cast<const unsigned char*>(&bl);
    uint8_t summ = 0;
    for (size_t i = 0; i != sizeof(public_integrated_address_outer_blob) - 1; i++)
        summ += pbuf[i];

    return summ;
}
//-----------------------------------------------------------------------
std::string get_account_address_as_str(
        network_type nettype, bool subaddress, account_public_address const& adr) {
    auto& conf = get_config(nettype);
    uint64_t address_prefix =
            subaddress ? conf.PUBLIC_SUBADDRESS_BASE58_PREFIX : conf.PUBLIC_ADDRESS_BASE58_PREFIX;

    return tools::base58::encode_addr(address_prefix, t_serializable_object_to_blob(adr));
}
//-----------------------------------------------------------------------
std::string get_account_integrated_address_as_str(
        network_type nettype, account_public_address const& adr, crypto::hash8 const& payment_id) {
    uint64_t integrated_address_prefix =
            get_config(nettype).PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;

    integrated_address iadr = {adr, payment_id};
    return tools::base58::encode_addr(
            integrated_address_prefix, t_serializable_object_to_blob(iadr));
}
//-----------------------------------------------------------------------
bool get_account_address_from_str(
        address_parse_info& info, network_type nettype, const std::string_view str) {
    auto& conf = get_config(nettype);
    uint64_t address_prefix = conf.PUBLIC_ADDRESS_BASE58_PREFIX;
    uint64_t integrated_address_prefix = conf.PUBLIC_INTEGRATED_ADDRESS_BASE58_PREFIX;
    uint64_t subaddress_prefix = conf.PUBLIC_SUBADDRESS_BASE58_PREFIX;

    std::string data;
    uint64_t prefix{0};
    if (!tools::base58::decode_addr(str, prefix, data)) {
        log::debug(logcat, "Invalid address format");
        return false;
    }

    if (integrated_address_prefix == prefix) {
        info.is_subaddress = false;
        info.has_payment_id = true;
    } else if (address_prefix == prefix) {
        info.is_subaddress = false;
        info.has_payment_id = false;
    } else if (subaddress_prefix == prefix) {
        info.is_subaddress = true;
        info.has_payment_id = false;
    } else {
        log::info(
                logcat,
                "Wrong address prefix: {}, expected {} or {} or {}",
                prefix,
                address_prefix,
                integrated_address_prefix,
                subaddress_prefix);
        return false;
    }

    try {
        if (info.has_payment_id) {
            integrated_address iadr;
            serialization::parse_binary(data, iadr);
            info.address = iadr.adr;
            info.payment_id = iadr.payment_id;
        } else {
            serialization::parse_binary(data, info.address);
        }
    } catch (const std::exception& e) {
        log::info(logcat, "Account public address keys can't be parsed: {}", e.what());
        return false;
    }

    if (!crypto::check_key(info.address.m_spend_public_key) ||
        !crypto::check_key(info.address.m_view_public_key)) {
        log::info(logcat, "Failed to validate address keys");
        return false;
    }

    return true;
}
//--------------------------------------------------------------------------------
bool operator==(const cryptonote::transaction& a, const cryptonote::transaction& b) {
    return cryptonote::get_transaction_hash(a) == cryptonote::get_transaction_hash(b);
}

bool operator==(const cryptonote::block& a, const cryptonote::block& b) {
    return cryptonote::get_block_hash(a) == cryptonote::get_block_hash(b);
}
}  // namespace cryptonote

KV_SERIALIZE_MAP_CODE_BEGIN(cryptonote::address_parse_info)
KV_SERIALIZE(address)
KV_SERIALIZE(is_subaddress)
KV_SERIALIZE(has_payment_id)
KV_SERIALIZE_VAL_POD_AS_BLOB_FORCE(payment_id)
KV_SERIALIZE_MAP_CODE_END()
