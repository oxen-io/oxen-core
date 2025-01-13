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

#include "transaction_info.h"

#include "common_defines.h"

namespace Wallet {

EXPORT
TransactionInfo::~TransactionInfo() {}

EXPORT
TransactionInfo::Transfer::Transfer(uint64_t _amount, std::string _address) :
        amount(_amount), address(std::move(_address)) {}

EXPORT
TransactionInfoImpl::TransactionInfoImpl() :
        m_direction(Direction_Out),
        m_pending(false),
        m_failed(false),
        m_reward_type(reward_type::unspecified),
        m_is_stake(false),
        m_amount(0),
        m_fee(0),
        m_blockheight(0),
        m_subaddrAccount(0),
        m_timestamp(0),
        m_confirmations(0),
        m_unlock_time(0) {}

EXPORT
TransactionInfoImpl::~TransactionInfoImpl() {}

EXPORT
int TransactionInfoImpl::direction() const {
    return m_direction;
}

EXPORT
bool TransactionInfoImpl::isServiceNodeReward() const {
    return m_reward_type == reward_type::service_node;
}

EXPORT
bool TransactionInfoImpl::isMinerReward() const {
    return m_reward_type == reward_type::miner;
}

EXPORT
bool TransactionInfoImpl::isStake() const {
    return m_is_stake;
}

EXPORT
bool TransactionInfoImpl::isPending() const {
    return m_pending;
}

EXPORT
bool TransactionInfoImpl::isFailed() const {
    return m_failed;
}

EXPORT
uint64_t TransactionInfoImpl::amount() const {
    return m_amount;
}

EXPORT
uint64_t TransactionInfoImpl::fee() const {
    return m_fee;
}

EXPORT
uint64_t TransactionInfoImpl::blockHeight() const {
    return m_blockheight;
}

EXPORT
std::set<uint32_t> TransactionInfoImpl::subaddrIndex() const {
    return m_subaddrIndex;
}

EXPORT
uint32_t TransactionInfoImpl::subaddrAccount() const {
    return m_subaddrAccount;
}

EXPORT
std::string TransactionInfoImpl::label() const {
    return m_label;
}

EXPORT
std::string TransactionInfoImpl::hash() const {
    return m_hash;
}

EXPORT
std::time_t TransactionInfoImpl::timestamp() const {
    return m_timestamp;
}

EXPORT
std::string TransactionInfoImpl::paymentId() const {
    return m_paymentid;
}

EXPORT
const std::vector<TransactionInfo::Transfer>& TransactionInfoImpl::transfers() const {
    return m_transfers;
}

EXPORT
uint64_t TransactionInfoImpl::confirmations() const {
    return m_confirmations;
}

EXPORT
uint64_t TransactionInfoImpl::unlockTime() const {
    return m_unlock_time;
}

}  // namespace Wallet
