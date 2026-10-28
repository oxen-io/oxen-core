// Copyright (c) 2019, The Monero Project
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

#include <gtest/gtest.h>

#include "cryptonote_protocol/cryptonote_protocol_defs.h"
#include "epee/storages/portable_storage_template_helper.h"

TEST(serialize_tx_notify, unpadded)
{
    const std::vector<std::string> txs{std::string(100, 'f'), std::string(200, 'e')};
    const std::string payload = cryptonote::serialize_tx_notify(txs, false);

    cryptonote::NOTIFY_NEW_TRANSACTIONS::request request;
    ASSERT_TRUE(epee::serialization::load_t_from_binary(request, payload));
    EXPECT_EQ(txs, request.txs);
    EXPECT_TRUE(request.blinks.empty());
    EXPECT_FALSE(request.requested);
    EXPECT_TRUE(request._.empty());
}

TEST(serialize_tx_notify, padded)
{
    const std::vector<std::string> txs{std::string(100, 'f'), std::string(200, 'e')};
    const std::string payload = cryptonote::serialize_tx_notify(txs, true);
    EXPECT_EQ(0u, payload.size() % 1024);

    cryptonote::NOTIFY_NEW_TRANSACTIONS::request request;
    ASSERT_TRUE(epee::serialization::load_t_from_binary(request, payload));
    EXPECT_EQ(txs, request.txs);
    EXPECT_TRUE(request.blinks.empty());
    EXPECT_FALSE(request.requested);
    EXPECT_FALSE(request._.empty());
}
