// Copyright (c) 2018, The Monero Project
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

#include "epee/net/net_utils_base.h"
#include "net/error.h"
#include "net/parse.h"

TEST(get_network_address, ipv4)
{
    expect<epee::net_utils::network_address> address =
        net::get_network_address("0.0.0.", 0);
    EXPECT_EQ(net::error::unsupported_address, address);

    address = net::get_network_address("0.0.0.257", 0);
    EXPECT_EQ(net::error::unsupported_address, address);

    address = net::get_network_address("0.0.0.254", 1000);
    ASSERT_TRUE(bool(address));
    EXPECT_EQ(epee::net_utils::address_type::ipv4, address->get_type_id());
    EXPECT_STREQ("0.0.0.254", address->host_str().c_str());
    EXPECT_STREQ("0.0.0.254:1000", address->str().c_str());

    address = net::get_network_address("23.0.0.254:2000", 1000);
    ASSERT_TRUE(bool(address));
    EXPECT_EQ(epee::net_utils::address_type::ipv4, address->get_type_id());
    EXPECT_STREQ("23.0.0.254", address->host_str().c_str());
    EXPECT_STREQ("23.0.0.254:2000", address->str().c_str());
}
