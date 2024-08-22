// Copyright (c) 2021, The Oxen Project
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

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "gtest/gtest.h"

using namespace cryptonote;

TEST(ADDRESS, empty) {
    EXPECT_FALSE(cryptonote::is_valid_address("", cryptonote::network_type::MAINNET));
}

TEST(ADDRESS, short_mainnet_address) {
    EXPECT_FALSE(cryptonote::is_valid_address(
            "LDBEN6Ut4NkMwyaXWZ7kBEAx8X64o6YtDhLXUP26uLHyYT4nFmcaPU2Z2fauqrhTLh4Qfr61pUUZVLaTHqAdyc"
            "ETKM1STr",
            cryptonote::network_type::MAINNET));
}
TEST(ADDRESS, long_mainnet_address) {
    EXPECT_FALSE(cryptonote::is_valid_address(
            "LDBEN6Ut4NkMwyaXWZ7kBEAx8X64o6YtDhLXUP26uLHyYT4nFmcaPU2Z2fauqrhTLh4Qfr61pUUZVLaTHqAdyc"
            "ETKM1STrzz",
            cryptonote::network_type::MAINNET));
}

TEST(ADDRESS, valid_test_address) {
    EXPECT_TRUE(cryptonote::is_valid_address(
            "T6TzkJb5EiASaCkcH7idBEi1HSrpSQJE1Zq3aL65ojBMPZvqHNYPTL56i3dncGVNEYCG5QG5zrBmRiVwcg6b1c"
            "RM1SRNqbp44",
            cryptonote::network_type::TESTNET));
}
TEST(ADDRESS, valid_mainnet_address) {
    EXPECT_TRUE(cryptonote::is_valid_address(
            "LDBEN6Ut4NkMwyaXWZ7kBEAx8X64o6YtDhLXUP26uLHyYT4nFmcaPU2Z2fauqrhTLh4Qfr61pUUZVLaTHqAdyc"
            "ETKM1STrz",
            cryptonote::network_type::MAINNET));
}
