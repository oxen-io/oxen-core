// Copyright (c) 2014-2018, The Monero Project
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

#include "gtest/gtest.h"

#include "cryptonote_basic/cryptonote_basic_impl.h"

using namespace cryptonote;

namespace
{
  //--------------------------------------------------------------------------------------------------------------------

  struct reward_test
  {
    uint64_t height;
    uint64_t supply;
    uint64_t expected_reward;
  };

  static const reward_test tests[] = {
    {1, 40000232000000000, 232000000000},
    {21916, 45084512000000000, 232000000000},
    {43831, 50168792000000000, 232000000000},
    {65746, 55242052220000000, 223870000000},
    {87661, 59660373170000000, 179770000000},
    {109576, 63098033600000000, 134200000000},
    {131491, 65555205500000000, 90100000000},
    {153406, 67028492442583801, 40904467723},
    {175321, 67920441692888160, 40496992162},
    {197236, 68803505666322522, 40093575727},
    {219151, 69677772874811670, 39694177979},
    {241066, 70543330948556595, 39298758888},
    {262981, 71400266644817810, 38907278820},
    {284896, 72248665856611529, 38519698536},
    {5872351, 150000001145623291, 3000000022},
    {5872352, 150000004145623313, 3000000082},
    {5872353, 150000007145623395, 3000000142}
  };

  class block_reward_schedule : public ::testing::Test
  {
  protected:

    virtual void SetUp()
    {
    }

    void do_test(uint64_t height, uint64_t supply)
    {
      m_success = get_block_reward(0, 0, supply, m_reward, 6, height);
    }

    uint64_t m_reward;
    bool m_success;
  };

  TEST_F(block_reward_schedule, matches_expected)
  {
    for (const auto& test : tests)
    {
      do_test(test.height, test.supply);
      ASSERT_TRUE(m_success);
      ASSERT_EQ(m_reward, test.expected_reward);
    }
  }

  //TODO: block size deduction for the reward is well-tested, but
  //      there should be tests added here for that regardless.
}
