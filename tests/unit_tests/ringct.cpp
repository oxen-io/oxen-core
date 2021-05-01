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

#include <cstdint>
#include <algorithm>
#include <sstream>

#include "ringct/rctTypes.h"
#include "ringct/rctSigs.h"
#include "ringct/rctOps.h"
#include "device/device.hpp"
#include "common/hex.h"

using namespace crypto;
using namespace rct;

TEST(ringct, CLSAG)
{
  const size_t N = 11;
  const size_t idx = 5;
  ctkeyV pubs;
  key p, t, t2, u;
  const key message = key::identity;
  ctkey backup;
  clsag clsag;

  for (size_t i = 0; i < N; ++i)
  {
    key sk;
    ctkey tmp;

    skpkGen(sk, tmp.dest);
    skpkGen(sk, tmp.mask);

    pubs.push_back(tmp);
  }

  // Set P[idx]
  skpkGen(p, pubs[idx].dest);

  // Set C[idx]
  t = skGen();
  u = skGen();
  addKeys2(pubs[idx].mask,t,u,H);

  // Set commitment offset
  key Cout;
  t2 = skGen();
  addKeys2(Cout,t2,u,H);

  // Prepare generation inputs
  ctkey insk;
  insk.dest = p;
  insk.mask = t;
  
  // bad message
  clsag = rct::proveRctCLSAGSimple(key::zero,pubs,insk,t2,Cout,NULL,NULL,NULL,idx,hw::get_device("default"));
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));

  // bad index at creation
  try
  {
    clsag = rct::proveRctCLSAGSimple(message,pubs,insk,t2,Cout,NULL,NULL,NULL,(idx + 1) % N,hw::get_device("default"));
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }

  // bad z at creation
  try
  {
    ctkey insk2;
    insk2.dest = insk.dest;
    insk2.mask = skGen();
    clsag = rct::proveRctCLSAGSimple(message,pubs,insk2,t2,Cout,NULL,NULL,NULL,idx,hw::get_device("default"));
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }

  // bad C at creation
  backup = pubs[idx];
  pubs[idx].mask = scalarmultBase(skGen());
  try
  {
    clsag = rct::proveRctCLSAGSimple(message,pubs,insk,t2,Cout,NULL,NULL,NULL,idx,hw::get_device("default"));
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }
  pubs[idx] = backup;

  // bad p at creation
  try
  {
    ctkey insk2;
    insk2.dest = skGen();
    insk2.mask = insk.mask;
    clsag = rct::proveRctCLSAGSimple(message,pubs,insk2,t2,Cout,NULL,NULL,NULL,idx,hw::get_device("default"));
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }

  // bad P at creation
  backup = pubs[idx];
  pubs[idx].dest = scalarmultBase(skGen());
  try
  {
    clsag = rct::proveRctCLSAGSimple(message,pubs,insk,t2,Cout,NULL,NULL,NULL,idx,hw::get_device("default"));
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }
  pubs[idx] = backup;

  // Test correct signature
  clsag = rct::proveRctCLSAGSimple(message,pubs,insk,t2,Cout,NULL,NULL,NULL,idx,hw::get_device("default"));
  ASSERT_TRUE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));

  // empty s
  auto sbackup = clsag.s;
  clsag.s.clear();
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.s = sbackup;

  // too few s elements
  key backup_key;
  backup_key = clsag.s.back();
  clsag.s.pop_back();
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.s.push_back(backup_key);

  // too many s elements
  clsag.s.push_back(skGen());
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.s.pop_back();

  // bad s in clsag at verification
  for (auto &s: clsag.s)
  {
    backup_key = s;
    s = skGen();
    ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
    s = backup_key;
  }

  // bad c1 in clsag at verification
  backup_key = clsag.c1;
  clsag.c1 = skGen();
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.c1 = backup_key;

  // bad I in clsag at verification
  backup_key = clsag.I;
  clsag.I = scalarmultBase(skGen());
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.I = backup_key;

  // bad D in clsag at verification
  backup_key = clsag.D;
  clsag.D = scalarmultBase(skGen());
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.D = backup_key;

  // D not in main subgroup in clsag at verification
  backup_key = clsag.D;
  rct::key x;
  ASSERT_TRUE(tools::hex_to_type("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", x));
  clsag.D = rct::addKeys(clsag.D, x);
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  clsag.D = backup_key;

  // swapped I and D in clsag at verification
  std::swap(clsag.I, clsag.D);
  ASSERT_FALSE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
  std::swap(clsag.I, clsag.D);

  // check it's still good, in case we failed to restore
  ASSERT_TRUE(rct::verRctCLSAGSimple(message,clsag,pubs,Cout));
}

TEST(ringct, range_proofs)
{
  //Ring CT Stuff
  //ct range proofs
  ctkeyV sc, pc;
  ctkey sctmp, pctmp;
  std::vector<uint64_t> inamounts;
  //add fake input 6000
  inamounts.push_back(6000);
  std::tie(sctmp, pctmp) = ctskpkGen(inamounts.back());
  sc.push_back(sctmp);
  pc.push_back(pctmp);


  inamounts.push_back(7000);
  std::tie(sctmp, pctmp) = ctskpkGen(inamounts.back());
  sc.push_back(sctmp);
  pc.push_back(pctmp);
  std::vector<xmr_amount >amounts;
  rct::keyV amount_keys;
  key mask;

  //add output 500
  amounts.push_back(500);
  amount_keys.push_back(rct::hash_to_scalar(rct::key::zero));
  keyV destinations;
  key Sk, Pk;
  skpkGen(Sk, Pk);
  destinations.push_back(Pk);


  //add output for 12500
  amounts.push_back(12500);
  amount_keys.push_back(rct::hash_to_scalar(rct::key::zero));
  skpkGen(Sk, Pk);
  destinations.push_back(Pk);

  const rct::RCTConfig rct_config { RangeProofType::PaddedBulletproof, 0 };

  //compute rct data with mixin 3
  rctSig s = genRctSimple(rct::key::zero, sc, pc, destinations, inamounts, amounts, amount_keys, NULL, NULL, 0, 3, rct_config, hw::get_device("default"));

  //verify rct data
  ASSERT_TRUE(verRctSimple(s));

  //decode received amount
  decodeRctSimple(s, amount_keys[1], 1, mask, hw::get_device("default"));

  // Ring CT with failing MG sig part should not verify!
  // Since sum of inputs != outputs

  amounts[1] = 12501;
  skpkGen(Sk, Pk);
  destinations[1] = Pk;


  //compute rct data with mixin 3
  s = genRctSimple(rct::key::zero, sc, pc, destinations, inamounts, amounts, amount_keys, NULL, NULL, 0, 3, rct_config, hw::get_device("default"));

  //verify rct data
  ASSERT_FALSE(verRctSimple(s));

  //decode received amount
  decodeRctSimple(s, amount_keys[1], 1, mask, hw::get_device("default"));
}

TEST(ringct, range_proofs_with_fee)
{
  //Ring CT Stuff
  //ct range proofs
  ctkeyV sc, pc;
  ctkey sctmp, pctmp;
  std::vector<uint64_t> inamounts;
  //add fake input 6001
  inamounts.push_back(6001);
  std::tie(sctmp, pctmp) = ctskpkGen(inamounts.back());
  sc.push_back(sctmp);
  pc.push_back(pctmp);


  inamounts.push_back(7000);
  std::tie(sctmp, pctmp) = ctskpkGen(inamounts.back());
  sc.push_back(sctmp);
  pc.push_back(pctmp);
  std::vector<xmr_amount >amounts;
  keyV amount_keys;
  key mask;

  //add output 500
  amounts.push_back(500);
  amount_keys.push_back(rct::hash_to_scalar(rct::key::zero));
  keyV destinations;
  key Sk, Pk;
  skpkGen(Sk, Pk);
  destinations.push_back(Pk);

  //add output for 12500
  amounts.push_back(12500);
  amount_keys.push_back(hash_to_scalar(key::zero));
  skpkGen(Sk, Pk);
  destinations.push_back(Pk);

  const rct::RCTConfig rct_config { RangeProofType::PaddedBulletproof, 0 };

  //compute rct data with mixin 3
  rctSig s = genRctSimple(rct::key::zero, sc, pc, destinations, inamounts, amounts, amount_keys, NULL, NULL, 1, 3, rct_config, hw::get_device("default"));

  //verify rct data
  ASSERT_TRUE(verRctSimple(s));

  //decode received amount
  decodeRctSimple(s, amount_keys[1], 1, mask, hw::get_device("default"));

  // Ring CT with failing MG sig part should not verify!
  // Since sum of inputs != outputs

  amounts[1] = 12501;
  skpkGen(Sk, Pk);
  destinations[1] = Pk;


  //compute rct data with mixin 3
  s = genRctSimple(rct::key::zero, sc, pc, destinations, inamounts, amounts, amount_keys, NULL, NULL, 500, 3, rct_config, hw::get_device("default"));

  //verify rct data
  ASSERT_FALSE(verRctSimple(s));

  //decode received amount
  decodeRctSimple(s, amount_keys[1], 1, mask, hw::get_device("default"));
}

TEST(ringct, simple)
{
  ctkeyV sc, pc;
  ctkey sctmp, pctmp;
  //this vector corresponds to output amounts
  std::vector<xmr_amount>outamounts;
  //this vector corresponds to input amounts
  std::vector<xmr_amount>inamounts;
  //this keyV corresponds to destination pubkeys
  keyV destinations;
  keyV amount_keys;
  key mask;

  //add fake input 3000
  //the sc is secret data
  //pc is public data
  std::tie(sctmp, pctmp) = ctskpkGen(3000);
  sc.push_back(sctmp);
  pc.push_back(pctmp);
  inamounts.push_back(3000);

  //add fake input 3000
  //the sc is secret data
  //pc is public data
  std::tie(sctmp, pctmp) = ctskpkGen(3000);
  sc.push_back(sctmp);
  pc.push_back(pctmp);
  inamounts.push_back(3000);

  //add output 5000
  outamounts.push_back(5000);
  amount_keys.push_back(rct::hash_to_scalar(rct::key::zero));
  //add the corresponding destination pubkey
  key Sk, Pk;
  skpkGen(Sk, Pk);
  destinations.push_back(Pk);

  //add output 999
  outamounts.push_back(999);
  amount_keys.push_back(rct::hash_to_scalar(rct::key::zero));
  //add the corresponding destination pubkey
  skpkGen(Sk, Pk);
  destinations.push_back(Pk);

  key message = skGen(); //real message later (hash of txn..)

  //compute sig with mixin 2
  xmr_amount txnfee = 1;

  const rct::RCTConfig rct_config { RangeProofType::PaddedBulletproof, 0 };
  rctSig s = genRctSimple(message, sc, pc, destinations,inamounts, outamounts, amount_keys, NULL, NULL, txnfee, 2, rct_config, hw::get_device("default"));

  //verify ring ct signature
  ASSERT_TRUE(verRctSimple(s));

  //decode received amount corresponding to output pubkey index 1
  decodeRctSimple(s, amount_keys[1], 1, mask,  hw::get_device("default"));
}

static rct::rctSig make_sample_simple_rct_sig(int n_inputs, const uint64_t input_amounts[], int n_outputs, const uint64_t output_amounts[], uint64_t fee)
{
  ctkeyV sc, pc;
  ctkey sctmp, pctmp;
  std::vector<xmr_amount> inamounts, outamounts;
  keyV destinations;
  keyV amount_keys;
  key Sk, Pk;

  for (int n = 0; n < n_inputs; ++n) {
    inamounts.push_back(input_amounts[n]);
    std::tie(sctmp, pctmp) = ctskpkGen(input_amounts[n]);
    sc.push_back(sctmp);
    pc.push_back(pctmp);
  }

  for (int n = 0; n < n_outputs; ++n) {
    outamounts.push_back(output_amounts[n]);
    amount_keys.push_back(hash_to_scalar(key::zero));
    skpkGen(Sk, Pk);
    destinations.push_back(Pk);
  }

  const rct::RCTConfig rct_config { RangeProofType::PaddedBulletproof, 0 };
  return genRctSimple(rct::key::zero, sc, pc, destinations, inamounts, outamounts, amount_keys, NULL, NULL, fee, 3, rct_config, hw::get_device("default"));
}

static bool range_proof_test(
    int n_inputs, const uint64_t input_amounts[], int n_outputs, const uint64_t output_amounts[], uint64_t fee = 0)
{
  //compute rct data
  bool valid;
  try {
    rctSig s;
    s = make_sample_simple_rct_sig(n_inputs, input_amounts, n_outputs, output_amounts, fee);
    valid = verRctSimple(s);
  }
  catch (const std::exception &e) {
    valid = false;
  }

  return valid;
}

#define NELTS(array) (sizeof(array)/sizeof(array[0]))

TEST(ringct, range_proofs_reject_empty_outs_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_reject_empty_ins_simple)
{
  const uint64_t inputs[] = {};
  const uint64_t outputs[] = {5000};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_reject_all_empty_simple)
{
  const uint64_t inputs[] = {};
  const uint64_t outputs[] = {};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_reject_zero_empty_simple)
{
  const uint64_t inputs[] = {0};
  const uint64_t outputs[] = {};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_reject_empty_zero_simple)
{
  const uint64_t inputs[] = {};
  const uint64_t outputs[] = {0};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_accept_zero_zero_simple)
{
  const uint64_t inputs[] = {0};
  const uint64_t outputs[] = {0};
  EXPECT_TRUE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_accept_zero_out_first_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {0, 5000};
  EXPECT_TRUE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_accept_zero_out_last_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {5000, 0};
  EXPECT_TRUE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_accept_zero_out_middle_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {2500, 0, 2500};
  EXPECT_TRUE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_accept_zero_in_first_simple)
{
  const uint64_t inputs[] = {0, 5000};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_accept_zero_in_last_simple)
{
  const uint64_t inputs[] = {5000, 0};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_accept_zero_in_middle_simple)
{
  const uint64_t inputs[] = {2500, 0, 2500};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_reject_single_lower_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {1};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_reject_single_higher_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {5001};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_reject_single_out_negative_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {(uint64_t)-1000ll};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_reject_out_negative_first_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {(uint64_t)-1000ll, 6000};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_reject_out_negative_last_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {6000, (uint64_t)-1000ll};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_reject_out_negative_middle_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {3000, (uint64_t)-1000ll, 3000};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_reject_single_in_negative_simple)
{
  const uint64_t inputs[] = {(uint64_t)-1000ll};
  const uint64_t outputs[] = {5000};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_reject_in_negative_first_simple)
{
  const uint64_t inputs[] = {(uint64_t)-1000ll, 6000};
  const uint64_t outputs[] = {5000};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_reject_in_negative_last_simple)
{
  const uint64_t inputs[] = {6000, (uint64_t)-1000ll};
  const uint64_t outputs[] = {5000};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_reject_in_negative_middle_simple)
{
  const uint64_t inputs[] = {3000, (uint64_t)-1000ll, 3000};
  const uint64_t outputs[] = {5000};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_reject_higher_list_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {1000, 1000, 1000, 1000, 1000, 1000};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_accept_1_to_1_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_accept_1_to_N_simple)
{
  const uint64_t inputs[] = {5000};
  const uint64_t outputs[] = {1000, 1000, 1000, 1000, 1000};
  EXPECT_TRUE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_accept_N_to_1_simple)
{
  const uint64_t inputs[] = {1000, 1000, 1000, 1000, 1000};
  const uint64_t outputs[] = {5000};
  EXPECT_TRUE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_accept_N_to_N_simple)
{
  const uint64_t inputs[] = {1000, 1000, 1000, 1000, 1000};
  const uint64_t outputs[] = {1000, 1000, 1000, 1000, 1000};
  EXPECT_TRUE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, range_proofs_accept_very_long_simple)
{
  const size_t N=12;
  uint64_t inputs[N];
  uint64_t outputs[N];
  for (size_t n = 0; n < N; ++n) {
    inputs[n] = n;
    outputs[n] = n;
  }
  std::shuffle(inputs, inputs + N, crypto::random_device{});
  std::shuffle(outputs, outputs + N, crypto::random_device{});
  EXPECT_TRUE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs));
}

TEST(ringct, HPow2)
{
  key G = scalarmultBase(rct::key::constant(1));

  // Note that H is computed differently than standard hashing
  // This method is not guaranteed to return a curvepoint for all inputs
  // Don't use it elsewhere
  key H = cn_fast_hash(G);
  ge_p3 H_p3;
  int decode = ge_frombytes_vartime(&H_p3, H);
  ASSERT_EQ(decode, 0); // this is known to pass for the particular value G
  ge_p2 H_p2;
  ge_p3_to_p2(&H_p2, &H_p3);
  ge_p1p1 H8_p1p1;
  ge_mul8(&H8_p1p1, &H_p2);
  ge_p1p1_to_p3(&H_p3, &H8_p1p1);
  ge_p3_tobytes(H, &H_p3);

  for (int j = 0 ; j < ATOMS ; j++) {
    ASSERT_TRUE(equalKeys(H, H2[j]));
    addKeys(H, H, H);
  }
}

static const xmr_amount test_amounts[]={0, 1, 2, 3, 4, 5, 10000, 10000000000000000000ull, 10203040506070809000ull, 123456789123456789};

TEST(ringct, rct_key_constant)
{
  for (auto amount: test_amounts) {
    auto k = rct::key::constant(amount);
    ASSERT_TRUE(amount == h2d(k));
  }
}

TEST(ringct, d2b)
{
  for (auto amount: test_amounts) {
    bits b;
    d2b(b, amount);
    ASSERT_TRUE(amount == b2d(b));
  }
}

TEST(ringct, fee_0_valid_simple)
{
  const uint64_t inputs[] = {1000, 1000};
  const uint64_t outputs[] = {2000};
  EXPECT_TRUE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs, 0));
}

TEST(ringct, fee_non_0_valid_simple)
{
  const uint64_t inputs[] = {1000, 1000};
  const uint64_t outputs[] = {1900};
  EXPECT_TRUE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs, 100));
}

TEST(ringct, fee_non_0_invalid_higher_simple)
{
  const uint64_t inputs[] = {1000, 1000};
  const uint64_t outputs[] = {1990};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs, 100));
}

TEST(ringct, fee_non_0_invalid_lower_simple)
{
  const uint64_t inputs[] = {1000, 1000};
  const uint64_t outputs[] = {1000};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs, 100));
}

TEST(ringct, fee_burn_valid_one_out_simple)
{
  const uint64_t inputs[] = {1000, 1000};
  const uint64_t outputs[] = {0};
  EXPECT_TRUE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs, 2000));
}

TEST(ringct, fee_burn_invalid_zero_out_simple)
{
  const uint64_t inputs[] = {1000, 1000};
  const uint64_t outputs[] = {};
  EXPECT_FALSE(range_proof_test(NELTS(inputs), inputs, NELTS(outputs), outputs, 2000));
}

static constexpr std::array<uint64_t, 2> base_inputs{1000, 1000};
static constexpr std::array<uint64_t, 1> base_outputs{1000};
static constexpr uint64_t base_fee = 1000;
rct::rctSig base_sig() {
    static const rct::rctSig base_sig = make_sample_simple_rct_sig(base_inputs.size(), base_inputs.data(), base_outputs.size(), base_outputs.data(), base_fee);
    return base_sig;
}

TEST(ringct, rctSig_base) \
{
  rct::rctSig sig = base_sig();
  ASSERT_TRUE(rct::verRctSimple(sig));
}

#define TEST_rctSig_elements(name, op) \
TEST(ringct, rctSig_##name) \
{ \
  rct::rctSig sig = base_sig(); \
  op; \
  ASSERT_FALSE(rct::verRctSimple(sig)); \
}

TEST_rctSig_elements(mixRing_empty, sig.mixRing.resize(0));
TEST_rctSig_elements(mixRing_too_many, sig.mixRing.push_back(sig.mixRing.back()));
TEST_rctSig_elements(mixRing_too_few, sig.mixRing.pop_back());
TEST_rctSig_elements(mixRing0_empty, sig.mixRing[0].resize(0));
TEST_rctSig_elements(mixRing0_too_many, sig.mixRing[0].push_back(sig.mixRing[0].back()));
TEST_rctSig_elements(mixRing0_too_few, sig.mixRing[0].pop_back());
TEST_rctSig_elements(pseudoOuts_empty, sig.p.pseudoOuts.clear());
TEST_rctSig_elements(pseudoOuts_too_many, sig.p.pseudoOuts.push_back(sig.p.pseudoOuts.back()));
TEST_rctSig_elements(pseudoOuts_too_few, sig.p.pseudoOuts.pop_back());
TEST_rctSig_elements(ecdhInfo_empty, sig.ecdhInfo.resize(0));
TEST_rctSig_elements(ecdhInfo_too_many, sig.ecdhInfo.push_back(sig.ecdhInfo.back()));
TEST_rctSig_elements(ecdhInfo_too_few, sig.ecdhInfo.pop_back());
TEST_rctSig_elements(outPk_empty, sig.outPk.resize(0));
TEST_rctSig_elements(outPk_too_many, sig.outPk.push_back(sig.outPk.back()));
TEST_rctSig_elements(outPk_too_few, sig.outPk.pop_back());

TEST(ringct, reject_gen_simple_ver_non_simple)
{
  const uint64_t inputs[] = {1000, 1000};
  const uint64_t outputs[] = {1000};
  rct::rctSig sig = make_sample_simple_rct_sig(NELTS(inputs), inputs, NELTS(outputs), outputs, 1000);
  ASSERT_FALSE(rct::verRct(sig));
}

TEST(ringct, key_ostream)
{
  std::stringstream out;
  out << "BEGIN" << rct::H << "END";
  EXPECT_EQ(
    std::string{"BEGIN<8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94>END"},
    out.str()
  );
}

TEST(ringct, zeroCommmit)
{
  static const uint64_t amount = crypto::random_filled<uint64_t>();
  const rct::key z = rct::zeroCommit(amount);
  const rct::key a = rct::scalarmultBase(rct::key::identity);
  const rct::key b = rct::scalarmultH(rct::key::constant(amount));
  const rct::key manual = rct::addKeys(a, b);
  ASSERT_EQ(z, manual);
}

static rct::key uncachedZeroCommit(uint64_t amount)
{
  const rct::key am = rct::key::constant(amount);
  const rct::key bH = rct::scalarmultH(am);
  return rct::addKeys(rct::key::G, bH);
}

TEST(ringct, zeroCommitCache)
{
  ASSERT_EQ(rct::zeroCommit(0), uncachedZeroCommit(0));
  ASSERT_EQ(rct::zeroCommit(1), uncachedZeroCommit(1));
  ASSERT_EQ(rct::zeroCommit(2), uncachedZeroCommit(2));
  ASSERT_EQ(rct::zeroCommit(10), uncachedZeroCommit(10));
  ASSERT_EQ(rct::zeroCommit(200), uncachedZeroCommit(200));
  ASSERT_EQ(rct::zeroCommit(1000000000), uncachedZeroCommit(1000000000));
  ASSERT_EQ(rct::zeroCommit(3000000000000), uncachedZeroCommit(3000000000000));
  ASSERT_EQ(rct::zeroCommit(900000000000000), uncachedZeroCommit(900000000000000));
}

TEST(ringct, H)
{
  ge_p3 p3;
  ASSERT_EQ(ge_frombytes_vartime(&p3, rct::H), 0);
  ASSERT_EQ(memcmp(&p3, &ge_p3_H, sizeof(ge_p3)), 0);
}

TEST(ringct, mul8)
{
  ge_p3 p3;
  rct::key key;
  ASSERT_EQ(rct::scalarmult8(rct::key::identity), rct::key::identity);
  rct::scalarmult8(p3,rct::key::identity);
  ge_p3_tobytes(key, &p3);
  ASSERT_EQ(key, rct::key::identity);
  constexpr auto EIGHT = rct::key::constant(8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
  ASSERT_EQ(rct::scalarmult8(rct::H), rct::scalarmultKey(rct::H, EIGHT));
  rct::scalarmult8(p3,rct::H);
  ge_p3_tobytes(key, &p3);
  ASSERT_EQ(key, rct::scalarmultKey(rct::H, EIGHT));
  ASSERT_EQ(rct::scalarmultKey(rct::scalarmultKey(rct::H, rct::key::inv_eight), EIGHT), rct::H);
}

TEST(ringct, aggregated)
{
  static const size_t N_PROOFS = 16;
  std::vector<rctSig> s(N_PROOFS);
  std::vector<const rctSig*> sp(N_PROOFS);

  for (size_t n = 0; n < N_PROOFS; ++n)
  {
    static const uint64_t inputs[] = {1000, 1000};
    static const uint64_t outputs[] = {500, 1500};
    s[n] = make_sample_simple_rct_sig(NELTS(inputs), inputs, NELTS(outputs), outputs, 0);
    sp[n] = &s[n];
  }

  ASSERT_TRUE(verRctSemanticsSimple(sp));
}
