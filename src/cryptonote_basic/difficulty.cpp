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

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "common/loki.h"
#include "int-util.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "difficulty.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "difficulty"

namespace cryptonote {

  using std::size_t;
  using std::uint64_t;
  using std::vector;

#if defined(__x86_64__)
  static inline void mul(uint64_t a, uint64_t b, uint64_t &low, uint64_t &high) {
    low = mul128(a, b, &high);
  }

#else

  static inline void mul(uint64_t a, uint64_t b, uint64_t &low, uint64_t &high) {
    // __int128 isn't part of the standard, so the previous function wasn't portable. mul128() in Windows is fine,
    // but this portable function should be used elsewhere. Credit for this function goes to latexi95.

    uint64_t aLow = a & 0xFFFFFFFF;
    uint64_t aHigh = a >> 32;
    uint64_t bLow = b & 0xFFFFFFFF;
    uint64_t bHigh = b >> 32;

    uint64_t res = aLow * bLow;
    uint64_t lowRes1 = res & 0xFFFFFFFF;
    uint64_t carry = res >> 32;

    res = aHigh * bLow + carry;
    uint64_t highResHigh1 = res >> 32;
    uint64_t highResLow1 = res & 0xFFFFFFFF;

    res = aLow * bHigh;
    uint64_t lowRes2 = res & 0xFFFFFFFF;
    carry = res >> 32;

    res = aHigh * bHigh + carry;
    uint64_t highResHigh2 = res >> 32;
    uint64_t highResLow2 = res & 0xFFFFFFFF;

    //Addition

    uint64_t r = highResLow1 + lowRes2;
    carry = r >> 32;
    low = (r << 32) | lowRes1;
    r = highResHigh1 + highResLow2 + carry;
    uint64_t d3 = r & 0xFFFFFFFF;
    carry = r >> 32;
    r = highResHigh2 + carry;
    high = d3 | (r << 32);
  }

#endif

  static inline bool cadd(uint64_t a, uint64_t b) {
    return a + b < a;
  }

  static inline bool cadc(uint64_t a, uint64_t b, bool c) {
    return a + b < a || (c && a + b == (uint64_t) -1);
  }

  bool check_hash(const crypto::hash &hash, difficulty_type difficulty) {
    uint64_t low, high, top, cur;
    // First check the highest word, this will most likely fail for a random hash.
    mul(swap64le(((const uint64_t *) &hash)[3]), difficulty, top, high);
    if (high != 0) {
      return false;
    }
    mul(swap64le(((const uint64_t *) &hash)[0]), difficulty, low, cur);
    mul(swap64le(((const uint64_t *) &hash)[1]), difficulty, low, high);
    bool carry = cadd(cur, low);
    cur = high;
    mul(swap64le(((const uint64_t *) &hash)[2]), difficulty, low, high);
    carry = cadc(cur, low, carry);
    carry = cadc(high, top, carry);
    return !carry;
  }

  // LWMA difficulty algorithm
  // Background:  https://github.com/zawy12/difficulty-algorithms/issues/3
  // Copyright (c) 2017-2018 Zawy (pseudocode)
  // MIT license http://www.opensource.org/licenses/mit-license.php
  // Copyright (c) 2018 Wownero Inc., a Monero Enterprise Alliance partner company
  // Copyright (c) 2018 The Karbowanec developers (initial code)
  // Copyright (c) 2018 Haven Protocol (refinements)
  // Degnr8, Karbowanec, Masari, Bitcoin Gold, Bitcoin Candy, and Haven have contributed.

  // This algorithm is: next_difficulty = harmonic_mean(Difficulties) * T / LWMA(Solvetimes)
  // The harmonic_mean(Difficulties) = 1/average(Targets) so it is also:
  // next_target = avg(Targets) * LWMA(Solvetimes) / T.
  // This is "the best algorithm" because it has lowest root-mean-square error between 
  // needed & actual difficulty during hash attacks while having the lowest standard 
  // deviation during stable hashrate. That is, it's the fastest for a given stability and vice versa.
  // Do not use "if solvetime < 1 then solvetime = 1" which allows a catastrophic exploit.
  // Do not sort timestamps.  "Solvetimes" and "LWMA" variables must allow negatives.
  // Do not use MTP as most recent block.  Do not use (POW)Limits, filtering, or tempering.
  // Do not forget to set N (aka DIFFICULTY_WINDOW in Cryptonote) to recommendation below.
  // The nodes' future time limit (FTL) aka CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT needs to
  // be reduced from 60*60*2 to 500 seconds to prevent timestamp manipulation from miner's with 
  //  > 50% hash power.  If this is too small, it can be increased to 1000 at a cost in protection.

  // Cryptonote clones:  #define DIFFICULTY_BLOCKS_COUNT_V2 DIFFICULTY_WINDOW_V2 + 1


  difficulty_type next_difficulty_v2(std::vector<std::uint64_t> timestamps, std::vector<difficulty_type> cumulative_difficulties, size_t target_seconds,
      bool use_old_lwma, bool v12_initial_override) {

    const int64_t T = static_cast<int64_t>(target_seconds);

    int64_t N = DIFFICULTY_WINDOW_V2 - 1;

    // Return a difficulty of 1 for first 4 blocks if it's the start of the chain.
    if (timestamps.size() < 4) {
      return 1;
    }
    // Otherwise, use a smaller N if the start of the chain is less than N+1.
    else if ( timestamps.size()-1 < (size_t) N ) {
      N = timestamps.size() - 1;
    }
    // Otherwise make sure timestamps and cumulative_difficulties are correct size.
    else {
      // TODO: put asserts here, so that the difficulty algorithm is never called with an oversized window
      //       OR make this use the last N+1 timestamps and cum_diff, not the first.
      timestamps.resize(N+1);
      cumulative_difficulties.resize(N+1);
    }
    // To get an average solvetime to within +/- ~0.1%, use an adjustment factor.
    // adjust=0.999 for 80 < N < 120(?)
    //const double adjust = 0.998;
    // The divisor k normalizes the LWMA sum to a standard LWMA.
    const int64_t k = (int64_t)N * (int64_t)(N + 1) / 2;

    // Mathematically we're aiming to find:
    //
    //          N * T(=120) * adjust(=0.998)
    //  diff = --------------------------------
    //         LWMA * (1/diff1 + 1/diff2 + ...)
    //
    // where LWMA = sum{(solvetime * i)} / k  i from 1 to N, where k = N(N+1)/2 normalizes the LWMA value
    // such that if all solve times were "x" we'd get LWMA="x" after summing them.  (More precisely:
    // k is the number that solves the equality LWMA=solvetime).
    //
    // This used to be done with floating point math, which caused endless difficult errors, and
    // should never have been done.  The equation does not *immediately* lend itself to a straight
    // calculation using integer math: the denominator is almost much smaller than 1.  So we need to
    // scale things, and we do this by trying to make the x/y terms in the denominator have as big
    // of an `x` as possible (relative to `y`), because the bigger `x` is relative to `y` the less
    // precision we lose from the x/y calculation.
    //
    // So as a first step we scale top and bottom by the average difficulty to get:
    //
    //          N * T(=120) * adjust(=499/500) * meandiff
    //  diff = ------------------------------------------
    //         LWMA * (1/diff1 + 1/diff2 + ...) * meandiff
    //
    // which lets us calculate (using integer math) as:
    //
    //                N * T(=120) * adjust(=499/500) * meandiff
    //  diff = -------------------------------------------------------
    //          (LWMA * meandiff)/diff1 + (LWMA*meandiff)/diff2 + ...
    // 
    // We can go one step further by factoring out the implicit `/k` term from LWMA_i and pushing it
    // into the denominator; let λ = LWMA*k (i.e. λ is the sum of LWMA calculations *not* divided by
    // k).
    //
    //                N * T(=120) * meandiff * k * 499 / 500
    //  diff = ----------------------------------------------------
    //          (λ * meandiff)/diff1 + (λ * meandiff)/diff2 + ...
    //
    // and to guard against possible (albeit unlikely) overflow in the numerator we bring the
    // *499/500 outside the main fraction:
    //
    //                    N * T(=120) * meandiff * k
    //  diff = ---------------------------------------------------- * 499 / 500
    //          (λ * meandiff)/diff1 + (λ * meandiff)/diff2 + ...
    //
    // There are two numbers here which could overflow:
    // - The numerator
    // - The λ*meandiff value
    //
    // Some historical context implies why these aren't something we need to worry about:
    // - LOKI peak difficulty (under CN-pico in July 2019) was somewhere around 40 billion (i.e. a
    //   little over 300MH/s).
    // - Using a ludicrously extreme final block time of one week without a block, and putting this
    //   in the last term (since it has the largest λ), we get a λ = 59*86400 = 5097600, and so λ *
    //   meandiff = 203'904'000'000'000'000, which is only about 1/45 the max value of an int64_t,
    //   so we'd need a massive difficulty increase *and* so-slow-that-they're-broken blocks to
    //   overflow the numerators of the sub-terms in the denominator.
    // - The numerator would overflow at a mean difficulty (over the last 59 blocks) of 21.9
    //   trillion = 182GH/s, or more than 500 times the peak difficulty we ever saw.  (This is why
    //   we don't add the * 499 term into the numerator: it would get us close to int64_t limits).
    //
    // Thus we ignore overflow concerns because even if someone managed to overflow something here
    // with an incredibly high difficulty on a private chain, checkpointing will prevent anyone from
    // caring about it.
    //
    // We can *slightly* improve the calculation accuracy from this point by pushing the 499 and 500
    // into the numerator and denominator, respectively, but *only* if it will not result in
    // overflow.  If it would, we keep them for the end.
    //
    int64_t mean_diff = (cumulative_difficulties[N] - cumulative_difficulties[0]) / N;

    int64_t lambda = 0;
    // Loop through N most recent blocks. N is most recently solved block.
    for (int64_t i = 1; i <= N; i++) {
      int64_t solveTime = static_cast<int64_t>(timestamps[i]) - static_cast<int64_t>(timestamps[i - 1]);

      if (use_old_lwma) solveTime = std::max<int64_t>(solveTime, (-7 * T));
      solveTime = std::min<int64_t>(solveTime, (T * 7));

      lambda += solveTime * i;
    }

    // Keep LWMA sane in case something unforeseen occurs.
    lambda = std::max(lambda, k * T / 20);

    int64_t numerator = N * T * mean_diff * k;
    int64_t final_mult = 1;
    if (numerator < std::numeric_limits<int64_t>::max() / 499)
        numerator *= 499;
    else
        final_mult = 499;

    int64_t denominator_base = lambda * mean_diff;
    int64_t final_div = 1;
    if (denominator_base < std::numeric_limits<int64_t>::max() / 500)
        denominator_base *= 500;
    else
        final_div = 500;

    int64_t denominator = 0;
    for (int64_t i = 1; i <= N; i++)
        denominator += denominator_base / (cumulative_difficulties[i] - cumulative_difficulties[i - 1]);

    int64_t next_difficulty = numerator / denominator * final_mult / final_div;

    if (next_difficulty <= 0)
        next_difficulty = 1;

    // Rough estimate based on comparable coins, pre-merge-mining hashrate, and hashrate changes is
    // that 30MH/s seems more or less right, so we cap it there for the first WINDOW blocks to
    // prevent too-long blocks right after the fork.
    if (v12_initial_override)
      return std::min(next_difficulty, 30000000 * T);

    return next_difficulty;
  }
}
