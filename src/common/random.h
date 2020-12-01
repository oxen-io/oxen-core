// Copyright (c) 2019, The Loki Project
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

#pragma once

#include <random>

namespace tools {

/// A thread-local, pre-seeded mt19937_64 rng ready for use.  Don't use this where an RNG with a
/// specific seed is needed.
extern thread_local std::mt19937_64 rng;

/// Generates a deterministic uint64_t uniformly distributed over [0, n).  This is roughly
/// equivalent to `std::uniform_int_distribution<uint64_t>{0, n}(rng)`, but that is not guaranteed
/// to be unique across platforms/compilers, while this is.
uint64_t uniform_distribution_portable(std::mt19937_64& rng, uint64_t n);

/// Uniformly shuffles all the elements in [begin, end) in a deterministic method so that, given the
/// same seed, this will always produce the same result on any platform/compiler/etc.
template<typename RandomIt>
void shuffle_portable(RandomIt begin, RandomIt end, std::mt19937_64 &rng)
{
  if (end <= begin + 1) return;
  const size_t size = std::distance(begin, end);
  for (size_t i = 1; i < size; i++)
  {
    size_t j = (size_t)uniform_distribution_portable(rng, i+1);
    using std::swap;
    swap(begin[i], begin[j]);
  }
}

/// Returns a random element between the elements in [begin, end) will use the random number generator provided as g
template<typename Iter, typename RandomGenerator>
Iter select_randomly(Iter begin, Iter end, RandomGenerator& g) {
  auto dist = std::distance(begin, end);
  if (dist <= 1) return begin; // Handles both begin=end case and single-element case
  std::advance(begin, std::uniform_int_distribution<>{0, static_cast<int>(dist-1)}(g));
  return begin;
}

/// Returns a random element same as above but defaults to the seeded random number generator defined in this file
template<typename Iter>
Iter select_randomly(Iter begin, Iter end) {
  return select_randomly(begin, end, rng);
}

};
