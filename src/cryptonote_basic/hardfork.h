// Copyright (c) 2018-2021, The Oxen Project
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

#include <cstdint>
#include <ctime>
#include <optional>
#include <span>
#include <vector>

#include "cryptonote_config.h"

namespace cryptonote {

// Defines where hard fork (i.e. new minimum network versions) begin
struct hard_fork {
    hf version;              // Blockchain major version
    uint8_t snode_revision;  // Snode revision for enforcing non-blockchain-breaking mandatory
                             // service node updates
    uint64_t height;
    time_t time;
};

// Stick your fake hard forks in here if you're into that sort of thing.
extern std::vector<hard_fork> fakechain_hardforks;

// Returns an span over hard fork values for the given network.
std::span<const hard_fork> get_hard_forks(network_type type);

// Returns the height range for which the given block/network version is valid.  Returns a pair of
// heights {A, B} where A/B is the first/last height at which the version is acceptable.  Returns
// nullopt for A if the version indicates a hardfork we do not know about (i.e. we are likely
// outdated), and returns nullopt for B if the version indicates that top network version we know
// about (i.e. there is no subsequent hardfork scheduled).
//
// This method only returns exact hard fork matches and will return a pair of nullopt for skipped
// hard forks.  As a result you should *not* call this method to detecting "are we on HF N or
// higher" because this method will return a pair of nullopts for hardforks that are skipped (such
// as on devnet/testnet); you instead want to use `hard_fork_begins`.
std::pair<std::optional<uint64_t>, std::optional<uint64_t>> get_hard_fork_heights(
        network_type type, hf version);

// Returns the latest hardfork
hard_fork get_latest_hard_fork(network_type type);

// Returns the lowest network version >= the given version, that is, it rounds up missing hf table
// entries to the next largest entry.  Typically this returns the network version itself, but if
// some versions are skipped (particularly on testnet/devnet/fakechain) then this will return the
// next version that does exist in the hard fork list.  If there is no >= value in the hard fork
// table then this returns the given hard fork value itself.
//
// For example, if the HF list contains hf versions {7,8,14} then:
//    hard_fork_ceil(7) == 7
//    hard_fork_ceil(8) == 8
//    hard_fork_ceil(9) == 14
//    ...
//    hard_fork_ceil(14) == 14
//    hard_fork_ceil(15) == 15
hf hard_fork_ceil(network_type type, hf version);

// Returns true if the given height is sufficiently high to be at or after the given hard fork
// version.
bool is_hard_fork_at_least(network_type type, hf version, uint64_t height);

// Returns the active network version and snode revision for the given height.
std::pair<hf, uint8_t> get_network_version_revision(network_type nettype, uint64_t height);

// Returns the network (i.e. block) version for the given height.
inline hf get_network_version(network_type nettype, uint64_t height) {
    return get_network_version_revision(nettype, height).first;
}

// Returns the height at which the given HF (or a later HF) became active.  Somewhat similar to
// `get_hard_fork_heights(...).first`, except that this returns the start height of the first hard
// fork >= the requested hardfork (which matters when the specified hardfork was skipped, such as
// occurs on testnet/devnet/stagenet).
//
// For example, stagenet jumps from HF14 to HF21: `get_hard_fork_heights(stagenet, hf16).first` will
// be nullopt, but `hard_fork_begins(stagenet, hf16)` will return the HF21 fork height.
//
// Equivalent to `get_hard_fork_heights(type, hard_fork_ceil(type, version)).first`
inline std::optional<uint64_t> hard_fork_begins(network_type type, hf version) {
    return get_hard_fork_heights(type, hard_fork_ceil(type, version)).first;
}

// Returns the "ideal" network version that we want to use on blocks we create, which is to use
// the required major version and current minor version.  (Minor versions are sometimes used to
// change network features, but do not change the blockchain rules).
// Before HF19, the minor version must be >= the major version, and is set to the largest major
// version we know about.
std::pair<hf, uint8_t> get_ideal_block_version(network_type nettype, uint64_t height);

}  // namespace cryptonote
