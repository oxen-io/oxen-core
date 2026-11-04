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

#pragma once
#include <optional>
#include <span>
#include <vector>

#include "common/fs.h"
#include "crypto/hash.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_config.h"
#include "cryptonote_core/service_node_rules.h"
#include "cryptonote_core/service_node_voting.h"

namespace cryptonote {
const fs::path JSON_HASH_FILE_NAME{u8"checkpoints.json"};

enum struct checkpoint_type {
    hardcoded,
    service_node,
    count,
};

struct checkpoint_t {
    uint8_t version = 0;
    checkpoint_type type;
    uint64_t height;
    crypto::hash block_hash;
    std::vector<service_nodes::quorum_signature>
            signatures;    // Only service node checkpoints use signatures
    uint64_t prev_height;  // TODO(doyle): Unused

    bool check(crypto::hash const& block_hash) const;
    static char const* type_to_string(checkpoint_type type) {
        switch (type) {
            case checkpoint_type::hardcoded: return "Hardcoded";
            case checkpoint_type::service_node: return "ServiceNode";
            default: assert(false); return "XXUnhandledVersion";
        }
    }

    template <class Archive>
    void serialize_object(Archive& ar) {
        field(ar, "version", version);
        field_varint(ar, "type", type, [](auto& type) { return type < checkpoint_type::count; });
        field(ar, "height", height);
        field(ar, "block_hash", block_hash);
        field(ar, "signatures", signatures);
        field(ar, "prev_height", prev_height);
    }
};

// Of the newest checkpoints at or below some height (newest first, at most
// CHECKPOINT_NUM_CHECKPOINTS_FOR_CHAIN_FINALITY of them), the one that makes the chain up to it
// immutable, if any: a hardcoded checkpoint is immutable itself; a service node one only once a
// second checkpoint follows it.
inline const checkpoint_t* find_immutable_checkpoint(std::span<const checkpoint_t> newest) {
    static_assert(
            service_nodes::CHECKPOINT_NUM_CHECKPOINTS_FOR_CHAIN_FINALITY == 2,
            "Expect checkpoint finality to be 2, otherwise the immutable logic needs to check for "
            "any hardcoded checkpoints inbetween");
    if (newest.empty())
        return nullptr;
    if (newest[0].type != checkpoint_type::service_node)
        return &newest[0];
    if (newest.size() >= service_nodes::CHECKPOINT_NUM_CHECKPOINTS_FOR_CHAIN_FINALITY)
        return &newest[1];
    return nullptr;
}

struct height_to_hash {
    uint64_t height;   //!< the height of the checkpoint
    std::string hash;  //!< the hash for the checkpoint
};

crypto::hash get_newest_hardcoded_checkpoint(cryptonote::network_type nettype, uint64_t* height);
bool load_checkpoints_from_json(
        const fs::path& json_hashfile_fullpath, std::vector<height_to_hash>& checkpoint_hashes);

/**
 * @brief A container for blockchain checkpoints
 *
 * A checkpoint is a pre-defined hash for the block at a given height.
 * Some of these are compiled-in, while others can be loaded at runtime
 * either from a json file or via DNS from a checkpoint-hosting server.
 */
class checkpoints {
  public:
    void block_add(const block_add_info& info);
    void blockchain_detached(uint64_t height);

    bool get_checkpoint(uint64_t height, checkpoint_t& checkpoint) const;
    /**
     * @brief adds a checkpoint to the container
     *
     * @param height the height of the block the checkpoint is for
     * @param hash_str the hash of the block, as a string
     *
     * @return false if parsing the hash fails, or if the height is a duplicate
     *         AND the existing checkpoint hash does not match the new one,
     *         otherwise returns true
     */
    bool add_checkpoint(uint64_t height, const std::string& hash_str);

    bool update_checkpoint(checkpoint_t const& checkpoint);

    /**
     * @brief checks if there is a checkpoint in the future
     *
     * This function checks if the height passed is lower than the highest
     * checkpoint.
     *
     * @param height the height to check against
     *
     * @return false if no checkpoints, otherwise returns whether or not
     *         the height passed is lower than the highest checkpoint.
     */
    bool is_in_checkpoint_zone(uint64_t height) const;

    /**
     * @brief checks if the given height and hash agree with the checkpoints
     *
     * This function checks if the given height and hash exist in the
     * checkpoints container.  If so, it returns whether or not the passed
     * parameters match the stored values.
     *
     * @param height the height to be checked
     * @param h the hash to be checked
     * @param blockchain the blockchain to query ancestor blocks from the current height
     * @param is_a_checkpoint optional return-by-pointer if there is a checkpoint at the given
     * height
     *
     * @return true if there is no checkpoint at the given height,
     *         true if the passed parameters match the stored checkpoint,
     *         false otherwise
     */
    bool check_block(
            uint64_t height,
            const crypto::hash& h,
            bool* is_a_checkpoint = nullptr,
            bool* service_node_checkpoint = nullptr) const;

    /**
     * @brief checks if alternate chain blocks should be kept for a given height and updates
     * m_immutable_height based on the available checkpoints
     *
     * this basically says if the blockchain is smaller than the first
     * checkpoint then alternate blocks are allowed.  Alternatively, if the
     * last checkpoint *before* the end of the current chain is also before
     * the block to be added, then this is fine.
     *
     * @param blockchain_height the current blockchain height
     * @param block_height the height of the block to be added as alternate
     *
     * @return true if alternate blocks are allowed given the parameters,
     *         otherwise false
     */
    bool is_alternative_block_allowed(
            uint64_t blockchain_height,
            uint64_t block_height,
            bool* service_node_checkpoint = nullptr);

    /**
     * @brief gets the highest checkpoint height
     *
     * @return the height of the highest checkpoint
     */
    uint64_t get_max_height() const;

    /**
     * @brief gets the height of the immutable checkpoint at a height (see
     * find_immutable_checkpoint), if there is one
     */
    std::optional<uint64_t> immutable_height(uint64_t height);

    /**
     * @brief loads the default main chain checkpoints
     * @param nettype network type
     *
     * @return true unless adding a checkpoint fails
     */
    bool init(network_type nettype, class BlockchainDB* db);

  private:
    network_type m_nettype = network_type::UNDEFINED;
    uint64_t m_last_cull_height = 0;
    uint64_t m_immutable_height = 0;
    BlockchainDB* m_db;

    // What the immutable checkpoint follows from at every height from `height` up to (not
    // including) `next`: the newest checkpoints at or below `height`, as find_immutable_checkpoint
    // takes them (without their signatures).  block_add needs it for every block, and querying the
    // DB for it each time was a significant part of adding a block, but it only changes when the
    // chain reaches a checkpoint or one is added or removed.  Every change to the checkpoints goes
    // through this class, which keeps this up to date (or drops it) as it makes them; a detach
    // drops it.
    struct finality_cache {
        uint64_t height;
        std::vector<checkpoint_t> newest;
        std::optional<uint64_t> next;
    };
    std::optional<finality_cache> m_finality;

    void cache_added(const checkpoint_t& checkpoint);
    void remove_checkpoint(uint64_t height);
};

}  // namespace cryptonote
