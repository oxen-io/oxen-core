// Copyright (c) 2014-2018, The Monero Project
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

#include "checkpoints.h"

#include "common/dns_utils.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h" // epee json include
#include "serialization/keyvalue_serialization.h"
#include <vector>

using namespace epee;

#include "common/loki_integration_test_hooks.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "checkpoints"

namespace cryptonote
{
  /**
   * @brief struct for loading a checkpoint from json
   */
  struct t_hashline
  {
    uint64_t height; //!< the height of the checkpoint
    std::string hash; //!< the hash for the checkpoint
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(height)
          KV_SERIALIZE(hash)
        END_KV_SERIALIZE_MAP()
  };

  /**
   * @brief struct for loading many checkpoints from json
   */
  struct t_hash_json {
    std::vector<t_hashline> hashlines; //!< the checkpoint lines from the file
        BEGIN_KV_SERIALIZE_MAP()
          KV_SERIALIZE(hashlines)
        END_KV_SERIALIZE_MAP()
  };

  //---------------------------------------------------------------------------
  bool checkpoints::add_checkpoint(uint64_t height, const std::string& hash_str)
  {
    crypto::hash h = crypto::null_hash;
    bool r         = epee::string_tools::hex_to_pod(hash_str, h);
    CHECK_AND_ASSERT_MES(r, false, "Failed to parse checkpoint hash string into binary representation!");

    if (m_points.count(height)) // return false if adding at a height we already have AND the hash is different
    {
      checkpoint_t const &checkpoint = m_points[height];
      crypto::hash const &curr_hash  = checkpoint.block_hash;
      CHECK_AND_ASSERT_MES(h == curr_hash, false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
    }
    else
    {
      checkpoint_t checkpoint = {};
      checkpoint.type         = checkpoint_type::predefined_or_dns;
      checkpoint.block_hash   = h;
      m_points[height]        = checkpoint;
    }

    return true;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::add_or_update_service_node_checkpoint(crypto::hash const &block_hash, service_nodes::checkpoint_vote const &vote)
  {
    if (m_points.count(vote.block_height))
      return true;

    uint64_t newest_checkpoint_height = get_max_height();
    if (vote.block_height < newest_checkpoint_height)
      return true;

    std::vector<checkpoint_t>::iterator curr_checkpoint = std::find_if(m_staging_points.begin(), m_staging_points.end(), [block_hash](checkpoint_t const &checkpoint) {
      bool result = (checkpoint.block_hash == block_hash);
      return result;
    });

    if (curr_checkpoint == m_staging_points.end())
    {
      checkpoint_t new_checkpoint = {};
      new_checkpoint.type         = checkpoint_type::service_node;
      new_checkpoint.block_hash   = block_hash;
      m_staging_points.push_back(new_checkpoint);
      curr_checkpoint = (m_staging_points.end() - 1);
    }

    const auto compare_vote_and_voter_to_signature = [](service_nodes::checkpoint_vote const &a, service_nodes::voter_to_signature const &b) {
      return a.voters_quorum_index < b.quorum_index;
    };

    auto signature_it = std::upper_bound(curr_checkpoint->signatures.begin(), curr_checkpoint->signatures.end(), vote, compare_vote_and_voter_to_signature);
    if (signature_it == curr_checkpoint->signatures.end() || signature_it->quorum_index != vote.voters_quorum_index)
    {
      service_nodes::voter_to_signature new_voter_to_signature = {};
      new_voter_to_signature.quorum_index                      = vote.voters_quorum_index;
      new_voter_to_signature.signature                         = vote.signature;
      curr_checkpoint->signatures.insert(signature_it, new_voter_to_signature);

      // TODO(doyle): Quorum SuperMajority variable
      if (curr_checkpoint->signatures.size() > 7)
      {
        m_points[vote.block_height] = *curr_checkpoint;
        m_staging_points.erase(curr_checkpoint);
      }
    }

    return true;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_in_checkpoint_zone(uint64_t height) const
  {
    return !m_points.empty() && (height <= (--m_points.end())->first);
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_block(uint64_t height, const crypto::hash& h, bool* is_a_checkpoint) const
  {
    auto it = m_points.find(height);
    bool found  = (it != m_points.end());
    if (*is_a_checkpoint) *is_a_checkpoint = found;

    if(!found)
      return true;

    checkpoint_t const &checkpoint = it->second;
    bool result = checkpoint.block_hash == h;
    if (result) MINFO   ("CHECKPOINT PASSED FOR HEIGHT " << height << " " << h);
    else        MWARNING("CHECKPOINT FAILED FOR HEIGHT " << height << ". EXPECTED HASH " << checkpoint.block_hash << "FETCHED HASH: " << h);
    return result;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::is_alternative_block_allowed(uint64_t blockchain_height, uint64_t block_height) const
  {
    if (0 == block_height)
      return false;

    auto it = m_points.upper_bound(blockchain_height);
    if (it == m_points.begin()) // Is blockchain_height before the first checkpoint?
      return true;

    //
    // NOTE: Verify alt block height is no older than the 2nd closest service
    // node checkpoint OR the 1st non service node checkpoint.
    //
    // Don't allow blocks older than a checkpoint if it is not a service node checkpoint
    // They are hardcoded in the code for a reason. NOTE: Loki disables DNS checkpoints for now.
    //
    uint64_t sentinel_height = 0;
    int      num_checkpoints = 0;
    for (auto it = m_points.rbegin(); it != m_points.rend() && num_checkpoints < 2; it++, num_checkpoints++)
    {
      const uint64_t checkpoint_height = it->first;
      const checkpoint_t &checkpoint   = it->second;
      sentinel_height                  = checkpoint_height;

      if (checkpoint.type == checkpoint_type::predefined_or_dns)
        break;
    }

    bool result = block_height > sentinel_height;
    return result;
  }
  //---------------------------------------------------------------------------
  uint64_t checkpoints::get_max_height() const
  {
    uint64_t result = 0;
    if (m_points.size() > 0)
    {
      auto last_it = m_points.rbegin();
      result = last_it->first;
    }

    return result;
  }
  //---------------------------------------------------------------------------
  bool checkpoints::check_for_conflicts(const checkpoints& other) const
  {
    for (auto& pt : other.get_points())
    {
      if (m_points.count(pt.first))
      {
        checkpoint_t const &our_checkpoint   = m_points.at(pt.first);
        checkpoint_t const &their_checkpoint = pt.second;
        CHECK_AND_ASSERT_MES(our_checkpoint.block_hash == their_checkpoint.block_hash, false, "Checkpoint at given height already exists, and hash for new checkpoint was different!");
      }
    }
    return true;
  }

  bool checkpoints::init_default_checkpoints(network_type nettype)
  {
    switch (nettype) {
      case STAGENET:
        break;
      case TESTNET:
        break;
      case FAKECHAIN:
        break;
      case UNDEFINED:
        break;
      case MAINNET:
#if !defined(LOKI_ENABLE_INTEGRATION_TEST_HOOKS)
        ADD_CHECKPOINT(0,     "08ff156d993012b0bdf2816c4bee47c9bbc7930593b70ee02574edddf15ee933");
        ADD_CHECKPOINT(1,     "647997953a5ea9b5ab329c2291d4cbb08eed587c287e451eeeb2c79bab9b940f");
        ADD_CHECKPOINT(10,    "4a7cd8b9bff380d48d6f3533a5e0509f8589cc77d18218b3f7218846e77738fc");
        ADD_CHECKPOINT(100,   "01b8d33a50713ff837f8ad7146021b8e3060e0316b5e4afc407e46cdb50b6760");
        ADD_CHECKPOINT(1000,  "5e3b0a1f931885bc0ab1d6ecdc625816576feae29e2f9ac94c5ccdbedb1465ac");
        ADD_CHECKPOINT(86535, "52b7c5a60b97bf1efbf0d63a0aa1a313e8f0abe4627eb354b0c5a73cb1f4391e");
        ADD_CHECKPOINT(97407, "504af73abbaba85a14ddc16634658bf4dcc241dc288b1eaad09e216836b71023");
        ADD_CHECKPOINT(98552, "2058d5c675bd91284f4996435593499c9ab84a5a0f569f57a86cde2e815e57da");
        ADD_CHECKPOINT(144650,"a1ab207afc790675070ecd7aac874eb0691eb6349ea37c44f8f58697a5d6cbc4");
#endif
        break;
    }
    return true;
  }

  bool checkpoints::load_checkpoints_from_json(const std::string &json_hashfile_fullpath)
  {
    boost::system::error_code errcode;
    if (! (boost::filesystem::exists(json_hashfile_fullpath, errcode)))
    {
      LOG_PRINT_L1("Blockchain checkpoints file not found");
      return true;
    }

    LOG_PRINT_L1("Adding checkpoints from blockchain hashfile");

    uint64_t prev_max_height = get_max_height();
    LOG_PRINT_L1("Hard-coded max checkpoint height is " << prev_max_height);
    t_hash_json hashes;
    if (!epee::serialization::load_t_from_json_file(hashes, json_hashfile_fullpath))
    {
      MERROR("Error loading checkpoints from " << json_hashfile_fullpath);
      return false;
    }
    for (std::vector<t_hashline>::const_iterator it = hashes.hashlines.begin(); it != hashes.hashlines.end(); )
    {
      uint64_t height;
      height = it->height;
      if (height <= prev_max_height) {
	LOG_PRINT_L1("ignoring checkpoint height " << height);
      } else {
	std::string blockhash = it->hash;
	LOG_PRINT_L1("Adding checkpoint height " << height << ", hash=" << blockhash);
	ADD_CHECKPOINT(height, blockhash);
      }
      ++it;
    }

    return true;
  }

  bool checkpoints::load_checkpoints_from_dns(network_type nettype)
  {
    return true;
  }

  bool checkpoints::load_new_checkpoints(const std::string &json_hashfile_fullpath, network_type nettype, bool dns)
  {
    bool result;

    result = load_checkpoints_from_json(json_hashfile_fullpath);
    if (dns)
    {
      result &= load_checkpoints_from_dns(nettype);
    }

    return result;
  }
}
