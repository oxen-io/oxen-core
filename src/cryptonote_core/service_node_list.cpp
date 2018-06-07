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

#include <functional>

#include "ringct/rctSigs.h"
#include "wallet/wallet2.h"

#include "service_node_list.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "service_nodes"

namespace service_nodes
{
  service_node_list::service_node_list(cryptonote::Blockchain& blockchain)
    : m_blockchain(blockchain)
  {
    blockchain.hook_block_added(*this);
    blockchain.hook_blockchain_detached(*this);
    blockchain.hook_init(*this);
  }

  void service_node_list::init()
  {
    // TODO: Save this calculation, only do it if it's not here.
    LOG_PRINT_L0("Recalculating service nodes list, scanning last 30 days");

    m_service_nodes_last_reward.clear();

    uint64_t current_height = m_blockchain.get_current_blockchain_height();
    uint64_t start_height = (current_height >= STAKING_REQUIREMENT_LOCK_BLOCKS ? current_height - STAKING_REQUIREMENT_LOCK_BLOCKS : 0);
    for (uint64_t height = start_height; height <= current_height; height += 1000)
    {
      std::list<std::pair<cryptonote::blobdata, cryptonote::block>> blocks;
      if (!m_blockchain.get_blocks(height, 1000, blocks))
      {
        LOG_ERROR("Unable to initialize service nodes list");
        return;
      }
      for (const auto& block_pair : blocks)
      {
        const cryptonote::block& block = block_pair.second;
        std::list<cryptonote::transaction> txs;
        std::list<crypto::hash> missed_txs;
        if (!m_blockchain.get_transactions(block.tx_hashes, txs, missed_txs))
        {
          LOG_ERROR("Unable to get transactions for block " << block.hash);
          return;
        }
        block_added_generic(block, txs);
      }
    }
  }

  bool service_node_list::reg_tx_has_correct_unlock_time(const cryptonote::transaction& tx, uint64_t block_height)
  {
    return tx.unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER && tx.unlock_time == block_height + STAKING_REQUIREMENT_LOCK_BLOCKS;
  }


  bool service_node_list::reg_tx_extract_fields(const cryptonote::transaction& tx, crypto::secret_key& viewkey, crypto::public_key& pub_viewkey, crypto::public_key& pub_spendkey, crypto::public_key& tx_pub_key)
  {
    viewkey = cryptonote::get_viewkey_from_tx_extra(tx.extra);
    pub_spendkey = cryptonote::get_pub_spendkey_from_tx_extra(tx.extra);
    tx_pub_key = cryptonote::get_tx_pub_key_from_extra(tx.extra);
    pub_viewkey = crypto::null_pkey;
    if (!crypto::secret_key_to_public_key(viewkey, pub_viewkey))
      return false;
    return viewkey != crypto::null_skey &&
      pub_spendkey != crypto::null_pkey &&
      tx_pub_key != crypto::null_pkey &&
      pub_viewkey != crypto::null_pkey;
  }

  void service_node_list::reg_tx_calculate_subaddresses(
      const crypto::secret_key& viewkey,
      const crypto::public_key& pub_viewkey,
      const crypto::public_key& pub_spendkey,
      std::vector<crypto::public_key>& subaddresses,
      hw::device& hwdev)
  {
    cryptonote::account_public_address public_address{ pub_spendkey, pub_viewkey };
    cryptonote::account_base account_base;
    account_base.create_from_viewkey(public_address, viewkey);
    subaddresses = hwdev.get_subaddress_spend_public_keys(account_base.get_keys(), 0 /* major account */, 0 /* minor account */, SUBADDRESS_LOOKAHEAD_MINOR);
  }

  bool service_node_list::is_reg_tx_staking_output(const cryptonote::transaction& tx, int i, uint64_t block_height, crypto::key_derivation derivation, std::vector<crypto::public_key> subaddresses, hw::device& hwdev)
  {
    if (tx.vout[i].target.type() != typeid(cryptonote::txout_to_key))
    {
      return false;
    }

    crypto::public_key subaddress_spendkey;
    if (!crypto::derive_subaddress_public_key(boost::get<cryptonote::txout_to_key>(tx.vout[i].target).key,
                                              derivation, i, subaddress_spendkey))
    {
      return false;
    }

    if (std::find(subaddresses.begin(), subaddresses.end(), subaddress_spendkey) == subaddresses.end())
    {
      return false;
    }

    rct::key mask;
    uint64_t money_transferred = 0;

    crypto::secret_key scalar1;
    hwdev.derivation_to_scalar(derivation, i, scalar1);
    try
    {
      switch (tx.rct_signatures.type)
      {
      case rct::RCTTypeSimple:
      case rct::RCTTypeSimpleBulletproof:
        money_transferred = rct::decodeRctSimple(tx.rct_signatures, rct::sk2rct(scalar1), i, mask, hwdev);
        break;
      case rct::RCTTypeFull:
      case rct::RCTTypeFullBulletproof:
        money_transferred = rct::decodeRct(tx.rct_signatures, rct::sk2rct(scalar1), i, mask, hwdev);
        break;
      default:
        LOG_ERROR("Unsupported rct type: " << tx.rct_signatures.type);
        return false;
      }
    }
    catch (const std::exception &e)
    {
      LOG_ERROR("Failed to decode input " << i);
      return false;
    }

    return money_transferred >= m_blockchain.get_staking_requirement(block_height);
  }

  // This function takes a tx and returns true if it is a staking transaction.
  // It also sets the pub_spendkey_out argument to the public spendkey in the
  // transaction.
  //
  bool service_node_list::process_registration_tx(const cryptonote::transaction& tx, uint64_t block_height, crypto::public_key& pub_spendkey_out)
  {
    if (!reg_tx_has_correct_unlock_time(tx, block_height))
    {
      return false;
    }

    crypto::secret_key viewkey;
    crypto::public_key pub_spendkey, pub_viewkey, tx_pub_key;
    
    if (!reg_tx_extract_fields(tx, viewkey, pub_viewkey, pub_spendkey, tx_pub_key))
    {
      return false;
    }

    // TODO(jcktm) - change all this stuff regarding key derivation from
    // the viewkey to be using the actual output decryption key in the tx
    // extra field, or use an old style transaction output so the amount
    // is not encrypted.

    crypto::key_derivation derivation;

    crypto::generate_key_derivation(tx_pub_key, viewkey, derivation);

    hw::device& hwdev = hw::get_device("default");

    std::vector<crypto::public_key> subaddresses;

    reg_tx_calculate_subaddresses(viewkey, pub_viewkey, pub_spendkey, subaddresses, hwdev);

    for (size_t i = 0; i < tx.vout.size(); ++i)
    {
      if (is_reg_tx_staking_output(tx, i, block_height, derivation, subaddresses, hwdev))
      {
        pub_spendkey_out = pub_spendkey;
        return true;
      }
    }
    return false;
  }

  void service_node_list::block_added(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs)
  {
    block_added_generic(block, txs);
  }

  template<typename T>
  void service_node_list::block_added_generic(const cryptonote::block& block, const T& txs)
  {
    uint64_t block_height = cryptonote::get_block_height(block);

    if (block.miner_tx.vout.size() >= 3)
    {
      // TODO: ensure validation of miner tx in validate_miner_tx()

      // TODO: update block reward
      // m_service_nodes_last_reward[pubkey] = block_height;
    }

    for (const crypto::public_key key : get_expired_nodes(block_height))
    {
      auto i = m_service_nodes_last_reward.find(key);
      if (i != m_service_nodes_last_reward.end())
      {
        m_service_nodes_last_reward.erase(i);
        // TODO: store the rollback information
      }
    }

    for (const cryptonote::transaction& tx : txs)
    {
      crypto::public_key pub_spendkey = crypto::null_pkey;
      if (process_registration_tx(tx, block_height, pub_spendkey))
      {
        // TODO: store rollback info
        m_service_nodes_last_reward[pub_spendkey] = block_height;
      }
    }
  }

  void service_node_list::blockchain_detached(uint64_t height)
  {
    // TODO: process reorgs efficiently. This could make a good intro/bootcamp project.
    // For now we just rescan the last 30 days.
    init();
  }

  std::vector<crypto::public_key> service_node_list::get_expired_nodes(uint64_t block_height)
  {
    std::vector<crypto::public_key> expired_nodes;

    if (block_height < STAKING_REQUIREMENT_LOCK_BLOCKS)
      return expired_nodes;

    std::list<std::pair<cryptonote::blobdata, cryptonote::block>> blocks;
    if (!m_blockchain.get_blocks(block_height - STAKING_REQUIREMENT_LOCK_BLOCKS, 1, blocks))
    {
      LOG_ERROR("Unable to get historical blocks");
      return expired_nodes;
    }

    const cryptonote::block& block = blocks.begin()->second;
    std::list<cryptonote::transaction> txs;
    std::list<crypto::hash> missed_txs;
    if (!m_blockchain.get_transactions(block.tx_hashes, txs, missed_txs))
    {
      LOG_ERROR("Unable to get transactions for block " << block.hash);
      return expired_nodes;
    }

    for (const cryptonote::transaction& tx : txs)
    {
      crypto::public_key pubkey;
      if (process_registration_tx(tx, block_height - STAKING_REQUIREMENT_LOCK_BLOCKS, pubkey))
      {
        expired_nodes.push_back(pubkey);
      }
    }

    return expired_nodes;
  }

}
