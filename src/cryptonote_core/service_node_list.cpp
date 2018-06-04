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

#include "service_node_list.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "service_nodes"

namespace service_nodes
{
  service_node_list::service_node_list(cryptonote::Blockchain& blockchain)
    : m_blockchain(blockchain)
  {
    blockchain.hook_new_block([&](const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs) {
      add_block(block, txs);
    });
    blockchain.hook_remove_block([&](const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs) {
      remove_block(block, txs);
    });
    blockchain.hook_init([&]() {
      init();
    });
  }

  void service_node_list::init()
  {
    LOG_PRINT_L0("Recalculating service nodes list (this may take some time)");
    // TODO: Save this calculation, only do it if it's not here.
    uint64_t current_height = m_blockchain.get_current_blockchain_height();
    for (uint64_t start_height = 1; start_height <= current_height; start_height += 1000)
    {
      std::list<std::pair<cryptonote::blobdata, cryptonote::block>> blocks;
      if (!m_blockchain.get_blocks(start_height, 1000, blocks))
      {
        LOG_ERROR("Unable to initialize service nodes list");
        return;
      }
      for (const auto block_pair : blocks)
      {
        const cryptonote::block& block = block_pair.second;
        std::list<cryptonote::transaction> txs;
        std::list<crypto::hash> missed_txs;
        if (!m_blockchain.get_transactions(block.tx_hashes, txs, missed_txs))
        {
          LOG_ERROR("Unable to get transactions for block " << block.hash);
          return;
        }
        std::vector<cryptonote::transaction> txs_vector{ std::make_move_iterator(std::begin(txs)),
                                                         std::make_move_iterator(std::end(txs)) };
        add_block(block, txs_vector);
      }
    }
  }

  // This function takes a tx and returns true if it is a staking transaction.
  // It also sets the pub_spendkey_out argument to the public spendkey in the
  // transaction.
  //
  bool service_node_list::process_tx(const cryptonote::transaction& tx, uint64_t block_height, crypto::public_key& pub_spendkey_out)
  {
    if (tx.unlock_time < CRYPTONOTE_MAX_BLOCK_NUMBER && tx.unlock_time == block_height + STAKING_REQUIREMENT_LOCK_BLOCKS)
    {
      uint64_t lock_time = tx.unlock_time - block_height;
      LOG_PRINT_L0("Found tx with lock time " << lock_time << " = " << tx.unlock_time << " - " << block_height);

      crypto::secret_key viewkey = cryptonote::get_viewkey_from_tx_extra(tx.extra);
      crypto::public_key pub_spendkey = cryptonote::get_pub_spendkey_from_tx_extra(tx.extra);
      crypto::public_key tx_pub_key = cryptonote::get_tx_pub_key_from_extra(tx.extra);

      if (viewkey != crypto::null_skey && pub_spendkey != crypto::null_pkey && tx_pub_key != crypto::null_pkey)
      {
        crypto::public_key pub_viewkey = crypto::null_pkey;
        if (!crypto::secret_key_to_public_key(viewkey, pub_viewkey))
        {
          LOG_ERROR("Couldn't calculate public key from secret key. Skipping transaction.");
          return false;
        }

        // TODO(jcktm) - change all this stuff regarding key derivation from
        // the viewkey to be using the actual output decryption key in the tx
        // extra field, or use an old style transaction output so the amount
        // is not encrypted.

        crypto::key_derivation derivation;
        crypto::generate_key_derivation(tx_pub_key, viewkey, derivation);

        hw::device& hwdev = hw::get_device("default");
        cryptonote::account_public_address public_address{ pub_spendkey, pub_viewkey };
        cryptonote::account_base account_base;
        account_base.create_from_viewkey(public_address, viewkey);
        const std::vector<crypto::public_key> subaddresses = hwdev.get_subaddress_spend_public_keys(account_base.get_keys(), 0 /* major account */, 0 /* minor account */, SUBADDRESS_LOOKAHEAD_MINOR);

        for (size_t i = 0; i < tx.vout.size(); ++i)
        {
          if (tx.vout[i].target.type() != typeid(cryptonote::txout_to_key))
          {
            LOG_ERROR("wrong type id in transaction out, skipping");
            return false;
          }

          crypto::public_key subaddress_spendkey;
          if (!crypto::derive_subaddress_public_key(boost::get<cryptonote::txout_to_key>(tx.vout[i].target).key,
                                                    derivation, i, subaddress_spendkey))
          {
            LOG_ERROR("Couldn't derive subaddress public key for tx out, skipping");
            return false;
          }

          if (std::find(subaddresses.begin(), subaddresses.end(), subaddress_spendkey) == subaddresses.end())
          {
            LOG_ERROR("Couldn't find subaddress in derived addresses for tx out, skipping");
            return false;
          }

          //boost::unique_lock<hw::device> hwdev_lock (hwdev); // TODO: What is going on here?
          //hwdev_lock.lock();
          hwdev.set_mode(hw::device::NONE);
          cryptonote::keypair in_ephemeral;
          crypto::key_image ki;
          bool r = cryptonote::generate_key_image_helper_precomp(account_base.get_keys(),
                                                                 boost::get<cryptonote::txout_to_key>(tx.vout[i].target).key,
                                                                 derivation, i, {0, 0}, in_ephemeral, ki, hwdev);
          //hwdev_lock.unlock();

          if (!r)
          {
            LOG_ERROR("could not generate key image for tx out, skipping");
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
              break;
            }
          }
          catch (const std::exception &e)
          {
            LOG_ERROR("Failed to decode input " << i);
            return false;
          }

          if (money_transferred >= STAKING_REQUIREMENT)
          {
            pub_spendkey_out = pub_spendkey;
            return true;
          }
        }
      }
    }
    return false;
  }

  void service_node_list::add_block(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs)
  {
    if (!m_service_nodes_pubkeys.empty())
    {
      m_service_nodes_pubkeys.push_back(m_service_nodes_pubkeys.front());
      m_service_nodes_pubkeys.pop_front();
    }

    // TODO: find nodes that should be removed from the list that expire on this block

    uint64_t block_height = cryptonote::get_block_height(block);
    for (const cryptonote::transaction& tx : txs)
    {
      crypto::public_key pub_spendkey = crypto::null_pkey;
      if (process_tx(tx, block_height, pub_spendkey))
      {
        m_service_nodes_pubkeys.push_back(pub_spendkey);
      }
    }
  }

  void service_node_list::remove_block(const cryptonote::block& block, const std::vector<cryptonote::transaction>& txs)
  {
    uint64_t block_height = cryptonote::get_block_height(block);
    for (auto i = txs.rbegin(); i != txs.rend(); i++)
    {
      crypto::public_key pub_spendkey = crypto::null_pkey;
      if (process_tx(*i, block_height, pub_spendkey))
      {
        if (m_service_nodes_pubkeys.back() != pub_spendkey)
        {
          LOG_ERROR("Tried rolling back a tx that wasn't at the end of the service node list");
          // TODO: Tom what should we do here? Trigger a rescan?
        }
        m_service_nodes_pubkeys.pop_back();
      }
    }

    // TODO: find nodes that should be added to the list that expire on this block

    if (!m_service_nodes_pubkeys.empty())
    {
      m_service_nodes_pubkeys.push_front(m_service_nodes_pubkeys.back());
      m_service_nodes_pubkeys.pop_back();
    }
  }
}
