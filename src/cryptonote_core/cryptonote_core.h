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

#include <ctime>
#include <future>
#include <chrono>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>

#include "cryptonote_protocol/cryptonote_protocol_handler_common.h"
#include "storages/portable_storage_template_helper.h"
#include "common/download.h"
#include "common/command_line.h"
#include "tx_pool.h"
#include "blockchain.h"
#include "service_node_voting.h"
#include "service_node_list.h"
#include "service_node_quorum_cop.h"
#include "cryptonote_core/miner.h"
#include "cryptonote_basic/connection_context.h"
#include "cryptonote_basic/cryptonote_stat_info.h"
#include "warnings.h"
#include "crypto/hash.h"
PUSH_WARNINGS
DISABLE_VS_WARNINGS(4355)

#include "common/loki_integration_test_hooks.h"
namespace cryptonote
{
  using namespace std::literals;

   struct test_options {
     std::vector<std::pair<uint8_t, uint64_t>> hard_forks;
     size_t long_term_block_weight_window;
   };

  extern const command_line::arg_descriptor<std::string, false, true, 2> arg_data_dir;
  extern const command_line::arg_descriptor<bool, false> arg_testnet_on;
  extern const command_line::arg_descriptor<bool, false> arg_stagenet_on;
  extern const command_line::arg_descriptor<bool, false> arg_regtest_on;
  extern const command_line::arg_descriptor<difficulty_type> arg_fixed_difficulty;
  extern const command_line::arg_descriptor<bool> arg_dev_allow_local;
  extern const command_line::arg_descriptor<bool> arg_offline;
  extern const command_line::arg_descriptor<size_t> arg_block_download_max_size;
  extern const command_line::arg_descriptor<uint64_t> arg_recalculate_difficulty;

  // Function pointers that are set to throwing stubs and get replaced by the actual functions in
  // cryptonote_protocol/quorumnet.cpp's quorumnet::init_core_callbacks().  This indirection is here
  // so that core doesn't need to link against cryptonote_protocol (plus everything it depends on).

  // Starts the quorumnet listener.  Return an opaque pointer (void *) that gets passed into all the
  // other callbacks below so that the callbacks can recast it into whatever it should be.  `bind`
  // will be null if the quorumnet object is started in remote-only (non-listening) mode, which only
  // happens on-demand when running in non-SN mode.
  extern void *(*quorumnet_new)(core &core, const std::string &bind);
  // Stops the quorumnet listener; is expected to delete the object and reset the pointer to nullptr.
  extern void (*quorumnet_delete)(void *&self);
  // Relays votes via quorumnet.
  extern void (*quorumnet_relay_obligation_votes)(void *self, const std::vector<service_nodes::quorum_vote_t> &votes);
  // Sends a blink tx to the current blink quorum, returns a future that can be used to wait for the
  // result.
  extern std::future<std::pair<blink_result, std::string>> (*quorumnet_send_blink)(void *self, const std::string &tx_blob);
  extern bool init_core_callback_complete;


  /************************************************************************/
  /*                                                                      */
  /************************************************************************/

   /**
    * @brief handles core cryptonote functionality
    *
    * This class coordinates cryptonote functionality including, but not
    * limited to, communication among the Blockchain, the transaction pool,
    * any miners, and the network.
    */
   class core: public i_miner_handler
   {
   public:

      /**
       * @brief constructor
       *
       * sets member variables into a usable state
       *
       * @param pprotocol pre-constructed protocol object to store and use
       */
     explicit core(i_cryptonote_protocol* pprotocol);

     // Non-copyable:
     core(const core &) = delete;
     core &operator=(const core &) = delete;

     /**
      * @brief calls various idle routines
      *
      * @note see miner::on_idle and tx_memory_pool::on_idle
      *
      * @return true
      */
     bool on_idle();

     /**
      * @brief handles an incoming uptime proof
      *
      * Parses an incoming uptime proof
      *
      * @return true if we haven't seen it before and thus need to relay.
      */
     bool handle_uptime_proof(const NOTIFY_UPTIME_PROOF::request &proof, bool &my_uptime_proof_confirmation);

     /**
      * @brief handles an incoming transaction
      *
      * Parses an incoming transaction and, if nothing is obviously wrong,
      * passes it along to the transaction pool
      *
      * @param tx_blob the tx to handle
      * @param tvc metadata about the transaction's validity
      * @param opts tx pool options for accepting this tx
      *
      * @return true if the transaction was accepted (or already exists), false otherwise
      */
     bool handle_incoming_tx(const blobdata& tx_blob, tx_verification_context& tvc, const tx_pool_options &opts);

     /**
      * Returned type of parse_incoming_txs() that provides details about which transactions failed
      * and why.  This is passed on to handle_parsed_txs() (potentially after modification such as
      * setting `approved_blink`) to handle_parsed_txs() to actually insert the transactions.
      */
     struct tx_verification_batch_info {
       tx_verification_context tvc{}; // Verification information
       bool parsed = false; // Will be true if we were able to at least parse the transaction
       bool result = false; // Indicates that the transaction was parsed and passed some basic checks
       bool already_have = false; // Indicates that the tx was found to already exist (in mempool or blockchain)
       bool approved_blink = false; // Can be set between the parse and handle calls to make this a blink tx (that replaces conflicting non-blink txes)
       const blobdata *blob = nullptr; // Will be set to a pointer to the incoming blobdata (i.e. string). caller must keep it alive!
       crypto::hash tx_hash; // The transaction hash (only set if `parsed`)
       transaction tx; // The parsed transaction (only set if `parsed`)
     };

     /// Returns an RAII unique lock holding the incoming tx mutex.
     auto incoming_tx_lock() { return std::unique_lock<boost::recursive_mutex>{m_incoming_tx_lock}; }

     /**
      * @brief parses a list of incoming transactions
      *
      * Parses incoming transactions and checks them for structural validity and whether they are
      * already seen.  The result is intended to be passed onto handle_parsed_txs (possibly with a
      * remove_conflicting_txs() first).
      *
      * m_incoming_tx_lock must already be held (i.e. via incoming_tx_lock()), and should be held
      * until the returned value is passed on to handle_parsed_txs.
      *
      * @param tx_blobs the txs to parse.  References to these blobs are stored inside the returned
      * vector: THE CALLER MUST ENSURE THE BLOBS PERSIST UNTIL THE RETURNED VECTOR IS PASSED OFF TO
      * HANDLE_INCOMING_TXS()!
      *
      * @return vector of tx_verification_batch_info structs for the given transactions.
      */
     std::vector<tx_verification_batch_info> parse_incoming_txs(const std::vector<blobdata>& tx_blobs, const tx_pool_options &opts);

     /**
      * @brief handles parsed incoming transactions
      *
      * Takes parsed incoming tx info (as returned by parse_incoming_txs) and attempts to insert any
      * valid, not-already-seen transactions into the mempool.  Returns the indices of any
      * transactions that failed insertion.
      *
      * m_incoming_tx_lock should already be held (i.e. via incoming_tx_lock()) from before the call to
      * parse_incoming_txs.
      *
      * @param tx_info the parsed transaction information to insert; transactions that have already
      * been detected as failed (`!info.result`) are not inserted but still treated as failures for
      * the return value.  Already existing txs (`info.already_have`) are ignored without triggering
      * a failure return.  `tvc` subelements in this vector are updated when insertion into the pool
      * is attempted (see tx_memory_pool::add_tx).
      *
      * @param opts tx pool options for accepting these transactions
      *
      * @param blink_rollback_height pointer to a uint64_t value to set to a rollback height *if*
      * one of the incoming transactions is tagged as a blink tx and that tx conflicts with a
      * recently mined, but not yet immutable block.  *Required* for blink handling (of tx_info
      * values with `.approved_blink` set) to be done.
      *
      * @return false if any transactions failed verification, true otherwise.  (To determine which
      * ones failed check the `tvc` values).
      */
     bool handle_parsed_txs(std::vector<tx_verification_batch_info> &parsed_txs, const tx_pool_options &opts, uint64_t *blink_rollback_height = nullptr);

     /**
      * Wrapper that does a parse + handle when nothing is needed between the parsing the handling.
      *
      * Both operations are performed under the required incoming transaction lock.
      *
      * @param tx_blobs see parse_incoming_txs
      * @param opts tx pool options for accepting these transactions
      *
      * @return vector of parsed transactions information with individual transactions results
      * available via the .tvc element members.
      */
     std::vector<tx_verification_batch_info> handle_incoming_txs(const std::vector<blobdata>& tx_blobs, const tx_pool_options &opts);

     /**
      * @brief parses and filters received blink transaction signatures
      *
      * This takes a vector of blink transaction metadata (typically from a p2p peer) and returns a
      * vector of blink_txs with signatures applied for any transactions that do not already have
      * stored blink signatures and can have applicable blink signatures (i.e. not in an immutable
      * mined block).
      *
      * Note that this does not require that enough valid signatures are present: the caller should
      * check `->approved()` on the return blinks to validate blink with valid signature sets.
      *
      * @param blinks vector of serializable_blink_metadata
      *
      * @return pair: `.first` is a vector of blink_tx shared pointers of any blink info that isn't
      * already stored and isn't for a known, immutable transaction.  `.second` is an unordered_set
      * of unknown (i.e.  neither on the chain or in the pool) transaction hashes.  Returns empty
      * containers if blinks are not yet enabled on the blockchain.
      */
     std::pair<std::vector<std::shared_ptr<blink_tx>>, std::unordered_set<crypto::hash>>
     parse_incoming_blinks(const std::vector<serializable_blink_metadata> &blinks);

     /**
      * @brief adds incoming blinks into the blink pool.
      *
      * This is for use with mempool txes or txes in recently mined blocks, though this is not
      * checked.  In the given input, only blinks with `approved()` status will be added; any
      * without full approval will be skipped.  Any blinks that are already stored will also be
      * skipped.  Typically this is used after `parse_incoming_blinks`.
      *
      * @param blinks vector of blinks, typically from parse_incoming_blinks.
      *
      * @return the number of blinks that were added.  Note that 0 is *not* an error value: it is
      * possible for no blinks to be added if all already exist.
      */
     int add_blinks(const std::vector<std::shared_ptr<blink_tx>> &blinks);

     /**
      * @brief handles an incoming blink transaction by dispatching it to the service node network
      * via quorumnet.  If this node is not a service node this will start up quorumnet in
      * remote-only mode the first time it is called.
      *
      * @param tx_blob the transaction data
      *
      * @returns a pair of a blink result value: rejected, accepted, or timeout; and a rejection
      * reason as returned by one of the blink quorum nodes.
      */
     std::future<std::pair<blink_result, std::string>> handle_blink_tx(const std::string &tx_blob);

     /**
      * @brief handles an incoming block
      *
      * periodic update to checkpoints is triggered here
      * Attempts to add the block to the Blockchain and, on success,
      * optionally updates the miner's block template.
      *
      * @param block_blob the block to be added
      * @param block the block to be added, or NULL
      * @param bvc return-by-reference metadata context about the block's validity
      * @param update_miner_blocktemplate whether or not to update the miner's block template
      *
      * @return false if loading new checkpoints fails, or the block is not
      * added, otherwise true
      */
     bool handle_incoming_block(const blobdata& block_blob, const block *b, block_verification_context& bvc, checkpoint_t *checkpoint, bool update_miner_blocktemplate = true);

     /**
      * @copydoc Blockchain::prepare_handle_incoming_blocks
      *
      * @note see Blockchain::prepare_handle_incoming_blocks
      */
     bool prepare_handle_incoming_blocks(const std::vector<block_complete_entry> &blocks_entry, std::vector<block> &blocks);

     /**
      * @copydoc Blockchain::cleanup_handle_incoming_blocks
      *
      * @note see Blockchain::cleanup_handle_incoming_blocks
      */
     bool cleanup_handle_incoming_blocks(bool force_sync = false);
     	     	
     /**
      * @brief check the size of a block against the current maximum
      *
      * @param block_blob the block to check
      *
      * @return whether or not the block is too big
      */
     bool check_incoming_block_size(const blobdata& block_blob) const;

     /**
      * @brief get the cryptonote protocol instance
      *
      * @return the instance
      */
     i_cryptonote_protocol* get_protocol(){return m_pprotocol;}

     //-------------------- i_miner_handler -----------------------

     /**
      * @brief stores and relays a block found by a miner
      *
      * Updates the miner's target block, attempts to store the found
      * block in Blockchain, and -- on success -- relays that block to
      * the network.
      *
      * @param b the block found
      * @param bvc returns the block verification flags
      *
      * @return true if the block was added to the main chain, otherwise false
      */
     virtual bool handle_block_found(block& b, block_verification_context &bvc);

     /**
      * @copydoc Blockchain::create_block_template
      *
      * @note see Blockchain::create_block_template
      */
     virtual bool get_block_template(block& b, const account_public_address& adr, difficulty_type& diffic, uint64_t& height, uint64_t& expected_reward, const blobdata& ex_nonce);
     virtual bool get_block_template(block& b, const crypto::hash *prev_block, const account_public_address& adr, difficulty_type& diffic, uint64_t& height, uint64_t& expected_reward, const blobdata& ex_nonce);

     /**
      * @brief called when a transaction is relayed; return the hash of the parsed tx, or null_hash
      * on parse failure.
      */
     virtual crypto::hash on_transaction_relayed(const cryptonote::blobdata& tx);

     /**
      * @brief gets the miner instance
      *
      * @return a reference to the miner instance
      */
     miner& get_miner(){return m_miner;}

     /**
      * @brief gets the miner instance (const)
      *
      * @return a const reference to the miner instance
      */
     const miner& get_miner()const{return m_miner;}

     /**
      * @brief adds command line options to the given options set
      *
      * As of now, there are no command line options specific to core,
      * so this function simply returns.
      *
      * @param desc return-by-reference the command line options set to add to
      */
     static void init_options(boost::program_options::options_description& desc);

     /**
      * @brief initializes the core as needed
      *
      * This function initializes the transaction pool, the Blockchain, and
      * a miner instance with parameters given on the command line (or defaults)
      *
      * @param vm command line parameters
      * @param test_options configuration options for testing
      * @param get_checkpoints if set, will be called to get checkpoints data, must return checkpoints data pointer and size or nullptr if there ain't any checkpoints for specific network type
      *
      * @return false if one of the init steps fails, otherwise true
      */
     bool init(const boost::program_options::variables_map& vm, const test_options *test_options = NULL, const GetCheckpointsCallback& get_checkpoints = nullptr);

     /**
      * @copydoc Blockchain::reset_and_set_genesis_block
      *
      * @note see Blockchain::reset_and_set_genesis_block
      */
     bool set_genesis_block(const block& b);

     /**
      * @brief performs safe shutdown steps for core and core components
      *
      * Uninitializes the miner instance, transaction pool, and Blockchain
      *
      * @return true
      */
     bool deinit();

     /**
      * @brief sets to drop blocks downloaded (for testing)
      */
     void test_drop_download();

     /**
      * @brief sets to drop blocks downloaded below a certain height
      *
      * @param height height below which to drop blocks
      */
     void test_drop_download_height(uint64_t height);

     /**
      * @brief gets whether or not to drop blocks (for testing)
      *
      * @return whether or not to drop blocks
      */
     bool get_test_drop_download() const;

     /**
      * @brief gets whether or not to drop blocks
      *
      * If the current blockchain height <= our block drop threshold
      * and test drop blocks is set, return true
      *
      * @return see above
      */
     bool get_test_drop_download_height() const;

     /**
      * @copydoc Blockchain::get_current_blockchain_height
      *
      * @note see Blockchain::get_current_blockchain_height()
      */
     uint64_t get_current_blockchain_height() const;

     /**
      * @brief get the hash and height of the most recent block
      *
      * @param height return-by-reference height of the block
      * @param top_id return-by-reference hash of the block
      */
     void get_blockchain_top(uint64_t& height, crypto::hash& top_id) const;

     /**
      * @copydoc Blockchain::get_blocks(uint64_t, size_t, std::vector<std::pair<cryptonote::blobdata,block>>&, std::vector<transaction>&) const
      *
      * @note see Blockchain::get_blocks(uint64_t, size_t, std::vector<std::pair<cryptonote::blobdata,block>>&, std::vector<transaction>&) const
      */
     bool get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<cryptonote::blobdata,block>>& blocks, std::vector<cryptonote::blobdata>& txs) const;

     /**
      * @copydoc Blockchain::get_blocks(uint64_t, size_t, std::vector<std::pair<cryptonote::blobdata,block>>&) const
      *
      * @note see Blockchain::get_blocks(uint64_t, size_t, std::vector<std::pair<cryptonote::blobdata,block>>&) const
      */
     bool get_blocks(uint64_t start_offset, size_t count, std::vector<std::pair<cryptonote::blobdata,block>>& blocks) const;

     /**
      * @copydoc Blockchain::get_blocks(uint64_t, size_t, std::vector<std::pair<cryptonote::blobdata,block>>&) const
      *
      * @note see Blockchain::get_blocks(uint64_t, size_t, std::vector<std::pair<cryptonote::blobdata,block>>&) const
      */
     bool get_blocks(uint64_t start_offset, size_t count, std::vector<block>& blocks) const;

     /**
      * @copydoc Blockchain::get_blocks(const t_ids_container&, t_blocks_container&, t_missed_container&) const
      *
      * @note see Blockchain::get_blocks(const t_ids_container&, t_blocks_container&, t_missed_container&) const
      */
     template<class t_ids_container, class t_blocks_container, class t_missed_container>
     bool get_blocks(const t_ids_container& block_ids, t_blocks_container& blocks, t_missed_container& missed_bs) const
     {
       return m_blockchain_storage.get_blocks(block_ids, blocks, missed_bs);
     }

     /**
      * @copydoc Blockchain::get_block_id_by_height
      *
      * @note see Blockchain::get_block_id_by_height
      */
     crypto::hash get_block_id_by_height(uint64_t height) const;

     /**
      * @copydoc Blockchain::get_transactions
      *
      * @note see Blockchain::get_transactions
      */
     bool get_transactions(const std::vector<crypto::hash>& txs_ids, std::vector<cryptonote::blobdata>& txs, std::vector<crypto::hash>& missed_txs) const;

     /**
      * @copydoc Blockchain::get_transactions
      *
      * @note see Blockchain::get_transactions
      */
     bool get_split_transactions_blobs(const std::vector<crypto::hash>& txs_ids, std::vector<std::tuple<crypto::hash, cryptonote::blobdata, crypto::hash, cryptonote::blobdata>>& txs, std::vector<crypto::hash>& missed_txs) const;

     /**
      * @copydoc Blockchain::get_transactions
      *
      * @note see Blockchain::get_transactions
      */
     bool get_transactions(const std::vector<crypto::hash>& txs_ids, std::vector<transaction>& txs, std::vector<crypto::hash>& missed_txs) const;

     /**
      * @copydoc Blockchain::get_block_by_hash
      *
      * @note see Blockchain::get_block_by_hash
      */
     bool get_block_by_hash(const crypto::hash &h, block &blk, bool *orphan = NULL) const;

     /**
      * @copydoc Blockchain::get_alternative_blocks
      *
      * @note see Blockchain::get_alternative_blocks(std::vector<block>&) const
      */
     bool get_alternative_blocks(std::vector<block>& blocks) const;

     /**
      * @copydoc Blockchain::get_alternative_blocks_count
      *
      * @note see Blockchain::get_alternative_blocks_count() const
      */
     size_t get_alternative_blocks_count() const;

     /**
      * @brief set the pointer to the cryptonote protocol object to use
      *
      * @param pprotocol the pointer to set ours as
      */
     void set_cryptonote_protocol(i_cryptonote_protocol* pprotocol);


     /**
      * @copydoc Blockchain::get_total_transactions
      *
      * @note see Blockchain::get_total_transactions
      */
     size_t get_blockchain_total_transactions() const;

     /**
      * @copydoc Blockchain::have_block
      *
      * @note see Blockchain::have_block
      */
     bool have_block(const crypto::hash& id) const;

     /**
      * @copydoc Blockchain::find_blockchain_supplement(const std::list<crypto::hash>&, NOTIFY_RESPONSE_CHAIN_ENTRY::request&) const
      *
      * @note see Blockchain::find_blockchain_supplement(const std::list<crypto::hash>&, NOTIFY_RESPONSE_CHAIN_ENTRY::request&) const
      */
     bool find_blockchain_supplement(const std::list<crypto::hash>& qblock_ids, NOTIFY_RESPONSE_CHAIN_ENTRY::request& resp) const;

     /**
      * @copydoc Blockchain::find_blockchain_supplement(const uint64_t, const std::list<crypto::hash>&, std::vector<std::pair<cryptonote::blobdata, std::vector<cryptonote::blobdata> > >&, uint64_t&, uint64_t&, size_t) const
      *
      * @note see Blockchain::find_blockchain_supplement(const uint64_t, const std::list<crypto::hash>&, std::vector<std::pair<cryptonote::blobdata, std::vector<transaction> > >&, uint64_t&, uint64_t&, size_t) const
      */
     bool find_blockchain_supplement(const uint64_t req_start_block, const std::list<crypto::hash>& qblock_ids, std::vector<std::pair<std::pair<cryptonote::blobdata, crypto::hash>, std::vector<std::pair<crypto::hash, cryptonote::blobdata> > > >& blocks, uint64_t& total_height, uint64_t& start_height, bool pruned, bool get_miner_tx_hash, size_t max_count) const;

     /**
      * @brief gets some stats about the daemon
      *
      * @param st_inf return-by-reference container for the stats requested
      *
      * @return true
      */
     bool get_stat_info(core_stat_info& st_inf) const;

     /**
      * @copydoc Blockchain::get_tx_outputs_gindexs
      *
      * @note see Blockchain::get_tx_outputs_gindexs
      */
     bool get_tx_outputs_gindexs(const crypto::hash& tx_id, std::vector<uint64_t>& indexs) const;
     bool get_tx_outputs_gindexs(const crypto::hash& tx_id, size_t n_txes, std::vector<std::vector<uint64_t>>& indexs) const;

     /**
      * @copydoc Blockchain::get_tail_id
      *
      * @note see Blockchain::get_tail_id
      */
     crypto::hash get_tail_id() const;

     /**
      * @copydoc Blockchain::get_block_cumulative_difficulty
      *
      * @note see Blockchain::get_block_cumulative_difficulty
      */
     difficulty_type get_block_cumulative_difficulty(uint64_t height) const;

     /**
      * @copydoc Blockchain::get_outs
      *
      * @note see Blockchain::get_outs
      */
     bool get_outs(const COMMAND_RPC_GET_OUTPUTS_BIN::request& req, COMMAND_RPC_GET_OUTPUTS_BIN::response& res) const;

     /**
      * @copydoc Blockchain::get_output_distribution
      *
      * @brief get per block distribution of outputs of a given amount
      */
     bool get_output_distribution(uint64_t amount, uint64_t from_height, uint64_t to_height, uint64_t &start_height, std::vector<uint64_t> &distribution, uint64_t &base) const;

     bool get_output_blacklist(std::vector<uint64_t> &blacklist) const;

     /**
      * @copydoc miner::pause
      *
      * @note see miner::pause
      */
     void pause_mine();

     /**
      * @copydoc miner::resume
      *
      * @note see miner::resume
      */
     void resume_mine();

     /**
      * @brief gets the Blockchain instance
      *
      * @return a reference to the Blockchain instance
      */
     Blockchain& get_blockchain_storage(){return m_blockchain_storage;}

     /**
      * @brief gets the Blockchain instance (const)
      *
      * @return a const reference to the Blockchain instance
      */
     const Blockchain& get_blockchain_storage()const{return m_blockchain_storage;}

     /// @brief return a reference to the service node list
     const service_nodes::service_node_list &get_service_node_list() const { return m_service_node_list; }
     /// @brief return a reference to the service node list
     service_nodes::service_node_list &get_service_node_list() { return m_service_node_list; }

     /// @brief return a reference to the tx pool
     const tx_memory_pool &get_pool() const { return m_mempool; }
     /// @brief return a reference to the service node list
     tx_memory_pool &get_pool() { return m_mempool; }

     /**
      * @copydoc miner::on_synchronized
      *
      * @note see miner::on_synchronized
      */
     void on_synchronized();

     /**
      * @copydoc Blockchain::safesyncmode
      *
      * 2note see Blockchain::safesyncmode
      */
     void safesyncmode(const bool onoff);

     /**
      * @brief sets the target blockchain height
      *
      * @param target_blockchain_height the height to set
      */
     void set_target_blockchain_height(uint64_t target_blockchain_height);

     /**
      * @brief gets the target blockchain height
      *
      * @param target_blockchain_height the target height
      */
     uint64_t get_target_blockchain_height() const;

     /**
      * @brief returns the newest hardfork version known to the blockchain
      *
      * @return the version
      */
     uint8_t get_ideal_hard_fork_version() const;

     /**
      * @brief return the ideal hard fork version for a given block height
      *
      * @return what it says above
      */
     uint8_t get_ideal_hard_fork_version(uint64_t height) const;

     /**
      * @brief return the hard fork version for a given block height
      *
      * @return what it says above
      */
     uint8_t get_hard_fork_version(uint64_t height) const;

     /**
      * @brief return the earliest block a given version may activate
      *
      * @return what it says above
      */
     uint64_t get_earliest_ideal_height_for_version(uint8_t version) const;

     /**
      * @brief gets start_time
      *
      */
     std::time_t get_start_time() const;

     /**
      * @brief tells the Blockchain to update its checkpoints
      *
      * This function will check if enough time has passed since the last
      * time checkpoints were updated and tell the Blockchain to update
      * its checkpoints if it is time.  If updating checkpoints fails,
      * the daemon is told to shut down.
      *
      * @note see Blockchain::update_checkpoints_from_json_file()
      */
     bool update_checkpoints_from_json_file();

     /**
      * @brief tells the daemon to wind down operations and stop running
      *
      * Currently this function raises SIGTERM, allowing the installed signal
      * handlers to do the actual stopping.
      */
     void graceful_exit();

     /**
      * @brief stops the daemon running
      *
      * @note see graceful_exit()
      */
     void stop();

     /**
      * @copydoc Blockchain::have_tx_keyimg_as_spent
      *
      * @note see Blockchain::have_tx_keyimg_as_spent
      */
     bool is_key_image_spent(const crypto::key_image& key_im) const;

     /**
      * @brief check if multiple key images are spent
      *
      * plural version of is_key_image_spent()
      *
      * @param key_im list of key images to check
      * @param spent return-by-reference result for each image checked
      *
      * @return true
      */
     bool are_key_images_spent(const std::vector<crypto::key_image>& key_im, std::vector<bool> &spent) const;

     /**
      * @brief check if multiple key images are spent in the transaction pool
      *
      * @param key_im list of key images to check
      * @param spent return-by-reference result for each image checked
      *
      * @return true
      */
     bool are_key_images_spent_in_pool(const std::vector<crypto::key_image>& key_im, std::vector<bool> &spent) const;

     /**
      * @brief get the number of blocks to sync in one go
      *
      * @return the number of blocks to sync in one go
      */
     size_t get_block_sync_size(uint64_t height) const;

     /**
      * @brief get the sum of coinbase tx amounts between blocks
      *
      * @return the number of blocks to sync in one go
      */
     std::pair<uint64_t, uint64_t> get_coinbase_tx_sum(const uint64_t start_offset, const size_t count);

     /**
      * @brief get the network type we're on
      *
      * @return which network are we on?
      */
     network_type get_nettype() const { return m_nettype; };

     /**
      * @brief check whether an update is known to be available or not
      *
      * This does not actually trigger a check, but returns the result
      * of the last check
      *
      * @return whether an update is known to be available or not
      */
     bool is_update_available() const { return m_update_available; }

     /**
      * @brief get whether transaction relay should be padded
      *
      * @return whether transaction relay should be padded
      */
     bool pad_transactions() const { return m_pad_transactions; }

     /**
      * @brief check a set of hashes against the precompiled hash set
      *
      * @return number of usable blocks
      */
     uint64_t prevalidate_block_hashes(uint64_t height, const std::vector<crypto::hash> &hashes);

     /**
      * @brief get free disk space on the blockchain partition
      *
      * @return free space in bytes
      */
     uint64_t get_free_space() const;

     /**
      * @brief get whether the core is running offline
      *
      * @return whether the core is running offline
      */
     bool offline() const { return m_offline; }

     /**
      * @brief Get the deterministic quorum of service node's public keys responsible for the specified quorum type
      *
      * @param type The quorum type to retrieve
      * @param height Block height to deterministically recreate the quorum list from (note that for
      * a checkpointing quorum this value is automatically reduced by the correct buffer size).
      * @param include_old whether to look in the old quorum states (does nothing unless running with --store-full-quorum-history)
      * @return Null shared ptr if quorum has not been determined yet or is not defined for height
      */
     std::shared_ptr<const service_nodes::quorum> get_quorum(service_nodes::quorum_type type, uint64_t height, bool include_old = false, std::vector<std::shared_ptr<const service_nodes::quorum>> *alt_states = nullptr) const;

     /**
      * @brief Get a non owning reference to the list of blacklisted key images
      */
     const std::vector<service_nodes::key_image_blacklist_entry> &get_service_node_blacklisted_key_images() const;

     /**
      * @brief get a snapshot of the service node list state at the time of the call.
      *
      * @param service_node_pubkeys pubkeys to search, if empty this indicates get all the pubkeys
      *
      * @return all the service nodes that can be matched from pubkeys in param
      */
     std::vector<service_nodes::service_node_pubkey_info> get_service_node_list_state(const std::vector<crypto::public_key>& service_node_pubkeys = {}) const;

     /**
       * @brief get whether `pubkey` is known as a service node.
       *
       * @param pubkey the public key to test
       * @param require_active if true also require that the service node is active (fully funded
       * and not decommissioned).
       *
       * @return whether `pubkey` is known as a (optionally active) service node
       */
     bool is_service_node(const crypto::public_key& pubkey, bool require_active) const;

     /**
      * @brief Add a service node vote
      *
      * @param vote The vote for deregistering a service node.

      * @return
      */
     bool add_service_node_vote(const service_nodes::quorum_vote_t& vote, vote_verification_context &vvc);

     using service_node_keys = service_nodes::service_node_keys;

     /**
      * @brief Get the keys for this service node.
      *
      * @return pointer to service node keys, or nullptr if this node is not running as a service node.
      */
     const service_node_keys* get_service_node_keys() const;

     /**
      * @brief attempts to submit an uptime proof to the network, if this is running in service node mode
      *
      * @return true
      */
     bool submit_uptime_proof();

     /** Called to signal that a significant service node application ping has arrived (either the
      * first, or the first after a long time).  This triggers a check and attempt to send an uptime
      * proof soon (i.e. at the next idle loop).
      */
     void reset_proof_interval();

     /*
      * @brief get the blockchain pruning seed
      *
      * @return the blockchain pruning seed
      */
     uint32_t get_blockchain_pruning_seed() const;

     /**
      * @brief prune the blockchain
      *
      * @param pruning_seed the seed to use to prune the chain (0 for default, highly recommended)
      *
      * @return true iff success
      */
     bool prune_blockchain(uint32_t pruning_seed = 0);

     /**
      * @brief incrementally prunes blockchain
      *
      * @return true on success, false otherwise
      */
     bool update_blockchain_pruning();

     /**
      * @brief checks the blockchain pruning if enabled
      *
      * @return true on success, false otherwise
      */
     bool check_blockchain_pruning();

     /**
      * @brief attempt to relay the pooled checkpoint votes
      *
      * @return true, necessary for binding this function to a periodic invoker
      */
     bool relay_service_node_votes();

     /**
      * @brief sets the given votes to relayed; generally called automatically when
      * relay_service_node_votes() is called.
      */
     void set_service_node_votes_relayed(const std::vector<service_nodes::quorum_vote_t> &votes);

     /**
      * @brief Record if the service node has checkpointed at this point in time
      */
     void record_checkpoint_vote(crypto::public_key const &pubkey, uint64_t height, bool voted) { m_service_node_list.record_checkpoint_vote(pubkey, height, voted); }

     /**
      * @brief Record the reachability status of node's storage server
      */
     bool set_storage_server_peer_reachable(crypto::public_key const &pubkey, bool value);

     /// Time point at which the storage server and lokinet last pinged us
     std::atomic<time_t> m_last_storage_server_ping, m_last_lokinet_ping;
     std::atomic<uint16_t> m_storage_lmq_port;

     /**
      * @brief attempts to relay any transactions in the mempool which need it
      *
      * @return true
      */
     bool relay_txpool_transactions();

     std::mutex              m_long_poll_mutex;
     std::condition_variable m_long_poll_wake_up_clients;
 private:

     /**
      * @copydoc Blockchain::add_new_block
      *
      * @note see Blockchain::add_new_block
      */
     bool add_new_block(const block& b, block_verification_context& bvc, checkpoint_t const *checkpoint);

     /**
      * @copydoc parse_tx_from_blob(transaction&, crypto::hash&, crypto::hash&, const blobdata&) const
      *
      * @note see parse_tx_from_blob(transaction&, crypto::hash&, crypto::hash&, const blobdata&) const
      */
     bool parse_tx_from_blob(transaction& tx, crypto::hash& tx_hash, const blobdata& blob) const;

     /**
      * @brief validates some simple properties of a transaction
      *
      * Currently checks: tx has inputs,
      *                   tx inputs all of supported type(s),
      *                   tx outputs valid (type, key, amount),
      *                   input and output total amounts don't overflow,
      *                   output amount <= input amount,
      *                   tx not too large,
      *                   each input has a different key image.
      *
      * @param tx the transaction to check
      * @param kept_by_block if the transaction has been in a block
      *
      * @return true if all the checks pass, otherwise false
      */
     bool check_tx_semantic(const transaction& tx, bool kept_by_block) const;
     void set_semantics_failed(const crypto::hash &tx_hash);

     void parse_incoming_tx_pre(tx_verification_batch_info &tx_info);
     void parse_incoming_tx_accumulated_batch(std::vector<tx_verification_batch_info> &tx_info, bool kept_by_block);

     /**
      * @brief act on a set of command line options given
      *
      * @param vm the command line options
      *
      * @return true
      */
     bool handle_command_line(const boost::program_options::variables_map& vm);

     /**
      * @brief verify that each input key image in a transaction is unique
      *
      * @param tx the transaction to check
      *
      * @return false if any key image is repeated, otherwise true
      */
     bool check_tx_inputs_keyimages_diff(const transaction& tx) const;

     /**
      * @brief verify that each ring uses distinct members
      *
      * @param tx the transaction to check
      *
      * @return false if any ring uses duplicate members, true otherwise
      */
     bool check_tx_inputs_ring_members_diff(const transaction& tx) const;

     /**
      * @brief verify that each input key image in a transaction is in
      * the valid domain
      *
      * @param tx the transaction to check
      *
      * @return false if any key image is not in the valid domain, otherwise true
      */
     bool check_tx_inputs_keyimages_domain(const transaction& tx) const;

     /**
      * @brief checks HardFork status and prints messages about it
      *
      * Checks the status of HardFork and logs/prints if an update to
      * the daemon is necessary.
      *
      * @note see Blockchain::get_hard_fork_state and HardFork::State
      *
      * @return true
      */
     bool check_fork_time();

     /**
      * @brief checks DNS versions
      *
      * @return true on success, false otherwise
      */
     bool check_updates();

     /**
      * @brief checks free disk space
      *
      * @return true on success, false otherwise
      */
     bool check_disk_space();

     /**
      * @brief Initializes service node key by loading or creating.
      *
      * @return true on success, false otherwise
      */
     bool init_service_node_keys();

     /**
      * @brief do the uptime proof logic and calls for idle loop.
      */
     void do_uptime_proof_call();

     /*
      * @brief checks block rate, and warns if it's too slow
      *
      * @return true on success, false otherwise
      */
     bool check_block_rate();

     bool m_test_drop_download = true; //!< whether or not to drop incoming blocks (for testing)

     uint64_t m_test_drop_download_height = 0; //!< height under which to drop incoming blocks, if doing so

     tx_memory_pool m_mempool; //!< transaction pool instance
     Blockchain m_blockchain_storage; //!< Blockchain instance

     service_nodes::service_node_list m_service_node_list;
     service_nodes::quorum_cop        m_quorum_cop;

     i_cryptonote_protocol* m_pprotocol; //!< cryptonote protocol instance

     boost::recursive_mutex m_incoming_tx_lock; //!< incoming transaction lock

     //m_miner and m_miner_addres are probably temporary here
     miner m_miner; //!< miner instance
     account_public_address m_miner_address; //!< address to mine to (for miner instance)

     std::string m_config_folder; //!< folder to look in for configs and other files

     cryptonote_protocol_stub m_protocol_stub; //!< cryptonote protocol stub instance

     epee::math_helper::periodic_task m_store_blockchain_interval{12h, false}; //!< interval for manual storing of Blockchain, if enabled
     epee::math_helper::periodic_task m_fork_moaner{2h}; //!< interval for checking HardFork status
     epee::math_helper::periodic_task m_txpool_auto_relayer{2min, false}; //!< interval for checking re-relaying txpool transactions
     epee::math_helper::periodic_task m_check_updates_interval{12h}; //!< interval for checking for new versions
     epee::math_helper::periodic_task m_check_disk_space_interval{10min}; //!< interval for checking for disk space
     epee::math_helper::periodic_task m_check_uptime_proof_interval{std::chrono::seconds{UPTIME_PROOF_TIMER_SECONDS}}; //!< interval for checking our own uptime proof
     epee::math_helper::periodic_task m_block_rate_interval{90s, false}; //!< interval for checking block rate
     epee::math_helper::periodic_task m_blockchain_pruning_interval{5h}; //!< interval for incremental blockchain pruning
     epee::math_helper::periodic_task m_service_node_vote_relayer{2min, false};
     epee::math_helper::periodic_task m_sn_proof_cleanup_interval{1h, false};
     epee::math_helper::periodic_task m_systemd_notify_interval{10s};

     std::atomic<bool> m_starter_message_showed; //!< has the "daemon will sync now" message been shown?

     uint64_t m_target_blockchain_height; //!< blockchain height target

     network_type m_nettype; //!< which network are we on?

     std::atomic<bool> m_update_available;

     std::string m_checkpoints_path; //!< path to json checkpoints file
     time_t m_last_json_checkpoints_update; //!< time when json checkpoints were last updated

     std::atomic_flag m_checkpoints_updating; //!< set if checkpoints are currently updating to avoid multiple threads attempting to update at once

     std::unique_ptr<service_node_keys> m_service_node_keys;

     /// Service Node's public IP and storage server port (http and lokimq)
     uint32_t m_sn_public_ip;
     uint16_t m_storage_port;
     uint16_t m_quorumnet_port;

     std::string m_quorumnet_bind_ip; // Currently just copied from p2p-bind-ip
     void *m_quorumnet_obj = nullptr;
     std::mutex m_quorumnet_init_mutex;

     size_t block_sync_size;

     time_t start_time;

     std::unordered_set<crypto::hash> bad_semantics_txes[2];
     boost::mutex bad_semantics_txes_lock;

     enum {
       UPDATES_DISABLED,
       UPDATES_NOTIFY,
       UPDATES_DOWNLOAD,
       UPDATES_UPDATE,
     } check_updates_level;

     tools::download_async_handle m_update_download;
     size_t m_last_update_length;
     boost::mutex m_update_mutex;

     bool m_offline;
     bool m_pad_transactions;

     std::shared_ptr<tools::Notify> m_block_rate_notify;

   };
}

POP_WARNINGS
