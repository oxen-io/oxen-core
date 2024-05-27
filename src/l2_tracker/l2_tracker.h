#pragma once

#include <atomic>
#include <thread>

#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "pool_contract.h"
#include "rewards_contract.h"

struct State {
    uint64_t height;
    std::string state;
    std::vector<TransactionStateChangeVariant>
            state_changes;  // List of transactions that changed the state this block

    State(uint64_t _height,
          const std::string& _state,
          const std::vector<TransactionStateChangeVariant>& _state_changes) :
            height(_height), state(_state), state_changes(_state_changes) {}
    State(const StateResponse& _state_response) :
            height(_state_response.height), state(_state_response.state) {}
};

struct TransactionReviewSession {
    bool service_node = true;
    uint64_t review_block_height_min;
    uint64_t review_block_height_max;
    std::vector<NewServiceNodeTx> new_service_nodes;
    std::vector<ServiceNodeLeaveRequestTx> leave_requests;
    std::vector<ServiceNodeDeregisterTx> deregs;
    std::vector<ServiceNodeExitTx> exits;

    TransactionReviewSession(uint64_t min_height, uint64_t max_height) :
            review_block_height_min(min_height), review_block_height_max(max_height) {}

    bool processNewServiceNodeTx(
            const crypto::bls_public_key& bls_key,
            const crypto::eth_address& eth_address,
            const std::string& service_node_pubkey,
            std::string& fail_reason);
    bool processServiceNodeLeaveRequestTx(
            const crypto::bls_public_key& bls_key, std::string& fail_reason);
    bool processServiceNodeExitTx(
            const crypto::eth_address& eth_address,
            const uint64_t amount,
            const crypto::bls_public_key& bls_key,
            std::string& fail_reason);
    bool processServiceNodeDeregisterTx(
            const crypto::bls_public_key& bls_key, std::string& fail_reason);

    bool finalize_review();
};

class L2Tracker {
  private:
    std::shared_ptr<RewardsContract> rewards_contract;
    std::shared_ptr<PoolContract> pool_contract;
    std::vector<State> state_history;
    std::unordered_map<uint64_t, uint64_t>
            oxen_to_ethereum_block_heights;  // Maps Oxen block height to Ethereum block height
    uint64_t latest_oxen_block = 0;
    std::atomic<bool> stop_thread;
    std::thread update_thread;

  public:
    L2Tracker(cryptonote::network_type nettype);
    ~L2Tracker();

    bool start();
    void update_state();
    bool check_state_in_history(uint64_t height, const crypto::hash& state_root);
    bool check_state_in_history(uint64_t height, const std::string& state_root);

    // These functions check whether transactions on the oxen chain should be there.
    // Call initialize before we loop, then for each transaction call processTransactionType
    // and the tracker will make sure that it should actually be on the oxen blockchain
    // at that height. When done looping call the finalize function which will
    // then check that all transactions have been accounted for.
    std::shared_ptr<TransactionReviewSession> initialize_transaction_review(
            uint64_t ethereum_height);
    std::shared_ptr<TransactionReviewSession> initialize_mempool_review();

    void record_block_height_mapping(uint64_t oxen_block_height, uint64_t ethereum_block_height);

    std::pair<uint64_t, crypto::hash> latest_state();
    std::vector<TransactionStateChangeVariant> get_block_transactions(const std::vector<crypto::bls_public_key>& bls_pubkeys);
    uint64_t get_last_l2_height();

    uint64_t get_pool_block_reward(uint64_t timestamp, uint64_t ethereum_block_height);
    std::vector<uint64_t> get_non_signers(const std::vector<std::string>& bls_public_keys);
    std::vector<std::string> get_all_bls_public_keys(uint64_t blockNumber);

    ethyl::Provider provider;

  private:
    void insert_in_order(State&& new_state);
    void process_logs_for_state(State& state);

    std::mutex mutex;
    static std::string_view get_rewards_contract_address(const cryptonote::network_type nettype);
    static std::string_view get_pool_contract_address(const cryptonote::network_type nettype);
    void get_review_transactions();
    void populate_review_transactions(std::shared_ptr<TransactionReviewSession> session);
    // END
};
