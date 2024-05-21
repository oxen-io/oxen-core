#include "l2_tracker.h"

#include <thread>
#include <utility>

#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("l2_tracker");

L2Tracker::L2Tracker() {
    service_node = false;
}

L2Tracker::L2Tracker(
        const cryptonote::network_type nettype, const std::shared_ptr<Provider>& _provider) :
        rewards_contract(std::make_shared<RewardsContract>(
                std::string(get_rewards_contract_address(nettype)), _provider)),
        pool_contract(std::make_shared<PoolContract>(
                std::string(get_pool_contract_address(nettype)), _provider)),
        stop_thread(false) {
    update_thread = std::thread([this] {
        while (!stop_thread.load()) {
            update_state();
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    });
}

L2Tracker::~L2Tracker() {
    stop_thread.store(true);
    if (update_thread.joinable()) {
        update_thread.join();
    }
}
void L2Tracker::insert_in_order(State&& new_state) {
    // Check if the state with the same height already exists
    auto it = std::find_if(
            state_history.begin(), state_history.end(), [&new_state](const State& state) {
                return state.height == new_state.height;
            });

    // If it doesn't exist, insert it in the appropriate location
    if (it == state_history.end()) {
        auto insert_loc = std::upper_bound(
                state_history.begin(),
                state_history.end(),
                new_state,
                [](const State& a, const State& b) { return a.height > b.height; });

        state_history.insert(insert_loc, std::move(new_state));  // Use std::move here
    }
}

void L2Tracker::process_logs_for_state(State& state) {
    std::vector<RewardsLogEntry> logs = rewards_contract->Logs(state.height);
    for (const auto& log : logs) {
        auto transaction = log.getLogTransaction();
        if (transaction) {
            state.state_changes.emplace_back(*transaction);
        }
    }
}

void L2Tracker::update_state() {
    std::lock_guard lock{mutex};
    try {
        State new_state(rewards_contract->State());
        process_logs_for_state(new_state);
        insert_in_order(std::move(new_state));

        // Check for missing heights between the first and second entries
        if (state_history.size() > 1) {
            uint64_t first_height = state_history[0].height;
            uint64_t second_height = state_history[1].height;

            for (uint64_t h = first_height - 1; h > second_height; --h) {
                State missing_state(rewards_contract->State(h));
                process_logs_for_state(missing_state);
                insert_in_order(std::move(missing_state));
            }
        }
    } catch (const std::exception& e) {
        oxen::log::warning(logcat, "Failed to update state: {}", e.what());
    }
}

std::pair<uint64_t, crypto::hash> L2Tracker::latest_state() {
    if (!service_node) {
        oxen::log::error(logcat, "L2 tracker doesnt have a provider and cant query state");
        throw std::runtime_error("Non Service node doesn't keep track of state");
    }
    std::lock_guard lock{mutex};
    if (state_history.empty()) {
        oxen::log::error(logcat, "L2 tracker doesnt have any state history to query");
        throw std::runtime_error("Internal error getting latest state from l2 tracker");
    }
    crypto::hash return_hash;
    auto& latest_state = state_history.front();
    tools::hex_to_type(latest_state.state, return_hash);
    return std::make_pair(latest_state.height, return_hash);
}

bool L2Tracker::check_state_in_history(uint64_t height, const crypto::hash& state_root) {
    std::string state_str = tools::type_to_hex(state_root);
    return check_state_in_history(height, state_str);
}

bool L2Tracker::check_state_in_history(uint64_t height, const std::string& state_root) {
    if (!service_node)
        return true;
    std::lock_guard lock{mutex};
    auto it = std::find_if(
            state_history.begin(), state_history.end(), [height, &state_root](const State& state) {
                return state.height == height && state.state == state_root;
            });
    return it != state_history.end();
}

std::shared_ptr<TransactionReviewSession> L2Tracker::initialize_transaction_review(
        uint64_t ethereum_height) {
    auto session = std::make_shared<TransactionReviewSession>(
            oxen_to_ethereum_block_heights[latest_oxen_block], ethereum_height);
    if (!service_node)
        session->service_node = false;
    std::lock_guard lock{mutex};
    populate_review_transactions(session);
    return session;
}

std::shared_ptr<TransactionReviewSession> L2Tracker::initialize_mempool_review() {
    auto session = std::make_shared<TransactionReviewSession>(
            oxen_to_ethereum_block_heights[latest_oxen_block],
            std::numeric_limits<uint64_t>::max());
    if (!service_node)
        session->service_node = false;
    std::lock_guard lock{mutex};
    populate_review_transactions(session);
    return session;
}

std::string_view L2Tracker::get_rewards_contract_address(const cryptonote::network_type nettype) {
    std::string_view result = get_config(nettype).ETHEREUM_REWARDS_CONTRACT;
    return result;
}

std::string_view L2Tracker::get_pool_contract_address(const cryptonote::network_type nettype) {
    std::string_view result = get_config(nettype).ETHEREUM_POOL_CONTRACT;
    return result;
}

void L2Tracker::populate_review_transactions(std::shared_ptr<TransactionReviewSession> session) {
    for (const auto& state : state_history) {
        if (state.height > session->review_block_height_min &&
            state.height <= session->review_block_height_max) {
            for (const auto& transactionVariant : state.state_changes) {
                std::visit(
                        [&session](auto&& arg) {
                            using T = std::decay_t<decltype(arg)>;
                            if constexpr (std::is_same_v<T, NewServiceNodeTx>) {
                                session->new_service_nodes.push_back(arg);
                            } else if constexpr (std::is_same_v<T, ServiceNodeLeaveRequestTx>) {
                                session->leave_requests.push_back(arg);
                            } else if constexpr (std::is_same_v<T, ServiceNodeExitTx>) {
                                session->exits.push_back(arg);
                            } else if constexpr (std::is_same_v<T, ServiceNodeDeregisterTx>) {
                                session->deregs.push_back(arg);
                            }
                        },
                        transactionVariant);
            }
        }
        if (state.height <= session->review_block_height_min) {
            // State history should be ordered, if we go below our desired height then we can exit
            break;
        }
    }
}

std::vector<TransactionStateChangeVariant> L2Tracker::get_block_transactions() {
    if (!service_node)
        throw std::runtime_error("Non Service node doesn't keep track of state");
    std::lock_guard lock{mutex};
    std::vector<TransactionStateChangeVariant> all_transactions;
    const auto begin_height = oxen_to_ethereum_block_heights[latest_oxen_block];
    for (const auto& state : state_history) {
        if (state.height > begin_height) {
            for (const auto& transactionVariant : state.state_changes) {
                all_transactions.push_back(transactionVariant);
            }
        }
        if (state.height <= begin_height) {
            // If we go below our desired begin height then break, as state history should be
            // ordered
            break;
        }
    }
    return all_transactions;
}

void L2Tracker::record_block_height_mapping(
        uint64_t oxen_block_height, uint64_t ethereum_block_height) {
    std::lock_guard lock{mutex};
    oxen_to_ethereum_block_heights[oxen_block_height] = ethereum_block_height;
    latest_oxen_block = oxen_block_height;
}

bool TransactionReviewSession::processNewServiceNodeTx(
        const crypto::bls_public_key& bls_key,
        const crypto::eth_address& eth_address,
        const std::string& service_node_pubkey,
        std::string& fail_reason) {
    if (!service_node)
        return true;
    if (review_block_height_max == 0) {
        fail_reason = "Review not initialized";
        oxen::log::error(
                logcat, "Failed to process new service node tx height {}", review_block_height_max);
        return false;
    }

    oxen::log::info(
            logcat,
            "Searching for new_service_node bls_key: {} eth_address {} service_node pubkey {}",
            tools::type_to_hex(bls_key),
            tools::type_to_hex(eth_address),
            service_node_pubkey);
    for (auto it = new_service_nodes.begin(); it != new_service_nodes.end(); ++it) {
        oxen::log::info(
                logcat,
                "new_service_node bls_key: {} eth_address {} service_node_pubkey: {}",
                tools::type_to_hex(it->bls_key),
                tools::type_to_hex(it->eth_address),
                it->service_node_pubkey);
        if (it->bls_key == bls_key && it->eth_address == eth_address &&
            it->service_node_pubkey == service_node_pubkey) {
            new_service_nodes.erase(it);
            return true;
        }
    }

    fail_reason = "New Service Node Transaction not found bls_key: " + tools::type_to_hex(bls_key) +
                  " eth_address: " + tools::type_to_hex(eth_address) +
                  " service_node_pubkey: " + service_node_pubkey;
    return false;
}

bool TransactionReviewSession::processServiceNodeLeaveRequestTx(
        const crypto::bls_public_key& bls_key, std::string& fail_reason) {
    if (!service_node)
        return true;
    if (review_block_height_max == 0) {
        fail_reason = "Review not initialized";
        oxen::log::error(
                logcat,
                "Failed to process service node leave request tx height {}",
                review_block_height_max);
        return false;
    }

    for (auto it = leave_requests.begin(); it != leave_requests.end(); ++it) {
        if (it->bls_key == bls_key) {
            leave_requests.erase(it);
            return true;
        }
    }

    fail_reason = "Leave Request Transaction not found bls_key: " + tools::type_to_hex(bls_key);
    return false;
}

bool TransactionReviewSession::processServiceNodeExitTx(
        const crypto::eth_address& eth_address,
        const uint64_t amount,
        const crypto::bls_public_key& bls_key,
        std::string& fail_reason) {
    if (!service_node)
        return true;
    if (review_block_height_max == 0) {
        fail_reason = "Review not initialized";
        oxen::log::error(
                logcat,
                "Failed to process service node exit tx height {}",
                review_block_height_max);
        return false;
    }

    for (auto it = exits.begin(); it != exits.end(); ++it) {
        if (it->bls_key == bls_key && it->eth_address == eth_address && it->amount == amount) {
            exits.erase(it);
            return true;
        }
    }

    fail_reason = "Exit Transaction not found bls_key: " + tools::type_to_hex(bls_key);
    return false;
}

bool TransactionReviewSession::processServiceNodeDeregisterTx(
        const crypto::bls_public_key& bls_key, std::string& fail_reason) {
    if (!service_node)
        return true;
    if (review_block_height_max == 0) {
        fail_reason = "Review not initialized";
        oxen::log::error(
                logcat, "Failed to process deregister tx height {}", review_block_height_max);
        return false;
    }

    for (auto it = deregs.begin(); it != deregs.end(); ++it) {
        if (it->bls_key == bls_key) {
            deregs.erase(it);
            return true;
        }
    }

    fail_reason = "Deregister Transaction not found bls_key: " + tools::type_to_hex(bls_key);
    return false;
}

bool TransactionReviewSession::finalize_review() {
    if (!service_node)
        return true;
    if (new_service_nodes.empty() && leave_requests.empty() && deregs.empty() && exits.empty()) {
        review_block_height_min = review_block_height_max + 1;
        review_block_height_max = 0;
        return true;
    }

    return false;
}

uint64_t L2Tracker::get_pool_block_reward(uint64_t timestamp, uint64_t ethereum_block_height) {
    const auto response = pool_contract->RewardRate(timestamp, ethereum_block_height);
    return response.reward;
}

std::vector<uint64_t> L2Tracker::get_non_signers(const std::vector<std::string>& bls_public_keys) {
    return rewards_contract->getNonSigners(bls_public_keys);
}

std::vector<std::string> L2Tracker::get_all_bls_public_keys(uint64_t blockNumber) {
    return rewards_contract->getAllBLSPubkeys(blockNumber);
}
