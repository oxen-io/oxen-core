#include "l2_tracker.h"

#include <oxenmq/oxenmq.h>

#include <chrono>
#include <concepts>
#include <thread>
#include <utility>

#include "common/bigint.h"
#include "common/guts.h"
#include "common/lock.h"
#include "contracts.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_core.h"
#include "fmt/color.h"
#include "logging/oxen_logger.h"

namespace eth {

static auto logcat = log::Cat("l2_tracker");

// For any given l2 height, we calculate the reward using the last height (inclusive) that was
// divisible by (netconfig).L2_REWARD_POOL_UPDATE_BLOCKS:
static inline uint64_t reward_height(uint64_t l2_height, uint64_t reward_update_blocks) {
    return l2_height - (l2_height % reward_update_blocks);
}

L2Tracker::L2Tracker(cryptonote::core& core_, std::chrono::milliseconds update_frequency) :
        core{core_}, rewards_contract{core.get_nettype(), provider} {

    if (core.get_nettype() == cryptonote::network_type::LOCALDEV)
        MAX_HIST_FETCH = 4;

    // We initially add this on a tiny interval so that it fires almost immediately after the oxenmq
    // object starts (which hasn't happened yet when we get constructed).  In the first call, we
    // kick off a state update then replace the timer with one that fires updates at the slower
    // `update_frequency` rate.
    oxenmq::TaggedThreadID dedicated_thread = core.get_omq().add_tagged_thread("L2 Tracker");
    core.get_omq().add_timer(
            updater,
            [this, update_frequency, dedicated_thread] {
                update_state();
                auto& omq = core.get_omq();
                omq.cancel_timer(updater);
                updater = omq.add_timer(
                        [this] { update_state(); },
                        update_frequency,
                        /*squelch*/ true,
                        dedicated_thread);
            },
            1ms,
            /*squelch*/ true,
            dedicated_thread);
}

void L2Tracker::prune_old_states(bool to_fetch_limit) {
    auto hist_size = to_fetch_limit ? std::min(MAX_HIST_FETCH, HIST_SIZE) : HIST_SIZE;
    if (latest_height < hist_size)
        hist_size = latest_height;
    auto min_to_keep = latest_height - hist_size + 1;
    if (earliest_height >= min_to_keep)
        return;
    size_t before = state_history.size();
    if (earliest_height > synced_height) {
        // We're pruning everything we have!
        state_history.clear();
        earliest_height = 0;
        synced_height = 0;
    } else {
        auto erase_until = state_history.lower_bound(min_to_keep);
        if (erase_until != state_history.end())
            state_history.erase(state_history.begin(), erase_until);
    }
    earliest_height = min_to_keep;
    log::debug(
            logcat,
            "Pruned {} expired of {} L2 state transactions; state range is now {}-{}",
            before - state_history.size(),
            before,
            earliest_height,
            synced_height);
}

void L2Tracker::update_state() {
    // TODO: also check chain id?

    std::lock_guard lock{mutex};
    if (update_in_progress)
        return;
    update_in_progress = true;
    log::trace(logcat, "L2 update state commencing");
    if (provider.numClients() > 1 && std::chrono::steady_clock::now() >= next_provider_check) {
        log::debug(logcat, "update_state initiating all-providers sync check");
        provider.getAllHeightsAsync([this](std::vector<ethyl::HeightInfo> height_info) {
            log::debug(logcat, "Got all provider heights");
            uint64_t best_height = 0;
            for (auto& hi : height_info)
                if (hi.height > best_height)
                    best_height = hi.height;
            uint64_t threshold = best_height < PROVIDERS_CHECK_THRESHOLD
                                       ? 0
                                       : best_height - PROVIDERS_CHECK_THRESHOLD;
            // Sort to maintain index order of any "good" (above threshold) providers first, and
            // then followed by any "bad" (below threshold) where the bad nodes are ordered by the
            // height they gave us in descending order.
            std::sort(height_info.begin(), height_info.end(), [&](const auto& a, const auto& b) {
                bool a_good = a.height >= threshold, b_good = b.height >= threshold;
                if (a_good && b_good)
                    // Both above threshold: preserve the configured order
                    return a.index < b.index;
                if (a_good && !b_good)
                    return true;
                if (b_good && !a_good)
                    return false;
                // both are not good: sort by height (descending), with a fallback to configured
                // order
                return a.height == b.height ? a.index < b.index : a.height > b.height;
            });

            std::vector<ethyl::Client> client_info_;
            auto client_info = [&]() -> const auto& {
                // Defer retrieval until/unless needed (i.e. in warnings below)
                if (client_info_.empty())
                    client_info_ = provider.getClients();
                return client_info_;
            };
            std::vector<size_t> new_prio;
            new_prio.reserve(height_info.size());
            for (const auto& hi : height_info) {
                new_prio.push_back(hi.index);
                if (!hi.success || hi.height < threshold) {
                    auto& name = client_info()[hi.index].name;
                    auto& url = client_info()[hi.index].url.str();
                    auto level = hi.index == 0 ? log::Level::err : log::Level::warn;

                    if (!hi.success)
                        log::log(
                                logcat, level, "Failed to retrieve height from {} [{}]", name, url);
                    else
                        log::log(
                                logcat,
                                level,
                                "{} [{}] is lagging (height {} < {})",
                                name,
                                url,
                                hi.height,
                                best_height);
                }
            }

            size_t primary_index = new_prio[0];
            auto old_prio = provider.getClientOrder();
            if (old_prio != new_prio) {
                auto& clients = client_info();
                std::vector<std::string_view> old_order_string, new_order_string;
                for (const auto& i : old_prio)
                    old_order_string.push_back(clients[i].name);
                for (const auto& i : new_prio)
                    new_order_string.push_back(clients[i].name);
                log::debug(
                        logcat,
                        "L2 provider order changed from ({}) to ({})",
                        fmt::join(old_order_string, ", "),
                        fmt::join(new_order_string, ", "));
                if (old_prio[0] != new_prio[0]) {
                    const auto& old_primary = client_info()[old_prio[0]];
                    const auto& new_primary = client_info()[new_prio[0]];
                    if (new_prio[0] != 0) {
                        // We were using the primary provider, but are switching to a backup
                        log::warning(
                                logcat,
                                "{} [{}] is not responding or is behind; switching to {} [{}] as "
                                "primary L2 source",
                                old_primary.name,
                                old_primary.url.str(),
                                new_primary.name,
                                new_primary.url.str());
                        primary_down = primary_last_warned = std::chrono::steady_clock::now();
                    } else {
                        // We *were* on a backup but now are switching back to the primary
                        log::warning(
                                logcat,
                                fg(fmt::terminal_color::green) | fmt::emphasis::bold,
                                "{} [{}] is available again; switching back to it as primary L2 "
                                "source",
                                new_primary.name,
                                new_primary.url.str());
                        primary_down.reset();
                    }
                }
                provider.setClientOrder(std::move(new_prio));
            } else if (primary_down) {
                if (auto now = std::chrono::steady_clock::now();
                    now - primary_last_warned >= 15min) {
                    log::warning(
                            logcat,
                            "{} [{}] is still unavailable",
                            client_info()[0].name,
                            client_info()[0].url.str());
                    primary_last_warned = now;
                }
            }

            // We just got the height, so no need to immediately fetch it again: just copy whatever
            // we got back from our (new) primary node and skip the update_height step.
            for (const auto& hi : height_info) {
                if (hi.index == primary_index) {
                    if (hi.success) {
                        {
                            std::lock_guard lock{mutex};
                            latest_height = hi.height;
                        }
                        update_rewards();
                        return;
                    }
                    break;
                }
            }

            // If we're still here then our best choice wasn't successful (which probably means
            // *all* our providers failed), and so our best option for now is to try re-fetching the
            // height the normal way:
            update_height();
        });
    } else {
        update_height();
    }
}

void L2Tracker::update_height() {
    provider.getLatestHeightAsync([this](std::optional<uint64_t> height) {
        bool keep_going = false;
        {
            std::lock_guard lock{mutex};
            if (height) {
                latest_height = *height;
                prune_old_states();
                log::debug(logcat, "L2 provider height updated to {}", *height);
            } else {
                log::warning(logcat, "Failed to retrieve current height from provider");
            }
            keep_going = latest_height > 0;
        }

        if (keep_going)
            update_rewards();
        else {
            // If we don't have a height (either from this call, or some previous call) then there's
            // nothing else further in the update chain we can do, so just stop here.
            std::unique_lock lock{mutex};
            update_in_progress = false;
            oxen::log::trace(logcat, "L2 update step finished");
        }
    });
}

void L2Tracker::update_rewards(std::optional<std::forward_list<uint64_t>> more) {

    // NOTE: Initial case of update_rewards from all entry-points has a nullopt
    // for `more`, e.g. this branch executes. After calling into
    // callReadFunctionJSONAsync to get the reward rate, `more` is populated and
    // this function is called again.
    if (!more) {
        const auto reward_update_blocks = core.get_net_config().L2_REWARD_POOL_UPDATE_BLOCKS;
        std::shared_lock lock{mutex};
        // Check that we have the rewards for all heights we need to cover both the current and the
        // last MAX_HIST_FETCH L2 block heights.
        auto r_height = reward_height(latest_height, reward_update_blocks);
        uint64_t earliest_height_to_get_rewards =
                latest_height - std::min(latest_height, MAX_HIST_FETCH);
        log::debug(
                logcat,
                "Earliest height to get rewards {} (reward height is {})",
                earliest_height_to_get_rewards,
                r_height);
        do {
            if (!reward_rate.count(r_height)) {
                if (!more)
                    more.emplace();
                more->push_front(r_height);
                oxen::log::debug(logcat, "Pushed height: {}", r_height);
            }
            r_height -= std::min(reward_update_blocks, r_height);
        } while (r_height > earliest_height_to_get_rewards);
    }

    if (more && !more->empty()) {
        std::shared_lock lock{mutex};
        auto r_height = more->front();
        more->pop_front();
        oxen::log::debug(logcat, "Starting query for reward height {}", r_height);
        provider.callReadFunctionJSONAsync(
                contract::pool_address(core.get_nettype()),
                "0x{:x}"_format(contract::call::Pool_rewardRate),
                [this, r_height, more = std::move(more)](
                        std::optional<nlohmann::json> result) mutable {
                    if (!result)
                        log::warning(logcat, "Failed to fetch reward rate for height {}", r_height);
                    else if (!result->is_string())
                        log::warning(logcat, "Unexpected reward rate result: {}", result->dump());
                    else {
                        // NOTE: In certain conditions (like when intialising an empty reward pool)
                        // the returned reward rate can be "0x" which we handle as 0.
                        std::array<std::byte, 32> rate256{};
                        std::span<const char> rate256_hex =
                                tools::hex_span(result->get<std::string_view>());

                        if (rate256_hex.empty() ||
                            tools::try_load_from_hex_guts(rate256_hex, rate256)) {
                            try {
                                auto reward = tools::decode_integer_be(rate256);
                                {
                                    std::lock_guard lock{mutex};
                                    reward_rate[r_height] = reward;
                                }
                                log::debug(
                                        logcat,
                                        "Block reward for L2 heights {}-{} is {}",
                                        r_height,
                                        r_height +
                                                core.get_net_config().L2_REWARD_POOL_UPDATE_BLOCKS -
                                                1,
                                        reward);
                            } catch (const std::exception& e) {
                                log::warning(logcat, "Failed to parse reward rate: {}", e.what());
                            }
                        } else {
                            log::warning(
                                    logcat,
                                    "Unparseable reward rate result: {} {}",
                                    result->get<std::string_view>(),
                                    std::string_view(rate256_hex.data(), rate256_hex.size()));
                        }
                    }

                    oxen::log::debug(
                            logcat,
                            "Finished querying reward for height {}, there is more {}",
                            r_height,
                            more->empty() ? "no" : "yes");
                    if (!more->empty())
                        update_rewards(std::move(more));
                    else
                        update_logs();
                },
                "0x{:x}"_format(r_height));
    } else {
        oxen::log::debug(logcat, "No more rewards to walk, updating logs");
        update_logs();
    }
}

void L2Tracker::add_to_mempool(
        uint64_t l2_height, const TransactionStateChangeVariant& tx_variant) {
    if (tx_variant.index() == 0)  // monostate, i.e. not a state change log
        return;

    using namespace cryptonote;

    const auto hf_version = core.get_blockchain_storage().get_network_version();
    transaction tx;
    tx.version = transaction_prefix::get_max_version_for_hf(hf_version);

    std::visit(
            [&tx]<typename T>(const T& arg) {
                if constexpr (std::is_same_v<T, eth::NewServiceNodeTx>) {
                    tx.type = txtype::ethereum_new_service_node;
                    std::vector<tx_extra_ethereum_contributor> contributors;
                    for (const auto& contributor : arg.contributors)
                        contributors.emplace_back(contributor.addr, contributor.amount);

                    tx_extra_ethereum_new_service_node new_service_node = {
                            0,
                            arg.bls_pubkey,
                            arg.eth_address,
                            arg.sn_pubkey,
                            arg.ed_signature,
                            arg.fee,
                            contributors};
                    add_new_service_node_to_tx_extra(tx.extra, new_service_node);

                } else if constexpr (std::is_same_v<T, eth::ServiceNodeRemovalRequestTx>) {
                    tx.type = txtype::ethereum_service_node_removal_request;
                    tx_extra_ethereum_service_node_removal_request removal_request = {
                            0, arg.bls_pubkey};
                    add_service_node_removal_request_to_tx_extra(tx.extra, removal_request);
                } else if constexpr (std::is_same_v<T, eth::ServiceNodeRemovalTx>) {
                    tx.type = txtype::ethereum_service_node_removal;
                    tx_extra_ethereum_service_node_removal removal_data = {
                            0, arg.eth_address, arg.amount, arg.bls_pubkey};
                    add_service_node_removal_to_tx_extra(tx.extra, removal_data);
                } else if constexpr (std::is_same_v<T, eth::ServiceNodeLiquidatedTx>) {
                    tx.type = txtype::ethereum_service_node_liquidated;
                    tx_extra_ethereum_service_node_liquidated liquidated = {0, arg.bls_pubkey};
                    add_service_node_liquidated_to_tx_extra(tx.extra, liquidated);
                } else {
                    static_assert(
                            std::is_same_v<T, std::monostate>,
                            "Unhandled state change variant type");
                }
            },
            tx_variant);
    const size_t tx_weight = get_transaction_weight(tx);
    const crypto::hash tx_hash = get_transaction_hash(tx);
    tx_verification_context tvc = {};

    // Add transaction to memory pool
    if (!core.get_pool().add_tx(
                tx,
                tx_hash,
                cryptonote::tx_to_blob(tx),
                tx_weight,
                tvc,
                tx_pool_options::from_l2(l2_height),
                hf_version,
                nullptr)) {
        if (tvc.m_verifivation_failed)
            log::error(log::Cat("verify"), "Transaction verification failed: {}", tx_hash);
        else if (tvc.m_verifivation_impossible)
            log::error(log::Cat("verify"), "Transaction verification impossible: {}", tx_hash);
    }
}

void L2Tracker::update_logs() {
    std::shared_lock lock{mutex};

    // Start from the *later* of our previous height+1 or the first block that we actually care
    // about if the previous one is too old.
    uint64_t from = std::max(
            synced_height + 1, latest_height >= HIST_SIZE ? latest_height - HIST_SIZE + 1 : 0);
    oxen::log::trace(
            logcat,
            "L2Tracker::{} synced_height={}, latest_height={}, HIST_SIZE={}, from={}",
            __func__,
            synced_height,
            latest_height,
            HIST_SIZE,
            from);

    if (latest_height < from) {
        oxen::log::trace(logcat, "L2Tracker upgrading shared lock to exclusive");
        auto ex_lock = tools::upgrade_lock(lock);
        update_in_progress = false;
        oxen::log::debug(logcat, "L2 update step finished");
        return;
    }

    if (latest_height >= from + MAX_HIST_FETCH) {
        // We are too far behind to fetch the full HIST_SIZE, so prune anything more than
        // MAX_HIST_FETCH ago and resync from there (so that we don't leave a gap).  (This is also
        // our "starting up" case to only fetch MAX_HIST_FETCH).
        oxen::log::debug(
                logcat,
                "Begin pruning of state {} >= ({} + {})",
                latest_height,
                from,
                MAX_HIST_FETCH);
        auto ex_lock = tools::upgrade_lock(lock);
        prune_old_states(true);
        from = latest_height - MAX_HIST_FETCH + 1;
        oxen::log::trace(logcat, "End pruning of old states", from);
    }

    uint64_t to = std::min(latest_height, from + GETLOGS_MAX_BLOCKS);

    log::debug(
            logcat,
            "Initiating L2 request for logs for heights {}-{} (target height: {})",
            from,
            to,
            latest_height);
    provider.getLogsAsync(
            from,
            to,
            rewards_contract.address(),
            [this, to, from, started = std::chrono::steady_clock::now()](
                    std::optional<std::vector<ethyl::LogEntry>> logs) {
                bool keep_going = false;
                {
                    std::lock_guard lock{mutex};
                    if (!logs) {
                        log::warning(logcat, "Failed to retrieve L2 logs for {}-{}", from, to);
                        update_in_progress = false;
                        oxen::log::debug(logcat, "L2 update step finished");
                        return;
                    }
                    log::debug(
                            logcat,
                            "Retrieved {} L2 logs for heights {}-{} in {:.3f}s",
                            logs->size(),
                            from,
                            to,
                            std::chrono::duration<double>{
                                    std::chrono::steady_clock::now() - started}
                                    .count());

                    for (const auto& log : *logs) {
                        if (!log.blockNumber) {
                            log::error(
                                    logcat,
                                    "Got back Log item from L2 provider without a blockNumber!");
                            continue;
                        }
                        try {
                            auto tx = getLogTransaction(log);
                            if (tx.index() != 0) {
                                auto& state_txs = state_history[*log.blockNumber];
                                state_txs.emplace_back(std::move(tx));
                                add_to_mempool(*log.blockNumber, state_txs.back());
                            }
                        } catch (const std::exception& e) {
                            log::error(
                                    logcat,
                                    "Failed to convert L2 state change transaction to an Oxen "
                                    "state change transaction: {}",
                                    e.what());
                            continue;
                        }
                    }

                    synced_height = to;

                    if (to < latest_height)
                        keep_going = true;
                }
                if (keep_going)
                    update_logs();
                else {
                    std::lock_guard lock{mutex};
                    update_in_progress = false;
                    oxen::log::debug(logcat, "L2 update step finished");
                }
            });
}

std::optional<uint64_t> L2Tracker::get_reward_rate(uint64_t height) const {
    std::shared_lock lock{mutex};
    if (auto it = reward_rate.find(
                reward_height(height, core.get_net_config().L2_REWARD_POOL_UPDATE_BLOCKS));
        it != reward_rate.end())
        return it->second;
    return std::nullopt;
}

TransactionReviewSession L2Tracker::initialize_review(uint64_t l2_height) const {
    std::shared_lock lock{mutex};

    // NOTE: In local devnet we bootstrap from height 0 which means it's
    // possible to get a l2_height and confirmed height that can be equal
    // (e.g l2 = confirmed = 0). If this is the case adding +1 to the confirmed
    // height will break the bounds check for `active`.
    uint64_t start_height = l2_height == confirmed_height ? l2_height : confirmed_height + 1;

    TransactionReviewSession session;
    session.active = provider.numClients() > 0 && start_height <= l2_height &&
                     start_height >= earliest_height && l2_height <= synced_height;

    if (!session) {
        log::debug(
                logcat,
                "Unable to initialize TransactionReviewSession: L2 block range [{}, {}] is not "
                "inside our synced L2 range [{}, {}]",
                start_height,
                l2_height,
                earliest_height,
                synced_height);
        return session;
    }

    // FIXME: we shouldn't have an L2Tracker at all without clients.
    for (auto it = state_history.lower_bound(start_height),
              end = state_history.upper_bound(l2_height);
         it != end;
         ++it) {
        const auto& [height, state_changes] = *it;
        for (const auto& transactionVariant : state_changes) {
            std::visit(
                    [&session]<typename T>(const T& arg) {
                        if constexpr (std::is_same_v<T, NewServiceNodeTx>) {
                            session.new_service_nodes.push_back(arg);
                        } else if constexpr (std::is_same_v<T, ServiceNodeRemovalRequestTx>) {
                            session.removal_requests.push_back(arg);
                        } else if constexpr (std::is_same_v<T, ServiceNodeRemovalTx>) {
                            session.removals.push_back(arg);
                        } else if constexpr (std::is_same_v<T, ServiceNodeLiquidatedTx>) {
                            session.liquidations.push_back(arg);
                        } else {
                            static_assert(
                                    std::is_same_v<T, std::monostate>,
                                    "unhandled state change type");
                        }
                    },
                    transactionVariant);
        }
    }
    return session;
}

uint64_t L2Tracker::get_latest_height() const {
    std::shared_lock lock{mutex};
    return latest_height;
}

uint64_t L2Tracker::get_safe_height() const {
    std::shared_lock lock{mutex};
    return SAFE_BLOCKS >= latest_height ? 0 : latest_height - SAFE_BLOCKS;
}

uint64_t L2Tracker::get_confirmed_height() const {
    std::shared_lock lock{mutex};
    return confirmed_height;
}

void L2Tracker::set_confirmed_height(uint64_t ethereum_block_height) {
    std::lock_guard lock{mutex};
    confirmed_height = ethereum_block_height;
}

template <typename Tx, std::predicate<const Tx&> Match>
static bool process_review_tx(bool active, std::list<Tx>& txes, Match match) {
    if (!active) {
        log::debug(
                logcat,
                "ignoring {} review; review session is not active",
                state_change_name<Tx>());
        return true;
    }

    auto it = std::find_if(txes.begin(), txes.end(), std::move(match));
    if (it != txes.end()) {
        log::debug(logcat, "review session matched {}", *it);
        txes.erase(it);
        return true;
    }

    return false;
}

bool TransactionReviewSession::processNewServiceNodeTx(
        const eth::bls_public_key& bls_pubkey,
        const eth::address& eth_address,
        const crypto::public_key& service_node_pubkey,
        std::string& fail_reason) {
    /// FIXME XXX TODO -- these should be verifying contributors and fee as well
    if (process_review_tx(active, new_service_nodes, [&](const auto& x) {
            return x.bls_pubkey == bls_pubkey && x.eth_address == eth_address &&
                   x.sn_pubkey == service_node_pubkey;
        }))
        return true;

    fail_reason = fmt::format(
            "New Service Node Transaction not found bls_pubkey: {}, eth_address: {}, "
            "sn_pubkey: {}",
            bls_pubkey,
            eth_address,
            service_node_pubkey);
    log::debug(logcat, "{}", fail_reason);
    return false;
}

bool TransactionReviewSession::processServiceNodeRemovalRequestTx(
        const eth::bls_public_key& bls_pubkey, std::string& fail_reason) {
    if (process_review_tx(
                active, removal_requests, [&](const auto& x) { return x.bls_pubkey == bls_pubkey; }))
        return true;

    fail_reason = "Leave Request Transaction not found bls_pubkey: {}"_format(bls_pubkey);
    log::debug(logcat, "{}", fail_reason);
    return false;
}

bool TransactionReviewSession::processServiceNodeRemovalTx(
        const eth::address& eth_address,
        const uint64_t amount,
        const eth::bls_public_key& bls_pubkey,
        std::string& fail_reason) {
    if (process_review_tx(active, removals, [&](const auto& x) {
            return x.bls_pubkey == bls_pubkey && x.eth_address == eth_address && x.amount == amount;
        }))
        return true;

    fail_reason = "Exit Transaction not found bls_pubkey: {}"_format(bls_pubkey);
    return false;
}

bool TransactionReviewSession::processServiceNodeLiquidatedTx(
        const eth::bls_public_key& bls_pubkey, std::string& fail_reason) {
    if (process_review_tx(
                active, liquidations, [&](const auto& x) { return x.bls_pubkey == bls_pubkey; }))
        return true;

    fail_reason = "Deregister Transaction not found bls_pubkey: {}"_format(bls_pubkey);
    return false;
}

bool TransactionReviewSession::finalize() {
    return !active ||
           (new_service_nodes.empty() && removal_requests.empty() && liquidations.empty() && removals.empty());
}

std::vector<uint64_t> L2Tracker::get_non_signers(
        const std::unordered_set<eth::bls_public_key>& bls_public_keys) {
    return rewards_contract.getNonSigners(bls_public_keys);
}

std::vector<eth::bls_public_key> L2Tracker::get_all_bls_public_keys(uint64_t blockNumber) {
    return rewards_contract.getAllBLSPubkeys(blockNumber);
}

}  // namespace eth
