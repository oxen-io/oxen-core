#include "l2_tracker.h"

#include <oxenmq/oxenmq.h>

#include <chrono>
#include <concepts>
#include <thread>
#include <utility>
#include <variant>

#include "common/bigint.h"
#include "common/guts.h"
#include "common/lock.h"
#include "contracts.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_config.h"
#include "cryptonote_core/cryptonote_core.h"
#include "fmt/color.h"
#include "l2_tracker/events.h"
#include "logging/oxen_logger.h"

namespace eth {

static auto logcat = log::Cat("l2_tracker");

// For any given l2 height, we calculate the reward using the last height (inclusive) that was
// divisible by (netconfig).L2_REWARD_POOL_UPDATE_BLOCKS:
static inline uint64_t reward_height(uint64_t l2_height, uint64_t reward_update_blocks) {
    return l2_height - (l2_height % reward_update_blocks);
}

L2Tracker::L2Tracker(cryptonote::core& core_, std::chrono::milliseconds update_frequency) :
        core{core_},
        rewards_contract{core.get_nettype(), provider},
        chain_id{core.get_net_config().ETHEREUM_CHAIN_ID} {

    // We initially add this on a tiny interval so that it fires almost immediately after the oxenmq
    // object starts (which hasn't happened yet when we get constructed).  In the first call, we
    // kick off a state update then replace the timer with one that fires updates at the slower
    // `update_frequency` rate.
    oxenmq::TaggedThreadID dedicated_thread = core.omq().add_tagged_thread("L2 Tracker");
    core.omq().add_timer(
            updater,
            [this, update_frequency, dedicated_thread] {
                update_state();
                auto& omq = core.omq();
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

void L2Tracker::prune_old_states() {
    const auto expiry = latest_height - std::min(latest_height, HIST_SIZE);
    recent_regs.expire(expiry);
    recent_unlocks.expire(expiry);
    recent_removals.expire(expiry);
    auto reward_exp = reward_height(expiry, core.get_net_config().L2_REWARD_POOL_UPDATE_BLOCKS);
    reward_rate.erase(reward_rate.begin(), reward_rate.lower_bound(reward_exp));
}

void L2Tracker::update_state() {
    // TODO: also check chain id?  Perhaps just one on first startup?

    std::lock_guard lock{mutex};
    if (update_in_progress)
        return;
    update_in_progress = true;

    log::trace(logcat, "L2 update state commencing");
    if (provider.numClients() > 1 && std::chrono::steady_clock::now() >= next_provider_check) {
        log::debug(logcat, "update_state initiating all-providers sync check");
        provider.getAllHeightsAsync([this](std::vector<ethyl::HeightInfo> height_info) {
            log::debug(logcat, "Got all provider heights");
            next_provider_check = std::chrono::steady_clock::now() + PROVIDERS_CHECK_INTERVAL;
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
                    auto& url = client_info()[hi.index].url;
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
                                old_primary.url,
                                new_primary.name,
                                new_primary.url);
                        primary_down = primary_last_warned = std::chrono::steady_clock::now();
                    } else {
                        // We *were* on a backup but now are switching back to the primary
                        log::warning(
                                logcat,
                                fg(fmt::terminal_color::green) | fmt::emphasis::bold,
                                "{} [{}] is available again; switching back to it as primary L2 "
                                "source",
                                new_primary.name,
                                new_primary.url);
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
                            client_info()[0].url);
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
                log::debug(logcat, "L2 provider height updated to {}", *height);
                prune_old_states();
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
    // Make sure we have the last 3 L2_REWARD_POOL_UPDATE_BLOCKS reward values on hand so that we
    // can be called on at any time as a pulse validator to validate the l2_reward amount with a
    // safety margin.  We get called with nullopt initially to determine which heights we need, then
    // recurse with more set to the list of heights we need to retrieve.  For each one, we retrieve,
    // remove it from the list, then recurse (as needed) until more is empty.
    if (!more) {
        const auto reward_update_blocks = core.get_net_config().L2_REWARD_POOL_UPDATE_BLOCKS;
        std::forward_list<uint64_t> need;
        {
            std::shared_lock lock{mutex};
            for (auto r_height = reward_height(
                         latest_height - std::min(latest_height, reward_update_blocks * 2),
                         reward_update_blocks);
                 r_height <= latest_height;
                 r_height += reward_update_blocks) {
                if (!reward_rate.count(r_height))
                    need.push_front(r_height);
            }
            log::debug(
                    logcat, "Need to fetch reward rate for heights: {{{}}}", fmt::join(need, ","));
        }

        if (!need.empty())
            update_rewards(std::move(need));
        else
            update_logs();
        return;
    }

    assert(!more->empty());
    std::shared_lock lock{mutex};
    auto r_height = more->front();
    more->pop_front();
    oxen::log::debug(logcat, "Starting query for reward height {}", r_height);
    provider.callReadFunctionJSONAsync(
            contract::pool_address(core.get_nettype()),
            "0x{:x}"_format(contract::call::Pool_rewardRate),
            [this, r_height, more = std::move(more)](std::optional<nlohmann::json> result) mutable {
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
                                    "Contract reward rate for L2 heights {}-{} is {}",
                                    r_height,
                                    r_height + core.get_net_config().L2_REWARD_POOL_UPDATE_BLOCKS -
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
                        "Finished querying reward for height {}, there is more: {}",
                        r_height,
                        more->empty() ? "no" : "yes");
                if (!more->empty())
                    update_rewards(std::move(more));
                else
                    update_logs();
            },
            "0x{:x}"_format(r_height));
}

void L2Tracker::add_to_mempool(uint64_t l2_height, const event::StateChangeVariant& tx_variant) {
    if (tx_variant.index() == 0)  // monostate, i.e. not a state change log
        return;

    using namespace cryptonote;

    const auto hf_version = core.blockchain.get_network_version();
    transaction tx;
    tx.version = transaction_prefix::get_max_version_for_hf(hf_version);

    std::visit(
            [&tx]<typename T>(const T& arg) {
                if constexpr (std::is_same_v<T, event::NewServiceNode>) {
                    tx.type = txtype::ethereum_new_service_node;
                    add_new_service_node_to_tx_extra(tx.extra, arg);
                } else if constexpr (std::is_same_v<T, event::ServiceNodeRemovalRequest>) {
                    tx.type = txtype::ethereum_service_node_removal_request;
                    add_service_node_removal_request_to_tx_extra(tx.extra, arg);
                } else if constexpr (std::is_same_v<T, event::ServiceNodeRemoval>) {
                    tx.type = txtype::ethereum_service_node_removal;
                    add_service_node_removal_to_tx_extra(tx.extra, arg);
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
    if (!core.mempool.add_tx(
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
        oxen::log::debug(logcat, "L2 update logs finished; nothing to update");
        return;
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
                    // NOTE: This lambda locks both the TX pool and the L2 tracker atomically
                    // because we will add the L2 transactions into the mempool. This prevents
                    // deadlock in other codepaths that may try to lock like
                    //
                    //   This thread: Lock(L2 Tracker) -> Lock (TX pool)
                    //   Other thread: Lock(TX pool)   -> Lock (L2 Tracker)
                    //
                    // For example, this was happening in our worker thread for
                    // (1) tx_memory_pool::remove_stuck_transaction and
                    // (2) blockchain::handle_block_to_main_chain whereby
                    //
                    //   This thread: Lock(L2 Tracker) -> Lock(TX pool)
                    //   (1):         Lock(TX Pool, Blockchain)
                    //   (2):         Lock(Blockchain) -> Lock(L2 Tracker)
                    //
                    auto locks = tools::unique_locks(mutex, core.mempool);
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
                            log::error(logcat, "Log item from L2 provider without a blockNumber!");
                            continue;
                        }
                        try {
                            auto tx = get_log_event(chain_id, log);
                            add_to_mempool(*log.blockNumber, tx);
                            if (auto* reg = std::get_if<event::NewServiceNode>(&tx))
                                recent_regs.add(std::move(*reg), *log.blockNumber);
                            else if (auto* ul = std::get_if<event::ServiceNodeRemovalRequest>(&tx))
                                recent_unlocks.add(std::move(*ul), *log.blockNumber);
                            else if (auto* removal = std::get_if<event::ServiceNodeRemoval>(&tx))
                                recent_removals.add(std::move(*removal), *log.blockNumber);
                            else
                                assert(tx.index() == 0);
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

                    if (to >= latest_height) {
                        update_in_progress = false;
                        oxen::log::debug(logcat, "L2 update step finished");
                    } else {
                        keep_going = true;
                    }
                }
                if (keep_going)
                    update_logs();
            });
}

bool L2Tracker::check_chain_id() const {
    auto chain_ids = provider.getAllChainIds();
    bool bad = false;

    auto clients = provider.getClients();
    for (auto& ci : chain_ids) {
        auto& name = clients[ci.index].name;
        auto& url = clients[ci.index].url;
        if (!ci.success)
            log::warning(logcat, "Failed to retrieve L2 chain ID from {} [{}]", name, url);
        else if (ci.chainId != chain_id) {
            log::critical(
                    logcat,
                    "L2 provider {} [{}] has invalid chain ID 0x{:x} (chainId 0x{:x} is required)",
                    name,
                    url,
                    ci.chainId,
                    chain_id);
            bad = true;
        } else {
            log::info(
                    logcat,
                    "L2 provider {} [{}] returned correct chainId 0x{:x}",
                    name,
                    url,
                    ci.chainId);
        }
    }

    return !bad;
}

std::optional<uint64_t> L2Tracker::get_reward_rate(uint64_t height) const {
    std::shared_lock lock{mutex};
    if (auto it = reward_rate.find(
                reward_height(height, core.get_net_config().L2_REWARD_POOL_UPDATE_BLOCKS));
        it != reward_rate.end())
        return it->second;
    return std::nullopt;
}

uint64_t L2Tracker::get_latest_height() const {
    std::shared_lock lock{mutex};
    return latest_height;
}

uint64_t L2Tracker::get_safe_height() const {
    std::shared_lock lock{mutex};
    const cryptonote::network_config& config = cryptonote::get_config(core.get_nettype());
    return config.L2_TRACKER_SAFE_BLOCKS >= latest_height
                 ? 0
                 : latest_height - config.L2_TRACKER_SAFE_BLOCKS;
}

std::vector<uint64_t> L2Tracker::get_non_signers(
        const std::unordered_set<bls_public_key>& bls_public_keys) {
    return rewards_contract.get_non_signers(bls_public_keys);
}

std::vector<bls_public_key> L2Tracker::get_all_bls_public_keys(uint64_t blockNumber) {
    return rewards_contract.get_all_bls_pubkeys(blockNumber);
}

RewardsContract::ServiceNodeIDs L2Tracker::get_all_service_node_ids(
        std::optional<uint64_t> height) {
    RewardsContract::ServiceNodeIDs result = rewards_contract.all_service_node_ids(height);
    return result;
}

bool L2Tracker::get_vote_for(const event::NewServiceNode& reg) const {
    return recent_regs.contains(reg);
}
bool L2Tracker::get_vote_for(const event::ServiceNodeRemoval& removal) const {
    return recent_removals.contains(removal);
}
bool L2Tracker::get_vote_for(const event::ServiceNodeRemovalRequest& unlock) const {
    return recent_unlocks.contains(unlock);
}

}  // namespace eth
