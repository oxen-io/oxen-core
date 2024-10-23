#include "l2_tracker.h"

#include <common/bigint.h>
#include <common/guts.h>
#include <common/lock.h>
#include <crypto/crypto.h>
#include <crypto/eth.h>
#include <cryptonote_basic/cryptonote_format_utils.h>
#include <cryptonote_core/cryptonote_core.h>
#include <fmt/color.h>
#include <logging/oxen_logger.h>
#include <oxenmq/oxenmq.h>

#include <chrono>
#include <utility>
#include <variant>

#include "contracts.h"
#include "events.h"

namespace eth {

static auto logcat = log::Cat("l2_tracker");

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

    core.blockchain.hook_block_post_add([this](const auto& info) {
        const cryptonote::block& block = info.block;
        if (block.major_version >= cryptonote::feature::ETH_BLS) {
            std::lock_guard lock{mutex};
            latest_blockchain_l2_height = block.l2_height;
        }
    });
}

// For any given l2 height, we calculate the reward using the last height (inclusive) that was
// divisible by (netconfig).L2_REWARD_POOL_UPDATE_BLOCKS:
static inline uint64_t reward_height(uint64_t l2_height, uint64_t reward_update_blocks) {
    return l2_height - (l2_height % reward_update_blocks);
}

void L2Tracker::prune_old_states() {
    const auto expiry = latest_height - std::min(latest_height, HIST_SIZE);
    recent_regs_v2.expire(expiry);
    recent_unlocks.expire(expiry);
    recent_exits.expire(expiry);
    recent_req_changes.expire(expiry);
    auto reward_exp = reward_height(expiry, core.get_net_config().L2_REWARD_POOL_UPDATE_BLOCKS);
    reward_rate.erase(reward_rate.begin(), reward_rate.lower_bound(reward_exp));
}

void L2Tracker::set_height(uint64_t l2_height, bool take_lock) {
    std::unique_lock lock{mutex, std::defer_lock};
    if (take_lock)
        lock.lock();
    latest_height = l2_height;
    latest_height_ts = std::chrono::steady_clock::now();
    log::debug(logcat, "L2 provider height updated to {}", l2_height);

    // Check against the blockchain height and warn loudly if it looks like we are behind it.  (We
    // don't worry about a safety buffer here because there's one build-in to the l2_height in a
    // block, which is already lagged by SAFE_BLOCKS, so a current height should always be ahead of
    // it).
    if (core.service_node() && latest_height < latest_blockchain_l2_height) {
        log::warning(
                globallogcat,
                fg(fmt::terminal_color::red) | fmt::emphasis::bold,
                "Latest RPC provider reported height ({}) is too far behind the latest Oxen "
                "chain reported height ({})",
                latest_height,
                latest_blockchain_l2_height);
    }

    prune_old_states();
}

void L2Tracker::update_state() {
    // TODO: also check chain id?  Perhaps just one on first startup?

    std::lock_guard lock{mutex};
    if (update_in_progress)
        return;
    update_in_progress = true;

    log::debug(logcat, "L2 update commencing");
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
                                tools::trim_url(url),
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
                                tools::trim_url(old_primary.url),
                                new_primary.name,
                                tools::trim_url(new_primary.url));
                        primary_down = primary_last_warned = std::chrono::steady_clock::now();
                    } else {
                        // We *were* on a backup but now are switching back to the primary
                        log::warning(
                                logcat,
                                fg(fmt::terminal_color::green) | fmt::emphasis::bold,
                                "{} [{}] is available again; switching back to it as primary L2 "
                                "source",
                                new_primary.name,
                                tools::trim_url(new_primary.url));
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
                            tools::trim_url(client_info()[0].url));
                    primary_last_warned = now;
                }
            }

            // We just got the height, so no need to immediately fetch it again: just copy whatever
            // we got back from our (new) primary node and skip the update_height step.
            for (const auto& hi : height_info) {
                if (hi.index == primary_index) {
                    if (hi.success) {
                        set_height(hi.height);
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
                set_height(*height, /*take_lock=*/false);
            } else {
                log::warning(
                        logcat,
                        "Failed to retrieve current height from L2 RPC provider; last successful "
                        "retrieval: {}",
                        latest_height_ts
                                ? "{} ago"_format(tools::friendly_duration(
                                          std::chrono::steady_clock::now() - *latest_height_ts))
                                : "never");
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
            log::debug(logcat, "L2 update finished (L2 height unchanged)");
        }
    });
}

void L2Tracker::update_rewards(std::optional<std::forward_list<uint64_t>> more) {
    // If the contract addresses aren't set yet (i.e. for HF20 before the contract is deployed)
    // then there's nothing else to actually update yet and so we're done.
    const auto& conf = core.get_net_config();
    if ((conf.ETHEREUM_POOL_CONTRACT.empty() || conf.ETHEREUM_REWARDS_CONTRACT.empty())) {
        if (core.blockchain.get_network_version() >= cryptonote::feature::ETH_BLS) {
            log::critical(
                    globallogcat,
                    "Error: we are on HF21, but pool and/or reward contract addresses are not "
                    "set!");
            assert(!"missing contract addresses");
        }
        oxen::log::debug(logcat, "No L2 contract addresses yet to update; L2 update finished.");
        std::unique_lock lock{mutex};
        update_in_progress = false;
        return;
    }

    // Make sure we have the last 2 L2_REWARD_POOL_UPDATE_BLOCKS reward values on hand so that we
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
                         latest_height - std::min(latest_height, reward_update_blocks),
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
    log::debug(logcat, "Starting query for reward height {}", r_height);
    provider.callReadFunctionJSONAsync(
            core.get_net_config().ETHEREUM_POOL_CONTRACT,
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

                log::debug(
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

void L2Tracker::update_logs() {
    std::shared_lock lock{mutex};

    // Start from the *later* of our previous height+1 or the first block that we actually care
    // about if the previous one is too old.
    uint64_t from = std::max(
            synced_height + 1, latest_height >= HIST_SIZE ? latest_height - HIST_SIZE + 1 : 0);
    log::trace(
            logcat,
            "L2Tracker::{} synced_height={}, latest_height={}, HIST_SIZE={}, from={}",
            __func__,
            synced_height,
            latest_height,
            HIST_SIZE,
            from);

    if (latest_height < from) {
        update_purge_list();
        return;
    }

    uint64_t to = std::min(latest_height, from + GETLOGS_MAX_BLOCKS - 1);

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
                        log::debug(logcat, "L2 update finished");
                        // End without calling update_purge_list because we want to be sure we've
                        // seen any pending events before we start considering purges.
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
                            add_to_mempool(tx);
                            if (auto* reg_v2 = std::get_if<event::NewServiceNodeV2>(&tx))
                                recent_regs_v2.add(std::move(*reg_v2), *log.blockNumber);
                            else if (auto* ul = std::get_if<event::ServiceNodeExitRequest>(&tx))
                                recent_unlocks.add(std::move(*ul), *log.blockNumber);
                            else if (auto* exit = std::get_if<event::ServiceNodeExit>(&tx))
                                recent_exits.add(std::move(*exit), *log.blockNumber);
                            else if (auto* req = std::get_if<event::StakingRequirementUpdated>(&tx))
                                recent_req_changes.add(std::move(*req), *log.blockNumber);
                            else {
                                assert(tx.index() == 0);
                            }
                        } catch (const std::exception& e) {

                            fmt::memory_buffer buffer{};
                            fmt::format_to(
                                    std::back_inserter(buffer),
                                    "The raw blob was (32 byte chunks/line):\n\n");
                            std::string_view hex = log.data;
                            while (hex.size()) {
                                std::string_view chunk = tools::string_safe_substr(
                                        hex, 0, 64);  // Grab 32 byte chunk
                                fmt::format_to(
                                        std::back_inserter(buffer),
                                        "  {}\n",
                                        chunk);  // Output the chunk
                                hex = tools::string_safe_substr(
                                        hex, 64, hex.size());  // Advance the hex
                            }

                            log::error(
                                    logcat,
                                    "Failed to convert L2 state change transaction to an Oxen "
                                    "state change transaction: {}\n\n{}",
                                    e.what(),
                                    fmt::to_string(buffer));
                            continue;
                        }
                    }

                    synced_height = to;

                    keep_going = to < latest_height;
                }
                if (keep_going)
                    update_logs();
                else
                    // NB: there is a `return` statement above that will bypass this on fetch error,
                    // but that is desirable: we want the purge list update to always follow a full
                    // log update so that we don't add nodes to the purge list that are undergoing a
                    // normal contract exit, and so we need any pending regular exits to be noticed
                    // before we consider purging.
                    update_purge_list();
            });
}

void L2Tracker::update_purge_list(bool curr_height_fallback) {
    std::unique_lock lock{mutex};

    auto purge_height = latest_height;
    if (!curr_height_fallback)
        purge_height -= latest_height % core.get_net_config().L2_NODE_LIST_PURGE_BLOCKS;

    log::trace(
            logcat,
            "Current l2 height {} requires SN list computed @ height {}{}; last purge height is {}",
            latest_height,
            purge_height,
            curr_height_fallback ? " (fallback)" : "",
            latest_purge_check);

    if (purge_height > latest_purge_check) {
        provider.callReadFunctionJSONAsync(
                core.get_net_config().ETHEREUM_REWARDS_CONTRACT,
                "0x{:x}"_format(contract::call::ServiceNodeRewards_allServiceNodeIDs),
                [this, purge_height, curr_height_fallback](
                        std::optional<nlohmann::json> maybe_result) mutable {
                    auto locks = tools::unique_locks(mutex, core.blockchain, core.mempool);
                    bool make_fallback_request = false;
                    auto update_finisher = oxen::defer([&] {
                        if (make_fallback_request) {
                            std::apply([](auto&... lock) { (lock.unlock(), ...); }, locks);
                            update_purge_list(true);
                        } else {
                            update_in_progress = false;
                            log::debug(logcat, "L2 update finished");
                        }
                    });

                    if (!maybe_result) {
                        log::warning(
                                logcat,
                                "Failed to fetch contract node list for L2 height {}",
                                purge_height);
                        if (!curr_height_fallback)
                            make_fallback_request = true;
                        return;
                    }
                    if (!maybe_result->is_string()) {
                        log::warning(
                                logcat,
                                "Failed to parse contract node list response for L2 height {}: "
                                "expected a string, got: {}",
                                purge_height,
                                maybe_result->dump());
                        if (!curr_height_fallback)
                            make_fallback_request = true;
                        return;
                    }

                    auto result_hex = maybe_result->get<std::string_view>();
                    std::vector<std::pair<uint64_t, bls_public_key>> result;
                    try {
                        result = RewardsContract::parse_all_service_node_ids(result_hex);
                    } catch (const std::exception& e) {
                        log::warning(
                                logcat,
                                "Failed to parse service node id list from contract for L2 height "
                                "{}: {}",
                                purge_height,
                                e.what());
                    }

                    if (!result.empty()) {
                        in_contract.clear();
                        for (const auto& [id, blspk] : result)
                            in_contract.insert(blspk);

                        latest_purge_check = purge_height;

                        log::debug(
                                logcat,
                                "purge node list update completed for L2 height {} with {} "
                                "contract nodes",
                                purge_height,
                                in_contract.size());

                        // Only insert into the mempool if it looks like we're a fully synced SN on
                        // HF21+.  If we *aren't* synced, we could end up putting nodes in because
                        // they look like they shouldn't be in oxend, but that's just because we're
                        // still syncing and haven't come across the transactions where they
                        // actually left the SN list.  (It isn't catastrophic if we do, but it could
                        // cause a missed pulse block or some denial votes to get rid of it).
                        if (core.blockchain.get_network_version() < cryptonote::feature::ETH_BLS ||
                            !core.service_node() || core.offline() ||
                            core.get_target_blockchain_height() >
                                    core.blockchain.get_current_blockchain_height()) {
                            log::debug(
                                    logcat,
                                    "Synced HF21+ service node checks failed; not constructing "
                                    "purge txes");
                            return;
                        }

                        // If we are in the fallback attempt then don't put it in the mempool
                        // because we only want to create mempool transactions at the configured
                        // purge interval L2 heights, and doing an out-of-band update on some height
                        // not on that interval could lead to duplicate purge transactions (which
                        // aren't harmful, but are a bit messy).
                        if (curr_height_fallback) {
                            log::debug(
                                    logcat,
                                    "Synced contract node list at fallback L2 height {}; "
                                    "not constructing purge txes",
                                    purge_height);
                            return;
                        }

                        // We only add nodes in the mempool here, on a fresh fetch of data.  It's
                        // possible that conditions change that make it purgeable before our next
                        // fetch, but if so that's okay: it'll get to live slightly longer to next
                        // update but we'll catch it then.
                        //
                        // Note that, unlike events, we will still confirm a purge (as a pulse
                        // validator) even if we don't have it in our mempool as long as the
                        // purgeable conditions are met when we vote on it.
                        std::vector<std::pair<crypto::public_key, bls_public_key>> to_purge;
                        core.service_node_list.for_each_service_node(
                                [this, &to_purge](
                                        const crypto::public_key& pubkey,
                                        const service_nodes::service_node_info& info) {
                                    if (is_node_purgeable(info.bls_public_key))
                                        to_purge.emplace_back(pubkey, info.bls_public_key);
                                });

                        if (!to_purge.empty()) {
                            event::ServiceNodePurge purge{chain_id, purge_height};
                            for (auto& [pk, bls] : to_purge) {
                                log::warning(
                                        logcat,
                                        "service node {} (bls: {}) is not in the L2 rewards "
                                        "contract; generating a purge tx",
                                        pk,
                                        bls);
                                purge.bls_pubkey = bls;
                                add_to_mempool(purge);
                            }
                        }
                    } else {
                        if (!curr_height_fallback) {
                            // We failed to get the target height, so lets retry using the current
                            // height (perhaps the target is too old for the Arb node to have
                            // available).  As per above, we won't initiate purges for such data,
                            // but we'll still be able to confirm/deny them.
                            log::info(
                                    logcat,
                                    "service node list for purge checks @ {} failed; retrying "
                                    "at current height {}",
                                    purge_height,
                                    latest_height);
                            make_fallback_request = true;
                        } else {
                            // We got an error *twice*, which indicates some error with our L2
                            // provider.  We clear the node list, rather than keeping an old, stale
                            // one that might lead us to incorrectly purge new nodes based on
                            // data that is too old.
                            in_contract.clear();
                            log::warning(
                                    logcat,
                                    "Unexpected service node list retrieval result for SN purge "
                                    "checks failed (twice): {}",
                                    maybe_result->dump());
                        }
                    }
                },

                "0x{:x}"_format(purge_height));
    } else {
        update_in_progress = false;
        log::debug(logcat, "L2 update step finished");
    }
}

void L2Tracker::add_to_mempool(const event::StateChangeVariant& tx_variant) {
    if (tx_variant.index() == 0)  // monostate, i.e. not a state change log
        return;

    using namespace cryptonote;

    const auto hf_version = core.blockchain.get_network_version();
    transaction tx;
    tx.version = transaction_prefix::get_max_version_for_hf(hf_version);

    std::visit(
            [&tx]<typename T>(const T& arg) {
                if constexpr (!std::is_same_v<T, std::monostate>) {
                    tx.type = arg.txtype;
                    add_l2_event_to_tx_extra(tx.extra, arg);
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
                tx_pool_options::new_tx(/*do_not_relay=*/true),
                hf_version,
                nullptr)) {
        if (tvc.m_verifivation_failed) {
            if (tvc.m_duplicate_nonstandard)
                log::debug(
                        log::Cat("verify"), "Transaction was already in the mempool: {}", tx_hash);
            else
                log::error(
                        log::Cat("verify"),
                        "Transaction verification failed for {}: {}",
                        tx_hash,
                        cryptonote::print_tx_verification_context(tvc));
        } else if (tvc.m_verifivation_impossible) {
            log::error(
                    log::Cat("verify"),
                    "Transaction verification impossible for {}: {}",
                    tx_hash,
                    cryptonote::print_tx_verification_context(tvc));
        }
    }
}

bool L2Tracker::check_chain_id() const {
    auto chain_ids = provider.getAllChainIds();
    bool bad = false;

    auto clients = provider.getClients();
    for (auto& ci : chain_ids) {
        auto& name = clients[ci.index].name;
        auto& url = clients[ci.index].url;
        std::string trimmed_url = tools::trim_url(url);
        if (!ci.success)
            log::warning(logcat, "Failed to retrieve L2 chain ID from {} [{}]", name, trimmed_url);
        else if (ci.chainId != chain_id) {
            log::critical(
                    logcat,
                    "L2 provider {} [{}] has invalid chain ID 0x{:x} (chainId 0x{:x} is required)",
                    name,
                    trimmed_url,
                    ci.chainId,
                    chain_id);
            bad = true;
        } else {
            log::info(
                    logcat,
                    "L2 provider {} [{}] returned correct chainId 0x{:x}",
                    name,
                    trimmed_url,
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

std::optional<std::chrono::nanoseconds> L2Tracker::latest_height_age() const {
    std::shared_lock lock{mutex};
    if (latest_height_ts)
        return std::chrono::steady_clock::now() - *latest_height_ts;
    return std::nullopt;
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

bool L2Tracker::get_vote_for(const event::NewServiceNodeV2& reg) const {
    return recent_regs_v2.contains(reg);
}
bool L2Tracker::get_vote_for(const event::ServiceNodeExit& exit) const {
    std::shared_lock lock{mutex};
    return recent_exits.contains(exit);
}
bool L2Tracker::get_vote_for(const event::ServiceNodeExitRequest& unlock) const {
    std::shared_lock lock{mutex};
    return recent_unlocks.contains(unlock);
}
bool L2Tracker::get_vote_for(const event::StakingRequirementUpdated& req_change) const {
    std::shared_lock lock{mutex};
    return recent_req_changes.contains(req_change);
}
bool L2Tracker::get_vote_for(const event::ServiceNodePurge& purge) const {
    // This works a little differently from votes for real L2 events, above: unlike real events,
    // there isn't an L2 authority that we are confirming, but rather this is an oxen-generated
    // event that we either agree or disagree with.
    auto locks = tools::shared_locks(mutex, core.blockchain);
    return is_node_purgeable(purge.bls_pubkey);
}
bool L2Tracker::is_node_purgeable(const bls_public_key& bls_pubkey) const {
    if (in_contract.empty())
        return false;  // we've somehow failed to get any node list

    if (in_contract.count(bls_pubkey))
        return false;  // something changed, and the node is in the contract now

    auto pk = core.service_node_list.find_public_key(bls_pubkey);
    if (!pk)
        return false;  // Doesn't exist on the oxen side anymore

    std::optional<uint64_t> reg_height;
    core.service_node_list.if_service_node(
            pk, [&](const auto& info) { reg_height = info.registration_height; });
    if (!reg_height)
        return false;  // Not a registered service node

    if (*reg_height + core.get_net_config().L2_NODE_LIST_PURGE_MIN_OXEN_AGE >=
        core.blockchain.get_current_blockchain_height())
        return false;  // Too young: our current contract node list can be a bit outdated and
                       // we don't want to catch brand new registrations that aren't in our
                       // potentially outdated list.

    return true;
}

}  // namespace eth
