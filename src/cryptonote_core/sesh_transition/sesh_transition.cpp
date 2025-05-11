#include "sesh_transition.h"

#include <fmt/chrono.h>

#include <fstream>
#include <iterator>
#include <ranges>

#include "crypto/crypto.h"
#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "detail.h"
#include "epee/int-util.h"
#include "logging/oxen_logger.h"
#include "network_config/mocknet.h"

namespace oxen::sesh {

namespace {
    auto logcat = oxen::log::Cat("sesh_transition");

    static const addrmap_t empty_addrmap;
    const proper_ed_keys_t empty_ed_keys;
    const bls_keys_t empty_bls_keys;
    const bonus_map_t empty_transition_bonus;
}  // namespace

transition_context get_transition_context(network_type net, uint64_t top_block_height) {
    transition_context result = {};
    if (net == cryptonote::network_type::MAINNET) {
        result.staking_requirement = SESH_STAKING_REQUIREMENT;
        result.oxen_staking_requirement = OXEN_STAKING_REQUIREMENT;
    } else {
        result.staking_requirement = SESH_STAKING_REQUIREMENT_TESTNET;
        result.oxen_staking_requirement = OXEN_STAKING_REQUIREMENT_TESTNET;
    }

    switch (net) {
        case network_type::TESTNET:
            result.addresses = &testnet::addresses;
            result.proper_ed_keys = &testnet::proper_ed_keys;
            result.bls_keys = &testnet::bls_keys;
            result.conv_ratio = testnet::conv_ratio;
            result.transition_bonus = &testnet::transition_bonus;
            break;

        case network_type::DEVNET:
            result.addresses = &devnet::addresses;
            result.proper_ed_keys = &devnet::proper_ed_keys;
            result.bls_keys = &devnet::bls_keys;
            result.conv_ratio = devnet::conv_ratio;
            result.transition_bonus = &devnet::transition_bonus;
            break;

        case network_type::MAINNET:
            result.addresses = &mainnet::addresses;
            result.proper_ed_keys = &mainnet::proper_ed_keys;
            result.bls_keys = &mainnet::bls_keys;
            result.conv_ratio = mainnet::conv_ratio;
            result.transition_bonus = &mainnet::transition_bonus;
            break;

        case network_type::STAGENET: [[fallthrough]];
        case network_type::LOCALDEV: [[fallthrough]];
        case network_type::FAKECHAIN: [[fallthrough]];
        case network_type::UNDEFINED:

            result.addresses = &empty_addrmap;
            result.proper_ed_keys = &empty_ed_keys;
            result.bls_keys = &empty_bls_keys;
            result.conv_ratio = mainnet::conv_ratio;
            result.transition_bonus = &empty_transition_bonus;
            break;
    }

    if (mocknet_is_forking(top_block_height) || mocknet_has_forked(top_block_height)) {
        mocknet_get_transition_context(result);
    }
    return result;
}

struct node_transition {
    crypto::public_key old_pkey;
    crypto::public_key pkey;
    std::shared_ptr<service_nodes::service_node_info> sn_info;
    uint64_t tokens_allocated;
    bool zombie;

    // NOTE: Flags to indicate why 'zombie' is true for this node
    bool missing_ed25519_key;
    bool missing_bls_key;
    bool partially_funded;
    bool contributor_not_registered_for_swap;
    bool insufficient_sesh;
};

namespace {
    // Drop-in replacement for fmt::output_file that supports a formatted .print(), because
    // fmt::output_file fails to link if fmt is in header-only mode, and fmt closed the issue about
    // "it doesn't work" by basically saying "it doesn't work" and closing the issue
    // (https://github.com/fmtlib/fmt/issues/3708).
    class FileFormatter {
        std::ofstream os;
        std::ostreambuf_iterator<char> out{os};

      public:
        explicit FileFormatter(std::string_view filename) {
            os.exceptions(std::ofstream::failbit | std::ofstream::badbit);
            os.open(tools::utf8_path(filename), std::ios_base::out | std::ios_base::trunc);
        }

        template <typename... Args>
        void print(fmt::format_string<Args...> format, Args&&... args) {
            fmt::format_to(out, format, std::forward<Args>(args)...);
        }
    };
}  // namespace

static void dump_transition_outcome_csv(
        const transition_context& context,
        const service_nodes::service_node_list::state_t& snl_state,
        network_type net,
        std::span<node_transition> node_list,
        const std::unordered_map<eth::address, uint64_t>& final_allocation_before_distrib,
        const std::unordered_map<eth::address, uint64_t>& final_unlocked_tokens) {
    uint64_t now = time(nullptr);
    oxen::log::debug(logcat, "Writing SESH->ETH allocation to disk");
    uint64_t total_bonus_sesh = 0;

    // NOTE: Calculate total OXEN staked prior to the transition
    uint64_t total_staked_oxen = 0;
    for (auto it : snl_state.service_nodes_infos) {
        for (auto contrib_it : it.second->contributors) {
            total_staked_oxen += contrib_it.amount;
        }
    }

    const size_t decimal_places = oxen::DISPLAY_DECIMAL_POINT;
    {
        FileFormatter file{
                "{:%Y%m%d_%H%M%S}_sesh_transition_result_stake_req_{}_conv_ratio_{}_oxen_per_{}_sesh_eth_addr_allocation.csv"_format(
                        fmt::localtime(now),
                        cryptonote::print_money(
                                context.staking_requirement,
                                cryptonote::strip_zeros::yes,
                                decimal_places),
                        cryptonote::print_money(context.conv_ratio.second),
                        cryptonote::print_money(context.conv_ratio.first))};
        file.print("height,{}\n", snl_state.height);
        file.print("rewards_program_snapshot_date,2025-02-27\n");
        file.print(
                "staking_requirement,{}\n", cryptonote::print_money(context.staking_requirement));

        // NOTE: Amount of OXEN staked prior to the transition
        file.print("total_staked_oxen,{}\n", cryptonote::print_money(total_staked_oxen));

        // NOTE: Find the amount of bonus tokens allocated to the address
        {
            for (auto it : *context.transition_bonus)
                total_bonus_sesh += it.second;
            file.print("total_bonus_sesh,{}\n", cryptonote::print_money(total_bonus_sesh));
        }

        // NOTE: Enumerate the amount of locked tokens
        {
            uint64_t total_staked_sesh = 0;
            for (auto node_it : node_list) {
                for (auto contrib_it : node_it.sn_info->contributors)
                    total_staked_sesh += contrib_it.amount;
            }
            file.print("total_staked_sesh,{}\n", cryptonote::print_money(total_staked_sesh));
        }

        // NOTE: Enumerate the amount of unlocked tokens
        {
            uint64_t total_unlocked_sesh = 0;
            for (auto it : final_unlocked_tokens) {
                total_unlocked_sesh += it.second;
            }
            file.print("total_unlocked_sesh,{}\n", cryptonote::print_money(total_unlocked_sesh));
        }

        // NOTE: Calculate the amount of tokens generated
        {
            uint64_t total_generated_sesh = 0;
            for (auto it : final_allocation_before_distrib)
                total_generated_sesh += it.second;
            file.print("total_generated_sesh,{}\n", cryptonote::print_money(total_generated_sesh));
        }

        // NOTE: Sort the final token allocations, highest to lowest
        struct sesh_alloc_pair {
            eth::address addr;
            uint64_t amount;
            size_t oxen_sn_count;
            size_t sesh_sn_count;
        };
        std::vector<sesh_alloc_pair> sorted;
        sorted.reserve(final_allocation_before_distrib.size());
        for (auto it : final_allocation_before_distrib) {
            sesh_alloc_pair& pair = sorted.emplace_back();
            pair.addr = it.first;
            pair.amount = it.second;

            std::vector<cryptonote::account_public_address> oxen_addrs_for_eth_addr;
            for (auto addr_it : *context.addresses) {
                if (addr_it.second == it.first) {

                    cryptonote::address_parse_info parse = {};
                    [[maybe_unused]] bool ok =
                            cryptonote::get_account_address_from_str(parse, net, addr_it.first);
                    assert(ok);

                    oxen_addrs_for_eth_addr.push_back(parse.address);
                }
            }

            // NOTE: Enumerate the number of SNs this ETH address was staked in before the
            // transition
            for (auto sn_info_it : snl_state.service_nodes_infos) {
                bool matched = false;

                // NOTE: Check if any of the contributors match the OXEN address that belonged to
                // this ETH address
                for (auto contrib_it : sn_info_it.second->contributors) {
                    for (auto oxen_addr : oxen_addrs_for_eth_addr) {
                        if (oxen_addr == contrib_it.address) {
                            pair.oxen_sn_count++;
                            matched = true;
                            break;
                        }
                    }

                    if (matched)
                        continue;
                }
            }

            // NOTE: Enumerate the number of SNs this ETH address is still, staked in after the
            // transition
            for (auto node_it : node_list) {
                // NOTE: Check if any of the contributors match the ETH address
                for (auto contrib_it : node_it.sn_info->contributors) {
                    if (pair.addr == contrib_it.ethereum_address) {
                        pair.sesh_sn_count++;
                        break;
                    }
                }
            }
        }
        std::sort(
                sorted.begin(),
                sorted.end(),
                [](const sesh_alloc_pair& lhs, const sesh_alloc_pair& rhs) {
                    bool result = lhs.amount > rhs.amount;
                    return result;
                });

        file.print(
                "conversion_ratio,{} OXEN/{} SESH\n",
                cryptonote::print_money(context.conv_ratio.second),
                cryptonote::print_money(context.conv_ratio.first));

        // NOTE: Print out the allocation for each address
        file.print(
                "eth_addr,pre_transition_sn_count,post_transition_sn_count,bonus_sesh,staked_sesh,"
                "unlocked_sesh,total_sesh (staked+unlocked)\n");
        size_t index = 0;
        for (auto sorted_it : sorted) {

            // NOTE: Find the amount of bonus tokens allocated to the address
            uint64_t bonus_tokens = 0;
            auto bonus_it = context.transition_bonus->find(sorted_it.addr);
            if (bonus_it != context.transition_bonus->end()) {
                bonus_tokens = bonus_it->second;
            }

            // NOTE: Enumerate the amount of tokens locked in a session node
            uint64_t locked_tokens = 0;
            for (auto node_it : node_list) {
                for (auto contrib_it : node_it.sn_info->contributors) {
                    if (contrib_it.ethereum_address == sorted_it.addr) {
                        locked_tokens += contrib_it.amount;
                    }
                }
            }

            // NOTE: Find the amount tokens claimable by address on day 1
            uint64_t unlocked_tokens = 0;
            auto unlocked_it = final_unlocked_tokens.find(sorted_it.addr);
            if (unlocked_it != final_unlocked_tokens.end())
                unlocked_tokens = unlocked_it->second;

            // NOTE: Write the CSV line
            file.print(
                    "redacted_{:04d},{},{},{},{},{},{}\n",
                    index++,
                    sorted_it.oxen_sn_count,
                    sorted_it.sesh_sn_count,
                    cryptonote::print_money(bonus_tokens),
                    cryptonote::print_money(locked_tokens),
                    cryptonote::print_money(unlocked_tokens),
                    cryptonote::print_money(sorted_it.amount));
        }
    }

    oxen::log::debug(logcat, "Writing SN SESH transition outcome to disk");
    {
        // NOTE: Count some stats
        size_t transitioned_node_count = 0;
        size_t missing_ed25519_key = 0;
        size_t missing_bls_key = 0;
        size_t partially_funded = 0;
        size_t contributor_not_registered_for_swap = 0;
        size_t insufficient_sesh = 0;
        for (auto it : node_list) {
            bool transitioned = it.tokens_allocated >= context.staking_requirement;
            if (transitioned)
                transitioned_node_count++;
            if (it.missing_ed25519_key)
                missing_ed25519_key++;
            if (it.missing_bls_key)
                missing_bls_key++;
            if (it.partially_funded)
                partially_funded++;
            if (it.contributor_not_registered_for_swap)
                contributor_not_registered_for_swap++;
            if (it.insufficient_sesh)
                insufficient_sesh++;
        }

        const float transition_pct =
                transitioned_node_count / static_cast<float>(node_list.size()) * 100.f;

        // NOTE: Generate file
        FileFormatter file{
                "{:%Y%m%d_%H%M%S}_sesh_transition_result_stake_req_{}_conv_ratio_{}_oxen_per_{}_sesh_transition_{}pct.csv"_format(
                        fmt::localtime(now),
                        cryptonote::print_money(
                                context.staking_requirement,
                                cryptonote::strip_zeros::yes,
                                decimal_places),
                        cryptonote::print_money(context.conv_ratio.second),
                        cryptonote::print_money(context.conv_ratio.first),
                        int(transition_pct))};

        // NOTE: CSV metadata
        file.print("height,{}\n", snl_state.height);
        file.print("rewards_program_snapshot_date,2025-02-27\n");
        file.print("total_staked_oxen,{}\n", cryptonote::print_money(total_staked_oxen));
        file.print("total_bonus_sesh,{}\n", cryptonote::print_money(total_bonus_sesh));
        file.print(
                "staking_requirement,{}\n", cryptonote::print_money(context.staking_requirement));
        file.print(
                "conversion_ratio,{} OXEN/{} SESH\n",
                cryptonote::print_money(context.conv_ratio.second),
                cryptonote::print_money(context.conv_ratio.first));
        file.print(
                "transition,{}/{} ({:.2f}%)\n",
                transitioned_node_count,
                node_list.size(),
                transition_pct);
        file.print("missing_ed25519_key_count,{}\n", missing_ed25519_key);
        file.print("missing_bls_key_count,{}\n", missing_bls_key);
        file.print("partially_funded,{}\n", partially_funded);
        file.print("contributor_not_registered_for_swap,{}\n", contributor_not_registered_for_swap);
        file.print("insufficient_sesh,{}\n", insufficient_sesh);

        file.print(
                "registration_height,node_pkey,sesh_allocated,transitioned,missing_ed25519_key,"
                "missing_bls_key,partially_funded,contributor_not_registered_for_swap,insufficient_"
                "sesh\n");
        size_t count = 0;
        for (const node_transition& it : node_list) {
            bool transitioned = it.tokens_allocated >= context.staking_requirement;
            file.print(
                    "{:06d},"           // registration_height
                    "redacted_{:04d},"  // pkey
                    "{},"               // tokens_allocated
                    "{},"               // transitioned
                    "{},"               // missing_ed25519_key
                    "{},"               // missing_bls_key
                    "{},"               // partially_funded
                    "{},"               // contributor_not_registered_for_swap
                    "{},"               // insufficient_sesh
                    "\n",
                    it.sn_info->registration_height,
                    count++,
                    cryptonote::print_money(it.tokens_allocated),
                    transitioned,
                    it.missing_ed25519_key,
                    it.missing_bls_key,
                    it.partially_funded,
                    it.contributor_not_registered_for_swap,
                    it.insufficient_sesh);
        }

        // NOTE: Sanity check some of the stats
        for (const node_transition& it : node_list) {
            bool transitioned = it.tokens_allocated >= context.staking_requirement;

            // NOTE: If you transitioned, you can't be a zombie and vice versa.
            assert(transitioned == !it.zombie);

            // NOTE: If you transitioned, then you will have some contributors
            if (transitioned) {
                assert(it.sn_info->contributors.size());
            }

            if (!transitioned) {
                assert(it.sn_info->contributors.empty());
            }
        }
    }
}

void transition(
        const transition_context& context,
        service_nodes::service_node_list::state_t& snl_state,
        cryptonote::BlockchainSQLite& sql,
        network_type net,
        service_nodes::block_add_result& add_result,
        uint32_t block_tx_count) {

    auto address_info_from_str = [net](std::string_view addr) {
        cryptonote::address_parse_info api;
        if (!get_account_address_from_str(api, net, addr) || api.has_payment_id ||
            api.is_subaddress)
            throw std::runtime_error{
                    "Unable to perform SESH transition: batching database contains invalid, "
                    "unparseable, or non-OXEN address '{}'"_format(addr)};
        return api;
    };
    const auto& conv_ratio = context.conv_ratio;

    const auto& unparsed_sesh_addrs = *context.addresses;
    log::debug(logcat, "oxen -> sesh addr map size: {}", unparsed_sesh_addrs.size());
    std::unordered_map<cryptonote::account_public_address, eth::address> sesh_addrs;
    for (const auto& [o, s] : unparsed_sesh_addrs) {
        auto parsed_addr_info = address_info_from_str(o);
        sesh_addrs[parsed_addr_info.address] = s;
    }

    const auto& remap_ed_keys = *context.proper_ed_keys;
    const auto& node_bls_keys = *context.bls_keys;

    auto oxen_to_sesh = [&conv_ratio](const cryptonote::reward_money& oxen) {
        uint64_t result = mul128_div64(oxen.to_coin(), conv_ratio.first, conv_ratio.second);
        return result;
    };

    // We start out by finding the total amount of SESH owed to each ETH address: starting from the
    // SN bonus, then we'll add converted amounts for any batched rewards, then convert existing
    // stakes.  Then, once we know each address's total, we'll go back and try to re-fill as many
    // SNs as we can from the unallocated amounts.
    std::unordered_map<eth::address, uint64_t> unallocated = *context.transition_bonus;
    for (const auto& [eth, amount] : unallocated) {
        log::debug(logcat, "transition bonuses:");
        log::debug(logcat, "\tSESH {} has {}", eth, amount);
    }

    // Convert any balances for registered accounts in the batching db, removing it from the
    // batching db.  (If there is SESH left over at the end we'll put it back in, but under the
    // converted ETH address).

    auto [accrued_addr, accrued_value] = sql.get_all_accrued_rewards();
    assert(accrued_addr.size() == accrued_value.size());
    for (size_t i = 0; i < accrued_addr.size(); i++) {
        auto& addr = accrued_addr[i];
        auto& val = accrued_value[i];

        auto api = address_info_from_str(addr);
        const auto& oxen_addr = api.address;

        auto it = sesh_addrs.find(oxen_addr);
        if (it == sesh_addrs.end())
            continue;

        const auto& eth_addr = it->second;
        unallocated[eth_addr] += oxen_to_sesh(val.amount);
        log::debug(
                logcat,
                "oxen -> sesh ({} -> {}) accrued unpaid oxen rewards: {}",
                addr,
                eth_addr,
                val.amount);
    }

    for (const auto& [eth, amount] : unallocated) {
        log::debug(logcat, "SESH {} has unallocated {}", eth, amount);
    }

    std::vector<crypto::key_image> permanent_stakes;
    // Pass one: convert all stakes (of registered users) to our SESH bucket.  We'll leave the
    // values in place for now; we come back and update everything later.
    for (const auto& [pubkey, info] : snl_state.service_nodes_infos) {
        auto& old_stakes = info->contributors;
        for (auto& contributor : old_stakes) {
            auto addr = cryptonote::get_account_address_as_str(net, false, contributor.address);
            if (auto it = sesh_addrs.find(contributor.address); it != sesh_addrs.end()) {
                // Although the sum of .locked_contributions.amount is *usually* the same as
                // .amount, it's possible for a small over-contribution to have been accepted which
                // would show up in the locked amounts but not the aggregate amount (for example: if
                // a SN has 123.456 available and someone contributes 123.5)
                cryptonote::reward_money total = {};
                for (const auto& lc : contributor.locked_contributions) {
                    permanent_stakes.push_back(lc.key_image);
                    total += cryptonote::reward_money::coin_amount(lc.amount);
                }
                unallocated[it->second] += oxen_to_sesh(total);
                log::debug(
                        logcat,
                        "old stake from {} of amount {} -> SESH {} of amount {}, SESH balance {}",
                        addr,
                        total,
                        it->second,
                        oxen_to_sesh(total),
                        unallocated[it->second]);
            } else
                log::debug(logcat, "no SESH address for OXEN wallet {}", addr);
        }
    }

    const std::unordered_map<eth::address, uint64_t> final_allocation_before_distrib = unallocated;

    // We consider service nodes from oldest to most recent, replacing OXEN allocations with the
    // same proportion of SESH allocations for each contributor, and replacing contributor addresses
    // with their SESH addresses.
    //
    // By going oldest to newest we prioritize nodes that have been online the longest, which means
    // they are more likely to be good, solid nodes, and (for multi-contributor nodes) the
    // contributors appear to be happy with them since they haven't unstaked. (We could sort just
    // about any way we like, but this seems a reasonable choice).  In the case of two equal age
    // nodes, we break the tie by sorting by pubkey.
    //
    // As we transition we first figure out whether a node can survive:
    // - all contributors (including the operator) must be registered for the swap
    // - all contributors (including the operator) must have enough so-far unallocated SESH to be
    //   able to commit the same proportional amount of SESH (e.g. a staker with 31% of the OXEN
    //   staking contribution needs to have 31% of the required SESH staking contribution).
    //
    // If it can survive, we update the staking addresses to the ETH addresses, update the stakes to
    // the SESH amount, and remove that amounts from the unallocated funds bucket.
    //
    // If it can't survive (either because of unregistered contributors, or because of insufficient
    // staking funds), we mark it as a zombie, which means no contributors and a zero stake.  This
    // zombification also immediately releases any OXEN (The testing swarms will take care of
    // ejecting these off the network over the blocks after the fork).
    std::vector<std::pair<crypto::public_key, const service_nodes::service_node_info*>> sorted_sns;
    sorted_sns.reserve(snl_state.service_nodes_infos.size());
    for (const auto& [pk, sn] : snl_state.service_nodes_infos) {
        sorted_sns.emplace_back(pk, sn.get());
    }

    std::sort(sorted_sns.begin(), sorted_sns.end(), [](auto& a, auto& b) {
        return std::tie(a.second->registration_height, a.first) <
               std::tie(b.second->registration_height, b.first);
    });

    // Re-key any nodes which were keyed on an old monero-style "ed" key.  If the key is not
    // found in the `proper_ed_keys` map, it does not need remapped (i.e. is proper ed already).
    std::unordered_map<crypto::public_key, crypto::ed25519_public_key> remapped = remap_ed_keys;
    for (const auto& [key, _ignore] : sorted_sns)
        if (!remapped.contains(key))
            remapped[key] = crypto::ed25519_public_key{key};

    // This will contain our *new* list of service nodes, with only SESH contributors/stakes
    // converted from `sorted_sns`.
    std::vector<node_transition> post_transition_sns;

    std::unordered_set<crypto::public_key> zombies;

    const auto& staking_requirement = context.staking_requirement;

    // This is the ratio of the SESH staking requirement to OXEN staking requirement at the time of
    // the transition, as a reduced form fraction.
    const std::pair<uint32_t, uint32_t> staking_ratio = {
            context.staking_requirement /
                    std::gcd(context.staking_requirement, context.oxen_staking_requirement),
            context.oxen_staking_requirement /
                    std::gcd(context.staking_requirement, context.oxen_staking_requirement)};

    const auto& oxen_staking_requirement = context.oxen_staking_requirement;

    // This ensure that the ratios above are sufficiently reduced that we won't overflow when
    // calculating 'atomic_oxen_stake * numerator'.  Most maximum stakes are 15k, but there are a
    // few very old registered nodes with higher staking requirements (up to just under 21825 OXEN),
    // registered before the staking requirement dropped to 15k, with a maximum single contribution
    // of 17493.
    if (staking_ratio.first >= std::numeric_limits<uint64_t>::max() / 17'500'000'000'000) {
        throw std::runtime_error{
                "64 bit overflow detected for atomic OXEN conversion to stake, ratio was {}/{}"_format(
                        staking_ratio.first, staking_ratio.second)};
    }

    for (const auto& [pk, sni] : sorted_sns) {
        node_transition& item = post_transition_sns.emplace_back();

        // We have 5 exceptions to the 15k staking requirement on the OXEN mainnet, registered
        // continuously since before the staking requirement was fixed at 15k (HF16, i.e. Oxen 8).
        std::optional<std::pair<uint32_t, uint32_t>> extra_ratio;
        if (sni->staking_requirement > oxen_staking_requirement) {
            // +1 because we want this ratio to err on the size of being too small so that we are
            // guaranteed to have a sum of contributions at the end that are <= the required amount.
            // This is computed in tenths of an OXEN to ensure we won't overflow when applying the
            // ratio while still being able to get reasonably close to the precise number.
            extra_ratio.emplace(
                    oxen_staking_requirement / 100'000'000,
                    sni->staking_requirement / 100'000'000 + 1);

            // The maximum OXEN contribution amount we have is just under 17500, which means in the
            // code below we could (as an intermediate step) end up calculating up to just under 7/6
            // of the SESH staking requirement; thus we want to ensure that when we multiply such a
            // value by extra_ratio.first, we won't overflow:
            static_assert(
                    std::numeric_limits<uint64_t>::max() / 15000'0 >
                    (SESH_STAKING_REQUIREMENT * 7 + 5) / 6 /* ceiling division */);
        }

        bool bls_ok = true;

        // Nodes with old monero-style key which did not broadcast a proper ed25519 key
        // shouldn't make it this far, but check just in case and zombie if so
        if (!remapped.contains(pk)) {
            log::debug(
                    logcat,
                    "Node {} (monero-ed) not transitioning because there is no mapped proper "
                    "ed25519 key",
                    pk);
            item.zombie = true;
            bls_ok = false;
            item.missing_ed25519_key = true;
        }

        // Nodes with no ed->bls key mapping do not get transitioned
        if (!node_bls_keys.contains(remapped[pk])) {
            log::debug(
                    logcat,
                    "Node {} (ed) not transitioning because there is no mapped bls key",
                    remapped[pk]);
            item.zombie = true;
            bls_ok = false;
            item.missing_bls_key = true;
        }

        // Partially funded nodes at the time of transition just get dropped and will have to be
        // re-registered via a SESH multi-contributor contract.
        if (!sni->is_fully_funded()) {
            log::debug(
                    logcat,
                    "Node {} (ed) not transitioning because it is not fully funded",
                    remapped[pk]);
            item.zombie = true;
            item.partially_funded = true;
        }

        // Now compute how much SESH must be staked in order to maintain the same relative stake in
        // this SN.  E.g. if you had a 21% stake before (3150 OXEN) and the SESH staking requirement
        // is 20k then your SESH stake in this node will become 21% of 20k (4200 SESH).
        std::unordered_map<eth::address, uint64_t> sesh_stake;
        for (auto& contributor : sni->contributors) {
            auto addr = cryptonote::get_account_address_as_str(net, false, contributor.address);
            auto it = sesh_addrs.find(contributor.address);

            if (it == sesh_addrs.end()) {
                log::debug(logcat, "no sesh addr for oxen wallet {}", addr);
                item.zombie = true;
                item.contributor_not_registered_for_swap = true;
                break;
            }

            uint64_t sesh_required =
                    contributor.amount * staking_ratio.first / staking_ratio.second;
            if (extra_ratio)
                sesh_required = sesh_required * extra_ratio->first / extra_ratio->second;

            sesh_stake[it->second] += sesh_required;
            log::debug(logcat, "have {} from SESH {} for node {}", sesh_required, it->second, pk);
        }

        eth::address sn_op = crypto::null<eth::address>;

        // Make sure all the contributors have enough unallocated SESH to actually carry over the
        // stake; if any don't then the SN becomes a zombie to be deregistered.
        if (!item.zombie) {
            sn_op = sesh_addrs.at(sni->operator_address);

            // Our truncating integer divisions above will likely have slightly undercalculated some
            // of the staking requirements, so add the missing atomic amount to the operator
            // requirement
            uint64_t deficit = staking_requirement;
            for (const auto& [eth, reqd] : sesh_stake) {
                assert(reqd <= staking_requirement);
                deficit -= reqd;
            }
            if (deficit)
                sesh_stake[sn_op] += deficit;

            std::unordered_map<eth::address, uint64_t> allocated;
            for (const auto& [eth, reqd] : sesh_stake) {
                assert(unallocated.count(eth));
                if (unallocated[eth] - allocated[eth] < reqd) {
                    log::debug(
                            logcat,
                            "insufficient sesh from {}, have {} need {}",
                            eth,
                            unallocated[eth] - allocated[eth],
                            reqd);
                    item.zombie = true;
                    item.insufficient_sesh = true;
                    break;
                }
                allocated[eth] += reqd;
            }

            if (!item.zombie) {
                for (auto& [eth, amt] : allocated) {
                    unallocated[eth] -= amt;
                    log::debug(
                            logcat,
                            "allocated {} from SESH {} for node {}, new SESH balance {}",
                            amt,
                            eth,
                            pk,
                            unallocated[eth]);
                    item.tokens_allocated += amt;
                }
            }
        }

        // We're going to rewrite the service node info now *regardless* of whether it's a zombie or
        // not, but if a zombie we're deliberately writing data that will get it kicked out shortly
        // after the fork.
        item.sn_info = std::make_shared<service_nodes::service_node_info>(*sni);
        item.old_pkey = pk;
        auto& sn = *item.sn_info;

        if (!item.zombie) {
            auto& stakers = sn.contributors;
            stakers.clear();

            sn.total_contributed = staking_requirement;
            sn.total_reserved = staking_requirement;
            sn.staking_requirement = staking_requirement;

            // Insert the operator first, then after that we sort by stake size descending, and then
            // address to break ties of equal-stake stakers.
            {
                auto it = sesh_stake.find(sn_op);
                assert(it != sesh_stake.end());
                auto& stake = stakers.emplace_back();
                stake.ethereum_address = it->first;
                stake.ethereum_beneficiary = it->first;
                stake.amount = it->second;
                sn.operator_ethereum_address = it->first;
                sesh_stake.erase(it);
            }
            std::vector<std::pair<eth::address, uint64_t>> stakes_desc{
                    sesh_stake.begin(), sesh_stake.end()};
            std::sort(stakes_desc.begin(), stakes_desc.end(), [](auto& a, auto& b) {
                if (a.second != b.second)
                    return a.second > b.second;  // a comes first if the *value* is larger
                return a.first <
                       b.first;  // same value: a comes first if the *address* is "smaller"
            });
            for (const auto& [address, amount] : stakes_desc) {
                auto& stake = stakers.emplace_back();
                stake.ethereum_address = address;
                stake.ethereum_beneficiary = address;
                stake.amount = amount;
            }

            sn.bls_public_key =
                    node_bls_keys.at(remapped[pk]);  // operator [] and const being weird
            item.pkey = crypto::public_key{remapped[pk]};
        } else {
            // This SN is a zombie, i.e. its dying and will get deregged shortly after the fork.
            // We're leaving it technically registered, but just a husk: it has no contributors and
            // a 0 staking requirement/total.

            sn.total_contributed = 0;
            sn.total_reserved = 0;
            sn.staking_requirement = 0;
            sn.contributors.clear();

            // if we made it this far and the node has supplied a bls key, we set it so that until
            // the node is removed we can still at least try to request a bls signature from it,
            // as its bls key will be in the contract until it is removed.
            if (bls_ok)
                sn.bls_public_key = node_bls_keys.at(remapped[pk]);
            else
                sn.bls_public_key = crypto::null<eth::bls_public_key>;

            item.pkey = pk;
        }
    }

    // Any yet-unallocated SESH balance goes in the rewards db to be claimed
    // All OXEN rewards are wiped first, any unconverted are dropped (but were paid out last block
    // anyway).
    {
        sql.db.exec("DELETE FROM batched_payments_accrued");
        cryptonote::block_payments rewards_payments;
        for (const auto& [eth_addr, amt] : unallocated) {
            cryptonote::sql_payment payment = {};
            payment.amount = cryptonote::reward_money::coin_amount(amt);
            rewards_payments[eth_addr] = payment;
        }
        sql.add_sn_rewards(cryptonote::hf::hf21_eth, rewards_payments, /*rewards_payment=*/true);
    }

    // First, clear the old key image blacklist so we don't leave unconverted stakes locked
    // any longer than necessary (and can re-use the blacklist for perma-locks)
    //
    // Then *permanently* blacklist the key images of all converted stakes (but not
    // unconverted ones), so that you can't go back to the OXEN wallet and then convert
    // them through the external SESH conversion process.
    snl_state.key_image_blacklist.clear();
    for (const crypto::key_image& img : permanent_stakes) {
        auto& bl_entry = snl_state.key_image_blacklist.emplace_back();
        bl_entry.key_image = img;
    }

    if (snl_state.service_nodes_infos.size() != post_transition_sns.size())
        throw std::runtime_error{"post-transition should have same number of service_node_infos!"};

    if (context.dump_csv)
        dump_transition_outcome_csv(
                context,
                snl_state,
                net,
                post_transition_sns,
                final_allocation_before_distrib,
                unallocated);

    // When we collect stake metadata (like the individual contributions of a user, we store them
    // into the database and have a unique clause on the (block, tx, contribution index) which
    // prevents duplicates from being submitted.
    //
    // These are typically extracted from an individual smart contract event witnessed on Arbitrum
    // and they get inserted into a TX. For HF21 we initially bootstrap the amount of locked tokens
    // by a user by their participation in the $OXEN->$SESH migration. These locked amounts don't
    // have a transaction associated with them. The DB is written to directly, so to encode these
    // stakes we set a synthetic TX index which is guaranteed to not conflict with any other TXs in
    // the block itself.
    uint32_t synthetic_tx_index = static_cast<uint32_t>(block_tx_count);

    snl_state.service_nodes_infos.clear();
    for (auto& it : post_transition_sns) {
        // Record the stake metadata to the `block_add_result`. The SQL DB will process these when
        // it's update set is triggered
        for (size_t contrib_index = 0; contrib_index < it.sn_info->contributors.size();
             contrib_index++) {
            const auto& contrib = it.sn_info->contributors[contrib_index];
            assert(!it.zombie && "Contributors should only be populated on non-zombie nodes");
            assert(contrib.ethereum_address);
            assert(contrib.address == cryptonote::account_public_address{});
            auto& s = add_result.locked_stakes.emplace_back();
            s.sn = crypto::ed25519_public_key{it.pkey};
            s.addr = contrib.ethereum_address;
            s.amount = cryptonote::reward_money::coin_amount(contrib.amount);
            s.liquidation = cryptonote::reward_money{};
            s.block_height = static_cast<uint32_t>(snl_state.height);
            s.tx_index = synthetic_tx_index++;
            s.contributor_index = static_cast<uint32_t>(contrib_index);
        }

        // Update the SNL with the new SN details
        snl_state.service_nodes_infos[it.pkey] = std::move(it.sn_info);
    }
}

}  // namespace oxen::sesh
