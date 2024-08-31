#include "rewards_contract.h"

#include <ethyl/utils.hpp>

#include "common/bigint.h"
#include "common/guts.h"
#include "common/string_util.h"
#include "contracts.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "cryptonote_config.h"
#include "logging/oxen_logger.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuseless-cast"
#include <nlohmann/json.hpp>
#pragma GCC diagnostic pop

namespace eth {

namespace {
    auto logcat = oxen::log::Cat("l2_tracker");

    enum class EventType {
        NewServiceNode,
        ServiceNodeRemovalRequest,
        ServiceNodeRemoval,
        StakingRequirementUpdated,
        Other
    };

    EventType get_log_type(const ethyl::LogEntry& log) {
        if (log.topics.empty())
            throw std::runtime_error("No topics in log entry");

        auto event_sig = tools::make_from_hex_guts<crypto::hash>(log.topics[0]);

        return event_sig == contract::event::NewServiceNode ? EventType::NewServiceNode
             : event_sig == contract::event::ServiceNodeRemovalRequest
                     ? EventType::ServiceNodeRemovalRequest
             : event_sig == contract::event::ServiceNodeRemoval ? EventType::ServiceNodeRemoval
                                                                : EventType::Other;
    }

}  // namespace

using u256 = std::array<std::byte, 32>;
using tools::skip;
using tools::skip_t;

static std::string log_more_contributors_than_allowed(
        size_t num_contributors,
        size_t max_contributors,
        const bls_public_key& bls_pk,
        std::optional<uint64_t> block_number,
        std::optional<uint64_t> sn_index) {
    std::string result;

    if (sn_index) {
        result = "The number of contributors ({}) in the service node blob exceeded the available "
                 "storage ({}) for service node ({}) w/ BLS public key {} at height {}"_format(
                         num_contributors,
                         max_contributors,
                         *sn_index,
                         bls_pk,
                         block_number ? "{}"_format(*block_number) : "(latest)");
    } else {
        result = "The number of contributors ({}) in the service node blob exceeded the available "
                 "storage ({}) for service node w/ BLS public key {} at height {}"_format(
                         num_contributors,
                         max_contributors,
                         bls_pk,
                         block_number ? "{}"_format(*block_number) : "(latest)");
    }
    return result;
}

static std::string log_new_service_node_tx(
        const event::NewServiceNode& item, std::string_view hex) {
    fmt::memory_buffer buffer{};
    fmt::format_to(
            std::back_inserter(buffer),
            "New service node TX components were:\n"
            "- SN Public Key:     {}\n"
            "- BLS Public Key:    {}\n"
            "- ED25519 Signature: {}\n"
            "- Fee:               {}\n"
            "- Contributor(s):    {}\n",
            item.sn_pubkey,
            item.bls_pubkey,
            item.ed_signature,
            item.fee,
            item.contributors.size());

    for (size_t index = 0; index < item.contributors.size(); index++) {
        const auto& contributor = item.contributors[index];
        fmt::format_to(
                std::back_inserter(buffer),
                "  - {:02} [address: {}, amount: {}]\n",
                index,
                contributor.address,
                contributor.amount);
    }

    fmt::format_to(std::back_inserter(buffer), "\nThe raw blob was (32 byte chunks/line):\n\n");
    std::string_view it = hex;
    if (it.starts_with("0x") || it.starts_with("0X"))
        it.remove_prefix(2);

    while (it.size()) {
        std::string_view chunk = tools::string_safe_substr(it, 0, 64);  // Grab 32 byte chunk
        fmt::format_to(std::back_inserter(buffer), "  {}\n", chunk);    // Output the chunk
        it = tools::string_safe_substr(it, 64, it.size());              // Advance the it
    }

    std::string result = fmt::to_string(buffer);
    return result;
}

static std::string log_service_node_blob(const ContractServiceNode& blob, std::string_view hex) {
    fmt::memory_buffer buffer{};
    fmt::format_to(
            std::back_inserter(buffer),
            "Service node blob components were:\n"
            "\n"
            "  - next:                   {}\n"
            "  - prev:                   {}\n"
            "  - operator:               {}\n"
            "  - pubkey:                 {}\n"
            "  - leaveRequestTimestamp:  {}\n"
            "  - deposit:                {}\n"
            "  - num contributors:       {}\n"
            "\n"
            "The raw blob was (32 byte chunks/line):\n\n",
            blob.next,
            blob.prev,
            blob.operatorAddr,
            blob.pubkey,
            blob.leaveRequestTimestamp,
            blob.deposit,
            blob.contributorsSize);

    std::string_view it = hex;
    if (it.starts_with("0x") || it.starts_with("0X"))
        it.remove_prefix(2);

    while (it.size()) {
        std::string_view chunk = tools::string_safe_substr(it, 0, 64);  // Grab 32 byte chunk
        fmt::format_to(std::back_inserter(buffer), "  {}\n", chunk);    // Output the chunk
        it = tools::string_safe_substr(it, 64, it.size());              // Advance the it
    }

    std::string result = fmt::to_string(buffer);
    return result;
}

event::StateChangeVariant get_log_event(const uint64_t chain_id, const ethyl::LogEntry& log) {
    event::StateChangeVariant result;
    const uint64_t l2_height = log.blockNumber.value_or(0);
    if (l2_height == 0) {
        log::warning(logcat, "Received L2 event without a block number; ignoring");
        return result;
    }

    switch (get_log_type(log)) {
        case EventType::NewServiceNode: {
            // event NewServiceNode(
            //      uint64 indexed serviceNodeID,
            //      address initiator,
            //      { // struct ServiceNodeParams
            //          BN256G1.G1Point pubkey,
            //          uint256 serviceNodePubkey,
            //          (uint256,uint256) serviceNodeSignature,
            //          uint256 fee,
            //      },
            //      Contributors[] contributors);
            //
            // Note:
            // - address is 32 bytes, the first 12 of which are padding
            // - fee is between 0 and 10000, despite being packed into a gigantic 256-bit int.

            auto& item = result.emplace<event::NewServiceNode>(chain_id, l2_height);

            u256 fee256, c_offset, c_len;
            std::string_view contrib_hex;
            std::tie(
                    item.bls_pubkey,
                    item.sn_pubkey,
                    item.ed_signature,
                    fee256,
                    c_offset,
                    c_len,
                    contrib_hex) =
                    tools::split_hex_into<
                            skip<12 + 20>,
                            bls_public_key,
                            crypto::public_key,
                            crypto::ed25519_signature,
                            u256,
                            u256,
                            u256,
                            std::string_view>(log.data);

            // NOTE: Decode fee and that it is within acceptable range
            item.fee = tools::decode_integer_be(fee256);
            if (item.fee > cryptonote::STAKING_FEE_BASIS)
                throw oxen::traced<std::invalid_argument>{
                        "Invalid NewServiceNode data: fee must be in [0, {}]"_format(
                                cryptonote::STAKING_FEE_BASIS)};

            // NOTE: Verify that the number of contributors in the blob is
            // within maximum range
            uint64_t num_contributors = tools::decode_integer_be(c_len);
            if (num_contributors > oxen::MAX_CONTRIBUTORS_HF19) {
                throw oxen::traced<std::invalid_argument>(
                        "Invalid NewServiceNode data: {}\n{}"_format(
                                log_more_contributors_than_allowed(
                                        num_contributors,
                                        oxen::MAX_CONTRIBUTORS_HF19,
                                        item.bls_pubkey,
                                        log.blockNumber,
                                        /*index*/ std::optional<uint64_t>()),
                                log_new_service_node_tx(item, log.data)));
            }

            // NOTE: Verify that there's atleast one contributor
            if (num_contributors <= 0) {
                throw oxen::traced<std::invalid_argument>(
                        "Invalid NewServiceNode data: There must be atleast one contributor, "
                        "received 0\n{}"
                        ""_format(log_new_service_node_tx(item, log.data)));
            }
            item.contributors.reserve(num_contributors);

            // NOTE: Verify that the offset to the dynamic part of the
            // contributors array is correct.
            const uint64_t c_offset_value = tools::decode_integer_be(c_offset);
            const uint64_t expected_c_offset_value = 32 /*ID*/ + 32 /*recipient*/ + 64 /*BLS Key*/ +
                                                     32 /*SN Key*/ + 64 /*SN Sig*/ + 32 /*Fee*/;
            if (c_offset_value != expected_c_offset_value) {
                throw oxen::traced<std::invalid_argument>(
                        "Invalid NewServiceNode data: The offset to the contributor payload ({} "
                        "bytes) did not match the offset we derived {}\n{}"
                        ""_format(
                                c_offset_value,
                                expected_c_offset_value,
                                log_new_service_node_tx(item, log.data)));
            }

            // NOTE: Verify the length of the contributor blob
            const size_t expected_contrib_hex_size =
                    2 /*hex*/ * num_contributors * (/*address*/ 32 + /*amount*/ 32);
            if (contrib_hex.size() != expected_contrib_hex_size) {
                throw oxen::traced<std::invalid_argument>{
                        "Invalid NewServiceNode data: The hex payload length ({}) derived for "
                        "{} contributors did not match the size we derived of {} hex characters\n"
                        "{}"_format(
                                contrib_hex.size(),
                                num_contributors,
                                expected_contrib_hex_size,
                                log_new_service_node_tx(item, log.data))};
            }

            // TODO: Validate the amount, can't be 0, should be min contribution. Is this done in
            // the SNL? Maybe.
            for (size_t index = 0; index < num_contributors; index++) {
                auto& [addr, amt] = item.contributors.emplace_back();
                u256 amt256;
                std::tie(addr, amt256, contrib_hex) =
                        tools::split_hex_into<skip<12>, eth::address, u256, std::string_view>(
                                contrib_hex);
                amt = tools::decode_integer_be(amt256);
            }

            oxen::log::debug(logcat, "{}", log_new_service_node_tx(item, log.data));
            break;
        }
        case EventType::ServiceNodeRemovalRequest: {
            // event ServiceNodeRemovalRequest(
            //      uint64 indexed serviceNodeID,
            //      address contributor,
            //      BN256G1.G1Point pubkey);
            // service node id is a topic so only address and pubkey are in data
            // address is 32 bytes (with 12-byte prefix padding)
            // pubkey is 64 bytes,
            auto& item = result.emplace<event::ServiceNodeRemovalRequest>(chain_id, l2_height);
            std::tie(item.bls_pubkey) =
                    tools::split_hex_into<skip<12 + 20>, bls_public_key>(log.data);
            break;
        }
        case EventType::ServiceNodeRemoval: {
            // event ServiceNodeRemoval(
            //      uint64 indexed serviceNodeID,
            //      address operator,
            //      uint256 returnedAmount,
            //      BN256G1.G1Point pubkey);
            // service node id is a topic so only address and pubkey are in data
            // address is 32 bytes (with 12-byte prefix padding)
            // pubkey is 64 bytes
            auto& item = result.emplace<event::ServiceNodeRemoval>(chain_id, l2_height);
            u256 amt256;
            std::tie(amt256, item.bls_pubkey) =
                    tools::split_hex_into<skip<12 + 20>, u256, bls_public_key>(log.data);
            item.returned_amount = tools::decode_integer_be(amt256);
            break;
        }
        case EventType::StakingRequirementUpdated: {
            // event StakingRequirementUpdated(uint256 newRequirement);

            auto& item = result.emplace<event::StakingRequirementUpdated>(chain_id, l2_height);
            auto [amt256] = tools::split_hex_into<u256>(log.data);
            item.staking_requirement = tools::decode_integer_be(amt256);
            break;
        }
        case EventType::Other: break;
    }
    return result;
}

RewardsContract::RewardsContract(cryptonote::network_type nettype, ethyl::Provider& provider) :
        contract_address{contract::rewards_address(nettype)}, provider{provider} {}

std::vector<bls_public_key> RewardsContract::get_all_bls_pubkeys(uint64_t blockNumber) {
    // Get the sentinel node to start the iteration
    const uint64_t service_node_sentinel_id = 0;
    ContractServiceNode sentinel_node = service_nodes(service_node_sentinel_id, blockNumber);
    uint64_t currentNodeId = sentinel_node.next;

    std::vector<bls_public_key> result;

    // Iterate over the linked list of service nodes
    while (currentNodeId != service_node_sentinel_id) {
        ContractServiceNode service_node = service_nodes(currentNodeId, blockNumber);
        if (!service_node.good)
            break;
        result.push_back(service_node.pubkey);
        currentNodeId = service_node.next;
    }

    return result;
}

RewardsContract::ServiceNodeIDs RewardsContract::all_service_node_ids(
        std::optional<uint64_t> height) {
    std::string call_data = "0x{:x}"_format(contract::call::ServiceNodeRewards_allServiceNodeIDs);
    std::string block_num_arg = height ? "0x{:x}"_format(*height) : "latest";
    nlohmann::json call_result =
            provider.callReadFunctionJSON(contract_address, call_data, block_num_arg);

    auto call_result_hex = call_result.get<std::string_view>();
    if (call_result_hex.starts_with("0x") || call_result_hex.starts_with("0X"))
        call_result_hex.remove_prefix(2);

    // NOTE: Extract the ID payload
    ServiceNodeIDs result = {};
    const auto [offset_to_ids_bytes, offset_to_keys_bytes, _unused] =
            tools::split_hex_into<u256, u256, std::string_view>(call_result_hex);
    const uint64_t offset_to_ids = tools::decode_integer_be(offset_to_ids_bytes);
    const uint64_t offset_to_keys = tools::decode_integer_be(offset_to_keys_bytes);

    std::string_view ids_start_hex =
            tools::string_safe_substr(call_result_hex, offset_to_ids * 2, call_result_hex.size());
    auto [num_ids_bytes, ids_remainder_hex] =
            tools::split_hex_into<u256, std::string_view>(ids_start_hex);
    uint64_t num_ids = tools::decode_integer_be(num_ids_bytes);

    const size_t ID_SIZE_IN_HEX = sizeof(u256) * 2;
    std::string_view ids_payload =
            tools::string_safe_substr(ids_remainder_hex, 0, num_ids * ID_SIZE_IN_HEX);

    // NOTE: Extract the keys payload
    std::string_view keys_start_hex =
            tools::string_safe_substr(call_result_hex, offset_to_keys * 2, call_result_hex.size());
    auto [num_keys_bytes, keys_remainder_hex] =
            tools::split_hex_into<u256, std::string_view>(keys_start_hex);
    uint64_t num_keys = tools::decode_integer_be(num_keys_bytes);

    const size_t KEY_SIZE_IN_HEX = sizeof(bls_public_key) * 2;
    std::string_view keys_payload =
            tools::string_safe_substr(keys_remainder_hex, 0, num_keys * KEY_SIZE_IN_HEX);

    // NOTE: Validate args
    if (num_keys != num_ids) {
        oxen::log::warning(
                logcat,
                "The number of ids ({}) and bls public keys ({}) returned do not match at block "
                "'{}'",
                num_ids,
                num_keys,
                block_num_arg);
        return result;
    }

    if (ids_payload.size() != (num_ids * ID_SIZE_IN_HEX)) {
        oxen::log::warning(
                logcat,
                "The number of ids ({}) specified when retrieving all SN BLS ids did not "
                "match the size ({} bytes) of the payload returned at block '{}'",
                num_ids,
                ids_payload.size() / 2,
                block_num_arg);
        return result;
    }

    if (keys_payload.size() != (num_keys * KEY_SIZE_IN_HEX)) {
        oxen::log::warning(
                logcat,
                "The number of keys ({}) specified when retrieving all SN BLS pubkeys did not "
                "match the size ({} bytes) of the payload returned at block '{}'",
                num_keys,
                keys_payload.size() / 2,
                block_num_arg);
        return result;
    }

    result.ids.reserve(num_ids);
    result.bls_pubkeys.reserve(num_keys);
    for (size_t index = 0; index < num_ids; index++) {
        std::string_view id_hex =
                tools::string_safe_substr(ids_payload, (index * ID_SIZE_IN_HEX), ID_SIZE_IN_HEX);
        std::string_view key_hex =
                tools::string_safe_substr(keys_payload, (index * KEY_SIZE_IN_HEX), KEY_SIZE_IN_HEX);
        auto [id_bytes] = tools::split_hex_into<u256>(id_hex);
        result.ids.push_back(tools::decode_integer_be(id_bytes));
        result.bls_pubkeys.push_back(tools::make_from_hex_guts<bls_public_key>(key_hex));

#if !defined(NDEBUG)
        log::trace(
                logcat, "  {:02d} {{{}, {}}}", index, result.ids.back(), result.bls_pubkeys.back());
#endif
    }

    return result;
}

ContractServiceNode RewardsContract::service_nodes(
        uint64_t index, std::optional<uint64_t> blockNumber) {
    auto call_data = "0x{:x}{:064x}"_format(contract::call::ServiceNodeRewards_serviceNodes, index);

    // FIXME(OXEN11): we *cannot* make a blocking request here like this because we are blocking
    // some other thread from doing work; we either need to get this from a local cache of the info,
    // or make it asynchronous (i.e. with a completion/timeout callback), or both (i.e. try cache,
    // make request asynchronously if not found).
    //
    // FIXME(OXEN11): nor can we make recursive linked lists requests like this!
    std::string block_num_arg = blockNumber ? "0x{:x}"_format(*blockNumber) : "latest";
    nlohmann::json callResult =
            provider.callReadFunctionJSON(contract_address, call_data, block_num_arg);
    auto call_result_hex = callResult.get<std::string_view>();
    if (call_result_hex.starts_with("0x") || call_result_hex.starts_with("0X"))
        call_result_hex.remove_prefix(2);

    ContractServiceNode result{};
    result.good = false;  // until proven otherwise
    if (call_result_hex.empty()) {
        oxen::log::warning(
                logcat,
                "Provider returned an empty string when querying contract service node {} at block "
                "'{}'",
                index,
                block_num_arg);
        return result;
    }

    // NOTE: The ServiceNode struct is a dynamic type (because its child `Contributor` field is
    // dynamic) hence the offset to the struct is encoded in the first 32 byte element.
    std::string_view sn_data_offset_hex =
            tools::string_safe_substr(call_result_hex, /*pos*/ 0, /*size*/ 64);
    auto sn_data_offset_bytes = tools::make_from_hex_guts<u256>(sn_data_offset_hex);
    auto sn_data = call_result_hex.substr(tools::decode_integer_be(sn_data_offset_bytes) * 2);
    auto [next,
          prev,
          op_addr,
          pubkey,
          added_timestamp,
          leave_request_timestamp,
          deposit,
          contr_offset,
          remainder] =
            tools::split_hex_into<
                    u256,
                    u256,
                    skip<12>,
                    eth::address,
                    eth::bls_public_key,
                    u256,
                    u256,
                    u256,
                    u256,
                    std::string_view>(sn_data);

    result.next = tools::decode_integer_be(next);
    result.prev = tools::decode_integer_be(prev);
    result.operatorAddr = op_addr;
    result.pubkey = pubkey;
    result.addedTimestamp = tools::decode_integer_be(added_timestamp);
    result.leaveRequestTimestamp = tools::decode_integer_be(leave_request_timestamp);
    result.deposit = tools::decode_integer_be(deposit);

    auto contrib_data = sn_data.substr(tools::decode_integer_be(contr_offset) * 2);
    auto [contrib_len, remainder2] = tools::split_hex_into<u256, std::string_view>(contrib_data);

    // NOTE: Set the contrib_data to point to directly after the 32 byte
    // contrib_len field (e.g. the payload of the contrib_data).
    contrib_data = remainder2;

    // NOTE: Start parsing the contributors blobs
    if (auto contributorSize = tools::decode_integer_be(contrib_len);
        contributorSize <= result.contributors.max_size())
        result.contributorsSize = contributorSize;
    else {
        oxen::log::error(
                logcat,
                "{}",
                log_more_contributors_than_allowed(
                        contributorSize,
                        result.contributors.max_size(),
                        result.pubkey,
                        blockNumber,
                        index));
        oxen::log::debug(logcat, "{}", log_service_node_blob(result, call_result_hex));
        return result;
    }

    for (size_t i = 0; i < result.contributorsSize; i++) {
        try {
            auto& [addr, amount] = result.contributors[i];
            u256 amt;
            std::tie(addr, amt, contrib_data) =
                    tools::split_hex_into<skip<12>, eth::address, u256, std::string_view>(
                            contrib_data);
            amount = tools::decode_integer_be(amt);
        } catch (const std::exception& e) {
            oxen::log::error(
                    logcat,
                    "Failed to parse contributor/contribution [{}] for service node {} with BLS "
                    "pubkey {} at height {}: {}",
                    i,
                    index,
                    result.pubkey,
                    blockNumber ? "{}"_format(*blockNumber) : "(latest)",
                    e.what());
            oxen::log::debug(logcat, "{}", log_service_node_blob(result, call_result_hex));
            return result;
        }
    }

#ifndef NDEBUG
    oxen::log::trace(
            logcat,
            "Successfully parsed new SN. {}",
            log_service_node_blob(result, call_result_hex));
#endif

    result.good = true;
    return result;
}

std::vector<uint64_t> RewardsContract::get_non_signers(
        const std::unordered_set<bls_public_key>& bls_public_keys) {

    std::vector<uint64_t> result;
    ServiceNodeIDs contract_ids = all_service_node_ids();
    assert(contract_ids.ids.size() == contract_ids.bls_pubkeys.size());
    for (size_t index = 0; index < contract_ids.ids.size(); index++) {
        const bls_public_key& key = contract_ids.bls_pubkeys[index];
        if (!bls_public_keys.count(key)) {
            uint64_t id = contract_ids.ids[index];
            result.push_back(id);
        }
    }

    return result;
}

}  // namespace eth
