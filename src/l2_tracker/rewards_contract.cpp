#include "rewards_contract.h"

#include <ethyl/utils.hpp>
#include <common/oxen.h>
#include <common/string_util.h>
#include <common/exception.h>

#include "crypto/crypto.h"
#include "cryptonote_config.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuseless-cast"
#include <nlohmann/json.hpp>
#pragma GCC diagnostic pop

#include "common/bigint.h"
#include "common/guts.h"
#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("l2_tracker");

TransactionType getLogType(const ethyl::LogEntry& log) {
    if (log.topics.empty()) {
        throw oxen::runtime_error("No topics in log entry");
    }
    // keccak256('NewServiceNode(uint64,address,(uint256,uint256),(uint256,uint256,uint256,uint16),(address,uint256)[])')
    if (log.topics[0] == "0xe82ed1bfc15e6602fba1a19273171c8a63c1d40b0e0117be4598167b8655498f") {
        return TransactionType::NewServiceNode;
        // keccak256('ServiceNodeRemovalRequest(uint64,address,(uint256,uint256))')
    } else if (
            log.topics[0] == "0x89477e9f4ddcb5eb9f30353ab22c31ef9a91ab33fd1ffef09aadb3458be7775d") {
        return TransactionType::ServiceNodeLeaveRequest;
        // keccak256('ServiceNodeRemoval(uint64,address,uint256,(uint256,uint256))')
    } else if (
            log.topics[0] == "0x130a7be04ef1f87b2b436f68f389bf863ee179b95399a3a8444196fab7a4e54c") {
        return TransactionType::ServiceNodeExit;
    }
    return TransactionType::Other;
}

using u256 = std::array<std::byte, 32>;
using tools::skip;
using tools::skip_t;

static std::string log_more_contributors_than_allowed(
        size_t num_contributors,
        size_t max_contributors,
        const crypto::bls_public_key& bls_pk,
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

static std::string log_new_service_node_tx(const NewServiceNodeTx& item, std::string_view hex) {
    fmt::memory_buffer buffer{};
    fmt::format_to(
            std::back_inserter(buffer),
            "New service node TX components were:\n"
            "- BLS Public Key:    {}\n"
            "- ETH Address:       {}\n"
            "- SN Public Key:     {}\n"
            "- ED25519 Signature: {}\n"
            "- Fee:               {}\n"
            "- Contributor(s):    {}\n",
            item.bls_pubkey,
            item.eth_address,
            item.sn_pubkey,
            item.ed_signature,
            item.fee,
            item.contributors.size());

    for (size_t index = 0; index < item.contributors.size(); index++) {
        const Contributor& contributor = item.contributors[index];
        fmt::format_to(std::back_inserter(buffer), "  - {:02} [address: {}, amount: {}]\n", index, contributor.addr, contributor.amount);
    }

    fmt::format_to(std::back_inserter(buffer), "\nThe raw blob was (32 byte chunks/line):\n\n", hex);
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

static std::string log_service_node_blob(const ContractServiceNode& result, std::string_view hex) {
    return "Service node blob components were:\n"
                "\n"
                "  - next:                   {}\n"
                "  - prev:                   {}\n"
                "  - operator:               {}\n"
                "  - pubkey:                 {}\n"
                "  - leaveRequestTimestamp:  {}\n"
                "  - deposit:                {}\n"
                "  - num contributors:       {}\n"
                "\n"
                "The raw blob was:\n\n{}"_format(
                result.next,
                result.prev,
                result.operatorAddr,
                result.pubkey,
                result.leaveRequestTimestamp,
                result.deposit,
                result.contributorsSize,
                hex);
}

TransactionStateChangeVariant getLogTransaction(const ethyl::LogEntry& log) {
    TransactionStateChangeVariant result;
    TransactionType type = getLogType(log);
    switch (type) {
        case TransactionType::NewServiceNode: {
            // event NewServiceNode(
            //      uint64 indexed serviceNodeID,
            //      address recipient,
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

            NewServiceNodeTx& item = result.emplace<NewServiceNodeTx>();

            u256 fee256, c_offset, c_len;
            std::string_view contrib_hex;
            std::tie(
                    item.eth_address,
                    item.bls_pubkey,
                    item.sn_pubkey,
                    item.ed_signature,
                    fee256,
                    c_offset,
                    c_len,
                    contrib_hex) =
                    tools::split_hex_into<
                            skip<12>,
                            crypto::eth_address,
                            crypto::bls_public_key,
                            crypto::public_key,
                            crypto::ed25519_signature,
                            u256,
                            u256,
                            u256,
                            std::string_view>(log.data);

            // NOTE: Decode fee and that it is within acceptable range
            item.fee = tools::decode_integer_be(fee256);
            if (item.fee > cryptonote::STAKING_FEE_BASIS)
                throw oxen::invalid_argument{
                    "Invalid NewServiceNode data: fee must be in [0, {}]"_format(cryptonote::STAKING_FEE_BASIS)};

            // NOTE: Verify that the number of contributors in the blob is
            // within maximum range
            uint64_t num_contributors = tools::decode_integer_be(c_len);
            if (num_contributors > oxen::MAX_CONTRIBUTORS_HF19) {
                throw oxen::invalid_argument("Invalid NewServiceNode data: {}\n{}"_format(
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
                throw oxen::invalid_argument(
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
                throw oxen::invalid_argument(
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
                throw oxen::invalid_argument{
                        "Invalid NewServiceNode data: The hex payload length ({}) derived for "
                        "{} contributors did not match the size we derived of {} hex characters\n{}"_format(
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
                std::tie(addr, amt256, contrib_hex) = tools::
                        split_hex_into<skip<12>, crypto::eth_address, u256, std::string_view>(
                                contrib_hex);
                amt = tools::decode_integer_be(amt256);
            }

            oxen::log::debug(logcat, "{}", log_new_service_node_tx(item, log.data));
            break;
        }
        case TransactionType::ServiceNodeLeaveRequest: {
            // event ServiceNodeRemovalRequest(
            //      uint64 indexed serviceNodeID,
            //      address recipient,
            //      BN256G1.G1Point pubkey);
            // service node id is a topic so only address and pubkey are in data
            // address is 32 bytes (with 12-byte prefix padding)
            // pubkey is 64 bytes,
            auto& [bls_pk] = result.emplace<ServiceNodeLeaveRequestTx>();
            std::tie(bls_pk) =
                    tools::split_hex_into<skip<12 + 20>, crypto::bls_public_key>(log.data);
            break;
        }
        case TransactionType::ServiceNodeDeregister: {
            // event ServiceNodeLiquidated(
            //      uint64 indexed serviceNodeID,
            //      address recipient,
            //      BN256G1.G1Point pubkey);
            // service node id is a topic so only address and pubkey are in data
            // address is 32 bytes (with 12-byte prefix padding)
            // pubkey is 64 bytes
            auto& [bls_pk] = result.emplace<ServiceNodeDeregisterTx>();
            std::tie(bls_pk) =
                    tools::split_hex_into<skip<12 + 20>, crypto::bls_public_key>(log.data);
            break;
        }
        case TransactionType::ServiceNodeExit: {
            // event ServiceNodeRemoval(
            //      uint64 indexed serviceNodeID,
            //      address recipient,
            //      uint256 returnedAmount,
            //      BN256G1.G1Point pubkey);
            // service node id is a topic so only address and pubkey are in data
            // address is 32 bytes (with 12-byte prefix padding)
            // pubkey is 64 bytes
            auto& [eth_addr, amount, bls_pk] = result.emplace<ServiceNodeExitTx>();
            u256 amt256;
            std::tie(eth_addr, amt256, bls_pk) = tools::split_hex_into<skip<12>, crypto::eth_address, u256, crypto::bls_public_key>(
                            log.data);
            amount = tools::decode_integer_be(amt256);
            break;
        }
        case TransactionType::Other:;
    }
    return result;
}

RewardsContract::RewardsContract(const std::string& _contractAddress, ethyl::Provider& _provider) :
        contractAddress(_contractAddress), provider(_provider) {}

StateResponse RewardsContract::State() {
    return State(provider.getLatestHeight());
}

StateResponse RewardsContract::State(uint64_t height) {
    std::string blockHash = provider.getContractStorageRoot(contractAddress, height);
    std::string_view bh{blockHash};
    if (bh.starts_with("0x"))
        bh.remove_prefix(2);
    return {height, tools::make_from_hex_guts<crypto::hash>(bh)};
}

std::vector<ethyl::LogEntry> RewardsContract::Logs(uint64_t height) {
    return provider.getLogs(height, contractAddress);
}

std::vector<crypto::bls_public_key> RewardsContract::getAllBLSPubkeys(uint64_t blockNumber) {
    // Get the sentinel node to start the iteration
    const uint64_t service_node_sentinel_id = 0;
    ContractServiceNode sentinelNode = serviceNodes(service_node_sentinel_id, blockNumber);
    uint64_t currentNodeId = sentinelNode.next;

    std::vector<crypto::bls_public_key> blsPublicKeys;

    // Iterate over the linked list of service nodes
    while (currentNodeId != service_node_sentinel_id) {
        ContractServiceNode serviceNode = serviceNodes(currentNodeId, blockNumber);
        blsPublicKeys.push_back(serviceNode.pubkey);
        currentNodeId = serviceNode.next;
    }

    return blsPublicKeys;
}

ContractServiceNode RewardsContract::serviceNodes(
        uint64_t index, std::optional<uint64_t> blockNumber) {
    ethyl::ReadCallData callData = {};
    std::string indexABI =
            ethyl::utils::padTo32Bytes(ethyl::utils::decimalToHex(index), ethyl::utils::PaddingDirection::LEFT);
    callData.contractAddress = contractAddress;
    callData.data = ethyl::utils::toEthFunctionSignature("serviceNodes(uint64)") + indexABI;
    // FIXME(OXEN11): we *cannot* make a blocking request here like this because we are blocking
    // some other thread from doing work; we either need to get this from a local cache of the info,
    // or make it asynchronous (i.e. with a completion/timeout callback), or both (i.e. try cache,
    // make request asynchronously if not found).
    //
    // FIXME(OXEN11): nor can we make recursive linked lists requests like this!
    std::string blockNumArg = blockNumber ? "0x{:x}"_format(*blockNumber) : "latest";
    nlohmann::json callResult = provider.callReadFunctionJSON(callData, blockNumArg);
    auto callResultHex = callResult.get<std::string_view>();

    // NOTE: The ServiceNode struct is a dynamic type (because its child `Contributor` field is
    // dynamic) hence the offset to the struct is encoded in the first 32 byte element.
    auto [sn_data_offset] = tools::split_hex_into<u256, tools::ignore>(callResultHex);
    auto sn_data = callResultHex.substr(tools::decode_integer_be(sn_data_offset));
    auto [next, prev, op_addr, pubkey, leaveRequestTimestamp, deposit, contr_offset] = tools::split_hex_into<
            u256,
            u256,
            skip<12>,
            crypto::eth_address,
            crypto::bls_public_key,
            u256,
            u256,
            u256,
            tools::ignore>(sn_data);

    ContractServiceNode result{};
    result.good = false; // until proven otherwise
    result.next = tools::decode_integer_be(next);
    result.prev = tools::decode_integer_be(prev);
    result.operatorAddr = op_addr;
    result.pubkey = pubkey;
    result.leaveRequestTimestamp = tools::decode_integer_be(leaveRequestTimestamp);
    result.deposit = tools::decode_integer_be(deposit);

    auto contrib_data = sn_data.substr(tools::decode_integer_be(contr_offset));
    auto [contrib_len] = tools::split_hex_into<u256, tools::ignore>(contrib_data);

    // NOTE: Start parsing the contributors blobs
    if (auto contributorSize = tools::decode_integer_be(contrib_len);contributorSize <= result.contributors.max_size())
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
        oxen::log::debug(logcat, "{}", log_service_node_blob(result, callResultHex));
        return result;
    }

    for (size_t i = 0; i < result.contributorsSize; i++) {
        try {
            auto& [addr, amount] = result.contributors[i];
            u256 amt;
            std::tie(addr, amt, contrib_data) = tools::split_hex_into<skip<12>, crypto::eth_address, u256, std::string_view>(contrib_data);
            amount = tools::decode_integer_be(amt);
        } catch (const std::exception& e) {
            oxen::log::error(
                    logcat,
                    "Failed to parse contributor/contribution [{}] for service node {} with BLS pubkey {} at height {}: {}",
                    i, index, result.pubkey,
                    blockNumber ? "{}"_format(*blockNumber) : "(latest)", e.what());
            oxen::log::debug(logcat, "{}", log_service_node_blob(result, callResultHex));
            return result;
        }
    }

    oxen::log::trace(
            logcat, "Successfully parsed new SN. {}", log_service_node_blob(result, callResultHex));

    result.good = true;
    return result;
}

std::vector<uint64_t> RewardsContract::getNonSigners(
        const std::unordered_set<crypto::bls_public_key>& bls_public_keys) {
    const uint64_t service_node_sentinel_id = 0;
    ContractServiceNode service_node_end = serviceNodes(service_node_sentinel_id);
    uint64_t service_node_id = service_node_end.next;
    std::vector<uint64_t> non_signers;

    while (service_node_id != service_node_sentinel_id) {
        ContractServiceNode service_node = serviceNodes(service_node_id);
        if (!bls_public_keys.count(service_node.pubkey))
            non_signers.push_back(service_node_id);
        service_node_id = service_node.next;
    }

    return non_signers;
}
