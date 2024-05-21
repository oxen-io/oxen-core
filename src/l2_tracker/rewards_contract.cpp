#include "rewards_contract.h"

#include <ethyl/utils.hpp>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wuseless-cast"
#include <nlohmann/json.hpp>
#pragma GCC diagnostic pop

#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("l2_tracker");

TransactionType RewardsLogEntry::getLogType() const {
    if (topics.empty()) {
        throw std::runtime_error("No topics in log entry");
    }
    // keccak256('NewServiceNode(uint64,address,(uint256,uint256),(uint256,uint256,uint256,uint16),(address,uint256)[])')
    if (topics[0] == "0xe82ed1bfc15e6602fba1a19273171c8a63c1d40b0e0117be4598167b8655498f") {
        return TransactionType::NewServiceNode;
        // keccak256('ServiceNodeRemovalRequest(uint64,address,(uint256,uint256))')
    } else if (topics[0] == "0x89477e9f4ddcb5eb9f30353ab22c31ef9a91ab33fd1ffef09aadb3458be7775d") {
        return TransactionType::ServiceNodeLeaveRequest;
        // keccak256('ServiceNodeRemoval(uint64,address,uint256,(uint256,uint256))')
    } else if (topics[0] == "0x130a7be04ef1f87b2b436f68f389bf863ee179b95399a3a8444196fab7a4e54c") {
        return TransactionType::ServiceNodeExit;
    }
    return TransactionType::Other;
}

std::optional<TransactionStateChangeVariant> RewardsLogEntry::getLogTransaction() const {
    TransactionType type = getLogType();
    switch (type) {
        case TransactionType::NewServiceNode: {
            // event NewServiceNode(uint64 indexed serviceNodeID, address recipient, BN256G1.G1Point
            // pubkey, uint256 serviceNodePubkey, uint256 serviceNodeSignature, uint16 fee,
            // Contributors[] contributors); service node id is a topic so only address, pubkeys,
            // signature, fee and contributors are in data address is 32 bytes , pubkey is 64 bytes
            // and serviceNodePubkey is 64 bytes
            //
            // The address is in 32 bytes, but actually only uses 20 bytes and the first 12 are
            // padding
            int pos = 2;  // Start after the 0x prefix
            std::string eth_address_str =
                    data.substr(pos + 24, 40);  // Skip 24 characters which are always blank
            crypto::eth_address eth_address;
            tools::hex_to_type(eth_address_str, eth_address);
            pos += 64;
            // pull 64 bytes (128 characters) for the BLS pubkey
            std::string bls_key_str = data.substr(pos, 128);
            crypto::bls_public_key bls_key;
            tools::hex_to_type(bls_key_str, bls_key);
            pos += 128;
            // pull 32 bytes (64 characters) ed pubkey
            std::string service_node_pubkey = data.substr(pos, 64);
            pos += 64;
            // pull 64 bytes (128 characters) for ed signature
            std::string signature = data.substr(pos, 128);
            pos += 128;
            // pull 32 bytes (64 characters) for fee
            std::string fee_str = data.substr(pos, 64);
            uint64_t fee = utils::fromHexStringToUint64(fee_str);
            pos += 64;
            // There are 32 bytes describing the size of contributors data here, ignore because we
            // always get the same data out of it
            pos += 64;
            // pull 32 bytes (64 characters) for the number of elements in the array
            std::vector<Contributor> contributors;
            std::string num_contributors_str = data.substr(pos, 64);

            uint64_t num_contributors = utils::fromHexStringToUint64(num_contributors_str);
            pos += 64;
            std::string contributor_address_str;
            std::string contributor_amount_str;
            for (uint64_t i = 0; i < num_contributors; ++i) {
                // Each loop iteration processes one contributor
                contributor_address_str = data.substr(pos + 24, 40);
                crypto::eth_address contributor_address;
                tools::hex_to_type(contributor_address_str, contributor_address);
                pos += 64;
                contributor_amount_str = data.substr(pos, 64);
                uint64_t contributor_amount = utils::fromHexStringToUint64(contributor_amount_str);
                pos += 64;
                contributors.emplace_back(contributor_address, contributor_amount);
            }

            return NewServiceNodeTx(
                    bls_key, eth_address, service_node_pubkey, signature, fee, contributors);
        }
        case TransactionType::ServiceNodeLeaveRequest: {
            // event ServiceNodeRemovalRequest(uint64 indexed serviceNodeID, address recipient,
            // BN256G1.G1Point pubkey); service node id is a topic so only address and pubkey are in
            // data address is 32 bytes and pubkey is 64 bytes,
            //
            // from position 64 (32 bytes -> 64 characters) + 2 for '0x' pull 64 bytes (128
            // characters)
            std::string bls_key_str = data.substr(64 + 2, 128);
            crypto::bls_public_key bls_key;
            tools::hex_to_type(bls_key_str, bls_key);
            return ServiceNodeLeaveRequestTx(bls_key);
        }
        case TransactionType::ServiceNodeDeregister: {
            // event ServiceNodeLiquidated(uint64 indexed serviceNodeID, address recipient,
            // BN256G1.G1Point pubkey); service node id is a topic so only address and pubkey are in
            // data address is 32 bytes and pubkey is 64 bytes,
            //
            // from position 64 (32 bytes -> 64 characters) + 2 for '0x' pull 64 bytes (128
            // characters)
            std::string bls_key_str = data.substr(64 + 2, 128);
            crypto::bls_public_key bls_key;
            tools::hex_to_type(bls_key_str, bls_key);
            return ServiceNodeDeregisterTx(bls_key);
        }
        case TransactionType::ServiceNodeExit: {
            // event ServiceNodeRemoval(uint64 indexed serviceNodeID, address recipient, uint256
            // returnedAmount, BN256G1.G1Point pubkey); address is 32 bytes, amount is 32 bytes and
            // pubkey is 64 bytes
            //
            // The address is in 32 bytes, but actually only uses 20 bytes and the first 12 are
            // padding
            std::string eth_address_str = data.substr(2 + 24, 40);
            crypto::eth_address eth_address;
            tools::hex_to_type(eth_address_str, eth_address);
            // from position 64 (32 bytes -> 64 characters) + 2 for '0x' pull 32 bytes (64
            // characters)
            std::string amount_str = data.substr(64 + 2, 64);
            uint64_t amount = utils::fromHexStringToUint64(amount_str);
            // pull 64 bytes (128 characters)
            std::string bls_key_str = data.substr(64 + 64 + 2, 128);
            crypto::bls_public_key bls_key;
            tools::hex_to_type(bls_key_str, bls_key);
            return ServiceNodeExitTx(eth_address, amount, bls_key);
        }
        default: return std::nullopt;
    }
}

RewardsContract::RewardsContract(
        const std::string& _contractAddress, std::shared_ptr<Provider> _provider) :
        contractAddress(_contractAddress), provider(std::move(_provider)) {}

StateResponse RewardsContract::State() {
    return State(provider->getLatestHeight());
}

StateResponse RewardsContract::State(uint64_t height) {
    std::string blockHash = provider->getContractStorageRoot(contractAddress, height);
    // Check if blockHash starts with "0x" and remove it
    if (blockHash.size() >= 2 && blockHash[0] == '0' && blockHash[1] == 'x') {
        blockHash = blockHash.substr(2);  // Skip the first two characters
    }
    return StateResponse{height, blockHash};
}

std::vector<RewardsLogEntry> RewardsContract::Logs(uint64_t height) {
    std::vector<RewardsLogEntry> logEntries;
    // Make the RPC call
    const auto logs = provider->getLogs(height, contractAddress);

    for (const auto& log : logs) {
        logEntries.emplace_back(RewardsLogEntry(log));
    }

    return logEntries;
}

std::vector<std::string> RewardsContract::getAllBLSPubkeys(uint64_t blockNumber) {
    std::stringstream stream;
    stream << "0x" << std::hex << blockNumber;
    std::string blockNumberHex = stream.str();

    // Get the sentinel node to start the iteration
    const uint64_t service_node_sentinel_id = 0;
    ContractServiceNode sentinelNode = serviceNodes(service_node_sentinel_id, blockNumberHex);
    uint64_t currentNodeId = sentinelNode.next;

    std::vector<std::string> blsPublicKeys;

    // Iterate over the linked list of service nodes
    while (currentNodeId != service_node_sentinel_id) {
        ContractServiceNode serviceNode = serviceNodes(currentNodeId, blockNumberHex);
        blsPublicKeys.push_back(serviceNode.pubkey);
        currentNodeId = serviceNode.next;
    }

    return blsPublicKeys;
}

ContractServiceNode RewardsContract::serviceNodes(uint64_t index, std::string_view blockNumber)
{
    ReadCallData callData            = {};
    std::string  indexABI            = utils::padTo32Bytes(utils::decimalToHex(index), utils::PaddingDirection::LEFT);
    callData.contractAddress         = contractAddress;
    callData.data                    = utils::getFunctionSignature("serviceNodes(uint64)") + indexABI;
    nlohmann::json     callResult    = provider->callReadFunctionJSON(callData, blockNumber);
    const std::string& callResultHex = callResult.get_ref<nlohmann::json::string_t&>();
    std::string_view   callResultIt  = utils::trimPrefix(callResultHex, "0x");

    const size_t        U256_HEX_SIZE                  = (256 / 8) * 2;
    const size_t        BLS_PKEY_XY_COMPONENT_HEX_SIZE = 32 * 2;
    const size_t        BLS_PKEY_HEX_SIZE              = BLS_PKEY_XY_COMPONENT_HEX_SIZE + BLS_PKEY_XY_COMPONENT_HEX_SIZE;
    const size_t        ADDRESS_HEX_SIZE               = 32 * 2;

    ContractServiceNode result                   = {};
    size_t              walkIt                   = 0;
    std::string_view    totalSize                = callResultIt.substr(walkIt, U256_HEX_SIZE);     walkIt += totalSize.size();
    std::string_view    nextHex                  = callResultIt.substr(walkIt, U256_HEX_SIZE);     walkIt += nextHex.size();
    std::string_view    prevHex                  = callResultIt.substr(walkIt, U256_HEX_SIZE);     walkIt += prevHex.size();
    std::string_view    recipientHex             = callResultIt.substr(walkIt, ADDRESS_HEX_SIZE);  walkIt += recipientHex.size();
    std::string_view    pubkeyHex                = callResultIt.substr(walkIt, BLS_PKEY_HEX_SIZE); walkIt += pubkeyHex.size();
    std::string_view    leaveRequestTimestampHex = callResultIt.substr(walkIt, U256_HEX_SIZE);     walkIt += leaveRequestTimestampHex.size();
    std::string_view    depositHex               = callResultIt.substr(walkIt, U256_HEX_SIZE);     walkIt += depositHex.size();
    assert(walkIt == callResultIt.size());

    // NOTE: Deserialize linked list
    result.next                = utils::fromHexStringToUint64(nextHex);
    result.prev                = utils::fromHexStringToUint64(prevHex);

    // NOTE: Deserialise recipient
    const size_t ETH_ADDRESS_HEX_SIZE = 20 * 2;
    std::vector<unsigned char> recipientBytes = utils::fromHexString(recipientHex.substr(recipientHex.size() - ETH_ADDRESS_HEX_SIZE, ETH_ADDRESS_HEX_SIZE));
    assert(recipientBytes.size() == result.recipient.max_size());
    std::memcpy(result.recipient.data(), recipientBytes.data(), recipientBytes.size());

    result.pubkey = std::string(pubkeyHex);

    // NOTE: Deserialise metadata
    result.leaveRequestTimestamp = utils::fromHexStringToUint64(leaveRequestTimestampHex);
    result.deposit               = depositHex;
    return result;
}

std::vector<uint64_t> RewardsContract::getNonSigners(const std::vector<std::string>& bls_public_keys) {
    const uint64_t service_node_sentinel_id = 0;
    ContractServiceNode service_node_end = serviceNodes(service_node_sentinel_id);
    uint64_t service_node_id = service_node_end.next;
    std::vector<uint64_t> non_signers;
    
    while (service_node_id != service_node_sentinel_id) {
        ContractServiceNode service_node = serviceNodes(service_node_id);
        if (std::find(bls_public_keys.begin(), bls_public_keys.end(), service_node.pubkey) == bls_public_keys.end()) {
            non_signers.push_back(service_node_id);
        }
        service_node_id = service_node.next;
    }

    return non_signers;
}
