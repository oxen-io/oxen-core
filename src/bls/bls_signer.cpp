#include "bls_signer.h"

#include <epee/memwipe.h>
#include <fmt/core.h>
#include <oxenc/hex.h>

#include <ethyl/utils.hpp>

#include "bls_utils.h"
#include "common/file.h"
#include "common/string_util.h"
#include "logging/oxen_logger.h"

static auto logcat = oxen::log::Cat("bls_signer");

BLSSigner::BLSSigner(const cryptonote::network_type nettype, const fs::path& key_filepath) {
    initCurve();
    const auto config = get_config(nettype);
    chainID = config.ETHEREUM_CHAIN_ID;
    contractAddress = config.ETHEREUM_REWARDS_CONTRACT;

    // NOTE: ioMode is taken from bls::SecretKey operator<< implementation
    int blsIoMode = 16 | bls::IoPrefix;
    if (fs::exists(key_filepath)) {
        oxen::log::info(logcat, "Loading bls key from: {}", key_filepath.string());

        std::string key_bytes;
        bool r = tools::slurp_file(key_filepath, key_bytes);
        secretKey.setStr(key_bytes, blsIoMode);
        memwipe(key_bytes.data(), key_bytes.size());
        if (!r)
            throw std::runtime_error(
                    fmt::format("Failed to read BLS key at: {}", key_filepath.string()));
    } else {
        // This init function generates a secret key calling blsSecretKeySetByCSPRNG
        secretKey.init();
        oxen::log::info(logcat, "No bls key found, saving new key to: {}", key_filepath.string());

        bool r = tools::dump_file(key_filepath, secretKey.getStr(blsIoMode));
        if (!r)
            throw std::runtime_error(
                    fmt::format("Failed to write BLS key to: {}", key_filepath.string()));
    }
}

void BLSSigner::initCurve() {
    // Initialize parameters for BN256 curve, this has a different name in our library
    bls::init(mclBn_CurveSNARK1);
    // Try and Inc method for hashing to the curve
    mclBn_setMapToMode(MCL_MAP_TO_MODE_TRY_AND_INC);
    // Our generator point was created using the old hash to curve method, redo it again using Try
    // and Inc method
    mcl::bn::G1 gen;
    bool b;
    mcl::bn::mapToG1(&b, gen, 1);

    blsPublicKey publicKey;
    static_assert(
            sizeof(publicKey.v) == sizeof(gen),
            "We memcpy into a C structure hence sizes must be the same");
    std::memcpy(&publicKey.v, &gen, sizeof(gen));

    blsSetGeneratorOfPublicKey(&publicKey);
}

std::string BLSSigner::buildTag(
        std::string_view baseTag, uint32_t chainID, std::string_view contractAddress) {
    std::string_view hexPrefix = "0x";
    std::string_view contractAddressOutput = utils::trimPrefix(contractAddress, hexPrefix);
    std::string baseTagHex = utils::toHexString(baseTag);
    std::string chainIDHex =
            utils::padTo32Bytes(utils::decimalToHex(chainID), utils::PaddingDirection::LEFT);

    std::string concatenatedTag;
    concatenatedTag.reserve(
            hexPrefix.size() + baseTagHex.size() + chainIDHex.size() +
            contractAddressOutput.size());
    concatenatedTag.append(hexPrefix);
    concatenatedTag.append(baseTagHex);
    concatenatedTag.append(chainIDHex);
    concatenatedTag.append(contractAddressOutput);

    std::array<unsigned char, 32> hash = utils::hash(concatenatedTag);
    std::string result = utils::toHexString(hash);
    return result;
}

std::string BLSSigner::buildTag(std::string_view baseTag) {
    return buildTag(baseTag, chainID, contractAddress);
}

bls::Signature BLSSigner::signHash(const crypto::bytes<32>& hash) {
    bls::Signature sig;
    secretKey.signHash(sig, hash.data(), hash.size());
    return sig;
}

std::string BLSSigner::proofOfPossession(
        std::string_view senderEthAddress, std::string_view serviceNodePubkey) {
    std::string fullTag = buildTag(proofOfPossessionTag, chainID, contractAddress);
    std::string_view hexPrefix = "0x";
    std::string_view senderAddressOutput = utils::trimPrefix(senderEthAddress, hexPrefix);

    // TODO(doyle): padTo32Bytes should take a string_view
    std::string publicKeyHex = getPublicKeyHex();
    std::string serviceNodePubkeyHex =
            utils::padTo32Bytes(std::string(serviceNodePubkey), utils::PaddingDirection::LEFT);

    std::string message;
    message.reserve(
            hexPrefix.size() + fullTag.size() + publicKeyHex.size() + senderAddressOutput.size() +
            serviceNodePubkeyHex.size());
    message.append(hexPrefix);
    message.append(fullTag);
    message.append(publicKeyHex);
    message.append(senderAddressOutput);
    message.append(serviceNodePubkeyHex);

    const crypto::bytes<32> hash = BLSSigner::hash(message);  // Get the hash of the publickey
    bls::Signature sig;
    secretKey.signHash(sig, hash.data(), hash.size());
    return bls_utils::SignatureToHex(sig);
}

std::string BLSSigner::getPublicKeyHex() {
    bls::PublicKey publicKey;
    secretKey.getPublicKey(publicKey);
    return bls_utils::PublicKeyToHex(publicKey);
}

bls::PublicKey BLSSigner::getPublicKey() {
    bls::PublicKey publicKey;
    secretKey.getPublicKey(publicKey);
    return publicKey;
}

crypto::bytes<32> BLSSigner::hash(std::string_view in) {
    // TODO(doyle): hash should take in a string_view
    crypto::bytes<32> result = {};
    result.data_ = utils::hash(std::string(in));
    return result;
}

crypto::bytes<32> BLSSigner::hashModulus(std::string_view message) {
    // TODO(doyle): hash should take in a string_view
    crypto::bytes<32> hash = BLSSigner::hash(std::string(message));
    mcl::bn::Fp x;
    x.clear();
    x.setArrayMask(hash.data(), hash.size());
    crypto::bytes<32> serialized_hash;
    uint8_t* hdst = serialized_hash.data();
    if (x.serialize(hdst, serialized_hash.data_.max_size(), mcl::IoSerialize | mcl::IoBigEndian) ==
        0)
        throw std::runtime_error("size of x is zero");
    return serialized_hash;
}
