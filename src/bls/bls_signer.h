#pragma once

#define BLS_ETH
#define MCLBN_FP_UNIT_SIZE 4
#define MCLBN_FR_UNIT_SIZE 4

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#pragma GCC diagnostic ignored "-Wshadow"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <bls/bls.hpp>
#include <mcl/bn.hpp>
#undef MCLBN_NO_AUTOLINK
#pragma GCC diagnostic pop

#include "common/fs.h"
#include "crypto/base.h"
#include "cryptonote_config.h"

class BLSSigner {
  private:
    bls::SecretKey secretKey;
    uint32_t chainID;
    std::string contractAddress;

    void initCurve();

  public:
    BLSSigner(const cryptonote::network_type nettype, const fs::path& key_filepath);

    bls::Signature signHash(const crypto::bytes<32>& hash);
    std::string proofOfPossession(
            std::string_view senderEthAddress, std::string_view serviceNodePubkey);
    std::string getPublicKeyHex();
    bls::PublicKey getPublicKey();

    static std::string buildTag(
            std::string_view baseTag, uint32_t chainID, std::string_view contractAddress);
    std::string buildTag(std::string_view baseTag);

    static crypto::bytes<32> hash(std::string_view in);
    static crypto::bytes<32> hashModulus(std::string_view message);

    static constexpr inline std::string_view proofOfPossessionTag = "BLS_SIG_TRYANDINCREMENT_POP";
    static constexpr inline std::string_view rewardTag = "BLS_SIG_TRYANDINCREMENT_REWARD";
    static constexpr inline std::string_view removalTag = "BLS_SIG_TRYANDINCREMENT_REMOVE";
    static constexpr inline std::string_view liquidateTag = "BLS_SIG_TRYANDINCREMENT_LIQUIDATE";
};
