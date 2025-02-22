#pragma once

#include <crypto/crypto.h>
#include <cryptonote_basic/subaddress_index.h>
#include <ringct/rctTypes.h>

#include <cstdint>
#include <string>

namespace wallet {
struct Output {
    int64_t amount;
    int64_t output_index;
    int64_t global_index;
    int64_t unlock_time;
    int64_t block_height;
    int64_t block_time;
    bool spending = false;
    int64_t spent_height;
    int64_t spent_time;

    crypto::hash tx_hash;
    crypto::public_key tx_public_key;
    crypto::public_key key;
    crypto::key_derivation derivation;
    rct::key rct_mask;
    crypto::key_image key_image;
    cryptonote::subaddress_index subaddress_index;

    Output(std::tuple<int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t> row) :
            amount(std::get<0>(row)),
            output_index(std::get<1>(row)),
            global_index(std::get<2>(row)),
            unlock_time(std::get<3>(row)),
            block_height(std::get<4>(row)),
            spending(static_cast<bool>(std::get<5>(row))),
            spent_height(std::get<6>(row)){};

    Output() = default;
};

}  // namespace wallet
