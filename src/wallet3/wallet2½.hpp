#pragma once

#include <crypto/crypto.h>
#include <cryptonote_basic/cryptonote_basic.h>
#include <ringct/rctTypes.h>

#include <device/device.hpp>

namespace wallet25 {
uint64_t output_amount(
        const rct::rctSig& rv,
        const crypto::key_derivation& derivation,
        unsigned int i,
        rct::key& mask,
        hw::device& hwdev);

crypto::hash tx_hash(const cryptonote::transaction& tx);

cryptonote::transaction tx_from_blob(const std::string_view blob);

}  // namespace wallet25
