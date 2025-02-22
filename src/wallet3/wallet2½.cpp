#include "wallet2½.hpp"

#include <cryptonote_basic/cryptonote_format_utils.h>
#include <ringct/rctSigs.h>

namespace wallet25 {
// TODO: copied from wallet2 for now, so to not redo crypto stuff just yet.
//
// Definitely quite nasty and needs revisited.
uint64_t output_amount(
        const rct::rctSig& rv,
        const crypto::key_derivation& derivation,
        unsigned int i,
        rct::key& mask,
        hw::device& hwdev) {
    crypto::secret_key scalar1;
    hwdev.derivation_to_scalar(derivation, i, scalar1);
    switch (rv.type) {
        case rct::RCTType::Simple:
        case rct::RCTType::Bulletproof:
        case rct::RCTType::Bulletproof2:
        case rct::RCTType::CLSAG:
            return rct::decodeRctSimple(rv, rct::sk2rct(scalar1), i, mask, hwdev);
        case rct::RCTType::Full: return rct::decodeRct(rv, rct::sk2rct(scalar1), i, mask, hwdev);
        default: throw std::invalid_argument("Unsupported rct type");
    }
}

crypto::hash tx_hash(const cryptonote::transaction& tx) {
    crypto::hash h;

    // this can technically return false, but practially won't and will be replaced.
    cryptonote::get_transaction_hash(tx, h, nullptr);
    return h;
}

cryptonote::transaction tx_from_blob(const std::string_view blob) {
    cryptonote::transaction t;
    parse_and_validate_tx_from_blob(blob, t);
    return t;
}
}  // namespace wallet25
