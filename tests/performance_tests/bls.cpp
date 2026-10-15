
#include <bn256/bn256.h>
#include <gmp.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <chrono>

#include "bls/bn256.h"
#include "bls/bls_signer.h"
#include "bls/bls_utils.h"
#include "bn256/src/constants.h"
#include "bn256/src/gfp.h"
#include "bn256/src/gfp2.h"
#include "bn256/src/int512.h"
#include "bn256/src/twist.h"
#include "common/guts.h"
#include "crypto/eth.h"
#include "crypto/random.h"
#include "cryptonote_config.h"

using namespace oxenc::literals;

std::vector<eth::BLSSigner> gen_signers(size_t s) {
    std::vector<eth::BLSSigner> signers;
    signers.reserve(s);
    while (signers.size() < s)
        signers.emplace_back(cryptonote::network_type::MAINNET);
    return signers;
}

std::vector<std::tuple<bn256::uint255_t, bn256::g1>> gen_keys_bn256(size_t s) {
    std::vector<std::tuple<bn256::uint255_t, bn256::g1>> skeys;
    skeys.reserve(s);
    while (skeys.size() < s)
        skeys.push_back(bn256::ramdom_g1());
    return skeys;
}

std::vector<eth::bls_public_key> get_pubkeys(const std::vector<eth::BLSSigner>& signers) {
    std::vector<eth::bls_public_key> pks;
    pks.reserve(signers.size());
    for (auto& signer : signers)
        pks.push_back(signer.getCryptoPubkey());
    return pks;
}

std::vector<eth::bls_signature> sign(
        std::span<const uint8_t> data, const std::vector<eth::BLSSigner>& signers) {
    std::vector<eth::bls_signature> sigs;
    sigs.reserve(signers.size());
    for (auto& signer : signers) {
        sigs.push_back(signer.signMsg(data));
    }
    return sigs;
}

size_t verify(
        std::span<const uint8_t> data,
        const std::vector<eth::bls_signature>& sigs,
        const std::vector<eth::bls_public_key>& pks) {
    if (sigs.size() != pks.size())
        throw std::invalid_argument{"sigs size != pks size"};
    size_t good = 0;
    for (size_t i = 0; i < sigs.size(); i++)
        good += eth::BLSSigner::verifyMsg(cryptonote::network_type::MAINNET, sigs[i], pks[i], data);
    return good;
}

void report_timing(
        std::string_view name, size_t count, std::chrono::steady_clock::time_point& since) {
    using dseconds = std::chrono::duration<double>;
    dseconds elapsed = std::chrono::steady_clock::now() - since;

    fmt::print(
            "{}: {} in {:.6f}s ({:3f}/s)\n", name, count, elapsed.count(), count / elapsed.count());

    since = std::chrono::steady_clock::now();
}

int main() {
    size_t count = 2000;

    auto now = std::chrono::steady_clock::now();
    auto signers = gen_signers(count);
    report_timing("generation", count, now);
    auto pks = get_pubkeys(signers);
    report_timing("get pubkey", count, now);

    auto data_sv =
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed varius volutpat purus, "
            "at scelerisque augue mattis non. Pellentesque tincidunt, augue sit amet aliquam "
            "dignissim, libero velit ornare velit, vel lobortis lacus est vitae odio. Vestibulum "
            "fringilla tempus porta. Phasellus eget nisl vivamus."sv;
    std::span<const uint8_t> data{reinterpret_cast<const uint8_t*>(data_sv.data()), data_sv.size()};

    auto sigs = sign(data, signers);
    report_timing("sign", count, now);

    auto verified = verify(data, sigs, pks);
    report_timing("verify", count, now);

    fmt::print("{}/{} signatures verified successfully\n", verified, count);
}
