
#include "bls/bls_crypto.h"

#include <bn256/bn256.h>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <chrono>

#include "common/guts.h"
#include "crypto/eth.h"
#include "cryptonote_config.h"

using namespace oxenc::literals;

std::vector<eth::bls_secret_key> gen_signers(size_t s) {
    std::vector<eth::bls_secret_key> signers;
    signers.reserve(s);
    while (signers.size() < s)
        signers.push_back(eth::generate_bls_key());
    return signers;
}

std::vector<eth::bls_public_key> get_pubkeys(const std::vector<eth::bls_secret_key>& signers) {
    std::vector<eth::bls_public_key> pks;
    pks.reserve(signers.size());
    for (auto& signer : signers)
        pks.push_back(get_pubkey(signer));
    return pks;
}

std::vector<eth::bls_signature> sign(
        std::span<const uint8_t> data, const std::vector<eth::bls_secret_key>& signers) {
    std::vector<eth::bls_signature> sigs;
    sigs.reserve(signers.size());
    for (auto& signer : signers) {
        sigs.push_back(eth::sign(cryptonote::network_type::MAINNET, signer, data));
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
    for (size_t i = 0; i < sigs.size(); i++) {
        auto pk = pks[i];
        auto sig = sigs[i];
        good += eth::verify(cryptonote::network_type::MAINNET, sig, pk, data);
    }
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
    constexpr size_t count = 1000;

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

    eth::pubkey_aggregator pk_agger;
    for (size_t i = 0; i < pks.size(); i++)
        pk_agger.add(pks[i]);
    auto agg_pk = pk_agger.get();
    report_timing("agg pks", count, now);

    eth::signature_aggregator sig_agger;
    for (size_t i = 0; i < sigs.size(); i++)
        sig_agger.add(sigs[i]);
    auto agg_sig = sig_agger.get();
    report_timing("agg sigs", count, now);

    verified += eth::verify(cryptonote::network_type::MAINNET, agg_sig, agg_pk, data);

    report_timing("agg verify", 1, now);

    fmt::print("{}/{} signatures verified successfully\n", verified, count);
}
