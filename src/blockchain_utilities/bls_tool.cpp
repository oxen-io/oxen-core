#include <fmt/format.h>
#include <oxenc/hex.h>

#include <list>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "bls/bls_crypto.h"
#include "common/guts.h"
#include "crypto/eth.h"
#include "networks.h"

std::string_view prog;

int usage(std::string_view argument = "", std::string_view extra_info = "") {
    if (!argument.empty())
        fmt::print(
                "\nInvalid argument: '{}'{}\n\n",
                argument,
                extra_info.empty() ? "" : ": {}"_format(extra_info));

    fmt::print(
            R"(
{0} -- BLS pubkey/signature aggregator and verifier

Usage:

pubkey addition/subtraction:

    {0} BLSPK +BLSPK [+BLSPK ...] # aggregates 2 or more pubkey, prints the aggregate
    {0} BLSPK -BLSPK [-BLSPK ...] # subtracts 1 or more pubkeys from another pubkey
    {0} BLSPK -BLSPK +BLSPK +BLSPK -BLSPK ... # combined addition/subtraction
    {0} -BLSPK # negation
    {0} +BLSPK # same as just BLSPK

signature addition/subtraction:

    {0} BLSSIG +BLSSIG [+BLSSIG ...] # aggregates signatures
    {0} BLSSIG -BLSSIG [-BLSSIG ...] # subtracts signatures
    {0} BLSSIG +BLSSIG -BLSSIG +BLSSIG ... # combined addition/subtraction
    {0} -BLSSIG # negation
    {0} +BLSSIG # same as just BLSSIG

signature verification (with optional aggregation):

    {0} NETWORK MSG BLSPK BLSSIG
    {0} NETWORK MSG BLSPK [{{+|-}}BLSPK ...] BLSSIG [{{+|-}}BLSSIG ...]

NETWORK must be mainnet, stagenet, devnet, etc.

MSG is the message that was allegedly signed, either with auto-detected hex or plaintext (but can be
prefixed with 0x or _ to force hex or plaintext interpretation).

)",
            prog);

    return 1;
}

int main(int argc, char* argv[]) {
    prog = argv[0];
    std::list<std::string_view> args;
    for (int i = 1; i < argc; i++)
        args.emplace_back(argv[i]);

    eth::pubkey_aggregator pk_agg;
    eth::signature_aggregator sig_agg;
    size_t n_pk = 0, n_sig = 0;

    std::optional<std::pair<cryptonote::network_type, std::vector<unsigned char>>> verify;

    if (args.empty())
        return usage();

    if (cryptonote::network_type nettype = cryptonote::network_type_from_string(args.front());
        nettype != cryptonote::network_type::UNDEFINED) {
        args.pop_front();
        if (args.empty())
            return usage(args.front(), "verification message must follow network type");
        auto msg_in = args.front();
        args.pop_front();
        verify.emplace();
        verify->first = nettype;
        bool is_hex;
        if (msg_in.starts_with("0x")) {
            is_hex = true;
            msg_in.remove_prefix(2);
        } else if (msg_in.starts_with('_')) {
            is_hex = false;
            msg_in.remove_prefix(1);
        } else if (oxenc::is_hex(msg_in)) {
            is_hex = true;
        } else {
            is_hex = false;
        }
        if (is_hex)
            oxenc::from_hex(msg_in.begin(), msg_in.end(), std::back_inserter(verify->second));
        else {
            verify->second.resize(msg_in.size());
            std::memcpy(verify->second.data(), msg_in.data(), msg_in.size());
        }
    }

    for (auto& arg : args) {
        bool add = arg.starts_with('+');
        bool sub = arg.starts_with('-');
        if (add || sub)
            arg.remove_prefix(1);
        if (!oxenc::is_hex(arg))
            return usage(arg);

        if (arg.size() == oxenc::to_hex_size(sizeof(eth::bls_public_key))) {
            if (n_pk > 0 && !add && !sub)
                return usage(arg, "+ or - required for pubkey aggregation");

            try {
                pk_agg.add(tools::make_from_hex_guts<eth::bls_public_key>(arg), sub);
            } catch (const std::invalid_argument& e) {
                fmt::print("\e[35;1mInvalid BLS pubkey \e[34m{}\e[31m: {}\e[0m\n", arg, e.what());
                return 2;
            }

            n_pk++;
        } else if (arg.size() == oxenc::to_hex_size(sizeof(eth::bls_signature))) {
            if (n_sig > 0 && !add && !sub)
                return usage(arg, "+ or - required for signature aggregation");

            try {
                sig_agg.add(tools::make_from_hex_guts<eth::bls_signature>(arg), sub);
            } catch (const std::invalid_argument& e) {
                fmt::print(
                        "\e[31;1mInvalid BLS signature \e[34m{}\e[31m: {}\e[0m\n", arg, e.what());
                return 3;
            }
            n_sig++;
        }
    }

    if (verify && (!n_pk || !n_sig))
        return usage(
                "NETWORK", "Cannot perform verification without at least one pubkey and signature");

    eth::bls_public_key pk{};
    eth::bls_signature sig{};
    fmt::print("\n");
    if (n_pk) {
        pk = pk_agg.get();
        fmt::print("\e[35;1m{}\e[0m: {}\n\n", n_pk > 1 ? "Aggregate pubkey" : "Pubkey", pk);
    }

    if (n_sig) {
        sig = sig_agg.get();
        fmt::print("\e[36;1m{}\e[0m: {}\n\n", n_sig > 1 ? "Aggregate signature" : "Signature", sig);
    }

    if (verify) {
        const auto& [nettype, msg] = *verify;
        auto good = eth::verify(nettype, sig, pk, msg);
        fmt::print(
                "\e[{}\e[0m\n\n",
                good ? "32;1mSignature verified!" : "31;1mSIGNATURE VERIFICATION FAILED!");
        return good ? 0 : 42;
    }
}
