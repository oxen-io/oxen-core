
#include <fmt/color.h>
#include <fmt/std.h>
#include <oxenc/base32z.h>
#include <oxenc/hex.h>
#include <sodium.h>

#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <list>
#include <optional>
#include <string>
#include <string_view>

#include "bls/bls_crypto.h"
#include "common/fs.h"
#include "common/guts.h"
#include "crypto/crypto.h"
#include "crypto/eth.h"

std::string_view arg0;

using namespace std::literals;

enum class key_type { legacy, ed25519, bls };

int usage(int exit_code, std::string_view msg = ""sv) {
    if (!msg.empty())
        fmt::print("\n{}\n\n", msg);
    fmt::print(
            R"(Usage: {} COMMAND [OPTIONS...] where support COMMANDs are:

ed25519 [--overwrite] FILENAME
bls [--overwrite] FILENAME
legacy [--overwrite] FILENAME

    Generates a new Ed25519, BLS, or legacy service node keypair and writes the
    secret key to FILENAME.  If FILENAME contains the string "PUBKEY" it will be
    replaced with the generated public key value (in hex).

    For an active service node these files are named `key_ed25519`, `key_bls`,
    or `key` in the oxend data directory, respectively.  (As of Oxen 11 the
    `key` file is not used).

    If FILENAME already exists the command will fail unless the `--overwrite`
    flag is specified.

    Note that legacy keypairs are not needed as of Oxen 8.x, and are not used at
    all as of the Oxen 11.x/SENT hard fork.  As of Oxen 11.x both the
    key_ed25519 and key_bls are required.

show [--ed25519|--bls|--legacy] FILENAME

    Reads FILENAME as a service node secret key (Ed25519 or legacy) and
    displays it as a hex value along with the associated public key.  The
    displayed secret key can be saved and later used to recreate the secret key
    file with the `restore` command.

    --ed25519, --bls, and --legacy are not normally required as they can
    usually be guessed from the size of the given file.  The options can be used
    to force the file to be interpreted as a secret key of the specified type.

restore [--overwrite] FILENAME
restore-bls [--overwrite] FILENAME
restore-legacy [--overwrite] FILENAME

    Restore an Ed25519 (restore), bls (restore-bls), or legacy (restore-legacy)
    secret key and write it to FILENAME.  You will be prompted to provide a
    secret key hex value (as produced by the show command) and asked to confirm
    the public key for confirmation.  As with `generate', if FILENAME contains
    the string "PUBKEY" it will be replaced with the actual public key (in hex).

    If FILENAME already exists the command will fail unless the `--overwrite`
    flag is specified.

)",
            arg0);
    return exit_code;
}

[[nodiscard]] int error(int exit_code, std::string_view msg) {
    fmt::print(fmt::fg(fmt::terminal_color::red) | fmt::emphasis::bold, "\n{}\n\n", msg);
    return exit_code;
}

using ustring = std::basic_string<unsigned char>;
using ustring_view = std::basic_string_view<unsigned char>;

crypto::ed25519_public_key pubkey_from_privkey(ustring_view privkey) {
    crypto::ed25519_public_key pubkey;
    // noclamp because Monero keys are not clamped at all, and because sodium keys are pre-clamped.
    crypto_scalarmult_ed25519_base_noclamp(pubkey.data(), privkey.data());
    return pubkey;
}
template <size_t N>
    requires(N >= 32)
crypto::ed25519_public_key pubkey_from_privkey(const std::array<unsigned char, N>& privkey) {
    return pubkey_from_privkey(ustring_view{privkey.data(), 32});
}

std::string display_ed(
        const crypto::ed25519_public_key& pubkey, const crypto::x25519_public_key& x_pubkey) {
    return fmt::format(
            R"(
Public key:      {0:x}
X25519 pubkey:   {1:x}
Lokinet address: {0:a}.snode
)",
            pubkey,
            x_pubkey);
}
std::string display_legacy(const crypto::ed25519_public_key& pubkey) {
    return fmt::format(
            R"(
Public key: {0:x}
)",
            pubkey);
}

std::string display_bls(const eth::bls_public_key& pubkey) {
    return fmt::format(
            R"(
Public key: {0:x}
)",
            pubkey);
}

int generate(key_type type, std::list<std::string_view> args) {
    bool overwrite = false;
    if (!args.empty()) {
        if (args.front() == "--overwrite") {
            overwrite = true;
            args.pop_front();
        } else if (args.back() == "--overwrite") {
            overwrite = true;
            args.pop_back();
        }
    }
    if (args.empty())
        return error(2, "generate requires a FILENAME");
    else if (args.size() > 1)
        return error(2, "unknown arguments to 'generate'");

    std::string filename{args.front()};
    size_t pubkey_pos = filename.find("PUBKEY");
    if (pubkey_pos != std::string::npos)
        overwrite = true;

    if (!overwrite && fs::exists(tools::utf8_path(filename)))
        return error(
                2,
                filename +
                        " to generate already exists, pass `--overwrite' if you want to overwrite "
                        "it");

    std::string key_bytes;
    std::string pk_display;
    std::string hex_pk;
    if (type == key_type::legacy || type == key_type::ed25519) {
        crypto::ed25519_public_key pubkey;
        crypto::ed25519_secret_key seckey;

        crypto_sign_keypair(pubkey.data(), seckey.data());
        std::array<unsigned char, crypto_hash_sha512_BYTES> privkey_signhash;
        crypto_hash_sha512(privkey_signhash.data(), seckey.data(), 32);
        // Clamp it to prevent small subgroups:
        privkey_signhash[0] &= 248;
        privkey_signhash[31] &= 63;
        privkey_signhash[31] |= 64;

        ustring_view privkey{privkey_signhash.data(), 32};

        // Double-check that we did it properly:
        if (pubkey_from_privkey(privkey) != pubkey)
            return error(11, "Internal error: pubkey check failed");

        if (type == key_type::ed25519)
            key_bytes = "0x" + oxenc::to_hex(seckey.begin(), seckey.end()) + "\n";
        else
            key_bytes = tools::view_guts(privkey);

        if (type == key_type::ed25519) {
            crypto::x25519_public_key x_pubkey;
            if (0 != crypto_sign_ed25519_pk_to_curve25519(x_pubkey.data(), pubkey.data()))
                return error(
                        14, "Internal error: unable to convert Ed25519 pubkey to X25519 pubkey");
            pk_display = display_ed(pubkey, x_pubkey);
        } else {
            pk_display = display_legacy(pubkey);
        }
        hex_pk = tools::hex_guts(pubkey);
    } else {  // bls
        eth::bls_secret_key seckey = eth::generate_bls_key();
        key_bytes = "0x" + tools::hex_guts(seckey);
        eth::bls_public_key bls_pubkey = eth::get_pubkey(seckey);
        hex_pk = tools::hex_guts(bls_pubkey);
        pk_display = display_bls(bls_pubkey);
    }

    if (pubkey_pos != std::string::npos)
        filename.replace(pubkey_pos, 6, hex_pk);
    std::ofstream out{tools::utf8_path(filename), std::ios::trunc | std::ios::binary};
    if (!out.good())
        return error(
                2,
                fmt::format("Failed to open output file '{}': {}", filename, std::strerror(errno)));
    out.write(key_bytes.data(), key_bytes.size());
    if (!out.good())
        return error(
                2, "Failed to write to output file '" + filename + "': " + std::strerror(errno));

    fmt::print("{}", pk_display);
    fmt::print(
            fmt::fg(fmt::terminal_color::green) | fmt::emphasis::bold,
            "\nGenerated SN {} secret key in {}\n\n",
            (type == key_type::ed25519 ? "Ed25519"
             : type == key_type::bls   ? "BLS"
                                       : "legacy"),
            filename);

    return 0;
}

static bool remove_flag(std::list<std::string_view>& args, std::string_view flag) {
    if (args.empty())
        return false;
    if (args.front() == flag) {
        args.pop_front();
        return true;
    }
    if (args.back() == flag) {
        args.pop_back();
        return true;
    }
    return false;
}

int show(std::list<std::string_view> args) {

    bool legacy = remove_flag(args, "--legacy");
    bool ed25519 = !legacy && remove_flag(args, "--ed25519");
    bool bls = !legacy && !ed25519 && remove_flag(args, "--bls");
    if (args.empty())
        return error(2, "show requires a FILENAME");
    else if (args.size() > 1)
        return error(2, "unknown arguments to 'show'");

    auto filename = tools::utf8_path(args.front());
    std::ifstream in{filename, std::ios::binary};
    if (!in.good())
        return error(2, fmt::format("Unable to open '{}': {}", filename, std::strerror(errno)));

    in.seekg(0, std::ios::end);
    auto sz = in.tellg();
    in.seekg(0, std::ios::beg);
    if (!legacy && !ed25519 && !bls) {
        // Guess based on the size:
        if (sz == 32)  // raw 32 bytes: legacy primary key (these were never written as hex)
            legacy = true;
        else if (sz == 64 || sz == 130 || sz == 131)  // raw 64 bytes, *or* 0x-prefixed hex with
                                                      // or
            ed25519 = true;                           // without trailing newline
        else if (sz == 66 || sz == 67)  // the BLS secret is always 0x-prefixed, 32-byte key in
                                        // hex
            bls = true;                 // (with or without newline)
    }
    auto size = static_cast<size_t>(sz);
    if (!legacy && !ed25519 && !bls)
        return error(
                2,
                fmt::format(
                        "Could not autodetect key type from {}-byte file; check the file or "
                        "pass one of the --ed25519/--bls/--legacy arguments",
                        size));

    std::string key_data;
    key_data.resize(size);
    in.read(key_data.data(), size);
    if (!in.good())
        return error(
                2, fmt::format("Failed to read from '{}': {}", filename, std::strerror(errno)));

    // Hex-encoded Ed/BLS keys (starting from Oxen 11) start with 0x, and may contain a newline
    // at the end, so we if find something that is 2 or 3 bytes larger than a multiple of 64,
    // try to strip off the 0x and \n and decode it from hex:
    if (!legacy && (size % 64 == 2 || size % 64 == 3) && key_data.starts_with("0x")) {
        std::string_view hex_data{key_data};
        hex_data.remove_prefix(2);
        if (size % 64 == 3 && hex_data.ends_with("\n"))
            hex_data.remove_suffix(1);
        if (!oxenc::is_hex(hex_data))
            return error(2, "File is invalid: expected 0x[hexdata], but found non-hex");
        key_data = oxenc::from_hex(hex_data);
    }

    if (legacy && size != 32)
        return error(
                2, fmt::format("File size ({} bytes) is invalid for a legacy secret key", size));
    if (ed25519 && key_data.size() != 64)
        return error(
                2, fmt::format("File size ({} bytes) is invalid for an Ed25519 secret key", size));
    if (bls && key_data.size() != 32)
        return error(2, fmt::format("File size ({} bytes) is invalid for a BLS secret key", size));

    ustring_view seckey{reinterpret_cast<const unsigned char*>(key_data.data()), key_data.size()};

    if (legacy) {
        auto pubkey = pubkey_from_privkey(seckey);

        fmt::print(
                R"(
{} (legacy SN keypair)
==========
Private key: {}
Public key:  {}

)",
                filename,
                oxenc::to_hex(seckey.begin(), seckey.begin() + 32),
                pubkey);
        return 0;
    }

    if (ed25519) {
        std::array<unsigned char, crypto_hash_sha512_BYTES> privkey_signhash;
        crypto_hash_sha512(privkey_signhash.data(), seckey.data(), 32);
        privkey_signhash[0] &= 248;
        privkey_signhash[31] &= 63;
        privkey_signhash[31] |= 64;

        ustring_view privkey{privkey_signhash.data(), 32};
        auto pubkey = pubkey_from_privkey(privkey);
        if (size >= 64 &&
            ustring_view{pubkey.data(), pubkey.size()} != ustring_view{seckey.data() + 32, 32})
            return error(
                    13,
                    "Error: derived pubkey (" + oxenc::to_hex(pubkey.begin(), pubkey.end()) +
                            ")"
                            " != embedded pubkey (" +
                            oxenc::to_hex(seckey.begin() + 32, seckey.end()) + ")");
        crypto::x25519_public_key x_pubkey;
        if (0 != crypto_sign_ed25519_pk_to_curve25519(x_pubkey.data(), pubkey.data()))
            return error(
                    14,
                    "Unable to convert Ed25519 pubkey to X25519 pubkey; is this a really valid "
                    "secret key?");

        fmt::print(
                R"(
{0} (Ed25519 SN keypair)
==========
Secret key:      {1}
Public key:      {2:x}
X25519 pubkey:   {3:x}
Lokinet address: {2:a}.snode

)",
                filename,
                oxenc::to_hex(seckey.begin(), seckey.begin() + 32),
                pubkey,
                x_pubkey);
        return 0;
    }

    if (bls) {
        auto bls_sec = tools::make_from_guts<eth::bls_secret_key>(key_data);
        auto eth_bls_pk = get_pubkey(bls_sec);
        auto eth_bls_sk_hex = tools::hex_guts(bls_sec);

        fmt::print(
                R"(
{} (BLS SN keypair)
==========
Secret key: 0x{}
Public key: 0x{}

)",
                filename,
                eth_bls_sk_hex,
                eth_bls_pk);
        return 0;
    }

    throw std::logic_error{"Unknown key type"};
}

int restore(key_type type, std::list<std::string_view> args) {
    bool overwrite = false;
    if (!args.empty()) {
        if (args.front() == "--overwrite") {
            overwrite = true;
            args.pop_front();
        } else if (args.back() == "--overwrite") {
            overwrite = true;
            args.pop_back();
        }
    }
    if (args.empty())
        return error(2, "restore requires a FILENAME");
    else if (args.size() > 1)
        return error(2, "unknown arguments to 'restore'");

    std::string filename{args.front()};
    size_t pubkey_pos = filename.find("PUBKEY");

    fmt::print(
            "Enter the {} secret key:\n",
            type == key_type::ed25519 ? "Ed25519"
            : type == key_type::bls   ? "BLS"
                                      : "legacy SN");
    char buf[131];
    std::cin.getline(buf, sizeof(buf));
    if (!std::cin.good())
        return error(7, "Invalid input, aborting!");
    std::string_view skey_hex{buf};

    if (skey_hex.starts_with("0x"))
        skey_hex.remove_prefix(2);

    std::string sk_data;
    std::string hex_pk;

    if (type == key_type::ed25519 || type == key_type::legacy) {
        // Advanced feature: if you provide the concatenated privkey and pubkey in hex, we won't
        // prompt for verification (as long as the pubkey matches what we derive from the privkey).
        if (!(skey_hex.size() == 64 || skey_hex.size() == 128) || !oxenc::is_hex(skey_hex))
            return error(7, "Invalid input: provide the secret key as 64 hex characters");
        crypto::ed25519_secret_key skey;
        crypto::ed25519_public_key pubkey;
        std::array<unsigned char, crypto_sign_SEEDBYTES> seed;
        std::optional<crypto::ed25519_public_key> pubkey_expected;
        oxenc::from_hex(skey_hex.begin(), skey_hex.begin() + 64, seed.begin());
        if (skey_hex.size() == 128)
            oxenc::from_hex(
                    skey_hex.begin() + 64, skey_hex.end(), pubkey_expected.emplace().begin());

        if (type == key_type::ed25519) {
            crypto_sign_seed_keypair(pubkey.data(), skey.data(), seed.data());
            crypto::x25519_public_key x_pubkey;
            if (0 != crypto_sign_ed25519_pk_to_curve25519(x_pubkey.data(), pubkey.data()))
                return error(
                        14,
                        "Unable to convert Ed25519 pubkey to X25519 pubkey; is this a really valid "
                        "secret key?");
            fmt::print("{}", display_ed(pubkey, x_pubkey));
            sk_data = "0x" + tools::hex_guts(skey) + "\n";
        } else {
            pubkey = pubkey_from_privkey(seed);
            fmt::print("{}", display_legacy(pubkey));
            sk_data = tools::view_guts(skey).substr(0, 32);
        }

        if (pubkey_expected) {
            if (*pubkey_expected != pubkey)
                return error(
                        2,
                        fmt::format(
                                "Derived pubkey ({}) doesn't match provided pubkey ({})",
                                pubkey,
                                *pubkey_expected));
        }

        hex_pk = tools::hex_guts(pubkey);
    } else {  // bls
        if (skey_hex.size() != 64 || !oxenc::is_hex(skey_hex))
            return error(7, "Invalid input: provide the secret key as 64 hex characters");

        auto bls_sec = tools::make_from_hex_guts<eth::bls_secret_key>(skey_hex);
        auto eth_bls_pk = get_pubkey(bls_sec);
        fmt::print("{}", display_bls(eth_bls_pk));
        hex_pk = tools::hex_guts(eth_bls_pk);
    }

    std::string cmd_instead, fn;
    if ((filename == "key" || filename.ends_with("/key")) && type != key_type::legacy) {
        fn = "key";
        cmd_instead = "restore-legacy";
    } else if (
            (filename == "key_ed25519" || filename.ends_with("/key_ed25519")) &&
            type != key_type::ed25519) {
        cmd_instead = "restore";
        fn = "key_ed25519";
    } else if ((filename == "key_bls" || filename.ends_with("/key_bls")) && type != key_type::bls) {
        cmd_instead = "restore-bls";
        fn = "key_bls";
    }

    if (!cmd_instead.empty()) {
        std::string cmd_used = type == key_type::legacy  ? "restore-legacy"
                             : type == key_type::ed25519 ? "restore"
                                                         : "restore-bls";
        std::string fn_instead = type == key_type::legacy  ? "key"
                               : type == key_type::ed25519 ? "key_ed25519"
                                                           : "key_bls";

        fmt::print(
                fmt::fg(fmt::terminal_color::red) | fmt::emphasis::bold,
                R"(

Warning: You are trying to restore a file named '{}' using the '{}'
command, which is intended for the '{}' key file.  You may have intended
to use the '{}' command instead.
)",
                fn,
                cmd_used,
                fn_instead,
                cmd_instead);

        fmt::print("\nIs this correct?  Press Enter to continue, Ctrl-C to cancel.\n");
        std::cin.getline(buf, sizeof(buf));
        if (!std::cin.good())
            return error(99, "Aborted");
    }

    if (pubkey_pos != std::string::npos)
        filename.replace(pubkey_pos, 6, hex_pk);

    auto filepath = tools::utf8_path(filename);
    if (!overwrite && fs::exists(filepath))
        return error(
                2, filename + " already exists, pass `--overwrite' if you want to overwrite it");

    std::ofstream out{filepath, std::ios::trunc | std::ios::binary};
    if (!out.good())
        return error(
                2,
                fmt::format("Failed to open output file '{}': {}", filename, std::strerror(errno)));
    out.write(sk_data.data(), sk_data.size());
    if (!out.good())
        return error(
                2,
                fmt::format(
                        "Failed to write to output file '{}': {}", filename, std::strerror(errno)));

    fmt::print(
            fmt::fg(fmt::terminal_color::green) | fmt::emphasis::bold,
            "\nSaved secret key to {}\n",
            filename);
    return 0;
}

int main(int argc, char* argv[]) {
    oxen::set_terminate_handler();
    arg0 = argv[0];
    if (argc < 2)
        return usage(1, "No command specified!");

    std::string_view cmd{argv[1]};
    std::list<std::string_view> args{argv + 2, argv + argc};

    if (sodium_init() == -1) {
        std::cerr << "Sodium initialization failed! Unable to continue.\n\n";
        return 3;
    }

    for (auto& flag : {"--help"sv, "-h"sv, "-?"sv})
        for (auto& arg : args)
            if (arg == flag)
                return usage(0);

    if (cmd == "ed25519" || cmd == "generate" /* old command name */)
        return generate(key_type::ed25519, std::move(args));
    if (cmd == "legacy")
        return generate(key_type::legacy, std::move(args));
    if (cmd == "bls")
        return generate(key_type::bls, std::move(args));
    if (cmd == "show")
        return show(std::move(args));
    if (cmd == "restore-ed25519" || cmd == "restore")
        return restore(key_type::ed25519, std::move(args));
    if (cmd == "restore-legacy")
        return restore(key_type::legacy, std::move(args));
    if (cmd == "restore-bls")
        return restore(key_type::bls, std::move(args));

    return usage(1, "Unknown command `" + std::string{cmd} + "'");
}
