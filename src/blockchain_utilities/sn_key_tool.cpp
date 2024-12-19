#include <algorithm>
extern "C" {
#include <sodium.h>
}
#include <iostream>
#include <fstream>
#include <oxenc/hex.h>
#include <oxenc/base32z.h>
#include <string_view>
#include <string>
#include <list>
#include <array>
#include <cstring>
#include <optional>
#include "common/fs.h"

std::string_view arg0;

using namespace std::literals;

int usage(int exit_code, std::string_view msg = ""sv) {
    if (!msg.empty())
        std::cout << "\n" << msg << "\n\n";
    std::cout << "Usage: " << arg0 << R"( COMMAND [OPTIONS...] where support COMMANDs are:

generate [--overwrite] FILENAME

    Generates a new Ed25519 service node keypair and writes the secret key to
    FILENAME.  If FILENAME contains the string "PUBKEY" it will be replaced
    with the generated public key value (in hex).

    For an active service node this file is named `key_ed25519` in the oxend
    data directory.

    If FILENAME already exists the command will fail unless the `--overwrite`
    flag is specified.

legacy [--overwrite] FILENAME

    Generates a new service node legacy keypair and write the private key to
    FILENAME. If FILENAME contains the string "PUBKEY" it will be replaced with
    the generated public key value (in hex).

    If FILENAME already exists the command will fail unless the `--overwrite`
    flag is specified.

    Note that legacy keypairs are not needed as of Oxen 8.x; you can use just a
    Ed25519 keypair (and this is the default for new service node
    installations).

show [--ed25519|--legacy] FILENAME

    Reads FILENAME as a service node secret key (Ed25519 or legacy) and
    displays it as a hex value along with the associated public key.  The
    displayed secret key can be saved and later used to recreate the secret key
    file with the `restore` command.

    --ed25519 and --legacy are not normally required as they can usually be
    inferred from the size of the given file (32 bytes = legacy, 64 bytes =
    Ed25519).  The options can be used to force the file to be interpreted as
    a secret key of the specified type.

restore [--overwrite] FILENAME
restore-legacy [--overwrite] FILENAME

    Restore an Ed25519 (restore) or legacy (restore-legacy) secret key and
    write it to FILENAME.  You will be prompted to provide a secret key hex
    value (as produced by the show command) and asked to confirm the public key
    for confirmation.  As with `generate', if FILENAME contains the string
    "PUBKEY" it will be replaced with the actual public key (in hex).

    If FILENAME already exists the command will fail unless the `--overwrite`
    flag is specified.

)";
    return exit_code;
}

[[nodiscard]] int error(int exit_code, std::string_view msg) {
    std::cout << "\n" << msg << "\n\n";
    return exit_code;
}

using ustring = std::basic_string<unsigned char>;
using ustring_view = std::basic_string_view<unsigned char>;

std::array<unsigned char, crypto_core_ed25519_BYTES> pubkey_from_privkey(ustring_view privkey) {
    std::array<unsigned char, crypto_core_ed25519_BYTES> pubkey;
    // noclamp because Monero keys are not clamped at all, and because sodium keys are pre-clamped.
    crypto_scalarmult_ed25519_base_noclamp(pubkey.data(), privkey.data());
    return pubkey;
}
template <size_t N, std::enable_if_t<(N >= 32), int> = 0>
std::array<unsigned char, crypto_core_ed25519_BYTES> pubkey_from_privkey(const std::array<unsigned char, N>& privkey) {
    return pubkey_from_privkey(ustring_view{privkey.data(), 32});
}

int generate(bool ed25519, std::list<std::string_view> args) {
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

    if (!overwrite && fs::exists(fs::u8path(filename)))
        return error(2, filename + " to generate already exists, pass `--overwrite' if you want to overwrite it");

    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> pubkey;
    std::array<unsigned char, crypto_sign_SECRETKEYBYTES> seckey;

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

    if (pubkey_pos != std::string::npos)
        filename.replace(pubkey_pos, 6, oxenc::to_hex(pubkey.begin(), pubkey.end()));
    fs::ofstream out{fs::u8path(filename), std::ios::trunc | std::ios::binary};
    if (!out.good())
        return error(2, "Failed to open output file '" + filename + "': " + std::strerror(errno));
    if (ed25519)
        out.write(reinterpret_cast<const char*>(seckey.data()), seckey.size());
    else
        out.write(reinterpret_cast<const char*>(privkey.data()), privkey.size());

    if (!out.good())
        return error(2, "Failed to write to output file '" + filename + "': " + std::strerror(errno));

    std::cout << "Generated SN " << (ed25519 ? "Ed25519 secret key" : "legacy private key") << " in " << filename << "\n";

    if (ed25519) {
        std::array<unsigned char, crypto_scalarmult_curve25519_BYTES> x_pubkey;
        if (0 != crypto_sign_ed25519_pk_to_curve25519(x_pubkey.data(), pubkey.data()))
            return error(14, "Internal error: unable to convert Ed25519 pubkey to X25519 pubkey");
        std::cout <<
              "Public key:      " << oxenc::to_hex(pubkey.begin(), pubkey.end()) <<
            "\nX25519 pubkey:   " << oxenc::to_hex(x_pubkey.begin(), x_pubkey.end()) <<
            "\nLokinet address: " << oxenc::to_base32z(pubkey.begin(), pubkey.end()) << ".snode\n";
    } else {
        std::cout << "Public key: " << oxenc::to_hex(pubkey.begin(), pubkey.end()) << "\n";
    }

    return 0;
}

int show(std::list<std::string_view> args) {

    bool legacy = false, ed25519 = false;
    if (!args.empty()) {
        if (args.front() == "--legacy") {
            legacy = true;
            args.pop_front();
        } else if (args.back() == "--legacy") {
            legacy = true;
            args.pop_back();
        } else if (args.front() == "--ed25519") {
            ed25519 = true;
            args.pop_front();
        } else if (args.back() == "--ed25519") {
            ed25519 = true;
            args.pop_back();
        }
    }
    if (args.empty())
        return error(2, "show requires a FILENAME");
    else if (args.size() > 1)
        return error(2, "unknown arguments to 'show'");

    fs::path filename = fs::u8path(args.front());
    fs::ifstream in{filename, std::ios::binary};
    if (!in.good())
        return error(2, "Unable to open '" + filename.u8string() + "': " + std::strerror(errno));

    in.seekg(0, std::ios::end);
    auto size = in.tellg();
    in.seekg(0, std::ios::beg);
    if (!legacy && !ed25519) {
        if (size == 32)
            legacy = true;
        else if (size == 64)
            ed25519 = true;
    }
    if (!legacy && !ed25519)
        return error(2, "Could not autodetect key type from " + std::to_string(size) + "-byte file; check the file or pass the --ed25519 or --legacy argument");

    if (size < 32)
        return error(2, "File size (" + std::to_string(size) + " bytes) is too small to be a secret key");

    std::array<unsigned char, crypto_core_ed25519_BYTES> pubkey;
    std::array<unsigned char, crypto_scalarmult_curve25519_BYTES> x_pubkey;
    std::array<unsigned char, crypto_sign_SECRETKEYBYTES> seckey;
    in.read(reinterpret_cast<char*>(seckey.data()), size >= 64 ? 64 : 32);
    if (!in.good())
        return error(2, "Failed to read from " + filename.u8string() + ": " + std::strerror(errno));

    if (legacy) {
        pubkey = pubkey_from_privkey(seckey);

        std::cout << filename.u8string() << " (legacy SN keypair)" << "\n==========" <<
            "\nPrivate key: " << oxenc::to_hex(seckey.begin(), seckey.begin() + 32) <<
            "\nPublic key:  " << oxenc::to_hex(pubkey.begin(), pubkey.end()) << "\n\n";
        return 0;
    }

    std::array<unsigned char, crypto_hash_sha512_BYTES> privkey_signhash;
    crypto_hash_sha512(privkey_signhash.data(), seckey.data(), 32);
    privkey_signhash[0] &= 248;
    privkey_signhash[31] &= 63;
    privkey_signhash[31] |= 64;

    ustring_view privkey{privkey_signhash.data(), 32};
    pubkey = pubkey_from_privkey(privkey);
    if (size >= 64 && ustring_view{pubkey.data(), pubkey.size()} != ustring_view{seckey.data() + 32, 32})
        return error(13, "Error: derived pubkey (" + oxenc::to_hex(pubkey.begin(), pubkey.end()) + ")"
                " != embedded pubkey (" + oxenc::to_hex(seckey.begin() + 32, seckey.end()) + ")");
    if (0 != crypto_sign_ed25519_pk_to_curve25519(x_pubkey.data(), pubkey.data()))
        return error(14, "Unable to convert Ed25519 pubkey to X25519 pubkey; is this a really valid secret key?");

    std::cout << filename << " (Ed25519 SN keypair)" << "\n==========" <<
        "\nSecret key:      " << oxenc::to_hex(seckey.begin(), seckey.begin() + 32) <<
        "\nPublic key:      " << oxenc::to_hex(pubkey.begin(), pubkey.end()) <<
        "\nX25519 pubkey:   " << oxenc::to_hex(x_pubkey.begin(), x_pubkey.end()) <<
        "\nLokinet address: " << oxenc::to_base32z(pubkey.begin(), pubkey.end()) << ".snode\n\n";
    return 0;
}

int restore(bool ed25519, std::list<std::string_view> args) {
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

    if (ed25519)
        std::cout << "Enter the Ed25519 secret key:\n";
    else
        std::cout << "Enter the legacy SN private key:\n";
    char buf[129];
    std::cin.getline(buf, 129);
    if (!std::cin.good())
        return error(7, "Invalid input, aborting!");
    std::string_view skey_hex{buf};

    // Advanced feature: if you provide the concatenated privkey and pubkey in hex, we won't prompt
    // for verification (as long as the pubkey matches what we derive from the privkey).
    if (!(skey_hex.size() == 64 || skey_hex.size() == 128) || !oxenc::is_hex(skey_hex))
        return error(7, "Invalid input: provide the secret key as 64 hex characters");
    std::array<unsigned char, crypto_sign_SECRETKEYBYTES> skey;
    std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> pubkey;
    std::array<unsigned char, crypto_sign_SEEDBYTES> seed;
    std::optional<std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>> pubkey_expected;
    oxenc::from_hex(skey_hex.begin(), skey_hex.begin() + 64, seed.begin());
    if (skey_hex.size() == 128)
        oxenc::from_hex(skey_hex.begin() + 64, skey_hex.end(), pubkey_expected.emplace().begin());

    if (ed25519) {
        crypto_sign_seed_keypair(pubkey.data(), skey.data(), seed.data());
    } else {
        pubkey = pubkey_from_privkey(seed);
    }

    std::cout << "\nPublic key:      " << oxenc::to_hex(pubkey.begin(), pubkey.end()) << "\n";
    if (ed25519) {
        std::array<unsigned char, crypto_scalarmult_curve25519_BYTES> x_pubkey;
        if (0 != crypto_sign_ed25519_pk_to_curve25519(x_pubkey.data(), pubkey.data()))
            return error(14, "Unable to convert Ed25519 pubkey to X25519 pubkey; is this a really valid secret key?");
        std::cout << "X25519 pubkey:   " << oxenc::to_hex(x_pubkey.begin(), x_pubkey.end()) <<
            "\nLokinet address: " << oxenc::to_base32z(pubkey.begin(), pubkey.end()) << ".snode";
    }

    if (pubkey_expected) {
        if (*pubkey_expected != pubkey)
            return error(2, "Derived pubkey (" + oxenc::to_hex(pubkey.begin(), pubkey.end()) + ") doesn't match "
                    "provided pubkey (" + oxenc::to_hex(pubkey_expected->begin(), pubkey_expected->end()) + ")");
    } else {

        if (ed25519 && filename.size() >= 4 && filename.substr(filename.size() - 4) == "/key") {
            std::cout << "\n\n\x1b[31;1m"
                "Warning: You are trying to restore a file named 'key' using the 'restore'\n"
                "command, which is intended for the key_ed25519 key file; for old service nodes\n"
                "with both key files you want to use 'restore-legacy' to restore the old\n"
                "(pre-Loki 8.x) pubkey.\x1b[0m\n";
        }

        std::cout << "\nIs this correct?  Press Enter to continue, Ctrl-C to cancel.\n";
        std::cin.getline(buf, 129);
        if (!std::cin.good())
            return error(99, "Aborted");
    }

    if (pubkey_pos != std::string::npos)
        filename.replace(pubkey_pos, 6, oxenc::to_hex(pubkey.begin(), pubkey.end()));

    auto filepath = fs::u8path(filename);
    if (!overwrite && fs::exists(filepath))
        return error(2, filename + " to generate already exists, pass `--overwrite' if you want to overwrite it");

    fs::ofstream out{filepath, std::ios::trunc | std::ios::binary};
    if (!out.good())
        return error(2, "Failed to open output file '" + filename + "': " + std::strerror(errno));
    if (ed25519)
        out.write(reinterpret_cast<const char*>(skey.data()), skey.size());
    else
        out.write(reinterpret_cast<const char*>(seed.data()), seed.size());

    if (!out.good())
        return error(2, "Failed to write to output file '" + filename + "': " + std::strerror(errno));

    std::cout << "Saved secret key to " << filename << "\n";
    return 0;
}


int main(int argc, char* argv[]) {
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

    if (cmd == "generate")
        return generate(true, std::move(args));
    if (cmd == "legacy")
        return generate(false, std::move(args));
    if (cmd == "show")
        return show(std::move(args));
    if (cmd == "restore")
        return restore(true, std::move(args));
    if (cmd == "restore-legacy")
        return restore(false, std::move(args));

    return usage(1, "Unknown command `" + std::string{cmd} + "'");
}
