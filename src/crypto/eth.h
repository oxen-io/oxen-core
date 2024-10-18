#pragma once

#include "base.h"
#include "epee/memwipe.h"
#include "epee/mlocker.h"

namespace eth {

struct address : crypto::bytes<20, true, uint32_t> {
    // Returns true if non-null, i.e. not all 0.
    explicit operator bool() const { return data_ != crypto::null<address>.data_; }
};

struct bls_public_key : crypto::bytes<64, true> {
    // Returns true if non-null, i.e. not all 0.
    explicit operator bool() const { return data_ != crypto::null<bls_public_key>.data_; }
};

struct bls_signature : crypto::bytes<128, true> {
    // Returns true if non-null, i.e. not 0.
    explicit operator bool() const { return data_ != crypto::null<bls_signature>.data_; }
};

struct bls_secret_key_ : crypto::bytes<32> {};
using bls_secret_key = epee::mlocked<tools::scrubbed<bls_secret_key_>>;

}  // namespace eth

template <>
struct std::hash<eth::bls_public_key> : crypto::raw_hasher<eth::bls_public_key> {};
template <>
struct std::hash<eth::address> : crypto::raw_hasher<eth::address> {};

// For an eth address, override the default format of <...hex...> to be 0x...hex... instead.  (But
// don't override for non-default formatting).
template <>
struct fmt::formatter<eth::address> : formattable::hex_span_formatter {
    fmt::format_context::iterator default_format(
            std::span<const unsigned char> val, fmt::format_context& ctx) const override;
};
