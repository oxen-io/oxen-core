#pragma once

#include "crypto.h"
#include "eth.h"

namespace crypto {

namespace detail {
    template <typename T, bool Prefix_0x = false>
    struct crypto_literal {
        T value;
        consteval crypto_literal(const char (&h)[2 * sizeof(T) + (Prefix_0x ? 3 : 1)]) {
            const auto* c = h;
            if constexpr (Prefix_0x) {
                if (h[0] != '0' || h[1] != 'x')
                    throw std::invalid_argument{"Invalid literal: missing 0x prefix"};
                c += 2;
            }

            if (!oxenc::is_hex(c, c + 2 * sizeof(T)) || c[2 * sizeof(T)] != '\0')
                throw std::invalid_argument{"Invalid hex literal"};
            oxenc::from_hex(c, c + 2 * sizeof(T), value.data_.begin());
        }
    };
}  // namespace detail

inline namespace literals {

    template <detail::crypto_literal<public_key> PK>
    consteval public_key operator""_pk() {
        return PK.value;
    }

    template <detail::crypto_literal<ed25519_public_key> EdPK>
    consteval ed25519_public_key operator""_edpk() {
        return EdPK.value;
    }

    template <crypto::detail::crypto_literal<x25519_public_key> XPK>
    consteval x25519_public_key operator""_xpk() {
        return XPK.value;
    }

    template <crypto::detail::crypto_literal<eth::address, true> Eth>
    consteval eth::address operator""_eth() {
        return Eth.value;
    }

    template <crypto::detail::crypto_literal<eth::bls_public_key> BLSPK>
    consteval eth::bls_public_key operator""_blspk() {
        return BLSPK.value;
    }

}  // namespace literals

}  // namespace crypto
