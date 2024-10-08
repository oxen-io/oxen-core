#include "bls_crypto.h"

#include <bn256/bn256.h>
#include <gmp.h>
#include <oxenc/endian.h>

#include <oxen/log.hpp>

#include "common/bigint.h"
#include "common/guts.h"
#include "crypto/crypto.h"
#include "networks.h"

// We need various internal structs found within the bn256 src dir to implement our hash-to-G2
// functionality:

#include "bn256/src/constants.h"
#include "bn256/src/curve.h"
#include "bn256/src/gfp.h"
#include "bn256/src/gfp2.h"
#include "bn256/src/int512.h"
#include "bn256/src/twist.h"

namespace eth {

namespace {

    namespace log = oxen::log;
    auto logcat = log::Cat("bls_crypto");

    struct gmp_const_impl {
        mpz_t p;
        mpz_t p_plus_1_over_4;
        gmp_const_impl() {
            mpz_init_set_str(
                    p, "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16);
            mpz_init_set_str(
                    p_plus_1_over_4,
                    "c19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52",
                    16);
        }
        ~gmp_const_impl() {
            mpz_clear(p);
            mpz_clear(p_plus_1_over_4);
        }
    };
    const gmp_const_impl gmp_const;

    const auto two = bn256::new_gfp(2);
    const auto half = two.invert();

    constexpr bn256::int512_t p512{
            bn256::constants::p[0],
            bn256::constants::p[1],
            bn256::constants::p[2],
            bn256::constants::p[3],
            /* ... 0 */};

    using bn256::gfp;
    using bn256::gfp2;

    std::optional<gfp> sqrt(const gfp& x_sq_in) {
        std::optional<gfp> result;
        mpz_t x_sq;
        mpz_init(x_sq);
        mpz_import(x_sq, 4, -1, sizeof(uint64_t), 0, 0, x_sq_in.data());

        mpz_t x;
        mpz_init(x);
        // x = x_sq ^ ((p+q)/4) mod p
        // which is a magical shortcut for calculating the square root when the modulus p is
        // congruent to 3 mod 4.
        mpz_powm(x, x_sq, gmp_const.p_plus_1_over_4, gmp_const.p);

        // Square the result to verify that it matches x_sq; if it doesn't then the square root
        // doesn't exist.
        mpz_t xx;
        mpz_init(xx);
        mpz_powm_ui(xx, x, 2, gmp_const.p);
        if (mpz_cmp(xx, x_sq) == 0) {
            result.emplace();
            size_t words;
            mpz_export(result->data(), &words, -1, sizeof(uint64_t), 0, 0, x);
        }
        mpz_clear(xx);
        mpz_clear(x);
        mpz_clear(x_sq);
        return result;
    }

    std::optional<gfp2> sqrt(const gfp2& x) {
        /*
         * @dev Square root function implemented as a translation from herumi's
         * bls/mcl/include/mcl/fp_tower.hpp Fp::squareRoot, see:
         *
         * github.com/herumi/mcl/blob/0ede57b846f02298bd80995533fb789f9067d86e/include/mcl/fp_tower.hpp#L364
         *
         * This is the original Hermui comment:
         *   (a + bi)^2 = (a^2 - b^2) + 2ab i = c + di
         *   A = a^2
         *   B = b^2
         *   A = (c +/- sqrt(c^2 + d^2))/2
         *   b = d / 2a
         *
         * Which is not particularly clear, but:
         * · c, d are the input coefficients
         * · a, b are the coefficients we are looking for
         * · these two equations come from matching real/complex coefficients:
         *   · c = a² - b²
         *   · d = 2ab
         * · c² = (a² - b²)²
         *       = a⁴ + b⁴ - 2a²b²
         * But because we also know:
         * · (a² + b²)² = a⁴ + b⁴ + 2a²b²
         * we can rewrite that c² equation as:
         * · c² = (a² + b²)² - 4a²b²
         * and because d = 2ab, d² = 4a²b² and so substituting that in and rearranging:
         * · c² + d² = (a² + b²)²
         * which means:
         * · a² + b² = ±sqrt(c² + d²)
         * and from earlier we have:
         * · a² - b² = c`
         * so we add these two equations together to lose the b² term and get:
         * · 2a² = c ± sqrt(c² + d²)
         * and thus:
         * · a² = [ c ± sqrt(c² + d²) ] / 2
         * and so:
         * · a = ±sqrt([ c ± sqrt(c² + d²) ] / 2)
         * and then, having that, we can just plug it into b = d/2a to get b.
         */

        auto result = std::make_optional<gfp2>();
        auto& a = result->y_;
        auto& b = result->x_;
        const auto& c = x.y_;
        const auto& d = x.x_;
        if (d == gfp::zero()) {
            // Simplification for c + 0i case: either (√c,0) or (0,√-c)
            result.emplace();
            if (auto root = sqrt(c)) {
                a = *root;
                b = gfp::zero();
            } else {
                root = sqrt(c.neg());
                assert(root);
                a = gfp::zero();
                b = *root;
            }
            return result;
        }

        auto z = c.mul(c).add(d.mul(d));  // z = c² + d²
        auto root_z = sqrt(z.mont_encode());
        if (!root_z) {
            result.reset();
            return result;  // failed!
        }

        // First we try the positive alternative:
        auto t = c.add(*root_z).mul(half);  // t = [ c + sqrt(c² + d²) ] / 2

        auto root_t = sqrt(t);

        if (!root_t) {
            // Instead use the negative alternative:
            t = c.sub(*root_z).mul(half);
            root_t = sqrt(t);
            assert(root_t);
        }

        a = *root_t;
        b = d.mul(a.add(a).invert()).mont_decode();  // b = d / 2a
        return result;
    }

    void expand_message_xmd_keccak256(
            std::span<uint8_t> out, std::span<const uint8_t> msg, std::span<const uint8_t> dst) {
        // NOTE: Setup parameters (note: Our implementation restricts the output to <= 256 bytes)
        constexpr size_t KECCAK256_OUTPUT_SIZE = 256 / 8;
        const uint16_t len_in_bytes = static_cast<uint16_t>(out.size());
        constexpr size_t b_in_bytes =
                KECCAK256_OUTPUT_SIZE;  // the output size of H [Keccak] in bits
        const size_t ell = len_in_bytes / b_in_bytes;

        // NOTE: Assert invariants
        assert((out.size() % KECCAK256_OUTPUT_SIZE) == 0 && 0 < out.size() && out.size() <= 256);
        assert(dst.size() <= 255);

        // NOTE: Construct (4) Z_pad
        //
        //   s_in_bytes = Input Block Size     = 1088 bits = 136 bytes
        //   Z_pad      = I2OSP(0, s_in_bytes) = [0 .. INPUT_BLOCK_SIZE) => {0 .. 0}
        constexpr size_t INPUT_BLOCK_SIZE = 136;
        static constexpr uint8_t Z_pad[INPUT_BLOCK_SIZE] = {};

        // NOTE: Construct (5) l_i_b_str
        //
        //   l_i_b_str    = I2OSP(len_in_bytes, 2) => output length expressed in big
        //                  endian in 2 bytes.
        uint16_t l_i_b_str = oxenc::host_to_big<uint16_t>(out.size());

        // NOTE: Construct I2OSP(len(DST), 1) for DST_prime
        //   DST_prime          = (DST || I2OSP(len(DST), 1)
        //   I2OSP(len(DST), 1) = DST length expressed in big endian as 1 byte.
        constexpr uint8_t I2OSP_0_1 = 0;
        const uint8_t I2OSP_len_dst = static_cast<uint8_t>(dst.size());

        // NOTE: Construct (7) b0 = H(msg_prime)
        uint8_t b0[KECCAK256_OUTPUT_SIZE];
        {
            // NOTE: Construct (6) msg_prime = Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime
            KECCAK_CTX msg_prime;
            keccak_init(&msg_prime);
            keccak_update(&msg_prime, Z_pad, sizeof(Z_pad));
            keccak_update(&msg_prime, msg.data(), msg.size());
            keccak_update(&msg_prime, reinterpret_cast<uint8_t*>(&l_i_b_str), sizeof(l_i_b_str));
            keccak_update(&msg_prime, &I2OSP_0_1, sizeof(I2OSP_0_1));
            keccak_update(&msg_prime, dst.data(), dst.size());
            keccak_update(&msg_prime, &I2OSP_len_dst, sizeof(I2OSP_len_dst));

            // NOTE: Executes H(msg_prime)
            keccak_finish(&msg_prime, b0, sizeof(b0));
        }

        // NOTE: Construct (8) b1 = H(b0 || I2OSP(1, 1) || DST_prime)
        uint8_t b1[KECCAK256_OUTPUT_SIZE];
        {
            uint8_t I2OSP_1_1 = 1;
            KECCAK_CTX ctx;
            keccak_init(&ctx);
            keccak_update(&ctx, b0, sizeof(b0));
            keccak_update(&ctx, &I2OSP_1_1, sizeof(I2OSP_1_1));
            keccak_update(&ctx, dst.data(), dst.size());
            keccak_update(&ctx, &I2OSP_len_dst, sizeof(I2OSP_len_dst));

            // NOTE: Executes H(...)
            keccak_finish(&ctx, b1, sizeof(b1));
        }

        // NOTE: Construct (11) uniform_bytes = b1 ... b_ell
        std::memcpy(out.data(), b1, sizeof(b1));

        for (size_t i = 1; i < ell; i++) {

            // NOTE: Construct strxor(b0, b(i-1))
            uint8_t strxor_b0_bi[KECCAK256_OUTPUT_SIZE];
            for (size_t j = 0; j < KECCAK256_OUTPUT_SIZE; j++) {
                strxor_b0_bi[j] = b0[j] ^ out[KECCAK256_OUTPUT_SIZE * (i - 1) + j];
            }

            // NOTE: Construct (10) bi = H(strxor(b0, b(i - 1)) || I2OSP(i, 1) || DST_prime)
            uint8_t bi[KECCAK256_OUTPUT_SIZE];
            {
                uint8_t I2OSP_i_1 = static_cast<uint8_t>(i + 1);
                KECCAK_CTX ctx;
                keccak_init(&ctx);
                keccak_update(&ctx, strxor_b0_bi, sizeof(strxor_b0_bi));
                keccak_update(&ctx, &I2OSP_i_1, sizeof(I2OSP_i_1));
                keccak_update(&ctx, dst.data(), dst.size());
                keccak_update(&ctx, &I2OSP_len_dst, sizeof(I2OSP_len_dst));

                // NOTE: Executes H(...)
                keccak_finish(&ctx, bi, sizeof(bi));
            }

            // NOTE: Transfer bi to uniform_bytes
            std::memcpy(out.data() + KECCAK256_OUTPUT_SIZE * i, bi, sizeof(bi));
        }
    }

    bn256::g2 map_to_g2(std::span<const uint8_t> msg, std::span<const uint8_t> tag) {
        bn256::g2 result;
        auto& twist_point = result.p();
        twist_point.z_.set_one();
        twist_point.t_.set_one();
        auto& x = twist_point.x_;
        auto& y = twist_point.y_;

        std::vector<uint8_t> messageWithI(msg.size() + 1);
        std::memcpy(messageWithI.data(), msg.data(), msg.size());

        for (uint8_t increment = 0;; increment++) {
            messageWithI[messageWithI.size() - 1] = increment;

            // NOTE: Solidity's BN256G2.hashToField(msg, tag) => (x1, x2, b)
            uint8_t expandedBytes[128];
            expand_message_xmd_keccak256(expandedBytes, messageWithI, tag);

            bn256::int512_t d1{}, d2{};
            static_assert(sizeof(d1) == 64 && sizeof(d1.limbs_) == 64);
            // `expandedBytes[0:48]` and [48:96] are our 384 bit pseudorandom hash data, in big
            // endian order, which we need to mod into an x1 and x2 value.  We load each into a 512
            // bit variable that consists of 8 uint64_t, with element [7] being the most
            // significant.
            //
            // We also use the least significant bit of expandedBytes[127] to decide whether or not
            // to take the negative of the sqrt value we get back.  The remaining 31 bytes + 7 bits
            // of the hash are not currently used.
            const bool negative_root = expandedBytes[127] & 1;
            for (int i = 0; i < 6; i++)
                d1.limbs_[5 - i] = oxenc::load_big_to_host<uint64_t>(expandedBytes + i * 8);
            d1 %= p512;
            for (int i = 0; i < 6; i++)
                d2.limbs_[5 - i] = oxenc::load_big_to_host<uint64_t>(expandedBytes + (i + 6) * 8);
            d2 %= p512;

            using bn256::gfp;
            using bn256::gfp2;
            std::memcpy(x.y_.data(), d1.limbs_.data(), 4 * sizeof(uint64_t));
            std::memcpy(x.x_.data(), d2.limbs_.data(), 4 * sizeof(uint64_t));
            x.y_ = x.y_.mont_encode();
            x.x_ = x.x_.mont_encode();

            // y² = x³ + b
            gfp2 y2 = gfp2::gfp2_decode(x.square().mul(x).add(bn256::twist_point::twist_b));

            if (auto sqrt_y2 = sqrt(y2)) {
                if (negative_root) {
                    auto yneg = sqrt_y2->neg();
                    y.y_ = yneg.y_.mont_encode();
                    y.x_ = yneg.x_.mont_encode();
                } else {
                    y.y_ = sqrt_y2->y_.mont_encode();
                    y.x_ = sqrt_y2->x_.mont_encode();
                }
                return result;
            }
            // Otherwise not on curve, increment and try again.
        }

        return result;
    }

    constexpr bn256::twist_point frob(bn256::twist_point P) {
        P.x_ = P.x_.conjugate();
        P.y_ = P.y_.conjugate();
        P.z_ = P.z_.conjugate();
        P.x_ = P.x_.mul(bn256::constants::xi_to_p_minus_1_over_3);
        P.y_ = P.y_.mul(bn256::constants::xi_to_p_minus_1_over_2);
        return P;
    }

    bn256::g2 mul_by_cofactor(const bn256::g2& P) {
        const auto& tp = P.p();

        // t0 = u * P
        auto t0 = tp.mul(bn256::constants::u);

        // t1 = Frobenius(3 * u * P)
        auto t1 = t0.double_().add(t0);
        t1 = frob(t1);

        // t2 = Frobenius^2(u * P)
        auto t2 = frob(frob(t0));

        // t3 = Frobenius^3(P)
        auto t3 = frob(frob(frob(tp)));

        // t0 + t1 + t2 + t3
        return bn256::g2{t0.add(t1).add(t2).add(t3)};
    }

    bn256::g2 signed_g2_base(std::span<const uint8_t> msg, cryptonote::network_type nettype) {

        // Map the message + tag to g2, then multiply by the cofactor to clear the cofactor
        //
        return mul_by_cofactor(map_to_g2(msg, build_tag_hash(tag::HASH_TO_G2, nettype)));
    }

    // bn256 takes scalars as u64x4 arrays, with the 4 array elements in little endian order and the
    // individual u64s in host order.
    //
    // This function takes a big-endian encoded u256 value and converts it into the u64x4 value.
    constexpr void load_u256(std::array<uint64_t, 4>& to, std::span<const uint8_t, 32> from_big) {
        for (size_t i = 0; i < to.size(); i++)
            to[i] = oxenc::load_big_to_host<uint64_t>(from_big.data() + (3 - i) * 8);
    }
    // Same, but returns a new array instead of copying into one.
    constexpr std::array<uint64_t, 4> load_u256(std::span<const uint8_t, 32> from_big) {
        std::array<uint64_t, 4> s;
        load_u256(s, from_big);
        return s;
    }

    // bn256's unmarshal code expects the final limb pairs to be in x/y order, but what we have from
    // the smart contract stores these as what bn256 considers to be y/x order.  This swaps each
    // pair of u256 values from the input (e.g. a bls_signature, bls_pubkey) to the output so that
    // the value can be given to unmarshal.  The spans must not overlap!
    template <size_t S>
        requires(S % 64 == 0)
    void swap_xy(std::span<const uint8_t, S> in, std::span<uint8_t, S> out) {
        for (size_t i = 0; i < S; i += 64) {
            std::memcpy(out.data() + i, in.data() + i + 32, 32);
            std::memcpy(out.data() + i + 32, in.data() + i, 32);
        }
    }
    // Same as above, but returns the result an a new array
    template <size_t S>
        requires(S % 64 == 0)
    std::array<uint8_t, S> swap_xy(std::span<const uint8_t, S> in) {
        std::array<uint8_t, S> out;
        swap_xy(in, std::span{out});
        return out;
    }
    // Same as above, but writes directly into a span instead of returning a new array.
    // Same as above, but swaps values inplace
    template <size_t S>
        requires(S % 64 == 0)
    void swap_xy_inplace(std::span<uint8_t, S> x) {
        std::array<uint8_t, 32> buf;
        for (size_t i = 0; i < S; i += 64) {
            std::memcpy(buf.data(), x.data() + i + 32, 32);
            std::memcpy(x.data() + i + 32, x.data() + i, 32);
            std::memcpy(x.data() + i, buf.data(), 32);
        }
    }

}  // namespace

bls_secret_key generate_bls_key() {
    bls_secret_key sk;
    crypto::rand(sizeof(sk), sk.data());
    // bn256 expects a 255-bit random, so clear the MSB
    sk.data()[0] &= 0b0111'1111;
    return sk;
}

bls_public_key get_pubkey(const bls_secret_key& seckey) {
    bls_public_key pk;
    bn256::g1::scalar_base_mult(load_u256(tools::span_guts(seckey))).marshal(tools::span_guts(pk));
    return pk;
}

/// Gets a signature (G2 point) from the given secret key signing a message.  The `nettype` gives
/// the network type (e.g. cryptonote::network_type::MAINNET) as the network type is used in the
/// signature tag so that testnet signatures aren't usable on mainnet and vice versa.
bls_signature sign(
        cryptonote::network_type nettype, const bls_secret_key& key, std::span<const uint8_t> msg) {

    bls_signature sig;

    // Get the public hash-to-G2 point of the value:
    signed_g2_base(msg, nettype)
            // and then multiply by the secret key scalar to get the signature G2 point
            .scalar_mult(load_u256(tools::span_guts(key)))
            // and write it out to our waiting bls_signature
            .marshal(tools::span_guts(sig));

    // marshal and our contract functions disagree about the order of the two x/y values in each of
    // the two signature values, so swap them to agree with the smart contract ordering:
    swap_xy_inplace(tools::span_guts(sig));

    return sig;
}

bool verify(
        cryptonote::network_type nettype,
        const bls_signature& signature,
        const bls_public_key& pubkey,
        std::span<const uint8_t> msg) {

    std::array<bn256::g1, 2> g1;
    g1[0] = bn256::g1::curve_gen;
    {
        if (auto ec = g1[1].unmarshal(tools::span_guts(pubkey)); ec != std::error_code{}) {
            log::debug(logcat, "BLS verification failed: invalid pubkey ({})", ec.message());
            return false;
        }
        g1[1] = g1[1].neg();
    }

    std::array<bn256::g2, 2> g2;
    g2[1] = signed_g2_base(msg, nettype);
    {
        // Swap inner u256 values from the order the contract expects into the order bn256 expects:
        auto sig_swapped = swap_xy(tools::span_guts(signature));
        if (auto ec = g2[0].unmarshal(sig_swapped); ec != std::error_code{}) {
            log::debug(logcat, "BLS verification failed: invalid signature ({})", ec.message());
            return false;
        }
    }

    if (bn256::pairing_check(g1, g2))
        return true;
    log::debug(logcat, "BLS verification failed: signature does not match");
    return false;
}

bls_signature proof_of_possession(
        cryptonote::network_type nettype,
        const eth::address& operator_addr,
        const crypto::public_key& sn_pubkey,
        const bls_secret_key& key,
        const bls_public_key* bls_pubkey) {
    bls_public_key pubkey_if_needed;
    if (!bls_pubkey) {
        pubkey_if_needed = get_pubkey(key);
        bls_pubkey = &pubkey_if_needed;
    }

    // TODO(doyle): Currently the ServiceNodeRewards.sol contract does
    //
    // ```
    // bytes memory encodedMessage = abi.encodePacked(
    //     proofOfPossessionTag,
    //     blsPubkey.X,
    //     blsPubkey.Y,
    //     caller,
    //     serviceNodePubkey
    // );
    // BN256G2.G2Point memory Hm = BN256G2.hashToG2(encodedMessage, hashToG2Tag);
    // ```
    //
    // It does not hash the message but forwards it through hashToG2 (e.g. our
    // signMsg). So we have to do similar and create the same message buffer
    // instead of forwarding everything to keccak(...params)
    //
    // We can probably just run `keccak(encodedMessage)` in solidity to simplify
    // things and then consequently do the same here.
    auto pop_tag = build_tag_hash(tag::PROOF_OF_POSSESSION, nettype);
    auto msg = tools::concat_guts<uint8_t>(pop_tag, *bls_pubkey, operator_addr, sn_pubkey);

    oxen::log::debug(
            logcat,
            "Generating proof-of-possession with parameters\n"
            "Tag:        {}\n"
            "BLS Pubkey: {}\n"
            "Sender:     {}\n"
            "SN Pubkey:  {}",
            pop_tag,
            *bls_pubkey,
            operator_addr,
            sn_pubkey);

    return sign(nettype, key, msg);
}

/// Constructs a keccak 32-byte hash of `baseTag` on network `nettype`.  This tag is used for domain
/// separation of different signature types and networks, and typically is called automatically by
/// the above functions.
crypto::hash build_tag_hash(std::string_view base_tag, cryptonote::network_type nettype) {
    const auto config = get_config(nettype);
    return crypto::keccak(
            base_tag,
            tools::encode_integer_be<32>(config.ETHEREUM_CHAIN_ID),
            tools::make_from_hex_guts<eth::address>(config.ETHEREUM_REWARDS_CONTRACT));
}

pubkey_aggregator::pubkey_aggregator() = default;
pubkey_aggregator::~pubkey_aggregator() = default;

void pubkey_aggregator::add(const bls_public_key& pubkey, bool _negate) {
    bn256::g1 g1;
    if (auto ec = g1.unmarshal(tools::span_guts(pubkey)); ec != std::error_code{})
        throw oxen::traced<std::invalid_argument>{"Invalid BLS public key: " + ec.message()};
    if (_negate)
        g1.neg();

    if (!aggregate_)
        aggregate_ = std::make_unique<bn256::g1>(std::move(g1));
    else
        aggregate_->add(g1);
}
void pubkey_aggregator::subtract(const bls_public_key& pubkey) {
    return add(pubkey, true);
}

bls_public_key pubkey_aggregator::get() const {
    if (!aggregate_)
        throw oxen::traced<std::invalid_argument>{
                "Cannot extract aggregate pubkey: no pubkeys added"};
    bls_public_key agg;
    aggregate_->marshal(tools::span_guts(agg));
    return agg;
}

signature_aggregator::signature_aggregator() = default;
signature_aggregator::~signature_aggregator() = default;

void signature_aggregator::add(const bls_signature& signature, bool _negate) {
    bn256::g2 g2;
    auto sig_swapped = swap_xy(tools::span_guts(signature));
    if (auto ec = g2.unmarshal(sig_swapped); ec != std::error_code{})
        throw oxen::traced<std::invalid_argument>{"Invalid BLS signature: " + ec.message()};
    if (_negate)
        g2.neg();
    if (!aggregate_)
        aggregate_ = std::make_unique<bn256::g2>(std::move(g2));
    else
        aggregate_->add(g2);
}
void signature_aggregator::subtract(const bls_signature& signature) {
    return add(signature, true);
}

bls_signature signature_aggregator::get() const {
    if (!aggregate_)
        throw oxen::traced<std::invalid_argument>{
                "Cannot extract aggregate signature: no signatures added"};
    bls_signature agg;
    auto span = tools::span_guts(agg);
    aggregate_->marshal(span);
    swap_xy_inplace(span);
    return agg;
}

}  // namespace eth
