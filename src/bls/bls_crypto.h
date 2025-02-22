#pragma once

#include <crypto/crypto.h>
#include <crypto/eth.h>
#include <cryptonote_config.h>

#include <iterator>

namespace bn256 {
class g1;
class g2;
}  // namespace bn256

namespace eth {

/// Generates a new random BLS secret key.
bls_secret_key generate_bls_key();

/// Obtains the BLS pubkey (G1 point) associated with the given secret key
bls_public_key get_pubkey(const bls_secret_key& seckey);

/// Gets a signature (G2 point) from the given secret key signing a message.  The `nettype` gives
/// the network type (e.g. cryptonote::network_type::MAINNET) as the network type is used in the
/// signature tag so that testnet signatures aren't usable on mainnet and vice versa.
/// The contract address is also used in the signature; omitting (or passing nullptr) uses the
/// ServiceNodeRewards contract address, which is usually what you want (HF20 uptime proofs
/// excepted).
bls_signature sign(
        cryptonote::network_type nettype,
        const bls_secret_key& key,
        std::span<const uint8_t> msg,
        const eth::address* contract_addr = nullptr);

/// Obtains a proof-of-possession signature of an operator address, BLS pubkey, and service node
/// pubkey.  This is used when submitting a new BLS key for a service node to the smart contract.
/// `bls_pubkey` is optional, but can be given if already known to save its computation.
bls_signature proof_of_possession(
        cryptonote::network_type nettype,
        const eth::address& operator_addr,
        const crypto::public_key& sn_pubkey,
        const bls_secret_key& key,
        const bls_public_key* pubkey = nullptr);

/// Verifies a BLS signature `signature` allegedly signed by `pubkey` for `msg` on `nettype`.
bool verify(
        cryptonote::network_type nettype,
        const bls_signature& signature,
        const bls_public_key& pubkey,
        std::span<const uint8_t> msg,
        const eth::address* contract_addr = nullptr);

/// Constructs a keccak 32-byte hash of `baseTag` on network `nettype`.  This tag is used for domain
/// separation of different signature types and networks, and typically is called automatically by
/// the above functions.  The pointer to the contract address can be used to override the contract
/// address that gets used in the signature, if non-nullptr (this is used, in particular, by HF20
/// uptime proofs to use a null eth address because HF20 nodes will be deployed before the contract
/// address is known).
crypto::hash build_tag_hash(
        std::string_view base_tag,
        cryptonote::network_type nettype,
        const eth::address* contract_addr = nullptr);

/// Help class that aggregates pubkeys.  Construct it, then call it repeatedly with all the pubkeys
/// to be aggregated, then retrieve the aggregate.
class pubkey_aggregator {
    std::unique_ptr<bn256::g1> aggregate_;

  public:
    pubkey_aggregator();
    ~pubkey_aggregator();

    // Adds a pubkey to the aggregate.  Will throw a std::invalid_argument if the public key is not
    // a valid curve point.  Passing negate=true is the same as calling subtract.
    void add(const bls_public_key& pk, bool negate = false);

    // Sutracts a pubkey from the aggregate.  Will throw a std::invalid_argument if the public key
    // is not a valid curve point.
    void subtract(const bls_public_key& pk);

    // Returns the current aggregate pubkey.
    bls_public_key get() const;
};

/// Help class that aggregates signatures.  Construct it, then call it repeatedly with all the
/// signatures to be aggregated, then retrieve the aggregate.
class signature_aggregator {
    std::unique_ptr<bn256::g2> aggregate_;

  public:
    signature_aggregator();
    ~signature_aggregator();

    // Adds a signature to the aggregate.  Will throw a std::invalid_argument if the signature is
    // not a valid curve point.
    void add(const bls_signature& sig, bool _negate = false);

    // Sutracts a signature from the aggregate.  Will throw a std::invalid_argument if the signature
    // is not a valid curve point.
    void subtract(const bls_signature& sig);

    // Returns the current aggregate signature.
    bls_signature get() const;
};

namespace tag {

    /// Pre-defined tags given to `build_tag_hash` for different types of signed values.
    inline constexpr auto PROOF_OF_POSSESSION = "BLS_SIG_TRYANDINCREMENT_POP"sv;
    inline constexpr auto REWARD = "BLS_SIG_TRYANDINCREMENT_REWARD"sv;
    inline constexpr auto EXIT = "BLS_SIG_TRYANDINCREMENT_EXIT"sv;
    inline constexpr auto LIQUIDATE = "BLS_SIG_TRYANDINCREMENT_LIQUIDATE"sv;
    inline constexpr auto HASH_TO_G2 = "BLS_SIG_HASH_TO_FIELD_TAG"sv;

}  // namespace tag

}  // namespace eth
