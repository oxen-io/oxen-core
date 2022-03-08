#pragma once

#include <wallet3/keyring.hpp>

namespace wallet
{

class MockKeyring : public Keyring
{
  public:

    MockKeyring() : Keyring() {}
    MockKeyring(
        crypto::secret_key _spend_private_key,
        crypto::public_key _spend_public_key,
        crypto::secret_key _view_private_key,
        crypto::public_key _view_public_key)
        : Keyring(_spend_private_key, _spend_public_key, _view_private_key, _view_public_key)
    {}

    std::vector<std::tuple<crypto::public_key, uint64_t, uint64_t, cryptonote::subaddress_index> > ours;
    std::vector<crypto::secret_key> predetermined_tx_keys{};
    int64_t next_tx_key = 0;


    void
    add_key_index_pair_as_ours(
        const crypto::public_key& key,
        const uint64_t index,
        const uint64_t amount,
        const cryptonote::subaddress_index& sub_index)
    {
      ours.push_back({key, index, amount, sub_index});
    }

    virtual crypto::key_derivation
    generate_key_derivation(const crypto::public_key& tx_pubkey) const override
    {
      return reinterpret_cast<const crypto::key_derivation&>(tx_pubkey);
    }

    virtual std::vector<crypto::key_derivation>
    generate_key_derivations(const std::vector<crypto::public_key>& tx_pubkeys) const override
    {
      std::vector<crypto::key_derivation> v;
      for (const auto& k : tx_pubkeys)
        v.push_back(reinterpret_cast<const crypto::key_derivation&>(k));

      return v;
    }

    virtual crypto::public_key
    output_spend_key(
        const crypto::key_derivation& derivation,
        const crypto::public_key& output_key,
        uint64_t output_index) override
    {
      return output_key;
    }

    virtual std::optional<cryptonote::subaddress_index>
    output_and_derivation_ours(
        const crypto::key_derivation& derivation,
        const crypto::public_key& output_key,
        uint64_t output_index) override
    {
      for (const auto& [our_key, our_index, our_amount, sub_index] : ours)
      {
        if (our_key == output_key && our_index == output_index)
          return sub_index;
      }
      return std::nullopt;
    }

    virtual crypto::key_image
    key_image(
        const crypto::key_derivation& derivation,
        const crypto::public_key& output_key,
        uint64_t output_index,
        const cryptonote::subaddress_index& sub_index) override
    {
      return {};
    }

    virtual uint64_t
    output_amount(
        const rct::rctSig& rv,
        const crypto::key_derivation& derivation,
        unsigned int i,
        rct::key& mask) override
    {
      for (const auto& [our_key, our_index, our_amount, sub_index] : ours)
      {
        if (our_key == reinterpret_cast<const crypto::public_key&>(derivation) && our_index == i)
          return our_amount;
      }
      return 0;
    }

    void
    add_tx_key(const std::string_view& key)
    {
      predetermined_tx_keys.push_back(crypto::secret_key{});
      crypto::secret_key& ephemeral_key = predetermined_tx_keys.back();
      tools::hex_to_type(key, ephemeral_key);
    }


    crypto::secret_key
    generate_tx_key(uint8_t hf_version)
    {
      if (predetermined_tx_keys.size() > 0)
      {
        auto& return_key = predetermined_tx_keys[next_tx_key];
        if (next_tx_key + 1 == static_cast<int64_t>(predetermined_tx_keys.size()))
          next_tx_key = 0;
        else
          next_tx_key++;
        return return_key;
      }
      return Keyring::generate_tx_key(hf_version);
    }

};

} // namespace wallet
