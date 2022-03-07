#pragma once

#include <wallet3/keyring.hpp>

namespace wallet
{

class MockKeyring : public Keyring
{
  public:

    MockKeyring() : Keyring({},{},{},{}) {}

    std::vector<std::tuple<crypto::public_key, uint64_t, uint64_t, cryptonote::subaddress_index> > ours;
    std::vector<crypto::public_key> predetermined_output_ephemeral_keys{};
    int64_t last_output_ephemeral_key = 0;


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
      predetermined_output_ephemeral_keys.push_back(crypto::public_key{});
      crypto::public_key& ephemeral_key = predetermined_output_ephemeral_keys.back();
      tools::hex_to_type(key, ephemeral_key);
    }


    crypto::public_key
    generate_output_ephemeral_keys(const crypto::secret_key& tx_key, const cryptonote::tx_destination_entry& dst_entr, const size_t output_index, std::vector<rct::key>& amount_keys)
    {
      if (predetermined_output_ephemeral_keys.size() > 0)
      {
        auto& return_key = predetermined_output_ephemeral_keys[last_output_ephemeral_key];
        if (last_output_ephemeral_key + 1 == static_cast<int64_t>(predetermined_output_ephemeral_keys.size()))
          last_output_ephemeral_key = 0;
        else
          last_output_ephemeral_key++;
        return return_key;
      }
      return Keyring::generate_output_ephemeral_keys(tx_key, dst_entr, output_index, amount_keys);
    }

};

} // namespace wallet
