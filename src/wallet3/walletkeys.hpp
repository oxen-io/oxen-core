#pragma once

class WalletKeys {
  public:
    virtual const crypto::secret_key& spend_privkey() const = 0;
    virtual const crypto::public_key& spend_pubkey() const = 0;
    virtual const crypto::secret_key& view_privkey() const = 0;
    virtual const crypto::public_key& view_pubkey() const = 0;
};

struct DBKeys : public WalletKeys {
    crypto::secret_key ssk, vsk;
    crypto::public_key spk, vpk;

    const crypto::secret_key& spend_privkey() const override { return ssk; }
    const crypto::public_key& spend_pubkey() const override { return spk; }
    const crypto::secret_key& view_privkey() const override { return vsk; }
    const crypto::public_key& view_pubkey() const override { return vpk; }
};
