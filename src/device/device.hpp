// Copyright (c) 2017-2019, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#pragma once

#include "crypto/chacha.h"
#include "crypto/crypto.h"
#include "cryptonote_basic/txtypes.h"
#include "cryptonote_config.h"
#include "epee/wipeable_string.h"
#include "logging/oxen_logger.h"
#include "ringct/rctTypes.h"

#ifndef USE_DEVICE_LEDGER
#define USE_DEVICE_LEDGER 1
#endif

#if !defined(HAVE_HIDAPI)
#undef USE_DEVICE_LEDGER
#define USE_DEVICE_LEDGER 0
#endif

#if USE_DEVICE_LEDGER
#define WITH_DEVICE_LEDGER
#endif

// forward declaration needed because this header is included by headers in libcryptonote_basic
// which depends on libdevice
namespace cryptonote {
struct account_public_address;
struct account_keys;
struct subaddress_index;
struct tx_destination_entry;
struct keypair;
class transaction_prefix;
}  // namespace cryptonote

namespace hw {
namespace log = oxen::log;

class device_progress {
  public:
    virtual double progress() const { return 0; }
    virtual bool indeterminate() const { return false; }
};

class i_device_callback {
  public:
    virtual void on_button_request(uint64_t code = 0) {}
    virtual void on_button_pressed() {}
    virtual std::optional<epee::wipeable_string> on_pin_request() { return std::nullopt; }
    virtual std::optional<epee::wipeable_string> on_passphrase_request(bool& on_device) {
        on_device = true;
        return std::nullopt;
    }
    virtual void on_progress(const device_progress& event) {}
    virtual ~i_device_callback() = default;
};

class device {
  protected:
    std::string name;

  public:
    device() = default;
    device(const device&) = delete;
    device& operator=(const device&) = delete;
    device(device&&) = default;
    device& operator=(device&&) = default;

    virtual ~device() = default;

    virtual bool is_hardware_device() const = 0;
    enum class mode { NONE, TRANSACTION_CREATE_REAL, TRANSACTION_CREATE_FAKE, TRANSACTION_PARSE };
    enum class type { SOFTWARE = 0, LEDGER = 1, TREZOR = 2 };

    enum class protocol {
        DEFAULT,
        PROXY,  // Originally defined by Ledger
        COLD,   // Originally defined by Trezor
    };

    /* ======================================================================= */
    /*                              SETUP/TEARDOWN                             */
    /* ======================================================================= */
    virtual bool set_name(std::string_view name) = 0;
    virtual std::string get_name() const = 0;

    // Optional; can be used to take an address parameter if required (e.g. Ledger TCP uses this
    // to specify the TCP address).
    virtual void set_address(std::string_view address) {}

    virtual bool init() = 0;
    virtual bool release() = 0;

    virtual bool connect() = 0;
    virtual bool disconnect() = 0;

    virtual bool set_mode(mode m) {
        mode_ = m;
        return true;
    }
    virtual mode get_mode() const { return mode_; }

    virtual type get_type() const = 0;

    virtual protocol device_protocol() const { return protocol::DEFAULT; };
    virtual void set_callback(i_device_callback* callback){};
    virtual void set_derivation_path(const std::string& derivation_path){};

    virtual void set_pin(const epee::wipeable_string& pin) {}
    virtual void set_passphrase(const epee::wipeable_string& passphrase) {}

    /* ======================================================================= */
    /*  LOCKER                                                                 */
    /* ======================================================================= */
    virtual void lock() = 0;
    virtual void unlock() = 0;
    virtual bool try_lock() = 0;

    /* ======================================================================= */
    /*                             WALLET & ADDRESS                            */
    /* ======================================================================= */
    virtual bool get_public_address(cryptonote::account_public_address& pubkey) = 0;
    virtual bool get_secret_keys(crypto::secret_key& viewkey, crypto::secret_key& spendkey) = 0;
    virtual bool generate_chacha_key(
            const cryptonote::account_keys& keys, crypto::chacha_key& key, uint64_t kdf_rounds) = 0;

    /* ======================================================================= */
    /*                               SUB ADDRESS                               */
    /* ======================================================================= */
    virtual bool derive_subaddress_public_key(
            const crypto::public_key& pub,
            const crypto::key_derivation& derivation,
            const std::size_t output_index,
            crypto::public_key& derived_pub) = 0;
    virtual crypto::public_key get_subaddress_spend_public_key(
            const cryptonote::account_keys& keys, const cryptonote::subaddress_index& index) = 0;
    virtual std::vector<crypto::public_key> get_subaddress_spend_public_keys(
            const cryptonote::account_keys& keys,
            uint32_t account,
            uint32_t begin,
            uint32_t end) = 0;
    virtual cryptonote::account_public_address get_subaddress(
            const cryptonote::account_keys& keys, const cryptonote::subaddress_index& index) = 0;
    virtual crypto::secret_key get_subaddress_secret_key(
            const crypto::secret_key& sec, const cryptonote::subaddress_index& index) = 0;

    /* ======================================================================= */
    /*                            DERIVATION & KEY                             */
    /* ======================================================================= */
    virtual bool verify_keys(
            const crypto::secret_key& secret_key, const crypto::public_key& public_key) = 0;
    virtual bool scalarmultKey(rct::key& aP, const rct::key& P, const rct::key& a) = 0;
    virtual bool scalarmultBase(rct::key& aG, const rct::key& a) = 0;
    virtual bool sc_secret_add(
            crypto::secret_key& r, const crypto::secret_key& a, const crypto::secret_key& b) = 0;
    virtual crypto::secret_key generate_keys(
            crypto::public_key& pub,
            crypto::secret_key& sec,
            const crypto::secret_key& recovery_key = crypto::secret_key(),
            bool recover = false) = 0;
    virtual crypto::key_derivation generate_key_derivation(
            const crypto::public_key& pub, const crypto::secret_key& sec) = 0;
    virtual bool generate_key_derivation(
            const crypto::public_key& pub,
            const crypto::secret_key& sec,
            crypto::key_derivation& derivation) = 0;
    virtual bool conceal_derivation(
            crypto::key_derivation& derivation,
            const crypto::public_key& tx_pub_key,
            const std::vector<crypto::public_key>& additional_tx_pub_keys,
            const crypto::key_derivation& main_derivation,
            const std::vector<crypto::key_derivation>& additional_derivations) = 0;
    virtual bool derivation_to_scalar(
            const crypto::key_derivation& derivation,
            const size_t output_index,
            crypto::ec_scalar& res) = 0;
    virtual bool derive_secret_key(
            const crypto::key_derivation& derivation,
            const std::size_t output_index,
            const crypto::secret_key& sec,
            crypto::secret_key& derived_sec) = 0;
    virtual bool derive_public_key(
            const crypto::key_derivation& derivation,
            const std::size_t output_index,
            const crypto::public_key& pub,
            crypto::public_key& derived_pub) = 0;
    virtual bool secret_key_to_public_key(
            const crypto::secret_key& sec, crypto::public_key& pub) = 0;
    virtual bool generate_key_image(
            const crypto::public_key& pub,
            const crypto::secret_key& sec,
            crypto::key_image& image) = 0;
    virtual bool generate_key_image_signature(
            const crypto::key_image& image,
            const crypto::public_key& pub,
            const crypto::secret_key& sec,
            crypto::signature& sig) = 0;
    virtual bool generate_unlock_signature(
            const crypto::public_key& pub,
            const crypto::secret_key& sec,
            crypto::signature& sig) = 0;
    virtual bool generate_ons_signature(
            std::string_view signature_data,
            const cryptonote::account_keys& keys,
            const cryptonote::subaddress_index& index,
            crypto::signature& sig) = 0;

    // alternative prototypes available in libringct
    rct::key scalarmultKey(const rct::key& P, const rct::key& a) {
        rct::key aP;
        scalarmultKey(aP, P, a);
        return aP;
    }

    rct::key scalarmultBase(const rct::key& a) {
        rct::key aG;
        scalarmultBase(aG, a);
        return aG;
    }

    /* ======================================================================= */
    /*                               TRANSACTION                               */
    /* ======================================================================= */

    virtual void generate_tx_proof(
            const crypto::hash& prefix_hash,
            const crypto::public_key& R,
            const crypto::public_key& A,
            const std::optional<crypto::public_key>& B,
            const crypto::public_key& D,
            const crypto::secret_key& r,
            crypto::signature& sig) = 0;

    virtual bool open_tx(
            crypto::secret_key& tx_key,
            cryptonote::txversion txversion,
            cryptonote::txtype txtype) = 0;

    virtual void get_transaction_prefix_hash(
            const cryptonote::transaction_prefix& tx, crypto::hash& h) = 0;

    virtual bool encrypt_payment_id(
            crypto::hash8& payment_id,
            const crypto::public_key& public_key,
            const crypto::secret_key& secret_key) = 0;
    bool decrypt_payment_id(
            crypto::hash8& payment_id,
            const crypto::public_key& public_key,
            const crypto::secret_key& secret_key) {
        // Encryption and decryption are the same operation (xor with a key)
        return encrypt_payment_id(payment_id, public_key, secret_key);
    }

    virtual rct::key genCommitmentMask(const rct::key& amount_key) = 0;

    virtual bool ecdhEncode(
            rct::ecdhTuple& unmasked, const rct::key& sharedSec, bool short_amount) = 0;
    virtual bool ecdhDecode(
            rct::ecdhTuple& masked, const rct::key& sharedSec, bool short_amount) = 0;

    virtual bool generate_output_ephemeral_keys(
            size_t tx_version,
            bool& found_change,
            const cryptonote::account_keys& sender_account_keys,
            const crypto::public_key& txkey_pub,
            const crypto::secret_key& tx_key,
            const cryptonote::tx_destination_entry& dst_entr,
            const std::optional<cryptonote::tx_destination_entry>& change_addr,
            size_t output_index,
            bool need_additional_txkeys,
            const std::vector<crypto::secret_key>& additional_tx_keys,
            std::vector<crypto::public_key>& additional_tx_public_keys,
            std::vector<rct::key>& amount_keys,
            crypto::public_key& out_eph_public_key) = 0;

    virtual bool clsag_prehash(
            const std::string& blob,
            size_t inputs_size,
            size_t outputs_size,
            const rct::keyV& hashes,
            const rct::ctkeyV& outPk,
            rct::key& prehash) = 0;
    virtual bool clsag_prepare(
            const rct::key& p,
            const rct::key& z,
            rct::key& I,
            rct::key& D,
            const rct::key& H,
            rct::key& a,
            rct::key& aG,
            rct::key& aH) = 0;
    virtual bool clsag_hash(const rct::keyV& data, rct::key& hash) = 0;
    virtual bool clsag_sign(
            const rct::key& c,
            const rct::key& a,
            const rct::key& p,
            const rct::key& z,
            const rct::key& mu_P,
            const rct::key& mu_C,
            rct::key& s) = 0;

    // Retrieves the tx secret key from the device; this should only be called for staking
    // transactions.  `key` will be whatever we got back from the device, but for hardware
    // devices that value may be encrypted or null; this call should update it to the actual
    // secret key value, if necessary.
    virtual bool update_staking_tx_secret_key(crypto::secret_key& key) = 0;

    virtual bool close_tx() = 0;

    virtual bool has_ki_cold_sync() const { return false; }
    virtual bool has_tx_cold_sign() const { return false; }
    virtual bool has_ki_live_refresh() const { return true; }
    virtual bool compute_key_image(
            const cryptonote::account_keys& ack,
            const crypto::public_key& out_key,
            const crypto::key_derivation& recv_derivation,
            size_t real_output_index,
            const cryptonote::subaddress_index& received_index,
            cryptonote::keypair& in_ephemeral,
            crypto::key_image& ki) {
        return false;
    }
    virtual void computing_key_images(bool started){};
    virtual void set_network_type(cryptonote::network_type network_type) {}
    virtual void display_address(
            const cryptonote::subaddress_index& index,
            const std::optional<crypto::hash8>& payment_id) {}

  protected:
    mode mode_ = mode::NONE;
};

struct mode_resetter {
    device& hwref;
    mode_resetter(hw::device& dev) : hwref(dev) {}
    ~mode_resetter() { hwref.set_mode(hw::device::mode::NONE); }
};

class device_registry {
  private:
    std::map<std::string, std::unique_ptr<device>> registry;

  public:
    device_registry();
    bool register_device(const std::string& device_name, device* hw_device);
    device& get_device(const std::string& device_descriptor);
};

device& get_device(const std::string& device_descriptor);
bool register_device(const std::string& device_name, device* hw_device);
}  // namespace hw
