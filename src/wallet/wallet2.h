// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2018, The Loki Project
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
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#pragma once

#include <memory>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/list.hpp>
#include <boost/serialization/deque.hpp>
#include <atomic>
#include <random>

#include "cryptonote_basic/account.h"
#include "cryptonote_basic/account_boost_serialization.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_core/oxen_name_system.h"
#include "common/unordered_containers_boost_serialization.h"
#include "common/file.h"
#include "crypto/chacha.h"
#include "crypto/hash.h"
#include "ringct/rctTypes.h"
#include "ringct/rctOps.h"
#include "checkpoints/checkpoints.h"
#include "serialization/pair.h"

#include "wallet_errors.h"
#include "common/password.h"
#include "node_rpc_proxy.h"
#ifdef WALLET_ENABLE_MMS
#include "message_store.h"
// Intended to make the ifdefs a bit less cumbersome where we need to pass an extra arg with MMS.
// E.g. `foo(a, b IF_MMS(, c))`  becomes `foo(a, b, c)` undef MMS and `foo(a,b)` without MMS.
#define ENABLE_IF_MMS(...) __VA_ARGS__
#else
#define ENABLE_IF_MMS(...)
#endif

#ifdef ENABLE_LIGHT_WALLET
#include "wallet_light_rpc.h"
// Same as above, but for light wallet args
#define ENABLE_IF_LIGHT_WALLET(...) __VA_ARGS__
#else
#define ENABLE_IF_LIGHT_WALLET(...)
#endif

#include "tx_construction_data.h"
#include "tx_sets.h"
#include "transfer_destination.h"
#include "transfer_details.h"
#include "transfer_view.h"
#include "multisig_info.h"
#include "pending_tx.h"
#include "multisig_sig.h"

#include "epee/wipeable_string.h"

#include "rpc/http_client.h"

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "wallet.wallet2"

#define SUBADDRESS_LOOKAHEAD_MAJOR 50
#define SUBADDRESS_LOOKAHEAD_MINOR 200

class Serialization_portability_wallet_Test;
class wallet_accessor_test;

OXEN_RPC_DOC_INTROSPECT
namespace tools
{
  class ringdb;
  class wallet2;
  class Notify;

  class gamma_picker
  {
  public:
    uint64_t pick();
    gamma_picker(const std::vector<uint64_t> &rct_offsets);
    gamma_picker(const std::vector<uint64_t> &rct_offsets, double shape, double scale);
    uint64_t get_num_rct_outs() const { return num_rct_outputs; }

  private:
    struct gamma_engine
    {
      typedef uint64_t result_type;
      static constexpr result_type min() { return 0; }
      static constexpr result_type max() { return std::numeric_limits<result_type>::max(); }
      result_type operator()() { return crypto::rand<result_type>(); }
    } engine;

private:
    std::gamma_distribution<double> gamma;
    const std::vector<uint64_t> &rct_offsets;
    const uint64_t *begin, *end;
    uint64_t num_rct_outputs;
    double average_output_time;
  };

  class wallet_keys_unlocker
  {
  public:
    wallet_keys_unlocker(wallet2 &w, const std::optional<tools::password_container> &password);
    wallet_keys_unlocker(wallet2 &w, bool locked, const epee::wipeable_string &password);
    ~wallet_keys_unlocker();
  private:
    wallet2 &w;
    bool locked;
    crypto::chacha_key key;
    static std::mutex lockers_mutex;
    static unsigned int lockers;
  };

  class i_wallet2_callback
  {
  public:
    // Full wallet callbacks
    virtual void on_new_block(uint64_t height, const cryptonote::block& block) {}
    virtual void on_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index, uint64_t unlock_time, bool blink) {}
    virtual void on_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index) {}
    virtual void on_money_spent(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& in_tx, uint64_t amount, const cryptonote::transaction& spend_tx, const cryptonote::subaddress_index& subaddr_index) {}
    virtual void on_skip_transaction(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx) {}
    virtual std::optional<epee::wipeable_string> on_get_password(const char *reason) { return std::nullopt; }
    // Light wallet callbacks
    virtual void on_lw_new_block(uint64_t height) {}
    virtual void on_lw_money_received(uint64_t height, const crypto::hash &txid, uint64_t amount) {}
    virtual void on_lw_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, uint64_t amount) {}
    virtual void on_lw_money_spent(uint64_t height, const crypto::hash &txid, uint64_t amount) {}
    // Device callbacks
    virtual void on_device_button_request(uint64_t code) {}
    virtual void on_device_button_pressed() {}
    virtual std::optional<epee::wipeable_string> on_device_pin_request() { return std::nullopt; }
    virtual std::optional<epee::wipeable_string> on_device_passphrase_request(bool& on_device) { on_device = true; return std::nullopt; }
    virtual void on_device_progress(const hw::device_progress& event) {};
    // Common callbacks
    virtual void on_pool_tx_removed(const crypto::hash &txid) {}
    virtual ~i_wallet2_callback() {}
  };

  class wallet_device_callback : public hw::i_device_callback
  {
  public:
    wallet_device_callback(wallet2 * wallet): wallet(wallet) {};
    void on_button_request(uint64_t code=0) override;
    void on_button_pressed() override;
    std::optional<epee::wipeable_string> on_pin_request() override;
    std::optional<epee::wipeable_string> on_passphrase_request(bool& on_device) override;
    void on_progress(const hw::device_progress& event) override;
  private:
    wallet2 * wallet;
  };

  struct tx_money_got_in_out
  {
    cryptonote::subaddress_index index;
    wallet::pay_type type;
    uint64_t amount;
    uint64_t unlock_time;
  };

  class hashchain
  {
  public:
    hashchain(): m_genesis(crypto::null_hash), m_offset(0) {}

    size_t size() const { return m_blockchain.size() + m_offset; }
    size_t offset() const { return m_offset; }
    const crypto::hash &genesis() const { return m_genesis; }
    void push_back(const crypto::hash &hash) { if (m_offset == 0 && m_blockchain.empty()) m_genesis = hash; m_blockchain.push_back(hash); }
    bool is_in_bounds(size_t idx) const { return idx >= m_offset && idx < size(); }
    const crypto::hash &operator[](size_t idx) const { return m_blockchain[idx - m_offset]; }
    crypto::hash &operator[](size_t idx) { return m_blockchain[idx - m_offset]; }
    void crop(size_t height) { m_blockchain.resize(height - m_offset); }
    void clear() { m_offset = 0; m_blockchain.clear(); }
    bool empty() const { return m_blockchain.empty() && m_offset == 0; }
    void trim(size_t height) { while (height > m_offset && m_blockchain.size() > 1) { m_blockchain.pop_front(); ++m_offset; } m_blockchain.shrink_to_fit(); }
    void refill(const crypto::hash &hash) { m_blockchain.push_back(hash); --m_offset; }

    template <class t_archive>
    void serialize(t_archive &a, const unsigned int ver)
    {
      a & m_offset;
      a & m_genesis;
      a & m_blockchain;
    }

  private:
    size_t m_offset;
    crypto::hash m_genesis;
    std::deque<crypto::hash> m_blockchain;
  };

  //enum class stake_check_result { allowed, not_allowed, try_later };

  enum tx_priority
  {
    tx_priority_default     = 0,
    tx_priority_unimportant = 1,
    tx_priority_normal      = 2,
    tx_priority_elevated    = 3,
    tx_priority_priority    = 4,
    tx_priority_blink       = 5,
    tx_priority_last
  };

  class wallet_keys_unlocker;
  class wallet2
  {
    friend class ::Serialization_portability_wallet_Test;
    friend class ::wallet_accessor_test;
    friend class wallet_keys_unlocker;
    friend class wallet_device_callback;
  public:
    static constexpr std::chrono::seconds rpc_timeout = 30s;
    enum RefreshType {
      RefreshFull,
      RefreshOptimizeCoinbase,
      RefreshNoCoinbase,
      RefreshDefault = RefreshOptimizeCoinbase,
    };

    enum AskPasswordType {
      AskPasswordNever = 0,
      AskPasswordOnAction = 1,
      AskPasswordToDecrypt = 2,
    };

    static const char* tr(const char* str);
    static const char *ERR_MSG_NETWORK_VERSION_QUERY_FAILED;
    static const char *ERR_MSG_NETWORK_HEIGHT_QUERY_FAILED;
    static const char *ERR_MSG_SERVICE_NODE_LIST_QUERY_FAILED;
    static const char *ERR_MSG_TOO_MANY_TXS_CONSTRUCTED;
    static const char *ERR_MSG_EXCEPTION_THROWN;

    static bool has_testnet_option(const boost::program_options::variables_map& vm);
    static bool has_devnet_option(const boost::program_options::variables_map& vm);
    static std::vector<std::string> has_deprecated_options(const boost::program_options::variables_map& vm);
    static bool has_disable_rpc_long_poll(const boost::program_options::variables_map& vm);
    static std::string device_name_option(const boost::program_options::variables_map& vm);
    static std::string device_derivation_path_option(const boost::program_options::variables_map &vm);
    static void init_options(boost::program_options::options_description& desc_params, boost::program_options::options_description& hidden_params);

    //! Uses stdin and stdout. Returns a wallet2 if no errors.
    static std::pair<std::unique_ptr<wallet2>, password_container>
    make_from_json(
        const boost::program_options::variables_map& vm,
        bool unattended,
        const fs::path& json_file,
        const std::function<std::optional<password_container>(const char *, bool)> &password_prompter);

    //! Uses stdin and stdout. Returns a wallet2 and password for `wallet_file` if no errors.
    static std::pair<std::unique_ptr<wallet2>, password_container>
    make_from_file(
        const boost::program_options::variables_map& vm,
        bool unattended,
        const fs::path& wallet_file,
        const std::function<std::optional<password_container>(const char *, bool)> &password_prompter);

    //! Uses stdin and stdout. Returns a wallet2 and password for wallet with no file if no errors.
    static std::pair<std::unique_ptr<wallet2>, password_container>
    make_new(
        const boost::program_options::variables_map& vm,
        bool unattended,
        const std::function<std::optional<password_container>(const char *, bool)> &password_prompter);

    //! Just parses variables.
    static std::unique_ptr<wallet2> make_dummy(
        const boost::program_options::variables_map& vm,
        bool unattended,
        const std::function<std::optional<password_container>(const char *, bool)> &password_prompter);

    static bool verify_password(const fs::path& keys_file_name, const epee::wipeable_string& password, bool no_spend_key, hw::device &hwdev, uint64_t kdf_rounds);
    static bool query_device(hw::device::type& device_type, const fs::path& keys_file_name, const epee::wipeable_string& password, uint64_t kdf_rounds = 1);

    wallet2(cryptonote::network_type nettype = cryptonote::network_type::MAINNET, uint64_t kdf_rounds = 1, bool unattended = false);
    ~wallet2();

    struct tx_scan_info_t
    {
      cryptonote::keypair in_ephemeral;
      crypto::key_image ki;
      rct::key mask;
      uint64_t amount;
      uint64_t money_transfered;
      uint64_t unlock_time;
      bool error;
      std::optional<cryptonote::subaddress_receive_info> received;

      tx_scan_info_t(): amount(0), money_transfered(0), error(true) {}
    };

    struct payment_details
    {
      crypto::hash m_tx_hash;
      uint64_t m_amount;
      uint64_t m_fee;
      uint64_t m_block_height;
      uint64_t m_unlock_time;
      uint64_t m_timestamp;
      wallet::pay_type m_type;
      cryptonote::subaddress_index m_subaddr_index;
      bool m_unmined_blink;
      bool m_was_blink;

      bool is_coinbase() const { return ((m_type == wallet::pay_type::miner) || (m_type == wallet::pay_type::service_node) || (m_type == wallet::pay_type::governance)); }
    };

    struct address_tx : payment_details
    {
      bool m_mempool;
      bool m_incoming;
    };

    struct pool_payment_details
    {
      payment_details m_pd;
      bool m_double_spend_seen;
    };

    struct unconfirmed_transfer_details
    {
      cryptonote::transaction_prefix m_tx;
      uint64_t m_amount_in;
      uint64_t m_amount_out;
      uint64_t m_change;
      time_t m_sent_time;
      std::vector<cryptonote::tx_destination_entry> m_dests;
      crypto::hash m_payment_id;
      enum { pending, pending_not_in_pool, failed } m_state;
      uint64_t m_timestamp;
      uint32_t m_subaddr_account;   // subaddress account of your wallet to be used in this transfer
      std::set<uint32_t> m_subaddr_indices;  // set of address indices used as inputs in this transfer
      std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> m_rings; // relative
      wallet::pay_type m_pay_type = wallet::pay_type::out;
    };

    struct confirmed_transfer_details
    {
      uint64_t m_amount_in = 0;
      uint64_t m_amount_out = 0;
      uint64_t m_change = std::numeric_limits<std::uint64_t>::max();
      uint64_t m_block_height = 0;
      std::vector<cryptonote::tx_destination_entry> m_dests;
      crypto::hash m_payment_id = crypto::null_hash;
      uint64_t m_timestamp = 0;
      uint64_t m_unlock_time = 0; // NOTE(oxen): Not used after TX v2.
      std::vector<uint64_t> m_unlock_times;
      uint32_t m_subaddr_account = std::numeric_limits<uint32_t>::max(); // subaddress account of your wallet to be used in this transfer
      std::set<uint32_t> m_subaddr_indices;  // set of address indices used as inputs in this transfer
      std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> m_rings; // relative
      wallet::pay_type m_pay_type = wallet::pay_type::out;

      confirmed_transfer_details() = default;
      confirmed_transfer_details(const unconfirmed_transfer_details &utd, uint64_t height)
      : m_amount_in(utd.m_amount_in)
      , m_amount_out(utd.m_amount_out)
      , m_change(utd.m_change)
      , m_block_height(height)
      , m_dests(utd.m_dests)
      , m_payment_id(utd.m_payment_id)
      , m_timestamp(utd.m_timestamp)
      , m_unlock_time(utd.m_tx.unlock_time)
      , m_unlock_times(utd.m_tx.output_unlock_times)
      , m_subaddr_account(utd.m_subaddr_account)
      , m_subaddr_indices(utd.m_subaddr_indices)
      , m_rings(utd.m_rings)
      , m_pay_type(utd.m_pay_type)
      {
      }
    };

    using transfer_details = wallet::transfer_details;
    using transfer_container = std::vector<transfer_details>;
    using pending_tx = wallet::pending_tx;
    using unsigned_tx_set = wallet::unsigned_tx_set;
    using signed_tx_set = wallet::signed_tx_set;
    using multisig_tx_set = wallet::multisig_tx_set;
    using payment_container = std::unordered_multimap<crypto::hash, payment_details>;

    struct keys_file_data
    {
      crypto::chacha_iv iv;
      std::string account_data;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(iv)
        FIELD(account_data)
      END_SERIALIZE()
    };

    struct cache_file_data
    {
      crypto::chacha_iv iv;
      std::string cache_data;

      BEGIN_SERIALIZE_OBJECT()
        FIELD(iv)
        FIELD(cache_data)
      END_SERIALIZE()
    };
    
    // GUI Address book
    struct address_book_row
    {
      cryptonote::account_public_address m_address;
      crypto::hash8 m_payment_id;
      std::string m_description;   
      bool m_is_subaddress;
      bool m_has_payment_id;
    };

    struct reserve_proof_entry
    {
      crypto::hash txid;
      uint64_t index_in_tx;
      crypto::public_key shared_secret;
      crypto::key_image key_image;
      crypto::signature shared_secret_sig;
      crypto::signature key_image_sig;
    };

    typedef std::tuple<uint64_t, crypto::public_key, rct::key> get_outs_entry;

    struct parsed_block
    {
      crypto::hash hash;
      cryptonote::block block;
      std::vector<cryptonote::transaction> txes;
      cryptonote::rpc::GET_BLOCKS_FAST::block_output_indices o_indices;
      bool error;
    };

    struct is_out_data
    {
      crypto::public_key pkey;
      crypto::key_derivation derivation;
      std::vector<std::optional<cryptonote::subaddress_receive_info>> received;
    };

    struct tx_cache_data
    {
      std::vector<cryptonote::tx_extra_field> tx_extra_fields;
      std::vector<is_out_data> primary;
      std::vector<is_out_data> additional;

      bool empty() const { return tx_extra_fields.empty() && primary.empty() && additional.empty(); }
    };

    /*!
     * \brief  Generates a wallet or restores one.
     * \param  wallet_              Name of wallet file
     * \param  password             Password of wallet file
     * \param  multisig_data        The multisig restore info and keys
     * \param  create_address_file  Whether to create an address file (defaults to yes)
     */
    void generate(const fs::path& wallet_, const epee::wipeable_string& password,
      const epee::wipeable_string& multisig_data, bool create_address_file = true);

    /*!
     * \brief Generates a wallet or restores one.
     * \param  wallet_              Name of wallet file
     * \param  password             Password of wallet file
     * \param  recovery_param       If it is a restore, the recovery key
     * \param  recover              Whether it is a restore
     * \param  two_random           Whether it is a non-deterministic wallet
     * \param  create_address_file  Whether to create an address file (defaults to yes)
     * \return                      The secret key of the generated wallet
     */
    crypto::secret_key generate(const fs::path& wallet, const epee::wipeable_string& password,
      const crypto::secret_key& recovery_param = crypto::secret_key(), bool recover = false,
      bool two_random = false, bool create_address_file = true);
    /*!
     * \brief Creates a wallet from a public address and a spend/view secret key pair.
     * \param  wallet_                 Name of wallet file
     * \param  password                Password of wallet file
     * \param  account_public_address  The account's public address
     * \param  spendkey                spend secret key
     * \param  viewkey                 view secret key
     * \param  create_address_file     Whether to create an address file (defaults to yes)
     */
    void generate(const fs::path& wallet, const epee::wipeable_string& password,
      const cryptonote::account_public_address &account_public_address,
      const crypto::secret_key& spendkey, const crypto::secret_key& viewkey, bool create_address_file = true);
    /*!
     * \brief Creates a watch only wallet from a public address and a view secret key.
     * \param  wallet_                 Name of wallet file
     * \param  password                Password of wallet file
     * \param  account_public_address  The account's public address
     * \param  viewkey                 view secret key
     * \param  create_address_file     Whether to create an address file
     */
    void generate(const fs::path& wallet, const epee::wipeable_string& password,
      const cryptonote::account_public_address &account_public_address,
      const crypto::secret_key& viewkey = crypto::secret_key(), bool create_address_file = true);
    /*!
     * \brief Restore a wallet from a hardware device
     * \param  wallet_        Name of wallet file
     * \param  password       Password of wallet file
     * \param  device_name    name of HW to use
     * \param  create_address_file     Whether to create an address file
     * \param  hwdev_label    if non-nullopt, create a [wallet].hwdev.txt containing the
     *                        specified string content (which can be empty).  Used to identify
     *                        a hardware-backed wallet file with an optional comment.
     * \param  status_callback callback to invoke with progress messages to display to the user
     */
    void restore_from_device(const fs::path& wallet_, const epee::wipeable_string& password, const std::string &device_name,
            bool create_address_file = false, std::optional<std::string> hwdev_label = std::nullopt, std::function<void(std::string msg)> status_callback = {});

    /*!
     * \brief Creates a multisig wallet
     * \return empty if done, non empty if we need to send another string
     * to other participants
     */
    std::string make_multisig(const epee::wipeable_string &password,
      const std::vector<std::string> &info,
      uint32_t threshold);
    /*!
     * \brief Creates a multisig wallet
     * \return empty if done, non empty if we need to send another string
     * to other participants
     */
    std::string make_multisig(const epee::wipeable_string &password,
      const std::vector<crypto::secret_key> &view_keys,
      const std::vector<crypto::public_key> &spend_keys,
      uint32_t threshold);
    std::string exchange_multisig_keys(const epee::wipeable_string &password,
      const std::vector<std::string> &info);
    /*!
     * \brief Any but first round of keys exchange
     */
    std::string exchange_multisig_keys(const epee::wipeable_string &password,
      std::unordered_set<crypto::public_key> pkeys,
      std::vector<crypto::public_key> signers);
    /*!
     * \brief Finalizes creation of a multisig wallet
     */
    bool finalize_multisig(const epee::wipeable_string &password, const std::vector<std::string> &info);
    /*!
     * \brief Finalizes creation of a multisig wallet
     */
    bool finalize_multisig(const epee::wipeable_string &password, const std::unordered_set<crypto::public_key> &pkeys, std::vector<crypto::public_key> signers);
    /*!
     * Get a packaged multisig information string
     */
    std::string get_multisig_info() const;
    /*!
     * Verifies and extracts keys from a packaged multisig information string
     */
    static bool verify_multisig_info(const std::string &data, crypto::secret_key &skey, crypto::public_key &pkey);
    /*!
     * Verifies and extracts keys from a packaged multisig information string
     */
    static bool verify_extra_multisig_info(const std::string &data, std::unordered_set<crypto::public_key> &pkeys, crypto::public_key &signer);
    /*!
     * Export multisig info
     * This will generate and remember new k values
     */
    std::string export_multisig();
    /*!
     * Import a set of multisig info from multisig partners
     * \return the number of inputs which were imported
     */
    size_t import_multisig(std::vector<std::string> info);
    /*!
     * \brief Rewrites to the wallet file for wallet upgrade (doesn't generate key, assumes it's already there)
     * \param wallet_name Name of wallet file (should exist)
     * \param password    Password for wallet file
     */
    void rewrite(const fs::path& wallet_name, const epee::wipeable_string& password);
    void write_watch_only_wallet(const fs::path& wallet_name, const epee::wipeable_string& password, fs::path& new_keys_filename);
    void load(const fs::path& wallet, const epee::wipeable_string& password, const std::string& keys_buf = "", const std::string& cache_buf = "");
    void store();
    /*!
     * \brief store_to  Stores wallet to another file(s), deleting old ones
     * \param path      Path to the wallet file (keys and address filenames will be generated based on this filename)
     * \param password  Password to protect new wallet (TODO: probably better save the password in the wallet object?)
     */
    void store_to(const fs::path &path, const epee::wipeable_string &password);
    /*!
     * \brief get_keys_file_data  Get wallet keys data which can be stored to a wallet file.
     * \param password            Password of the encrypted wallet buffer (TODO: probably better save the password in the wallet object?)
     * \param watch_only          true to include only view key, false to include both spend and view keys
     * \return                    Encrypted wallet keys data which can be stored to a wallet file
     */
    std::optional<wallet2::keys_file_data> get_keys_file_data(const epee::wipeable_string& password, bool watch_only);
    /*!
     * \brief get_cache_file_data   Get wallet cache data which can be stored to a wallet file.
     * \param password              Password to protect the wallet cache data (TODO: probably better save the password in the wallet object?)
     * \return                      Encrypted wallet cache data which can be stored to a wallet file
     */
    std::optional<wallet2::cache_file_data> get_cache_file_data(const epee::wipeable_string& password);

    const fs::path& path() const;

    /*!
     * \brief verifies given password is correct for default wallet keys file
     */
    bool verify_password(const epee::wipeable_string& password);
    cryptonote::account_base& get_account(){return m_account;}
    const cryptonote::account_base& get_account()const{return m_account;}

    void encrypt_keys(const crypto::chacha_key &key);
    void encrypt_keys(const epee::wipeable_string &password);
    void decrypt_keys(const crypto::chacha_key &key);
    void decrypt_keys(const epee::wipeable_string &password);

    void set_refresh_from_block_height(uint64_t height) {m_refresh_from_block_height = height;}
    uint64_t get_refresh_from_block_height() const {return m_refresh_from_block_height;}

    void explicit_refresh_from_block_height(bool expl) {m_explicit_refresh_from_block_height = expl;}
    bool explicit_refresh_from_block_height() const {return m_explicit_refresh_from_block_height;}

    bool deinit();
    bool init(
        std::string daemon_address,
        std::optional<tools::login> daemon_login = std::nullopt,
        std::string proxy = "",
        uint64_t upper_transaction_weight_limit = 0,
        bool trusted_daemon = true);
    bool set_daemon(
        std::string daemon_address,
        std::optional<tools::login> daemon_login = std::nullopt,
        std::string proxy = "",
        bool trusted_daemon = true);

    void stop() {
        m_run.store(false, std::memory_order_relaxed);
#ifdef WALLET_ENABLE_MMS
        m_message_store.stop();
#endif
    }

    i_wallet2_callback* callback() const { return m_callback; }
    void callback(i_wallet2_callback* callback) { m_callback = callback; }

    bool is_trusted_daemon() const { return m_trusted_daemon; }
    void set_trusted_daemon(bool trusted) { m_trusted_daemon = trusted; }

    /*!
     * \brief Checks if deterministic wallet
     */
    bool is_deterministic() const;
    bool get_seed(epee::wipeable_string& electrum_words, const epee::wipeable_string &passphrase = epee::wipeable_string()) const;

#ifdef ENABLE_LIGHT_WALLET
    /*!
    * \brief Checks if light wallet. A light wallet sends view key to a server where the blockchain is scanned.
    */
    bool light_wallet() const { return m_light_wallet; }
    void set_light_wallet(bool light_wallet) { m_light_wallet = light_wallet; }
    uint64_t get_light_wallet_scanned_block_height() const { return m_light_wallet_scanned_block_height; }
    uint64_t get_light_wallet_blockchain_height() const { return m_light_wallet_blockchain_height; }
#endif

    /*!
     * \brief Gets the seed language
     */
    const std::string &get_seed_language() const;
    /*!
     * \brief Sets the seed language
     */
    void set_seed_language(const std::string &language);

    // Subaddress scheme
    cryptonote::account_public_address get_subaddress(const cryptonote::subaddress_index& index) const;
    cryptonote::account_public_address get_address() const { return get_subaddress({0,0}); }
    std::optional<cryptonote::subaddress_index> get_subaddress_index(const cryptonote::account_public_address& address) const;
    crypto::public_key get_subaddress_spend_public_key(const cryptonote::subaddress_index& index) const;
    std::vector<crypto::public_key> get_subaddress_spend_public_keys(uint32_t account, uint32_t begin, uint32_t end) const;
    std::string get_subaddress_as_str(const cryptonote::subaddress_index& index) const;
    std::string get_address_as_str() const { return get_subaddress_as_str({0, 0}); }
    std::string get_integrated_address_as_str(const crypto::hash8& payment_id) const;
    void add_subaddress_account(const std::string& label);
    size_t get_num_subaddress_accounts() const { return m_subaddress_labels.size(); }
    size_t get_num_subaddresses(uint32_t index_major) const { return index_major < m_subaddress_labels.size() ? m_subaddress_labels[index_major].size() : 0; }
    void add_subaddress(uint32_t index_major, const std::string& label); // throws when index is out of bound
    void expand_subaddresses(const cryptonote::subaddress_index& index);
    std::string get_subaddress_label(const cryptonote::subaddress_index& index) const;
    void set_subaddress_label(const cryptonote::subaddress_index &index, const std::string &label);
    void set_subaddress_lookahead(size_t major, size_t minor);
    std::pair<size_t, size_t> get_subaddress_lookahead() const { return {m_subaddress_lookahead_major, m_subaddress_lookahead_minor}; }
    bool contains_address(const cryptonote::account_public_address& address) const;
    bool contains_key_image(const crypto::key_image& key_image) const;
    bool generate_signature_for_request_stake_unlock(crypto::key_image const &key_image, crypto::signature &signature) const;
    /*!
     * \brief Tells if the wallet file is deprecated.
     */
    bool is_deprecated() const;
    void refresh(bool trusted_daemon);
    void refresh(bool trusted_daemon, uint64_t start_height, uint64_t & blocks_fetched);
    void refresh(bool trusted_daemon, uint64_t start_height, uint64_t & blocks_fetched, bool& received_money, bool check_pool = true);
    bool refresh(bool trusted_daemon, uint64_t & blocks_fetched, bool& received_money, bool& ok);

    void set_refresh_type(RefreshType refresh_type) { m_refresh_type = refresh_type; }
    RefreshType get_refresh_type() const { return m_refresh_type; }

    cryptonote::network_type nettype() const { return m_nettype; }
    bool watch_only() const { return m_watch_only; }
    bool multisig(bool *ready = NULL, uint32_t *threshold = NULL, uint32_t *total = NULL) const;
    bool has_multisig_partial_key_images() const;
    bool has_unknown_key_images() const;
    bool get_multisig_seed(epee::wipeable_string& seed, const epee::wipeable_string &passphrase = std::string(), bool raw = true) const;
    bool key_on_device() const { return get_device_type() != hw::device::type::SOFTWARE; }
    hw::device::type get_device_type() const { return m_key_device_type; }
    bool reconnect_device();

    // locked & unlocked balance of given or current subaddress account
    uint64_t balance(uint32_t subaddr_index_major, bool strict) const;
    uint64_t unlocked_balance(uint32_t subaddr_index_major, bool strict, uint64_t *blocks_to_unlock = NULL, uint64_t *time_to_unlock = NULL) const;
    // locked & unlocked balance per subaddress of given or current subaddress account
    std::map<uint32_t, uint64_t> balance_per_subaddress(uint32_t subaddr_index_major, bool strict) const;
    std::map<uint32_t, std::pair<uint64_t, std::pair<uint64_t, uint64_t>>> unlocked_balance_per_subaddress(uint32_t subaddr_index_major, bool strict) const;
    // all locked & unlocked balances of all subaddress accounts
    uint64_t balance_all(bool strict) const;
    uint64_t unlocked_balance_all(bool strict, uint64_t *blocks_to_unlock = NULL, uint64_t *time_to_unlock = NULL) const;
    void transfer_selected_rct(std::vector<cryptonote::tx_destination_entry> dsts, const std::vector<size_t>& selected_transfers, size_t fake_outputs_count,
      std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs,
      uint64_t unlock_time, uint64_t fee, const std::vector<uint8_t>& extra, cryptonote::transaction& tx, pending_tx &ptx, const rct::RCTConfig &rct_config, const cryptonote::oxen_construct_tx_params &oxen_tx_params);

    void commit_tx(pending_tx& ptx_vector, bool blink = false);
    void commit_tx(std::vector<pending_tx>& ptx_vector, bool blink = false);
    bool save_tx(const std::vector<pending_tx>& ptx_vector, const fs::path& filename) const;
    std::string dump_tx_to_str(const std::vector<pending_tx> &ptx_vector) const;
    std::string save_multisig_tx(multisig_tx_set txs);
    bool save_multisig_tx(const multisig_tx_set& txs, const fs::path& filename);
    std::string save_multisig_tx(const std::vector<pending_tx>& ptx_vector);
    bool save_multisig_tx(const std::vector<pending_tx>& ptx_vector, const fs::path& filename);
    multisig_tx_set make_multisig_tx_set(const std::vector<pending_tx>& ptx_vector) const;
    // load unsigned tx from file and sign it. Takes confirmation callback as argument. Used by the cli wallet
    bool sign_tx(const fs::path& unsigned_filename, const fs::path& signed_filename, std::vector<pending_tx> &ptx, std::function<bool(const unsigned_tx_set&)> accept_func = NULL, bool export_raw = false);
    // sign unsigned tx. Takes unsigned_tx_set as argument. Used by GUI
    bool sign_tx(unsigned_tx_set& exported_txs, const fs::path& signed_filename, std::vector<pending_tx> &ptx, bool export_raw = false);
    bool sign_tx(unsigned_tx_set &exported_txs, std::vector<pending_tx> &ptx, signed_tx_set &signed_txs);
    std::string sign_tx_dump_to_str(unsigned_tx_set &exported_txs, std::vector<pending_tx> &ptx, signed_tx_set &signed_txes);
    // load unsigned_tx_set from file. 
    bool load_unsigned_tx(const fs::path& unsigned_filename, unsigned_tx_set& exported_txs) const;
    bool parse_unsigned_tx_from_str(std::string_view unsigned_tx_st, unsigned_tx_set &exported_txs) const;
    bool load_tx(const fs::path& signed_filename, std::vector<pending_tx>& ptx, std::function<bool(const signed_tx_set&)> accept_func = NULL);
    bool parse_tx_from_str(std::string_view signed_tx_st, std::vector<pending_tx> &ptx, std::function<bool(const signed_tx_set &)> accept_func);
    std::vector<pending_tx> create_transactions_2(std::vector<cryptonote::tx_destination_entry> dsts, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra_base, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices, cryptonote::oxen_construct_tx_params &tx_params);

    std::vector<pending_tx> create_transactions_all(uint64_t below, const cryptonote::account_public_address &address, bool is_subaddress, const size_t outputs, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices, cryptonote::txtype tx_type = cryptonote::txtype::standard);
    std::vector<pending_tx> create_transactions_single(const crypto::key_image &ki, const cryptonote::account_public_address &address, bool is_subaddress, const size_t outputs, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, cryptonote::txtype tx_type = cryptonote::txtype::standard);
    std::vector<pending_tx> create_transactions_from(const cryptonote::account_public_address &address, bool is_subaddress, const size_t outputs, std::vector<size_t> unused_transfers_indices, std::vector<size_t> unused_dust_indices, const size_t fake_outs_count, const uint64_t unlock_time, uint32_t priority, const std::vector<uint8_t>& extra, cryptonote::txtype tx_type = cryptonote::txtype::standard);

    bool sanity_check(const std::vector<pending_tx> &ptx_vector, std::vector<cryptonote::tx_destination_entry> dsts) const;
    void cold_tx_aux_import(const std::vector<pending_tx>& ptx, const std::vector<std::string>& tx_device_aux);
    void cold_sign_tx(const std::vector<pending_tx>& ptx_vector, signed_tx_set &exported_txs, std::vector<cryptonote::address_parse_info> const &dsts_info, std::vector<std::string> & tx_device_aux);
    uint64_t cold_key_image_sync(uint64_t &spent, uint64_t &unspent);
    void device_show_address(uint32_t account_index, uint32_t address_index, const std::optional<crypto::hash8> &payment_id);
    bool parse_multisig_tx_from_str(std::string_view multisig_tx_st, multisig_tx_set &exported_txs) const;
    bool load_multisig_tx(std::string blob, multisig_tx_set &exported_txs, std::function<bool(const multisig_tx_set&)> accept_func = NULL);
    bool load_multisig_tx_from_file(const fs::path& filename, multisig_tx_set &exported_txs, std::function<bool(const multisig_tx_set&)> accept_func = NULL);
    bool sign_multisig_tx_from_file(const fs::path& filename, std::vector<crypto::hash> &txids, std::function<bool(const multisig_tx_set&)> accept_func);
    bool sign_multisig_tx(multisig_tx_set &exported_txs, std::vector<crypto::hash> &txids);
    bool sign_multisig_tx_to_file(multisig_tx_set &exported_txs, const fs::path& filename, std::vector<crypto::hash> &txids);
    std::vector<pending_tx> create_unmixable_sweep_transactions();
    void discard_unmixable_outputs();
    bool check_connection(cryptonote::rpc::version_t *version = nullptr, bool *ssl = nullptr, bool throw_on_http_error = false);
    wallet::transfer_view make_transfer_view(const crypto::hash &txid, const crypto::hash &payment_id, const wallet2::payment_details &pd) const;
    wallet::transfer_view make_transfer_view(const crypto::hash &txid, const tools::wallet2::confirmed_transfer_details &pd) const;
    wallet::transfer_view make_transfer_view(const crypto::hash &txid, const tools::wallet2::unconfirmed_transfer_details &pd) const;
    wallet::transfer_view make_transfer_view(const crypto::hash &payment_id, const tools::wallet2::pool_payment_details &pd) const;
    void get_transfers(wallet2::transfer_container& incoming_transfers) const;

    struct get_transfers_args_t
    {
      bool in = false;
      bool out = false;
      bool stake = false;
      bool ons = false;
      bool pending = false;
      bool failed = false;
      bool pool = false;
      bool coinbase = false;
      bool filter_by_height = false;
      uint64_t min_height = 0;
      uint64_t max_height = cryptonote::MAX_BLOCK_NUMBER;
      std::set<uint32_t> subaddr_indices;
      uint32_t account_index;
      bool all_accounts;
    };
    void get_transfers(get_transfers_args_t args, std::vector<wallet::transfer_view>& transfers);
    std::string transfers_to_csv(const std::vector<wallet::transfer_view>& transfers, bool formatting = false) const;
    void get_payments(const crypto::hash& payment_id, std::list<wallet2::payment_details>& payments, uint64_t min_height = 0, const std::optional<uint32_t>& subaddr_account = std::nullopt, const std::set<uint32_t>& subaddr_indices = {}) const;
    void get_payments(std::list<std::pair<crypto::hash,wallet2::payment_details>>& payments, uint64_t min_height, uint64_t max_height = (uint64_t)-1, const std::optional<uint32_t>& subaddr_account = std::nullopt, const std::set<uint32_t>& subaddr_indices = {}) const;
    void get_payments_out(std::list<std::pair<crypto::hash,wallet2::confirmed_transfer_details>>& confirmed_payments,
      uint64_t min_height, uint64_t max_height = (uint64_t)-1, const std::optional<uint32_t>& subaddr_account = std::nullopt, const std::set<uint32_t>& subaddr_indices = {}) const;
    void get_unconfirmed_payments_out(std::list<std::pair<crypto::hash,wallet2::unconfirmed_transfer_details>>& unconfirmed_payments, const std::optional<uint32_t>& subaddr_account = std::nullopt, const std::set<uint32_t>& subaddr_indices = {}) const;
    void get_unconfirmed_payments(std::list<std::pair<crypto::hash,wallet2::pool_payment_details>>& unconfirmed_payments, const std::optional<uint32_t>& subaddr_account = std::nullopt, const std::set<uint32_t>& subaddr_indices = {}) const;
    std::optional<std::string> resolve_address(std::string address, uint64_t height = 0);

    // These return pairs where .first == true if the request was successful, and .second is a
    // vector of the requested entries.
    //
    // NOTE(oxen): get_all_service_node caches the result, get_service_nodes doesn't
    auto get_all_service_nodes()                                    const { return m_node_rpc_proxy.get_all_service_nodes(); }
    auto get_service_nodes(std::vector<std::string> const &pubkeys) const { return m_node_rpc_proxy.get_service_nodes(pubkeys); }
    auto get_service_node_blacklisted_key_images()                  const { return m_node_rpc_proxy.get_service_node_blacklisted_key_images(); }
    // List of service nodes this wallet has a stake in:
    std::vector<cryptonote::rpc::GET_SERVICE_NODES::response::entry> get_staked_service_nodes();
    auto ons_owners_to_names(cryptonote::rpc::ONS_OWNERS_TO_NAMES::request const &request) const { return m_node_rpc_proxy.ons_owners_to_names(request); }
    auto ons_names_to_owners(cryptonote::rpc::ONS_NAMES_TO_OWNERS::request const &request) const { return m_node_rpc_proxy.ons_names_to_owners(request); }
    auto resolve(cryptonote::rpc::ONS_RESOLVE::request const &request) const { return m_node_rpc_proxy.ons_resolve(request); }

    struct ons_detail
    {
      ons::mapping_type type;
      std::string name;
      std::string hashed_name;
    };
    std::unordered_map<std::string, ons_detail> ons_records_cache;

    void set_ons_cache_record(wallet2::ons_detail detail);

    void delete_ons_cache_record(const std::string& name);

    std::unordered_map<std::string, ons_detail> get_ons_cache();

    std::unordered_map<std::string, uint64_t> batching_records_cache;

    void refresh_batching_cache();
    // Returns the batched amount for the given address, or main address if empty.
    uint64_t get_batched_amount(std::optional<std::string> address = std::nullopt) const;
    // Calculates the next batching height for the given address, or main address if nullopt
    uint64_t get_next_batch_payout(std::optional<std::string> address = std::nullopt) const;

    // Returns the current height up to which the wallet has synchronized the blockchain.  Thread
    // safe (though the value may be behind if another thread is in the middle of adding blocks).
    uint64_t get_blockchain_current_height() const { return m_cached_height; }
    void rescan_spent();
    void rescan_blockchain(bool hard, bool refresh = true, bool keep_key_images = false);
    bool is_transfer_unlocked(const transfer_details &td) const;
    bool is_transfer_unlocked(uint64_t unlock_time, uint64_t block_height, bool unmined_blink, crypto::key_image const *key_image = nullptr) const;

    uint64_t get_last_block_reward() const { return m_last_block_reward; }
    uint64_t get_device_last_key_image_sync() const { return m_device_last_key_image_sync; }
    uint64_t get_immutable_height() const { return m_immutable_height; }

    template <class t_archive>
    void serialize(t_archive &a, const unsigned int ver)
    {
      uint64_t dummy_refresh_height = 0; // moved to keys file
      if(ver < 5)
        return;
      if (ver < 19)
      {
        std::vector<crypto::hash> blockchain;
        a & blockchain;
        for (const auto &b: blockchain)
        {
          m_blockchain.push_back(b);
        }
      }
      else
      {
        a & m_blockchain;
      }
      m_cached_height = m_blockchain.size();
      a & m_transfers;
      a & m_account_public_address;
      a & m_key_images;
      if(ver < 6)
        return;
      a & m_unconfirmed_txs;
      if(ver < 7)
        return;
      a & m_payments;
      if(ver < 8)
        return;
      a & m_tx_keys;
      if(ver < 9)
        return;
      a & m_confirmed_txs;
      if(ver < 11)
        return;
      a & dummy_refresh_height;
      if(ver < 12)
        return;
      a & m_tx_notes;
      if(ver < 13)
        return;
      if (ver < 17)
      {
        // we're loading an old version, where m_unconfirmed_payments was a std::map
        std::unordered_map<crypto::hash, payment_details> m;
        a & m;
        for (std::unordered_map<crypto::hash, payment_details>::const_iterator i = m.begin(); i != m.end(); ++i)
          m_unconfirmed_payments.insert(std::make_pair(i->first, pool_payment_details{i->second, false}));
      }
      if(ver < 14)
        return;
      if(ver < 15)
      {
        // we're loading an older wallet without a pubkey map, rebuild it
        for (size_t i = 0; i < m_transfers.size(); ++i)
        {
          const transfer_details &td = m_transfers[i];
          const cryptonote::tx_out &out = td.m_tx.vout[td.m_internal_output_index];
          const cryptonote::txout_to_key &o = var::get<cryptonote::txout_to_key>(out.target);
          m_pub_keys.emplace(o.key, i);
        }
        return;
      }
      a & m_pub_keys;
      if(ver < 16)
        return;
      a & m_address_book;
      if(ver < 17)
        return;
      if (ver < 22)
      {
        // we're loading an old version, where m_unconfirmed_payments payload was payment_details
        std::unordered_multimap<crypto::hash, payment_details> m;
        a & m;
        for (const auto &i: m)
          m_unconfirmed_payments.insert(std::make_pair(i.first, pool_payment_details{i.second, false}));
      }
      if(ver < 18)
        return;
      a & m_scanned_pool_txs[0];
      a & m_scanned_pool_txs[1];
      if (ver < 20)
        return;
      a & m_subaddresses;
      std::unordered_map<cryptonote::subaddress_index, crypto::public_key> dummy_subaddresses_inv;
      a & dummy_subaddresses_inv;
      a & m_subaddress_labels;
      a & m_additional_tx_keys;
      if(ver < 21)
        return;
      a & m_attributes;
      if(ver < 22)
        return;
      a & m_unconfirmed_payments;
      if(ver < 23)
        return;
      a & m_account_tags;
      if(ver < 24)
        return;
      a & m_ring_history_saved;
      if(ver < 25)
        return;
      a & m_last_block_reward;
      if(ver < 26)
        return;
      a & m_tx_device;
      if(ver < 27)
        return;
      a & m_device_last_key_image_sync;
      if(ver < 28)
        return;
      a & m_cold_key_images;
      if(ver < 29)
        return;
      a & m_immutable_height;
      if(ver < 30)
        return;
      a & ons_records_cache;
    }

    /*!
     * \brief  Check if wallet keys and bin files exist
     * \param  file_path           Wallet file path
     * \param  keys_file_exists    Whether keys file exists
     * \param  wallet_file_exists  Whether bin file exists
     */
    static void wallet_exists(const fs::path& file_path, bool& keys_file_exists, bool& wallet_file_exists);
    static bool parse_payment_id(std::string_view payment_id_str, crypto::hash& payment_id);

    bool always_confirm_transfers() const { return m_always_confirm_transfers; }
    void always_confirm_transfers(bool always) { m_always_confirm_transfers = always; }
    bool print_ring_members() const { return m_print_ring_members; }
    void print_ring_members(bool value) { m_print_ring_members = value; }
    bool store_tx_info() const { return m_store_tx_info; }
    void store_tx_info(bool store) { m_store_tx_info = store; }
    uint32_t get_default_priority() const { return m_default_priority; }
    void set_default_priority(uint32_t p) { m_default_priority = p; }
    bool auto_refresh() const { return m_auto_refresh; }
    void auto_refresh(bool r) { m_auto_refresh = r; }
    AskPasswordType ask_password() const { return m_ask_password; }
    void ask_password(AskPasswordType ask) { m_ask_password = ask; }
    void set_min_output_count(uint32_t count) { m_min_output_count = count; }
    uint32_t get_min_output_count() const { return m_min_output_count; }
    void set_min_output_value(uint64_t value) { m_min_output_value = value; }
    uint64_t get_min_output_value() const { return m_min_output_value; }
    void merge_destinations(bool merge) { m_merge_destinations = merge; }
    bool merge_destinations() const { return m_merge_destinations; }
    bool confirm_backlog() const { return m_confirm_backlog; }
    void confirm_backlog(bool always) { m_confirm_backlog = always; }
    void set_confirm_backlog_threshold(uint32_t threshold) { m_confirm_backlog_threshold = threshold; };
    uint32_t get_confirm_backlog_threshold() const { return m_confirm_backlog_threshold; };
    bool confirm_export_overwrite() const { return m_confirm_export_overwrite; }
    void confirm_export_overwrite(bool always) { m_confirm_export_overwrite = always; }
    bool segregate_pre_fork_outputs() const { return m_segregate_pre_fork_outputs; }
    void segregate_pre_fork_outputs(bool value) { m_segregate_pre_fork_outputs = value; }
    bool key_reuse_mitigation2() const { return m_key_reuse_mitigation2; }
    void key_reuse_mitigation2(bool value) { m_key_reuse_mitigation2 = value; }
    uint64_t segregation_height() const { return m_segregation_height; }
    void segregation_height(uint64_t height) { m_segregation_height = height; }
    bool confirm_non_default_ring_size() const { return m_confirm_non_default_ring_size; }
    void confirm_non_default_ring_size(bool always) { m_confirm_non_default_ring_size = always; }
    uint64_t ignore_outputs_above() const { return m_ignore_outputs_above; }
    void ignore_outputs_above(uint64_t value) { m_ignore_outputs_above = value; }
    uint64_t ignore_outputs_below() const { return m_ignore_outputs_below; }
    void ignore_outputs_below(uint64_t value) { m_ignore_outputs_below = value; }
    bool track_uses() const { return m_track_uses; }
    void track_uses(bool value) { m_track_uses = value; }
    std::chrono::seconds inactivity_lock_timeout() const { return m_inactivity_lock_timeout; }
    void inactivity_lock_timeout(std::chrono::seconds seconds) { m_inactivity_lock_timeout = seconds; }
    const std::string& device_name() const { return m_device_name; }
    const std::string& device_address() const { return m_device_address; }
    void device_name(std::string device_name) { m_device_name = std::move(device_name); }
    void device_address(std::string device_address) { m_device_address = std::move(device_address); }
    const std::string & device_derivation_path() const { return m_device_derivation_path; }
    void device_derivation_path(const std::string &device_derivation_path) { m_device_derivation_path = device_derivation_path; }

    bool get_tx_key_cached(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys) const;
    void set_tx_key(const crypto::hash &txid, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys);
    bool get_tx_key(const crypto::hash &txid, crypto::secret_key &tx_key, std::vector<crypto::secret_key> &additional_tx_keys);
    void check_tx_key(const crypto::hash &txid, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, const cryptonote::account_public_address &address, uint64_t &received, bool &in_pool, uint64_t &confirmations);
    void check_tx_key_helper(const crypto::hash &txid, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, const cryptonote::account_public_address &address, uint64_t &received, bool &in_pool, uint64_t &confirmations);
    void check_tx_key_helper(const cryptonote::transaction &tx, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, const cryptonote::account_public_address &address, uint64_t &received) const;
    std::string get_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address, bool is_subaddress, std::string_view message);
    std::string get_tx_proof(const cryptonote::transaction &tx, const crypto::secret_key &tx_key, const std::vector<crypto::secret_key> &additional_tx_keys, const cryptonote::account_public_address &address, bool is_subaddress, std::string_view message) const;
    bool check_tx_proof(const crypto::hash &txid, const cryptonote::account_public_address &address, bool is_subaddress, std::string_view message, std::string_view sig_str, uint64_t &received, bool &in_pool, uint64_t &confirmations);
    bool check_tx_proof(const cryptonote::transaction &tx, const cryptonote::account_public_address &address, bool is_subaddress, std::string_view message, std::string_view sig_str, uint64_t &received) const;

    std::string get_spend_proof(const crypto::hash &txid, std::string_view message);
    bool check_spend_proof(const crypto::hash &txid, std::string_view message, std::string_view sig_str);

    /*!
     * \brief  Generates a proof that proves the reserve of unspent funds
     * \param  account_minreserve       When specified, collect outputs only belonging to the given account and prove the smallest reserve above the given amount
     *                                  When unspecified, proves for all unspent outputs across all accounts
     * \param  message                  Arbitrary challenge message to be signed together
     * \return                          Signature string
     */
    std::string get_reserve_proof(const std::optional<std::pair<uint32_t, uint64_t>> &account_minreserve, std::string message);
    /*!
     * \brief  Verifies a proof of reserve
     * \param  address                  The signer's address
     * \param  message                  Challenge message used for signing
     * \param  sig_str                  Signature string
     * \param  total                    [OUT] the sum of funds included in the signature
     * \param  spent                    [OUT] the sum of spent funds included in the signature
     * \return                          true if the signature verifies correctly
     */
    bool check_reserve_proof(const cryptonote::account_public_address &address, std::string_view message, std::string_view sig_str, uint64_t &total, uint64_t &spent);

   /*!
    * \brief GUI Address book get/store
    */
    std::vector<address_book_row> get_address_book() const { return m_address_book; }
    bool add_address_book_row(const cryptonote::account_public_address &address, const crypto::hash8 *payment_id, const std::string &description, bool is_subaddress);
    bool set_address_book_row(size_t row_id, const cryptonote::account_public_address &address, const crypto::hash8 *payment_id, const std::string &description, bool is_subaddress);
    bool delete_address_book_row(std::size_t row_id);
        
    uint64_t get_num_rct_outputs();
    size_t get_num_transfer_details() const { return m_transfers.size(); }
    const transfer_details &get_transfer_details(size_t idx) const;

    void get_hard_fork_info (uint8_t version, uint64_t &earliest_height) const;
    std::optional<cryptonote::hf> get_hard_fork_version() const { return m_node_rpc_proxy.get_hardfork_version(); }
    bool use_fork_rules(cryptonote::hf version, uint64_t early_blocks = 0) const;

    const fs::path& get_wallet_file() const;
    const fs::path& get_keys_file() const;
    std::string get_daemon_address() const;
    uint64_t get_daemon_blockchain_height(std::string& err) const;
    uint64_t get_daemon_blockchain_target_height(std::string& err);
   /*!
    * \brief Calculates the approximate blockchain height from current date/time.
    */
    uint64_t get_approximate_blockchain_height() const;
    uint64_t estimate_blockchain_height();
    std::vector<size_t> select_available_outputs_from_histogram(uint64_t count, bool atleast, bool unlocked, bool allow_rct);
    std::vector<size_t> select_available_outputs(const std::function<bool(const transfer_details &td)> &f) const;
    std::vector<size_t> select_available_unmixable_outputs();
    std::vector<size_t> select_available_mixable_outputs();

    size_t pop_best_value_from(const transfer_container &transfers, std::vector<size_t> &unused_dust_indices, const std::vector<size_t>& selected_transfers, bool smallest = false) const;
    size_t pop_best_value(std::vector<size_t> &unused_dust_indices, const std::vector<size_t>& selected_transfers, bool smallest = false) const;

    void set_tx_note(const crypto::hash &txid, const std::string &note);
    std::string get_tx_note(const crypto::hash &txid) const;

    void set_tx_device_aux(const crypto::hash &txid, const std::string &aux);
    std::string get_tx_device_aux(const crypto::hash &txid) const;

    void set_description(const std::string &description);
    std::string get_description() const;

    /*!
     * \brief  Get the list of registered account tags. 
     * \return first.Key=(tag's name), first.Value=(tag's label), second[i]=(i-th account's tag)
     */
    const std::pair<std::map<std::string, std::string>, std::vector<std::string>>& get_account_tags();
    /*!
     * \brief  Set a tag to the given accounts.
     * \param  account_indices  Indices of accounts.
     * \param  tag              Tag's name. If empty, the accounts become untagged.
     */
    void set_account_tag(const std::set<uint32_t> &account_indices, const std::string& tag);
    /*!
     * \brief  Set the label of the given tag.
     * \param  tag            Tag's name (which must be non-empty).
     * \param  description    Tag's description.
     */
    void set_account_tag_description(const std::string& tag, const std::string& description);

    /*!
     * \brief Signs an arbitrary string using the wallet's secret spend key.
     *
     * \param data the data to sign
     * \param index the subaccount/subaddress indices to use (if omitted: use main address)
     *
     * \return the signature.
     *
     * \throw std::logic_error if called on a view-only wallet.
     */
    std::string sign(std::string_view data, cryptonote::subaddress_index index = {0, 0}) const;

    /*!
     * \brief Verifies a signed string.
     *
     * \param data - the data that has been signed.
     * \param address - the public address of the wallet that signed the data.
     * \param signature - the signature itself.
     *
     * \return true if the signature verified successfully, false if verification failed.
     */
    static bool verify(std::string_view data, const cryptonote::account_public_address &address, std::string_view signature);

    /*!
     * \brief sign_multisig_participant signs given message with the multisig public signer key
     * \param data                      message to sign
     * \throws                          if wallet is not multisig
     * \return                          signature
     */
    std::string sign_multisig_participant(std::string_view data) const;
    /*!
     * \brief verify_with_public_key verifies message was signed with given public key
     * \param data                   message
     * \param public_key             public key to check signature
     * \param signature              signature of the message
     * \return                       true if the signature is correct
     */
    bool verify_with_public_key(std::string_view data, const crypto::public_key &public_key, std::string_view signature) const;

    // Import/Export wallet data
    std::pair<size_t, std::vector<transfer_details>> export_outputs(bool all = false) const;
    std::string export_outputs_to_str(bool all = false) const;
    size_t import_outputs(const std::pair<size_t, std::vector<transfer_details>> &outputs);
    size_t import_outputs_from_str(std::string outputs_st);
    payment_container export_payments() const;
    void import_payments(const payment_container &payments);
    void import_payments_out(const std::list<std::pair<crypto::hash,wallet2::confirmed_transfer_details>> &confirmed_payments);
    std::tuple<size_t, crypto::hash, std::vector<crypto::hash>> export_blockchain() const;
    void import_blockchain(const std::tuple<size_t, crypto::hash, std::vector<crypto::hash>> &bc);
    bool export_key_images_to_file(const fs::path &filename, bool requested_only) const;
    std::pair<size_t, std::vector<std::pair<crypto::key_image, crypto::signature>>> export_key_images(bool requested_only) const;
    uint64_t import_key_images(const std::vector<std::pair<crypto::key_image, crypto::signature>> &signed_key_images, size_t offset, uint64_t &spent, uint64_t &unspent, bool check_spent = true);
    uint64_t import_key_images_from_file(const fs::path& filename, uint64_t &spent, uint64_t &unspent);
    bool import_key_images(std::vector<crypto::key_image> key_images, size_t offset=0, std::optional<std::unordered_set<size_t>> selected_transfers=std::nullopt);
    bool import_key_images(signed_tx_set & signed_tx, size_t offset=0, bool only_selected_transfers=false);
    crypto::public_key get_tx_pub_key_from_received_outs(const transfer_details &td) const;

    crypto::hash get_long_poll_tx_pool_checksum() const
    {
      std::lock_guard<decltype(m_long_poll_tx_pool_checksum_mutex)> lock(m_long_poll_tx_pool_checksum_mutex);
      return m_long_poll_tx_pool_checksum;
    }

    // long_poll_pool_state is blocking and does NOT return to the caller until
    // the daemon detects a change in the contents of the txpool by comparing
    // our last tx pool checksum with theirs.

    // This call also takes the long poll mutex and uses it's own individual
    // http client that it exclusively owns.

    // Returns true if call succeeded, false if the long poll timed out, throws
    // if a network error.
    bool long_poll_pool_state();

    // Attempts to cancel an existing long poll request (by resetting the timeout).
    void cancel_long_poll();

    struct get_pool_state_tx
    {
        cryptonote::transaction tx;
        crypto::hash tx_hash;
        bool double_spend_seen;
        bool blink;
    };
    std::vector<get_pool_state_tx> get_pool_state(bool refreshed = false);
    void process_pool_state(const std::vector<get_pool_state_tx> &txs);

    void remove_obsolete_pool_txs(const std::vector<crypto::hash> &tx_hashes);

    std::string encrypt(std::string_view plaintext, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string encrypt(const epee::span<char> &span, const crypto::secret_key &skey, bool authenticated = true) const;
    std::string encrypt_with_view_secret_key(std::string_view plaintext, bool authenticated = true) const;
    epee::wipeable_string decrypt(std::string_view ciphertext, const crypto::secret_key &skey, bool authenticated = true) const;
    epee::wipeable_string decrypt_with_view_secret_key(std::string_view ciphertext, bool authenticated = true) const;

    std::string make_uri(const std::string &address, const std::string &payment_id, uint64_t amount, const std::string &tx_description, const std::string &recipient_name, std::string &error) const;
    bool parse_uri(std::string_view uri, std::string &address, std::string &payment_id, uint64_t &amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error);

    uint64_t get_blockchain_height_by_date(uint16_t year, uint8_t month, uint8_t day);    // 1<=month<=12, 1<=day<=31

    /// Returns true if the wallet is synced with the chain; if grace_blocks > 0 then the check is
    /// that we are within that many blocks of the top of the chain.
    bool is_synced(uint64_t grace_blocks = 0) const;

    uint64_t get_fee_percent(uint32_t priority, cryptonote::txtype type) const;
    cryptonote::byte_and_output_fees get_base_fees() const;
    uint64_t get_fee_quantization_mask() const;

    // params constructor, accumulates the burn amounts if the priority is
    // a blink and, or a ons tx. If it is a blink TX, ons_burn_type is ignored.
    static cryptonote::oxen_construct_tx_params construct_params(cryptonote::hf hf_version, cryptonote::txtype tx_type, uint32_t priority, uint64_t extra_burn = 0, ons::mapping_type ons_burn_type = static_cast<ons::mapping_type>(0));

    bool is_unattended() const { return m_unattended; }

#ifdef ENABLE_LIGHT_WALLET
    // Light wallet specific functions
    // fetch unspent outs from lw node and store in m_transfers
    void light_wallet_get_unspent_outs();
    // fetch txs and store in m_payments
    void light_wallet_get_address_txs();
    // get_address_info
    bool light_wallet_get_address_info(tools::light_rpc::GET_ADDRESS_INFO::response &response);
    // Login. new_address is true if address hasn't been used on lw node before.
    bool light_wallet_login(bool &new_address);
    // Send an import request to lw node. returns info about import fee, address and payment_id
    bool light_wallet_import_wallet_request(tools::light_rpc::IMPORT_WALLET_REQUEST::response &response);
    // get random outputs from light wallet server
    void light_wallet_get_outs(std::vector<std::vector<get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count);
    // Parse rct string
    bool light_wallet_parse_rct_str(const std::string& rct_string, const crypto::public_key& tx_pub_key, uint64_t internal_output_index, rct::key& decrypted_mask, rct::key& rct_commit, bool decrypt) const;
    // check if key image is ours
    bool light_wallet_key_image_is_ours(const crypto::key_image& key_image, const crypto::public_key& tx_public_key, uint64_t out_index);
#endif

    /*
     * "attributes" are a mechanism to store an arbitrary number of string values
     * on the level of the wallet as a whole, identified by keys. Their introduction,
     * technically the unordered map m_attributes stored as part of a wallet file,
     * led to a new wallet file version, but now new singular pieces of info may be added
     * without the need for a new version.
     *
     * The first and so far only value stored as such an attribute is the description.
     * It's stored under the standard key ATTRIBUTE_DESCRIPTION (see method set_description).
     *
     * The mechanism is open to all clients and allows them to use it for storing basically any
     * single string values in a wallet. To avoid the problem that different clients possibly
     * overwrite or misunderstand each other's attributes, a two-part key scheme is
     * proposed: <client name>.<value name>
     */
    const char* const ATTRIBUTE_DESCRIPTION = "wallet2.description";
    void set_attribute(const std::string &key, const std::string &value);
    std::optional<std::string> get_attribute(const std::string &key) const;

    crypto::public_key get_multisig_signer_public_key(const crypto::secret_key &spend_skey) const;
    crypto::public_key get_multisig_signer_public_key() const;
    crypto::public_key get_multisig_signing_public_key(size_t idx) const;
    crypto::public_key get_multisig_signing_public_key(const crypto::secret_key &skey) const;

    template <typename RPC>
    bool invoke_http(const typename RPC::request& req, typename RPC::response& res, bool throw_on_error = false)
    {
      using namespace cryptonote::rpc;
      static_assert(std::is_base_of_v<RPC_COMMAND, RPC>
#ifdef ENABLE_LIGHT_WALLET
              || std::is_base_of_v<tools::light_rpc::LIGHT_RPC_COMMAND, RPC>
#endif
              );

      if (m_offline) return false;

      try {
        if constexpr (std::is_base_of_v<LEGACY, RPC>)
          // TODO: post-8.x hard fork we can remove this one and let everything go through the
          // non-binary json_rpc version instead (because all legacy json commands are callable via
          // json_rpc as of daemon 8.x).
          res = m_http_client.json<RPC>(RPC::names().front(), req);
        else if constexpr (std::is_base_of_v<BINARY, RPC>)
          res = m_http_client.binary<RPC>(RPC::names().front(), req);
        else if constexpr (std::is_base_of_v<RPC_COMMAND, RPC>)
          res = m_http_client.json_rpc<RPC>(RPC::names().front(), req);
        else // light RPC:
          res = m_http_client.json<RPC>(RPC::name, req);
        return true;
      } catch (const std::exception& e) {
        if (throw_on_error)
          throw;
        else
          MERROR("HTTP request failed: " << e.what());
      } catch (...) {
        if (throw_on_error)
          throw;
        else
          MERROR("HTTP request failed: unknown error");
      }
      return false;
    }

    bool set_ring_database(fs::path filename);
    const fs::path& get_ring_database() const { return m_ring_database; }
    bool get_ring(const crypto::key_image &key_image, std::vector<uint64_t> &outs);
    bool get_rings(const crypto::hash &txid, std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> &outs);
    bool set_ring(const crypto::key_image &key_image, const std::vector<uint64_t> &outs, bool relative);
    bool unset_ring(const std::vector<crypto::key_image> &key_images);
    bool unset_ring(const crypto::hash &txid);
    bool find_and_save_rings(bool force = true);

    bool blackball_output(const std::pair<uint64_t, uint64_t> &output);
    bool set_blackballed_outputs(const std::vector<std::pair<uint64_t, uint64_t>> &outputs, bool add = false);
    bool unblackball_output(const std::pair<uint64_t, uint64_t> &output);
    bool is_output_blackballed(const std::pair<uint64_t, uint64_t> &output) const;

    enum struct stake_result_status
    {
      invalid,
      success,
      exception_thrown,
      payment_id_disallowed,
      subaddress_disallowed,
      address_must_be_primary,
      service_node_list_query_failed,
      service_node_not_registered,
      network_version_query_failed,
      network_height_query_failed,
      service_node_contribution_maxed,
      service_node_contributors_maxed,
      service_node_insufficient_contribution,
      too_many_transactions_constructed,
      no_blink,
    };

    struct stake_result
    {
      stake_result_status status;
      std::string         msg;
      pending_tx          ptx;
    };

    /// Modifies the `amount` to maximum possible if too large, but rejects if insufficient.
    /// `fraction` is only used to determine the amount if specified zero.
    stake_result check_stake_allowed(const crypto::public_key& sn_key, const cryptonote::address_parse_info& addr_info, uint64_t& amount, double fraction = 0);
    stake_result create_stake_tx    (const crypto::public_key& service_node_key, uint64_t amount,
                                     double amount_fraction = 0, uint32_t priority = 0, std::set<uint32_t> subaddr_indices = {});
    enum struct register_service_node_result_status
    {
      invalid,
      success,
      insufficient_num_args,
      subaddr_indices_parse_fail,
      network_height_query_failed,
      network_version_query_failed,
      convert_registration_args_failed,
      registration_timestamp_expired,
      registration_timestamp_parse_fail,
      validate_registration_args_fail,
      service_node_key_parse_fail,
      service_node_signature_parse_fail,
      service_node_register_serialize_to_tx_extra_fail,
      first_address_must_be_primary_address,
      service_node_list_query_failed,
      service_node_cannot_reregister,
      insufficient_portions,
      wallet_not_synced,
      too_many_transactions_constructed,
      exception_thrown,
      no_blink,
    };

    struct register_service_node_result
    {
      register_service_node_result_status status;
      std::string                         msg;
      pending_tx                          ptx;
    };
    register_service_node_result create_register_service_node_tx(const std::vector<std::string> &args_, uint32_t subaddr_account = 0);

    struct request_stake_unlock_result
    {
      bool        success;
      std::string msg;
      pending_tx  ptx;
    };
    request_stake_unlock_result can_request_stake_unlock(const crypto::public_key &sn_key);

    // Attempts to convert the ONS type string to a mapping type (checking the current hard fork).
    // If type isn't valid then returns std::nullopt and sets the failure reason in `reason` (if not
    // nullptr).
    std::optional<ons::mapping_type> ons_validate_type(std::string_view type, ons::ons_tx_type ons_action, std::string *reason);

    std::vector<pending_tx> ons_create_buy_mapping_tx(ons::mapping_type type, std::string const *owner, std::string const *backup_owner, std::string name, std::string const &value, std::string *reason, uint32_t priority = 0, uint32_t account_index = 0, std::set<uint32_t> subaddr_indices = {});

    // signature: (Optional) If set, use the signature given, otherwise by default derive the signature from the wallet spend key as an ed25519 key.
    //            The signature is derived from the hash of the previous txid blob and previous value blob of the mapping. By default this is signed using the wallet's spend key as an ed25519 keypair.
    std::vector<pending_tx> ons_create_update_mapping_tx(ons::mapping_type type, std::string name, std::string const *value, std::string const *owner, std::string const *backup_owner, std::string const *signature, std::string *reason, uint32_t priority = 0, uint32_t account_index = 0, std::set<uint32_t> subaddr_indices = {}, std::vector<cryptonote::rpc::ONS_NAMES_TO_OWNERS::response_entry> *response = {});

    // ONS renewal (for lokinet registrations, not for session/wallet)
    std::vector<pending_tx> ons_create_renewal_tx(ons::mapping_type type, std::string name, std::string *reason, uint32_t priority = 0, uint32_t account_index = 0, std::set<uint32_t> subaddr_indices = {}, std::vector<cryptonote::rpc::ONS_NAMES_TO_OWNERS::response_entry> *response = {});

    // Generate just the signature required for putting into ons_update_mapping command in the wallet
    bool ons_make_update_mapping_signature(ons::mapping_type type, std::string name, std::string const *value, std::string const *owner, std::string const *backup_owner, ons::generic_signature &signature, uint32_t account_index = 0, std::string *reason = nullptr);

    void freeze(size_t idx);
    void thaw(size_t idx);
    bool frozen(size_t idx) const;
    void freeze(const crypto::key_image &ki);
    void thaw(const crypto::key_image &ki);
    bool frozen(const crypto::key_image &ki) const;
    bool frozen(const transfer_details &td) const;

    uint64_t get_bytes_sent() const;
    uint64_t get_bytes_received() const;

#ifdef WALLET_ENABLE_MMS
    // MMS -------------------------------------------------------------------------------------------------
    mms::message_store& get_message_store() { return m_message_store; };
    const mms::message_store& get_message_store() const { return m_message_store; };
    mms::multisig_wallet_state get_multisig_wallet_state() const;
#endif

    bool lock_keys_file();
    bool unlock_keys_file();
    bool is_keys_file_locked() const;

    void change_password(const fs::path& filename, const epee::wipeable_string& original_password, const epee::wipeable_string& new_password);

    void set_tx_notify(std::shared_ptr<tools::Notify> notify) { m_tx_notify = std::move(notify); }

    bool is_tx_spendtime_unlocked(uint64_t unlock_time, uint64_t block_height) const;
    void hash_m_transfer(const transfer_details & transfer, crypto::hash &hash) const;
    uint64_t hash_m_transfers(int64_t transfer_height, crypto::hash &hash) const;
    void finish_rescan_bc_keep_key_images(uint64_t transfer_height, const crypto::hash &hash);
    void set_offline(bool offline = true);


    std::atomic<bool> m_long_poll_disabled;
    static std::string get_default_daemon_address();

    /// Requests transactions from daemon given hex strings of the tx ids; throws a wallet exception
    /// on error, otherwise returns the response.
    cryptonote::rpc::GET_TRANSACTIONS::response request_transactions(std::vector<std::string> txids_hex);

    /// Requests transactions from daemon given a vector of crypto::hash.  Throws a wallet exception
    /// on error, otherwise returns the response.
    cryptonote::rpc::GET_TRANSACTIONS::response request_transactions(const std::vector<crypto::hash>& txids);

    /// Same as above, but for a single transaction.
    cryptonote::rpc::GET_TRANSACTIONS::response request_transaction(const crypto::hash& txid) { return request_transactions(std::vector<crypto::hash>{{txid}}); }

    // The wallet's RPC client; public for advanced configuration purposes.
    cryptonote::rpc::http_client m_http_client;

  private:
    /*!
     * \brief  Stores wallet information to wallet file.
     * \param  keys_file_name Name of wallet file
     * \param  password       Password of wallet file
     * \param  watch_only     true to save only view key, false to save both spend and view keys
     * \return                Whether it was successful.
     */
    bool store_keys(const fs::path& keys_file_name, const epee::wipeable_string& password, bool watch_only = false);
    /*!
     * \brief Load wallet keys information from wallet file.
     * \param keys_file_name Name of wallet file
     * \param password       Password of wallet file
     */
    bool load_keys(const fs::path& keys_file_name, const epee::wipeable_string& password);
    /*!
     * \brief Load wallet keys information from a string buffer.
     * \param keys_buf       Keys buffer to load
     * \param password       Password of keys buffer
     */
    bool load_keys_buf(const std::string& keys_buf, const epee::wipeable_string& password);
    bool load_keys_buf(const std::string& keys_buf, const epee::wipeable_string& password, std::optional<crypto::chacha_key>& keys_to_encrypt);
    void process_new_transaction(const crypto::hash &txid, const cryptonote::transaction& tx, const std::vector<uint64_t> &o_indices, uint64_t height, cryptonote::hf block_version, uint64_t ts, bool miner_tx, bool pool, bool blink, bool double_spend_seen, const tx_cache_data &tx_cache_data, std::map<std::pair<uint64_t, uint64_t>, size_t> *output_tracker_cache = NULL);
    bool should_skip_block(const cryptonote::block &b, uint64_t height) const;
    void process_new_blockchain_entry(const cryptonote::block& b, const cryptonote::block_complete_entry& bche, const parsed_block &parsed_block, const crypto::hash& bl_id, uint64_t height, const std::vector<tx_cache_data> &tx_cache_data, size_t tx_cache_data_offset, std::map<std::pair<uint64_t, uint64_t>, size_t> *output_tracker_cache = NULL);
    void detach_blockchain(uint64_t height, std::map<std::pair<uint64_t, uint64_t>, size_t> *output_tracker_cache = NULL);
    void get_short_chain_history(std::list<crypto::hash>& ids, uint64_t granularity = 1) const;
    bool clear();
    void clear_soft(bool keep_key_images=false);
    void pull_blocks(uint64_t start_height, uint64_t& blocks_start_height, const std::list<crypto::hash> &short_chain_history, std::vector<cryptonote::block_complete_entry> &blocks, std::vector<cryptonote::rpc::GET_BLOCKS_FAST::block_output_indices> &o_indices, uint64_t &current_height);
    void pull_hashes(uint64_t start_height, uint64_t& blocks_start_height, const std::list<crypto::hash> &short_chain_history, std::vector<crypto::hash> &hashes);
    void fast_refresh(uint64_t stop_height, uint64_t &blocks_start_height, std::list<crypto::hash> &short_chain_history, bool force = false);
    void pull_and_parse_next_blocks(uint64_t start_height, uint64_t &blocks_start_height, std::list<crypto::hash> &short_chain_history, const std::vector<cryptonote::block_complete_entry> &prev_blocks, const std::vector<parsed_block> &prev_parsed_blocks, std::vector<cryptonote::block_complete_entry> &blocks, std::vector<parsed_block> &parsed_blocks, bool &last, bool &error, std::exception_ptr &exception);
    void process_parsed_blocks(uint64_t start_height, const std::vector<cryptonote::block_complete_entry> &blocks, const std::vector<parsed_block> &parsed_blocks, uint64_t& blocks_added, std::map<std::pair<uint64_t, uint64_t>, size_t> *output_tracker_cache = NULL);
    uint64_t select_transfers(uint64_t needed_money, std::vector<size_t> unused_transfers_indices, std::vector<size_t>& selected_transfers) const;
    bool prepare_file_names(const fs::path& file_path);
    confirmed_transfer_details* process_unconfirmed(const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t height);
    void process_outgoing(const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t height, uint64_t ts, uint64_t spent, uint64_t received, uint32_t subaddr_account, const std::set<uint32_t>& subaddr_indices);
    void add_unconfirmed_tx(const cryptonote::transaction& tx, uint64_t amount_in, const std::vector<cryptonote::tx_destination_entry> &dests, const crypto::hash &payment_id, uint64_t change_amount, uint32_t subaddr_account, const std::set<uint32_t>& subaddr_indices);
    void generate_genesis(cryptonote::block& b) const;
    void check_genesis(const crypto::hash& genesis_hash) const; //throws
    bool generate_chacha_key_from_secret_keys(crypto::chacha_key &key) const;
    void generate_chacha_key_from_password(const epee::wipeable_string &pass, crypto::chacha_key &key) const;
    crypto::hash get_payment_id(const pending_tx &ptx) const;
    void check_acc_out_precomp(const cryptonote::tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, tx_scan_info_t &tx_scan_info) const;
    void check_acc_out_precomp(const cryptonote::tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, const is_out_data *is_out_data, tx_scan_info_t &tx_scan_info) const;
    void check_acc_out_precomp_once(const cryptonote::tx_out &o, const crypto::key_derivation &derivation, const std::vector<crypto::key_derivation> &additional_derivations, size_t i, const is_out_data *is_out_data, tx_scan_info_t &tx_scan_info, bool &already_seen) const;
    void parse_block_round(const std::string &blob, cryptonote::block &bl, crypto::hash &bl_id, bool &error) const;
    uint64_t get_upper_transaction_weight_limit() const;
    std::vector<uint64_t> get_unspent_amounts_vector(bool strict) const;
    cryptonote::byte_and_output_fees get_dynamic_base_fee_estimate() const;
    float get_output_relatedness(const transfer_details &td0, const transfer_details &td1) const;
    std::vector<size_t> pick_preferred_rct_inputs(uint64_t needed_money, uint32_t subaddr_account, const std::set<uint32_t> &subaddr_indices) const;
    void set_spent(size_t idx, uint64_t height);
    void set_unspent(size_t idx);
    bool is_spent(const transfer_details &td, bool strict = true) const;
    bool is_spent(size_t idx, bool strict = true) const;
    void get_outs(std::vector<std::vector<get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count, bool has_rct);
    void get_outs(std::vector<std::vector<get_outs_entry>> &outs, const std::vector<size_t> &selected_transfers, size_t fake_outputs_count, std::vector<uint64_t> &rct_offsets, bool has_rct);
    bool tx_add_fake_output(std::vector<std::vector<tools::wallet2::get_outs_entry>> &outs, uint64_t global_index, const crypto::public_key& tx_public_key, const rct::key& mask, uint64_t real_index, bool unlocked) const;
    bool should_pick_a_second_output(size_t n_transfers, const std::vector<size_t> &unused_transfers_indices, const std::vector<size_t> &unused_dust_indices) const;
    std::vector<size_t> get_only_rct(const std::vector<size_t> &unused_dust_indices, const std::vector<size_t> &unused_transfers_indices) const;
    void scan_output(const cryptonote::transaction &tx, bool miner_tx, const crypto::public_key &tx_pub_key, size_t vout_index, tx_scan_info_t &tx_scan_info, std::vector<tx_money_got_in_out> &tx_money_got_in_outs, std::vector<size_t> &outs, bool pool, bool blink);
    void trim_hashchain();
    crypto::key_image get_multisig_composite_key_image(size_t n) const;
    rct::multisig_kLRki get_multisig_composite_kLRki(size_t n,  const std::unordered_set<crypto::public_key> &ignore_set, std::unordered_set<rct::key> &used_L, std::unordered_set<rct::key> &new_used_L) const;
    rct::multisig_kLRki get_multisig_kLRki(size_t n, const rct::key &k) const;
    rct::key get_multisig_k(size_t idx, const std::unordered_set<rct::key> &used_L) const;
    void update_multisig_rescan_info(const std::vector<std::vector<rct::key>> &multisig_k, const std::vector<std::vector<wallet::multisig_info>> &info, size_t n);
    bool add_rings(const crypto::chacha_key &key, const cryptonote::transaction_prefix &tx);
    bool add_rings(const cryptonote::transaction_prefix &tx);
    bool remove_rings(const cryptonote::transaction_prefix &tx);
    bool get_ring(const crypto::chacha_key &key, const crypto::key_image &key_image, std::vector<uint64_t> &outs);
    crypto::chacha_key get_ringdb_key();
    void setup_keys(const epee::wipeable_string &password);
    size_t get_transfer_details(const crypto::key_image &ki) const;

    void register_devices();
    hw::device& lookup_device(const std::string & device_descriptor);

    bool get_rct_distribution(uint64_t &start_height, std::vector<uint64_t> &distribution);
    bool get_output_blacklist(std::vector<uint64_t> &blacklist);

    uint64_t get_segregation_fork_height() const;
    void unpack_multisig_info(const std::vector<std::string>& info,
      std::vector<crypto::public_key> &public_keys,
      std::vector<crypto::secret_key> &secret_keys) const;
    bool unpack_extra_multisig_info(const std::vector<std::string>& info,
      std::vector<crypto::public_key> &signers,
      std::unordered_set<crypto::public_key> &pkeys) const;

    void cache_tx_data(const cryptonote::transaction& tx, const crypto::hash &txid, tx_cache_data &tx_cache_data) const;
    std::shared_ptr<std::map<std::pair<uint64_t, uint64_t>, size_t>> create_output_tracker_cache() const;

    void init_type(hw::device::type device_type);
    void setup_new_blockchain();
    void create_keys_file(const fs::path &wallet_, bool watch_only, const epee::wipeable_string &password, bool create_address_file);

    wallet_device_callback * get_device_callback();
    void on_device_button_request(uint64_t code);
    void on_device_button_pressed();
    std::optional<epee::wipeable_string> on_device_pin_request();
    std::optional<epee::wipeable_string> on_device_passphrase_request(bool& on_device);
    void on_device_progress(const hw::device_progress& event);

    std::string get_rpc_status(const std::string &s) const;

    bool should_expand(const cryptonote::subaddress_index &index) const;

    cryptonote::account_base m_account;
    fs::path m_wallet_file;
    fs::path m_keys_file;
#ifdef WALLET_ENABLE_MMS
    fs::path m_mms_file;
#endif
    hashchain m_blockchain;
    std::atomic<uint64_t> m_cached_height; // Tracks m_blockchain.size(), but thread-safe.
    std::unordered_map<crypto::hash, unconfirmed_transfer_details> m_unconfirmed_txs;
    std::unordered_map<crypto::hash, confirmed_transfer_details> m_confirmed_txs;
    std::unordered_multimap<crypto::hash, pool_payment_details> m_unconfirmed_payments;
    std::unordered_map<crypto::hash, crypto::secret_key> m_tx_keys;
    std::unordered_map<crypto::hash, std::vector<crypto::secret_key>> m_additional_tx_keys;

    cryptonote::rpc::http_client              m_long_poll_client;
    bool                                      m_long_poll_local;
    mutable std::mutex                        m_long_poll_tx_pool_checksum_mutex;
    crypto::hash                              m_long_poll_tx_pool_checksum = {};

    transfer_container m_transfers;
    payment_container m_payments;
    std::unordered_map<crypto::key_image, size_t> m_key_images;
    std::unordered_map<crypto::public_key, size_t> m_pub_keys;
    cryptonote::account_public_address m_account_public_address;
    std::unordered_map<crypto::public_key, cryptonote::subaddress_index> m_subaddresses;
    std::vector<std::vector<std::string>> m_subaddress_labels;
    std::unordered_map<crypto::hash, std::string> m_tx_notes;
    std::unordered_map<std::string, std::string> m_attributes;
    std::vector<tools::wallet2::address_book_row> m_address_book;
    std::pair<std::map<std::string, std::string>, std::vector<std::string>> m_account_tags;
    uint64_t m_upper_transaction_weight_limit; //TODO: auto-calc this value or request from daemon, now use some fixed value
    const std::vector<std::vector<wallet::multisig_info>> *m_multisig_rescan_info;
    const std::vector<std::vector<rct::key>> *m_multisig_rescan_k;
    std::unordered_map<crypto::public_key, crypto::key_image> m_cold_key_images;

    std::atomic<bool> m_run;

    bool m_trusted_daemon;
    i_wallet2_callback* m_callback;
    hw::device::type m_key_device_type;
    cryptonote::network_type m_nettype;
    uint64_t m_kdf_rounds;
    std::string seed_language; /*!< Language of the mnemonics (seed). */
    bool is_old_file_format; /*!< Whether the wallet file is of an old file format */
    bool m_watch_only; /*!< no spend key */
    bool m_multisig; /*!< if > 1 spend secret key will not match spend public key */
    uint32_t m_multisig_threshold;
    std::vector<crypto::public_key> m_multisig_signers;
    //in case of general M/N multisig wallet we should perform N - M + 1 key exchange rounds and remember how many rounds are passed.
    uint32_t m_multisig_rounds_passed;
    std::vector<crypto::public_key> m_multisig_derivations;
    bool m_always_confirm_transfers;
    bool m_print_ring_members;
    bool m_store_tx_info; /*!< request txkey to be returned in RPC, and store in the wallet cache file */
    uint32_t m_default_priority;
    RefreshType m_refresh_type;
    bool m_auto_refresh;
    bool m_first_refresh_done;
    uint64_t m_refresh_from_block_height;
    // If m_refresh_from_block_height is explicitly set to zero we need this to differentiate it from the case that
    // m_refresh_from_block_height was defaulted to zero.*/
    bool m_explicit_refresh_from_block_height;
    bool m_confirm_non_default_ring_size;
    AskPasswordType m_ask_password;
    uint32_t m_min_output_count;
    uint64_t m_min_output_value;
    bool m_merge_destinations;
    bool m_confirm_backlog;
    uint32_t m_confirm_backlog_threshold;
    bool m_confirm_export_overwrite;
    bool m_segregate_pre_fork_outputs;
    bool m_key_reuse_mitigation2;
    uint64_t m_segregation_height;
    uint64_t m_ignore_outputs_above;
    uint64_t m_ignore_outputs_below;
    bool m_track_uses;
    std::chrono::seconds m_inactivity_lock_timeout;
    bool m_is_initialized;
    NodeRPCProxy m_node_rpc_proxy;
    std::unordered_set<crypto::hash> m_scanned_pool_txs[2];
    size_t m_subaddress_lookahead_major, m_subaddress_lookahead_minor;
    std::string m_device_name;
    std::string m_device_address;
    std::string m_device_derivation_path;
    uint64_t m_device_last_key_image_sync;
    bool m_offline;
    uint64_t m_immutable_height;
    uint32_t m_rpc_version;

    // Aux transaction data from device
    std::unordered_map<crypto::hash, std::string> m_tx_device;

#ifdef ENABLE_LIGHT_WALLET
    // Light wallet
    bool m_light_wallet; /* sends view key to daemon for scanning */
    uint64_t m_light_wallet_scanned_block_height;
    uint64_t m_light_wallet_blockchain_height;
    uint64_t m_light_wallet_per_kb_fee = FEE_PER_BYTE_V13 * 1024;
    bool m_light_wallet_connected;
    uint64_t m_light_wallet_balance;
    uint64_t m_light_wallet_unlocked_balance;
    // Light wallet info needed to populate m_payment requires 2 separate api calls (get_address_txs and get_unspent_outs)
    // We save the info from the first call in m_light_wallet_address_txs for easier lookup.
    std::unordered_map<crypto::hash, address_tx> m_light_wallet_address_txs;
#endif

    // FIXME should this be with the light wallet stuff?
    // store calculated key image for faster lookup
    std::unordered_map<crypto::public_key, std::map<uint64_t, crypto::key_image> > m_key_image_cache;

    fs::path m_ring_database;
    bool m_ring_history_saved;
    std::unique_ptr<ringdb> m_ringdb;
    std::optional<crypto::chacha_key> m_ringdb_key;

    uint64_t m_last_block_reward;
    std::unique_ptr<tools::file_locker> m_keys_file_locker;
    
#ifdef WALLET_ENABLE_MMS
    mms::message_store m_message_store;
#endif
    bool m_original_keys_available;
    cryptonote::account_public_address m_original_address;
    crypto::secret_key m_original_view_secret_key;

    crypto::chacha_key m_cache_key;
    std::optional<epee::wipeable_string> m_encrypt_keys_after_refresh;
    std::mutex m_decrypt_keys_mutex;
    unsigned int m_decrypt_keys_lockers;

    bool m_unattended;
    bool m_devices_registered;

    std::shared_ptr<tools::Notify> m_tx_notify;
    std::unique_ptr<wallet_device_callback> m_device_callback;

    inline static std::mutex default_daemon_address_mutex;
    inline static std::string default_daemon_address;
  };

  // TODO(oxen): Hmm. We need this here because we make register_service_node do
  // parsing on the wallet2 side instead of simplewallet. This is so that
  // register_service_node RPC command doesn't make it the wallet_rpc's
  // responsibility to parse out the string returned from the daemon. We're
  // purposely abstracting that complexity out to just wallet2's responsibility.

  // TODO(oxen): The better question is if anyone is ever going to try use
  // register service node funded by multiple subaddresses. This is unlikely.
  constexpr std::array<const char* const, 6> allowed_priority_strings = {{"default", "unimportant", "normal", "elevated", "priority", "blink"}};
  bool parse_subaddress_indices(std::string_view arg, std::set<uint32_t>& subaddr_indices, std::string *err_msg = nullptr);
  bool parse_priority          (const std::string& arg, uint32_t& priority);

}
BOOST_CLASS_VERSION(tools::wallet2, 30)
BOOST_CLASS_VERSION(tools::wallet2::payment_details, 6)
BOOST_CLASS_VERSION(tools::wallet2::pool_payment_details, 1)
BOOST_CLASS_VERSION(tools::wallet2::unconfirmed_transfer_details, 9)
BOOST_CLASS_VERSION(tools::wallet2::confirmed_transfer_details, 8)
BOOST_CLASS_VERSION(tools::wallet2::address_book_row, 18)
BOOST_CLASS_VERSION(tools::wallet2::reserve_proof_entry, 0)
BOOST_CLASS_VERSION(tools::wallet2::ons_detail, 1)

namespace boost::serialization
{
    template <class Archive>
    void serialize(Archive &a, tools::wallet2::ons_detail &x, const unsigned int ver)
    {
      a & x.type;
      a & x.name;
      a & x.hashed_name;
      if (ver < 1)
      { // Old fields, no longer used:
        std::string value, owner, backup_owner;
        a & value & owner & backup_owner;
      }
    }

    template <class Archive>
    void serialize(Archive &a, tools::wallet2::unconfirmed_transfer_details &x, const unsigned int ver)
    {
      a & x.m_change;
      a & x.m_sent_time;
      if (ver < 5)
      {
        cryptonote::transaction tx;
        a & tx;
        x.m_tx = (const cryptonote::transaction_prefix&)tx;
      }
      else
      {
        a & x.m_tx;
      }
      if (ver < 9)
       x.m_pay_type = wallet::pay_type::out;
      if (ver < 1)
        return;
      a & x.m_dests;
      a & x.m_payment_id;
      if (ver < 2)
        return;
      a & x.m_state;
      if (ver < 3)
        return;
      a & x.m_timestamp;
      if (ver < 4)
        return;
      a & x.m_amount_in;
      a & x.m_amount_out;
      if (ver < 6)
      {
        // v<6 may not have change accumulated in m_amount_out, which is a pain,
        // as it's readily understood to be sum of outputs.
        // We convert it to include change from v6
        if (!typename Archive::is_saving() && x.m_change != (uint64_t)-1)
          x.m_amount_out += x.m_change;
      }
      if (ver < 7)
      {
        x.m_subaddr_account = 0;
        return;
      }
      a & x.m_subaddr_account;
      a & x.m_subaddr_indices;
      if (ver < 8)
        return;
      a & x.m_rings;
      if (ver < 9)
        return;
      a & x.m_pay_type;
    }

    template <class Archive>
    void serialize(Archive &a, tools::wallet2::confirmed_transfer_details &x, const unsigned int ver)
    {
      a & x.m_amount_in;
      a & x.m_amount_out;
      a & x.m_change;
      a & x.m_block_height;
      if (ver < 8)
        x.m_pay_type = wallet::pay_type::out;
      if (ver < 1)
        return;
      a & x.m_dests;
      a & x.m_payment_id;
      if (ver < 2)
        return;
      a & x.m_timestamp;
      if (ver < 3)
      {
        // v<3 may not have change accumulated in m_amount_out, which is a pain,
        // as it's readily understood to be sum of outputs. Whether it got added
        // or not depends on whether it came from a unconfirmed_transfer_details
        // (not included) or not (included). We can't reliably tell here, so we
        // check whether either yields a "negative" fee, or use the other if so.
        // We convert it to include change from v3
        if (!typename Archive::is_saving() && x.m_change != (uint64_t)-1)
        {
          if (x.m_amount_in > (x.m_amount_out + x.m_change))
            x.m_amount_out += x.m_change;
        }
      }
      if (ver < 4)
      {
        if (!typename Archive::is_saving())
          x.m_unlock_time = 0;
        return;
      }
      a & x.m_unlock_time;
      if (ver < 5)
      {
        x.m_subaddr_account = 0;
        return;
      }
      a & x.m_subaddr_account;
      a & x.m_subaddr_indices;
      if (ver < 6)
        return;
      a & x.m_rings;

      if (ver < 7)
        return;
      a & x.m_unlock_times;
      if (ver < 8)
        return;
      a & x.m_pay_type;
    }

    template <class Archive>
    void serialize(Archive& a, tools::wallet2::payment_details& x, const unsigned int ver)
    {
      a & x.m_tx_hash;
      a & x.m_amount;
      a & x.m_block_height;
      a & x.m_unlock_time;

      // Set defaults for old versions:
      if (ver < 1)
        x.m_timestamp = 0;
      if (ver < 2)
        x.m_subaddr_index = {};
      if (ver < 3)
        x.m_fee = 0;
      if (ver < 4)
        x.m_type = wallet::pay_type::in;
      if (ver < 5)
        x.m_unmined_blink = false;
      if (ver < 6)
        x.m_was_blink = false;


      if (ver < 1) return;
      a & x.m_timestamp;
      if (ver < 2) return;
      a & x.m_subaddr_index;
      if (ver < 3) return;
      a & x.m_fee;
      if (ver < 4) return;
      a & x.m_type;
      if (ver < 5) return;
      a & x.m_unmined_blink;
      if (ver < 6) return;
      a & x.m_was_blink;
    }

    template <class Archive>
    void serialize(Archive& a, tools::wallet2::pool_payment_details& x, const unsigned int ver)
    {
      a & x.m_pd;
      a & x.m_double_spend_seen;
    }

    template <class Archive>
    void serialize(Archive& a, tools::wallet2::address_book_row& x, const unsigned int ver)
    {
      a & x.m_address;
      if (ver < 18)
      {
        crypto::hash payment_id;
        a & payment_id;
        x.m_has_payment_id = !(payment_id == crypto::null_hash);
        if (x.m_has_payment_id)
        {
          bool is_long = false;
          for (int i = 8; i < 32; ++i)
            is_long |= payment_id.data[i];
          if (is_long)
          {
            MWARNING("Long payment ID ignored on address book load");
            x.m_payment_id = crypto::null_hash8;
            x.m_has_payment_id = false;
          }
          else
            memcpy(x.m_payment_id.data, payment_id.data, 8);
        }
      }
      a & x.m_description;
      if (ver < 17)
      {
        x.m_is_subaddress = false;
        return;
      }
      a & x.m_is_subaddress;
      if (ver < 18)
        return;
      a & x.m_has_payment_id;
      if (x.m_has_payment_id)
        a & x.m_payment_id;
    }

    template <class Archive>
    void serialize(Archive& a, tools::wallet2::reserve_proof_entry& x, const unsigned int ver)
    {
      a & x.txid;
      a & x.index_in_tx;
      a & x.shared_secret;
      a & x.key_image;
      a & x.shared_secret_sig;
      a & x.key_image_sig;
    }

}
