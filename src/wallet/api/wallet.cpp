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

#include "crypto/crypto.h"
#ifdef _WIN32
 #define __STDC_FORMAT_MACROS // NOTE(oxen): Explicitly define the PRIu64 macro on Mingw
#endif

#include "wallet.h"
#include "pending_transaction.h"
#include "unsigned_transaction.h"
#include "stake_unlock_result.h"
#include "transaction_history.h"
#include "address_book.h"
#include "subaddress.h"
#include "subaddress_account.h"
#include "common_defines.h"
#include "common/util.h"
#include "common/fs.h"

#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include <boost/format.hpp>
#include <sstream>
#include <unordered_map>
#include <thread>

using namespace cryptonote;

#undef OXEN_DEFAULT_LOG_CATEGORY
#define OXEN_DEFAULT_LOG_CATEGORY "WalletAPI"

namespace Wallet {

namespace {
    static const int    DEFAULT_REFRESH_INTERVAL_MILLIS = 1000 * 10;
    // limit maximum refresh interval as one minute
    static const int    MAX_REFRESH_INTERVAL_MILLIS = 1000 * 60 * 1;
    // Default refresh interval when connected to remote node
    static const int    DEFAULT_REMOTE_NODE_REFRESH_INTERVAL_MILLIS = 1000 * 10;
    // Connection timeout 30 sec
    static const int    DEFAULT_CONNECTION_TIMEOUT_MILLIS = 1000 * 30;

    fs::path get_default_ringdb_path(cryptonote::network_type nettype)
    {
      auto dir = tools::get_default_data_dir();
      // remove .oxen, replace with .shared-ringdb
      dir.replace_filename(".shared-ringdb");
      if (nettype == cryptonote::network_type::TESTNET)
        dir /= "testnet";
      else if (nettype == cryptonote::network_type::DEVNET)
        dir /= "devnet";
      return dir;
    }

    void checkMultisigWalletReady(LockedWallet& wallet) {
        if (!wallet.wallet)
            throw std::runtime_error("Wallet is not initialized yet");

        bool ready;
        if (!wallet->multisig(&ready))
            throw std::runtime_error("Wallet is not multisig");

        if (!ready)
            throw std::runtime_error("Multisig wallet is not finalized yet");
    }

    void checkMultisigWalletNotReady(LockedWallet& wallet) {
        if (!wallet.wallet)
            throw std::runtime_error("Wallet is not initialized yet");

        bool ready;
        if (!wallet->multisig(&ready))
            throw std::runtime_error("Wallet is not multisig");

        if (ready)
            throw std::runtime_error("Multisig wallet is already finalized");
    }
}

struct Wallet2CallbackImpl : public tools::i_wallet2_callback
{

    EXPORT
    Wallet2CallbackImpl(WalletImpl * wallet)
     : m_listener(nullptr)
     , m_wallet(wallet)
    {

    }

    EXPORT
    ~Wallet2CallbackImpl()
    {

    }

    EXPORT
    void setListener(WalletListener * listener)
    {
        m_listener = listener;
    }

    EXPORT
    WalletListener * getListener() const
    {
        return m_listener;
    }

    EXPORT
    void on_new_block(uint64_t height, const cryptonote::block& block) override
    {
        // Don't flood the GUI with signals. On fast refresh - send signal every 1000th block
        // get_refresh_from_block_height() returns the blockheight from when the wallet was 
        // created or the restore height specified when wallet was recovered
        // 
        if(height >= m_wallet->m_wallet_ptr->get_refresh_from_block_height() || height % 1000 == 0) {
            // LOG_PRINT_L3(__FUNCTION__ << ": new block. height: " << height);
            if (m_listener) {
                m_listener->newBlock(height);
            }
        }
    }

    EXPORT
    void on_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index, uint64_t unlock_time, bool blink) override
    {
        std::string tx_hash = tools::type_to_hex(txid);

        LOG_PRINT_L3(__FUNCTION__ << ": money received." << (blink ? "blink: " : "height: ") << height
                     << ", tx: " << tx_hash
                     << ", amount: " << print_money(amount)
                     << ", idx: " << subaddr_index);
        // do not signal on received tx if wallet is not syncronized completely
        if (m_listener && m_wallet->synchronized()) {
            m_listener->moneyReceived(tx_hash, amount);
            m_listener->updated();
        }
    }

    EXPORT
    void on_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx, uint64_t amount, const cryptonote::subaddress_index& subaddr_index) override
    {

        std::string tx_hash = tools::type_to_hex(txid);

        LOG_PRINT_L3(__FUNCTION__ << ": unconfirmed money received. height:  " << height
                     << ", tx: " << tx_hash
                     << ", amount: " << print_money(amount)
                     << ", idx: " << subaddr_index);
        // do not signal on received tx if wallet is not syncronized completely
        if (m_listener && m_wallet->synchronized()) {
            m_listener->unconfirmedMoneyReceived(tx_hash, amount);
            m_listener->updated();
        }
    }

    EXPORT
    void on_money_spent(uint64_t height,
                        const crypto::hash &txid,
                        const cryptonote::transaction &in_tx,
                        uint64_t amount,
                        const cryptonote::transaction &spend_tx,
                        const cryptonote::subaddress_index &subaddr_index) override
    {
        // TODO;
        std::string tx_hash = tools::type_to_hex(txid);
        LOG_PRINT_L3(__FUNCTION__ << ": money spent. height:  " << height
                     << ", tx: " << tx_hash
                     << ", amount: " << print_money(amount)
                     << ", idx: " << subaddr_index);
        // do not signal on sent tx if wallet is not syncronized completely
        if (m_listener && m_wallet->synchronized()) {
            m_listener->moneySpent(tx_hash, amount);
            m_listener->updated();
        }
    }

    EXPORT
    void on_skip_transaction(uint64_t height, const crypto::hash &txid, const cryptonote::transaction& tx) override
    {
        // TODO;
    }

    // Light wallet callbacks
    EXPORT
    void on_lw_new_block(uint64_t height) override
    {
      if (m_listener) {
        m_listener->newBlock(height);
      }
    }

    EXPORT
    void on_lw_money_received(uint64_t height, const crypto::hash &txid, uint64_t amount) override
    {
      if (m_listener) {
        std::string tx_hash = tools::type_to_hex(txid);
        m_listener->moneyReceived(tx_hash, amount);
      }
    }

    EXPORT
    void on_lw_unconfirmed_money_received(uint64_t height, const crypto::hash &txid, uint64_t amount) override
    {
      if (m_listener) {
        std::string tx_hash = tools::type_to_hex(txid);
        m_listener->unconfirmedMoneyReceived(tx_hash, amount);
      }
    }

    EXPORT
    void on_lw_money_spent(uint64_t height, const crypto::hash &txid, uint64_t amount) override
    {
      if (m_listener) {
        std::string tx_hash = tools::type_to_hex(txid);
        m_listener->moneySpent(tx_hash, amount);
      }
    }

    EXPORT
    void on_device_button_request(uint64_t code) override
    {
      if (m_listener) {
        m_listener->onDeviceButtonRequest(code);
      }
    }

    EXPORT
    void on_device_button_pressed() override
    {
      if (m_listener) {
        m_listener->onDeviceButtonPressed();
      }
    }

    EXPORT
    std::optional<epee::wipeable_string> on_device_pin_request() override
    {
      if (m_listener) {
        auto pin = m_listener->onDevicePinRequest();
        if (pin){
          return std::make_optional(epee::wipeable_string(pin->data(), pin->size()));
        }
      }
      return std::nullopt;
    }

    EXPORT
    std::optional<epee::wipeable_string> on_device_passphrase_request(bool& on_device) override
    {
      if (m_listener) {
        auto passphrase = m_listener->onDevicePassphraseRequest(on_device);
        if (passphrase) {
          return std::make_optional(epee::wipeable_string(passphrase->data(), passphrase->size()));
        }
      } else {
        on_device = true;
      }
      return std::nullopt;
    }

    EXPORT
    void on_device_progress(const hw::device_progress & event) override
    {
      if (m_listener) {
        m_listener->onDeviceProgress(DeviceProgress(event.progress(), event.indeterminate()));
      }
    }

    WalletListener * m_listener;
    WalletImpl     * m_wallet;
};

EXPORT
Wallet::~Wallet() {}

EXPORT
WalletListener::~WalletListener() {}


EXPORT
std::string Wallet::displayAmount(uint64_t amount)
{
    return cryptonote::print_money(amount);
}

EXPORT
uint64_t Wallet::amountFromString(const std::string &amount)
{
    return cryptonote::parse_amount(amount).value_or(0);
}

EXPORT
uint64_t Wallet::amountFromDouble(double amount)
{
    std::stringstream ss;
    ss << std::fixed << std::setprecision(oxen::DISPLAY_DECIMAL_POINT) << amount;
    return amountFromString(ss.str());
}

EXPORT
std::string Wallet::genPaymentId()
{
    crypto::hash8 payment_id = crypto::rand<crypto::hash8>();
    return tools::type_to_hex(payment_id);

}

EXPORT
bool Wallet::paymentIdValid(const std::string &payment_id)
{
    return payment_id.size() == 16 && oxenc::is_hex(payment_id);
}

EXPORT
bool Wallet::serviceNodePubkeyValid(const std::string &str)
{
    crypto::public_key sn_key;
    return str.size() == 64 && oxenc::is_hex(str);
}

EXPORT
bool Wallet::addressValid(const std::string &str, NetworkType nettype)
{
  cryptonote::address_parse_info info;
  return get_account_address_from_str(info, static_cast<cryptonote::network_type>(nettype), str);
}

EXPORT
bool Wallet::keyValid(const std::string &secret_key_string, const std::string &address_string, bool isViewKey, NetworkType nettype, std::string &error)
{
  cryptonote::address_parse_info info;
  if(!get_account_address_from_str(info, static_cast<cryptonote::network_type>(nettype), address_string)) {
      error = tr("Failed to parse address");
      return false;
  }

  crypto::secret_key key;
  if (!tools::hex_to_type(secret_key_string, unwrap(unwrap(key))))
  {
      error = tr("Failed to parse key");
      return false;
  }

  // check the key match the given address
  crypto::public_key pkey;
  if (!crypto::secret_key_to_public_key(key, pkey)) {
      error = tr("failed to verify key");
      return false;
  }
  bool matchAddress = false;
  if(isViewKey)
      matchAddress = info.address.m_view_public_key == pkey;
  else
      matchAddress = info.address.m_spend_public_key == pkey;

  if(!matchAddress) {
      error = tr("key does not match address");
      return false;
  }
  
  return true;
}

EXPORT
std::string Wallet::paymentIdFromAddress(const std::string &str, NetworkType nettype)
{
  cryptonote::address_parse_info info;
  if (!get_account_address_from_str(info, static_cast<cryptonote::network_type>(nettype), str))
    return "";
  if (!info.has_payment_id)
    return "";
  return tools::type_to_hex(info.payment_id);
}

EXPORT
uint64_t Wallet::maximumAllowedAmount()
{
    return std::numeric_limits<uint64_t>::max();
}

EXPORT
void Wallet::init(const char *argv0, const char *default_log_base_name, const std::string& log_path, bool console) {
    epee::string_tools::set_module_name_and_folder(argv0);
    mlog_configure(log_path.empty() ? mlog_get_default_log_path(default_log_base_name) : log_path, console);
}

EXPORT
void Wallet::debug(const std::string &category, const std::string &str) {
    MCDEBUG(category.empty() ? OXEN_DEFAULT_LOG_CATEGORY : category.c_str(), str);
}

EXPORT
void Wallet::info(const std::string &category, const std::string &str) {
    MCINFO(category.empty() ? OXEN_DEFAULT_LOG_CATEGORY : category.c_str(), str);
}

EXPORT
void Wallet::warning(const std::string &category, const std::string &str) {
    MCWARNING(category.empty() ? OXEN_DEFAULT_LOG_CATEGORY : category.c_str(), str);
}

EXPORT
void Wallet::error(const std::string &category, const std::string &str) {
    MCERROR(category.empty() ? OXEN_DEFAULT_LOG_CATEGORY : category.c_str(), str);
}

///////////////////////// WalletImpl implementation ////////////////////////
EXPORT
WalletImpl::WalletImpl(NetworkType nettype, uint64_t kdf_rounds)
    :m_wallet_ptr(nullptr)
    , m_status(Wallet::Status_Ok, "")
    , m_wallet2Callback(nullptr)
    , m_recoveringFromSeed(false)
    , m_recoveringFromDevice(false)
    , m_synchronized(false)
    , m_rebuildWalletCache(false)
    , m_is_connected(false)
    , m_refreshShouldRescan(false)
{
    m_wallet_ptr.reset(new tools::wallet2(static_cast<cryptonote::network_type>(nettype), kdf_rounds, true));
    m_history.reset(new TransactionHistoryImpl(this));
    m_wallet2Callback.reset(new Wallet2CallbackImpl(this));
    m_wallet_ptr->callback(m_wallet2Callback.get());
    m_refreshThreadDone = false;
    m_refreshEnabled = false;
    m_addressBook.reset(new AddressBookImpl(this));
    m_subaddress.reset(new SubaddressImpl(this));
    m_subaddressAccount.reset(new SubaddressAccountImpl(this));


    m_refreshIntervalMillis = DEFAULT_REFRESH_INTERVAL_MILLIS;

    m_refreshThread = std::thread([this] { refreshThreadFunc(); });

    m_longPollThread = std::thread([this] {
      for (;;)
      {
        if (m_wallet_ptr->m_long_poll_disabled)
          return true;
        try {
          if (m_refreshEnabled && m_wallet_ptr->long_poll_pool_state())
            m_refreshCV.notify_one();
        } catch (...) { /* ignore */ }

        std::this_thread::sleep_for(1s);
      }
    });
}

EXPORT
WalletImpl::~WalletImpl()
{

    LOG_PRINT_L1(__FUNCTION__);
    m_wallet_ptr->callback(nullptr);
    // Stop refresh and long poll threads
    stopRefresh();
    m_wallet_ptr->cancel_long_poll();
    if (m_longPollThread.joinable())
      m_longPollThread.join();

    // Close wallet - stores cache and stops ongoing refresh operation 
    close(false); // do not store wallet as part of the closing activities

    if (m_wallet2Callback->getListener()) {
      m_wallet2Callback->getListener()->onSetWallet(nullptr);
    }

    LOG_PRINT_L1(__FUNCTION__ << " finished");
}

EXPORT
bool WalletImpl::create(std::string_view path_, const std::string &password, const std::string &language)
{

    auto path = fs::u8path(path_);
    clearStatus();
    m_recoveringFromSeed = false;
    m_recoveringFromDevice = false;
    bool keys_file_exists;
    bool wallet_file_exists;
    tools::wallet2::wallet_exists(path, keys_file_exists, wallet_file_exists);
    LOG_PRINT_L3("wallet_path: " << path);
    LOG_PRINT_L3("keys_file_exists: " << std::boolalpha << keys_file_exists << std::noboolalpha
                 << "  wallet_file_exists: " << std::boolalpha << wallet_file_exists << std::noboolalpha);


    // add logic to error out if new wallet requested but named wallet file exists
    if (keys_file_exists || wallet_file_exists) {
        std::string error = "attempting to generate or restore wallet, but specified file(s) exist.  Exiting to not risk overwriting.";
        LOG_ERROR(error);
        setStatusCritical(error);
        return false;
    }
    // TODO: validate language
    auto w = wallet();
    w->set_seed_language(language);
    crypto::secret_key recovery_val, secret_key;
    try {
        recovery_val = w->generate(path, password, secret_key, false, false);
        m_password = password;
        clearStatus();
    } catch (const std::exception &e) {
        LOG_ERROR("Error creating wallet: " << e.what());
        setStatusCritical(e.what());
        return false;
    }

    return true;
}

EXPORT
bool WalletImpl::createWatchOnly(std::string_view path_, const std::string &password, const std::string &language) const
{
    auto path = fs::u8path(path_);
    auto w = wallet();
    clearStatus();
    std::unique_ptr<tools::wallet2> view_wallet(new tools::wallet2(w->nettype()));

    // Store same refresh height as original wallet
    view_wallet->set_refresh_from_block_height(w->get_refresh_from_block_height());

    bool keys_file_exists;
    bool wallet_file_exists;
    tools::wallet2::wallet_exists(path, keys_file_exists, wallet_file_exists);
    LOG_PRINT_L3("wallet_path: " << path);
    LOG_PRINT_L3("keys_file_exists: " << std::boolalpha << keys_file_exists << std::noboolalpha
                 << "  wallet_file_exists: " << std::boolalpha << wallet_file_exists << std::noboolalpha);

    // add logic to error out if new wallet requested but named wallet file exists
    if (keys_file_exists || wallet_file_exists) {
        std::string error = "attempting to generate view only wallet, but specified file(s) exist.  Exiting to not risk overwriting.";
        LOG_ERROR(error);
        setStatusError(error);
        return false;
    }
    // TODO: validate language
    view_wallet->set_seed_language(language);

    const crypto::secret_key viewkey = w->get_account().get_keys().m_view_secret_key;
    const cryptonote::account_public_address address = w->get_account().get_keys().m_account_address;

    try {
        // Generate view only wallet
        view_wallet->generate(path, password, address, viewkey);

        // Export/Import outputs
        auto outputs = w->export_outputs();
        view_wallet->import_outputs(outputs);

        // Copy scanned blockchain
        auto bc = w->export_blockchain();
        view_wallet->import_blockchain(bc);

        // copy payments
        auto payments = w->export_payments();
        view_wallet->import_payments(payments);

        // copy confirmed outgoing payments
        std::list<std::pair<crypto::hash, tools::wallet2::confirmed_transfer_details>> out_payments;
        w->get_payments_out(out_payments, 0);
        view_wallet->import_payments_out(out_payments);

        // Export/Import key images
        // We already know the spent status from the outputs we exported, thus no need to check them again
        auto key_images = w->export_key_images(false /* requested_ki_only */);
        uint64_t spent = 0;
        uint64_t unspent = 0;
        view_wallet->import_key_images(key_images.second, key_images.first, spent, unspent, false);
        clearStatus();
    } catch (const std::exception &e) {
        LOG_ERROR("Error creating view only wallet: " << e.what());
        setStatusError(e.what());
        return false;
    }
    // Store wallet
    view_wallet->store();
    return true;
}

EXPORT
bool WalletImpl::recoverFromKeysWithPassword(std::string_view path_,
                                 const std::string &password,
                                 const std::string &language,
                                 const std::string &address_string,
                                 const std::string &viewkey_string,
                                 const std::string &spendkey_string)
{
    auto path = fs::u8path(path_);
    cryptonote::address_parse_info info;
    if(!get_account_address_from_str(info, m_wallet_ptr->nettype(), address_string))
    {
        setStatusError(tr("failed to parse address"));
        return false;
    }

    // parse optional spend key
    crypto::secret_key spendkey;
    bool has_spendkey = !spendkey_string.empty();
    if (has_spendkey && !tools::hex_to_type(spendkey_string, unwrap(unwrap(spendkey))))
    {
        setStatusError(tr("failed to parse secret spend key"));
        return false;
    }

    // parse view secret key
    bool has_viewkey = true;
    crypto::secret_key viewkey;
    if (viewkey_string.empty()) {
        if(has_spendkey) {
          has_viewkey = false;
        }
        else {
          setStatusError(tr("Neither view key nor spend key supplied, cancelled"));
          return false;
        }
    }
    if(has_viewkey) {
      if (!tools::hex_to_type(viewkey_string, unwrap(unwrap(viewkey))))
      {
          setStatusError(tr("failed to parse secret view key"));
          return false;
      }
    }
    // check the spend and view keys match the given address
    crypto::public_key pkey;
    if(has_spendkey) {
        if (!crypto::secret_key_to_public_key(spendkey, pkey)) {
            setStatusError(tr("failed to verify secret spend key"));
            return false;
        }
        if (info.address.m_spend_public_key != pkey) {
            setStatusError(tr("spend key does not match address"));
            return false;
        }
    }
    if(has_viewkey) {
       if (!crypto::secret_key_to_public_key(viewkey, pkey)) {
           setStatusError(tr("failed to verify secret view key"));
           return false;
       }
       if (info.address.m_view_public_key != pkey) {
           setStatusError(tr("view key does not match address"));
           return false;
       }
    }

    try
    {
        auto w = wallet();
        if (has_spendkey && has_viewkey) {
            w->generate(path, password, info.address, spendkey, viewkey);
            LOG_PRINT_L1("Generated new wallet from spend key and view key");
        }
        if(!has_spendkey && has_viewkey) {
            w->generate(path, password, info.address, viewkey);
            LOG_PRINT_L1("Generated new view only wallet from keys");
        }
        if(has_spendkey && !has_viewkey) {
            w->generate(path, password, spendkey, true, false);
            setSeedLanguage(language);
            LOG_PRINT_L1("Generated deterministic wallet from spend key with seed language: " + language);
        }
        
    }
    catch (const std::exception& e) {
        setStatusError(std::string(tr("failed to generate new wallet: ")) + e.what());
        return false;
    }
    return true;
}

EXPORT
bool WalletImpl::recoverFromDevice(std::string_view path_, const std::string &password, const std::string &device_name)
{
    auto path = fs::u8path(path_);
    clearStatus();
    auto w = wallet();
    m_recoveringFromSeed = false;
    m_recoveringFromDevice = true;
    try
    {
        w->restore_from_device(path, password, device_name);
        LOG_PRINT_L1("Generated new wallet from device: " + device_name);
    }
    catch (const std::exception& e) {
        setStatusError(std::string(tr("failed to generate new wallet: ")) + e.what());
        return false;
    }
    return true;
}

EXPORT
Wallet::Device WalletImpl::getDeviceType() const
{
    return static_cast<Wallet::Device>(m_wallet_ptr->get_device_type());
}

EXPORT
bool WalletImpl::open(std::string_view path_, const std::string &password)
{
    auto path = fs::u8path(path_);
    clearStatus();
    auto w = wallet();
    m_recoveringFromSeed = false;
    m_recoveringFromDevice = false;
    try {
        // TODO: handle "deprecated"
        // Check if wallet cache exists
        bool keys_file_exists;
        bool wallet_file_exists;
        tools::wallet2::wallet_exists(path, keys_file_exists, wallet_file_exists);
        if(!wallet_file_exists){
            // Rebuilding wallet cache, using refresh height from .keys file
            m_rebuildWalletCache = true;
        }
        w->set_ring_database(get_default_ringdb_path(w->nettype()));
        w->load(path, password);

        m_password = password;
    } catch (const std::exception &e) {
        LOG_ERROR("Error opening wallet: " << e.what());
        setStatusCritical(e.what());
    }
    return good();
}

EXPORT
bool WalletImpl::recover(std::string_view path_, const std::string &password, const std::string &seed, const std::string &seed_offset/* = {}*/)
{
    auto path = fs::u8path(path_);
    clearStatus();
    if (seed.empty()) {
        LOG_ERROR("Electrum seed is empty");
        setStatusError(tr("Electrum seed is empty"));
        return false;
    }

    m_recoveringFromSeed = true;
    m_recoveringFromDevice = false;
    crypto::secret_key recovery_key;
    std::string old_language;
    if (!crypto::ElectrumWords::words_to_bytes(seed, recovery_key, old_language)) {
        setStatusError(tr("Electrum-style word list failed verification"));
        return false;
    }
    if (!seed_offset.empty())
    {
        recovery_key = cryptonote::decrypt_key(recovery_key, seed_offset);
    }

    if (old_language == crypto::ElectrumWords::old_language_name)
        old_language = Language::English().get_language_name();

    try {
        auto w = wallet();
        w->set_seed_language(old_language);
        w->generate(path, password, recovery_key, true, false);

    } catch (const std::exception &e) {
        setStatusCritical(e.what());
    }
    return good();
}

EXPORT
bool WalletImpl::close(bool store)
{

    bool result = false;
    LOG_PRINT_L1("closing wallet...");
    try {
        auto w = wallet();
        if (store) {
            // Do not store wallet with invalid status
            // Status Critical refers to errors on opening or creating wallets.
            if (status().first != Status_Critical)
                w->store();
            else
                LOG_ERROR("Status_Critical - not saving wallet");
            LOG_PRINT_L1("wallet::store done");
        }
        LOG_PRINT_L1("Calling wallet::stop...");
        w->stop();
        LOG_PRINT_L1("wallet::stop done");
        w->deinit();
        result = true;
        clearStatus();
    } catch (const std::exception &e) {
        setStatusCritical(e.what());
        LOG_ERROR("Error closing wallet: " << e.what());
    }
    return result;
}

EXPORT
std::string WalletImpl::seed() const
{
    epee::wipeable_string seed;
    if (m_wallet_ptr)
        wallet()->get_seed(seed);
    return std::string(seed.data(), seed.size()); // TODO
}

EXPORT
std::string WalletImpl::getSeedLanguage() const
{
    return wallet()->get_seed_language();
}

EXPORT
void WalletImpl::setSeedLanguage(const std::string &arg)
{
    wallet()->set_seed_language(arg);
}

EXPORT
std::pair<int, std::string> WalletImpl::status() const {
    std::lock_guard l{m_statusMutex};
    return m_status;
}
EXPORT
bool WalletImpl::good() const {
    std::lock_guard l{m_statusMutex};
    return m_status.first == Status_Ok;
}

EXPORT
bool WalletImpl::setPassword(const std::string &password)
{
    clearStatus();
    try {
        auto w = wallet();
        w->change_password(w->get_wallet_file(), m_password, password);
        m_password = password;
    } catch (const std::exception &e) {
        setStatusError(e.what());
    }
    return good();
}

EXPORT
bool WalletImpl::setDevicePin(const std::string &pin)
{
    clearStatus();
    try {
        wallet()->get_account().get_device().set_pin(epee::wipeable_string(pin.data(), pin.size()));
    } catch (const std::exception &e) {
        setStatusError(e.what());
    }
    return good();
}

EXPORT
bool WalletImpl::setDevicePassphrase(const std::string &passphrase)
{
    clearStatus();
    try {
        wallet()->get_account().get_device().set_passphrase(epee::wipeable_string(passphrase.data(), passphrase.size()));
    } catch (const std::exception &e) {
        setStatusError(e.what());
    }
    return good();
}

EXPORT
std::string WalletImpl::address(uint32_t accountIndex, uint32_t addressIndex) const
{
    return wallet()->get_subaddress_as_str({accountIndex, addressIndex});
}

EXPORT
std::string WalletImpl::integratedAddress(const std::string &payment_id) const
{
    crypto::hash8 pid;
    if (!tools::hex_to_type(payment_id, pid))
        return "";
    return wallet()->get_integrated_address_as_str(pid);
}

EXPORT
std::string WalletImpl::secretViewKey() const
{
    return tools::type_to_hex(wallet()->get_account().get_keys().m_view_secret_key);
}

EXPORT
std::string WalletImpl::publicViewKey() const
{
    return tools::type_to_hex(wallet()->get_account().get_keys().m_account_address.m_view_public_key);
}

EXPORT
std::string WalletImpl::secretSpendKey() const
{
    return tools::type_to_hex(wallet()->get_account().get_keys().m_spend_secret_key);
}

EXPORT
std::string WalletImpl::publicSpendKey() const
{
    return tools::type_to_hex(wallet()->get_account().get_keys().m_account_address.m_spend_public_key);
}

EXPORT
std::string WalletImpl::publicMultisigSignerKey() const
{
    try {
        crypto::public_key signer = wallet()->get_multisig_signer_public_key();
        return tools::type_to_hex(signer);
    } catch (const std::exception&) {
        return "";
    }
}

EXPORT
std::string WalletImpl::path() const
{
    return wallet()->path().u8string();
}

EXPORT
bool WalletImpl::store(std::string_view path_)
{
    auto path = fs::u8path(path_);
    clearStatus();
    try {
        if (path.empty()) {
            wallet()->store();
        } else {
            wallet()->store_to(path, m_password);
        }
    } catch (const std::exception &e) {
        LOG_ERROR("Error saving wallet: " << e.what());
        setStatusError(e.what());
        return false;
    }

    return true;
}

EXPORT
std::string WalletImpl::filename() const
{
    return wallet()->get_wallet_file().u8string();
}

EXPORT
std::string WalletImpl::keysFilename() const
{
    return wallet()->get_keys_file().u8string();
}

EXPORT
bool WalletImpl::init(const std::string &daemon_address, uint64_t upper_transaction_size_limit, const std::string &daemon_username, const std::string &daemon_password, bool use_ssl ENABLE_IF_LIGHT_WALLET(, bool lightWallet))
{
    clearStatus();
#ifdef ENABLE_LIGHT_WALLET
    wallet()->set_light_wallet(lightWallet);
#endif
    if(daemon_username != "")
        m_daemon_login.emplace(daemon_username, daemon_password);
    return doInit(daemon_address, upper_transaction_size_limit, use_ssl);
}

#ifdef ENABLE_LIGHT_WALLET
EXPORT
bool WalletImpl::lightWalletLogin(bool &isNewWallet) const
{
  return wallet()->light_wallet_login(isNewWallet);
}

EXPORT
bool WalletImpl::lightWalletImportWalletRequest(std::string &payment_id, uint64_t &fee, bool &new_request, bool &request_fulfilled, std::string &payment_address, std::string &status)
{
  try
  {
    tools::light_rpc::IMPORT_WALLET_REQUEST::response response{};
    if(!wallet()->light_wallet_import_wallet_request(response)){
      setStatusError(tr("Failed to send import wallet request"));
      return false;
    }
    fee = response.import_fee;
    payment_id = response.payment_id;
    new_request = response.new_request;
    request_fulfilled = response.request_fulfilled;
    payment_address = response.payment_address;
    status = response.status;
  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Error sending import wallet request: " << e.what());
    setStatusError(e.what());
    return false;
  }
  return true;
}
#endif

EXPORT
void WalletImpl::setRefreshFromBlockHeight(uint64_t refresh_from_block_height)
{
    wallet()->set_refresh_from_block_height(refresh_from_block_height);
}

EXPORT
void WalletImpl::setRecoveringFromSeed(bool recoveringFromSeed)
{
    m_recoveringFromSeed = recoveringFromSeed;
}

EXPORT
void WalletImpl::setRecoveringFromDevice(bool recoveringFromDevice)
{
    m_recoveringFromDevice = recoveringFromDevice;
}

EXPORT
void WalletImpl::setSubaddressLookahead(uint32_t major, uint32_t minor)
{
    wallet()->set_subaddress_lookahead(major, minor);
}

EXPORT
uint64_t WalletImpl::balance(uint32_t accountIndex) const
{
    return wallet()->balance(accountIndex, false);
}

EXPORT
uint64_t WalletImpl::unlockedBalance(uint32_t accountIndex) const
{
    return wallet()->unlocked_balance(accountIndex, false);
}

EXPORT
uint64_t WalletImpl::accruedBalance(std::optional<std::string> address) const
{
    return wallet()->get_batched_amount(std::move(address));
}

EXPORT
uint64_t WalletImpl::nextAccruedPaymentHeight(std::optional<std::string> address) const
{
    return wallet()->get_next_batch_payout(std::move(address));
}

EXPORT
std::vector<Wallet::stake_info>* WalletImpl::listCurrentStakes() const
{
    auto* stakes = new std::vector<Wallet::stake_info>;

    auto response = wallet()->get_staked_service_nodes();
    auto main_addr = mainAddress();

    for (const auto& node_info : response)
        for (const auto& contributor : node_info.contributors)
            if (contributor.address == main_addr) {
                auto& info = stakes->emplace_back();
                info.sn_pubkey = node_info.service_node_pubkey;
                info.stake = contributor.amount;
                if (node_info.requested_unlock_height != 0)
                    info.unlock_height = node_info.requested_unlock_height;
                info.awaiting = !node_info.funded;
                info.decommissioned = node_info.funded && !node_info.active;
            }

    return stakes;
}

EXPORT
uint64_t WalletImpl::blockChainHeight() const
{
    // This call is thread-safe
    auto& w = m_wallet_ptr;
#ifdef ENABLE_LIGHT_WALLET
    if(w->light_wallet()) {
        return w->get_light_wallet_scanned_block_height();
    }
#endif
    return w->get_blockchain_current_height();
}
EXPORT
uint64_t WalletImpl::approximateBlockChainHeight() const
{
    return wallet()->get_approximate_blockchain_height();
}

EXPORT
uint64_t WalletImpl::estimateBlockChainHeight() const
{
    return wallet()->estimate_blockchain_height();
}

EXPORT
uint64_t WalletImpl::daemonBlockChainHeight() const
{
    // I *think* the calls here are thread-safe, so we can do this without locking
    //auto w = wallet();
    auto& w = m_wallet_ptr;

#ifdef ENABLE_LIGHT_WALLET
    if(w->light_wallet()) {
        return w->get_light_wallet_scanned_block_height();
    }
#endif
    if (!m_is_connected)
        return 0;
    std::string err;
    uint64_t result = w->get_daemon_blockchain_height(err);
    if (!err.empty()) {
        LOG_ERROR(__FUNCTION__ << ": " << err);
        result = 0;
        setStatusError(err);
    } else {
        clearStatus();
    }
    return result;
}

EXPORT
uint64_t WalletImpl::daemonBlockChainTargetHeight() const
{
    // As above
    //auto w = wallet();
    auto& w = m_wallet_ptr;

#ifdef ENABLE_LIGHT_WALLET
    if(w->light_wallet()) {
        return w->get_light_wallet_blockchain_height();
    }
#endif
    if (!m_is_connected)
        return 0;
    std::string err;
    uint64_t result = w->get_daemon_blockchain_target_height(err);
    if (!err.empty()) {
        LOG_ERROR(__FUNCTION__ << ": " << err);
        result = 0;
        setStatusError(err);
    } else {
        clearStatus();
    }
    // Target height can be 0 when daemon is synced. Use blockchain height instead. 
    if(result == 0)
        result = daemonBlockChainHeight();
    return result;
}

EXPORT
bool WalletImpl::daemonSynced() const
{   
    if(connected() == Wallet::ConnectionStatus_Disconnected)
        return false;
    uint64_t blockChainHeight = daemonBlockChainHeight();
    return (blockChainHeight >= daemonBlockChainTargetHeight() && blockChainHeight > 1);
}

EXPORT
bool WalletImpl::synchronized() const
{
    return m_synchronized;
}

EXPORT
bool WalletImpl::refresh()
{
    clearStatus();
    //TODO: make doRefresh return bool to know whether the error occured during refresh or not
    //otherwise one may try, say, to send transaction, transfer fails and this method returns false
    doRefresh();
    return good();
}

EXPORT
void WalletImpl::refreshAsync()
{
    LOG_PRINT_L3(__FUNCTION__ << ": Refreshing asynchronously..");
    clearStatus();
    m_refreshCV.notify_one();
}

EXPORT
bool WalletImpl::isRefreshing(std::chrono::milliseconds max_wait) {
    std::unique_lock lock{m_refreshMutex2, std::defer_lock};
    return !lock.try_lock_for(max_wait);
}

EXPORT
bool WalletImpl::rescanBlockchain()
{
    clearStatus();
    m_refreshShouldRescan = true;
    doRefresh();
    return good();
}

EXPORT
void WalletImpl::rescanBlockchainAsync()
{
    m_refreshShouldRescan = true;
    refreshAsync();
}

EXPORT
void WalletImpl::setAutoRefreshInterval(int millis)
{
    if (millis > MAX_REFRESH_INTERVAL_MILLIS) {
        LOG_ERROR(__FUNCTION__<< ": invalid refresh interval " << millis
                  << " ms, maximum allowed is " << MAX_REFRESH_INTERVAL_MILLIS << " ms");
        m_refreshIntervalMillis = MAX_REFRESH_INTERVAL_MILLIS;
    } else {
        m_refreshIntervalMillis = millis;
    }
}

EXPORT
int WalletImpl::autoRefreshInterval() const
{
    return m_refreshIntervalMillis;
}

UnsignedTransaction* WalletImpl::loadUnsignedTx(std::string_view unsigned_filename_) {
  auto unsigned_filename = fs::u8path(unsigned_filename_);
  clearStatus();
  UnsignedTransactionImpl* transaction = new UnsignedTransactionImpl(*this);
  if (!wallet()->load_unsigned_tx(unsigned_filename, transaction->m_unsigned_tx_set)){
    setStatusError(tr("Failed to load unsigned transactions"));
    transaction->m_status = {UnsignedTransaction::Status::Status_Error, status().second};

    return transaction;
  }
  
  // Check tx data and construct confirmation message
  std::string extra_message;
  if (!transaction->m_unsigned_tx_set.transfers.second.empty())
    extra_message = (boost::format("%u outputs to import. ") % (unsigned)transaction->m_unsigned_tx_set.transfers.second.size()).str();
  transaction->checkLoadedTx([&transaction](){return transaction->m_unsigned_tx_set.txes.size();}, [&transaction](size_t n)->const wallet::tx_construction_data&{return transaction->m_unsigned_tx_set.txes[n];}, extra_message);
  auto [code, msg] = transaction->status();
  setStatus(code, std::move(msg));

  return transaction;
}

EXPORT
bool WalletImpl::submitTransaction(std::string_view filename_) {
  auto fileName = fs::u8path(filename_);
  clearStatus();
  std::unique_ptr<PendingTransactionImpl> transaction(new PendingTransactionImpl(*this));

  bool r = wallet()->load_tx(fileName, transaction->m_pending_tx);
  if (!r) {
    setStatus(Status_Error, tr("Failed to load transaction from file"));
    return false;
  }
  
  if(!transaction->commit()) {
    setStatusError(transaction->status().second);
    return false;
  }

  return true;
}

EXPORT
bool WalletImpl::exportKeyImages(std::string_view filename_) 
{
  auto filename = fs::u8path(filename_);
  auto w = wallet();
  if (w->watch_only())
  {
    setStatusError(tr("Wallet is view only"));
    return false;
  }
  
  try
  {
    if (!w->export_key_images_to_file(filename, false /* requested_ki_only */))
    {
      setStatusError(tr("failed to save file ") + filename.u8string());
      return false;
    }
  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Error exporting key images: " << e.what());
    setStatusError(e.what());
    return false;
  }
  return true;
}

EXPORT
bool WalletImpl::importKeyImages(std::string_view filename_)
{
  auto filename = fs::u8path(filename_);
  if (!trustedDaemon()) {
    setStatusError(tr("Key images can only be imported with a trusted daemon"));
    return false;
  }
  try
  {
    uint64_t spent = 0, unspent = 0;
    uint64_t height = wallet()->import_key_images_from_file(filename, spent, unspent);
    LOG_PRINT_L2("Signed key images imported to height " << height << ", "
        << print_money(spent) << " spent, " << print_money(unspent) << " unspent");
  }
  catch (const std::exception &e)
  {
    LOG_ERROR("Error exporting key images: " << e.what());
    setStatusError(std::string(tr("Failed to import key images: ")) + e.what());
    return false;
  }

  return true;
}

EXPORT
void WalletImpl::addSubaddressAccount(const std::string& label)
{
    wallet()->add_subaddress_account(label);
}
EXPORT
size_t WalletImpl::numSubaddressAccounts() const
{
    return wallet()->get_num_subaddress_accounts();
}
EXPORT
size_t WalletImpl::numSubaddresses(uint32_t accountIndex) const
{
    return wallet()->get_num_subaddresses(accountIndex);
}
EXPORT
void WalletImpl::addSubaddress(uint32_t accountIndex, const std::string& label)
{
    wallet()->add_subaddress(accountIndex, label);
}
EXPORT
std::string WalletImpl::getSubaddressLabel(uint32_t accountIndex, uint32_t addressIndex) const
{
    try
    {
        return wallet()->get_subaddress_label({accountIndex, addressIndex});
    }
    catch (const std::exception &e)
    {
        LOG_ERROR("Error getting subaddress label: " << e.what());
        setStatusError(std::string(tr("Failed to get subaddress label: ")) + e.what());
        return "";
    }
}
EXPORT
void WalletImpl::setSubaddressLabel(uint32_t accountIndex, uint32_t addressIndex, const std::string &label)
{
    try
    {
        return wallet()->set_subaddress_label({accountIndex, addressIndex}, label);
    }
    catch (const std::exception &e)
    {
        LOG_ERROR("Error setting subaddress label: " << e.what());
        setStatusError(std::string(tr("Failed to set subaddress label: ")) + e.what());
    }
}

MultisigState WalletImpl::multisig(LockedWallet& w) {
    MultisigState state;
    state.isMultisig = w->multisig(&state.isReady, &state.threshold, &state.total);
    return state;
}

EXPORT
MultisigState WalletImpl::multisig() const {
    auto w = wallet();
    return multisig(w);
}

EXPORT
std::string WalletImpl::getMultisigInfo() const {
    try {
        clearStatus();
        return wallet()->get_multisig_info();
    } catch (const std::exception& e) {
        LOG_ERROR("Error on generating multisig info: " << e.what());
        setStatusError(std::string(tr("Failed to get multisig info: ")) + e.what());
    }

    return {};
}

EXPORT
std::string WalletImpl::makeMultisig(const std::vector<std::string>& info, uint32_t threshold) {
    try {
        clearStatus();

        auto w = wallet();
        if (w->multisig())
            throw std::runtime_error("Wallet is already multisig");

        return w->make_multisig(epee::wipeable_string(m_password), info, threshold);
    } catch (const std::exception& e) {
        LOG_ERROR("Error on making multisig wallet: " << e.what());
        setStatusError(std::string(tr("Failed to make multisig: ")) + e.what());
    }

    return {};
}

EXPORT
std::string WalletImpl::exchangeMultisigKeys(const std::vector<std::string> &info) {
    try {
        clearStatus();
        auto w = wallet();
        checkMultisigWalletNotReady(w);

        return w->exchange_multisig_keys(epee::wipeable_string(m_password), info);
    } catch (const std::exception& e) {
        LOG_ERROR("Error on exchanging multisig keys: " << e.what());
        setStatusError(std::string(tr("Failed to make multisig: ")) + e.what());
    }

    return {};
}

EXPORT
bool WalletImpl::finalizeMultisig(const std::vector<std::string>& extraMultisigInfo) {
    try {
        clearStatus();
        auto w = wallet();
        checkMultisigWalletNotReady(w);

        if (w->finalize_multisig(epee::wipeable_string(m_password), extraMultisigInfo)) {
            return true;
        }

        setStatusError(tr("Failed to finalize multisig wallet creation"));
    } catch (const std::exception& e) {
        LOG_ERROR("Error on finalizing multisig wallet creation: " << e.what());
        setStatusError(std::string(tr("Failed to finalize multisig wallet creation: ")) + e.what());
    }

    return false;
}

EXPORT
bool WalletImpl::exportMultisigImages(std::string& images) {
    try {
        clearStatus();
        auto w = wallet();
        checkMultisigWalletReady(w);

        auto blob = w->export_multisig();
        images = oxenc::to_hex(blob);
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Error on exporting multisig images: " << e.what());
        setStatusError(std::string(tr("Failed to export multisig images: ")) + e.what());
    }

    return false;
}

EXPORT
size_t WalletImpl::importMultisigImages(const std::vector<std::string>& images) {
    try {
        clearStatus();
        auto w = wallet();
        checkMultisigWalletReady(w);

        std::vector<std::string> blobs;
        blobs.reserve(images.size());

        for (const auto& image: images) {
            if (!oxenc::is_hex(image)) {
                LOG_ERROR("Failed to parse imported multisig images");
                setStatusError(tr("Failed to parse imported multisig images"));
                return 0;
            }

            blobs.push_back(oxenc::from_hex(image));
        }

        return w->import_multisig(blobs);
    } catch (const std::exception& e) {
        LOG_ERROR("Error on importing multisig images: " << e.what());
        setStatusError(std::string(tr("Failed to import multisig images: ")) + e.what());
    }

    return 0;
}

EXPORT
bool WalletImpl::hasMultisigPartialKeyImages() const {
    try {
        clearStatus();
        auto w = wallet();
        checkMultisigWalletReady(w);

        return w->has_multisig_partial_key_images();
    } catch (const std::exception& e) {
        LOG_ERROR("Error on checking for partial multisig key images: " << e.what());
        setStatusError(std::string(tr("Failed to check for partial multisig key images: ")) + e.what());
    }

    return false;
}

EXPORT
PendingTransaction* WalletImpl::restoreMultisigTransaction(const std::string& signData) {
    try {
        clearStatus();
        auto w = wallet();
        checkMultisigWalletReady(w);

        if (!oxenc::is_hex(signData))
            throw std::runtime_error("Failed to deserialize multisig transaction");

        tools::wallet2::multisig_tx_set txSet;
        if (!w->load_multisig_tx(oxenc::from_hex(signData), txSet, {}))
          throw std::runtime_error("couldn't parse multisig transaction data");

        auto ptx = new PendingTransactionImpl(*this);
        ptx->m_pending_tx = txSet.m_ptx;
        ptx->m_signers = txSet.m_signers;

        return ptx;
    } catch (std::exception& e) {
        LOG_ERROR("Error on restoring multisig transaction: " << e.what());
        setStatusError(std::string(tr("Failed to restore multisig transaction: ")) + e.what());
    }

    return nullptr;
}

// TODO:
// - check / design how "Transaction" can be single interface
// (instead of few different data structures within wallet2 implementation:
//    - pending_tx;
//    - transfer_details;
//    - payment_details;
//    - unconfirmed_transfer_details;
//    - confirmed_transfer_details)

EXPORT
PendingTransaction *WalletImpl::createTransactionMultDest(const std::vector<std::string> &dst_addr, std::optional<std::vector<uint64_t>> amount, uint32_t priority, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices)

{
    clearStatus();
    // Pause refresh thread while creating transaction
    pauseRefresh();
      
    cryptonote::address_parse_info info;

    PendingTransactionImpl * transaction = new PendingTransactionImpl(*this);

    do {
        std::vector<uint8_t> extra;
        std::string extra_nonce;
        std::vector<cryptonote::tx_destination_entry> dsts;
        if (!amount && dst_addr.size() > 1) {
            setStatusError(tr("Sending all requires one destination address"));
            break;
        }
        if (amount && (dst_addr.size() != (*amount).size())) {
            setStatusError(tr("Destinations and amounts are unequal"));
            break;
        }
        bool error = false;
        auto w = wallet();
        for (size_t i = 0; i < dst_addr.size() && !error; i++) {
            if(!cryptonote::get_account_address_from_str(info, m_wallet_ptr->nettype(), dst_addr[i])) {
                // TODO: copy-paste 'if treating as an address fails, try as url' from simplewallet.cpp:1982
                setStatusError(tr("Invalid destination address"));
                error = true;
                break;
            }
            if (info.has_payment_id) {
                if (!extra_nonce.empty()) {
                    setStatusError(tr("a single transaction cannot use more than one payment id"));
                    error = true;
                    break;
                }
                set_encrypted_payment_id_to_tx_extra_nonce(extra_nonce, info.payment_id);
            }

            if (amount) {
                cryptonote::tx_destination_entry de;
                de.original = dst_addr[i];
                de.addr = info.address;
                de.amount = (*amount)[i];
                de.is_subaddress = info.is_subaddress;
                de.is_integrated = info.has_payment_id;
                dsts.push_back(de);

            } else {
                if (subaddr_indices.empty()) {
                    for (uint32_t index = 0; index < w->get_num_subaddresses(subaddr_account); ++index)
                        subaddr_indices.insert(index);
                }
            }
        }
        if (error) {
            break;
        }
        if (!extra_nonce.empty() && !add_extra_nonce_to_tx_extra(extra, extra_nonce)) {
            setStatusError(tr("failed to set up payment id, though it was decoded correctly"));
            break;
        }
        try {
            auto hf_version = w->get_hard_fork_version();
            if (!hf_version)
            {
              setStatusError(tools::wallet2::ERR_MSG_NETWORK_VERSION_QUERY_FAILED);
              return transaction;
            }

            if (amount) {
                oxen_construct_tx_params tx_params = tools::wallet2::construct_params(*hf_version, txtype::standard, priority);
                transaction->m_pending_tx = w->create_transactions_2(
                        dsts, cryptonote::TX_OUTPUT_DECOYS, 0 /* unlock_time */,
                        priority,
                        extra, subaddr_account, subaddr_indices, tx_params);
            } else {
                transaction->m_pending_tx = w->create_transactions_all(
                        0, info.address, info.is_subaddress, 1, cryptonote::TX_OUTPUT_DECOYS, 0 /* unlock_time */,
                        priority,
                        extra, subaddr_account, subaddr_indices);
            }
            pendingTxPostProcess(transaction);

            if (multisig().isMultisig) {
                auto tx_set = w->make_multisig_tx_set(transaction->m_pending_tx);
                transaction->m_pending_tx = tx_set.m_ptx;
                transaction->m_signers = tx_set.m_signers;
            }
        } catch (const tools::error::daemon_busy&) {
            // TODO: make it translatable with "tr"?
            setStatusError(tr("daemon is busy. Please try again later."));
        } catch (const tools::error::no_connection_to_daemon&) {
            setStatusError(tr("no connection to daemon. Please make sure daemon is running."));
        } catch (const tools::error::wallet_rpc_error& e) {
            setStatusError(tr("RPC error: ") +  e.to_string());
        } catch (const tools::error::get_outs_error &e) {
            setStatusError((boost::format(tr("failed to get outputs to mix: %s")) % e.what()).str());
        } catch (const tools::error::not_enough_unlocked_money& e) {
            std::ostringstream writer;

            writer << boost::format(tr("not enough money to transfer, available only %s, sent amount %s")) %
                      print_money(e.available()) %
                      print_money(e.tx_amount());
            setStatusError(writer.str());
        } catch (const tools::error::not_enough_money& e) {
            std::ostringstream writer;

            writer << boost::format(tr("not enough money to transfer, overall balance only %s, sent amount %s")) %
                      print_money(e.available()) %
                      print_money(e.tx_amount());
            setStatusError(writer.str());
        } catch (const tools::error::tx_not_possible& e) {
            std::ostringstream writer;

            writer << boost::format(tr("not enough money to transfer, available only %s, transaction amount %s = %s + %s (fee)")) %
                      print_money(e.available()) %
                      print_money(e.tx_amount() + e.fee())  %
                      print_money(e.tx_amount()) %
                      print_money(e.fee());
            setStatusError(writer.str());
        } catch (const tools::error::not_enough_outs_to_mix& e) {
            std::ostringstream writer;
            writer << tr("not enough outputs for specified ring size") << " = " << (e.mixin_count() + 1) << ":";
            for (const std::pair<uint64_t, uint64_t> outs_for_amount : e.scanty_outs()) {
                writer << "\n" << tr("output amount") << " = " << print_money(outs_for_amount.first) << ", " << tr("found outputs to use") << " = " << outs_for_amount.second;
            }
            writer << "\n" << tr("Please sweep unmixable outputs.");
            setStatusError(writer.str());
        } catch (const tools::error::tx_not_constructed&) {
            setStatusError(tr("transaction was not constructed"));
        } catch (const tools::error::tx_rejected& e) {
            std::ostringstream writer;
            writer << (boost::format(tr("transaction %s was rejected by daemon with status: ")) % get_transaction_hash(e.tx())) <<  e.status();
            setStatusError(writer.str());
        } catch (const tools::error::tx_sum_overflow& e) {
            setStatusError(e.what());
        } catch (const tools::error::zero_destination&) {
            setStatusError(tr("one of destinations is zero"));
        } catch (const tools::error::tx_too_big& e) {
            setStatusError(tr("failed to find a suitable way to split transactions"));
        } catch (const tools::error::transfer_error& e) {
            setStatusError(std::string(tr("unknown transfer error: ")) + e.what());
        } catch (const tools::error::wallet_internal_error& e) {
            setStatusError(std::string(tr("internal error: ")) + e.what());
        } catch (const std::exception& e) {
            setStatusError(std::string(tr("unexpected error: ")) + e.what());
        } catch (...) {
            setStatusError(tr("unknown error"));
        }
    } while (false);

    transaction->m_status = status();
    // Resume refresh thread
    startRefresh();
    return transaction;
}

EXPORT
PendingTransaction *WalletImpl::createTransaction(const std::string &dst_addr, std::optional<uint64_t> amount,
                                                  uint32_t priority, uint32_t subaddr_account, std::set<uint32_t> subaddr_indices)

{
    return createTransactionMultDest(std::vector<std::string> {dst_addr},  amount ? (std::vector<uint64_t> {*amount}) : (std::optional<std::vector<uint64_t>>()), priority, subaddr_account, subaddr_indices);
}

EXPORT
PendingTransaction *WalletImpl::createSweepUnmixableTransaction()

{
    clearStatus();
    cryptonote::tx_destination_entry de;

    PendingTransactionImpl * transaction = new PendingTransactionImpl(*this);

    try {
        transaction->m_pending_tx = wallet()->create_unmixable_sweep_transactions();
        pendingTxPostProcess(transaction);

    } catch (const tools::error::daemon_busy&) {
        // TODO: make it translatable with "tr"?
        setStatusError(tr("daemon is busy. Please try again later."));
    } catch (const tools::error::no_connection_to_daemon&) {
        setStatusError(tr("no connection to daemon. Please make sure daemon is running."));
    } catch (const tools::error::wallet_rpc_error& e) {
        setStatusError(tr("RPC error: ") +  e.to_string());
    } catch (const tools::error::get_outs_error&) {
        setStatusError(tr("failed to get outputs to mix"));
    } catch (const tools::error::not_enough_unlocked_money& e) {
        setStatusError("");
        std::ostringstream writer;

        writer << boost::format(tr("not enough money to transfer, available only %s, sent amount %s")) %
                  print_money(e.available()) %
                  print_money(e.tx_amount());
        setStatusError(writer.str());
    } catch (const tools::error::not_enough_money& e) {
        setStatusError("");
        std::ostringstream writer;

        writer << boost::format(tr("not enough money to transfer, overall balance only %s, sent amount %s")) %
                  print_money(e.available()) %
                  print_money(e.tx_amount());
        setStatusError(writer.str());
    } catch (const tools::error::tx_not_possible& e) {
        setStatusError("");
        std::ostringstream writer;

        writer << boost::format(tr("not enough money to transfer, available only %s, transaction amount %s = %s + %s (fee)")) %
                  print_money(e.available()) %
                  print_money(e.tx_amount() + e.fee())  %
                  print_money(e.tx_amount()) %
                  print_money(e.fee());
        setStatusError(writer.str());
    } catch (const tools::error::not_enough_outs_to_mix& e) {
        std::ostringstream writer;
        writer << tr("not enough outputs for specified ring size") << " = " << (e.mixin_count() + 1) << ":";
        for (const std::pair<uint64_t, uint64_t> outs_for_amount : e.scanty_outs()) {
            writer << "\n" << tr("output amount") << " = " << print_money(outs_for_amount.first) << ", " << tr("found outputs to use") << " = " << outs_for_amount.second;
        }
        setStatusError(writer.str());
    } catch (const tools::error::tx_not_constructed&) {
        setStatusError(tr("transaction was not constructed"));
    } catch (const tools::error::tx_rejected& e) {
        std::ostringstream writer;
        writer << (boost::format(tr("transaction %s was rejected by daemon with status: ")) % get_transaction_hash(e.tx())) <<  e.status();
        setStatusError(writer.str());
    } catch (const tools::error::tx_sum_overflow& e) {
        setStatusError(e.what());
    } catch (const tools::error::zero_destination&) {
        setStatusError(tr("one of destinations is zero"));
    } catch (const tools::error::tx_too_big& e) {
        setStatusError(tr("failed to find a suitable way to split transactions"));
    } catch (const tools::error::transfer_error& e) {
        setStatusError(std::string(tr("unknown transfer error: ")) + e.what());
    } catch (const tools::error::wallet_internal_error& e) {
        setStatusError(std::string(tr("internal error: ")) + e.what());
    } catch (const std::exception& e) {
        setStatusError(std::string(tr("unexpected error: ")) + e.what());
    } catch (...) {
        setStatusError(tr("unknown error"));
    }

    transaction->m_status = status();
    return transaction;
}

EXPORT
void WalletImpl::disposeTransaction(PendingTransaction *t)
{
    delete t;
}

EXPORT
uint64_t WalletImpl::estimateTransactionFee(uint32_t priority, uint32_t recipients) const
{
    constexpr uint32_t typical_size = 2000;
    auto w = wallet();
    const auto base_fee = w->get_base_fees();
    uint64_t pct = w->get_fee_percent(priority == 1 ? 1 : 5, txtype::standard);
    return (base_fee.first * typical_size + base_fee.second * (recipients + 1)) * pct / 100;
}

EXPORT
TransactionHistory *WalletImpl::history()
{
    return m_history.get();
}

EXPORT
AddressBook *WalletImpl::addressBook()
{
    return m_addressBook.get();
}

EXPORT
Subaddress *WalletImpl::subaddress()
{
    return m_subaddress.get();
}

EXPORT
SubaddressAccount *WalletImpl::subaddressAccount()
{
    return m_subaddressAccount.get();
}

EXPORT
void WalletImpl::setListener(WalletListener *l)
{
    // TODO thread synchronization;
    m_wallet2Callback->setListener(l);
}

EXPORT
bool WalletImpl::setCacheAttribute(const std::string &key, const std::string &val)
{
    wallet()->set_attribute(key, val);
    return true;
}

EXPORT
std::string WalletImpl::getCacheAttribute(const std::string &key) const
{
    return wallet()->get_attribute(key).value_or(""s);
}

EXPORT
bool WalletImpl::setUserNote(const std::string &txid, const std::string &note)
{
    crypto::hash htxid;
    if (!tools::hex_to_type(txid, htxid))
      return false;

    wallet()->set_tx_note(htxid, note);
    return true;
}

EXPORT
std::string WalletImpl::getUserNote(const std::string &txid) const
{
    crypto::hash htxid;
    if (!tools::hex_to_type(txid, htxid))
      return "";

    return wallet()->get_tx_note(htxid);
}

EXPORT
std::string WalletImpl::getTxKey(const std::string &txid_str) const
{
    crypto::hash txid;
    if(!tools::hex_to_type(txid_str, txid))
    {
        setStatusError(tr("Failed to parse txid"));
        return "";
    }

    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    try
    {
        clearStatus();
        if (wallet()->get_tx_key(txid, tx_key, additional_tx_keys))
        {
            clearStatus();
            std::ostringstream oss;
            oss << tools::type_to_hex(tx_key);
            for (size_t i = 0; i < additional_tx_keys.size(); ++i)
                oss << tools::type_to_hex(additional_tx_keys[i]);
            return oss.str();
        }
        else
        {
            setStatusError(tr("no tx keys found for this txid"));
            return "";
        }
    }
    catch (const std::exception &e)
    {
        setStatusError(e.what());
        return "";
    }
}

EXPORT
bool WalletImpl::checkTxKey(const std::string &txid_str, std::string_view tx_key_str, const std::string &address_str, uint64_t &received, bool &in_pool, uint64_t &confirmations)
{
    crypto::hash txid;
    if (!tools::hex_to_type(txid_str, txid))
    {
        setStatusError(tr("Failed to parse txid"));
        return false;
    }

    crypto::secret_key tx_key;
    std::vector<crypto::secret_key> additional_tx_keys;
    bool first = true;
    while (first || !tx_key_str.empty())
    {
        auto& key = first ? tx_key : additional_tx_keys.emplace_back();
        if (first) first = false;

        if (!tools::hex_to_type(tx_key_str.substr(0, 64), key))
        {
            setStatusError(tr("Failed to parse tx key"));
            return false;
        }
        tx_key_str.remove_prefix(64);
    }

    cryptonote::address_parse_info info;
    if (!cryptonote::get_account_address_from_str(info, m_wallet_ptr->nettype(), address_str))
    {
        setStatusError(tr("Failed to parse address"));
        return false;
    }

    try
    {
        wallet()->check_tx_key(txid, tx_key, additional_tx_keys, info.address, received, in_pool, confirmations);
        clearStatus();
        return true;
    }
    catch (const std::exception &e)
    {
        setStatusError(e.what());
        return false;
    }
}

EXPORT
std::string WalletImpl::getTxProof(const std::string &txid_str, const std::string &address_str, const std::string &message) const
{
    crypto::hash txid;
    if (!tools::hex_to_type(txid_str, txid))
    {
        setStatusError(tr("Failed to parse txid"));
        return "";
    }

    cryptonote::address_parse_info info;
    if (!cryptonote::get_account_address_from_str(info, m_wallet_ptr->nettype(), address_str))
    {
        setStatusError(tr("Failed to parse address"));
        return "";
    }

    try
    {
        clearStatus();
        return wallet()->get_tx_proof(txid, info.address, info.is_subaddress, message);
    }
    catch (const std::exception &e)
    {
        setStatusError(e.what());
        return "";
    }
}

EXPORT
bool WalletImpl::checkTxProof(const std::string &txid_str, const std::string &address_str, const std::string &message, const std::string &signature, bool &good, uint64_t &received, bool &in_pool, uint64_t &confirmations)
{
    crypto::hash txid;
    if (!tools::hex_to_type(txid_str, txid))
    {
        setStatusError(tr("Failed to parse txid"));
        return false;
    }

    cryptonote::address_parse_info info;
    if (!cryptonote::get_account_address_from_str(info, m_wallet_ptr->nettype(), address_str))
    {
        setStatusError(tr("Failed to parse address"));
        return false;
    }

    try
    {
        good = wallet()->check_tx_proof(txid, info.address, info.is_subaddress, message, signature, received, in_pool, confirmations);
        clearStatus();
        return true;
    }
    catch (const std::exception &e)
    {
        setStatusError(e.what());
        return false;
    }
}

EXPORT
std::string WalletImpl::getSpendProof(const std::string &txid_str, const std::string &message) const {
    crypto::hash txid;
    if(!tools::hex_to_type(txid_str, txid))
    {
        setStatusError(tr("Failed to parse txid"));
        return "";
    }

    try
    {
        clearStatus();
        return wallet()->get_spend_proof(txid, message);
    }
    catch (const std::exception &e)
    {
        setStatusError(e.what());
        return "";
    }
}

EXPORT
bool WalletImpl::checkSpendProof(const std::string &txid_str, const std::string &message, const std::string &signature, bool &good) const {
    good = false;
    crypto::hash txid;
    if(!tools::hex_to_type(txid_str, txid))
    {
        setStatusError(tr("Failed to parse txid"));
        return false;
    }

    try
    {
        clearStatus();
        good = wallet()->check_spend_proof(txid, message, signature);
        return true;
    }
    catch (const std::exception &e)
    {
        setStatusError(e.what());
        return false;
    }
}

EXPORT
std::string WalletImpl::getReserveProof(bool all, uint32_t account_index, uint64_t amount, const std::string &message) const {
    try
    {
        clearStatus();
        std::optional<std::pair<uint32_t, uint64_t>> account_minreserve;
        if (!all)
        {
            account_minreserve = std::make_pair(account_index, amount);
        }
        return wallet()->get_reserve_proof(account_minreserve, message);
    }
    catch (const std::exception &e)
    {
        setStatusError(e.what());
        return "";
    }
}

EXPORT
bool WalletImpl::checkReserveProof(const std::string &address, const std::string &message, const std::string &signature, bool &good, uint64_t &total, uint64_t &spent) const {
    cryptonote::address_parse_info info;
    if (!cryptonote::get_account_address_from_str(info, m_wallet_ptr->nettype(), address))
    {
        setStatusError(tr("Failed to parse address"));
        return false;
    }
    if (info.is_subaddress)
    {
        setStatusError(tr("Address must not be a subaddress"));
        return false;
    }

    good = false;
    try
    {
        clearStatus();
        good = wallet()->check_reserve_proof(info.address, message, signature, total, spent);
        return true;
    }
    catch (const std::exception &e)
    {
        setStatusError(e.what());
        return false;
    }
}

EXPORT
std::string WalletImpl::signMessage(const std::string &message)
{
  return wallet()->sign(message);
}

EXPORT
bool WalletImpl::verifySignedMessage(const std::string &message, const std::string &address, const std::string &signature) const
{
  cryptonote::address_parse_info info;

  if (!cryptonote::get_account_address_from_str(info, m_wallet_ptr->nettype(), address))
    return false;

  return wallet()->verify(message, info.address, signature);
}

EXPORT
std::string WalletImpl::signMultisigParticipant(const std::string &message) const
{
    clearStatus();

    bool ready = false;
    auto w = wallet();
    if (!w->multisig(&ready) || !ready) {
        setStatusError(tr("The wallet must be in multisig ready state"));
        return {};
    }

    try {
        return w->sign_multisig_participant(message);
    } catch (const std::exception& e) {
        setStatusError(e.what());
    }

    return {};
}

EXPORT
bool WalletImpl::verifyMessageWithPublicKey(const std::string &message, const std::string &publicKey, const std::string &signature) const
{
    clearStatus();

    crypto::public_key pkey;
    if (!tools::hex_to_type(publicKey, pkey))
        return setStatusError(tr("Given string is not a key"));

    try {
        return wallet()->verify_with_public_key(message, pkey, signature);
    } catch (const std::exception& e) {
        return setStatusError(e.what());
    }

    return false;
}

EXPORT
bool WalletImpl::connectToDaemon()
{
    auto w = wallet();
    bool result = w->check_connection(NULL, NULL, DEFAULT_CONNECTION_TIMEOUT_MILLIS);
    if (!result) {
        setStatusError("Error connecting to daemon at " + w->get_daemon_address());
    } else {
        clearStatus();
        // start refreshing here
    }
    return result;
}

EXPORT
Wallet::ConnectionStatus WalletImpl::connected() const
{
    rpc::version_t version;
    auto w = wallet();
    m_is_connected = w->check_connection(&version, NULL, DEFAULT_CONNECTION_TIMEOUT_MILLIS);
    if (!m_is_connected)
        return Wallet::ConnectionStatus_Disconnected;
    if (
#ifdef ENABLE_LIGHT_WALLET
    // Version check is not implemented in light wallets nodes/wallets
            !w->light_wallet() &&
#endif
            version.first != rpc::VERSION.first)
        return Wallet::ConnectionStatus_WrongVersion;
    return Wallet::ConnectionStatus_Connected;
}

EXPORT
void WalletImpl::setTrustedDaemon(bool arg)
{
    wallet()->set_trusted_daemon(arg);
}

EXPORT
bool WalletImpl::trustedDaemon() const
{
    return wallet()->is_trusted_daemon();
}

EXPORT
bool WalletImpl::watchOnly() const
{
    return wallet()->watch_only();
}

EXPORT
void WalletImpl::clearStatus() const
{
    std::lock_guard l{m_statusMutex};
    m_status = {Status_Ok, ""};
}

EXPORT
bool WalletImpl::setStatusError(std::string message) const
{
    return setStatus(Status_Error, std::move(message));
}

EXPORT
bool WalletImpl::setStatusCritical(std::string message) const
{
    return setStatus(Status_Critical, std::move(message));
}

EXPORT
bool WalletImpl::setStatus(int status, std::string message) const
{
    std::lock_guard l{m_statusMutex};
    m_status.first = status;
    m_status.second = std::move(message);
    return status == Status_Ok;
}

EXPORT
void WalletImpl::refreshThreadFunc()
{
    LOG_PRINT_L3(__FUNCTION__ << ": starting refresh thread");

    while (true) {
        std::unique_lock lock{m_refreshMutex};
        if (m_refreshThreadDone) {
            break;
        }
        LOG_PRINT_L3(__FUNCTION__ << ": waiting for refresh...");
        // if auto refresh enabled, we wait for the "m_refreshIntervalSeconds" interval.
        // if not - we wait forever
        if (std::chrono::milliseconds max_delay{m_refreshIntervalMillis.load()};
                max_delay > 0ms) {
            m_refreshCV.wait_for(lock, max_delay);
        } else {
            m_refreshCV.wait(lock);
        }

        LOG_PRINT_L3(__FUNCTION__ << ": refresh lock acquired...");
        LOG_PRINT_L3(__FUNCTION__ << ": m_refreshEnabled: " << m_refreshEnabled);
        auto st = status();
        LOG_PRINT_L3(__FUNCTION__ << ": m_status: " << st.first << ": " << st.second);
        LOG_PRINT_L3(__FUNCTION__ << ": m_refreshShouldRescan: " << m_refreshShouldRescan);
        if (m_refreshEnabled) {
            LOG_PRINT_L3(__FUNCTION__ << ": refreshing...");
            doRefresh();
        }
    }
    LOG_PRINT_L3(__FUNCTION__ << ": refresh thread stopped");
}

EXPORT
void WalletImpl::doRefresh()
{
    bool rescan = m_refreshShouldRescan.exchange(false);
    // synchronizing async and sync refresh calls
    std::lock_guard guard{m_refreshMutex2};
    do {
        try {
            LOG_PRINT_L3(__FUNCTION__ << ": doRefresh, rescan = "<<rescan);
            auto w = wallet();

            // Syncing daemon and refreshing wallet simultaneously is very resource intensive.
            // Disable refresh if wallet is disconnected or daemon isn't synced.
            if (
#ifdef ENABLE_LIGHT_WALLET
                    w->light_wallet() ||
#endif
                    daemonSynced()) {
                if(rescan)
                    w->rescan_blockchain(false);
                w->refresh(trustedDaemon());
                if (!m_synchronized) {
                    m_synchronized = true;
                }
                // assuming if we have empty history, it wasn't initialized yet
                // for further history changes client need to update history in
                // "on_money_received" and "on_money_sent" callbacks
                if (m_history->count() == 0) {
                    m_history->refresh();
                }
                w->find_and_save_rings(false);
            } else {
               LOG_PRINT_L3(__FUNCTION__ << ": skipping refresh - daemon is not synced");
            }
        } catch (const std::exception &e) {
            setStatusError(e.what());
            break;
        }
    } while (!rescan && (rescan=m_refreshShouldRescan.exchange(false))); // repeat if not rescanned and rescan was requested

    if (m_wallet2Callback->getListener()) {
        m_wallet2Callback->getListener()->refreshed();
    }
}


EXPORT
void WalletImpl::startRefresh()
{
    if (!m_refreshEnabled) {
        LOG_PRINT_L2(__FUNCTION__ << ": refresh started/resumed...");
        m_refreshEnabled = true;
        m_refreshCV.notify_one();
    }
}



EXPORT
void WalletImpl::stopRefresh()
{
    if (!m_refreshThreadDone) {
        m_refreshEnabled = false;
        m_refreshThreadDone = true;
        m_refreshCV.notify_one();
        m_refreshThread.join();
    }
}

EXPORT
void WalletImpl::pauseRefresh()
{
    LOG_PRINT_L2(__FUNCTION__ << ": refresh paused...");
    // TODO synchronize access
    if (!m_refreshThreadDone) {
        m_refreshEnabled = false;
    }
}


EXPORT
bool WalletImpl::isNewWallet() const
{
    // in case wallet created without daemon connection, closed and opened again,
    // it's the same case as if it created from scratch, i.e. we need "fast sync"
    // with the daemon (pull hashes instead of pull blocks).
    // If wallet cache is rebuilt, creation height stored in .keys is used.
    // Watch only wallet is a copy of an existing wallet. 
    return !(blockChainHeight() > 1 || m_recoveringFromSeed || m_recoveringFromDevice || m_rebuildWalletCache) && !watchOnly();
}

EXPORT
void WalletImpl::pendingTxPostProcess(PendingTransactionImpl * pending)
{
  // If the device being used is HW device with cold signing protocol, cold sign then.
  if (!wallet()->get_account().get_device().has_tx_cold_sign()){
    return;
  }

  tools::wallet2::signed_tx_set exported_txs;
  std::vector<cryptonote::address_parse_info> dsts_info;

  wallet()->cold_sign_tx(pending->m_pending_tx, exported_txs, dsts_info, pending->m_tx_device_aux);
  pending->m_key_images = exported_txs.key_images;
  pending->m_pending_tx = exported_txs.ptx;
}

EXPORT
bool WalletImpl::doInit(const std::string &daemon_address, uint64_t upper_transaction_size_limit, bool ssl)
{
    auto w = wallet();
    if (!w->init(daemon_address, m_daemon_login, /*proxy=*/ "", upper_transaction_size_limit))
       return false;

    // in case new wallet, this will force fast-refresh (pulling hashes instead of blocks)
    // If daemon isn't synced a calculated block height will be used instead
    //TODO: Handle light wallet scenario where block height = 0.
    if (isNewWallet() && daemonSynced()) {
        LOG_PRINT_L2(__FUNCTION__ << ":New Wallet - fast refresh until " << daemonBlockChainHeight());
        w->set_refresh_from_block_height(daemonBlockChainHeight());
    }

    if (m_rebuildWalletCache)
      LOG_PRINT_L2(__FUNCTION__ << ": Rebuilding wallet cache, fast refresh until block " << w->get_refresh_from_block_height());

    if (Utils::isAddressLocal(daemon_address)) {
        this->setTrustedDaemon(true);
        m_refreshIntervalMillis = DEFAULT_REFRESH_INTERVAL_MILLIS;
    } else {
        this->setTrustedDaemon(false);
        m_refreshIntervalMillis = DEFAULT_REMOTE_NODE_REFRESH_INTERVAL_MILLIS;
    }
    return true;
}

EXPORT
bool WalletImpl::parse_uri(const std::string &uri, std::string &address, std::string &payment_id, uint64_t &amount, std::string &tx_description, std::string &recipient_name, std::vector<std::string> &unknown_parameters, std::string &error)
{
    return m_wallet_ptr->parse_uri(uri, address, payment_id, amount, tx_description, recipient_name, unknown_parameters, error);
}

EXPORT
std::string WalletImpl::getDefaultDataDir() const
{
 return tools::get_default_data_dir();
}

EXPORT
bool WalletImpl::rescanSpent()
{
  clearStatus();
  if (!trustedDaemon()) {
    setStatusError(tr("Rescan spent can only be used with a trusted daemon"));
    return false;
  }
  try {
      wallet()->rescan_spent();
  } catch (const std::exception &e) {
      LOG_ERROR(__FUNCTION__ << " error: " << e.what());
      setStatusError(e.what());
      return false;
  }
  return true;
}


EXPORT
void WalletImpl::hardForkInfo(uint8_t &version, uint64_t &earliest_height) const
{
    wallet()->get_hard_fork_info(version, earliest_height);
}

EXPORT
std::optional<uint8_t> WalletImpl::hardForkVersion() const
{
    auto v = m_wallet_ptr->get_hard_fork_version();
    if (!v)
      return std::nullopt;
    return static_cast<uint8_t>(*v);
}

EXPORT
bool WalletImpl::useForkRules(uint8_t version, int64_t early_blocks) const 
{
    return wallet()->use_fork_rules(static_cast<hf>(version),early_blocks);
}

EXPORT
bool WalletImpl::blackballOutputs(const std::vector<std::string> &outputs, bool add)
{
    std::vector<std::pair<uint64_t, uint64_t>> raw_outputs;
    raw_outputs.reserve(outputs.size());
    uint64_t amount = std::numeric_limits<uint64_t>::max(), offset, num_offsets;
    for (const std::string &str: outputs)
    {
        if (sscanf(str.c_str(), "@%" PRIu64, &amount) == 1)
          continue;
        if (amount == std::numeric_limits<uint64_t>::max())
        {
          setStatusError("First line is not an amount");
          return true;
        }
        if (sscanf(str.c_str(), "%" PRIu64 "*%" PRIu64, &offset, &num_offsets) == 2 && num_offsets <= std::numeric_limits<uint64_t>::max() - offset)
        {
          while (num_offsets--)
            raw_outputs.push_back(std::make_pair(amount, offset++));
        }
        else if (sscanf(str.c_str(), "%" PRIu64, &offset) == 1)
        {
          raw_outputs.push_back(std::make_pair(amount, offset));
        }
        else
        {
          setStatusError(tr("Invalid output: ") + str);
          return false;
        }
    }
    bool ret = wallet()->set_blackballed_outputs(raw_outputs, add);
    if (!ret)
    {
        setStatusError(tr("Failed to mark outputs as spent"));
        return false;
    }
    return true;
}

EXPORT
bool WalletImpl::blackballOutput(const std::string &amount, const std::string &offset)
{
    uint64_t raw_amount, raw_offset;
    if (!epee::string_tools::get_xtype_from_string(raw_amount, amount))
    {
        setStatusError(tr("Failed to parse output amount"));
        return false;
    }
    if (!epee::string_tools::get_xtype_from_string(raw_offset, offset))
    {
        setStatusError(tr("Failed to parse output offset"));
        return false;
    }
    bool ret = wallet()->blackball_output(std::make_pair(raw_amount, raw_offset));
    if (!ret)
    {
        setStatusError(tr("Failed to mark output as spent"));
        return false;
    }
    return true;
}

EXPORT
bool WalletImpl::unblackballOutput(const std::string &amount, const std::string &offset)
{
    uint64_t raw_amount, raw_offset;
    if (!epee::string_tools::get_xtype_from_string(raw_amount, amount))
    {
        setStatusError(tr("Failed to parse output amount"));
        return false;
    }
    if (!epee::string_tools::get_xtype_from_string(raw_offset, offset))
    {
        setStatusError(tr("Failed to parse output offset"));
        return false;
    }
    bool ret = wallet()->unblackball_output(std::make_pair(raw_amount, raw_offset));
    if (!ret)
    {
        setStatusError(tr("Failed to mark output as unspent"));
        return false;
    }
    return true;
}

EXPORT
bool WalletImpl::getRing(const std::string &key_image, std::vector<uint64_t> &ring) const
{
    crypto::key_image raw_key_image;
    if (!tools::hex_to_type(key_image, raw_key_image))
    {
        setStatusError(tr("Failed to parse key image"));
        return false;
    }
    bool ret = wallet()->get_ring(raw_key_image, ring);
    if (!ret)
    {
        setStatusError(tr("Failed to get ring"));
        return false;
    }
    return true;
}

EXPORT
bool WalletImpl::getRings(const std::string &txid, std::vector<std::pair<std::string, std::vector<uint64_t>>> &rings) const
{
    crypto::hash raw_txid;
    if (!tools::hex_to_type(txid, raw_txid))
    {
        setStatusError(tr("Failed to parse txid"));
        return false;
    }
    std::vector<std::pair<crypto::key_image, std::vector<uint64_t>>> raw_rings;
    bool ret = wallet()->get_rings(raw_txid, raw_rings);
    if (!ret)
    {
        setStatusError(tr("Failed to get rings"));
        return false;
    }
    for (const auto &r: raw_rings)
    {
      rings.push_back(std::make_pair(tools::type_to_hex(r.first), r.second));
    }
    return true;
}

EXPORT
bool WalletImpl::setRing(const std::string &key_image, const std::vector<uint64_t> &ring, bool relative)
{
    crypto::key_image raw_key_image;
    if (!tools::hex_to_type(key_image, raw_key_image))
    {
        setStatusError(tr("Failed to parse key image"));
        return false;
    }
    bool ret = wallet()->set_ring(raw_key_image, ring, relative);
    if (!ret)
    {
        setStatusError(tr("Failed to set ring"));
        return false;
    }
    return true;
}

EXPORT
void WalletImpl::segregatePreForkOutputs(bool segregate)
{
    wallet()->segregate_pre_fork_outputs(segregate);
}

EXPORT
void WalletImpl::segregationHeight(uint64_t height)
{
    wallet()->segregation_height(height);
}

EXPORT
void WalletImpl::keyReuseMitigation2(bool mitigation)
{
    wallet()->key_reuse_mitigation2(mitigation);
}

EXPORT
bool WalletImpl::lockKeysFile()
{
    return wallet()->lock_keys_file();
}

EXPORT
bool WalletImpl::unlockKeysFile()
{
    return wallet()->unlock_keys_file();
}

EXPORT
bool WalletImpl::isKeysFileLocked()
{
    return wallet()->is_keys_file_locked();
}

EXPORT
PendingTransaction* WalletImpl::stakePending(const std::string& sn_key_str, const uint64_t& amount)
{
  /// Note(maxim): need to be careful to call `WalletImpl::disposeTransaction` when it is no longer needed
  PendingTransactionImpl * transaction = new PendingTransactionImpl(*this);
  std::string error_msg;

  crypto::public_key sn_key;
  if (!tools::hex_to_type(sn_key_str, sn_key))
  {
    error_msg = "Failed to parse service node pubkey";
    LOG_ERROR(error_msg);
    transaction->setError(error_msg);
    return transaction;
  }

  tools::wallet2::stake_result stake_result = wallet()->create_stake_tx(sn_key, amount);
  if (stake_result.status != tools::wallet2::stake_result_status::success)
  {
    error_msg = "Failed to create a stake transaction: " + stake_result.msg;
    LOG_ERROR(error_msg);
    transaction->setError(error_msg);
    return transaction;
  }

  transaction->m_pending_tx = {stake_result.ptx};
  return transaction;
}

EXPORT
StakeUnlockResult* WalletImpl::canRequestStakeUnlock(const std::string &sn_key)
{
    crypto::public_key snode_key;
    if (!tools::hex_to_type(sn_key, snode_key))
    {
      tools::wallet2::request_stake_unlock_result res{};
      res.success = false;
      res.msg = "Failed to Parse Service Node Key";
      return new StakeUnlockResultImpl(*this, res);
    }

    return new StakeUnlockResultImpl(*this, wallet()->can_request_stake_unlock(snode_key));
}

EXPORT
StakeUnlockResult* WalletImpl::requestStakeUnlock(const std::string &sn_key)
{
    tools::wallet2::request_stake_unlock_result res = {};

    crypto::public_key snode_key;
    if (!tools::hex_to_type(sn_key, snode_key))
    {
      res.success = false;
      res.msg = "Failed to Parse Service Node Key";
      return new StakeUnlockResultImpl(*this, res);
    }
    auto w = wallet();
    tools::wallet2::request_stake_unlock_result unlock_result = w->can_request_stake_unlock(snode_key);
    if (unlock_result.success)
    {
      try
      {
        w->commit_tx(unlock_result.ptx);
      }
      catch(const std::exception &e)
      {
        res.success = false;
        res.msg = "Failed to commit tx.";
        return new StakeUnlockResultImpl(*this, res);
      }
    }
    else
    {
      res.success = false;
      res.msg = tr("Cannot request stake unlock: " + unlock_result.msg);
      return new StakeUnlockResultImpl(*this, res);
    }

    return new StakeUnlockResultImpl(*this, unlock_result);
}

EXPORT
uint64_t WalletImpl::coldKeyImageSync(uint64_t &spent, uint64_t &unspent)
{
    return wallet()->cold_key_image_sync(spent, unspent);
}

EXPORT
void WalletImpl::deviceShowAddress(uint32_t accountIndex, uint32_t addressIndex, const std::string &paymentId)
{
    std::optional<crypto::hash8> payment_id_param = std::nullopt;
    if (!paymentId.empty())
        if (!tools::hex_to_type(paymentId, payment_id_param.emplace()))
            throw std::runtime_error("Invalid payment ID");

    wallet()->device_show_address(accountIndex, addressIndex, payment_id_param);
}
} // namespace
