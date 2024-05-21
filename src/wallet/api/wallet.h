// Copyright (c) 2014-2019, The Monero Project
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

#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

#include "wallet/api/wallet2_api.h"
#include "wallet/wallet2.h"

namespace Wallet {

namespace log = oxen::log;
inline auto logcat = log::Cat("wallet.api");

class TransactionHistoryImpl;
class PendingTransactionImpl;
class UnsignedTransactionImpl;
class StakeUnlockResultImpl;
class AddressBookImpl;
class SubaddressImpl;
class SubaddressAccountImpl;
struct Wallet2CallbackImpl;

// Wrapper that holds a lock to prevent background refreshes, which kill things; provides `->`
// indirection into the tools::wallet2 instance.
struct LockedWallet {
    std::unique_lock<std::recursive_timed_mutex> refresh_lock;
    tools::wallet2* const wallet;
    // Constructs a wallet wrapper from a moved existing unique_lock which may be initially locked
    // or unlocked (if unlocked, it will be immediately locked).
    LockedWallet(
            const std::unique_ptr<tools::wallet2>& w,
            std::unique_lock<std::recursive_timed_mutex>&& lock) :
            refresh_lock{std::move(lock)}, wallet{w.get()} {
        if (!refresh_lock)
            refresh_lock.lock();
    }
    // Constructs a wallet wrapper from a wallet and the refresh mutex; locks the mutex immediately.
    LockedWallet(
            const std::unique_ptr<tools::wallet2>& w, std::recursive_timed_mutex& refresh_mutex) :
            refresh_lock{refresh_mutex}, wallet{w.get()} {}

    // Returns the wallet2 pointer, to allow `w->whatever()` to call into wallet functions through
    // the locking wrapper.
    tools::wallet2* operator->() { return wallet; }
};

class WalletImpl : public Wallet {
  public:
    WalletImpl(NetworkType nettype = MAINNET, uint64_t kdf_rounds = 1);
    ~WalletImpl();
    bool create(
            const std::string_view path, const std::string& password, const std::string& language);
    bool createWatchOnly(
            std::string_view path,
            const std::string& password,
            const std::string& language) const override;
    bool open(std::string_view path, const std::string& password);
    bool recover(
            std::string_view path,
            const std::string& password,
            const std::string& seed,
            const std::string& seed_offset = {});
    bool recoverFromKeysWithPassword(
            std::string_view path,
            const std::string& password,
            const std::string& language,
            const std::string& address_string,
            const std::string& viewkey_string,
            const std::string& spendkey_string = "");
    bool recoverFromDevice(
            std::string_view path, const std::string& password, const std::string& device_name);
    Device getDeviceType() const override;
    bool close(bool store = true);
    std::string seed() const override;
    std::string getSeedLanguage() const override;
    void setSeedLanguage(const std::string& arg) override;
    bool good() const override;
    std::pair<int, std::string> status() const override;
    bool setPassword(const std::string& password) override;
    bool setDevicePin(const std::string& password) override;
    bool setDevicePassphrase(const std::string& password) override;
    std::string address(uint32_t accountIndex = 0, uint32_t addressIndex = 0) const override;
    std::string integratedAddress(const std::string& payment_id) const override;
    std::string secretViewKey() const override;
    std::string publicViewKey() const override;
    std::string secretSpendKey() const override;
    std::string publicSpendKey() const override;
    std::string publicMultisigSignerKey() const override;
    std::string path() const override;
    bool store(std::string_view path) override;
    std::string filename() const override;
    std::string keysFilename() const override;
    bool init(
            const std::string& daemon_address,
            uint64_t upper_transaction_size_limit = 0,
            const std::string& daemon_username = "",
            const std::string& daemon_password = "",
            bool use_ssl = false ENABLE_IF_LIGHT_WALLET(, bool lightWallet = false)) override;
    bool connectToDaemon() override;
    ConnectionStatus connected() const override;
    void setTrustedDaemon(bool arg) override;
    bool trustedDaemon() const override;
    uint64_t balance(uint32_t accountIndex = 0) const override;
    uint64_t unlockedBalance(uint32_t accountIndex = 0) const override;
    uint64_t accruedBalance(std::optional<std::string> address = std::nullopt) const override;
    uint64_t nextAccruedPaymentHeight(
            std::optional<std::string> address = std::nullopt) const override;
    std::vector<Wallet::stake_info>* listCurrentStakes() const override;
    uint64_t blockChainHeight() const override;
    uint64_t approximateBlockChainHeight() const override;
    uint64_t estimateBlockChainHeight() const override;
    // Returns the current daemon height, either from the wallet's current cached value or (if the
    // cache is too old) via a request to the daemon.
    uint64_t daemonBlockChainHeight() const override;
    uint64_t daemonBlockChainTargetHeight() const override;
    bool synchronized() const override;
    bool refresh() override;
    void refreshAsync() override;
    bool isRefreshing(std::chrono::milliseconds max_wait = std::chrono::milliseconds{50}) override;
    bool rescanBlockchain() override;
    void rescanBlockchainAsync() override;
    void setAutoRefreshInterval(int millis) override;
    int autoRefreshInterval() const override;
    void setRefreshFromBlockHeight(uint64_t refresh_from_block_height) override;
    uint64_t getRefreshFromBlockHeight() const override {
        return m_wallet_ptr->get_refresh_from_block_height();
    };
    void setRecoveringFromSeed(bool recoveringFromSeed) override;
    void setRecoveringFromDevice(bool recoveringFromDevice) override;
    void setSubaddressLookahead(uint32_t major, uint32_t minor) override;
    bool watchOnly() const override;
    bool rescanSpent() override;
    NetworkType nettype() const override {
        return static_cast<NetworkType>(m_wallet_ptr->nettype());
    }
    void hardForkInfo(uint8_t& version, uint64_t& earliest_height) const override;
    std::optional<uint8_t> hardForkVersion() const override;
    bool useForkRules(uint8_t version, int64_t early_blocks) const override;

    void addSubaddressAccount(const std::string& label) override;
    size_t numSubaddressAccounts() const override;
    size_t numSubaddresses(uint32_t accountIndex) const override;
    void addSubaddress(uint32_t accountIndex, const std::string& label) override;
    std::string getSubaddressLabel(uint32_t accountIndex, uint32_t addressIndex) const override;
    void setSubaddressLabel(
            uint32_t accountIndex, uint32_t addressIndex, const std::string& label) override;

    PendingTransaction* stakePending(
            const std::string& service_node_key, const uint64_t& amount) override;

    StakeUnlockResult* canRequestStakeUnlock(const std::string& sn_key) override;

    StakeUnlockResult* requestStakeUnlock(const std::string& sn_key) override;

    static MultisigState multisig(LockedWallet& w);
    MultisigState multisig() const override;
    std::string getMultisigInfo() const override;
    std::string makeMultisig(const std::vector<std::string>& info, uint32_t threshold) override;
    std::string exchangeMultisigKeys(const std::vector<std::string>& info) override;
    bool finalizeMultisig(const std::vector<std::string>& extraMultisigInfo) override;
    bool exportMultisigImages(std::string& images) override;
    size_t importMultisigImages(const std::vector<std::string>& images) override;
    bool hasMultisigPartialKeyImages() const override;
    PendingTransaction* restoreMultisigTransaction(const std::string& signData) override;

    PendingTransaction* createTransactionMultDest(
            const std::vector<std::string>& dst_addr,
            std::optional<std::vector<uint64_t>> amount,
            uint32_t priority = 0,
            uint32_t subaddr_account = 0,
            std::set<uint32_t> subaddr_indices = {}) override;
    PendingTransaction* createTransaction(
            const std::string& dst_addr,
            std::optional<uint64_t> amount,
            uint32_t priority = 0,
            uint32_t subaddr_account = 0,
            std::set<uint32_t> subaddr_indices = {}) override;
    PendingTransaction* createSweepUnmixableTransaction() override;
    bool submitTransaction(std::string_view filename) override;
    UnsignedTransaction* loadUnsignedTx(std::string_view unsigned_filename) override;
    bool exportKeyImages(std::string_view filename) override;
    bool importKeyImages(std::string_view filename) override;

    void disposeTransaction(PendingTransaction* t) override;
    uint64_t estimateTransactionFee(uint32_t priority, uint32_t recipients = 1) const override;
    TransactionHistory* history() override;
    AddressBook* addressBook() override;
    Subaddress* subaddress() override;
    SubaddressAccount* subaddressAccount() override;
    void setListener(WalletListener* l) override;
    bool setCacheAttribute(const std::string& key, const std::string& val) override;
    std::string getCacheAttribute(const std::string& key) const override;
    bool setUserNote(const std::string& txid, const std::string& note) override;
    std::string getUserNote(const std::string& txid) const override;
    std::string getTxKey(const std::string& txid) const override;
    bool checkTxKey(
            const std::string& txid,
            std::string_view tx_key,
            const std::string& address,
            uint64_t& received,
            bool& in_pool,
            uint64_t& confirmations) override;
    std::string getTxProof(
            const std::string& txid,
            const std::string& address,
            const std::string& message) const override;
    bool checkTxProof(
            const std::string& txid,
            const std::string& address,
            const std::string& message,
            const std::string& signature,
            bool& good,
            uint64_t& received,
            bool& in_pool,
            uint64_t& confirmations) override;
    std::string getSpendProof(const std::string& txid, const std::string& message) const override;
    bool checkSpendProof(
            const std::string& txid,
            const std::string& message,
            const std::string& signature,
            bool& good) const override;
    std::string getReserveProof(
            bool all,
            uint32_t account_index,
            uint64_t amount,
            const std::string& message) const override;
    bool checkReserveProof(
            const std::string& address,
            const std::string& message,
            const std::string& signature,
            bool& good,
            uint64_t& total,
            uint64_t& spent) const override;
    std::string signMessage(const std::string& message) override;
    bool verifySignedMessage(
            const std::string& message,
            const std::string& address,
            const std::string& signature) const override;
    std::string signMultisigParticipant(const std::string& message) const override;
    bool verifyMessageWithPublicKey(
            const std::string& message,
            const std::string& publicKey,
            const std::string& signature) const override;
    void startRefresh() override;
    void pauseRefresh() override;
    bool parse_uri(
            const std::string& uri,
            std::string& address,
            std::string& payment_id,
            uint64_t& amount,
            std::string& tx_description,
            std::string& recipient_name,
            std::vector<std::string>& unknown_parameters,
            std::string& error) override;
    std::string getDefaultDataDir() const override;
#ifdef ENABLE_LIGHT_WALLET
    bool lightWalletLogin(bool& isNewWallet) const override;
    bool lightWalletImportWalletRequest(
            std::string& payment_id,
            uint64_t& fee,
            bool& new_request,
            bool& request_fulfilled,
            std::string& payment_address,
            std::string& status) override;
#endif
    bool blackballOutputs(const std::vector<std::string>& outputs, bool add) override;
    bool blackballOutput(const std::string& amount, const std::string& offset) override;
    bool unblackballOutput(const std::string& amount, const std::string& offset) override;
    bool getRing(const std::string& key_image, std::vector<uint64_t>& ring) const override;
    bool getRings(
            const std::string& txid,
            std::vector<std::pair<std::string, std::vector<uint64_t>>>& rings) const override;
    bool setRing(const std::string& key_image, const std::vector<uint64_t>& ring, bool relative)
            override;
    void segregatePreForkOutputs(bool segregate) override;
    void segregationHeight(uint64_t height) override;
    void keyReuseMitigation2(bool mitigation) override;
    bool lockKeysFile() override;
    bool unlockKeysFile() override;
    bool isKeysFileLocked() override;
    uint64_t coldKeyImageSync(uint64_t& spent, uint64_t& unspent) override;
    void deviceShowAddress(
            uint32_t accountIndex, uint32_t addressIndex, const std::string& paymentId) override;

  private:
    void clearStatus() const;
    bool setStatusError(std::string message) const;
    bool setStatusCritical(std::string message) const;
    bool setStatus(int status, std::string message) const;
    void refreshThreadFunc();
    void doRefresh();
    bool daemonSynced() const;
    void stopRefresh();
    bool isNewWallet() const;
    void pendingTxPostProcess(PendingTransactionImpl* pending);
    bool doInit(
            const std::string& daemon_address,
            uint64_t upper_transaction_size_limit = 0,
            bool ssl = false);

    friend class PendingTransactionImpl;
    friend class UnsignedTransactionImpl;
    friend class TransactionHistoryImpl;
    friend struct Wallet2CallbackImpl;
    friend class AddressBookImpl;
    friend class SubaddressImpl;
    friend class SubaddressAccountImpl;

    std::unique_ptr<tools::wallet2> m_wallet_ptr;
    mutable std::mutex m_statusMutex;
    LockedWallet wallet() const { return {m_wallet_ptr, m_refreshMutex2}; }
    mutable std::pair<int, std::string> m_status;
    std::string m_password;
    std::unique_ptr<TransactionHistoryImpl> m_history;
    std::unique_ptr<Wallet2CallbackImpl> m_wallet2Callback;
    std::unique_ptr<AddressBookImpl> m_addressBook;
    std::unique_ptr<SubaddressImpl> m_subaddress;
    std::unique_ptr<SubaddressAccountImpl> m_subaddressAccount;

    // multi-threaded refresh stuff
    std::atomic<bool> m_refreshEnabled;
    std::atomic<bool> m_refreshThreadDone;
    std::atomic<int> m_refreshIntervalMillis;
    std::atomic<bool> m_refreshShouldRescan;
    // synchronizing  refresh loop;
    std::mutex m_refreshMutex;

    // synchronizing  sync and async refresh
    mutable std::recursive_timed_mutex m_refreshMutex2;
    std::condition_variable m_refreshCV;
    std::thread m_refreshThread;
    std::thread m_longPollThread;

    // flag indicating wallet is recovering from seed
    // so it shouldn't be considered as new and pull blocks (slow-refresh)
    // instead of pulling hashes (fast-refresh)
    std::atomic<bool> m_recoveringFromSeed;
    std::atomic<bool> m_recoveringFromDevice;
    std::atomic<bool> m_synchronized;
    std::atomic<bool> m_rebuildWalletCache;
    // cache connection status to avoid unnecessary RPC calls
    mutable std::atomic<bool> m_is_connected;
    std::optional<tools::login> m_daemon_login;
};

}  // namespace Wallet
