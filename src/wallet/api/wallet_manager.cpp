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


#include "wallet_manager.h"
#include "common/string_util.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "wallet.h"
#include "common_defines.h"
#include "common/dns_utils.h"
#include "common/util.h"
#include "version.h"
#include <boost/filesystem.hpp>

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "WalletAPI"

namespace Monero {

Wallet *WalletManagerImpl::createWallet(const std::string &path, const std::string &password,
                                    const std::string &language, NetworkType nettype, uint64_t kdf_rounds)
{
    WalletImpl * wallet = new WalletImpl(nettype, kdf_rounds);
    wallet->create(path, password, language);
    return wallet;
}

Wallet *WalletManagerImpl::openWallet(const std::string &path, const std::string &password, NetworkType nettype, uint64_t kdf_rounds, WalletListener * listener)
{
    WalletImpl * wallet = new WalletImpl(nettype, kdf_rounds);
    wallet->setListener(listener);
    if (listener){
        listener->onSetWallet(wallet);
    }

    wallet->open(path, password);
    //Refresh addressBook
    wallet->addressBook()->refresh(); 
    return wallet;
}

Wallet *WalletManagerImpl::recoveryWallet(const std::string &path, const std::string &mnemonic, NetworkType nettype, uint64_t restoreHeight)
{
    return recoveryWallet(path, "", mnemonic, nettype, restoreHeight);
}

Wallet *WalletManagerImpl::createWalletFromKeys(const std::string &path,
                                                const std::string &language,
                                                NetworkType nettype,
                                                uint64_t restoreHeight,
                                                const std::string &addressString,
                                                const std::string &viewKeyString,
                                                const std::string &spendKeyString)
{
    return createWalletFromKeys(path, "", language, nettype, restoreHeight,
                                addressString, viewKeyString, spendKeyString);
}

Wallet *WalletManagerImpl::recoveryWallet(const std::string &path,
                                                const std::string &password,
                                                const std::string &mnemonic,
                                                NetworkType nettype,
                                                uint64_t restoreHeight,
                                                uint64_t kdf_rounds,
                                                const std::string &seed_offset/* = {}*/)
{
    WalletImpl * wallet = new WalletImpl(nettype, kdf_rounds);
    if(restoreHeight > 0){
        wallet->setRefreshFromBlockHeight(restoreHeight);
    }
    wallet->recover(path, password, mnemonic, seed_offset);
    return wallet;
}

Wallet *WalletManagerImpl::createWalletFromKeys(const std::string &path,
                                                const std::string &password,
                                                const std::string &language,
                                                NetworkType nettype, 
                                                uint64_t restoreHeight,
                                                const std::string &addressString,
                                                const std::string &viewKeyString,
                                                const std::string &spendKeyString,
                                                uint64_t kdf_rounds)
{
    WalletImpl * wallet = new WalletImpl(nettype, kdf_rounds);
    if(restoreHeight > 0){
        wallet->setRefreshFromBlockHeight(restoreHeight);
    }
    wallet->recoverFromKeysWithPassword(path, password, language, addressString, viewKeyString, spendKeyString);
    return wallet;
}

Wallet *WalletManagerImpl::createWalletFromDevice(const std::string &path,
                                                  const std::string &password,
                                                  NetworkType nettype,
                                                  const std::string &deviceName,
                                                  uint64_t restoreHeight,
                                                  const std::string &subaddressLookahead,
                                                  uint64_t kdf_rounds,
                                                  WalletListener * listener)
{
    WalletImpl * wallet = new WalletImpl(nettype, kdf_rounds);
    wallet->setListener(listener);
    if (listener){
        listener->onSetWallet(wallet);
    }

    if(restoreHeight > 0){
        wallet->setRefreshFromBlockHeight(restoreHeight);
    } else {
        wallet->setRefreshFromBlockHeight(wallet->estimateBlockChainHeight());
    }
    auto lookahead = tools::parse_subaddress_lookahead(subaddressLookahead);
    if (lookahead)
    {
        wallet->setSubaddressLookahead(lookahead->first, lookahead->second);
    }
    wallet->recoverFromDevice(path, password, deviceName);
    return wallet;
}

bool WalletManagerImpl::closeWallet(Wallet *wallet, bool store)
{
    WalletImpl * wallet_ = dynamic_cast<WalletImpl*>(wallet);
    if (!wallet_)
        return false;
    bool result = wallet_->close(store);
    if (!result) {
        m_errorString = wallet_->errorString();
    } else {
        delete wallet_;
    }
    return result;
}

bool WalletManagerImpl::walletExists(const std::string &path)
{
    bool keys_file_exists;
    bool wallet_file_exists;
    tools::wallet2::wallet_exists(path, keys_file_exists, wallet_file_exists);
    if(keys_file_exists){
        return true;
    }
    return false;
}

bool WalletManagerImpl::verifyWalletPassword(const std::string &keys_file_name, const std::string &password, bool no_spend_key, uint64_t kdf_rounds) const
{
	    return tools::wallet2::verify_password(keys_file_name, password, no_spend_key, hw::get_device("default"), kdf_rounds);
}

bool WalletManagerImpl::queryWalletDevice(Wallet::Device& device_type, const std::string &keys_file_name, const std::string &password, uint64_t kdf_rounds) const
{
    hw::device::device_type type;
    bool r = tools::wallet2::query_device(type, keys_file_name, password, kdf_rounds);
    device_type = static_cast<Wallet::Device>(type);
    return r;
}

std::vector<std::string> WalletManagerImpl::findWallets(const std::string &path)
{
    std::vector<std::string> result;
    boost::filesystem::path work_dir(path);
    // return empty result if path doesn't exist
    if(!boost::filesystem::is_directory(path)){
        return result;
    }
    boost::filesystem::recursive_directory_iterator end_itr; // Default ctor yields past-the-end
    for (boost::filesystem::recursive_directory_iterator itr(path); itr != end_itr; ++itr) {
        // Skip if not a file
        if (!boost::filesystem::is_regular_file(itr->status()))
            continue;
        std::string filename = itr->path().filename().string();

        LOG_PRINT_L3("Checking filename: " << filename);

        if (tools::ends_with(filename, ".keys")) {
            // if keys file found, checking if there's wallet file itself
            filename.erase(filename.size() - 5);
            if (boost::filesystem::exists(filename)) {
                LOG_PRINT_L3("Found wallet: " << filename);
                result.push_back(std::move(filename));
            }
        }
    }
    return result;
}

std::string WalletManagerImpl::errorString() const
{
    return m_errorString;
}

void WalletManagerImpl::setDaemonAddress(std::string address)
{
    if (!tools::starts_with(address, "https://") && !tools::starts_with(address, "http://"))
        address.insert(0, "http://");
    m_http_client.set_base_url(std::move(address));
}

bool WalletManagerImpl::connected(uint32_t *version)
{
    using namespace cryptonote::rpc;
    try {
        auto res = m_http_client.json_rpc<GET_VERSION>(GET_VERSION::names()[0], {});
        if (version) *version = res.version;
        return true;
    } catch (...) {}

    return false;
}

template <typename RPC>
static std::optional<typename RPC::response> json_rpc(cryptonote::rpc::http_client& http, const typename RPC::request& req = {})
{
    using namespace cryptonote::rpc;
    try { return http.json_rpc<RPC>(RPC::names()[0], req); }
    catch (...) {}
    return std::nullopt;
}

static std::optional<cryptonote::rpc::GET_INFO::response> get_info(cryptonote::rpc::http_client& http)
{
    return json_rpc<cryptonote::rpc::GET_INFO>(http);
}


uint64_t WalletManagerImpl::blockchainHeight()
{
    auto res = get_info(m_http_client);
    return res ? res->height : 0;
}

uint64_t WalletManagerImpl::blockchainTargetHeight()
{
    auto res = get_info(m_http_client);
    if (!res)
        return 0;
    return std::max(res->target_height, res->height);
}

uint64_t WalletManagerImpl::networkDifficulty()
{
    auto res = get_info(m_http_client);
    return res ? res->difficulty : 0;
}

double WalletManagerImpl::miningHashRate()
{
    auto mres = json_rpc<cryptonote::rpc::MINING_STATUS>(m_http_client);
    return mres && mres->active ? mres->speed : 0.0;
}

uint64_t WalletManagerImpl::blockTarget()
{
    auto res = get_info(m_http_client);
    return res ? res->target : 0;
}

bool WalletManagerImpl::isMining()
{
    auto mres = json_rpc<cryptonote::rpc::MINING_STATUS>(m_http_client);
    return mres && mres->active;
}

bool WalletManagerImpl::startMining(const std::string &address, uint32_t threads)
{
    cryptonote::rpc::START_MINING::request mreq{};
    mreq.miner_address = address;
    mreq.threads_count = threads;

    auto mres = json_rpc<cryptonote::rpc::START_MINING>(m_http_client, mreq);
    return mres && mres->status == cryptonote::rpc::STATUS_OK;
}

bool WalletManagerImpl::stopMining()
{
    auto mres = json_rpc<cryptonote::rpc::STOP_MINING>(m_http_client);
    return mres && mres->status == cryptonote::rpc::STATUS_OK;
}

std::string WalletManagerImpl::resolveOpenAlias(const std::string &address, bool &dnssec_valid) const
{
    std::vector<std::string> addresses = tools::dns_utils::addresses_from_url(address, dnssec_valid);
    if (addresses.empty())
        return "";
    return addresses.front();
}

///////////////////// WalletManagerFactory implementation //////////////////////
WalletManagerBase *WalletManagerFactory::getWalletManager()
{

    static WalletManagerImpl * g_walletManager = nullptr;

    if  (!g_walletManager) {
        g_walletManager = new WalletManagerImpl();
    }

    return g_walletManager;
}

void WalletManagerFactory::setLogLevel(int level)
{
    mlog_set_log_level(level);
}

void WalletManagerFactory::setLogCategories(const std::string &categories)
{
    mlog_set_log(categories.c_str());
}



}

namespace Bitmonero = Monero;
