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
#include "common/util.h"
#include "version.h"
#include "common/fs.h"

namespace Wallet {

Wallet* WalletManagerImpl::createWallet(std::string_view path, const std::string &password,
                                    const std::string &language, NetworkType nettype, uint64_t kdf_rounds)
{
    WalletImpl* wallet = new WalletImpl(nettype, kdf_rounds);
    wallet->create(path, password, language);
    return wallet;
}

Wallet* WalletManagerImpl::openWallet(std::string_view path, const std::string &password, NetworkType nettype, uint64_t kdf_rounds, WalletListener * listener)
{
    WalletImpl* wallet = new WalletImpl(nettype, kdf_rounds);
    wallet->setListener(listener);
    if (listener){
        listener->onSetWallet(wallet);
    }

    wallet->open(path, password);
    //Refresh addressBook
    wallet->addressBook()->refresh(); 
    return wallet;
}

Wallet* WalletManagerImpl::recoveryWallet(std::string_view path,
                                                const std::string &password,
                                                const std::string &mnemonic,
                                                NetworkType nettype,
                                                uint64_t restoreHeight,
                                                uint64_t kdf_rounds,
                                                const std::string &seed_offset/* = {}*/)
{
    WalletImpl* wallet = new WalletImpl(nettype, kdf_rounds);
    if(restoreHeight > 0){
        wallet->setRefreshFromBlockHeight(restoreHeight);
    }
    wallet->recover(path, password, mnemonic, seed_offset);
    return wallet;
}

Wallet* WalletManagerImpl::createWalletFromKeys(std::string_view path,
                                                const std::string &password,
                                                const std::string &language,
                                                NetworkType nettype, 
                                                uint64_t restoreHeight,
                                                const std::string &addressString,
                                                const std::string &viewKeyString,
                                                const std::string &spendKeyString,
                                                uint64_t kdf_rounds)
{
    WalletImpl* wallet = new WalletImpl(nettype, kdf_rounds);
    if(restoreHeight > 0){
        wallet->setRefreshFromBlockHeight(restoreHeight);
    }
    wallet->recoverFromKeysWithPassword(path, password, language, addressString, viewKeyString, spendKeyString);
    return wallet;
}

Wallet* WalletManagerImpl::createWalletFromDevice(std::string_view path,
                                                  const std::string &password,
                                                  NetworkType nettype,
                                                  const std::string &deviceName,
                                                  uint64_t restoreHeight,
                                                  const std::string &subaddressLookahead,
                                                  uint64_t kdf_rounds,
                                                  WalletListener * listener)
{
    WalletImpl* wallet = new WalletImpl(nettype, kdf_rounds);
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

bool WalletManagerImpl::closeWallet(Wallet* wallet, bool store)
{
    WalletImpl* wallet_ = dynamic_cast<WalletImpl*>(wallet);
    if (!wallet_)
        return false;
    bool result = wallet_->close(store);
    if (!result) {
        m_errorString = wallet_->status().second;
    } else {
        delete wallet_;
    }
    return result;
}

bool WalletManagerImpl::walletExists(std::string_view path)
{
    bool keys_file_exists;
    bool wallet_file_exists;
    tools::wallet2::wallet_exists(fs::u8path(path), keys_file_exists, wallet_file_exists);
    if(keys_file_exists){
        return true;
    }
    return false;
}

bool WalletManagerImpl::verifyWalletPassword(std::string_view keys_file_name, const std::string &password, bool no_spend_key, uint64_t kdf_rounds) const
{
	    return tools::wallet2::verify_password(fs::u8path(keys_file_name), password, no_spend_key, hw::get_device("default"), kdf_rounds);
}

bool WalletManagerImpl::queryWalletDevice(Wallet::Device& device_type, std::string_view keys_file_name, const std::string &password, uint64_t kdf_rounds) const
{
    hw::device::type type;
    bool r = tools::wallet2::query_device(type, fs::u8path(keys_file_name), password, kdf_rounds);
    device_type = static_cast<Wallet::Device>(type);
    return r;
}

std::vector<std::string> WalletManagerImpl::findWallets(std::string_view path_)
{
    auto path = fs::u8path(path_);
    std::vector<std::string> result;
    // return empty result if path doesn't exist
    if (!fs::is_directory(path)){
        return result;
    }
    for (auto& p : fs::recursive_directory_iterator{path}) {
        // Skip if not a file
        if (!p.is_regular_file())
            continue;
        auto filename = p.path();

        log::trace(logcat, "Checking filename: {}", filename.string());

        if (filename.extension() == ".keys") {
            // if keys file found, checking if there's wallet file itself
            filename.replace_extension();
            if (fs::exists(filename)) {
                log::trace(logcat, "Found wallet: {}", filename.string());
                result.push_back(filename.u8string());
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
        auto res = m_http_client.json_rpc("get_version");
        if (version) *version = res["version"];
        return true;
    } catch (...) {}

    return false;
}

static nlohmann::json get_info(cryptonote::rpc::http_client& http)
{
    return http.json_rpc("get_info");
}


uint64_t WalletManagerImpl::blockchainHeight()
{
    auto res = get_info(m_http_client);
    return res ? res["height"].get<uint64_t>() : 0;
}

uint64_t WalletManagerImpl::blockchainTargetHeight()
{
    auto res = get_info(m_http_client);
    if (!res)
        return 0;
    return std::max(res["target_height"].get<uint64_t>(), res["height"].get<uint64_t>());
}

uint64_t WalletManagerImpl::blockTarget()
{
    auto res = get_info(m_http_client);
    return res ? res["target"].get<uint64_t>() : 0;
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
    auto log_level = oxen::logging::parse_level(level);
    if (log_level.has_value())
      log::reset_level(*log_level);
}

void WalletManagerFactory::setLogCategories(const std::string &categories)
{
    oxen::logging::process_categories_string(categories);
}



}
