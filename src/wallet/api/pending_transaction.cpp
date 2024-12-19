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

#include "pending_transaction.h"
#include "wallet.h"
#include "common_defines.h"

#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "common/base58.h"
#include "common/fs.h"

#include <memory>
#include <vector>
#include <sstream>
#include <boost/format.hpp>

namespace Wallet {

EXPORT
PendingTransaction::~PendingTransaction() {}


EXPORT
PendingTransactionImpl::PendingTransactionImpl(WalletImpl &wallet)
    : m_wallet(wallet), m_status{Status_Ok, ""}
{
}

EXPORT
PendingTransactionImpl::PendingTransactionImpl(WalletImpl& wallet, std::vector<tools::wallet2::pending_tx> pending_tx)
    : m_wallet{wallet}, m_status{Status_Ok, ""}, m_pending_tx{std::move(pending_tx)}
{}

EXPORT
PendingTransactionImpl::~PendingTransactionImpl()
{

}

EXPORT
void PendingTransactionImpl::setError(std::string error_msg) {
  m_status = {Status_Error, tr(error_msg)};
}

EXPORT
std::vector<std::string> PendingTransactionImpl::txid() const
{
    std::vector<std::string> txid;
    for (const auto &pt: m_pending_tx)
        txid.push_back(tools::type_to_hex(cryptonote::get_transaction_hash(pt.tx)));
    return txid;
}

EXPORT
bool PendingTransactionImpl::commit(std::string_view filename_, bool overwrite, bool blink)
{

    LOG_PRINT_L3("m_pending_tx size: " << m_pending_tx.size());

    auto filename = fs::u8path(filename_);

    auto w = m_wallet.wallet();
    try {
      // Save tx to file
      if (!filename.empty()) {
        if (std::error_code ec_ignore; fs::exists(filename, ec_ignore) && !overwrite){
          m_status = {Status_Error, tr("Attempting to save transaction to file, but specified file(s) exist. Exiting to not risk overwriting. File:") + filename.u8string()};
          LOG_ERROR(m_status.second);
          return false;
        }
        bool r = w->save_tx(m_pending_tx, filename);
        if (!r) {
          m_status = {Status_Error, tr("Failed to write transaction(s) to file")};
        } else {
          m_status = {Status_Ok, ""};
        }
      }
      // Commit tx
      else {
        auto multisigState = m_wallet.multisig(w);
        if (multisigState.isMultisig && m_signers.size() < multisigState.threshold) {
            throw std::runtime_error("Not enough signers to send multisig transaction");
        }

        const bool tx_cold_signed = w->get_account().get_device().has_tx_cold_sign();
        if (tx_cold_signed){
          std::unordered_set<size_t> selected_transfers;
          for(const tools::wallet2::pending_tx & ptx : m_pending_tx){
            for(size_t s : ptx.selected_transfers){
              selected_transfers.insert(s);
            }
          }

          w->cold_tx_aux_import(m_pending_tx, m_tx_device_aux);
          bool r = w->import_key_images(m_key_images, 0, selected_transfers);
          if (!r){
            throw std::runtime_error("Cold sign transaction submit failed - key image sync fail");
          }
        }

        while (!m_pending_tx.empty()) {
            auto & ptx = m_pending_tx.back();
            w->commit_tx(ptx, blink);
            // if no exception, remove element from vector
            m_pending_tx.pop_back();
        } // TODO: extract method;
      }
    } catch (const tools::error::daemon_busy&) {
        m_status = {Status_Error, tr("daemon is busy. Please try again later.")};
    } catch (const tools::error::no_connection_to_daemon&) {
        m_status = {Status_Error, tr("no connection to daemon. Please make sure daemon is running.")};
    } catch (const tools::error::tx_rejected& e) {
        m_status.first = Status_Error;
        m_status.second += (boost::format(tr("transaction %s was rejected by daemon with status: ")) % get_transaction_hash(e.tx())).str();
        m_status.second += e.status();
        if (auto& reason = e.reason(); !reason.empty())
            m_status.second += tr(". Reason: ") + reason;
    } catch (const std::exception &e) {
        m_status = {Status_Error, std::string(tr("Unknown exception: ")) + e.what()};
    } catch (...) {
        m_status = {Status_Error, tr("Unhandled exception")};
        LOG_ERROR(m_status.second);
    }

    return good();
}

EXPORT
uint64_t PendingTransactionImpl::amount() const
{
    uint64_t result = 0;
    auto w = m_wallet.wallet();
    for (const auto &ptx : m_pending_tx)   {
        for (const auto &dest : ptx.dests) {
            result += dest.amount;
        }
        service_nodes::staking_components sc;
        uint64_t height = m_wallet.blockChainHeight();
        std::optional<uint8_t> hf_version = m_wallet.hardForkVersion();
        if (hf_version)
        {
          auto hf = static_cast<cryptonote::hf>(*hf_version);
          if (service_nodes::tx_get_staking_components_and_amounts(static_cast<cryptonote::network_type>(w->nettype()), hf, ptx.tx, height, &sc)
          && sc.transferred > 0)
            result = sc.transferred;
        }
    }
    return result;
}

EXPORT
uint64_t PendingTransactionImpl::dust() const
{
    uint64_t result = 0;
    for (const auto & ptx : m_pending_tx) {
        result += ptx.dust;
    }
    return result;
}

EXPORT
uint64_t PendingTransactionImpl::fee() const
{
    uint64_t result = 0;
    for (const auto &ptx : m_pending_tx) {
        result += ptx.fee;
    }
    return result;
}

EXPORT
uint64_t PendingTransactionImpl::txCount() const
{
    return m_pending_tx.size();
}

EXPORT
std::vector<uint32_t> PendingTransactionImpl::subaddrAccount() const
{
    std::vector<uint32_t> result;
    for (const auto& ptx : m_pending_tx)
        result.push_back(ptx.construction_data.subaddr_account);
    return result;
}

EXPORT
std::vector<std::set<uint32_t>> PendingTransactionImpl::subaddrIndices() const
{
    std::vector<std::set<uint32_t>> result;
    for (const auto& ptx : m_pending_tx)
        result.push_back(ptx.construction_data.subaddr_indices);
    return result;
}

EXPORT
std::string PendingTransactionImpl::multisigSignData() {
    try {
        if (!m_wallet.multisig().isMultisig) {
            throw std::runtime_error("wallet is not multisig");
        }

        tools::wallet2::multisig_tx_set txSet;
        txSet.m_ptx = m_pending_tx;
        txSet.m_signers = m_signers;
        auto cipher = m_wallet.wallet()->save_multisig_tx(txSet);

        return oxenc::to_hex(cipher);
    } catch (const std::exception& e) {
        m_status = {Status_Error, std::string(tr("Couldn't multisig sign data: ")) + e.what()};
    }

    return std::string();
}

EXPORT
void PendingTransactionImpl::signMultisigTx() {
    try {
        std::vector<crypto::hash> ignore;

        tools::wallet2::multisig_tx_set txSet;
        txSet.m_ptx = m_pending_tx;
        txSet.m_signers = m_signers;

        if (!m_wallet.wallet()->sign_multisig_tx(txSet, ignore)) {
            throw std::runtime_error("couldn't sign multisig transaction");
        }

        std::swap(m_pending_tx, txSet.m_ptx);
        std::swap(m_signers, txSet.m_signers);
    } catch (const std::exception& e) {
        m_status = {Status_Error, std::string(tr("Couldn't sign multisig transaction: ")) + e.what()};
    }
}

EXPORT
std::vector<std::string> PendingTransactionImpl::signersKeys() const {
    std::vector<std::string> keys;
    keys.reserve(m_signers.size());

    for (const auto& signer: m_signers) {
        keys.emplace_back(tools::base58::encode(cryptonote::t_serializable_object_to_blob(signer)));
    }

    return keys;
}

}
