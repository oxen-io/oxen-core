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

#include "address_book.h"

#include <vector>

#include "common_defines.h"
#include "crypto/hash.h"
#include "wallet.h"
#include "wallet/wallet2.h"

namespace Wallet {

EXPORT
AddressBook::~AddressBook() {}

EXPORT
AddressBookImpl::AddressBookImpl(WalletImpl* wallet) : m_wallet(wallet), m_errorCode(Status_Ok) {}

EXPORT
bool AddressBookImpl::addRow(const std::string& dst_addr, const std::string& description) {
    clearStatus();

    auto w = m_wallet->wallet();
    cryptonote::address_parse_info info;
    if (!cryptonote::get_account_address_from_str(info, w->nettype(), dst_addr)) {
        m_errorString = "Invalid destination address";
        m_errorCode = Invalid_Address;
        return false;
    }

    bool r = w->add_address_book_row(
            info.address,
            info.has_payment_id ? &info.payment_id : NULL,
            description,
            info.is_subaddress);
    if (r)
        refresh();
    else
        m_errorCode = General_Error;
    return r;
}

EXPORT
void AddressBookImpl::refresh() {
    log::debug(logcat, "Refreshing addressbook");

    clearRows();

    // Fetch from Wallet2 and create vector of AddressBookRow objects
    std::vector<tools::wallet2::address_book_row> rows = m_wallet->wallet()->get_address_book();
    for (size_t i = 0; i < rows.size(); ++i) {
        tools::wallet2::address_book_row* row = &rows.at(i);

        std::string address;
        if (row->m_has_payment_id)
            address = cryptonote::get_account_integrated_address_as_str(
                    m_wallet->m_wallet_ptr->nettype(), row->m_address, row->m_payment_id);
        else
            address = get_account_address_as_str(
                    m_wallet->m_wallet_ptr->nettype(), row->m_is_subaddress, row->m_address);
        AddressBookRow* abr = new AddressBookRow(i, address, row->m_description);
        m_rows.push_back(abr);
    }
}

EXPORT
bool AddressBookImpl::deleteRow(std::size_t rowId) {
    log::debug(logcat, "Deleting address book row {}", rowId);
    bool r = m_wallet->wallet()->delete_address_book_row(rowId);
    if (r)
        refresh();
    return r;
}

EXPORT
void AddressBookImpl::clearRows() {
    for (auto r : m_rows) {
        delete r;
    }
    m_rows.clear();
}

EXPORT
void AddressBookImpl::clearStatus() {
    m_errorString = "";
    m_errorCode = 0;
}

EXPORT
std::vector<AddressBookRow*> AddressBookImpl::getAll() const {
    return m_rows;
}

EXPORT
AddressBookImpl::~AddressBookImpl() {
    clearRows();
}

}  // namespace Wallet
