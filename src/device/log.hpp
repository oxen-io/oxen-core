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

#include <cstddef>
#include <string>

#include "crypto/crypto.h"
#include "cryptonote_basic/account.h"
#include "device.hpp"
#include "ringct/rctOps.h"

namespace hw {

/* Note about debug:
 * To debug Device you can def the following :
 * #define DEBUG_HWDEVICE
 *   Activate debug mechanism:
 *     - Add more trace
 *     - All computation done by device are checked by default device.
 *       Required IODUMMYCRYPT_HWDEVICE or IONOCRYPT_HWDEVICE for fully working
 * #define IODUMMYCRYPT_HWDEVICE 1
 *     - It assumes sensitive data encryption is is off on device side. a XOR with 0x55. This allow
 * Ledger Class to make check on clear value #define IONOCRYPT_HWDEVICE 1
 *     - It assumes sensitive data encryption is off on device side.
 */

void log_hexbuffer(std::string_view msg, const void* buff, size_t len);
void log_message(std::string_view msg, std::string_view info);

#ifdef WITH_DEVICE_LEDGER
namespace ledger {

    inline constexpr unsigned const char dummy_view_key[32] = {0};
    inline constexpr unsigned const char dummy_spend_key[32] = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

#ifdef DEBUG_HWDEVICE

    extern crypto::secret_key dbg_viewkey;
    extern crypto::secret_key dbg_spendkey;

    void decrypt(char* buf, size_t len);
    crypto::key_derivation decrypt(const crypto::key_derivation& derivation);
    cryptonote::account_keys decrypt(const cryptonote::account_keys& keys);
    crypto::secret_key decrypt(const crypto::secret_key& sec);
    rct::key decrypt(const rct::key& sec);
    crypto::ec_scalar decrypt(const crypto::ec_scalar& res);

    void check32(
            const std::string& msg,
            const std::string& info,
            const void* h,
            const void* d,
            bool crypted = false);
    void check8(
            const std::string& msg,
            const std::string& info,
            const void* h,
            const void* d,
            bool crypted = false);

    void set_check_verbose(bool verbose);
#endif
}  // namespace ledger
#endif
}  // namespace hw
