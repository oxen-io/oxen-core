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
#include <cstdint>

namespace tools::wallet_rpc::error_code {

constexpr int16_t UNKNOWN_ERROR = -1;
constexpr int16_t WRONG_ADDRESS = -2;
constexpr int16_t DAEMON_IS_BUSY = -3;
constexpr int16_t GENERIC_TRANSFER_ERROR = -4;
constexpr int16_t WRONG_PAYMENT_ID = -5;
constexpr int16_t TRANSFER_TYPE = -6;
constexpr int16_t DENIED = -7;
constexpr int16_t WRONG_TXID = -8;
constexpr int16_t WRONG_SIGNATURE = -9;
constexpr int16_t WRONG_KEY_IMAGE = -10;
constexpr int16_t WRONG_URI = -11;
constexpr int16_t WRONG_INDEX = -12;
constexpr int16_t NOT_OPEN = -13;
constexpr int16_t ACCOUNT_INDEX_OUT_OF_BOUNDS = -14;
constexpr int16_t ADDRESS_INDEX_OUT_OF_BOUNDS = -15;
constexpr int16_t TX_NOT_POSSIBLE = -16;
constexpr int16_t NOT_ENOUGH_MONEY = -17;
constexpr int16_t TX_TOO_LARGE = -18;
constexpr int16_t NOT_ENOUGH_OUTS_TO_MIX = -19;
constexpr int16_t ZERO_DESTINATION = -20;
constexpr int16_t WALLET_ALREADY_EXISTS = -21;
constexpr int16_t INVALID_PASSWORD = -22;
constexpr int16_t NO_WALLET_DIR = -23;
constexpr int16_t NO_TXKEY = -24;
constexpr int16_t WRONG_KEY = -25;
constexpr int16_t BAD_HEX = -26;
constexpr int16_t BAD_TX_METADATA = -27;
constexpr int16_t ALREADY_MULTISIG = -28;
constexpr int16_t WATCH_ONLY = -29;
constexpr int16_t BAD_MULTISIG_INFO = -30;
constexpr int16_t NOT_MULTISIG = -31;
constexpr int16_t WRONG_LR = -32;
constexpr int16_t THRESHOLD_NOT_REACHED = -33;
constexpr int16_t BAD_MULTISIG_TX_DATA = -34;
constexpr int16_t MULTISIG_SIGNATURE = -35;
constexpr int16_t MULTISIG_SUBMISSION = -36;
constexpr int16_t NOT_ENOUGH_UNLOCKED_MONEY = -37;
constexpr int16_t NO_DAEMON_CONNECTION = -38;
constexpr int16_t BAD_UNSIGNED_TX_DATA = -39;
constexpr int16_t BAD_SIGNED_TX_DATA = -40;
constexpr int16_t SIGNED_SUBMISSION = -41;
constexpr int16_t SIGN_UNSIGNED = -42;
constexpr int16_t NON_DETERMINISTIC = -43;
constexpr int16_t INVALID_LOG_LEVEL = -44;
constexpr int16_t ATTRIBUTE_NOT_FOUND = -45;

// Loki:
constexpr int16_t BLINK_FAILED = -1000;
constexpr int16_t HF_QUERY_FAILED = -1001;
constexpr int16_t WRONG_ONS_TYPE = -1002;
constexpr int16_t ONS_BAD_NAME = -1003;
constexpr int16_t ONS_VALUE_TOO_LONG = -1004;
constexpr int16_t ONS_VALUE_NOT_HEX = -1005;
constexpr int16_t ONS_VALUE_LENGTH_NOT_EVEN = -1006;
constexpr int16_t ONS_VALUE_DECRYPT_FAILED = -1007;
constexpr int16_t ONS_VALUE_ENCRYPT_FAILED = -1008;
constexpr int16_t ONS_BAD_VALUE = -1009;

}  // namespace tools::wallet_rpc::error_code
