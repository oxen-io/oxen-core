// Copyright (c) 2017-2019, The Monero Project
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

#include "crypto/crypto.h"
#include "version.h"
#include "device_ledger.hpp"
#include "ringct/rctOps.h"
#include "cryptonote_basic/account.h"
#include "cryptonote_basic/subaddress_index.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "common/lock.h"
#include "common/varint.h"
#include <chrono>
#include <boost/endian/conversion.hpp>

#ifdef DEBUG_HWDEVICE
#include <sodium/crypto_generichash.h>
#endif

namespace hw {

  namespace ledger {

  #ifdef WITH_DEVICE_LEDGER

    #undef OXEN_DEFAULT_LOG_CATEGORY
    #define OXEN_DEFAULT_LOG_CATEGORY "device.ledger"

    /* ===================================================================== */
    /* ===                           Debug                              ==== */
    /* ===================================================================== */

    namespace {

    bool apdu_verbose = true;

    #define LEDGER_STATUS(status) {status, #status##sv}
    constexpr std::pair<unsigned int, std::string_view> status_codes[] = {
      LEDGER_STATUS(SW_SECURITY_PIN_LOCKED),
      LEDGER_STATUS(SW_SECURITY_LOAD_KEY),
      LEDGER_STATUS(SW_SECURITY_COMMITMENT_CONTROL),
      LEDGER_STATUS(SW_SECURITY_AMOUNT_CHAIN_CONTROL),
      LEDGER_STATUS(SW_SECURITY_COMMITMENT_CHAIN_CONTROL),
      LEDGER_STATUS(SW_SECURITY_OUTKEYS_CHAIN_CONTROL),
      LEDGER_STATUS(SW_SECURITY_MAXOUTPUT_REACHED),
      LEDGER_STATUS(SW_SECURITY_HMAC),
      LEDGER_STATUS(SW_SECURITY_RANGE_VALUE),
      LEDGER_STATUS(SW_SECURITY_INTERNAL),
      LEDGER_STATUS(SW_SECURITY_MAX_SIGNATURE_REACHED),
      LEDGER_STATUS(SW_SECURITY_PREFIX_HASH),
      LEDGER_STATUS(SW_SECURITY_LOCKED),

      LEDGER_STATUS(SW_COMMAND_NOT_ALLOWED),
      LEDGER_STATUS(SW_SUBCOMMAND_NOT_ALLOWED),
      LEDGER_STATUS(SW_DENY),
      LEDGER_STATUS(SW_KEY_NOT_SET),
      LEDGER_STATUS(SW_WRONG_DATA),
      LEDGER_STATUS(SW_WRONG_DATA_RANGE),
      LEDGER_STATUS(SW_IO_FULL),

      LEDGER_STATUS(SW_CLIENT_NOT_SUPPORTED),

      LEDGER_STATUS(SW_WRONG_P1P2),
      LEDGER_STATUS(SW_INS_NOT_SUPPORTED),
      LEDGER_STATUS(SW_PROTOCOL_NOT_SUPPORTED),

      LEDGER_STATUS(SW_UNKNOWN),
    };

    std::string status_string(unsigned int code)
    {
      for (auto& [code_, str] : status_codes)
        if (code_ == code)
          return std::string{str};
      if ((code & 0xff00) == SW_WRONG_LENGTH)
        return "SW_WRONG_LENGTH(" + std::to_string(code & 0xff) + ")";
      return "UNKNOWN"s;
    }

    } // anon namespace

    void set_apdu_verbose(bool verbose) {
      apdu_verbose = verbose;
    }

#ifdef DEBUG_HWDEVICE
    crypto::secret_key dbg_viewkey;
    crypto::secret_key dbg_spendkey;
#endif

    /* ===================================================================== */
    /* ===                        hmacmap                               ==== */
    /* ===================================================================== */


    SecHMAC::SecHMAC(const uint8_t s[32], const uint8_t h[32]) {
        std::memcpy(sec, s, 32);
        std::memcpy(hmac, h, 32);
    }

    void  HMACmap::find_mac(const uint8_t sec[32], uint8_t hmac[32]) {
      size_t sz = hmacs.size();
      log_hexbuffer("find_mac: lookup for ", sec,32);
      for (size_t i=0; i<sz; i++) {
       log_hexbuffer("find_mac:   - try ", hmacs[i].sec, 32);
        if (memcmp(sec, hmacs[i].sec, 32) == 0) {
          std::memcpy(hmac, hmacs[i].hmac, 32);
          log_hexbuffer("find_mac:   - found ", hmacs[i].hmac, 32);
          return;
        }

      }
      throw std::runtime_error("Protocol error: try to send untrusted secret");
    }

    void  HMACmap::add_mac(const uint8_t sec[32], const uint8_t hmac[32]) {
      log_hexbuffer("add_mac: sec  ", sec, 32);
      log_hexbuffer("add_mac: hmac ", hmac, 32);
      hmacs.push_back(SecHMAC(sec,hmac));
    }

    void HMACmap::clear() {
      hmacs.clear();
    }

    /* ===================================================================== */
    /* ===                        Keymap                                ==== */
    /* ===================================================================== */

    ABPkeys::ABPkeys(const rct::key& A, const rct::key& B, const bool is_subaddr,  const bool is_change, const bool need_additional_txkeys,  const size_t real_output_index, const rct::key& P, const rct::key& AK) {
      Aout = A;
      Bout = B;
      is_subaddress = is_subaddr;
      is_change_address = is_change;
      additional_key = need_additional_txkeys;
      index = real_output_index;
      Pout = P;
      AKout = AK;
    }

    ABPkeys::ABPkeys(const ABPkeys& keys) {
      Aout = keys.Aout;
      Bout = keys.Bout;
      is_subaddress = keys.is_subaddress;
      is_change_address = keys.is_change_address;
      additional_key = keys.additional_key;
      index = keys.index;
      Pout = keys.Pout;
      AKout = keys.AKout;
    }

    ABPkeys &ABPkeys::operator=(const ABPkeys& keys) {
      if (&keys == this)
        return *this;
      Aout = keys.Aout;
      Bout = keys.Bout;
      is_subaddress = keys.is_subaddress;
      is_change_address = keys.is_change_address;
      additional_key = keys.additional_key;
      index = keys.index;
      Pout = keys.Pout;
      AKout = keys.AKout;
      return *this;
    }

    bool Keymap::find(const rct::key& P, ABPkeys& keys) const {
      size_t sz = ABP.size();
      for (size_t i=0; i<sz; i++) {
        if (ABP[i].Pout == P) {
          keys = ABP[i];
          return true;
        }
      }
      return false;
    }

    void Keymap::add(const ABPkeys& keys) {
      ABP.push_back(keys);
    }

    void Keymap::clear() {
      ABP.clear();
    }

#ifdef DEBUG_HWDEVICE
    void Keymap::log() {
      log_message("keymap", "content");
      size_t sz = ABP.size();
      for (size_t i=0; i<sz; i++) {
        log_message("  keymap", std::to_string(i));
        log_hexbuffer("    Aout", ABP[i].Aout.bytes, 32);
        log_hexbuffer("    Bout", ABP[i].Bout.bytes, 32);
        log_message  ("  is_sub", std::to_string(ABP[i].is_subaddress));
        log_message  ("   index", std::to_string(ABP[i].index));
        log_hexbuffer("    Pout", ABP[i].Pout.bytes, 32);
      }
    }
#endif

    /* ===================================================================== */
    /* ===                       Internal Helpers                       ==== */
    /* ===================================================================== */
    static bool is_fake_view_key(const crypto::secret_key &sec) {
      return sec == crypto::secret_key::null;
    }

    bool operator==(const crypto::key_derivation &d0, const crypto::key_derivation &d1) {
      static_assert(sizeof(crypto::key_derivation) == 32, "key_derivation must be 32 bytes");
      return !crypto_verify_32(reinterpret_cast<const unsigned char*>(&d0), reinterpret_cast<const unsigned char*>(&d1));
    }

    /* ===================================================================== */
    /* ===                             Device                           ==== */
    /* ===================================================================== */

    static int device_id = 0;

    #define PROTOCOL_VERSION                    1

#ifdef NDEBUG
    #define LEDGER_INS(name, code) \
    static constexpr uint8_t INS_##name = code
#else
    // Reverse lookup table for commands -> names, only available in debug compilations
    static std::unordered_map<uint8_t, std::string_view> debug_ins_names;
    static uint8_t debug_record_ins(uint8_t code, std::string_view name) { debug_ins_names.emplace(code, name); return code; }

    #define LEDGER_INS(name, code) \
    static const uint8_t INS_##name = debug_record_ins(code, #name##sv)
#endif

    LEDGER_INS(RESET,                           0x02);

    LEDGER_INS(GET_NETWORK,                     0x10);

    LEDGER_INS(GET_KEY,                         0x20);
    LEDGER_INS(DISPLAY_ADDRESS,                 0x21);
    LEDGER_INS(PUT_KEY,                         0x22);
    LEDGER_INS(GET_CHACHA8_PREKEY,              0x24);
    LEDGER_INS(VERIFY_KEY,                      0x26);

    LEDGER_INS(SECRET_KEY_TO_PUBLIC_KEY,        0x30);
    LEDGER_INS(GEN_KEY_DERIVATION,              0x32);
    LEDGER_INS(DERIVATION_TO_SCALAR,            0x34);
    LEDGER_INS(DERIVE_PUBLIC_KEY,               0x36);
    LEDGER_INS(DERIVE_SECRET_KEY,               0x38);
    LEDGER_INS(GEN_KEY_IMAGE,                   0x3A);
    LEDGER_INS(SECRET_KEY_ADD,                  0x3C);
    LEDGER_INS(SECRET_KEY_SUB,                  0x3E);
    LEDGER_INS(GENERATE_KEYPAIR,                0x40);
    LEDGER_INS(SECRET_SCAL_MUL_KEY,             0x42);
    LEDGER_INS(SECRET_SCAL_MUL_BASE,            0x44);

    LEDGER_INS(DERIVE_SUBADDRESS_PUBLIC_KEY,    0x46);
    LEDGER_INS(GET_SUBADDRESS,                  0x48);
    LEDGER_INS(GET_SUBADDRESS_SPEND_PUBLIC_KEY, 0x4A);
    LEDGER_INS(GET_SUBADDRESS_SECRET_KEY,       0x4C);

    LEDGER_INS(OPEN_TX,                         0x70);
    LEDGER_INS(SET_SIGNATURE_MODE,              0x72);
    LEDGER_INS(GET_ADDITIONAL_KEY,              0x74);
    LEDGER_INS(GET_TX_SECRET_KEY,               0x75);
    LEDGER_INS(ENCRYPT_PAYMENT_ID,              0x76);
    LEDGER_INS(GEN_COMMITMENT_MASK,             0x77);
    LEDGER_INS(BLIND,                           0x78);
    LEDGER_INS(UNBLIND,                         0x7A);
    LEDGER_INS(GEN_TXOUT_KEYS,                  0x7B);
    LEDGER_INS(PREFIX_HASH,                     0x7D);
    LEDGER_INS(VALIDATE,                        0x7C);
    LEDGER_INS(CLSAG,                           0x7F);
    LEDGER_INS(CLOSE_TX,                        0x80);

    LEDGER_INS(GET_TX_PROOF,                    0xA0);
    LEDGER_INS(GEN_UNLOCK_SIGNATURE,            0xA2);
    LEDGER_INS(GEN_ONS_SIGNATURE,               0xA3);
    LEDGER_INS(GEN_KEY_IMAGE_SIGNATURE,         0xA4);

    LEDGER_INS(GET_RESPONSE,                    0xc0);

    #define OPTION_MORE_DATA                    0x80

    // When we have to send a bunch of data to be keccak hashed we send in chunks of this size; we
    // could go up to 254, but Keccak uses 136-byte chunks so it makes some sense to send at that
    // size.
    constexpr size_t KECCAK_HASH_CHUNK_SIZE = 136;
    static_assert(KECCAK_HASH_CHUNK_SIZE <= 254, "Max keccak data chunk size exceeds the protocol limit");

    constexpr size_t BLAKE2B_HASH_CHUNK_SIZE = 128;
    static_assert(BLAKE2B_HASH_CHUNK_SIZE <= 254, "Max BLAKE2b data chunk size exceeds the protocol limit");


    device_ledger::device_ledger(): hw_device(0x0101, 0x05, 64, 2000) {
      id = device_id++;
      reset_buffer();
      mode = NONE;
      has_view_key = false;
      tx_in_progress = false;
      MDEBUG("Device " << id << " Created");
    }

    device_ledger::~device_ledger() {
      release();
      MDEBUG("Device " << id << " Destroyed");
    }

    /* ======================================================================= */
    /*  LOCKER                                                                 */
    /* ======================================================================= */

    //lock the device for a long sequence
    void device_ledger::lock() {
      MDEBUG("Ask for LOCKING for device " << name << " in thread ");
      device_locker.lock();
      MDEBUG("Device " << name << " LOCKed");
    }

    //lock the device for a long sequence
    bool device_ledger::try_lock() {
      MDEBUG("Ask for LOCKING(try) for device " << name << " in thread ");
      bool r = device_locker.try_lock();
      MDEBUG("Device " << name << (r ? "" : " not") << " LOCKed(try)");
      return r;
    }

    //unlock the device after a long sequence
    void device_ledger::unlock() {
      MDEBUG("Ask for UNLOCKING for device " << name << " in thread ");
      device_locker.unlock();
      MDEBUG("Device " << name << " UNLOCKed");
    }


    /* ======================================================================= */
    /*                                     IO                                  */
    /* ======================================================================= */

    #define IO_SW_DENY    0x6982
    #define IO_SECRET_KEY 0x02

      void device_ledger::logCMD() {
      if (apdu_verbose) {
        std::ostringstream cmd;
        cmd << std::hex << std::setfill('0');
        cmd << "v=0x" << std::setw(2) << +buffer_send[0];
        cmd << " i=0x" << std::setw(2) << +buffer_send[1];
#ifndef NDEBUG
        if (auto it = debug_ins_names.find(buffer_send[1]); it != debug_ins_names.end())
          cmd << '[' << it->second << ']';
#endif
        cmd << " p=(0x" << std::setw(2) << +buffer_send[2] << ",0x" << std::setw(2) << +buffer_send[3] << ')';
        cmd << " sz=0x" << std::setw(2) << +buffer_send[4] << '[' << std::to_string(buffer_send[4]) << "] ";
        MDEBUG("CMD: " << cmd.str() << oxenmq::to_hex(buffer_send + 5, buffer_send + length_send));
        last_cmd = std::chrono::steady_clock::now();
      }
    }

    void device_ledger::logRESP() {
      if (apdu_verbose)
        MDEBUG("RESP (+" << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - last_cmd).count() << "ms): "
              << oxenmq::to_hex(std::string_view{reinterpret_cast<const char*>(&sw), sizeof(sw)})
              << ' ' << oxenmq::to_hex(buffer_recv, buffer_recv + length_recv));
    }

    int device_ledger::set_command_header(unsigned char ins, unsigned char p1, unsigned char p2) {
      reset_buffer();
      buffer_send[0] = PROTOCOL_VERSION;
      buffer_send[1] = ins;
      buffer_send[2] = p1;
      buffer_send[3] = p2;
      buffer_send[4] = 0x00;
      return 5;
    }

    int device_ledger::set_command_header_noopt(unsigned char ins, unsigned char p1, unsigned char p2) {
      int offset = set_command_header(ins, p1, p2);
      buffer_send[offset++] = 0; // options
      buffer_send[4] = offset - 5;
      return offset;
    }

    void device_ledger::send_simple(unsigned char ins, unsigned char p1) {
      length_send = set_command_header_noopt(ins, p1);
      bool wait = ins == INS_GET_KEY && p1 == IO_SECRET_KEY;
      exchange(wait);
    }

    void device_ledger::send_bytes(const void* buf, size_t size, int& offset) {
      CHECK_AND_ASSERT_THROW_MES(offset + size <= BUFFER_SEND_SIZE, "send_bytes: out of bounds write");
      std::memmove(buffer_send+offset, buf, size);
      offset += size;
    }

    void device_ledger::receive_bytes(void* dest, size_t size, int& offset) {
      CHECK_AND_ASSERT_THROW_MES(offset + size <= BUFFER_RECV_SIZE, "receive_bytes: out of bounds read");
      std::memmove(dest, buffer_recv+offset, size);
      offset += size;
    }

    void device_ledger::receive_bytes(void* dest, size_t size) {
      int offset = 0;
      receive_bytes(dest, size, offset);
    }

    void device_ledger::send_u32(uint32_t x, int& offset) {
      boost::endian::native_to_big_inplace(x);
      send_bytes(&x, 4, offset);
    }

    void device_ledger::send_u16(uint16_t x, int& offset) {
      boost::endian::native_to_big_inplace(x);
      send_bytes(&x, 2, offset);
    }

    uint32_t device_ledger::receive_u32(int& offset) {
      uint32_t x;
      receive_bytes(&x, 4, offset);
      boost::endian::big_to_native_inplace(x);
      return x;
    }
    uint32_t device_ledger::receive_u32() {
      int offset = 0;
      return receive_u32(offset);
    }

    void device_ledger::send_secret(const unsigned char sec[32], int &offset) {
      MDEBUG("send_secret: " << tx_in_progress);
      send_bytes(sec, 32, offset);
      if (tx_in_progress) {
        CHECK_AND_ASSERT_THROW_MES(offset + 32 <= BUFFER_SEND_SIZE, "send_secret: out of bounds write (mac)");
        hmac_map.find_mac((uint8_t*)sec, buffer_send+offset);
        offset += 32;
      }
    }

    void device_ledger::receive_secret(unsigned char sec[32], int &offset) {
      MDEBUG("receive_secret: " << tx_in_progress);
      receive_bytes(sec, 32, offset);
      if (tx_in_progress) {
        CHECK_AND_ASSERT_THROW_MES(offset + 32 <= BUFFER_RECV_SIZE, "receive_secret: out of bounds read (mac)");
        hmac_map.add_mac((uint8_t*)sec, buffer_recv+offset);
        offset += 32;
      }
    }

    void device_ledger::send_finish(int& offset) {
      buffer_send[4] = offset-5;
      length_send = offset;
      offset = 0;
    }

    unsigned int device_ledger::finish_and_exchange(int& offset, bool wait_on_input) {
      send_finish(offset);
      return exchange(wait_on_input);
    }

    bool device_ledger::reset() {
      reset_buffer();
      int offset = set_command_header_noopt(INS_RESET);
      CHECK_AND_ASSERT_THROW_MES(offset + OXEN_VERSION_STR.size() <= BUFFER_SEND_SIZE, "OXEN_VERSION_STR is too long");
      send_bytes(OXEN_VERSION_STR.data(), OXEN_VERSION_STR.size(), offset);
      finish_and_exchange(offset);

      CHECK_AND_ASSERT_THROW_MES(length_recv>=3, "Communication error, less than three bytes received. Check your application version.");

      unsigned int device_version = 0;
      device_version = VERSION(buffer_recv[0], buffer_recv[1], buffer_recv[2]);

      CHECK_AND_ASSERT_THROW_MES (device_version >= MINIMAL_APP_VERSION,
                "Unsupported device application version: " << VERSION_MAJOR(device_version)<<"."<<VERSION_MINOR(device_version)<<"."<<VERSION_MICRO(device_version) <<
                " At least " << MINIMAL_APP_VERSION_MAJOR<<"."<<MINIMAL_APP_VERSION_MINOR<<"."<<MINIMAL_APP_VERSION_MICRO<<" is required.");

      return true;
    }

    unsigned int device_ledger::exchange(bool wait_on_input) {
      logCMD();

      length_recv = hw_device.exchange(buffer_send, length_send, buffer_recv, BUFFER_SEND_SIZE, wait_on_input);
      CHECK_AND_ASSERT_THROW_MES(length_recv >= 2, "Communication error, less than two bytes received");

      length_recv -= 2;
      sw = (buffer_recv[length_recv] << 8) | buffer_recv[length_recv+1];
      logRESP();

      // If we are waiting on input then we also want to be able to return a DENY
      if (wait_on_input && sw == IO_SW_DENY)
        return sw;

      CHECK_AND_ASSERT_THROW_MES(sw == SW_OK,
        "Wrong Device Status: " << "0x" << std::hex << sw << " (" << status_string(sw) << "), " <<
        "EXPECTED 0x" << std::hex << SW_OK << " (" << status_string(SW_OK) << "), ");

      return sw;
    }

    void device_ledger::reset_buffer() {
      length_send = 0;
      std::memset(buffer_send, 0, BUFFER_SEND_SIZE);
      length_recv = 0;
      std::memset(buffer_recv, 0, BUFFER_RECV_SIZE);
    }

    /* ======================================================================= */
    /*                              SETUP/TEARDOWN                             */
    /* ======================================================================= */

    bool device_ledger::set_name(std::string_view name) {
      this->name = name;
      return true;
    }

    std::string device_ledger::get_name() const {
      if (!connected())
        return "<disconnected:" + name + ">";
      return name;
    }

    bool device_ledger::init() {
#ifdef DEBUG_HWDEVICE
      debug_device = &hw::get_device("default");
#endif
      release();
      hw_device.init();
      MDEBUG("Device " << id <<" HIDUSB inited");
      return true;
    }

    static const std::vector<hw::io::hid_conn_params> known_devices {
        {0x2c97, 0x0001, 0, 0xffa0},
        {0x2c97, 0x0004, 0, 0xffa0},
    };

    bool device_ledger::connect() {
      disconnect();
      hw_device.connect(known_devices);
      reset();

      check_network_type();

#ifdef DEBUG_HWDEVICE
      cryptonote::account_public_address pubkey;
      get_public_address(pubkey);
#endif
      crypto::secret_key vkey;
      crypto::secret_key skey;
      get_secret_keys(vkey,skey);

      return true;
    }

    bool device_ledger::connected() const {
      return hw_device.connected();
    }

    bool device_ledger::disconnect() {
      hw_device.disconnect();
      return true;
    }

    bool device_ledger::release() {
      disconnect();
      hw_device.release();
      return true;
    }

    static std::string nettype_string(cryptonote::network_type n) {
        switch (n) {
            case cryptonote::network_type::MAINNET: return "mainnet";
            case cryptonote::network_type::TESTNET: return "testnet";
            case cryptonote::network_type::DEVNET: return "devnet";
            case cryptonote::network_type::FAKECHAIN: return "fakenet";
            default: return "(unknown)";
        }
    }

    void device_ledger::check_network_type() {
        auto locks = tools::unique_locks(device_locker, command_locker);

        send_simple(INS_GET_NETWORK);

        std::string coin{reinterpret_cast<const char*>(buffer_recv), 4};
        auto device_nettype = static_cast<cryptonote::network_type>(buffer_recv[4]);
        MDEBUG("Ledger wallet is set to " << coin << " " << nettype_string(device_nettype));
        if (coin != COIN_NETWORK)
            throw std::runtime_error{"Invalid wallet app: expected " + std::string{COIN_NETWORK} + ", got " + coin};
        if (device_nettype != nettype)
            throw std::runtime_error{"Ledger wallet is set to the wrong network type: expected " + nettype_string(nettype)
                + " but the device is set to " + nettype_string(device_nettype)};
    }

    void device_ledger::set_network_type(cryptonote::network_type set_nettype) {
        nettype = set_nettype;
    }

    bool  device_ledger::set_mode(device_mode mode) {
        auto locks = tools::unique_locks(device_locker, command_locker);

        int offset;

        switch(mode) {
        case TRANSACTION_CREATE_REAL:
        case TRANSACTION_CREATE_FAKE:
          offset = set_command_header_noopt(INS_SET_SIGNATURE_MODE, 1);
          buffer_send[offset++] = mode;

          finish_and_exchange(offset);

          this->mode = mode;
          break;

        case TRANSACTION_PARSE:
        case NONE:
          this->mode = mode;
          break;
        default:
           CHECK_AND_ASSERT_THROW_MES(false, " device_ledger::set_mode(unsigned int mode): invalid mode: "<<mode);
        }
        MDEBUG("Switch to mode: " <<mode);
        return device::set_mode(mode);
    }


    /* ======================================================================= */
    /*                             WALLET & ADDRESS                            */
    /* ======================================================================= */

    bool device_ledger::get_public_address(cryptonote::account_public_address &pubkey){
        auto locks = tools::unique_locks(device_locker, command_locker);

        send_simple(INS_GET_KEY, 1);

        int offset = 0;
        receive_bytes(pubkey.m_view_public_key.data, 32, offset);
        receive_bytes(pubkey.m_spend_public_key.data, 32, offset);

        return true;
    }

    bool device_ledger::get_secret_keys(crypto::secret_key& vkey, crypto::secret_key& skey) {
        auto locks = tools::unique_locks(device_locker, command_locker);

        //secret key are represented as fake key on the wallet side
        memcpy(vkey.data, dummy_view_key, 32);
        memcpy(skey.data, dummy_spend_key, 32);

        //spcialkey, normal conf handled in decrypt
        send_simple(INS_GET_KEY, 0x02);

        //View key is retrieved, if allowed, to speed up blockchain parsing
        receive_bytes(viewkey.data, 32);
        has_view_key = !is_fake_view_key(viewkey);
        MDEBUG((has_view_key ? "Have view key" : "Have no view key"));

#ifdef DEBUG_HWDEVICE
        send_simple(INS_GET_KEY, 0x04);
        int offset = 0;
        receive_bytes(dbg_viewkey.data, 32, offset);
        receive_bytes(dbg_spendkey.data, 32, offset);
#endif

        return true;
    }

    bool device_ledger::generate_chacha_key(const cryptonote::account_keys &keys, crypto::chacha_key &key, uint64_t kdf_rounds) {
        auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
        crypto::chacha_key key_x;
        debug_device->generate_chacha_key(hw::ledger::decrypt(keys), key_x, kdf_rounds);
#endif

        send_simple(INS_GET_CHACHA8_PREKEY);

        char prekey[200];
        receive_bytes(prekey, 200);
        crypto::generate_chacha_key_prehashed(prekey, sizeof(prekey), key, kdf_rounds);

#ifdef DEBUG_HWDEVICE
        hw::ledger::check32("generate_chacha_key_prehashed", "key", key_x.data(), key.data());
#endif

      return true;
    }

    void  device_ledger::display_address(const cryptonote::subaddress_index& index, const std::optional<crypto::hash8> &payment_id) {
        auto locks = tools::unique_locks(device_locker, command_locker);

        int offset = set_command_header_noopt(INS_DISPLAY_ADDRESS, payment_id?1:0);
        //index
        send_bytes(&index, sizeof(index), offset);

        //payment ID
        send_bytes(payment_id ? payment_id->data : crypto::hash8::null.data, 8, offset);

        CHECK_AND_ASSERT_THROW_MES(finish_and_exchange(offset, true) == SW_OK, "Timeout/Error on display address.");
    }

    /* ======================================================================= */
    /*                               SUB ADDRESS                               */
    /* ======================================================================= */

    bool device_ledger::derive_subaddress_public_key(const crypto::public_key &pub, const crypto::key_derivation &derivation, const std::size_t output_index, crypto::public_key &derived_pub){
      auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
      crypto::key_derivation derivation_x =
        (mode == TRANSACTION_PARSE && has_view_key) ? derivation : hw::ledger::decrypt(derivation);
      log_hexbuffer("derive_subaddress_public_key: [[IN]]  pub       ", pub.data, 32);
      log_hexbuffer("derive_subaddress_public_key: [[IN]]  derivation", derivation_x.data, 32);
      log_message(  "derive_subaddress_public_key: [[IN]]  index     ", std::to_string(output_index));
      crypto::public_key derived_pub_x;
      debug_device->derive_subaddress_public_key(pub, derivation_x, output_index, derived_pub_x);
      log_hexbuffer("derive_subaddress_public_key: [[OUT]] derived_pub", derived_pub_x.data, 32);
#endif

      if (mode == TRANSACTION_PARSE && has_view_key) {
        //If we are in TRANSACTION_PARSE, the given derivation has been retrieved uncrypted (wihtout the help
        //of the device), so continue that way.
        MDEBUG("derive_subaddress_public_key  : PARSE mode with known viewkey");
        crypto::derive_subaddress_public_key(pub, derivation, output_index, derived_pub);
      } else {

        int offset = set_command_header_noopt(INS_DERIVE_SUBADDRESS_PUBLIC_KEY);
        //pub
        send_bytes(pub.data, 32, offset);
        //derivation
        send_secret(derivation, offset);
        //index
        send_u32(output_index, offset);

        finish_and_exchange(offset);

        //pub key
        receive_bytes(derived_pub.data, 32);
      }
#ifdef DEBUG_HWDEVICE
      hw::ledger::check32("derive_subaddress_public_key", "derived_pub", derived_pub_x.data, derived_pub.data);
#endif

      return true;
    }

    crypto::public_key device_ledger::get_subaddress_spend_public_key(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index) {
        auto locks = tools::unique_locks(device_locker, command_locker);
        crypto::public_key D;

#ifdef DEBUG_HWDEVICE
        const cryptonote::account_keys keys_x = hw::ledger::decrypt(keys);
        log_hexbuffer("get_subaddress_spend_public_key: [[IN]]  keys.m_view_secret_key ", keys_x.m_view_secret_key.data, 32);
        log_hexbuffer("get_subaddress_spend_public_key: [[IN]]  keys.m_spend_secret_key", keys_x.m_spend_secret_key.data, 32);
        log_message  ("get_subaddress_spend_public_key: [[IN]]  index               ", std::to_string(index.major)+"."+std::to_string(index.minor));
        crypto::public_key D_x = debug_device->get_subaddress_spend_public_key(keys_x, index);
        log_hexbuffer("get_subaddress_spend_public_key: [[OUT]] derivation          ", D_x.data, 32);
#endif

        if (index.is_zero()) {
           D = keys.m_account_address.m_spend_public_key;
        } else {

          int offset = set_command_header_noopt(INS_GET_SUBADDRESS_SPEND_PUBLIC_KEY);
          //index
          static_assert(sizeof(cryptonote::subaddress_index) == 8);
          send_bytes(&index, sizeof(index), offset);

          finish_and_exchange(offset);

          receive_bytes(D.data, 32);
        }

#ifdef DEBUG_HWDEVICE
        hw::ledger::check32("get_subaddress_spend_public_key", "D", D_x.data, D.data);
#endif

        return D;
    }

    std::vector<crypto::public_key> device_ledger::get_subaddress_spend_public_keys(const cryptonote::account_keys &keys, uint32_t account, uint32_t begin, uint32_t end) {
      std::vector<crypto::public_key> pkeys;
      cryptonote::subaddress_index index{account, begin};
      for (uint32_t idx = begin; idx < end; ++idx) {
        index.minor = idx;
        pkeys.push_back(get_subaddress_spend_public_key(keys, index));
      }
      return pkeys;
    }

    cryptonote::account_public_address device_ledger::get_subaddress(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index) {
        auto locks = tools::unique_locks(device_locker, command_locker);
        cryptonote::account_public_address address;

#ifdef DEBUG_HWDEVICE
        const cryptonote::account_keys keys_x =  hw::ledger::decrypt(keys);
        log_hexbuffer("get_subaddress: [[IN]]  keys.m_view_secret_key ", keys_x.m_view_secret_key.data, 32);
        log_hexbuffer("get_subaddress: [[IN]]  keys.m_view_public_key",  keys_x.m_account_address.m_view_public_key.data, 32);
        log_hexbuffer("get_subaddress: [[IN]]  keys.m_spend_secret_key ", keys_x.m_spend_secret_key.data, 32);
        log_hexbuffer("get_subaddress: [[IN]]  keys.m_spend_public_key", keys_x.m_account_address.m_spend_public_key.data, 32);
        log_message(  "get_subaddress: [[IN]]  index                                ", std::to_string(index.major)+"."+std::to_string(index.minor));
        cryptonote::account_public_address address_x = debug_device->get_subaddress(keys_x, index);
        log_hexbuffer("get_subaddress: [[OUT]]  keys.m_view_public_key ", address_x.m_view_public_key.data, 32);
        log_hexbuffer("get_subaddress: [[OUT]]  keys.m_spend_public_key", address_x.m_spend_public_key.data, 32);
#endif

        if (index.is_zero()) {
          address = keys.m_account_address;
        } else {
          int offset = set_command_header_noopt(INS_GET_SUBADDRESS);
          //index
          static_assert(sizeof(cryptonote::subaddress_index) == 8);
          send_bytes(&index, sizeof(index), offset);

          finish_and_exchange(offset);

          offset = 0;
          receive_bytes(address.m_view_public_key.data, 32, offset);
          receive_bytes(address.m_spend_public_key.data, 32, offset);
        }

#ifdef DEBUG_HWDEVICE
        hw::ledger::check32("get_subaddress", "address.m_view_public_key.data", address_x.m_view_public_key.data, address.m_view_public_key.data);
        hw::ledger::check32("get_subaddress", "address.m_spend_public_key.data", address_x.m_spend_public_key.data, address.m_spend_public_key.data);
#endif

        return address;
    }

    crypto::secret_key  device_ledger::get_subaddress_secret_key(const crypto::secret_key &sec, const cryptonote::subaddress_index &index) {
        auto locks = tools::unique_locks(device_locker, command_locker);
        crypto::secret_key sub_sec;

#ifdef DEBUG_HWDEVICE
        const crypto::secret_key sec_x =  hw::ledger::decrypt(sec);
        log_message  ("get_subaddress_secret_key: [[IN]]  index  ", std::to_string(index.major)+"."+std::to_string(index.minor));
        log_hexbuffer("get_subaddress_secret_key: [[IN]]  sec    ", sec_x.data, 32);
        crypto::secret_key sub_sec_x = debug_device->get_subaddress_secret_key(sec_x, index);
        log_hexbuffer("get_subaddress_secret_key: [[OUT]] sub_sec", sub_sec_x.data, 32);
#endif

        int offset = set_command_header_noopt(INS_GET_SUBADDRESS_SECRET_KEY);
        //sec
        send_secret(sec, offset);
        //index
        static_assert(sizeof(cryptonote::subaddress_index) == 8);
        send_bytes(&index, sizeof(index), offset);

        finish_and_exchange(offset);

        offset = 0;
        receive_secret(sub_sec,  offset);

#ifdef DEBUG_HWDEVICE
        crypto::secret_key            sub_sec_clear =   hw::ledger::decrypt(sub_sec);
        hw::ledger::check32("get_subaddress_secret_key", "sub_sec", sub_sec_x.data, sub_sec_clear.data);
#endif

        return sub_sec;
    }

    /* ======================================================================= */
    /*                            DERIVATION & KEY                             */
    /* ======================================================================= */

    bool  device_ledger::verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key) {
        auto locks = tools::unique_locks(device_locker, command_locker);
        int offset;

        offset = set_command_header_noopt(INS_VERIFY_KEY);
        //sec
        send_secret(secret_key, offset);
        //pub
        send_bytes(public_key.data, 32, offset);

        finish_and_exchange(offset);

        offset = 0;
        uint32_t verified = receive_u32(offset);

        return verified == 1;
    }

    bool device_ledger::scalarmultKey(rct::key& aP, const rct::key &P, const rct::key &a) {
        auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
        const rct::key a_x = hw::ledger::decrypt(a);
        log_hexbuffer("scalarmultKey: [[IN]]  P ", P.bytes, 32);
        log_hexbuffer("scalarmultKey: [[IN]]  a ", a_x.bytes, 32);
        rct::key aP_x;
        debug_device->scalarmultKey(aP_x, P, a_x);
        log_hexbuffer("scalarmultKey: [[OUT]] aP", aP_x.bytes, 32);
#endif

        int offset = set_command_header_noopt(INS_SECRET_SCAL_MUL_KEY);
        //pub
        send_bytes(P.bytes, 32, offset);
        //sec
        send_secret(a, offset);

        finish_and_exchange(offset);

        //pub key
        receive_bytes(aP.bytes, 32);

#ifdef DEBUG_HWDEVICE
        hw::ledger::check32("scalarmultKey", "mulkey", aP_x.bytes, aP.bytes);
#endif

        return true;
    }

    bool device_ledger::scalarmultBase(rct::key &aG, const rct::key &a) {
        auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
        const rct::key a_x =  hw::ledger::decrypt(a);
        log_hexbuffer("scalarmultKey: [[IN]]  a ", a_x.bytes, 32);
        rct::key aG_x;
        debug_device->scalarmultBase(aG_x, a_x);
        log_hexbuffer("scalarmultKey: [[OUT]] aG", aG_x.bytes, 32);
#endif

        int offset = set_command_header_noopt(INS_SECRET_SCAL_MUL_BASE);
        //sec
        send_secret(a, offset);

        finish_and_exchange(offset);

        //pub key
        receive_bytes(aG.bytes, 32);

#ifdef DEBUG_HWDEVICE
        hw::ledger::check32("scalarmultBase", "mulkey", aG_x.bytes, aG.bytes);
#endif

        return true;
    }

    bool device_ledger::sc_secret_add( crypto::secret_key &r, const crypto::secret_key &a, const crypto::secret_key &b) {
        auto locks = tools::unique_locks(device_locker, command_locker);
        int offset;

#ifdef DEBUG_HWDEVICE
        const crypto::secret_key a_x = hw::ledger::decrypt(a);
        const crypto::secret_key b_x = hw::ledger::decrypt(b);
        log_hexbuffer("sc_secret_add: [[IN]]  a ", a_x.data, 32);
        log_hexbuffer("sc_secret_add: [[IN]]  b ", b_x.data, 32);
        crypto::secret_key r_x;
        rct::key aG_x;
        debug_device->sc_secret_add(r_x, a_x, b_x);
        log_hexbuffer("sc_secret_add: [[OUT]] aG", r_x.data, 32);
#endif

        offset = set_command_header_noopt(INS_SECRET_KEY_ADD);
        //sec key
        send_secret(a, offset);
        //sec key
        send_secret(b, offset);

        finish_and_exchange(offset);

        //sec key
        offset = 0;
        receive_secret(r, offset);

#ifdef DEBUG_HWDEVICE
        crypto::secret_key r_clear = hw::ledger::decrypt(r);
        hw::ledger::check32("sc_secret_add", "r", r_x.data, r_clear.data);
#endif

        return true;
    }

    crypto::secret_key  device_ledger::generate_keys(crypto::public_key &pub, crypto::secret_key &sec, const crypto::secret_key& recovery_key, bool recover) {
        auto locks = tools::unique_locks(device_locker, command_locker);
        int offset;
        if (recover) {
           throw std::runtime_error("device generate key does not support recover");
        }

#ifdef DEBUG_HWDEVICE
        crypto::public_key pub_x;
        crypto::secret_key sec_x;
        crypto::secret_key recovery_key_x;
        if (recover) {
         recovery_key_x = hw::ledger::decrypt(recovery_key);
         log_hexbuffer("generate_keys: [[IN]] pub", recovery_key_x.data, 32);
        }
#endif

        send_simple(INS_GENERATE_KEYPAIR);

        offset = 0;
        //pub key
        receive_bytes(pub.data, 32, offset);
        receive_secret(sec, offset);

#ifdef DEBUG_HWDEVICE
        crypto::secret_key sec_clear = hw::ledger::decrypt(sec);
        sec_x = sec_clear;
        log_hexbuffer("generate_keys: [[OUT]] pub", pub.data, 32);
        log_hexbuffer("generate_keys: [[OUT]] sec", sec_clear.data, 32);

        crypto::secret_key_to_public_key(sec_x,pub_x);
        hw::ledger::check32("generate_keys", "pub", pub_x.data, pub.data);
#endif

        return sec;

    }

    bool device_ledger::generate_key_derivation(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_derivation &derivation) {
        auto locks = tools::unique_locks(device_locker, command_locker);
        bool r = false;

#ifdef DEBUG_HWDEVICE
        log_hexbuffer("generate_key_derivation: [[IN]]  pub       ", pub.data, 32);
        const crypto::secret_key sec_x = (sec == rct::rct2sk(rct::I)) ? sec : hw::ledger::decrypt(sec);
        log_hexbuffer("generate_key_derivation: [[IN]]  sec       ", sec_x.data, 32);
        crypto::key_derivation derivation_x;
        debug_device->generate_key_derivation(pub, sec_x, derivation_x);
        log_hexbuffer("generate_key_derivation: [[OUT]] derivation", derivation_x.data, 32);
#endif

      if (mode == TRANSACTION_PARSE && has_view_key) {
        //A derivation is requested in PARSE mode and we have the view key,
        //so do that without the device and return the derivation unencrypted.
        MDEBUG( "generate_key_derivation  : PARSE mode with known viewkey");
        //Note derivation in PARSE mode can only happen with viewkey, so assert it!
        assert(is_fake_view_key(sec));
        r = crypto::generate_key_derivation(pub, viewkey, derivation);
      } else {
        int offset = set_command_header_noopt(INS_GEN_KEY_DERIVATION);
        //pub
        send_bytes(pub.data, 32, offset);
         //sec
        send_secret(sec, offset);

        finish_and_exchange(offset);

        offset = 0;
        //derivation data
        receive_secret(derivation, offset);

        r = true;
      }
#ifdef DEBUG_HWDEVICE
      crypto::key_derivation derivation_clear =
        (mode == TRANSACTION_PARSE && has_view_key) ? derivation : hw::ledger::decrypt(derivation);
      hw::ledger::check32("generate_key_derivation", "derivation", derivation_x.data, derivation_clear.data);
#endif

      return r;
    }

    bool device_ledger::conceal_derivation(crypto::key_derivation &derivation, const crypto::public_key &tx_pub_key, const std::vector<crypto::public_key> &additional_tx_pub_keys, const crypto::key_derivation &main_derivation, const std::vector<crypto::key_derivation> &additional_derivations) {
      const crypto::public_key *pkey = nullptr;
      if (derivation == main_derivation) {
        pkey = &tx_pub_key;
        MDEBUG("conceal derivation with main tx pub key");
      } else {
        for (size_t n = 0; n < additional_derivations.size(); ++n) {
          if (derivation == additional_derivations[n]) {
            pkey = &additional_tx_pub_keys[n];
            MDEBUG("conceal derivation with additionnal tx pub key");
            break;
          }
        }
      }
      CHECK_AND_ASSERT_THROW_MES(pkey, "Mismatched derivation on scan info");
      return generate_key_derivation(*pkey,  crypto::secret_key::null, derivation);
    }

    bool device_ledger::derivation_to_scalar(const crypto::key_derivation &derivation, const size_t output_index, crypto::ec_scalar &res) {
        auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
        const crypto::key_derivation derivation_x = hw::ledger::decrypt(derivation);
        log_hexbuffer("derivation_to_scalar: [[IN]]  derivation    ", derivation_x.data, 32);
        log_message  ("derivation_to_scalar: [[IN]]  output_index  ", std::to_string(output_index));
        crypto::ec_scalar res_x;
        debug_device->derivation_to_scalar(derivation_x, output_index, res_x);
        log_hexbuffer("derivation_to_scalar: [[OUT]] res          ", res_x.data, 32);
#endif

        int offset = set_command_header_noopt(INS_DERIVATION_TO_SCALAR);
        //derivation
        send_secret(derivation, offset);

        //index
        send_u32(output_index, offset);

        finish_and_exchange(offset);

        //derivation data
        offset = 0;
        receive_secret(res, offset);

#ifdef DEBUG_HWDEVICE
        crypto::ec_scalar res_clear  = hw::ledger::decrypt(res);
        hw::ledger::check32("derivation_to_scalar", "res", res_x.data, res_clear.data);
#endif

        return true;
    }

    bool device_ledger::derive_secret_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::secret_key &sec, crypto::secret_key &derived_sec) {
        auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
        const crypto::key_derivation derivation_x   = hw::ledger::decrypt(derivation);
        const crypto::secret_key     sec_x          = hw::ledger::decrypt(sec);
        log_hexbuffer("derive_secret_key: [[IN]]  derivation ", derivation_x.data, 32);
        log_message  ("derive_secret_key: [[IN]]  index      ", std::to_string(output_index));
        log_hexbuffer("derive_secret_key: [[IN]]  sec        ", sec_x.data, 32);
        crypto::secret_key derived_sec_x;
        debug_device->derive_secret_key(derivation_x, output_index, sec_x, derived_sec_x);
        log_hexbuffer("derive_secret_key: [[OUT]] derived_sec", derived_sec_x.data, 32);
#endif

        int offset = set_command_header_noopt(INS_DERIVE_SECRET_KEY);
        //derivation
        send_secret(derivation, offset);
        //index
        send_u32(output_index, offset);
        //sec
        send_secret(sec, offset);

        finish_and_exchange(offset);

        offset = 0;
        //sec key
        receive_secret(derived_sec, offset);

#ifdef DEBUG_HWDEVICE
        crypto::secret_key derived_sec_clear = hw::ledger::decrypt(derived_sec);
        hw::ledger::check32("derive_secret_key", "derived_sec", derived_sec_x.data, derived_sec_clear.data);
#endif

        return true;
    }

    bool device_ledger::derive_public_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::public_key &pub, crypto::public_key &derived_pub){
        auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
        const crypto::key_derivation derivation_x = hw::ledger::decrypt(derivation);
        log_hexbuffer("derive_public_key: [[IN]]  derivation  ", derivation_x.data, 32);
        log_message  ("derive_public_key: [[IN]]  output_index", std::to_string(output_index));
        log_hexbuffer("derive_public_key: [[IN]]  pub         ", pub.data, 32);
        crypto::public_key derived_pub_x;
        debug_device->derive_public_key(derivation_x, output_index, pub, derived_pub_x);
        log_hexbuffer("derive_public_key: [[OUT]] derived_pub ", derived_pub_x.data, 32);
#endif

        int offset = set_command_header_noopt(INS_DERIVE_PUBLIC_KEY);
        //derivation
        send_secret(derivation, offset);
        //index
        send_u32(output_index, offset);
        //pub
        send_bytes(pub.data, 32, offset);

        finish_and_exchange(offset);

        //pub key
        receive_bytes(derived_pub.data, 32);

#ifdef DEBUG_HWDEVICE
        hw::ledger::check32("derive_public_key", "derived_pub", derived_pub_x.data, derived_pub.data);
#endif

        return true;
    }

    bool device_ledger::secret_key_to_public_key(const crypto::secret_key &sec, crypto::public_key &pub) {
        auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
        const crypto::secret_key sec_x = hw::ledger::decrypt(sec);
        log_hexbuffer("secret_key_to_public_key: [[IN]] sec ", sec_x.data, 32);
        crypto::public_key pub_x;
        bool rc = debug_device->secret_key_to_public_key(sec_x, pub_x);
        log_hexbuffer("secret_key_to_public_key: [[OUT]] pub", pub_x.data, 32);
        if (!rc){
          log_message("FAIL secret_key_to_public_key", "secret_key rejected");
        }
#endif

        int offset = set_command_header_noopt(INS_SECRET_KEY_TO_PUBLIC_KEY);
        //sec key
        send_secret(sec, offset);

        finish_and_exchange(offset);

        //pub key
        receive_bytes(pub.data, 32);

#ifdef DEBUG_HWDEVICE
        hw::ledger::check32("secret_key_to_public_key", "pub", pub_x.data, pub.data);
#endif

        return true;
    }

    bool device_ledger::generate_key_image(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_image &image){
        auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
        const crypto::secret_key sec_x = hw::ledger::decrypt(sec);
        log_hexbuffer("generate_key_image: [[IN]]  pub ", pub.data, 32);
        log_hexbuffer("generate_key_image: [[IN]]  sec ", sec_x.data, 32);
        crypto::key_image image_x;
        debug_device->generate_key_image(pub, sec_x, image_x);
        log_hexbuffer("generate_key_image: [[OUT]] image ", image_x.data, 32);
#endif

        int offset = set_command_header_noopt(INS_GEN_KEY_IMAGE);
        //pub
        send_bytes(pub.data, 32, offset);
        //sec
        send_secret(sec, offset);

        finish_and_exchange(offset);

        //key image
        receive_bytes(image.data, 32);

#ifdef DEBUG_HWDEVICE
        hw::ledger::check32("generate_key_image", "image", image_x.data, image.data);
#endif

        return true;
    }

    bool device_ledger::generate_key_image_signature(const crypto::key_image& image, const crypto::public_key& pub, const crypto::secret_key& sec, crypto::signature& sig) {
        auto locks = tools::unique_locks(device_locker, command_locker);

        int offset = set_command_header_noopt(INS_GEN_KEY_IMAGE_SIGNATURE);
        send_bytes(image.data, 32, offset);
        send_bytes(pub.data, 32, offset);
        send_secret(sec, offset);

        finish_and_exchange(offset);

        receive_bytes(reinterpret_cast<char*>(&sig), 64);

#ifdef DEBUG_HWDEVICE
        // We can't check the actual returned signature byte values because a random component is
        // involved, but we *can* attempt to verify the signature
        bool good = crypto::check_key_image_signature(image, pub, sig);
        log_hexbuffer("generate_key_image_signature: key image", image.data, 32);
        log_hexbuffer("generate_key_image_signature: pubkey", pub.data, 32);
        log_hexbuffer("generate_key_image_signature: signature.c", sig.c.data, 32);
        log_hexbuffer("generate_key_image_signature: signature.r", sig.r.data, 32);
        log_message("generate_key_image_signature: signature returned from device", good ? "passed" : "FAILED");
#endif

        return true;
    }

    bool device_ledger::generate_unlock_signature(const crypto::public_key& pub, const crypto::secret_key& sec, crypto::signature& sig) {
        auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
        log_hexbuffer("generate_unlock_signature: [[IN]]  pub ", pub.data, 32);
        const crypto::secret_key sec_x = hw::ledger::decrypt(sec);
        log_hexbuffer("generate_unlock_signature: [[IN]]  sec ", sec_x.data, 32);
#endif

        // Ask for confirmation:
        int offset = set_command_header_noopt(INS_GEN_UNLOCK_SIGNATURE);
        CHECK_AND_ASSERT_THROW_MES(finish_and_exchange(offset, true) == SW_OK, "Unlock denied on device.");

        // If we got permission then we can ask for the actual signature:
        offset = set_command_header_noopt(INS_GEN_UNLOCK_SIGNATURE, 1);
        send_bytes(pub.data, 32, offset);
        send_secret(sec, offset);
        finish_and_exchange(offset);

        receive_bytes(reinterpret_cast<char*>(&sig), 64);

#ifdef DEBUG_HWDEVICE
        // We can't check the actual returned signature byte values because a random component is
        // involved, but we *can* attempt to verify the signature
        bool good = crypto::check_signature(cryptonote::tx_extra_tx_key_image_unlock::HASH, pub, sig);
        log_hexbuffer("generate_unlock_signature: signature.c", sig.c.data, 32);
        log_hexbuffer("generate_unlock_signature: signature.r", sig.r.data, 32);
        log_message("generate_unlock_signature: signature returned from device", good ? "passed" : "FAILED");
#endif

        return true;
    }

    bool device_ledger::generate_ons_signature(std::string_view sig_data, const cryptonote::account_keys& keys, const cryptonote::subaddress_index& index, crypto::signature& sig) {
        // Initialize (prompts the user):
        int offset = set_command_header_noopt(INS_GEN_ONS_SIGNATURE);
        CHECK_AND_ASSERT_THROW_MES(finish_and_exchange(offset, true) == SW_OK, "ONS denied on device.");

        // Send ons signature data to be hashed:
        exchange_multipart_data(INS_GEN_ONS_SIGNATURE, 1, sig_data, BLAKE2B_HASH_CHUNK_SIZE);

        // Send the subaddr indices and get the signature:
        offset = set_command_header_noopt(INS_GEN_ONS_SIGNATURE, 2);
        send_bytes(&index, sizeof(index), offset);
        finish_and_exchange(offset);

        receive_bytes(reinterpret_cast<char*>(&sig), 64);

        return true;
    }

    /* ======================================================================= */
    /*                               TRANSACTION                               */
    /* ======================================================================= */

    void device_ledger::generate_tx_proof(const crypto::hash &prefix_hash,
                                          const crypto::public_key &R, const crypto::public_key &A, const std::optional<crypto::public_key> &B, const crypto::public_key &D, const crypto::secret_key &r,
                                          crypto::signature &sig)  {

      auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
      const crypto::hash prefix_hash_x = prefix_hash;
      const crypto::public_key R_x = R;
      const crypto::public_key A_x = A;
      const std::optional<crypto::public_key> B_x = B;
      const crypto::public_key D_x = D;
      const crypto::secret_key r_x = hw::ledger::decrypt(r);
      crypto::signature sig_x;
      log_hexbuffer("generate_tx_proof: [[IN]]  prefix_hash ", prefix_hash_x.data, 32);
      log_hexbuffer("generate_tx_proof: [[IN]]  R ", R_x.data, 32);
      log_hexbuffer("generate_tx_proof: [[IN]]  A ", A_x.data, 32);
      if (B_x)
        log_hexbuffer("generate_tx_proof: [[IN]]  B ", B_x->data, 32);
      log_hexbuffer("generate_tx_proof: [[IN]]  D ", D_x.data, 32);
      log_hexbuffer("generate_tx_proof: [[IN]]  r ", r_x.data, 32);
#endif


      int offset = set_command_header(INS_GET_TX_PROOF);
      //options
      buffer_send[offset++] = B ? 0x01 : 0x00;
      send_bytes(prefix_hash.data, 32, offset);                     // prefix_hash
      send_bytes(R.data, 32, offset);                               // R
      send_bytes(A.data, 32, offset);                               // A
      send_bytes(B ? B->data : crypto::public_key::null.data, 32, offset); // B
      send_bytes(D.data, 32, offset);                               // D
      send_secret(r, offset);                                       // r

      finish_and_exchange(offset);

      offset = 0;
      receive_bytes(sig.c.data, 32, offset);
      receive_bytes(sig.r.data, 32, offset);
#ifdef DEBUG_HWDEVICE
      log_hexbuffer("GENERATE_TX_PROOF: **c**   ", sig.c.data, sizeof(sig.c.data));
      log_hexbuffer("GENERATE_TX_PROOF: **r**   ", sig.r.data, sizeof(sig.r.data));

      debug_device->generate_tx_proof(prefix_hash_x, R_x, A_x, B_x, D_x, r_x, sig_x);
      MDEBUG("FAIL is normal if random is not fixed in proof");
      hw::ledger::check32("generate_tx_proof", "c", sig_x.c.data, sig.c.data);
      hw::ledger::check32("generate_tx_proof", "r", sig_x.r.data, sig.r.data);

#endif
    }

    bool device_ledger::open_tx(crypto::secret_key &tx_key, cryptonote::txversion txversion, cryptonote::txtype txtype) {
        auto locks = tools::unique_locks(device_locker, command_locker, *this);

        key_map.clear();
        hmac_map.clear();
        tx_in_progress = true;
        int offset = set_command_header_noopt(INS_OPEN_TX, 0x01);

        send_u16(static_cast<uint16_t>(txversion), offset);
        send_u16(static_cast<uint16_t>(txtype), offset);

        finish_and_exchange(offset);

        //skip R, receive: r, r_hmac, fake_a, a_hmac, fake_b, hmac_b
        unsigned char tmp[32];
        offset = 32;
        receive_secret(tx_key, offset);
        receive_secret(tmp, offset);
        receive_secret(tmp, offset);

#ifdef DEBUG_HWDEVICE
        const crypto::secret_key r_x = hw::ledger::decrypt(tx_key);
        log_hexbuffer("open_tx: [[OUT]] R ", buffer_recv, 32);
        log_hexbuffer("open_tx: [[OUT]] r ", r_x.data, 32);
#endif
        return true;
    }

    // Sends data in chunks using the given ins/p1 values, with p2 set to a sequence
    // 1->2->....->255->1->...->0 so that the hw device can make sure it didn't miss anything.
    // (Note the wrapping goes 255->1, not 255->0, as 0 always indicates the last piece).
    // Max chunk size is 254 bytes.
    void device_ledger::exchange_multipart_data(uint8_t ins, uint8_t p1, std::string_view data, uint8_t chunk_size) {
      assert(chunk_size <= 254);
      size_t cnt = 0;
      while (!data.empty()) {
        auto piece = data.substr(0, chunk_size);
        data.remove_prefix(piece.size());
        if (data.empty())
          cnt = 0; // Signals last piece
        else
          cnt = cnt == 255 ? 1 : cnt + 1;

        int offset = set_command_header_noopt(ins, p1, cnt);
        send_bytes(piece.data(), piece.size(), offset);
        finish_and_exchange(offset);
      }
    }

    void device_ledger::get_transaction_prefix_hash(const cryptonote::transaction_prefix& tx, crypto::hash& h) {
      auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
      crypto::hash h_x;
      debug_device->get_transaction_prefix_hash(tx, h_x);
      MDEBUG("get_transaction_prefix_hash [[IN]] h_x/1 " << h_x);
#endif

      // As of protocol version 4, we send:
      // - tx version
      // - tx type (transfer, registration, stake, ons)
      // - tx lock time (if the tx has multiple lock times this will be the largest one)
      // We then wait for confirmation from the device, and if we get it we continue by sending the
      // data in chunks.  The last chunk will have a p2 subparameter of 0;
      // otherwise the p2 subparameters are in order starting at 1 (and, if we wrap, we go from 255->1).

      std::string tx_prefix;
      try {
        tx_prefix = serialization::dump_binary(const_cast<cryptonote::transaction_prefix&>(tx));
      } catch (const std::exception& e) {
        ASSERT_MES_AND_THROW("unable to serialize transaction prefix: " << e.what());
      }

      unsigned char* send = buffer_send + set_command_header_noopt(INS_PREFIX_HASH, 1);

      // version as varint
      tools::write_varint(send, static_cast<std::underlying_type_t<cryptonote::txversion>>(tx.version));

      // transaction type as varint
      tools::write_varint(send, static_cast<std::underlying_type_t<cryptonote::txtype>>(tx.type));

      // Transactions can have multiple unlock times; find the longest one and send that
      uint64_t max_unlock = 0;
      for (size_t i = 0; i < tx.vout.size(); i++)
        max_unlock = std::max(max_unlock, tx.get_unlock_time(i));
      tools::write_varint(send, max_unlock);

      length_send = send - buffer_send;
      buffer_send[4] = length_send - 5;
      exchange(true);

      // hash the full prefix
      exchange_multipart_data(INS_PREFIX_HASH, 2, tx_prefix, KECCAK_HASH_CHUNK_SIZE);

      receive_bytes(h.data, 32);

#ifdef DEBUG_HWDEVICE
      hw::ledger::check8("prefix_hash", "h", h_x.data, h.data);
#endif
    }

    bool device_ledger::encrypt_payment_id(crypto::hash8 &payment_id, const crypto::public_key &public_key, const crypto::secret_key &secret_key) {
        auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
        const crypto::secret_key secret_key_x = hw::ledger::decrypt(secret_key);
        log_hexbuffer("encrypt_payment_id: [[IN]] payment_id ", payment_id.data, 32);
        log_hexbuffer("encrypt_payment_id: [[IN]] public_key ", public_key.data, 32);
        log_hexbuffer("encrypt_payment_id: [[IN]] secret_key ", secret_key_x.data, 32);
        crypto::hash8 payment_id_x = payment_id;
        debug_device->encrypt_payment_id(payment_id_x, public_key, secret_key_x);
        log_hexbuffer("encrypt_payment_id: [[OUT]] payment_id ", payment_id_x.data, 32);
#endif

        int offset = set_command_header_noopt(INS_ENCRYPT_PAYMENT_ID);
        send_bytes(public_key.data, 32, offset); // pub
        send_secret(secret_key, offset); //sec
        send_bytes(payment_id.data, 8, offset); //id

        finish_and_exchange(offset);
        receive_bytes(payment_id.data, 8);

#ifdef DEBUG_HWDEVICE
        hw::ledger::check8("stealth", "payment_id", payment_id_x.data, payment_id.data);
#endif

        return true;
    }


    bool device_ledger::generate_output_ephemeral_keys(
        const size_t tx_version,
        bool& found_change,
        const cryptonote::account_keys& sender_account_keys,
        const crypto::public_key& txkey_pub,
        const crypto::secret_key& tx_key,
        const cryptonote::tx_destination_entry& dst_entr,
        const std::optional<cryptonote::tx_destination_entry>& change_addr,
        const size_t output_index,
        const bool need_additional_txkeys,
        const std::vector<crypto::secret_key>& additional_tx_keys,
        std::vector<crypto::public_key>& additional_tx_public_keys,
        std::vector<rct::key>& amount_keys,
        crypto::public_key& out_eph_public_key) {

      auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
      cryptonote::account_keys sender_account_keys_x = hw::ledger::decrypt(sender_account_keys);
      std::memmove(sender_account_keys_x.m_view_secret_key.data, dbg_viewkey.data, 32);

      const crypto::secret_key tx_key_x = hw::ledger::decrypt(tx_key);

      std::vector<crypto::secret_key> additional_tx_keys_x;
      for (const auto& k: additional_tx_keys) {
        additional_tx_keys_x.push_back(hw::ledger::decrypt(k));
      }

      log_message("generate_output_ephemeral_keys: [[IN]] tx_version", std::to_string(tx_version));
      //log_hexbuffer("generate_output_ephemeral_keys: [[IN]] sender_account_keys.view", sender_account_keys.m_sview_secret_key.data, 32);
      //log_hexbuffer("generate_output_ephemeral_keys: [[IN]] sender_account_keys.spend", sender_account_keys.m_spend_secret_key.data, 32);
      log_hexbuffer("generate_output_ephemeral_keys: [[IN]] txkey_pub", txkey_pub.data, 32);
      log_hexbuffer("generate_output_ephemeral_keys: [[IN]] tx_key", tx_key_x.data, 32);
      log_hexbuffer("generate_output_ephemeral_keys: [[IN]] dst_entr.view", dst_entr.addr.m_view_public_key.data, 32);
      log_hexbuffer("generate_output_ephemeral_keys: [[IN]] dst_entr.spend", dst_entr.addr.m_spend_public_key.data, 32);
      if (change_addr) {
        log_hexbuffer("generate_output_ephemeral_keys: [[IN]] change_addr.view", change_addr->addr.m_view_public_key.data, 32);
        log_hexbuffer("generate_output_ephemeral_keys: [[IN]] change_addr.spend", change_addr->addr.m_spend_public_key.data, 32);
      }
      log_message("generate_output_ephemeral_keys: [[IN]] output_index",  std::to_string(output_index));
      log_message("generate_output_ephemeral_keys: [[IN]] need_additional_txkeys",  std::to_string(need_additional_txkeys));
      if (need_additional_txkeys) {
        log_hexbuffer("generate_output_ephemeral_keys: [[IN]] additional_tx_keys[oi]", additional_tx_keys_x[output_index].data, 32);
      }
      std::vector<crypto::public_key> additional_tx_public_keys_x;
      std::vector<rct::key> amount_keys_x;
      crypto::public_key out_eph_public_key_x;
      debug_device->generate_output_ephemeral_keys(tx_version, found_change, sender_account_keys_x, txkey_pub, tx_key_x, dst_entr, change_addr, output_index, need_additional_txkeys,  additional_tx_keys_x,
          additional_tx_public_keys_x, amount_keys_x, out_eph_public_key_x);
      if(need_additional_txkeys) {
        log_hexbuffer("additional_tx_public_keys_x: [[OUT]] additional_tx_public_keys_x", additional_tx_public_keys_x.back().data, 32);
      }
      log_hexbuffer("generate_output_ephemeral_keys: [[OUT]] amount_keys ", amount_keys_x.back().bytes, 32);
      log_hexbuffer("generate_output_ephemeral_keys: [[OUT]] out_eph_public_key ", out_eph_public_key_x.data, 32);
#endif

      CHECK_AND_ASSERT_THROW_MES(tx_version > 1, "TX version not supported"<<tx_version);

      // make additional tx pubkey if necessary
      cryptonote::keypair additional_txkey;
      if (need_additional_txkeys) {
          additional_txkey.sec = additional_tx_keys[output_index];
      }

      bool &is_change = found_change; // NOTE(oxen): Alias our param into theirs so we don't have to change much code.

      if (change_addr && dst_entr == *change_addr && !is_change)
        is_change = true; // sending change to yourself; derivation = a*R

      int offset = set_command_header_noopt(INS_GEN_TXOUT_KEYS);
      send_u32(tx_version, offset); //tx_version
      send_secret(tx_key, offset); //tx_key
      send_bytes(txkey_pub.data, 32, offset); //txkey_pub
      send_bytes(dst_entr.addr.m_view_public_key.data, 32, offset); //Aout
      send_bytes(dst_entr.addr.m_spend_public_key.data, 32, offset); //Bout
      send_u32(output_index, offset); //output index
      buffer_send[offset++] = is_change; //is_change
      buffer_send[offset++] = dst_entr.is_subaddress; //is_subaddress
      buffer_send[offset++] = need_additional_txkeys; //need_additional_key
      //additional_tx_key
      if (need_additional_txkeys)
        send_secret(additional_txkey.sec, offset);

      finish_and_exchange(offset);

      offset = 0;
      unsigned int recv_len = length_recv;

      //if (tx_version > 1)
      {
        CHECK_AND_ASSERT_THROW_MES(recv_len>=32, "Not enough data from device");
        crypto::secret_key scalar1;
        receive_secret(scalar1, offset);
        amount_keys.push_back(rct::sk2rct(scalar1));
        recv_len -= 32;
      }
      CHECK_AND_ASSERT_THROW_MES(recv_len>=32, "Not enough data from device");
      receive_bytes(out_eph_public_key.data, 32, offset);
      recv_len -= 32;

      if (need_additional_txkeys)
      {
        CHECK_AND_ASSERT_THROW_MES(recv_len>=32, "Not enough data from device");
        receive_bytes(additional_txkey.pub.data, 32, offset);
        additional_tx_public_keys.push_back(additional_txkey.pub);
        recv_len -= 32;
      }

      // add ABPkeys
      add_output_key_mapping(dst_entr.addr.m_view_public_key, dst_entr.addr.m_spend_public_key, dst_entr.is_subaddress, is_change,
                             need_additional_txkeys, output_index,
                             amount_keys.back(), out_eph_public_key);

#ifdef DEBUG_HWDEVICE
      rct::key amount_back = hw::ledger::decrypt(amount_keys.back());
      log_hexbuffer("generate_output_ephemeral_keys: clear amount_key", amount_back.bytes, 32);
      hw::ledger::check32("generate_output_ephemeral_keys", "amount_key", amount_keys_x.back().bytes, amount_back.bytes);
      if (need_additional_txkeys) {
        hw::ledger::check32("generate_output_ephemeral_keys", "additional_tx_key", additional_tx_public_keys_x.back().data, additional_tx_public_keys.back().data);
      }
      hw::ledger::check32("generate_output_ephemeral_keys", "out_eph_public_key", out_eph_public_key_x.data, out_eph_public_key.data);
#endif

      return true;
    }

    bool  device_ledger::add_output_key_mapping(const crypto::public_key &Aout, const crypto::public_key &Bout, const bool is_subaddress, const bool is_change,
                                                const bool need_additional, const size_t real_output_index,
                                                const rct::key &amount_key,  const crypto::public_key &out_eph_public_key)  {
        key_map.add(ABPkeys(rct::pk2rct(Aout),rct::pk2rct(Bout), is_subaddress, is_change, need_additional, real_output_index, rct::pk2rct(out_eph_public_key), amount_key));
        return true;
    }

    rct::key device_ledger::genCommitmentMask(const rct::key &AKout) {
#ifdef DEBUG_HWDEVICE
        rct::key mask_x = debug_device->genCommitmentMask(hw::ledger::decrypt(AKout));
#endif

        rct::key mask;
        int offset = set_command_header_noopt(INS_GEN_COMMITMENT_MASK);
        // AKout
        send_secret(AKout, offset);

        finish_and_exchange(offset);

        receive_bytes(mask.bytes, 32);

#ifdef DEBUG_HWDEVICE
        hw::ledger::check32("genCommitmentMask", "mask", mask_x.bytes, mask.bytes);
#endif

        return mask;
    }

    bool  device_ledger::ecdhEncode(rct::ecdhTuple& unmasked, const rct::key& AKout, bool short_amount) {
        auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
        const rct::key AKout_x = hw::ledger::decrypt(AKout);
        rct::ecdhTuple unmasked_x = unmasked;
        debug_device->ecdhEncode(unmasked_x, AKout_x, short_amount);
#endif

        int offset = set_command_header(INS_BLIND);
        buffer_send[offset++] = short_amount ? 0x02 : 0x00; //options
        send_secret(AKout, offset); // AKout
        send_bytes(unmasked.mask.bytes, 32, offset); //mask k
        send_bytes(unmasked.amount.bytes, 32, offset); //value v

        finish_and_exchange(offset);

        offset = 0;
        receive_bytes(unmasked.amount.bytes, 32, offset);
        receive_bytes(unmasked.mask.bytes, 32, offset);

#ifdef DEBUG_HWDEVICE
        MDEBUG("ecdhEncode: Akout: "<<AKout_x);
        hw::ledger::check32("ecdhEncode", "amount", unmasked_x.amount.bytes, unmasked.amount.bytes);
        hw::ledger::check32("ecdhEncode", "mask", unmasked_x.mask.bytes, unmasked.mask.bytes);

        log_hexbuffer("Blind AKV input", &buffer_recv[64], 3*32);
#endif

        return true;
    }

    bool  device_ledger::ecdhDecode(rct::ecdhTuple& masked, const rct::key& AKout, bool short_amount) {
        auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
        const rct::key AKout_x =   hw::ledger::decrypt(AKout);
        rct::ecdhTuple masked_x = masked;
        debug_device->ecdhDecode(masked_x, AKout_x, short_amount);
#endif

        int offset = set_command_header(INS_UNBLIND);
        buffer_send[offset++] = short_amount ? 0x02 : 0x00; //options
        send_secret(AKout, offset); // AKout
        send_bytes(masked.mask.bytes, 32, offset); //mask k
        send_bytes(masked.amount.bytes, 32, offset); //value v

        finish_and_exchange(offset);

        offset = 0;
        receive_bytes(masked.amount.bytes, 32, offset);
        receive_bytes(masked.mask.bytes, 32, offset);

#ifdef DEBUG_HWDEVICE
        MDEBUG("ecdhEncode: Akout: "<<AKout_x);
        hw::ledger::check32("ecdhDecode", "amount", masked_x.amount.bytes, masked.amount.bytes);
        hw::ledger::check32("ecdhDecode", "mask", masked_x.mask.bytes, masked.mask.bytes);
#endif

        return true;
    }

    bool device_ledger::clsag_prehash(const std::string &data, size_t inputs_size, size_t outputs_size,
                                     const std::array<rct::key, 3>& hashes, const rct::ctkeyV &outPk,
                                     rct::key &prehash) {
        auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
        rct::key prehash_x;
        debug_device->clsag_prehash(data, inputs_size, outputs_size, hashes, outPk, prehash_x);
        if (inputs_size) {
          log_message("clsag_prehash", (std::string("inputs_size not null: ") +  std::to_string(inputs_size)).c_str());
        }
        key_map.log();
#endif

        // ======  u8 type, varint txnfee ======
        int offset = set_command_header(INS_VALIDATE, 0x01, 0x01);
        //options
        buffer_send[offset++] = (inputs_size == 0) ? 0x00 : OPTION_MORE_DATA;

        buffer_send[offset++] = data[0];

        // txnfee
        size_t data_offset = 1;
        while (data[data_offset] & 0x80)
          buffer_send[offset++] = data[data_offset++];
        buffer_send[offset++] = data[data_offset++];

        // check fee user input
        CHECK_AND_ASSERT_THROW_MES(finish_and_exchange(offset, true) == SW_OK, "Fee denied on device.");

        auto type = static_cast<rct::RCTType>(data[0]);
        CHECK_AND_ASSERT_THROW_MES(type == rct::RCTType::CLSAG, "non-CLSAG generation not supported");

        // ======  Aout, Bout, AKout, C, v, k ======
        size_t kv_offset = data_offset;
        size_t C_offset = kv_offset + 8 * outputs_size;
        for (size_t i = 0; i < outputs_size; i++) {
          ABPkeys outKeys;
          bool found;

          found = key_map.find(outPk[i].dest, outKeys);
          if (!found) {
            log_hexbuffer("Pout not found", outPk[i].dest.bytes, 32);
            CHECK_AND_ASSERT_THROW_MES(found, "Pout not found");
          }
          offset = set_command_header(INS_VALIDATE, 0x02, i+1);
          // options
          buffer_send[offset++] = (i < outputs_size-1 ? OPTION_MORE_DATA : 0) | 0x02;

          buffer_send[offset++] = outKeys.is_subaddress; //is_subaddress
          buffer_send[offset++] = outKeys.is_change_address; //is_change_address
          send_bytes(outKeys.Aout.bytes, 32, offset); //Aout
          send_bytes(outKeys.Bout.bytes, 32, offset); //Bout
          send_secret(outKeys.AKout, offset); //AKout
          send_bytes(&data[C_offset], 32, offset); //C
          C_offset += 32;
          send_bytes(crypto::hash::null.data, 32, offset); // k
          send_bytes(&data[kv_offset], 8, offset); // v
          kv_offset += 8;
          send_bytes(crypto::hash::null.data, 24, offset); // v padding

          // check transaction user input
          CHECK_AND_ASSERT_THROW_MES(finish_and_exchange(offset, true) == SW_OK, "Transaction denied on device.");
#ifdef DEBUG_HWDEVICE
          log_hexbuffer("Prehash AKV input", &buffer_recv[64], 3*32);
#endif
        }

        // ======   C[], message, proof======
        C_offset = kv_offset;
        for (size_t i = 0; i < outputs_size; i++) {
          offset = set_command_header(INS_VALIDATE, 0x03, i+1);
          buffer_send[offset++] = 0x80; //options
          send_bytes(&data[C_offset], 32, offset); //C
          C_offset += 32;

          finish_and_exchange(offset);
        }

        offset = set_command_header_noopt(INS_VALIDATE, 0x03, outputs_size+1);
        send_bytes(hashes[0].bytes, 32, offset); //message
        send_bytes(hashes[2].bytes, 32, offset); //proof

        finish_and_exchange(offset);

        receive_bytes(prehash.bytes, 32);

#ifdef DEBUG_HWDEVICE
        hw::ledger::check32("clsag_prehash", "prehash", prehash_x.bytes, prehash.bytes);
#endif

        return true;
    }

    bool device_ledger::clsag_prepare(const rct::key &p, const rct::key &z, rct::key &I, rct::key &D, const rct::key &H, rct::key &a, rct::key &aG, rct::key &aH) {
        auto locks = tools::unique_locks(device_locker, command_locker);
#ifdef DEBUG_HWDEVICE
        const rct::key p_x   = hw::ledger::decrypt(p);
        rct::key       I_x;
        rct::key       D_x;
        rct::key       a_x;
        rct::key       aG_x;
        rct::key       aH_x;
        hw::get_device("default").clsag_prepare(p_x, z, I_x, D_x, H, a_x, aG_x, aH_x);
#endif

        /*
        rct::skpkGen(a,aG); // aG = a*G
        rct::scalarmultKey(aH,H,a); // aH = a*H
        rct::scalarmultKey(I,H,p); // I = p*H
        rct::scalarmultKey(D,H,z); // D = z*H
        */
        int offset = set_command_header_noopt(INS_CLSAG, 1);
        send_secret(p, offset); //p
        send_bytes(z.bytes, 32, offset); //z
        send_bytes(H.bytes, 32, offset); //H

        finish_and_exchange(offset);

        offset = 0;
        receive_secret(a, offset); //a
        receive_bytes(aG.bytes, 32, offset); //aG
        receive_bytes(aH.bytes, 32, offset); //aH
        receive_bytes(I.bytes, 32, offset); //I = pH
        receive_bytes(D.bytes, 32, offset); //D = zH

#ifdef DEBUG_HWDEVICE
        hw::ledger::check32("clsag_prepare", "I", I_x.bytes, I.bytes);
        hw::ledger::check32("clsag_prepare", "D", D_x.bytes, D.bytes);
        hw::ledger::check32("clsag_prepare", "a", a_x.bytes, a.bytes);
        hw::ledger::check32("clsag_prepare", "aG", aG_x.bytes, aG.bytes);
        hw::ledger::check32("clsag_prepare", "aH", aH_x.bytes, aH.bytes);
#endif

        return true;
    }

    bool device_ledger::clsag_hash(const rct::keyV &keydata, rct::key &hash) {
        auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
        rct::key hash_x;
        debug_device->clsag_hash(keydata, hash_x);
#endif

        std::string_view data{reinterpret_cast<const char*>(keydata.data()), sizeof(rct::key)*keydata.size()};
        exchange_multipart_data(INS_CLSAG, 2, data, KECCAK_HASH_CHUNK_SIZE);

        //c/hash
        receive_bytes(hash.bytes, 32);

#ifdef DEBUG_HWDEVICE
        hw::ledger::check32("clsag_hash", "hash", hash_x.bytes, hash.bytes);
#endif
        return true;
    }

    bool device_ledger::clsag_sign(const rct::key &c, const rct::key &a, const rct::key &p, const rct::key &z, const rct::key &mu_P, const rct::key &mu_C, rct::key &s) {
        auto locks = tools::unique_locks(device_locker, command_locker);

#ifdef DEBUG_HWDEVICE
        rct::key s_x;
        debug_device->clsag_sign(c, hw::ledger::decrypt(a), hw::ledger::decrypt(p), z, mu_P, mu_C, s_x);
#endif

        /*
        rct::key s0_p_mu_P;
        sc_mul(s0_p_mu_P.bytes,mu_P.bytes,p.bytes);
        rct::key s0_add_z_mu_C;
        sc_muladd(s0_add_z_mu_C.bytes,mu_C.bytes,z.bytes,s0_p_mu_P.bytes);
        sc_mulsub(s.bytes,c.bytes,s0_add_z_mu_C.bytes,a.bytes);
        */

        int offset = set_command_header_noopt(INS_CLSAG, 3);

        send_secret(a, offset); //a
        send_secret(p, offset); //p
        send_bytes(z.bytes, 32, offset); //z
        send_bytes(mu_P.bytes, 32, offset); //mu_P
        send_bytes(mu_C.bytes, 32, offset); //mu_C

        finish_and_exchange(offset);

        receive_bytes(s.bytes, 32); //s

#ifdef DEBUG_HWDEVICE
        hw::ledger::check32("clsag_sign", "s", s_x.bytes, s.bytes);
#endif

        return true;
    }

    bool device_ledger::update_staking_tx_secret_key(crypto::secret_key& key) {
        auto locks = tools::unique_locks(device_locker, command_locker);

        // This will fail if this isn't an open stake tx.
        send_simple(INS_GET_TX_SECRET_KEY);
        // The ledger provides us with the (unencrypted) tx secret key if we're allowed to have it
        receive_bytes(key.data, 32);

        return true;
    }

    bool device_ledger::close_tx() {
        auto locks = tools::unique_locks(device_locker, command_locker);
        send_simple(INS_CLOSE_TX);
        key_map.clear();
        hmac_map.clear();
        tx_in_progress = false;
        unlock();
        return true;
    }

    /* ---------------------------------------------------------- */

    static device_ledger *legder_device = NULL;
    void register_all(std::map<std::string, std::unique_ptr<device>> &registry) {
      if (!legder_device) {
        legder_device = new device_ledger();
        legder_device->set_name("Ledger");
      }
      registry.insert(std::make_pair("Ledger", std::unique_ptr<device>(legder_device)));
    }

  #else //WITH_DEVICE_LEDGER

    void register_all(std::map<std::string, std::unique_ptr<device>> &registry) {
    }

  #endif //WITH_DEVICE_LEDGER

  }
}

