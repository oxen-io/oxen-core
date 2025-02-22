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

#if defined(HAVE_HIDAPI)

#include <hidapi/hidapi.h>

#include <optional>
#include <vector>

#include "io_device.hpp"

#pragma once

namespace hw::io {

/** HID class base. Commands are formated as follow:
 *
 * |----------------------------------------------------------|
 * |  2 bytes  |  1 byte  |  2 bytes  | 2 bytes  |  len bytes |
 * |-----------|----------|-----------|----------|------------|
 * |  channel  |    tag   |  sequence |   len    |  payload   |
 * |----------------------------------------------------------|
 */

struct hid_conn_params {
    unsigned int vid;
    unsigned int pid;
    int interface_number;
    unsigned short usage_page;
};

class hid : public device {

    unsigned short channel = 0x0001;
    unsigned char tag = 0x01;
    unsigned int packet_size = 64;
    unsigned int timeout = 120000;

    unsigned int usb_vid = 0;
    unsigned int usb_pid = 0;
    hid_device* usb_device = nullptr;

    void io_hid_log(int read, unsigned char* buf, int buf_len);
    void io_hid_init();
    void io_hid_exit();
    void io_hid_open(int vid, int pid, int mode);
    void io_hid_close();

    unsigned int wrapCommand(
            const unsigned char* command, size_t command_len, unsigned char* out, size_t out_len);
    unsigned int unwrapReponse(
            const unsigned char* data, size_t data_len, unsigned char* out, size_t out_len);

    hid_device_info* find_device(
            hid_device_info* devices_list,
            std::optional<int> interface_number,
            std::optional<unsigned short> usage_page);

  public:
    bool hid_verbose = false;

    hid(unsigned short channel, unsigned char tag, unsigned int packet_zize, unsigned int timeout);
    hid() = default;

    void init() override;
    void connect(const std::vector<hid_conn_params>& conn);
    bool connect(
            unsigned int vid,
            unsigned int pid,
            std::optional<int> interface_number,
            std::optional<unsigned short> usage_page);
    bool connected() const override;
    int exchange(
            const unsigned char* command,
            unsigned int cmd_len,
            unsigned char* response,
            unsigned int max_resp_len,
            bool user_input) override;
    void disconnect() override;
    void release() override;
};
}  // namespace hw::io

#endif  // #if defined(HAVE_HIDAPI)
