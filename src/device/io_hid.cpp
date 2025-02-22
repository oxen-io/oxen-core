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

#include "io_hid.hpp"

#include "common/oxen.h"
#include "log.hpp"

namespace hw::io {

static auto logcat = log::Cat("device.io");

static constexpr size_t MAX_BLOCK = 64;

static std::string safe_hid_error(hid_device* hwdev) {
    if (hwdev) {
        const wchar_t* error_wstr = hid_error(hwdev);
        if (error_wstr == nullptr) {
            return "Unknown error";
        }
        std::mbstate_t state{};
        const size_t len_symbols = std::wcsrtombs(nullptr, &error_wstr, 0, &state);
        if (len_symbols == static_cast<std::size_t>(-1)) {
            return "Failed to convert wide char error";
        }
        std::string error_str(len_symbols + 1, 0);
        std::wcsrtombs(&error_str[0], &error_wstr, error_str.size(), &state);
        return error_str;
    }
    return "NULL device";
}

static std::string safe_hid_path(const hid_device_info* hwdev_info) {
    if (hwdev_info && hwdev_info->path) {
        return hwdev_info->path;
    }
    return "NULL path";
}

hid::hid(unsigned short c, unsigned char t, unsigned int ps, unsigned int to) :
        channel{c}, tag{t}, packet_size{ps}, timeout{to} {}

void hid::io_hid_log(int read, unsigned char* buffer, int block_len) {
    if (hid_verbose)
        log::debug(
                logcat,
                "HID {} : {}",
                (read ? '<' : '>'),
                oxenc::to_hex(buffer, buffer + block_len));
}

void hid::init() {
    int r;
    r = hid_init();
    CHECK_AND_ASSERT_THROW_MES(
            r >= 0, "Unable to init hidapi library. Error {}: {}", r, safe_hid_error(usb_device));
}

void hid::connect(const std::vector<hid_conn_params>& hcp) {
    for (const auto& p : hcp)
        if (connect(p.vid, p.pid, p.interface_number, p.usage_page))
            return;
    CHECK_AND_ASSERT_THROW_MES(
            false, "No device found. (Is the device running with the wallet app opened?)");
}

hid_device_info* hid::find_device(
        hid_device_info* devices_list,
        std::optional<int> interface_number,
        std::optional<unsigned short> usage_page) {
    bool select_any = !interface_number && !usage_page;

    log::debug(
            logcat,
            "Looking for {}{}{}{}",
            (select_any ? "any HID Device" : "HID Device with"),
            (interface_number ? (" interface_number " + std::to_string(*interface_number)) : ""),
            ((interface_number && usage_page) ? " or" : ""),
            (usage_page ? (" usage_page " + std::to_string(*usage_page)) : ""));

    hid_device_info* result = nullptr;
    for (; !result && devices_list; devices_list = devices_list->next) {
        if (select_any ||
            (interface_number && devices_list->interface_number == *interface_number) ||
            (usage_page && devices_list->usage_page == *usage_page))
            result = devices_list;

        log::debug(
                logcat,
                "{} HID Device path {} interface_number {} usage_page {}",
                (result == devices_list ? "SELECTED" : "SKIPPED "),
                safe_hid_path(devices_list),
                devices_list->interface_number,
                devices_list->usage_page);
    }

    return result;
}

bool hid::connect(
        unsigned int vid,
        unsigned int pid,
        std::optional<int> interface_number,
        std::optional<unsigned short> usage_page) {

    disconnect();

    hid_device_info* hwdev_info_list = hid_enumerate(vid, pid);
    if (!hwdev_info_list) {
        log::debug(
                logcat,
                "Unable to enumerate device {}:{}: {}",
                vid,
                pid,
                safe_hid_error(usb_device));
        return false;
    }
    hid_device* hwdev = nullptr;
    if (hid_device_info* device = find_device(hwdev_info_list, interface_number, usage_page)) {
        hwdev = hid_open_path(device->path);
    }
    hid_free_enumeration(hwdev_info_list);
    CHECK_AND_ASSERT_THROW_MES(hwdev, "Unable to open device {}: {}", pid, vid);
    usb_vid = vid;
    usb_pid = pid;
    usb_device = hwdev;
    return hwdev;
}

bool hid::connected() const {
    return usb_device != nullptr;
}

int hid::exchange(
        const unsigned char* command,
        unsigned int cmd_len,
        unsigned char* response,
        unsigned int max_resp_len,
        bool user_input) {
    unsigned char buffer[400];
    unsigned char padding_buffer[MAX_BLOCK + 1];
    unsigned int result;
    int hid_ret;
    unsigned int sw_offset;
    unsigned int remaining;
    unsigned int offset = 0;

    CHECK_AND_ASSERT_THROW_MES(usb_device, "No device opened");

    // Split command in several HID packet
    memset(buffer, 0, sizeof(buffer));
    result = wrapCommand(command, cmd_len, buffer, sizeof(buffer));
    remaining = result;

    while (remaining > 0) {
        int block_size = (remaining > MAX_BLOCK ? MAX_BLOCK : remaining);
        memset(padding_buffer, 0, sizeof(padding_buffer));
        memcpy(padding_buffer + 1, buffer + offset, block_size);
        io_hid_log(0, padding_buffer, block_size + 1);
        hid_ret = hid_write(usb_device, padding_buffer, block_size + 1);
        CHECK_AND_ASSERT_THROW_MES(
                hid_ret >= 0,
                "Unable to send hidapi command. Error {}: {}",
                result,
                safe_hid_error(usb_device));
        offset += block_size;
        remaining -= block_size;
    }

    // get first response
    memset(buffer, 0, sizeof(buffer));
    if (!user_input) {
        hid_ret = hid_read_timeout(usb_device, buffer, MAX_BLOCK, timeout);
    } else {
        hid_ret = hid_read(usb_device, buffer, MAX_BLOCK);
    }
    CHECK_AND_ASSERT_THROW_MES(
            hid_ret >= 0,
            "Unable to read hidapi response. Error {}: {}",
            result,
            safe_hid_error(usb_device));
    result = (unsigned int)hid_ret;
    io_hid_log(1, buffer, result);
    offset = MAX_BLOCK;
    // parse first response and get others if any
    while (true) {
        result = unwrapReponse(buffer, offset, response, max_resp_len);
        if (result != 0) {
            break;
        }
        hid_ret = hid_read_timeout(usb_device, buffer + offset, MAX_BLOCK, timeout);
        CHECK_AND_ASSERT_THROW_MES(
                hid_ret >= 0,
                "Unable to receive hidapi response. Error {}: {}",
                result,
                safe_hid_error(usb_device));
        result = static_cast<unsigned int>(hid_ret);
        io_hid_log(1, buffer + offset, result);
        offset += MAX_BLOCK;
    }
    return result;
}

void hid::disconnect(void) {
    if (usb_device) {
        hid_close(usb_device);
    }
    usb_vid = 0;
    usb_pid = 0;
    usb_device = nullptr;
}

void hid::release() {
    /* Do not exit, as the lib context is global*/
    // hid_exit();
}

unsigned int hid::wrapCommand(
        const unsigned char* command, size_t command_len, unsigned char* out, size_t out_len) {
    unsigned int sequence_idx = 0;
    unsigned int offset = 0;
    unsigned int offset_out = 0;
    unsigned int block_size;

    CHECK_AND_ASSERT_THROW_MES(packet_size >= 3, "Invalid Packet size: {}", packet_size);
    CHECK_AND_ASSERT_THROW_MES(out_len >= 7, "out_len too short: {}", out_len);

    out_len -= 7;
    out[offset_out++] = ((channel >> 8) & 0xff);
    out[offset_out++] = (channel & 0xff);
    out[offset_out++] = tag;
    out[offset_out++] = ((sequence_idx >> 8) & 0xff);
    out[offset_out++] = (sequence_idx & 0xff);
    sequence_idx++;
    out[offset_out++] = ((command_len >> 8) & 0xff);
    out[offset_out++] = (command_len & 0xff);
    block_size = (command_len > packet_size - 7 ? packet_size - 7 : command_len);
    CHECK_AND_ASSERT_THROW_MES(out_len >= block_size, "out_len too short: {}", out_len);
    out_len -= block_size;
    memcpy(out + offset_out, command + offset, block_size);
    offset_out += block_size;
    offset += block_size;
    while (offset != command_len) {
        CHECK_AND_ASSERT_THROW_MES(out_len >= 5, "out_len too short: {}", out_len);
        out_len -= 5;
        out[offset_out++] = ((channel >> 8) & 0xff);
        out[offset_out++] = (channel & 0xff);
        out[offset_out++] = tag;
        out[offset_out++] = ((sequence_idx >> 8) & 0xff);
        out[offset_out++] = (sequence_idx & 0xff);
        sequence_idx++;
        block_size =
                ((command_len - offset) > packet_size - 5 ? packet_size - 5 : command_len - offset);
        CHECK_AND_ASSERT_THROW_MES(out_len >= block_size, "out_len too short: {}", out_len);
        out_len -= block_size;
        memcpy(out + offset_out, command + offset, block_size);
        offset_out += block_size;
        offset += block_size;
    }
    while ((offset_out % packet_size) != 0) {
        CHECK_AND_ASSERT_THROW_MES(out_len >= 1, "out_len too short: {}", out_len);
        out_len--;
        out[offset_out++] = 0;
    }
    return offset_out;
}

/*
 * return  0 if more data are needed
 *         >0 if response is fully available
 */
unsigned int hid::unwrapReponse(
        const unsigned char* data, size_t data_len, unsigned char* out, size_t out_len) {
    unsigned int sequence_idx = 0;
    unsigned int offset = 0;
    unsigned int offset_out = 0;
    unsigned int response_len;
    unsigned int block_size;
    unsigned int val;

    // end?
    if ((data == nullptr) || (data_len < 7 + 5)) {
        return 0;
    }

    // check hid header
    val = (data[offset] << 8) + data[offset + 1];
    offset += 2;
    CHECK_AND_ASSERT_THROW_MES(val == channel, "Wrong Channel");
    val = data[offset];
    offset++;
    CHECK_AND_ASSERT_THROW_MES(val == tag, "Wrong TAG");
    val = (data[offset] << 8) + data[offset + 1];
    offset += 2;
    CHECK_AND_ASSERT_THROW_MES(val == sequence_idx, "Wrong sequence_idx");

    // fetch
    response_len = (data[offset++] << 8);
    response_len |= data[offset++];
    CHECK_AND_ASSERT_THROW_MES(out_len >= response_len, "Out Buffer too short");
    if (data_len < (7 + response_len)) {
        return 0;
    }
    block_size = (response_len > (packet_size - 7) ? packet_size - 7 : response_len);
    memcpy(out + offset_out, data + offset, block_size);
    offset += block_size;
    offset_out += block_size;
    while (offset_out != response_len) {
        sequence_idx++;
        if (offset == data_len) {
            return 0;
        }
        val = (data[offset] << 8) + data[offset + 1];
        offset += 2;
        CHECK_AND_ASSERT_THROW_MES(val == channel, "Wrong Channel");
        val = data[offset];
        offset++;
        CHECK_AND_ASSERT_THROW_MES(val == tag, "Wrong TAG");
        val = (data[offset] << 8) + data[offset + 1];
        offset += 2;
        CHECK_AND_ASSERT_THROW_MES(val == sequence_idx, "Wrong sequence_idx");

        block_size =
                ((response_len - offset_out) > packet_size - 5 ? packet_size - 5
                                                               : response_len - offset_out);
        if (block_size > (data_len - offset)) {
            return 0;
        }
        memcpy(out + offset_out, data + offset, block_size);
        offset += block_size;
        offset_out += block_size;
    }
    return offset_out;
}

}  // namespace hw::io

#endif  // #if defined(HAVE_HIDAPI)
