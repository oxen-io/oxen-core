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

#include "command_line.h"

#include <boost/program_options/variables_map.hpp>

#include "common/i18n.h"
#include "common/string_util.h"
#include "networks.h"
#ifdef HAVE_READLINE
#include "epee/readline_buffer.h"
#endif
#include <iostream>
#ifdef _WIN32
#include "windows.h"
#endif

namespace command_line {

const arg_flag arg_help{"help", "Produce help message"};
const arg_flag arg_version{"version", "Output version information"};

const arg_flag arg_stagenet{"stagenet", "Run on stagenet."};
const arg_flag arg_testnet{"testnet", "Run on testnet."};
const arg_flag arg_devnet{"devnet", "Run on devnet."};
const arg_flag arg_regtest{"regtest", "Run in regression testing mode (aka \"fakechain\")."};
const arg_flag arg_localdev{"localdev", "Run in local developer test network mode."};

void add_network_args(boost::program_options::options_description& od) {
    add_arg(od, arg_stagenet);
    add_arg(od, arg_testnet);
    add_arg(od, arg_devnet);
    add_arg(od, arg_regtest);
    add_arg(od, arg_localdev);
}

cryptonote::network_type get_network(const boost::program_options::variables_map& vm) {
    auto [stagenet, testnet, devnet, regtest, localdev] =
            get_args(vm, arg_stagenet, arg_testnet, arg_devnet, arg_regtest, arg_localdev);
    using cryptonote::network_type;
    network_type nettype = stagenet ? network_type::STAGENET
                         : testnet  ? network_type::TESTNET
                         : devnet   ? network_type::DEVNET
                         : regtest  ? network_type::FAKECHAIN
                         : localdev ? network_type::LOCALDEV
                                    : network_type::MAINNET;
    if (stagenet + testnet + devnet + regtest + localdev > 1)
        log::error(
                globallogcat,
                "Multiple network options (--stagenet, --testnet, etc.) specified; using {}",
                network_type_to_string(nettype));

    return nettype;
}

// Terminal sizing.
//
// Currently only linux is supported.

#ifdef __linux__

extern "C" {
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
}
std::pair<unsigned, unsigned> terminal_size() {
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) != -1)
        return {w.ws_col, w.ws_row};
    return {0, 0};
}

#else

std::pair<unsigned, unsigned> terminal_size() {
    return {0, 0};
}

#endif

std::pair<unsigned, unsigned> boost_option_sizes() {
    std::pair<unsigned, unsigned> result;

    result.first = std::max(
            terminal_size().first,
            boost::program_options::options_description::m_default_line_length);

    result.second =
            result.first - boost::program_options::options_description::m_default_line_length / 2;

    return result;
}

void clear_screen() {
#ifdef HAVE_READLINE
    rdln::clear_screen();
#else
    std::cout << "\033[2K";    // clear whole line
    std::cout << "\033c";      // clear current screen and scrollback
    std::cout << "\033[2J";    // clear current screen only, scrollback is still around
    std::cout << "\033[3J";    // does nothing, should clear current screen and scrollback
    std::cout << "\033[1;1H";  // move cursor top/left
    std::cout << "\r                                                \r"
              << std::flush;  // erase odd chars if the ANSI codes were printed raw
#ifdef _WIN32
    COORD coord{0, 0};
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleScreenBufferInfo(h, &csbi)) {
        DWORD cbConSize = csbi.dwSize.X * csbi.dwSize.Y, w;
        FillConsoleOutputCharacter(h, (TCHAR)' ', cbConSize, coord, &w);
        if (GetConsoleScreenBufferInfo(h, &csbi))
            FillConsoleOutputAttribute(h, csbi.wAttributes, cbConSize, coord, &w);
        SetConsoleCursorPosition(h, coord);
    }
#endif
#endif
}

bool handle_error_helper(
        const boost::program_options::options_description& desc, std::function<bool()> parser) {
    try {
        return parser();
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse arguments: " << e.what() << std::endl;
        std::cerr << desc << std::endl;
        return false;
    } catch (...) {
        std::cerr << "Failed to parse arguments: unknown exception" << std::endl;
        std::cerr << desc << std::endl;
        return false;
    }
}

}  // namespace command_line
