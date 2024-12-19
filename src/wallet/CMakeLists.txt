# Copyright (c) 2018, The Loki Project
# Copyright (c) 2014-2019, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

add_library(wallet
  wallet2.cpp
  wallet_args.cpp
  ringdb.cpp
  node_rpc_proxy.cpp
  transfer_view.cpp
)

# Unmaintained wallet features, disabled by default
option(ENABLE_LIGHT_WALLET "Enable (unsupported) light wallet support" OFF)
option(ENABLE_WALLET_MMS "Enable (unsupported) monero Multisig Messaging System" OFF)

if (ENABLE_LIGHT_WALLET)
  target_compile_definitions(wallet PUBLIC ENABLE_LIGHT_WALLET)
endif()
if (ENABLE_WALLET_MMS)
  target_compile_definitions(wallet PUBLIC ENABLE_WALLET_MMS)
  target_sources(wallet PRIVATE message_store.cpp message_transporter.cpp)
endif()

target_link_libraries(wallet
  PUBLIC
    multisig
    rpc_commands
    rpc_server_base
    cryptonote_core
    mnemonics
    net
    lmdb
    rpc_http_client
    Boost::serialization
    filesystem
    Boost::thread
  PRIVATE
    extra)

if(TARGET device_trezor)
  target_link_libraries(wallet PUBLIC device_trezor)
endif()

oxen_add_executable(wallet_rpc_server "oxen-wallet-rpc"
  wallet_rpc_server.cpp
  wallet_rpc_server_commands_defs.cpp
  )

target_link_libraries(wallet_rpc_server
  PRIVATE
    rpc_server_base
    wallet
    daemonizer
    Boost::program_options
    extra)


add_subdirectory(api)
