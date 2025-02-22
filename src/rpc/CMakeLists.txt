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

add_subdirectory(common)

oxen_add_library(rpc_commands
  core_rpc_server_commands_defs.cpp
  core_rpc_server_binary_commands.cpp
  core_rpc_server_command_parser.cpp
  )

oxen_add_library(rpc
  core_rpc_server.cpp
  )

oxen_add_library(daemon_rpc_server
  http_server.cpp
  omq_server.cpp
  )

oxen_add_library(rpc_http_client
    http_client.cpp
    )
target_link_libraries(rpc_commands
  PUBLIC
    rpc_common
    common
    cpr::cpr
  PRIVATE
    cryptonote_protocol
    logging
    extra)

target_link_libraries(rpc
  PUBLIC
    cryptonote_core
    rpc_commands
    rpc_common
    net
    version
  PRIVATE
    cryptonote_protocol
    Boost::thread
    SQLiteCpp
    logging
    extra)

target_link_libraries(daemon_rpc_server
  PRIVATE
    oxenc
    rpc_common
    rpc
    Boost::thread
    SQLiteCpp
    logging
    extra)

target_link_libraries(rpc_http_client
  PUBLIC
    common
    cpr::cpr
  PRIVATE
    logging
    extra)
