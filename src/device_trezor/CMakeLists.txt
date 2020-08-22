# Copyright (c) 2014-2017, The Monero Project
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

# Protobuf and LibUSB processed by CheckTrezor
if(DEVICE_TREZOR_READY)
    message(STATUS "Trezor support enabled")

    add_library(device_trezor
        trezor/messages_map.cpp
        trezor/protocol.cpp
        trezor/transport.cpp
        device_trezor_base.cpp
        device_trezor.cpp
        trezor/messages/messages.pb.cc
        trezor/messages/messages-common.pb.cc
        trezor/messages/messages-management.pb.cc
        trezor/messages/messages-monero.pb.cc
    )


    if(USE_DEVICE_TREZOR_DEBUG)
        target_sources(device_trezor PRIVATE trezor/debug_link.cpp trezor/messages/messages-debug.pb.cc)
        message(STATUS "Trezor debugging enabled")
    endif()

    target_link_libraries(device_trezor
        PRIVATE
            device
            cncrypto
            ringct_basic
            cryptonote_core
            common
            sodium
            libusb
            protobuf
            cpr::cpr
            extra)

else()
    message(STATUS "Trezor support disabled")
    add_library(device_trezor device_trezor.cpp)
    target_link_libraries(device_trezor PRIVATE cncrypto)
endif()
