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
  message_store.cpp
  message_transporter.cpp
  transfer_view.cpp
)

target_link_libraries(wallet
  PUBLIC
    multisig
    rpc_commands
    rpc_args
    cryptonote_core
    mnemonics
    device_trezor
    net
    lmdb
    Boost::serialization
    Boost::filesystem
    Boost::thread
  PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    extra)

loki_add_executable(wallet_rpc_server "loki-wallet-rpc"
  wallet_rpc_server.cpp
  )

target_link_libraries(wallet_rpc_server
  PRIVATE
    wallet
    daemonizer
    Boost::program_options
    extra)


function(combine_archives output_archive)
    set(mri_file ${CMAKE_CURRENT_BINARY_DIR}/${output_archive}.mri)
    set(FULL_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}/lib${output_archive}.a)
    set(mri_content "create ${FULL_OUTPUT_PATH}\n")
    FOREACH(in_archive ${ARGN})
        string(APPEND mri_content "addlib $<TARGET_FILE:${in_archive}>\n")
    ENDFOREACH()
    string(APPEND mri_content "save\nend\n")
    file(GENERATE OUTPUT ${mri_file} CONTENT "${mri_content}")

    set(output_archive_dummy_file ${CMAKE_CURRENT_BINARY_DIR}/${output_archive}.dummy.cpp)
    add_custom_command(OUTPUT ${output_archive_dummy_file}
                       COMMAND touch ${output_archive_dummy_file}
                       DEPENDS ${ARGN})

    add_library(${output_archive} STATIC ${output_archive_dummy_file})
    add_custom_command(TARGET ${output_archive}
                       POST_BUILD
                       COMMAND ar -M < ${mri_file})
endfunction(combine_archives)

# build and install libwallet_merged only if we building for GUI
if (BUILD_GUI_DEPS AND STATIC)
    combine_archives(wallet_merged
            wallet_api
            wallet
            multisig
            cryptonote_core
            cryptonote_basic
            mnemonics
            common
            cncrypto
            device
            ringct
            ringct_basic
            checkpoints
            version
            net
            device_trezor)

    if(IOS)
        set(lib_folder lib-${ARCH})
    else()
        set(lib_folder lib)
    endif()
    install(TARGETS wallet_merged
        ARCHIVE DESTINATION ${lib_folder})

    install(FILES ${TREZOR_DEP_LIBS}
            DESTINATION ${lib_folder})
    file(WRITE "trezor_link_flags.txt" ${TREZOR_DEP_LINKER})
    install(FILES "trezor_link_flags.txt"
            DESTINATION ${lib_folder})
endif()

add_subdirectory(api)
