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

add_library(wallet_api
  wallet.cpp
  wallet_manager.cpp
  transaction_info.cpp
  transaction_history.cpp
  pending_transaction.cpp
  utils.cpp
  address_book.cpp
  stake_unlock_result.cpp
  subaddress.cpp
  subaddress_account.cpp
  unsigned_transaction.cpp)

target_link_libraries(wallet_api
  PUBLIC
    wallet
    cryptonote_core
    mnemonics
    lmdb
    Boost::serialization
    filesystem
    Boost::thread
  PRIVATE
    extra)

set_property(TARGET wallet_api PROPERTY EXCLUDE_FROM_ALL TRUE)

if(IOS)
    set(lib_folder lib-${ARCH})
else()
    set(lib_folder lib)
endif()

install(FILES ${wallet_api_headers}
    DESTINATION include/wallet/api)

function(combine_archives output_archive)
  set(FULL_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR}/lib${output_archive}.a)
  set(output_archive_dummy_file ${CMAKE_CURRENT_BINARY_DIR}/${output_archive}.dummy.cpp)
  add_custom_command(OUTPUT ${output_archive_dummy_file}
                     COMMAND touch ${output_archive_dummy_file}
                     DEPENDS ${ARGN})
  add_library(${output_archive} STATIC EXCLUDE_FROM_ALL ${output_archive_dummy_file})

  if(NOT APPLE)
    set(mri_file ${CMAKE_CURRENT_BINARY_DIR}/${output_archive}.mri)
    set(mri_content "create ${FULL_OUTPUT_PATH}\n")
    foreach(in_archive ${ARGN})
        string(APPEND mri_content "addlib $<TARGET_FILE:${in_archive}>\n")
    endforeach()
    string(APPEND mri_content "save\nend\n")
    file(GENERATE OUTPUT ${mri_file} CONTENT "${mri_content}")

    add_custom_command(TARGET ${output_archive}
                       POST_BUILD
                       COMMAND ar -M < ${mri_file})
  else()
    set(merge_libs)
    foreach(in_archive ${ARGN})
      list(APPEND merge_libs $<TARGET_FILE:${in_archive}>)
    endforeach()
    add_custom_command(TARGET ${output_archive}
                       POST_BUILD
                       COMMAND /usr/bin/libtool -static -o ${FULL_OUTPUT_PATH} ${merge_libs})
  endif()
endfunction(combine_archives)

if (STATIC AND BUILD_STATIC_DEPS)
    set(optional_deps)
    if(TARGET protobuf_lite)
      list(APPEND optional_deps protobuf_lite)
    endif()
    if(TARGET device_trezor)
      list(APPEND optional_deps device_trezor)
    endif()

    combine_archives(wallet_merged
            wallet_api
            wallet
            multisig
            cryptonote_core
            cryptonote_basic
            cryptonote_protocol
            sqlitedb
            mnemonics
            common
            cncrypto
            device
            ringct
            ringct_basic
            checkpoints
            version
            net
            epee
            blockchain_db
            rpc_http_client
            rpc_commands

            ${optional_deps}

            # Static deps:
            Boost::program_options Boost::serialization Boost::system Boost::thread
            zlib
            SQLite::SQLite3
            SQLiteCpp
            sodium
            libzmq
            CURL::libcurl
            oxenmq::oxenmq
            lmdb
            easylogging
            randomx
            uSockets
            cpr
            fmt
            )

    if(IOS)
        set(lib_folder lib-${ARCH})
    else()
        set(lib_folder lib)
    endif()
    install(TARGETS wallet_merged
        ARCHIVE DESTINATION ${lib_folder}
        EXCLUDE_FROM_ALL)
endif()
