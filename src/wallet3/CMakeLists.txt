add_library(wallet3
  db/walletdb.cpp
  default_daemon_comms.cpp
  keyring.cpp
  keyring_manager.cpp
  transaction_constructor.cpp
  transaction_scanner.cpp
  pending_transaction.cpp
  output_selection/output_selection.cpp
  decoy_selection/decoy_selection.cpp
  wallet.cpp
  wallet2½.cpp
  rpc/command_parser.cpp
  rpc/request_handler.cpp
  rpc/omq_server.cpp)

target_link_libraries(wallet3
  PUBLIC
    rpc_common
    common
    oxenmq::oxenmq
    oxenc::oxenc
  PRIVATE
    cryptonote_protocol
    cryptonote_basic
    cryptonote_core
    extra
    mnemonics
    logging
    oxen::logging
    SQLiteCpp)

function(combine_archives output_archive)
  set(FULL_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR}/lib${output_archive}.a)

  if(NOT APPLE)
    set(mri_file ${CMAKE_CURRENT_BINARY_DIR}/${output_archive}.mri)
    set(mri_content "create ${FULL_OUTPUT_PATH}\n")
    foreach(in_archive ${ARGN})
        string(APPEND mri_content "addlib $<TARGET_FILE:${in_archive}>\n")
    endforeach()
    string(APPEND mri_content "save\nend\n")
    file(GENERATE OUTPUT ${mri_file} CONTENT "${mri_content}")

    add_custom_command(
        OUTPUT ${FULL_OUTPUT_PATH}
        DEPENDS ${mri_file} ${ARGN}
        COMMAND ar -M < ${mri_file})
  else()
    set(merge_libs)
    foreach(in_archive ${ARGN})
      list(APPEND merge_libs $<TARGET_FILE:${in_archive}>)
    endforeach()
    add_custom_command(
        OUTPUT ${FULL_OUTPUT_PATH}
        DEPENDS ${mri_file} ${ARGN}
        COMMAND /usr/bin/libtool -static -o ${FULL_OUTPUT_PATH} ${merge_libs})
  endif()
  add_custom_target(wallet3_merged DEPENDS ${FULL_OUTPUT_PATH})
endfunction(combine_archives)

if (STATIC AND BUILD_STATIC_DEPS)
    set(optional_targets)
    foreach(maybe_target IN ITEMS libusb_vendor hidapi_libusb)
        if(TARGET ${maybe_target})
            list(APPEND optional_targets ${maybe_target})
        endif()
    endforeach()

    combine_archives(wallet3_merged
            multisig
            cryptonote_core
            cryptonote_basic
            cryptonote_protocol
            sqlitedb
            logging
            wallet3
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
            rpc_common
            rpc_http_client
            rpc_commands

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
            randomx
            uSockets
            cpr
            oxen::logging

            ${optional_targets}
            )

    if(IOS)
        set(lib_folder lib-${ARCH})
    else()
        set(lib_folder lib)
    endif()
endif()
