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
#
# Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

# warnings are cleared only for GCC on Linux
if (NOT (MINGW OR APPLE OR FREEBSD OR OPENBSD OR DRAGONFLY))
  message(STATUS "Setting warnings as errors")
  #add_compile_options("${WARNINGS_AS_ERRORS_FLAG}") # applies only to targets that follow
endif()

add_subdirectory(common)
add_subdirectory(crypto)
add_subdirectory(ringct)
add_subdirectory(checkpoints)
add_subdirectory(cryptonote_basic)
add_subdirectory(cryptonote_core)
add_subdirectory(logging)
add_subdirectory(l2_tracker)
add_subdirectory(bls)
add_subdirectory(multisig)
add_subdirectory(net)
add_subdirectory(mnemonics)
add_subdirectory(wallet)
add_subdirectory(cryptonote_protocol)
add_subdirectory(blockchain_db)
add_subdirectory(rpc)
add_subdirectory(serialization)
add_subdirectory(p2p)
add_subdirectory(daemonizer)
add_subdirectory(daemon)
add_subdirectory(simplewallet)
add_subdirectory(sqlitedb)

add_subdirectory(gen_multisig)
add_subdirectory(blockchain_utilities)

option(BUILD_EVERYTHING "Enable building of all optional components" OFF)

# We'll always add, but with EXCLUDE_FROM_ALL if you didn't ask for them (but this lets you do a
# `make cn_deserialize` or whatever from a build dir without needing to reconfigure).
option(BUILD_DEBUG_UTILS "Build debug utils as part of the default build" ${BUILD_EVERYTHING})
if(BUILD_DEBUG_UTILS)
  message(STATUS "Building debug utilities")
  add_subdirectory(debug_utilities)
else()
  message(STATUS "Not building debug utilities by default")
  add_subdirectory(debug_utilities EXCLUDE_FROM_ALL)
endif()

if(PER_BLOCK_CHECKPOINT)
  add_subdirectory(blocks)
endif()

add_subdirectory(device)
add_subdirectory(device_trezor)


if(OXEN_VERSIONTAG)
  set(VERSIONTAG "${OXEN_VERSIONTAG}")
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.cpp.in" "${CMAKE_CURRENT_BINARY_DIR}/version.cpp")
else()
  set(GIT_INDEX_FILE "${PROJECT_SOURCE_DIR}/.git/index")
  find_package(Git)
  if(EXISTS ${GIT_INDEX_FILE} AND ( GIT_FOUND OR Git_FOUND) )
    message(STATUS "Found Git: ${GIT_EXECUTABLE}")

    set(genversion_args "-DGIT=${GIT_EXECUTABLE}")
    foreach(v oxen_VERSION oxen_VERSION_MAJOR oxen_VERSION_MINOR oxen_VERSION_PATCH OXEN_RELEASE_CODENAME OXEN_RELEASE_SUFFIX)
      list(APPEND genversion_args "-D${v}=${${v}}")
    endforeach()

    add_custom_command(
      OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/version.cpp"
      COMMAND
        "${CMAKE_COMMAND}"
        ${genversion_args}
        "-DSRC=${CMAKE_CURRENT_SOURCE_DIR}/version.cpp.in"
        "-DDEST=${CMAKE_CURRENT_BINARY_DIR}/version.cpp"
        "-P" "${PROJECT_SOURCE_DIR}/cmake/GenVersion.cmake"
      DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/version.cpp.in"
        "${GIT_INDEX_FILE}")
  else()
    message(STATUS "Git was not found! Setting version tag to to nogit")
    set(VERSIONTAG "nogit")
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.cpp.in" "${CMAKE_CURRENT_BINARY_DIR}/version.cpp")
  endif()
endif()

oxen_add_library(version "${CMAKE_CURRENT_BINARY_DIR}/version.cpp")

install(
    DIRECTORY   "${CMAKE_CURRENT_SOURCE_DIR}/"
    DESTINATION "include${OXEN_INSTALL_INCLUDEDIR_SUFFIX}"
    FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
