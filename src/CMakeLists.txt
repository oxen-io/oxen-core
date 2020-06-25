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
  add_compile_options("${WARNINGS_AS_ERRORS_FLAG}") # applies only to targets that follow
endif()

function (enable_stack_trace target)
  if(STACK_TRACE)
    target_compile_definitions("${target}" PRIVATE STACK_TRACE)
    if (STATIC)
      set_property(TARGET "${target}"
        APPEND PROPERTY LINK_FLAGS "-Wl,--wrap=__cxa_throw")
    endif()
  endif()
endfunction()

set_property(GLOBAL PROPERTY loki_executable_targets "")
function (loki_add_executable target binary)
  add_executable("${target}" ${ARGN})
  target_link_libraries("${target}" PRIVATE extra)
  enable_stack_trace("${target}")
  set_target_properties("${target}" PROPERTIES
    OUTPUT_NAME "${binary}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
  install(TARGETS "${target}" DESTINATION bin)
  get_property(exec_tgt GLOBAL PROPERTY loki_executable_targets)
  list(APPEND exec_tgt "${target}")
  set_property(GLOBAL PROPERTY loki_executable_targets "${exec_tgt}")
endfunction ()

include(Version)
add_library(version ${CMAKE_BINARY_DIR}/version.cpp)
add_dependencies(version genversion)

add_subdirectory(common)
add_subdirectory(crypto)
add_subdirectory(ringct)
add_subdirectory(checkpoints)
add_subdirectory(cryptonote_basic)
add_subdirectory(cryptonote_core)
add_subdirectory(lmdb)
add_subdirectory(multisig)
add_subdirectory(net)
add_subdirectory(mnemonics)
add_subdirectory(wallet)
add_subdirectory(cryptonote_protocol)

if(NOT IOS)
  if (NOT BUILD_INTEGRATION)
    add_subdirectory(gen_multisig)
    add_subdirectory(blockchain_utilities)
  endif()
  add_subdirectory(blockchain_db)
  add_subdirectory(rpc)
  add_subdirectory(serialization)
  add_subdirectory(p2p)
  add_subdirectory(daemonizer)
  add_subdirectory(daemon)
  add_subdirectory(simplewallet)
endif()

# We'll always add, but with EXCLUDE_FROM_ALL if you didn't ask for them (but this lets you do a
# `make cn_deserialize` or whatever from a build dir without needing to reconfigure).
option(BUILD_DEBUG_UTILS "Build debug utils as part of the default build" OFF)
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
