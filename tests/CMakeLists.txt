# Copyright (c) 2014-2018, The Monero Project
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

# The docs say this only affects grouping in IDEs
set(folder "tests")
set(TEST_DATA_DIR "${CMAKE_CURRENT_LIST_DIR}/data")

add_subdirectory(../external/googletest gtest EXCLUDE_FROM_ALL)

file(COPY
  data/wallet_testnet.keys
  data/wallet_testnet
  data/outputs
  data/unsigned_loki_tx
  data/signed_loki_tx
  DESTINATION data)

if(NOT CMAKE_VERSION VERSION_LESS 3.12)
  find_package(Python COMPONENTS Interpreter)
else()
  set(Python_ADDITIONAL_VERSIONS 3)
  find_package(PythonInterp)
  set(Python_EXECUTABLE ${PYTHON_EXECUTABLE})
endif()

add_subdirectory(core_tests)
add_subdirectory(fuzz)
add_subdirectory(crypto)
# Still expects to find monero daemon/wallet; disable for now.
#add_subdirectory(functional_tests)
add_subdirectory(performance_tests)
add_subdirectory(core_proxy)
add_subdirectory(unit_tests)
add_subdirectory(difficulty)
add_subdirectory(block_weight)
add_subdirectory(hash)
add_subdirectory(net_load_tests)
add_subdirectory(network_tests)
add_subdirectory(wallet3_tests)
if (ANDROID)
# Currently failed to compile
#  add_subdirectory(libwallet_api_tests)
endif()

if (TREZOR_DEBUG)
  add_subdirectory(trezor)
endif()

# add_subdirectory(daemon_tests)

add_executable(hash-target-tests
  hash-target.cpp)
target_link_libraries(hash-target-tests
  PRIVATE
    cryptonote_core)
set_property(TARGET hash-target-tests
  PROPERTY
    FOLDER "${folder}")

add_test(
  NAME    hash-target
  COMMAND hash-target-tests)

set(enabled_tests
    core_tests
    difficulty
    block_weight
    hash
    performance_tests
    core_proxy
    fuzz
    wallet3_tests
    unit_tests)

add_custom_target(tests DEPENDS ${enabled_tests})
set_property(TARGET tests PROPERTY FOLDER "${folder}")
