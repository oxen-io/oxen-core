# Copyright (c) 2018, The Loki Project
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
cmake_minimum_required(VERSION 3.1)

set(CMAKE_C_FLAGS "-Wformat -Wformat-security -fstack-protector -fstack-protector-strong -O2")
set(CMAKE_CXX_FLAGS "-Wformat -Wformat-security -fstack-protector -fstack-protector-strong -O2")
set(CMAKE_EXE_LINKER_FLAGS "-pie")

add_library(sqlite STATIC sqlite3.c)

# https://www.sqlite.org/compile.html#recommended_compile_time_options
target_compile_definitions(sqlite PRIVATE
    SQLITE_THREADSAFE=1 # single threaded
    SQLITE_DEFAULT_MEMSTATUS=0 # no need for runtime performance tracking
    SQLITE_LIKE_DOESNT_MATCH_BLOBS # no need to match blobs
    SQLITE_MAX_EXPR_DEPTH=0 # unlimited expression tree depth
    SQLITE_OMIT_DECLTYPE # no need to query the column's types
    SQLITE_OMIT_DEPRECATED # no need for deprecated stuff
    SQLITE_OMIT_PROGRESS_CALLBACK # no need for progress callback
)

if(UNIX AND NOT APPLE)
    target_compile_options(sqlite PRIVATE "-fPIC")
endif()
