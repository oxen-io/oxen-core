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


# We always compile if we are building statically to reduce static dependency issues...
# ...except for FreeBSD, because FreeBSD is a special case that doesn't play well with
# others.

if(NOT STATIC AND NOT BUILD_STATIC_DEPS)
  find_package(PkgConfig REQUIRED)
endif()

macro(system_or_submodule BIGNAME smallname pkgconf subdir)
  option(FORCE_${BIGNAME}_SUBMODULE "force using ${smallname} submodule" OFF)
  if(NOT STATIC AND NOT FORCE_${BIGNAME}_SUBMODULE)
    pkg_check_modules(${BIGNAME} ${pkgconf} IMPORTED_TARGET)
  endif()
  if(${BIGNAME}_FOUND)
    add_library(${smallname} INTERFACE)
    if(NOT TARGET PkgConfig::${BIGNAME} AND CMAKE_VERSION VERSION_LESS "3.21")
      # Work around cmake bug 22180 (PkgConfig::THING not set if no flags needed)
    else()
      target_link_libraries(${smallname} INTERFACE PkgConfig::${BIGNAME})
    endif()
    message(STATUS "Found system ${smallname} ${${BIGNAME}_VERSION}")
  else()
    message(STATUS "using ${smallname} submodule")
    add_subdirectory(${subdir})
  endif()
  if(NOT TARGET ${smallname}::${smallname})
    add_library(${smallname}::${smallname} ALIAS ${smallname})
  endif()
endmacro()

system_or_submodule(OXENC oxenc liboxenc>=1.0.10 oxen-encoding)
system_or_submodule(OXENMQ oxenmq liboxenmq>=1.2.12 oxen-mq)
system_or_submodule(FMT fmt fmt>=8.0.0 fmt)

add_subdirectory(db_drivers)
add_subdirectory(easylogging++ easyloggingpp)
add_subdirectory(randomx EXCLUDE_FROM_ALL)

# uSockets doesn't really have a proper build system (just a very simple Makefile) so build it
# ourselves.
if (NOT CMAKE_VERSION VERSION_LESS 3.12)
    set(conf_depends "CONFIGURE_DEPENDS")
else()
    set(conf_depends "")
endif()
file(GLOB usockets_src ${conf_depends} uWebSockets/uSockets/src/*.c uWebSockets/uSockets/src/eventing/*.c)
file(COPY uWebSockets/uSockets/src/libusockets.h DESTINATION uWebSockets)
add_library(uSockets STATIC EXCLUDE_FROM_ALL ${usockets_src})
target_compile_definitions(uSockets PRIVATE LIBUS_NO_SSL=1)
target_include_directories(uSockets PRIVATE uWebSockets/uSockets/src)

# On Windows uSockets uses libuv for its event loop; on Mac kqueue is the default, but that seems to
# not be reliable on older macos versions (like 10.12), so we use libuv on macos as well.
if (WIN32 OR (APPLE AND NOT IOS))
  add_subdirectory(libuv EXCLUDE_FROM_ALL)
  target_link_libraries(uSockets uv_a)
  target_compile_definitions(uSockets PUBLIC LIBUS_USE_LIBUV)
endif()


# The uWebSockets C++ layer is header-only but isn't actually prefixed in the repository itself, but
# rather only on install (which, as above, is just a very simple Makefile).  This is unfortunate
# because it means that we can't use `#include <uWebSockets/App.h>` directly with the repo; so
# instead we emulate the installation process into the build directory and include it (with the
# prefix) from there.
file(COPY uWebSockets/src/ DESTINATION uWebSockets/uWebSockets FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
add_library(uWebSockets INTERFACE)
target_include_directories(uWebSockets INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/uWebSockets)
target_link_libraries(uWebSockets INTERFACE uSockets)
target_compile_definitions(uWebSockets INTERFACE UWS_HTTPRESPONSE_NO_WRITEMARK UWS_NO_ZLIB)


# cpr configuration.  Ideally we'd just do this via add_subdirectory, but cpr's cmake requires
# 3.15+, and we target lower than that (and this is fairly simple to build).

if(NOT BUILD_STATIC_DEPS)
  find_package(CURL REQUIRED COMPONENTS HTTP HTTPS SSL)

  # CURL::libcurl wasn't added to FindCURL until cmake 3.12, so add it if necessary
  if (CMAKE_VERSION VERSION_LESS 3.12 AND NOT TARGET CURL::libcurl)
    add_library(libcurl UNKNOWN IMPORTED GLOBAL)
    set_target_properties(libcurl PROPERTIES
      IMPORTED_LOCATION ${CURL_LIBRARIES}
      INTERFACE_INCLUDE_DIRECTORIES "${CURL_INCLUDE_DIRS}")
    add_library(CURL_libcurl INTERFACE)
    target_link_libraries(CURL_libcurl INTERFACE libcurl)
    add_library(CURL::libcurl ALIAS CURL_libcurl)
  endif()
endif()

file(GLOB cpr_sources ${conf_depends} cpr/cpr/*.cpp)

add_library(cpr STATIC EXCLUDE_FROM_ALL ${cpr_sources})
target_link_libraries(cpr PUBLIC CURL::libcurl)
target_include_directories(cpr PUBLIC cpr/include)
target_compile_definitions(cpr PUBLIC CPR_CURL_NOSIGNAL)
add_library(cpr::cpr ALIAS cpr)

file(READ cpr/CMakeLists.txt cpr_cmake_head LIMIT 1000)
if(cpr_cmake_head MATCHES "project\\(cpr VERSION ([0-9]+)\.([0-9]+)\.([0-9]+) LANGUAGES CXX\\)")
    set(cpr_VERSION_MAJOR ${CMAKE_MATCH_1})
    set(cpr_VERSION_MINOR ${CMAKE_MATCH_2})
    set(cpr_VERSION_PATCH ${CMAKE_MATCH_3})
    set(cpr_VERSION "${cpr_VERSION_MAJOR}.${cpr_VERSION_MINOR}.${cpr_VERSION_PATCH}")
    set(cpr_VERSION_NUM "(${cpr_VERSION_MAJOR} * 0x10000 + ${cpr_VERSION_MINOR} * 0x100 + ${cpr_VERSION_PATCH})")

    configure_file(cpr/cmake/cprver.h.in "${CMAKE_CURRENT_BINARY_DIR}/cpr_generated_includes/cpr/cprver.h")
    target_include_directories(cpr PUBLIC "${CMAKE_CURRENT_BINARY_DIR}/cpr_generated_includes")
else()
    message(FATAL_ERROR "Could not identify cpr submodule version!")
endif()


# Hack around SQLiteCpp's attempts to locate sqlite3 because we *don't* want to link against the
# system one, but don't download and build the embedded one until build time.  Thankfully it
# actually links against the SQLite::SQLite3 cmake target if it already exists, so all we have to do
# is set that up and circumvent some of the non-target bits of its FindSQLite3.cmake.
set(SQLite3_FOUND TRUE CACHE BOOL "" FORCE)
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/ignored")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/ignored/sqlite3.h" "#define SQLITE_VERSION \"${SQLite3_VERSION}\"")
set(SQLite3_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/ignored" CACHE STRING "" FORCE)
set(SQLite3_LIBRARY "ignored" CACHE STRING "" FORCE)
set(SQLITECPP_INTERNAL_SQLITE OFF CACHE BOOL "don't build SQLiteCpp's internal sqlite3" FORCE)
set(SQLITE_ENABLE_COLUMN_METADATA OFF CACHE BOOL "" FORCE)
set(SQLITECPP_RUN_CPPLINT OFF CACHE BOOL "" FORCE)
set(SQLITECPP_RUN_CPPCHECK OFF CACHE BOOL "" FORCE)
set(SQLITECPP_RUN_DOXYGEN OFF CACHE BOOL "" FORCE)
set(SQLITECPP_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SQLITECPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)

add_subdirectory(SQLiteCpp)
