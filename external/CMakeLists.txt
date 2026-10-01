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


# oxen::logging, with matching fmt/spdlog targets.  This can't go through sessiondep_or_submodule
# because oxen-logging's public headers expose fmt types, which a system liboxen-logging's .pc file
# doesn't pull in; load.cmake resolves that for us.  It doesn't know about our submodule/static
# options, though, so translate those for it.
option(DEPS_FORCE_liboxen-logging_SUBMODULE "force using liboxen-logging submodule" OFF)
if(BUILD_STATIC_DEPS OR DEPS_FORCE_SUBMODULE OR DEPS_FORCE_liboxen-logging_SUBMODULE)
    set(OXEN_LOGGING_FORCE_SUBMODULES ON)
endif()
include(oxen-logging/cmake/load.cmake)

sessiondep_or_submodule(liboxenc 1.5.0 oxen-encoding oxenc::oxenc)

# 1.3.2 is the first release carrying session-deps' fixed libzmq (a submodule build takes libzmq
# from session-deps itself) and the proxy deadlock fix.
sessiondep_or_submodule(liboxenmq 1.3.2 oxen-mq oxenmq::oxenmq)

add_subdirectory(db_drivers)
add_subdirectory(randomx EXCLUDE_FROM_ALL)
oxen_install_library(randomx)
add_subdirectory(date EXCLUDE_FROM_ALL)

set(BN256_ENABLE_TEST OFF CACHE BOOL "" FORCE)
set(BUILD_DOC OFF CACHE BOOL "" FORCE)
add_subdirectory(bn256 EXCLUDE_FROM_ALL)
oxen_install_library(bn256)

install(
    DIRECTORY boost
    DESTINATION include${OXEN_INSTALL_INCLUDEDIR_SUFFIX}
    COMPONENT development
    FILES_MATCHING PATTERN "*.hpp")

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
target_compile_definitions(uWebSockets INTERFACE UWS_HTTPRESPONSE_NO_WRITEMARK)
session_dep(zlib 1.2)
target_link_libraries(uWebSockets INTERFACE sessiondep::zlib)


# SQLiteCpp is built here directly rather than through its own cmake, which insists on
# find_package(SQLite3) and so can't see a static sqlite3 that won't exist until build time.  Its
# sources are a handful of files with no configuration of their own.
file(GLOB sqlitecpp_sources CONFIGURE_DEPENDS SQLiteCpp/src/*.cpp)
add_library(SQLiteCpp ${sqlitecpp_sources})
target_include_directories(SQLiteCpp PUBLIC SQLiteCpp/include)
target_link_libraries(SQLiteCpp PUBLIC sessiondep::sqlite3)
target_compile_definitions(SQLiteCpp PUBLIC SQLITE_OMIT_LOAD_EXTENSION)
if(WIN32 AND BUILD_SHARED_LIBS)
    target_compile_definitions(SQLiteCpp PUBLIC SQLITECPP_COMPILE_DLL PRIVATE SQLITECPP_DLL_EXPORT)
endif()
oxen_install_library(SQLiteCpp)

add_subdirectory(Catch2)

if(BUILD_PYBIND)
  add_subdirectory(pybind11 EXCLUDE_FROM_ALL)
endif()


set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_MultipleHeaders ON CACHE BOOL "") # Allows multi-header nlohmann use
sessiondep_or_submodule(nlohmann_json 3.7.0 ethyl/external/json nlohmann_json::nlohmann_json)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(default_nlohmann_diags OFF)
else()
    set(default_nlohmann_diags ON)
endif()
option(WITH_NLOHMANN_JSON_DIAGNOSTICS "Enables nlohmann-json extended diagnostic exception info" ${default_nlohmann_diags})
if(WITH_NLOHMANN_JSON_DIAGNOSTICS)
    # JSON_DIAGNOSTICS changes the layout of json values, so it has to reach every user of the
    # headers, whichever of the system library or the submodule they came from.
    get_target_property(nlohmann_json_target nlohmann_json::nlohmann_json ALIASED_TARGET)
    target_compile_definitions(${nlohmann_json_target} INTERFACE JSON_DIAGNOSTICS=1)
endif()


session_dep(libcurl 7)

# cpr is built here directly, which ethyl uses instead of its own copy when the target already
# exists: cpr's cmake would otherwise go looking for curl and an SSL backend with find_package,
# neither of which can see the static builds.  Its SSL backend choice only switches on an
# OpenSSL-specific in-memory CA certificate API we don't use; TLS itself is libcurl's business.
file(GLOB cpr_sources CONFIGURE_DEPENDS ethyl/external/cpr/cpr/*.cpp)
file(READ ethyl/external/cpr/CMakeLists.txt cpr_cmakelists_txt)
if(NOT cpr_cmakelists_txt MATCHES "project\\(cpr VERSION ([0-9]+)\\.([0-9]+)\\.([0-9]+) LANGUAGES CXX\\)")
    message(FATAL_ERROR "Failed to detect cpr version")
endif()
set(cpr_VERSION_MAJOR "${CMAKE_MATCH_1}")
set(cpr_VERSION_MINOR "${CMAKE_MATCH_2}")
set(cpr_VERSION_PATCH "${CMAKE_MATCH_3}")
set(cpr_VERSION "${cpr_VERSION_MAJOR}.${cpr_VERSION_MINOR}.${cpr_VERSION_PATCH}")
set(cpr_VERSION_NUM "(${cpr_VERSION_MAJOR} * 0x10000 + ${cpr_VERSION_MINOR} * 0x100 + ${cpr_VERSION_PATCH})")
configure_file(ethyl/external/cpr/cmake/cprver.h.in "${CMAKE_CURRENT_BINARY_DIR}/cpr-include/cpr/cprver.h")

add_library(cpr ${cpr_sources})
target_link_libraries(cpr PUBLIC sessiondep::libcurl)
target_include_directories(cpr PUBLIC ethyl/external/cpr/include "${CMAKE_CURRENT_BINARY_DIR}/cpr-include")
add_library(cpr::cpr ALIAS cpr)
oxen_install_library(cpr)

set(ethyl_ENABLE_CRYPTO_LIBRARY FALSE CACHE BOOL "" FORCE)
set(ethyl_ENABLE_SIGNER FALSE CACHE BOOL "" FORCE)
set(ethyl_ENABLE_LTO FALSE CACHE BOOL "" FORCE)
add_subdirectory(ethyl EXCLUDE_FROM_ALL)
oxen_install_library(ethyl)


# NOTE: By default cpptrace is configured to make stack-traces using libdwarf.
# On this codebase libdward segfaults trying to handle our stack-traces so we
# switch to a more primitive method, addr2line which does work.
set(CPPTRACE_GET_SYMBOLS_WITH_ADDR2LINE ON CACHE BOOL "")
add_subdirectory(cpptrace EXCLUDE_FROM_ALL)

option(TRACY_ENABLE "Enable the profiler markers to be captured and displayable with the Tracy Profiler" OFF)
if (TRACY_ENABLE)
    add_subdirectory(tracy)
endif()
