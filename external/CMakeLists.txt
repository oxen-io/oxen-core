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


# This is broken up into two parts: first we check for miniupnp, compile it if we can't
# find it, and thereafter we check for libunbound, and compile it if we can't find it.
# We always compile if we are building statically to reduce static dependency issues...
# ...except for FreeBSD, because FreeBSD is a special case that doesn't play well with
# others.

find_package(PkgConfig REQUIRED)

if(NOT STATIC)
  pkg_check_modules(MINIUPNPC miniupnpc>=2.1)
  pkg_check_modules(UNBOUND libunbound)
  pkg_check_modules(LOKIMQ liblokimq>=1.1.0)
endif()

if(MINIUPNPC_FOUND)
  message(STATUS "Found miniupnpc")
  link_dep_libs(miniupnpc INTERFACE "${MINIUPNPC_LIBRARY_DIRS}" ${MINIUPNPC_LIBRARIES})
  target_include_directories(miniupnpc INTERFACE ${MINIUPNPC_INCLUDE_DIRS})
else()
  message(STATUS "Using in-tree miniupnpc")
  add_subdirectory(miniupnp/miniupnpc)
  if(MSVC)
    target_compile_options(libminiupnpc-static PRIVATE -wd4244 -wd4267)
  else()
    target_compile_options(libminiupnpc-static PRIVATE -Wno-undef -Wno-unused-result -Wno-unused-value)
  endif()
  if(CMAKE_SYSTEM_NAME MATCHES "NetBSD")
    target_compile_definitions(libminiupnpc-static PRIVATE _NETBSD_SOURCE)
  endif()

  target_link_libraries(miniupnpc INTERFACE libminiupnpc-static)
endif()


if(NOT UNBOUND_FOUND)
  # NOTE: If STATIC is true, CMAKE_FIND_LIBRARY_SUFFIXES has been reordered.
  # unbound has config tests which used OpenSSL libraries, so -ldl may need to
  # be set in this case.
  # The unbound CMakeLists.txt can set it, since it's also needed for the
  # static OpenSSL libraries set up there after with target_link_libraries.
  message(STATUS "Using in-tree unbound")
  if(STATIC AND NOT IOS)
    if(UNIX)
      set(OPENSSL_LIBRARIES "${OPENSSL_LIBRARIES};${CMAKE_DL_LIBS};${CMAKE_THREAD_LIBS_INIT}")
    elseif(MINGW)
      set(OPENSSL_LIBRARIES "${OPENSSL_LIBRARIES};extra")
    endif()
  endif()
  add_subdirectory(unbound)
  target_link_libraries(libunbound INTERFACE unbound)
  target_include_directories(libunbound INTERFACE unbound/libunbound)
else()
  message(STATUS "Found libunbound include (unbound.h) in ${UNBOUND_INCLUDE_DIRS}")
  if(NOT UNBOUND_LIBRARIES)
    message(FATAL_ERROR "Found libunbound includes, but could not find libunbound library. Please make sure you have installed libunbound or libunbound-dev or the equivalent")
  endif()

  link_dep_libs(libunbound INTERFACE "${UNBOUND_LIBRARY_DIRS}" ${UNBOUND_LIBRARIES})
  target_include_directories(libunbound INTERFACE ${UNBOUND_INCLUDE_DIRS})
endif()

if(NOT LOKIMQ_FOUND)
  message(STATUS "Using in-tree lokimq")
  if (DEPENDS)
    # The depends system builds a static libzmq so set up a target loki-mq can use to avoid building
    add_library(libzmq STATIC IMPORTED GLOBAL)
    set_target_properties(libzmq PROPERTIES IMPORTED_LOCATION ${ZMQ_LIBRARIES})
    target_link_libraries(libzmq INTERFACE sodium)
    target_include_directories(libzmq INTERFACE ${ZMQ_INCLUDE_DIRS})
    message(STATUS "${ZMQ_INCLUDE_DIRS} ${ZMQ_LIBRARIES}")
  endif()
  add_subdirectory(loki-mq)
else()
  add_library(lokimq INTERFACE)
  link_dep_libs(lokimq INTERFACE "${LOKIMQ_LIBRARY_DIRS}" ${LOKIMQ_LIBRARIES})
  target_include_directories(lokimq INTERFACE ${LOKIMQ_INCLUDE_DIRS})
  add_library(lokimq::lokimq ALIAS lokimq)
  message(STATUS "Found liblokimq ${LOKIMQ_VERSION}")

  # TODO: Temporary fix for also linking libzmq; this can go when the direct zmq code (for zmq
  # server) gets replaced with lokimq.
  pkg_check_modules(LIBZMQ libzmq)
  if (LIBZMQ_FOUND)
    link_dep_libs(lokimq INTERFACE "${LIBZMQ_LIBRARY_DIRS}" ${LIBZMQ_LIBRARIES})
    target_include_directories(lokimq INTERFACE ${LIBZMQ_INCLUDE_DIRS})
  endif()
endif()

add_subdirectory(db_drivers)
add_subdirectory(easylogging++)
add_subdirectory(randomx EXCLUDE_FROM_ALL)
