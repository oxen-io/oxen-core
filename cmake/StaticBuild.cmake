# cmake bits to do a full static build, downloading and building all dependencies.

# Most of these are CACHE STRINGs so that you can override them using -DWHATEVER during cmake
# invocation to override.

set(LOCAL_MIRROR "" CACHE STRING "local mirror path/URL for lib downloads")

set(OPENSSL_VERSION 1.1.1k CACHE STRING "openssl version")
set(OPENSSL_MIRROR ${LOCAL_MIRROR} https://www.openssl.org/source CACHE STRING "openssl download mirror(s)")
set(OPENSSL_SOURCE openssl-${OPENSSL_VERSION}.tar.gz)
set(OPENSSL_HASH SHA256=892a0875b9872acd04a9fde79b1f943075d5ea162415de3047c327df33fbaee5
    CACHE STRING "openssl source hash")

set(EXPAT_VERSION 2.3.0 CACHE STRING "expat version")
string(REPLACE "." "_" EXPAT_TAG "R_${EXPAT_VERSION}")
set(EXPAT_MIRROR ${LOCAL_MIRROR} https://github.com/libexpat/libexpat/releases/download/${EXPAT_TAG}
    CACHE STRING "expat download mirror(s)")
set(EXPAT_SOURCE expat-${EXPAT_VERSION}.tar.xz)
set(EXPAT_HASH SHA512=dde8a9a094b18d795a0e86ca4aa68488b352dc67019e0d669e8b910ed149628de4c2a49bc3a5b832f624319336a01f9e4debe03433a43e1c420f36356d886820
    CACHE STRING "expat source hash")

set(UNBOUND_VERSION 1.13.1 CACHE STRING "unbound version")
set(UNBOUND_MIRROR ${LOCAL_MIRROR} https://nlnetlabs.nl/downloads/unbound CACHE STRING "unbound download mirror(s)")
set(UNBOUND_SOURCE unbound-${UNBOUND_VERSION}.tar.gz)
set(UNBOUND_HASH SHA256=8504d97b8fc5bd897345c95d116e0ee0ddf8c8ff99590ab2b4bd13278c9f50b8
    CACHE STRING "unbound source hash")

set(BOOST_VERSION 1.76.0 CACHE STRING "boost version")
set(BOOST_MIRROR ${LOCAL_MIRROR} https://boostorg.jfrog.io/artifactory/main/release/${BOOST_VERSION}/source
    CACHE STRING "boost download mirror(s)")
string(REPLACE "." "_" BOOST_VERSION_ ${BOOST_VERSION})
set(BOOST_SOURCE boost_${BOOST_VERSION_}.tar.bz2)
set(BOOST_HASH SHA256=f0397ba6e982c4450f27bf32a2a83292aba035b827a5623a14636ea583318c41
    CACHE STRING "boost source hash")

set(NCURSES_VERSION 6.2 CACHE STRING "ncurses version")
set(NCURSES_MIRROR ${LOCAL_MIRROR} http://ftpmirror.gnu.org/gnu/ncurses
    CACHE STRING "ncurses download mirror(s)")
set(NCURSES_SOURCE ncurses-${NCURSES_VERSION}.tar.gz)
set(NCURSES_HASH SHA512=4c1333dcc30e858e8a9525d4b9aefb60000cfc727bc4a1062bace06ffc4639ad9f6e54f6bdda0e3a0e5ea14de995f96b52b3327d9ec633608792c99a1e8d840d
    CACHE STRING "ncurses source hash")

set(READLINE_VERSION 8.1 CACHE STRING "readline version")
set(READLINE_MIRROR ${LOCAL_MIRROR} http://ftpmirror.gnu.org/gnu/readline
    CACHE STRING "readline download mirror(s)")
set(READLINE_SOURCE readline-${READLINE_VERSION}.tar.gz)
set(READLINE_HASH SHA512=27790d0461da3093a7fee6e89a51dcab5dc61928ec42e9228ab36493b17220641d5e481ea3d8fee5ee0044c70bf960f55c7d3f1a704cf6b9c42e5c269b797e00
    CACHE STRING "readline source hash")

set(SQLITE3_VERSION 3350500 CACHE STRING "sqlite3 version")
set(SQLITE3_MIRROR ${LOCAL_MIRROR} https://www.sqlite.org/2021
    CACHE STRING "sqlite3 download mirror(s)")
set(SQLITE3_SOURCE sqlite-autoconf-${SQLITE3_VERSION}.tar.gz)
set(SQLITE3_HASH SHA512=039af796f79fc4517be0bd5ba37886264d49da309e234ae6fccdb488ef0109ed2b917fc3e6c1fc7224dff4f736824c653aaf8f0a37550c5ebc14d035cb8ac737
    CACHE STRING "sqlite3 source hash")

set(EUDEV_VERSION 3.2.10 CACHE STRING "eudev version")
set(EUDEV_MIRROR ${LOCAL_MIRROR} https://github.com/gentoo/eudev/archive/
    CACHE STRING "eudev download mirror(s)")
set(EUDEV_SOURCE v${EUDEV_VERSION}.tar.gz)
set(EUDEV_HASH SHA512=37fc5e7f960a843fa68269697882123af4515555788a9e856474f51dd8c330a4c8e52e7c897aeb5d3eb36c6ad66cc99f5a38a284a75620b7e6c275c703e25d42
    CACHE STRING "eudev source hash")

set(LIBUSB_VERSION 1.0.24 CACHE STRING "libusb version")
set(LIBUSB_MIRROR ${LOCAL_MIRROR} https://github.com/libusb/libusb/releases/download/v${LIBUSB_VERSION}
    CACHE STRING "libusb download mirror(s)")
set(LIBUSB_SOURCE libusb-${LIBUSB_VERSION}.tar.bz2)
set(LIBUSB_HASH SHA512=5aea36a530aaa15c6dd656d0ed3ce204522c9946d8d39ffbb290dab4a98cda388a2598da4995123d1032324056090bd429e702459626d3e8d7daeebc4e7ff3dc
    CACHE STRING "libusb source hash")

set(HIDAPI_VERSION 0.9.0 CACHE STRING "hidapi version")
set(HIDAPI_MIRROR ${LOCAL_MIRROR} https://github.com/libusb/hidapi/archive
    CACHE STRING "hidapi download mirror(s)")
set(HIDAPI_SOURCE hidapi-${HIDAPI_VERSION}.tar.gz)
set(HIDAPI_HASH SHA512=d9f28d394b78daece7d2dfb946e62349a56b388b3a06241585c6fad5a4e24dc914723de6c0f12a9e51cd23fb245f6b5ac9b3721319646d5ba5912bbe0a3f9a52
    CACHE STRING "hidapi source hash")

# NB: not currently built, used for (non-functional) trezor code
set(PROTOBUF_VERSION 3.13.0 CACHE STRING "protobuf version")
set(PROTOBUF_MIRROR ${LOCAL_MIRROR} https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOBUF_VERSION}
  CACHE STRING "protobuf mirror(s)")
set(PROTOBUF_SOURCE protobuf-cpp-${PROTOBUF_VERSION}.tar.gz)
set(PROTOBUF_HASH SHA512=89a3d6207d14cc9afbd50a514a7c0f781c0e530bdbbe720e7e2f645301cdf59fb6772d5a95aea4a35ebcb2e17a738d8fdba8314fbc3aa6f34a97427ccf0c7342
  CACHE STRING "protobuf source hash")

set(SODIUM_VERSION 1.0.18 CACHE STRING "libsodium version")
set(SODIUM_MIRROR ${LOCAL_MIRROR}
  https://download.libsodium.org/libsodium/releases
  https://github.com/jedisct1/libsodium/releases/download/${SODIUM_VERSION}-RELEASE
  CACHE STRING "libsodium mirror(s)")
set(SODIUM_SOURCE libsodium-${SODIUM_VERSION}.tar.gz)
set(SODIUM_HASH SHA512=17e8638e46d8f6f7d024fe5559eccf2b8baf23e143fadd472a7d29d228b186d86686a5e6920385fe2020729119a5f12f989c3a782afbd05a8db4819bb18666ef
  CACHE STRING "libsodium source hash")

set(ZMQ_VERSION 4.3.4 CACHE STRING "libzmq version")
set(ZMQ_MIRROR ${LOCAL_MIRROR} https://github.com/zeromq/libzmq/releases/download/v${ZMQ_VERSION}
    CACHE STRING "libzmq mirror(s)")
set(ZMQ_SOURCE zeromq-${ZMQ_VERSION}.tar.gz)
set(ZMQ_HASH SHA512=e198ef9f82d392754caadd547537666d4fba0afd7d027749b3adae450516bcf284d241d4616cad3cb4ad9af8c10373d456de92dc6d115b037941659f141e7c0e
    CACHE STRING "libzmq source hash")

set(ZLIB_VERSION 1.2.11 CACHE STRING "zlib version")
set(ZLIB_MIRROR ${LOCAL_MIRROR} https://zlib.net
    CACHE STRING "zlib mirror(s)")
set(ZLIB_SOURCE zlib-${ZLIB_VERSION}.tar.gz)
set(ZLIB_HASH SHA512=73fd3fff4adeccd4894084c15ddac89890cd10ef105dd5e1835e1e9bbb6a49ff229713bd197d203edfa17c2727700fce65a2a235f07568212d820dca88b528ae
    CACHE STRING "zlib source hash")

set(CURL_VERSION 7.76.1 CACHE STRING "curl version")
set(CURL_MIRROR ${LOCAL_MIRROR} https://curl.haxx.se/download https://curl.askapache.com
  CACHE STRING "curl mirror(s)")
set(CURL_SOURCE curl-${CURL_VERSION}.tar.xz)
set(CURL_HASH SHA256=64bb5288c39f0840c07d077e30d9052e1cbb9fa6c2dc52523824cc859e679145
  CACHE STRING "curl source hash")



include(ExternalProject)

set(DEPS_DESTDIR ${CMAKE_BINARY_DIR}/static-deps)
set(DEPS_SOURCEDIR ${CMAKE_BINARY_DIR}/static-deps-sources)

include_directories(BEFORE SYSTEM ${DEPS_DESTDIR}/include)

file(MAKE_DIRECTORY ${DEPS_DESTDIR}/include)

set(deps_cc "${CMAKE_C_COMPILER}")
set(deps_cxx "${CMAKE_CXX_COMPILER}")
if (ANDROID)
  if(NOT ANDROID_TOOLCHAIN_NAME)
    message(FATAL_ERROR "ANDROID_TOOLCHAIN_NAME not set; did you run with the proper android toolchain options?")
  endif()
  if(CMAKE_ANDROID_ARCH_ABI MATCHES x86_64)
    set(android_clang x86_64-linux-android${ANDROID_PLATFORM_LEVEL}-clang)
    set(openssl_machine x86_64)
  elseif(CMAKE_ANDROID_ARCH_ABI MATCHES x86)
    set(android_clang i686-linux-android${ANDROID_PLATFORM_LEVEL}-clang)
    set(openssl_machine i686)
  elseif(CMAKE_ANDROID_ARCH_ABI MATCHES armeabi-v7a)
    set(android_clang armv7a-linux-androideabi${ANDROID_PLATFORM_LEVEL}-clang)
    set(openssl_machine armv7)
  elseif(CMAKE_ANDROID_ARCH_ABI MATCHES arm64-v8a)
    set(android_clang aarch64-linux-android${ANDROID_PLATFORM_LEVEL}-clang)
    set(openssl_machine aarch64)
  else()
    message(FATAL_ERROR "Don't know how to build for android arch abi ${CMAKE_ANDROID_ARCH_ABI}")
  endif()
  set(deps_cc "${ANDROID_TOOLCHAIN_ROOT}/bin/${android_clang}")
  set(deps_cxx "${deps_cc}++")
endif()

if(CMAKE_C_COMPILER_LAUNCHER)
  set(deps_cc "${CMAKE_C_COMPILER_LAUNCHER} ${deps_cc}")
endif()
if(CMAKE_CXX_COMPILER_LAUNCHER)
  set(deps_cxx "${CMAKE_CXX_COMPILER_LAUNCHER} ${deps_cxx}")
endif()

function(expand_urls output source_file)
  set(expanded)
  foreach(mirror ${ARGN})
    list(APPEND expanded "${mirror}/${source_file}")
  endforeach()
  set(${output} "${expanded}" PARENT_SCOPE)
endfunction()

function(add_static_target target ext_target libname)
  add_library(${target} STATIC IMPORTED GLOBAL)
  add_dependencies(${target} ${ext_target})
  set_target_properties(${target} PROPERTIES
    IMPORTED_LOCATION ${DEPS_DESTDIR}/lib/${libname}
  )
endfunction()



if(USE_LTO)
  set(flto "-flto")
else()
  set(flto "")
endif()

set(cross_host "")
set(cross_extra "")
if (ANDROID)
  set(cross_host "--host=${CMAKE_LIBRARY_ARCHITECTURE}")
  set(cross_extra "LD=${ANDROID_TOOLCHAIN_ROOT}/bin/${CMAKE_LIBRARY_ARCHITECTURE}-ld" "RANLIB=${CMAKE_RANLIB}" "AR=${CMAKE_AR}")
elseif(CMAKE_CROSSCOMPILING)
  if(APPLE)
    set(cross_host "--host=${APPLE_TARGET_TRIPLE}")
  else()
    set(cross_host "--host=${ARCH_TRIPLET}")
    if (ARCH_TRIPLET MATCHES mingw AND CMAKE_RC_COMPILER)
      set(cross_extra "WINDRES=${CMAKE_RC_COMPILER}")
    endif()
  endif()
endif()



set(deps_CFLAGS "-O2 ${flto}")
set(deps_CXXFLAGS "-O2 ${flto}")
set(deps_noarch_CFLAGS "${deps_CFLAGS}")
set(deps_noarch_CXXFLAGS "${deps_CXXFLAGS}")

if(APPLE)
  foreach(lang C CXX)
    string(APPEND deps_${lang}FLAGS " ${CMAKE_${lang}_SYSROOT_FLAG} ${CMAKE_OSX_SYSROOT} ${CMAKE_${lang}_OSX_DEPLOYMENT_TARGET_FLAG}${CMAKE_OSX_DEPLOYMENT_TARGET}")

    set(deps_noarch_${lang}FLAGS "${deps_${lang}FLAGS}")

    foreach(arch ${CMAKE_OSX_ARCHITECTURES})
      string(APPEND deps_${lang}FLAGS " -arch ${arch}")
    endforeach()
  endforeach()
endif()

# Builds a target; takes the target name (e.g. "readline") and builds it in an external project with
# target name suffixed with `_external`.  Its upper-case value is used to get the download details
# (from the variables set above).  The following options are supported and passed through to
# ExternalProject_Add if specified.  If omitted, these defaults are used:
set(build_def_DEPENDS "")
set(build_def_PATCH_COMMAND "")
set(build_def_CONFIGURE_COMMAND ./configure ${cross_host} --disable-shared --prefix=${DEPS_DESTDIR} --with-pic
    "CC=${deps_cc}" "CXX=${deps_cxx}" "CFLAGS=${deps_CFLAGS}" "CXXFLAGS=${deps_CXXFLAGS}" ${cross_extra})
set(build_def_BUILD_COMMAND make)
set(build_def_INSTALL_COMMAND make install)
set(build_def_BUILD_BYPRODUCTS ${DEPS_DESTDIR}/lib/lib___TARGET___.a ${DEPS_DESTDIR}/include/___TARGET___.h)
set(build_dep_TARGET_SUFFIX "")

function(build_external target)
  set(options TARGET_SUFFIX DEPENDS PATCH_COMMAND CONFIGURE_COMMAND BUILD_COMMAND INSTALL_COMMAND BUILD_BYPRODUCTS)
  cmake_parse_arguments(PARSE_ARGV 1 arg "" "" "${options}")
  foreach(o ${options})
    if(NOT DEFINED arg_${o})
      set(arg_${o} ${build_def_${o}})
    endif()
  endforeach()
  string(REPLACE ___TARGET___ ${target} arg_BUILD_BYPRODUCTS "${arg_BUILD_BYPRODUCTS}")

  string(TOUPPER "${target}" prefix)
  expand_urls(urls ${${prefix}_SOURCE} ${${prefix}_MIRROR})
  ExternalProject_Add("${target}${arg_TARGET_SUFFIX}_external"
    DEPENDS ${arg_DEPENDS}
    BUILD_IN_SOURCE ON
    PREFIX ${DEPS_SOURCEDIR}
    URL ${urls}
    URL_HASH ${${prefix}_HASH}
    DOWNLOAD_NO_PROGRESS ON
    PATCH_COMMAND ${arg_PATCH_COMMAND}
    CONFIGURE_COMMAND ${arg_CONFIGURE_COMMAND}
    BUILD_COMMAND ${arg_BUILD_COMMAND}
    INSTALL_COMMAND ${arg_INSTALL_COMMAND}
    BUILD_BYPRODUCTS ${arg_BUILD_BYPRODUCTS}
  )
endfunction()



build_external(zlib
  CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env "CC=${deps_cc}" "CFLAGS=${deps_CFLAGS} -fPIC" ${cross_extra} ./configure --prefix=${DEPS_DESTDIR} --static
  BUILD_BYPRODUCTS
    ${DEPS_DESTDIR}/lib/libz.a
    ${DEPS_DESTDIR}/include/zlib.h
)
add_static_target(zlib zlib_external libz.a)



set(openssl_configure ./config)
set(openssl_system_env "")
set(openssl_cc "${deps_cc}")
if(CMAKE_CROSSCOMPILING)
  if(ARCH_TRIPLET STREQUAL x86_64-w64-mingw32)
    set(openssl_system_env SYSTEM=MINGW64 RC=${CMAKE_RC_COMPILER})
  elseif(ARCH_TRIPLET STREQUAL i686-w64-mingw32)
    set(openssl_system_env SYSTEM=MINGW64 RC=${CMAKE_RC_COMPILER})
  elseif(ANDROID)
    set(openssl_system_env SYSTEM=Linux MACHINE=${openssl_machine} ${cross_extra})
    set(openssl_extra_opts no-asm)
  elseif(IOS)
    get_filename_component(apple_toolchain "${CMAKE_C_COMPILER}" DIRECTORY)
    get_filename_component(apple_sdk "${CMAKE_OSX_SYSROOT}" NAME)
    if(NOT ${apple_toolchain} MATCHES Xcode OR NOT ${apple_sdk} MATCHES "iPhone(OS|Simulator)")
      message(FATAL_ERROR "didn't find your toolchain and sdk correctly from ${CMAKE_C_COMPILER}/${CMAKE_OSX_SYSROOT}: found toolchain=${apple_toolchain}, sdk=${apple_sdk}")
    endif()
    set(openssl_system_env CROSS_COMPILE=${apple_toolchain}/ CROSS_TOP=${CMAKE_DEVELOPER_ROOT} CROSS_SDK=${apple_sdk})
    set(openssl_configure ./Configure iphoneos-cross)
    set(openssl_cc "clang")
  endif()
endif()
build_external(openssl
  CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env CC=${openssl_cc} ${openssl_system_env} ${openssl_configure}
    --prefix=${DEPS_DESTDIR} ${openssl_extra_opts} no-shared no-capieng no-dso no-dtls1 no-ec_nistp_64_gcc_128 no-gost
    no-heartbeats no-md2 no-rc5 no-rdrand no-rfc3779 no-sctp no-ssl-trace no-ssl2 no-ssl3
    no-static-engine no-tests no-weak-ssl-ciphers no-zlib-dynamic "CFLAGS=${deps_CFLAGS}"
  INSTALL_COMMAND make install_sw
  BUILD_BYPRODUCTS
    ${DEPS_DESTDIR}/lib/libssl.a ${DEPS_DESTDIR}/lib/libcrypto.a
    ${DEPS_DESTDIR}/include/openssl/ssl.h ${DEPS_DESTDIR}/include/openssl/crypto.h
)
add_static_target(OpenSSL::SSL openssl_external libssl.a)
add_static_target(OpenSSL::Crypto openssl_external libcrypto.a)
set(OPENSSL_INCLUDE_DIR ${DEPS_DESTDIR}/include)
set(OPENSSL_VERSION 1.1.1)



build_external(expat
  CONFIGURE_COMMAND ./configure ${cross_host} --prefix=${DEPS_DESTDIR} --enable-static
  --disable-shared --with-pic --without-examples --without-tests --without-docbook --without-xmlwf
  "CC=${deps_cc}" "CFLAGS=${deps_CFLAGS}"
)
add_static_target(expat expat_external libexpat.a)


set(unbound_extra)
if(APPLE AND IOS)
  # I have no idea why this is necessary: without this it runs `clang -E` which should work, but
  # doesn't because... hurray ios is wonderful?
  set(unbound_extra CPP=cpp)
endif()
build_external(unbound
  DEPENDS openssl_external expat_external
  CONFIGURE_COMMAND ./configure ${cross_host} ${cross_extra} --prefix=${DEPS_DESTDIR} --disable-shared
  --enable-static --with-libunbound-only --with-pic --disable-gost
  --$<IF:$<BOOL:${USE_LTO}>,enable,disable>-flto --with-ssl=${DEPS_DESTDIR}
  --with-libexpat=${DEPS_DESTDIR}
  "CC=${deps_cc}" "CFLAGS=${deps_CFLAGS}" ${unbound_extra}
)
add_static_target(libunbound unbound_external libunbound.a)
if(WIN32)
  set_target_properties(libunbound PROPERTIES INTERFACE_LINK_LIBRARIES "ws2_32;crypt32;iphlpapi")
endif()



set(boost_threadapi "pthread")
set(boost_bootstrap_cxx "--cxx=${deps_cxx}")
set(boost_toolset "")
set(boost_extra "")
if(USE_LTO)
  list(APPEND boost_extra "lto=on")
endif()
if(CMAKE_CROSSCOMPILING)
  set(boost_bootstrap_cxx "") # need to use our native compiler to bootstrap
  if(ARCH_TRIPLET MATCHES mingw)
    set(boost_threadapi win32)
    list(APPEND boost_extra "target-os=windows")
    if(ARCH_TRIPLET MATCHES x86_64)
      list(APPEND boost_extra "address-model=64")
    else()
      list(APPEND boost_extra "address-model=32")
    endif()
  elseif(ANDROID)
    set(boost_bootstrap_cxx "--cxx=c++")
  endif()
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL GNU)
  set(boost_toolset gcc)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "^(Apple)?Clang$")
  set(boost_toolset clang)
else()
  message(FATAL_ERROR "don't know how to build boost with ${CMAKE_CXX_COMPILER_ID}")
endif()

if(IOS)
  set(boost_arch_flags)
    foreach(arch ${CMAKE_OSX_ARCHITECTURES})
      string(APPEND boost_arch_flags " -arch ${arch}")
    endforeach()
  file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/user-config.bjam "using darwin : : ${deps_cxx} :
  <architecture>arm
  <target-os>iphone
  <compileflags>\"-fPIC ${boost_arch_flags} ${CMAKE_CXX_OSX_DEPLOYMENT_TARGET_FLAG}${CMAKE_OSX_DEPLOYMENT_TARGET} -isysroot ${CMAKE_OSX_SYSROOT}\"
  <threading>multi
  ;")
else()
  file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/user-config.bjam "using ${boost_toolset} : : ${deps_cxx} ;")
endif()

set(boost_patch_commands "")
if(IOS)
  set(boost_patch_commands PATCH_COMMAND patch -p1 -i ${PROJECT_SOURCE_DIR}/utils/build_scripts/boost-darwin-libtool-path.patch)
elseif(APPLE AND BOOST_VERSION VERSION_LESS 1.74.0)
  set(boost_patch_commands PATCH_COMMAND patch -p1 -d tools/build -i ${PROJECT_SOURCE_DIR}/utils/build_scripts/boostorg-build-pr560-macos-build-fix.patch)
endif()

set(boost_buildflags "cxxflags=-fPIC")
if(IOS)
  set(boost_buildflags)
elseif(APPLE)
  set(boost_buildflags "cxxflags=-fPIC -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}" "cflags=-mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
endif()

build_external(boost
  #  PATCH_COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_BINARY_DIR}/user-config.bjam tools/build/src/user-config.jam
  ${boost_patch_commands}
  CONFIGURE_COMMAND
    ./tools/build/src/engine/build.sh ${boost_toolset} ${boost_bootstrap_cxx}
  BUILD_COMMAND
    cp tools/build/src/engine/b2 .
  INSTALL_COMMAND
    ./b2 -d0 variant=release link=static runtime-link=static optimization=speed ${boost_extra}
      threading=multi threadapi=${boost_threadapi} ${boost_buildflags} cxxstd=17 visibility=global
      --disable-icu --user-config=${CMAKE_CURRENT_BINARY_DIR}/user-config.bjam
      --prefix=${DEPS_DESTDIR} --exec-prefix=${DEPS_DESTDIR} --libdir=${DEPS_DESTDIR}/lib --includedir=${DEPS_DESTDIR}/include
      --with-program_options --with-system --with-thread --with-serialization
      install
  BUILD_BYPRODUCTS
    ${DEPS_DESTDIR}/lib/libboost_program_options.a
    ${DEPS_DESTDIR}/lib/libboost_serialization.a
    ${DEPS_DESTDIR}/lib/libboost_system.a
    ${DEPS_DESTDIR}/lib/libboost_thread.a
    ${DEPS_DESTDIR}/include/boost/version.hpp
)
add_library(boost_core INTERFACE)
add_dependencies(boost_core INTERFACE boost_external)
target_include_directories(boost_core SYSTEM INTERFACE ${DEPS_DESTDIR}/include)
add_library(Boost::boost ALIAS boost_core)
foreach(boostlib program_options serialization system thread)
  add_static_target(Boost::${boostlib} boost_external libboost_${boostlib}.a)
  target_link_libraries(Boost::${boostlib} INTERFACE boost_core)
endforeach()
set(Boost_FOUND ON)
set(Boost_VERSION ${BOOST_VERSION})



build_external(sqlite3
  BUILD_COMMAND true
  INSTALL_COMMAND make install-includeHEADERS install-libLTLIBRARIES)
add_static_target(sqlite3 sqlite3_external libsqlite3.a)



if (NOT (WIN32 OR ANDROID OR IOS))
  build_external(ncurses
    CONFIGURE_COMMAND ./configure ${cross_host} --prefix=${DEPS_DESTDIR} --without-debug --without-ada
      --without-cxx-binding --without-cxx --without-ticlib --without-tic --without-progs
      --without-tests --without-tack --without-manpages --with-termlib --disable-tic-depends
      --disable-big-strings --disable-ext-colors --enable-pc-files --without-shared --without-pthread
      --disable-rpath --disable-colorfgbg --disable-ext-mouse --disable-symlinks --enable-warnings
      --enable-assertions --with-default-terminfo-dir=/etc/_terminfo_
      --with-terminfo-dirs=/etc/_terminfo_ --disable-pc-files --enable-database --enable-sp-funcs
      --disable-term-driver --enable-interop --enable-widec "CC=${CMAKE_C_COMPILER}" "CFLAGS=${deps_CFLAGS} -fPIC"
    INSTALL_COMMAND make install.libs
    BUILD_BYPRODUCTS
      ${DEPS_DESTDIR}/lib/libncursesw.a
      ${DEPS_DESTDIR}/lib/libtinfow.a
      ${DEPS_DESTDIR}/include/ncursesw
      ${DEPS_DESTDIR}/include/ncursesw/termcap.h
      ${DEPS_DESTDIR}/include/ncursesw/ncurses.h
  )
  add_static_target(ncurses_tinfo ncurses_external libtinfow.a)



 if(FALSE) # not working reliably
  build_external(readline
    DEPENDS ncurses_external
    CONFIGURE_COMMAND ./configure ${cross_host} --prefix=${DEPS_DESTDIR} --disable-shared --with-curses
      "CC=${deps_cc}" "CFLAGS=${deps_CFLAGS} -fPIC"
    BUILD_BYPRODUCTS
      ${DEPS_DESTDIR}/lib/libreadline.a
      ${DEPS_DESTDIR}/include/readline
      ${DEPS_DESTDIR}/include/readline/readline.h
  )
  add_static_target(readline readline_external libreadline.a)
  set_target_properties(readline PROPERTIES
    INTERFACE_LINK_LIBRARIES ncurses_tinfo
    INTERFACE_COMPILE_DEFINITIONS HAVE_READLINE)
 endif()
endif()



if(APPLE OR WIN32 OR ANDROID OR IOS)
  add_library(libudev INTERFACE)
  set(maybe_eudev "")
else()
  build_external(eudev
    CONFIGURE_COMMAND autoreconf -ivf && ./configure ${cross_host} --prefix=${DEPS_DESTDIR} --disable-shared --disable-introspection
      --disable-programs --disable-manpages --disable-hwdb --with-pic "CC=${deps_cc}" "CFLAGS=${deps_CFLAGS}"
    BUILD_BYPRODUCTS
      ${DEPS_DESTDIR}/lib/libudev.a
      ${DEPS_DESTDIR}/include/libudev.h
  )
  add_static_target(libudev eudev_external libudev.a)
  set(maybe_eudev "eudev_external")
endif()



if(NOT (ANDROID OR IOS))
  build_external(libusb
    CONFIGURE_COMMAND autoreconf -ivf && ./configure ${cross_host} --prefix=${DEPS_DESTDIR} --disable-shared --disable-udev --with-pic
      "CC=${deps_cc}" "CXX=${deps_cxx}" "CFLAGS=${deps_CFLAGS}" "CXXFLAGS=${deps_CXXFLAGS}"
    BUILD_BYPRODUCTS
      ${DEPS_DESTDIR}/lib/libusb-1.0.a
      ${DEPS_DESTDIR}/include/libusb-1.0
      ${DEPS_DESTDIR}/include/libusb-1.0/libusb.h
  )
  add_static_target(libusb_vendor libusb_external libusb-1.0.a)
  set_target_properties(libusb_vendor PROPERTIES INTERFACE_SYSTEM_INCLUDE_DIRECTORIES ${DEPS_DESTDIR}/include/libusb-1.0)
endif()



if(ANDROID OR IOS)
  set(HIDAPI_FOUND FALSE)
else()
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(hidapi_libusb_lib libhidapi-libusb.a)
    set(hidapi_lib_byproducts ${DEPS_DESTDIR}/lib/libhidapi-libusb.a ${DEPS_DESTDIR}/lib/libhidapi-hidraw.a)
  else()
    set(hidapi_libusb_lib libhidapi.a)
    set(hidapi_lib_byproducts ${DEPS_DESTDIR}/lib/libhidapi.a)
  endif()
  build_external(hidapi
    DEPENDS ${maybe_eudev} libusb_external
    CONFIGURE_COMMAND autoreconf -ivf && ./configure ${cross_host} --prefix=${DEPS_DESTDIR} --disable-shared --enable-static --with-pic
      "CC=${deps_cc}" "CXX=${deps_cxx}" "CFLAGS=${deps_CFLAGS}" "CXXFLAGS=${deps_CXXFLAGS}"
      ${cross_extra}
      "libudev_CFLAGS=-I${DEPS_DESTDIR}/include" "libudev_LIBS=-L${DEPS_DESTDIR}/lib -ludev"
      "libusb_CFLAGS=-I${DEPS_DESTDIR}/include/libusb-1.0" "libusb_LIBS=-L${DEPS_DESTDIR}/lib -lusb-1.0"
    BUILD_BYPRODUCTS
      ${hidapi_lib_byproducts}
      ${DEPS_DESTDIR}/include/hidapi
      ${DEPS_DESTDIR}/include/hidapi/hidapi.h
  )
  set(HIDAPI_FOUND TRUE)
  add_static_target(hidapi_libusb hidapi_external ${hidapi_libusb_lib})
  set(hidapi_links "libusb_vendor;libudev")
  if(WIN32)
    list(APPEND hidapi_links setupapi)
  endif()
  set_target_properties(hidapi_libusb PROPERTIES
      INTERFACE_LINK_LIBRARIES "${hidapi_links}"
      INTERFACE_COMPILE_DEFINITIONS HAVE_HIDAPI)
endif()



if(USE_DEVICE_TREZOR)
  set(protobuf_extra "")
  if(ANDROID)
    set(protobuf_extra "LDFLAGS=-llog")
  endif()
  build_external(protobuf
    CONFIGURE_COMMAND
      ./configure ${cross_host} --disable-shared --prefix=${DEPS_DESTDIR} --with-pic
        "CC=${deps_cc}" "CXX=${deps_cxx}" "CFLAGS=${deps_CFLAGS}" "CXXFLAGS=${deps_CXXFLAGS}"
        ${cross_extra} ${protobuf_extra}
        "CPP=${deps_cc} -E" "CXXCPP=${deps_cxx} -E"
        "CC_FOR_BUILD=${deps_cc}" "CXX_FOR_BUILD=${deps_cxx}"  # Thanks Google for making people hunt for undocumented magic variables
    BUILD_BYPRODUCTS
      ${DEPS_DESTDIR}/lib/libprotobuf-lite.a
      ${DEPS_DESTDIR}/lib/libprotobuf.a
      ${DEPS_DESTDIR}/lib/libprotoc.a
      ${DEPS_DESTDIR}/include/google/protobuf
  )
  add_static_target(protobuf_lite protobuf_external libprotobuf-lite.a)
  add_static_target(protobuf_bloated protobuf_external libprotobuf.a)
endif()



build_external(sodium)
add_static_target(sodium sodium_external libsodium.a)


if(CMAKE_CROSSCOMPILING AND ARCH_TRIPLET MATCHES mingw)
  set(zmq_patch PATCH_COMMAND patch -p1 -i ${PROJECT_SOURCE_DIR}/utils/build_scripts/libzmq-mingw-closesocket.patch)
endif()

set(zmq_cross_host "${cross_host}")
if(IOS AND cross_host MATCHES "-ios$")
  # zmq doesn't like "-ios" for the host, so replace it with -darwin
  string(REGEX REPLACE "-ios$" "-darwin" zmq_cross_host ${cross_host})
endif()

build_external(zmq
  DEPENDS sodium_external
  ${zmq_patch}
  CONFIGURE_COMMAND ./configure ${zmq_cross_host} --prefix=${DEPS_DESTDIR} --enable-static --disable-shared
    --disable-curve-keygen --enable-curve --disable-drafts --disable-libunwind --with-libsodium
    --without-pgm --without-norm --without-vmci --without-docs --with-pic --disable-Werror
    "CC=${deps_cc}" "CXX=${deps_cxx}" "CFLAGS=-fstack-protector ${deps_CFLAGS}" "CXXFLAGS=-fstack-protector ${deps_CXXFLAGS}"
    ${cross_extra}
    "sodium_CFLAGS=-I${DEPS_DESTDIR}/include" "sodium_LIBS=-L${DEPS_DESTDIR}/lib -lsodium"
)
add_static_target(libzmq zmq_external libzmq.a)

set(libzmq_link_libs "sodium")
if(CMAKE_CROSSCOMPILING AND ARCH_TRIPLET MATCHES mingw)
  list(APPEND libzmq_link_libs iphlpapi)
endif()

set_target_properties(libzmq PROPERTIES
    INTERFACE_LINK_LIBRARIES "${libzmq_link_libs}"
    INTERFACE_COMPILE_DEFINITIONS "ZMQ_STATIC")



set(curl_extra)
if(WIN32)
  set(curl_ssl_opts --without-ssl --with-schannel)
elseif(APPLE)
  set(curl_ssl_opts --without-ssl --with-secure-transport)
  if(IOS)
    # This CPP crap shouldn't be necessary but is because Apple's toolchain is trash
    set(curl_extra "LDFLAGS=-L${DEPS_DESTDIR}/lib -isysroot ${CMAKE_OSX_SYSROOT}" CPP=cpp)
  endif()
else()
  set(curl_ssl_opts --with-ssl=${DEPS_DESTDIR})
  set(curl_extra "LIBS=-pthread")
endif()

set(curl_arches default)
set(curl_lib_outputs)
if(IOS)
  # On iOS things get a little messy: curl won't build a multi-arch library (with `clang -arch arch1
  # -arch arch2`) so we have to build them separately then glue them together if we're building
  # multiple.
  set(curl_arches ${CMAKE_OSX_ARCHITECTURES})
  list(GET curl_arches 0 curl_arch0)
  list(LENGTH CMAKE_OSX_ARCHITECTURES num_arches)
endif()

foreach(curl_arch ${curl_arches})
  set(curl_target_suffix "")
  set(curl_prefix "${DEPS_DESTDIR}")
  if(curl_arch STREQUAL "default")
    set(curl_cflags_extra "")
  elseif(IOS)
    set(cflags_extra " -arch ${curl_arch}")
    if(num_arches GREATER 1)
      set(curl_target_suffix "-${curl_arch}")
      set(curl_prefix "${DEPS_DESTDIR}/tmp/${curl_arch}")
    endif()
  else()
    message(FATAL_ERROR "unexpected curl_arch=${curl_arch}")
  endif()

  build_external(curl
    TARGET_SUFFIX ${curl_target_suffix}
    DEPENDS openssl_external zlib_external
    CONFIGURE_COMMAND ./configure ${cross_host} ${cross_extra} --prefix=${curl_prefix} --disable-shared
    --enable-static --disable-ares --disable-ftp --disable-ldap --disable-laps --disable-rtsp
    --disable-dict --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smb
    --disable-smtp --disable-gopher --disable-manual --disable-libcurl-option --enable-http
    --enable-ipv6 --disable-threaded-resolver --disable-pthreads --disable-verbose --disable-sspi
    --enable-crypto-auth --disable-ntlm-wb --disable-tls-srp --disable-unix-sockets --disable-cookies
    --enable-http-auth --enable-doh --disable-mime --enable-dateparse --disable-netrc --without-libidn2
    --disable-progress-meter --without-brotli --with-zlib=${DEPS_DESTDIR} ${curl_ssl_opts}
    --without-libmetalink --without-librtmp --disable-versioned-symbols --enable-hidden-symbols
    --without-zsh-functions-dir --without-fish-functions-dir
    "CC=${deps_cc}" "CFLAGS=${deps_noarch_CFLAGS}${cflags_extra}" ${curl_extra}
    BUILD_COMMAND true
    INSTALL_COMMAND make -C lib install && make -C include install
    BUILD_BYPRODUCTS
      ${curl_prefix}/lib/libcurl.a
      ${curl_prefix}/include/curl/curl.h
  )
  list(APPEND curl_lib_targets curl${curl_target_suffix}_external)
  list(APPEND curl_lib_outputs ${curl_prefix}/lib/libcurl.a)
endforeach()

message(STATUS "TARGETS: ${curl_lib_targets}")

if(IOS AND num_arches GREATER 1)
  # We are building multiple architectures for different iOS devices, so we need to glue the
  # separate libraries into one. (Normally multiple -arch values passed to clang does this for us,
  # but curl refuses to build that way).
  add_custom_target(curl_external
    COMMAND lipo ${curl_lib_outputs} -create -output ${DEPS_DESTDIR}/libcurl.a
    COMMAND ${CMAKE_COMMAND} -E copy_directory ${DEPS_DESTDIR}/tmp/${curl_arch0}/include/curl ${DEPS_DESTDIR}/include/curl
    BYPRODUCTS ${DEPS_DESTDIR}/lib/libcurl.a ${DEPS_DESTDIR}/include/curl/curl.h
    DEPENDS ${curl_lib_targets})
endif()

add_static_target(CURL::libcurl curl_external libcurl.a)
set(libcurl_link_libs zlib)
if(CMAKE_CROSSCOMPILING AND ARCH_TRIPLET MATCHES mingw)
  list(APPEND libcurl_link_libs crypt32)
elseif(APPLE)
  list(APPEND libcurl_link_libs "-framework Security")
endif()
set_target_properties(CURL::libcurl PROPERTIES
  INTERFACE_LINK_LIBRARIES "${libcurl_link_libs}"
  INTERFACE_COMPILE_DEFINITIONS "CURL_STATICLIB")
