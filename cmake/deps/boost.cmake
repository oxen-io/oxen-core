# Static boost build for BUILD_STATIC_DEPS, using session-deps' static build functions.

include(${PROJECT_SOURCE_DIR}/cmake/session-deps/deps/StaticBuild.cmake)

set(BOOST_VERSION 1.92.0)
string(REPLACE "." "_" boost_version_ ${BOOST_VERSION})
set(BOOST_MIRROR https://archives.boost.io/release/${BOOST_VERSION}/source)
set(BOOST_SOURCE boost_${boost_version_}.tar.bz2)
set(BOOST_HASH SHA256=5c1d40cb8e19adbf740a4ec2da35b3e58f3f5804b1dce44deb53df72193cbc6c)

set(boost_libraries program_options serialization thread)

if(CMAKE_CXX_COMPILER_ID STREQUAL GNU)
    set(boost_toolset gcc)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "^(Apple)?Clang$")
    set(boost_toolset clang)
else()
    message(FATAL_ERROR "Don't know how to build boost with ${CMAKE_CXX_COMPILER_ID}")
endif()

# b2 is itself built first and run on the build machine, so a cross build has to bootstrap it with
# the host's compiler rather than the target's.
if(CMAKE_CROSSCOMPILING)
    set(boost_bootstrap cxx --cxx=c++)
else()
    set(boost_bootstrap ${boost_toolset} --cxx=${CMAKE_CXX_COMPILER})
endif()

set(boost_options)
if(WIN32)
    list(APPEND boost_options threadapi=win32 target-os=windows)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        list(APPEND boost_options address-model=64)
    else()
        list(APPEND boost_options address-model=32)
    endif()
else()
    list(APPEND boost_options threadapi=pthread)
endif()

# b2 takes the compiler (and, for a cross build, the archiver) only from a user config file.
set(boost_tool_options)
if(CMAKE_CROSSCOMPILING)
    set(boost_tool_options "<archiver>${CMAKE_AR} <ranlib>${CMAKE_RANLIB}")
endif()
set(boost_user_config_file ${CMAKE_BINARY_DIR}/boost-user-config.jam)
file(WRITE ${boost_user_config_file} "using ${boost_toolset} : : ${sessiondeps_cxx} : ${boost_tool_options} ;\n")

set(boost_with_libraries)
set(boost_byproducts)
foreach(lib IN LISTS boost_libraries)
    list(APPEND boost_with_libraries --with-${lib})
    list(APPEND boost_byproducts ${SESSIONDEPS_DESTDIR}/lib/libboost_${lib}.a)
endforeach()

sessiondep_build_external(boost
    CONFIGURE_COMMAND ./tools/build/src/engine/build.sh ${boost_bootstrap}
    BUILD_COMMAND ${CMAKE_COMMAND} -E copy tools/build/src/engine/b2 b2
    INSTALL_COMMAND
        ./b2 -d0 variant=release link=static runtime-link=static optimization=speed threading=multi
            cxxstd=17 visibility=global ${boost_options}
            "cxxflags=${sessiondeps_CXXFLAGS} -fPIC" "cflags=${sessiondeps_CFLAGS} -fPIC"
            --disable-icu --user-config=${boost_user_config_file} --layout=system
            --prefix=${SESSIONDEPS_DESTDIR} --libdir=${SESSIONDEPS_DESTDIR}/lib
            --includedir=${SESSIONDEPS_DESTDIR}/include
            ${boost_with_libraries}
            install
    BUILD_BYPRODUCTS
        ${boost_byproducts}
        ${SESSIONDEPS_DESTDIR}/include/boost/version.hpp
)

add_library(Boost::boost INTERFACE IMPORTED GLOBAL)
add_dependencies(Boost::boost sessiondep_boost_external)
target_include_directories(Boost::boost INTERFACE ${SESSIONDEPS_DESTDIR}/include)

set(boost_extra_deps)
if(NOT WIN32)
    list(APPEND boost_extra_deps -pthread)
endif()
foreach(lib IN LISTS boost_libraries)
    sessiondep_static_target(Boost::${lib} boost libboost_${lib}.a Boost::boost ${boost_extra_deps})
endforeach()

set(Boost_FOUND ON)
set(Boost_VERSION ${BOOST_VERSION})
