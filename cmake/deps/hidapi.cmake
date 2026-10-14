# Static hidapi build for BUILD_STATIC_DEPS, using session-deps' static build functions.  Provides
# the hidapi_libusb target and sets HIDAPI_FOUND.

include(${PROJECT_SOURCE_DIR}/cmake/session-deps/deps/StaticBuild.cmake)

set(HIDAPI_VERSION 0.15.0)
set(HIDAPI_MIRROR https://github.com/libusb/hidapi/archive/refs/tags)
set(HIDAPI_SOURCE hidapi-${HIDAPI_VERSION}.tar.gz)
set(HIDAPI_HASH SHA512=a4ddd13a80a84956872fa52aa861b40e4959f301d8d91afe0feaf9dbd87394561e1fdd20cbf8cf47200845f80a8db8a934bc2e3025fe6f16435e37c17621e7b6)

set(hidapi_cmake_args)
set(hidapi_depends)
set(hidapi_extra_deps)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # On Linux we build only hidapi's libusb backend: the hidraw one needs libudev, which would be
    # another library to build and link statically.  libusb itself is likewise built without udev,
    # enumerating devices through netlink and sysfs instead.
    set(LIBUSB_VERSION 1.0.30)
    set(LIBUSB_MIRROR https://github.com/libusb/libusb/releases/download/v${LIBUSB_VERSION})
    set(LIBUSB_SOURCE libusb-${LIBUSB_VERSION}.tar.bz2)
    set(LIBUSB_HASH SHA512=b14241bc499cdf353bb7fe02cea9a754b011f40ef0d0376ff8921f129f888b514d481e54c6aa380be04f655e027aaf4d6d9eba142b15758dea2e32f64af7b0c2)

    sessiondep_build_external(libusb
        CONFIGURE_COMMAND ./configure ${sessiondeps_cross_host} --prefix=${SESSIONDEPS_DESTDIR}
            --disable-shared --enable-static --with-pic --disable-udev
            --disable-examples-build --disable-tests-build
            "CC=${sessiondeps_cc}" "CFLAGS=${sessiondeps_CFLAGS}" "LDFLAGS=${sessiondeps_ldflags}"
        BUILD_BYPRODUCTS
            ${SESSIONDEPS_DESTDIR}/lib/libusb-1.0.a
            ${SESSIONDEPS_DESTDIR}/include/libusb-1.0/libusb.h
    )
    sessiondep_static_target(libusb::libusb libusb libusb-1.0.a -pthread)

    set(hidapi_lib libhidapi-libusb.a)
    # CMAKE_PREFIX_PATH is what puts the destdir on the pkg-config path that hidapi's libusb lookup
    # searches, ahead of the system's.
    set(hidapi_cmake_args -DHIDAPI_WITH_LIBUSB=ON -DHIDAPI_WITH_HIDRAW=OFF
        -DCMAKE_PREFIX_PATH=${SESSIONDEPS_DESTDIR})
    set(hidapi_depends sessiondep_libusb_external)
    set(hidapi_extra_deps libusb::libusb -pthread)
elseif(APPLE)
    set(hidapi_lib libhidapi.a)
    set(hidapi_extra_deps "-framework IOKit" "-framework CoreFoundation")
elseif(WIN32)
    set(hidapi_lib libhidapi.a)
else()
    message(FATAL_ERROR "The static hidapi build doesn't know which backend to build for ${CMAKE_SYSTEM_NAME}")
endif()

sessiondep_build_external(hidapi
    DEPENDS ${hidapi_depends}
    CONFIGURE_COMMAND DEFAULT_CMAKE
        -DBUILD_SHARED_LIBS=OFF -DHIDAPI_WITH_TESTS=OFF -DHIDAPI_BUILD_HIDTEST=OFF
        ${hidapi_cmake_args}
    BUILD_BYPRODUCTS
        ${SESSIONDEPS_DESTDIR}/lib/${hidapi_lib}
        ${SESSIONDEPS_DESTDIR}/include/hidapi/hidapi.h
)

sessiondep_static_target(hidapi_libusb hidapi ${hidapi_lib} ${hidapi_extra_deps})
target_compile_definitions(hidapi_libusb INTERFACE HAVE_HIDAPI)
if(WIN32)
    # Without this hidapi.h declares everything __declspec(dllexport).
    target_compile_definitions(hidapi_libusb INTERFACE HID_API_NO_EXPORT_DEFINE)
endif()
set(HIDAPI_FOUND TRUE)
