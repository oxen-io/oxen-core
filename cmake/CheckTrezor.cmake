OPTION(USE_DEVICE_TREZOR_LIBUSB "Trezor LibUSB compilation" ON)
OPTION(USE_DEVICE_TREZOR_UDP_RELEASE "Trezor UdpTransport in release mode" OFF)
OPTION(USE_DEVICE_TREZOR_DEBUG "Trezor Debugging enabled" OFF)
OPTION(TREZOR_DEBUG "Main trezor debugging switch" OFF)

add_library(protobuf INTERFACE)

# Use Trezor master switch
if (USE_DEVICE_TREZOR)
    if (BUILD_STATIC_DEPS)
        message(FATAL_ERROR "USE_DEVICE_TREZOR is not supported with BUILD_STATIC_DEPS: there is no static protobuf build")
    endif()

    # Protobuf is required to build protobuf messages for Trezor
    include(FindProtobuf OPTIONAL)
    find_package(Protobuf)

    # Protobuf handling the cache variables set in docker.
    if(NOT Protobuf_FOUND)
        message(STATUS "Could not find Protobuf")
    elseif(NOT TARGET protobuf::libprotobuf)
        message(STATUS "Protobuf library not found")
        unset(Protobuf_FOUND)
    elseif(NOT Protobuf_PROTOC_EXECUTABLE OR NOT EXISTS "${Protobuf_PROTOC_EXECUTABLE}")
        message(STATUS "Protobuf executable not found: ${Protobuf_PROTOC_EXECUTABLE}")
        unset(Protobuf_FOUND)
    else()
        message(STATUS "Protobuf lib ${Protobuf_VERSION}, protoc: ${Protobuf_PROTOC_EXECUTABLE}")
    endif()

    if(TREZOR_DEBUG)
        set(USE_DEVICE_TREZOR_DEBUG 1)
    endif()

    # Compile debugging support (for tests)
    if (USE_DEVICE_TREZOR_DEBUG)
        add_definitions(-DWITH_TREZOR_DEBUGGING=1)
    endif()
else()
    message(STATUS "Trezor support disabled by USE_DEVICE_TREZOR")
endif()

if(Protobuf_FOUND AND USE_DEVICE_TREZOR)
    if (NOT "$ENV{TREZOR_PYTHON}" STREQUAL "")
        set(TREZOR_PYTHON "$ENV{TREZOR_PYTHON}" CACHE INTERNAL "Copied from environment variable TREZOR_PYTHON")
    else()
        find_package(Python QUIET COMPONENTS Interpreter)  # cmake 3.12+
        if(Python_Interpreter_FOUND)
            set(TREZOR_PYTHON "${Python_EXECUTABLE}")
        endif()
    endif()

    if(NOT TREZOR_PYTHON)
        find_package(PythonInterp)
        if(PYTHONINTERP_FOUND AND PYTHON_EXECUTABLE)
            set(TREZOR_PYTHON "${PYTHON_EXECUTABLE}")
        endif()
    endif()

    if(NOT TREZOR_PYTHON)
        message(STATUS "Trezor: Python not found")
    endif()
endif()

# Protobuf compilation test
if(Protobuf_FOUND AND USE_DEVICE_TREZOR AND TREZOR_PYTHON)
    execute_process(COMMAND ${Protobuf_PROTOC_EXECUTABLE} -I "${CMAKE_SOURCE_DIR}/cmake" -I "${Protobuf_INCLUDE_DIR}" "${CMAKE_SOURCE_DIR}/cmake/test-protobuf.proto" --cpp_out ${CMAKE_BINARY_DIR} RESULT_VARIABLE RET OUTPUT_VARIABLE OUT ERROR_VARIABLE ERR)
    if(RET)
        message(STATUS "Protobuf test generation failed: ${OUT} ${ERR}")
    endif()

    try_compile(Protobuf_COMPILE_TEST_PASSED
        "${CMAKE_BINARY_DIR}"
        SOURCES
        "${CMAKE_BINARY_DIR}/test-protobuf.pb.cc"
        "${CMAKE_SOURCE_DIR}/cmake/test-protobuf.cpp"
        CMAKE_FLAGS
        "-DINCLUDE_DIRECTORIES=${Protobuf_INCLUDE_DIR};${CMAKE_BINARY_DIR}"
        "-DCMAKE_CXX_STANDARD=11"
        LINK_LIBRARIES protobuf::libprotobuf
        OUTPUT_VARIABLE OUTPUT
    )
    if(NOT Protobuf_COMPILE_TEST_PASSED)
        message(STATUS "Protobuf Compilation test failed: ${OUTPUT}.")
    endif()
endif()

# Try to build protobuf messages
if(Protobuf_FOUND AND USE_DEVICE_TREZOR AND TREZOR_PYTHON AND Protobuf_COMPILE_TEST_PASSED)
    set(TREZOR_PROTOBUF_PARAMS "")
    if (USE_DEVICE_TREZOR_DEBUG)
        set(TREZOR_PROTOBUF_PARAMS "--debug")
    endif()

    execute_process(COMMAND ${CMAKE_COMMAND} -E env "PROTOBUF_INCLUDE_DIRS=${Protobuf_INCLUDE_DIR}" "PROTOBUF_PROTOC_EXECUTABLE=${Protobuf_PROTOC_EXECUTABLE}"
            ${TREZOR_PYTHON} tools/build_protob.py ${TREZOR_PROTOBUF_PARAMS}
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/../src/device_trezor/trezor
        RESULT_VARIABLE RET OUTPUT_VARIABLE OUT ERROR_VARIABLE ERR)
    if(RET)
        message(WARNING "Trezor protobuf messages could not be regenerated (err=${RET}, python ${PYTHON})."
                "OUT: ${OUT}, ERR: ${ERR}."
                "Please read src/device_trezor/trezor/tools/README.md")
    else()
        message(STATUS "Trezor protobuf messages regenerated out: \"${OUT}.\"")
        set(DEVICE_TREZOR_READY 1)
        target_compile_definitions(protobuf INTERFACE DEVICE_TREZOR_READY=1 PROTOBUF_INLINE_NOT_IN_HEADERS=0)

        if(CMAKE_BUILD_TYPE STREQUAL "Debug")
            target_compile_definitions(protobuf INTERFACE TREZOR_DEBUG=1)
        endif()

        if(USE_DEVICE_TREZOR_UDP_RELEASE)
            target_compile_definitions(protobuf INTERFACE USE_DEVICE_TREZOR_UDP_RELEASE=1)
        endif()

        if (Protobuf_INCLUDE_DIR)
            target_include_directories(protobuf INTERFACE ${Protobuf_INCLUDE_DIR})
        endif()

        target_link_libraries(protobuf INTERFACE protobuf::libprotobuf)

        # LibUSB support, check for particular version
        # Include support only if compilation test passes
        add_library(libusb INTERFACE)
        find_package(LibUSB)

        if (LibUSB_COMPILE_TEST_PASSED)
            target_compile_definitions(libusb INTERFACE HAVE_TREZOR_LIBUSB=1)
            if(LibUSB_INCLUDE_DIRS)
                target_include_directories(libusb INTERFACE ${LibUSB_INCLUDE_DIRS})
            endif()

            target_link_libraries(libusb INTERFACE ${LibUSB_LIBRARIES} ${LIBUSB_DEP_LINKER})
            message(STATUS "Trezor compatible LibUSB found")
        endif()

        if (ANDROID)

            if (Protobuf_LIBRARY)
                list(APPEND TREZOR_DEP_LIBS ${Protobuf_LIBRARY})
                string(APPEND TREZOR_DEP_LINKER " -lprotobuf")
            endif()

            if (TREZOR_LIBUSB_LIBRARIES)
                list(APPEND TREZOR_DEP_LIBS ${TREZOR_LIBUSB_LIBRARIES})
                string(APPEND TREZOR_DEP_LINKER " -lusb-1.0 ${LIBUSB_DEP_LINKER}")
            endif()
        endif()
    endif()
endif()
