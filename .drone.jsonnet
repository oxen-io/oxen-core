local default_deps_base='libsystemd-dev libboost-filesystem-dev libboost-thread-dev libboost-date-time-dev libgtest-dev ' +
    'libboost-serialization-dev libboost-program-options-dev libunbound-dev nettle-dev libevent-dev libminiupnpc-dev ' +
    'libunwind8-dev libsodium-dev libssl-dev libreadline-dev libhidapi-dev libusb-1.0-0-dev libprotobuf-dev protobuf-compiler python3 ' +
    'pkg-config libsqlite3-dev qttools5-dev libcurl4-openssl-dev';
local default_deps='g++ ' + default_deps_base; // g++ sometimes needs replacement

local gtest_filter='-AddressFromURL.Failure:DNSResolver.DNSSEC*';

local submodules = {
    name: 'submodules',
    image: 'drone/git',
    commands: ['git fetch --tags', 'git submodule update --init --recursive --depth=1']
};

local apt_get_quiet = 'apt-get -o=Dpkg::Use-Pty=0 -q';


// Regular build on a debian-like system:
local debian_pipeline(name, image,
        arch='amd64',
        deps=default_deps,
        build_type='Release',
        lto=false,
        werror=false, // FIXME
        build_tests=true,
        test_lokid=true, # Simple lokid offline startup test
        run_tests=false, # Runs full test suite
        cmake_extra='',
        extra_cmds=[],
        jobs=6,
        allow_fail=false) = {
    kind: 'pipeline',
    type: 'docker',
    name: name,
    platform: { arch: arch },
    steps: [
        submodules,
        {
            name: 'build',
            image: image,
            [if allow_fail then "failure"]: "ignore",
            environment: { SSH_KEY: { from_secret: "SSH_KEY" }, GTEST_FILTER: gtest_filter },
            commands: [
                'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
                apt_get_quiet + ' update',
                apt_get_quiet + ' install -y eatmydata',
                'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
                'eatmydata ' + apt_get_quiet + ' install -y --no-install-recommends cmake git ca-certificates ninja-build ccache ' + deps,
                'mkdir build',
                'cd build',
                'cmake .. -G Ninja -DCMAKE_CXX_FLAGS=-fdiagnostics-color=always -DCMAKE_BUILD_TYPE='+build_type+' ' +
                    '-DLOCAL_MIRROR=https://builds.lokinet.dev/deps -DUSE_LTO=' + (if lto then 'ON ' else 'OFF ') +
                    (if werror then '-DWARNINGS_AS_ERRORS=ON ' else '') +
                    (if build_tests || run_tests then '-DBUILD_TESTS=ON ' else '') +
                    cmake_extra
            ] + (if arch == 'arm64' && jobs > 1 then
                    // The wallet code is too bloated to be compiled at -j2 with only 4GB ram, so do
                    // the huge bloated jobs at -j1 and the rest at -j2
                    ['ninja -j1 rpc wallet -v', 'ninja -j2 daemon device_trezor -v', 'ninja -j1 wallet_rpc_server -v', 'ninja -j2 -v']
                else
                    ['ninja -j' + jobs + ' -v']
            ) + (
                if test_lokid then [
                    '(sleep 3; echo "status\ndiff\nexit") | TERM=xterm ./bin/lokid --offline --data-dir=startuptest'
                ] else []
            ) + (
                if run_tests then [
                    'mkdir -v -p $$HOME/.loki',
                    'GTEST_COLOR=1 ctest --output-on-failure -j'+jobs
                ] else []
            ) + extra_cmds,
        }
    ],
}; 

// Macos build
local mac_builder(name,
        build_type='Release',
        lto=false,
        werror=false, // FIXME
        build_tests=true,
        run_tests=false,
        cmake_extra='',
        extra_cmds=[],
        jobs=6,
        allow_fail=false) = {
    kind: 'pipeline',
    type: 'exec',
    name: name,
    platform: { os: 'darwin', arch: 'amd64' },
    steps: [
        {
            name: 'submodules',
            commands: ['git fetch --tags', 'git submodule update --init --recursive']
        },
        {
            name: 'build',
            environment: { SSH_KEY: { from_secret: "SSH_KEY" }, GTEST_FILTER: gtest_filter },
            commands: [
                // If you don't do this then the C compiler doesn't have an include path containing
                // basic system headers.  WTF apple:
                'export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"',
                'mkdir build',
                'cd build',
                'cmake .. -G Ninja -DCMAKE_CXX_FLAGS=-fcolor-diagnostics -DCMAKE_BUILD_TYPE='+build_type+' ' +
                    '-DLOCAL_MIRROR=https://builds.lokinet.dev/deps -DUSE_LTO=' + (if lto then 'ON ' else 'OFF ') +
                    (if werror then '-DWARNINGS_AS_ERRORS=ON ' else '') +
                    (if build_tests || run_tests then '-DBUILD_TESTS=ON ' else '') +
                    cmake_extra,
                'ninja -j' + jobs + ' -v'
            ] + (
                if run_tests then [
                    'mkdir -v -p $$HOME/.loki',
                    'GTEST_COLOR=1 ctest --output-on-failure -j'+jobs
                ] else []
            ) + extra_cmds,
        }
    ]
};

local static_check_and_upload = [
    '../utils/build_scripts/drone-check-static-libs.sh',
    'ninja strip_binaries',
    'ninja create_tarxz',
    '../utils/build_scripts/drone-static-upload.sh'
];

local static_build_deps='autoconf automake make qttools5-dev file libtool gperf pkg-config patch openssh-client';



[
    // Various debian builds
    debian_pipeline("Debian (w/ tests) (amd64)", "debian:testing", lto=true, run_tests=true),
    debian_pipeline("Debian Debug (amd64)", "debian:testing", build_type='Debug'),
    debian_pipeline("Debian clang-10 (amd64)", "debian:testing", deps='clang-10 '+default_deps_base,
                    cmake_extra='-DCMAKE_C_COMPILER=clang-10 -DCMAKE_CXX_COMPILER=clang++-10 ', lto=true),
    debian_pipeline("Debian gcc-10 (amd64)", "debian:testing", deps='g++-10 '+default_deps_base,
                    cmake_extra='-DCMAKE_C_COMPILER=gcc-10 -DCMAKE_CXX_COMPILER=g++-10 -DBUILD_DEBUG_UTILS=ON'),
    debian_pipeline("Debian buster (i386)", "i386/debian:buster", cmake_extra='-DDOWNLOAD_SODIUM=ON -DARCH_ID=i386'),
    debian_pipeline("Ubuntu focal (amd64)", "ubuntu:focal"),

    // ARM builds (ARM64 and armhf)
    debian_pipeline("Debian (ARM64)", "debian:testing", arch="arm64", build_tests=false),
    debian_pipeline("Debian buster (armhf)", "arm32v7/debian:buster", arch="arm64", build_tests=false, cmake_extra='-DDOWNLOAD_SODIUM=ON -DARCH_ID=armhf'),

    // Static build (on bionic) which gets uploaded to builds.lokinet.dev:
    debian_pipeline("Static (bionic amd64)", "ubuntu:bionic", deps='g++-8 '+static_build_deps,
                    cmake_extra='-DBUILD_STATIC_DEPS=ON -DCMAKE_C_COMPILER=gcc-8 -DCMAKE_CXX_COMPILER=g++-8 -DARCH=x86-64',
                    build_tests=false, lto=true, extra_cmds=static_check_and_upload),
    // Static mingw build (on focal) which gets uploaded to builds.lokinet.dev:
    debian_pipeline("Static (win64)", "ubuntu:focal", deps='g++ g++-mingw-w64-x86-64 '+static_build_deps,
                    cmake_extra='-DCMAKE_TOOLCHAIN_FILE=../cmake/64-bit-toolchain.cmake -DBUILD_STATIC_DEPS=ON -DARCH=x86-64',
                    build_tests=false, lto=false, test_lokid=false, extra_cmds=[
                        'ninja strip_binaries', 'ninja create_zip', '../utils/build_scripts/drone-static-upload.sh']),

    // Macos builds:
    mac_builder('macOS (Release)', run_tests=true),
    mac_builder('macOS (Debug)', build_type='Debug', cmake_extra='-DBUILD_DEBUG_UTILS=ON'),
    mac_builder('macOS (Static)', cmake_extra='-DBUILD_STATIC_DEPS=ON -DCMAKE_OSX_DEPLOYMENT_TARGET=10.14',
                build_tests=false, extra_cmds=static_check_and_upload),
]
