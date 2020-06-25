local default_deps_base='libsystemd-dev libboost-filesystem-dev libboost-thread-dev libboost-date-time-dev libboost-chrono-dev libgtest-dev ' +
    'libboost-regex-dev libboost-serialization-dev libboost-program-options-dev libunbound-dev nettle-dev libevent-dev libminiupnpc-dev ' +
    'libunwind8-dev libsodium-dev libssl-dev libreadline-dev libhidapi-dev libusb-1.0-0-dev libprotobuf-dev protobuf-compiler python3 ' +
    'pkg-config libsqlite3-dev qttools5-dev';
local default_deps='g++ ' + default_deps_base; // g++ sometimes needs replacement

local gtest_filter='-AddressFromURL.Failure:DNSResolver.DNSSEC*:is_hdd.linux_os_root';

local submodules = {
    name: 'submodules',
    image: 'drone/git',
    commands: ['git fetch --tags', 'git submodule update --init --recursive']
};

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
    trigger: { branch: { exclude: ['debian/*', 'ubuntu/*'] } },
    steps: [submodules,
        {
            name: 'build',
            image: image,
            [if allow_fail then "failure"]: "ignore",
            environment: { SSH_KEY: { from_secret: "SSH_KEY" }, GTEST_FILTER: gtest_filter },
            commands: [
                'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
                'apt-get update',
                'apt-get install -y eatmydata',
                'eatmydata apt-get dist-upgrade -y',
                'eatmydata apt-get install -y --no-install-recommends cmake git ca-certificates ninja-build ccache ' + deps,
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

// Builds a snapshot .deb on a debian-like system by merging into the debian/* or ubuntu/* branch
local deb_builder(image, distro, distro_branch, arch='amd64', imaginary_repo=false) = {
    kind: 'pipeline',
    type: 'docker',
    name: 'DEB (' + distro + (if arch == 'amd64' then '' else '/' + arch) + ')',
    platform: { arch: arch },
    environment: { distro_branch: distro_branch, distro: distro },
    steps: [submodules,
        {
            name: 'build',
            image: image,
            failure: 'ignore',
            environment: { SSH_KEY: { from_secret: "SSH_KEY" } },
            commands: [
                'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
                'apt-get update',
                'apt-get install -y eatmydata',
                'eatmydata apt-get install -y git devscripts equivs ccache git-buildpackage python3-dev' + (if imaginary_repo then ' gpg' else'')
                ] + (if imaginary_repo then [ // Some distros need the imaginary.stream repo for backported sodium, etc.
                    'echo deb https://deb.imaginary.stream $${distro} main >/etc/apt/sources.list.d/imaginary.stream.list',
                    'curl -s https://deb.imaginary.stream/public.gpg | apt-key add -',
                    'eatmydata apt-get update'
                ] else []) + [
                |||
                    # Look for the debian branch in this repo first, try upstream if that fails.
                    if ! git checkout $${distro_branch}; then
                        git remote add --fetch upstream https://github.com/loki-project/loki-network.git &&
                        git checkout $${distro_branch}
                    fi
                |||,
                'git merge ${DRONE_COMMIT}',
                'export DEBEMAIL="${DRONE_COMMIT_AUTHOR_EMAIL}" DEBFULLNAME="${DRONE_COMMIT_AUTHOR_NAME}"',
                'gbp dch -S -s "HEAD^" --spawn-editor=never -U low',
                'eatmydata mk-build-deps --install --remove --tool "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y"',
                'export DEB_BUILD_OPTIONS="parallel=$$(nproc)"',
                'grep -q lib debian/lokinet-bin.install || echo "/usr/lib/lib*.so*" >>debian/lokinet-bin.install',
                'debuild -e CCACHE_DIR -b',
                'pwd',
                'find ./contrib/ci',
                './contrib/ci/drone-debs-upload.sh ' + distro,
            ]
        }
    ]
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
    debian_pipeline("Debian sid (w/ tests) (amd64)", "debian:sid", lto=true, run_tests=true),
    debian_pipeline("Debian sid/Debug (amd64)", "debian:sid", build_type='Debug', lto=true),
    debian_pipeline("Debian sid/clang-10 (amd64)", "debian:sid", deps='clang-10 '+default_deps_base,
                    cmake_extra='-DCMAKE_C_COMPILER=clang-10 -DCMAKE_CXX_COMPILER=clang++-10 ', lto=true),
    debian_pipeline("Debian sid/gcc-10 (amd64)", "debian:sid", deps='g++-10 '+default_deps_base,
                    cmake_extra='-DCMAKE_C_COMPILER=gcc-10 -DCMAKE_CXX_COMPILER=g++-10 -DBUILD_DEBUG_UTILS=ON'),
    debian_pipeline("Debian buster (i386)", "i386/debian:buster", cmake_extra='-DDOWNLOAD_SODIUM=ON -DARCH_ID=i386'),
    debian_pipeline("Ubuntu focal (amd64)", "ubuntu:focal"),

    // ARM builds (ARM64 and armhf)
    debian_pipeline("Ubuntu bionic (ARM64)", "ubuntu:bionic", arch="arm64", build_tests=false, deps='g++-8 ' + default_deps_base,
                    cmake_extra='-DCMAKE_C_COMPILER=gcc-8 -DCMAKE_CXX_COMPILER=g++-8 -DDOWNLOAD_SODIUM=ON'),
    debian_pipeline("Debian sid (ARM64)", "debian:sid", arch="arm64", build_tests=false),
    debian_pipeline("Debian buster (armhf)", "arm32v7/debian:buster", arch="arm64", build_tests=false, cmake_extra='-DDOWNLOAD_SODIUM=ON -DARCH_ID=armhf'),

    // Static build (on bionic) which gets uploaded to builds.lokinet.dev:
    debian_pipeline("Static (bionic amd64)", "ubuntu:bionic", deps='g++-8 '+static_build_deps,
                    cmake_extra='-DBUILD_STATIC_DEPS=ON -DCMAKE_C_COMPILER=gcc-8 -DCMAKE_CXX_COMPILER=g++-8',
                    build_tests=false, lto=true, extra_cmds=static_check_and_upload),
    // Static mingw build (on focal) which gets uploaded to builds.lokinet.dev:
    debian_pipeline("Static (win64)", "ubuntu:focal", deps='g++ g++-mingw-w64-x86-64 '+static_build_deps,
                    cmake_extra='-DCMAKE_TOOLCHAIN_FILE=../cmake/64-bit-toolchain.cmake -DBUILD_STATIC_DEPS=ON',
                    build_tests=false, lto=false, test_lokid=false, extra_cmds=[
                        'ninja strip_binaries', 'ninja create_zip', '../utils/build_scripts/drone-static-upload.sh']),
/*
    // Deb builds:
    deb_builder("debian:sid", "sid", "debian/sid"),
    deb_builder("debian:buster", "buster", "debian/buster", imaginary_repo=true),
    deb_builder("ubuntu:focal", "focal", "ubuntu/focal"),
    deb_builder("debian:sid", "sid", "debian/sid", arch='arm64'),
*/
    // Macos builds:
    mac_builder('macOS (Release)', run_tests=true),
    mac_builder('macOS (Debug)', build_type='Debug', cmake_extra='-DBUILD_DEBUG_UTILS=ON'),
    mac_builder('macOS (Static)', cmake_extra='-DBUILD_STATIC_DEPS=ON -DCMAKE_OSX_DEPLOYMENT_TARGET=10.13',
                build_tests=false, extra_cmds=static_check_and_upload),
]
