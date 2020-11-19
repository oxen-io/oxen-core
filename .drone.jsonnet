local default_deps_base='libsystemd-dev libboost-thread-dev libgtest-dev ' +
    'libboost-serialization-dev libboost-program-options-dev libunbound-dev nettle-dev libevent-dev libminiupnpc-dev ' +
    'libunwind8-dev libsodium-dev libssl-dev libreadline-dev libhidapi-dev libusb-1.0-0-dev libprotobuf-dev protobuf-compiler python3 ' +
    'pkg-config libsqlite3-dev qttools5-dev libcurl4-openssl-dev';
local default_deps='g++ ' + default_deps_base; // g++ sometimes needs replacement

local gtest_filter='-AddressFromURL.Failure:DNSResolver.DNSSEC*';

local submodules_commands = ['git fetch --tags', 'git submodule update --init --recursive --depth=1'];
local submodules = {
    name: 'submodules',
    image: 'drone/git',
    commands: submodules_commands
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
        extra_steps=[],
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
                'echo "Building on ${DRONE_STAGE_MACHINE}"',
                'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
                apt_get_quiet + ' update',
                apt_get_quiet + ' install -y eatmydata',
                'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
                'eatmydata ' + apt_get_quiet + ' install -y --no-install-recommends cmake git ca-certificates ninja-build ccache '
                    + deps + (if test_lokid then ' gdb' else ''),
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
                    '(sleep 3; echo "status\ndiff\nexit") | TERM=xterm ../utils/build_scripts/drone-gdb.sh ./bin/lokid --offline --data-dir=startuptest'
                ] else []
            ) + (
                if run_tests then [
                    'mkdir -v -p $$HOME/.loki',
                    'GTEST_COLOR=1 ctest --output-on-failure -j'+jobs
                ] else []
            ) + extra_cmds,
        }
    ] + extra_steps,
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
        extra_steps=[],
        jobs=6,
        allow_fail=false) = {
    kind: 'pipeline',
    type: 'exec',
    name: name,
    platform: { os: 'darwin', arch: 'amd64' },
    steps: [
        { name: 'submodules', commands: submodules_commands },
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
    ] + extra_steps
};

local static_check_and_upload = [
    '../utils/build_scripts/drone-check-static-libs.sh',
    'ninja strip_binaries',
    'ninja create_tarxz',
    '../utils/build_scripts/drone-static-upload.sh'
];

local static_build_deps='autoconf automake make qttools5-dev file libtool gperf pkg-config patch openssh-client';


local android_build_steps(android_abi, android_platform=21, jobs=6, cmake_extra='') = [
    'mkdir build-' + android_abi,
    'cd build-' + android_abi,
    'cmake .. -DCMAKE_CXX_FLAGS=-fdiagnostics-color=always -DCMAKE_C_FLAGS=-fdiagnostics-color=always ' +
        '-DCMAKE_BUILD_TYPE=Release ' +
        '-DCMAKE_TOOLCHAIN_FILE=/usr/lib/android-sdk/ndk-bundle/build/cmake/android.toolchain.cmake ' +
        '-DANDROID_PLATFORM=' + android_platform + ' -DANDROID_ABI=' + android_abi + ' ' +
        '-DMONERO_SLOW_HASH=ON ' +
        '-DBUILD_STATIC_DEPS=ON -DSTATIC=ON -G Ninja ' + cmake_extra,
    'ninja -j' + jobs + ' -v wallet_merged',
    'cd ..',
];

local gui_wallet_step(image, wine=false) = {
    name: 'GUI Wallet (dev)',
    platform: { arch: 'amd64' },
    image: image,
    environment: { SSH_KEY: { from_secret: "SSH_KEY" } },
    commands: [
        'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
        ] + (if wine then ['dpkg --add-architecture i386'] else []) + [
        apt_get_quiet + ' update',
        apt_get_quiet + ' install -y eatmydata',
        'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
        'eatmydata ' + apt_get_quiet + ' install -y --no-install-recommends git ssh curl ca-certificates binutils make' + (if wine then ' wine32 wine sed' else ''),
        'curl -sSL https://deb.nodesource.com/setup_14.x | bash -',
        'eatmydata ' + apt_get_quiet + ' update',
        'eatmydata ' + apt_get_quiet + ' install -y nodejs',
        'git clone https://github.com/loki-project/loki-electron-gui-wallet.git',
        'cp -v build/bin/lokid' + (if wine then '.exe' else '') + ' loki-electron-gui-wallet/bin',
        'cp -v build/bin/loki-wallet-rpc' + (if wine then '.exe' else '') + ' loki-electron-gui-wallet/bin',
        'cd loki-electron-gui-wallet',
        'eatmydata npm install',
        'sed -i -e \'s/^\\\\( *"version": ".*\\\\)",/\\\\\\\\1-${DRONE_COMMIT_SHA:0:8}",/\' package.json',
        ] + (if wine then ['sed -i -e \'s/^\\\\( *"build": "quasar.*\\\\)",/\\\\\\\\1 --target=win",/\' package.json'] else []) + [
        'eatmydata npm run build',
        '../utils/build_scripts/drone-wallet-upload.sh'
    ]
};
local gui_wallet_step_darwin = {
    name: 'GUI Wallet (dev)',
    platform: { os: 'darwin', arch: 'amd64' },
    environment: { SSH_KEY: { from_secret: "SSH_KEY" }, CSC_IDENTITY_AUTO_DISCOVERY: 'false' },
    commands: [
        'git clone https://github.com/loki-project/loki-electron-gui-wallet.git',
        'cp -v build/bin/{lokid,loki-wallet-rpc} loki-electron-gui-wallet/bin',
        'cd loki-electron-gui-wallet',
        'sed -i -e \'s/^\\\\( *"version": ".*\\\\)",/\\\\1-${DRONE_COMMIT_SHA:0:8}",/\' package.json',
        'npm install',
        'npm run build',
        '../utils/build_scripts/drone-wallet-upload.sh'
    ]
};





[
    // Various debian builds
    debian_pipeline("Debian (w/ tests) (amd64)", "debian:sid", lto=true, run_tests=true),
    debian_pipeline("Debian Debug (amd64)", "debian:sid", build_type='Debug'),
    debian_pipeline("Debian clang-11 (amd64)", "debian:sid", deps='clang-11 '+default_deps_base,
                    cmake_extra='-DCMAKE_C_COMPILER=clang-11 -DCMAKE_CXX_COMPILER=clang++-11 ', lto=true),
    debian_pipeline("Debian gcc-10 (amd64)", "debian:testing", deps='g++-10 '+default_deps_base,
                    cmake_extra='-DCMAKE_C_COMPILER=gcc-10 -DCMAKE_CXX_COMPILER=g++-10 -DBUILD_DEBUG_UTILS=ON'),
    debian_pipeline("Debian buster (i386)", "i386/debian:buster", cmake_extra='-DDOWNLOAD_SODIUM=ON -DARCH_ID=i386'),
    debian_pipeline("Ubuntu focal (amd64)", "ubuntu:focal"),

    // ARM builds (ARM64 and armhf)
    debian_pipeline("Debian (ARM64)", "debian:sid", arch="arm64", build_tests=false),
    debian_pipeline("Debian buster (armhf)", "arm32v7/debian:buster", arch="arm64", build_tests=false, cmake_extra='-DDOWNLOAD_SODIUM=ON -DARCH_ID=armhf'),

    // Static build (on bionic) which gets uploaded to builds.lokinet.dev:
    debian_pipeline("Static (bionic amd64)", "ubuntu:bionic", deps='g++-8 '+static_build_deps,
                    cmake_extra='-DBUILD_STATIC_DEPS=ON -DCMAKE_C_COMPILER=gcc-8 -DCMAKE_CXX_COMPILER=g++-8 -DARCH=x86-64',
                    build_tests=false, lto=true, extra_cmds=static_check_and_upload,
                    extra_steps=[gui_wallet_step('ubuntu:bionic')]),

    // Static mingw build (on focal) which gets uploaded to builds.lokinet.dev:
    debian_pipeline("Static (win64)", "ubuntu:focal", deps='g++ g++-mingw-w64-x86-64 '+static_build_deps,
                    cmake_extra='-DCMAKE_TOOLCHAIN_FILE=../cmake/64-bit-toolchain.cmake -DBUILD_STATIC_DEPS=ON -DARCH=x86-64',
                    build_tests=false, lto=false, test_lokid=false, extra_cmds=[
                        'ninja strip_binaries', 'ninja create_zip', '../utils/build_scripts/drone-static-upload.sh'],
                    extra_steps=[gui_wallet_step('debian:stable', wine=true)]),

    // Macos builds:
    mac_builder('macOS (Static)', cmake_extra='-DBUILD_STATIC_DEPS=ON -DARCH=core2 -DARCH_ID=amd64',
                build_tests=false, lto=true, extra_cmds=static_check_and_upload, extra_steps=[gui_wallet_step_darwin]),
    mac_builder('macOS (Release)', run_tests=true),
    mac_builder('macOS (Debug)', build_type='Debug', cmake_extra='-DBUILD_DEBUG_UTILS=ON'),


    // Android builds; we do them all in one image because the android NDK is huge
    {   name: 'Android wallet_api', kind: 'pipeline', type: 'docker', platform: { arch: 'amd64' },
        steps: [submodules, {
                name: 'build',
                image: 'debian:sid',
                environment: { SSH_KEY: { from_secret: "SSH_KEY" } },
                commands: [
                    'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
                    'echo deb http://deb.debian.org/debian sid contrib >/etc/apt/sources.list.d/sid-contrib.list',
                    apt_get_quiet + ' update',
                    apt_get_quiet + ' install -y eatmydata',
                    'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
                    // Keep cached copies of the android NDK around because it is huge:
                    'if [ -d /cache ]; then if ! [ -d /cache/google-android-ndk-installer ]; then mkdir /cache/google-android-ndk-installer; fi; ln -s /cache/google-android-ndk-installer /var/cache/; fi',
                    'eatmydata ' + apt_get_quiet + ' install -y --no-install-recommends cmake g++ git ninja-build ccache tar xz-utils google-android-ndk-installer ' + static_build_deps,
                    ]
                    + android_build_steps('armeabi-v7a', cmake_extra='-DARCH=armv7-a -DARCH_ID=arm32')
                    + android_build_steps('arm64-v8a', cmake_extra='-DARCH=armv8-a -DARCH_ID=arm64')
                    + android_build_steps('x86_64', cmake_extra='-DARCH="x86-64 -msse4.2 -mpopcnt" -DARCH_ID=x86-64')
                    + android_build_steps('x86', cmake_extra='-DARCH="i686 -mssse3 -mfpmath=sse" -DARCH_ID=i386')
                    + [
                    './utils/build_scripts/drone-android-static-upload.sh armeabi-v7a arm64-v8a x86_64 x86'
                ]
            }
        ]
    },

    // iOS build
    {   name: 'iOS wallet_api', kind: 'pipeline', type: 'exec', platform: { os: 'darwin', arch: 'amd64' },
        steps: [{
            name: 'build',
            environment: { SSH_KEY: { from_secret: "SSH_KEY" } },
            commands: submodules_commands + [
                'mkdir -p build/{arm64,sim64}',
                'cd build/arm64',
                'cmake ../.. -G Ninja ' +
                    '-DCMAKE_TOOLCHAIN_FILE=../../cmake/ios.toolchain.cmake -DPLATFORM=OS -DDEPLOYMENT_TARGET=11 -DENABLE_VISIBILITY=ON -DENABLE_BITCODE=OFF ' +
                    '-DSTATIC=ON -DBUILD_STATIC_DEPS=ON -DUSE_LTO=OFF -DCMAKE_BUILD_TYPE=Release ' +
                    '-DRANDOMX_ENABLE_JIT=OFF -DCMAKE_CXX_FLAGS=-fcolor-diagnostics',
                'ninja -j6 -v wallet_merged',
                'cd ../sim64',
                'cmake ../.. -G Ninja ' +
                    '-DCMAKE_TOOLCHAIN_FILE=../../cmake/ios.toolchain.cmake -DPLATFORM=SIMULATOR64 -DDEPLOYMENT_TARGET=11 -DENABLE_VISIBILITY=ON -DENABLE_BITCODE=OFF ' +
                    '-DSTATIC=ON -DBUILD_STATIC_DEPS=ON -DUSE_LTO=OFF -DCMAKE_BUILD_TYPE=Release ' +
                    '-DRANDOMX_ENABLE_JIT=OFF -DCMAKE_CXX_FLAGS=-fcolor-diagnostics',
                'ninja -j6 -v wallet_merged',
                'cd ../..',
                './utils/build_scripts/drone-ios-static-upload.sh'
            ]
        }]
    },
]
