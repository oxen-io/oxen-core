local default_deps_nocxx = [
  'libboost-program-options-dev',
  'libboost-serialization-dev',
  'libboost-thread-dev',
  'libcurl4-openssl-dev',
  'libevent-dev',
  'libgtest-dev',
  'libhidapi-dev',
  'libreadline-dev',
  'libsodium-dev',
  'libsqlite3-dev',
  'libssl-dev',
  'libsystemd-dev',
  'libunbound-dev',
  'libunwind8-dev',
  'libusb-1.0-0-dev',
  'nettle-dev',
  'pkg-config',
  'python3',
  'qttools5-dev',
];
local default_deps = ['g++'] + default_deps_nocxx;  // g++ sometimes needs replacement

local gtest_filter = '-AddressFromURL.Failure:DNSResolver.DNSSEC*';

local docker_base = 'registry.oxen.rocks/lokinet-ci-';

local submodules_commands = ['git fetch --tags', 'git submodule update --init --recursive --depth=1 --jobs=4'];
local submodules = {
  name: 'submodules',
  image: 'drone/git',
  commands: submodules_commands,
};

local apt_get_quiet = 'apt-get -o=Dpkg::Use-Pty=0 -q';

local cmake_options(opts) = std.join(' ', [' -D' + o + '=' + (if opts[o] then 'ON' else 'OFF') for o in std.objectFields(opts)]) + ' ';

// Regular build on a debian-like system:
local debian_pipeline(name,
                      image,
                      arch='amd64',
                      deps=default_deps,
                      build_type='Release',
                      lto=false,
                      werror=false,  // FIXME
                      build_tests=true,
                      test_oxend=true,  // Simple oxend offline startup test
                      run_tests=false,  // Runs full test suite
                      cmake_extra='',
                      extra_cmds=[],
                      extra_steps=[],
                      jobs=6,
                      kitware_cmake_distro='',
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
      pull: 'always',
      [if allow_fail then 'failure']: 'ignore',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' }, GTEST_FILTER: gtest_filter },
      commands: [
        'echo "Building on ${DRONE_STAGE_MACHINE}"',
        apt_get_quiet + ' update',
        apt_get_quiet + ' install -y eatmydata',
        'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
      ] + (
        if kitware_cmake_distro != '' then
          [
            'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y curl ca-certificates',
            'curl https://apt.kitware.com/keys/kitware-archive-latest.asc | gpg --dearmor - >/etc/apt/trusted.gpg.d/kitware.gpg',
            'echo deb https://apt.kitware.com/ubuntu/ ' + kitware_cmake_distro + ' main >/etc/apt/sources.list.d/kitware.list',
            apt_get_quiet + ' update',
          ] else []
      ) + [
        'eatmydata ' + apt_get_quiet + ' install -y --no-install-recommends cmake git ninja-build ccache '
        + (if test_oxend then 'gdb ' else '') + std.join(' ', deps),
        'mkdir build',
        'cd build',
        'cmake .. -G Ninja -DCMAKE_CXX_FLAGS=-fdiagnostics-color=always -DCMAKE_BUILD_TYPE=' + build_type + ' ' +
        '-DLOCAL_MIRROR=https://builds.lokinet.dev/deps '
        + cmake_options({ USE_LTO: lto, WARNINGS_AS_ERRORS: werror, BUILD_TESTS: build_tests || run_tests })
        + cmake_extra,
      ] + (
        if arch == 'arm64' && jobs > 1 then
          // The wallet code is too bloated to be compiled at -j2 with only 4GB ram, so do
          // the huge bloated jobs at -j1 and the rest at -j2
          ['ninja -j1 rpc wallet -v', 'ninja -j2 daemon -v', 'ninja -j1 wallet_rpc_server -v', 'ninja -j2 -v']
        else
          ['ninja -j' + jobs + ' -v']
      ) + (
        if test_oxend then [
          '(sleep 3; echo "status\ndiff\nexit") | TERM=xterm ../utils/build_scripts/drone-gdb.sh ./bin/oxend --offline --data-dir=startuptest',
        ] else []
      ) + (
        if run_tests then [
          'mkdir -v -p $$HOME/.oxen',
          'GTEST_COLOR=1 ctest --output-on-failure -j' + jobs,
        ] else []
      ) + extra_cmds,
    },
  ] + extra_steps,
};

local clang(version, lto=false) = debian_pipeline(
  'Debian sid/clang-' + version + ' (amd64)',
  docker_base + 'debian-sid-clang',
  deps=['clang-' + version] + default_deps_nocxx,
  cmake_extra='-DCMAKE_C_COMPILER=clang-' + version + ' -DCMAKE_CXX_COMPILER=clang++-' + version + ' ',
  lto=lto
);

// Macos build
local mac_builder(name,
                  build_type='Release',
                  lto=false,
                  werror=false,  // FIXME
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
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' }, GTEST_FILTER: gtest_filter },
      commands: [
        // If you don't do this then the C compiler doesn't have an include path containing
        // basic system headers.  WTF apple:
        'export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"',
        'mkdir build',
        'cd build',
        'cmake .. -G Ninja -DCMAKE_CXX_FLAGS=-fcolor-diagnostics -DCMAKE_BUILD_TYPE=' + build_type + ' ' +
        '-DOXEN_LOGGING_FORCE_SUBMODULES=ON ' +
        '-DLOCAL_MIRROR=https://builds.lokinet.dev/deps -DUSE_LTO=' + (if lto then 'ON ' else 'OFF ') +
        (if werror then '-DWARNINGS_AS_ERRORS=ON ' else '') +
        (if build_tests || run_tests then '-DBUILD_TESTS=ON ' else '') +
        cmake_extra,
        'ninja -j' + jobs + ' -v',
      ] + (
        if run_tests then [
          'mkdir -v -p $$HOME/.oxen',
          'GTEST_COLOR=1 ctest --output-on-failure -j' + jobs,
        ] else []
      ) + extra_cmds,
    },
  ] + extra_steps,
};

local static_check_and_upload = [
  '../utils/build_scripts/drone-check-static-libs.sh',
  'ninja strip_binaries',
  'ninja create_tarxz',
  '../utils/build_scripts/drone-static-upload.sh',
];

local static_build_deps = [
  'autoconf',
  'automake',
  'file',
  'gperf',
  'libtool',
  'make',
  'openssh-client',
  'patch',
  'pkg-config',
  'qttools5-dev',
];


local android_build_steps(android_abi, android_platform=21, jobs=6, cmake_extra='') = [
  'mkdir build-' + android_abi,
  'cd build-' + android_abi,
  'cmake .. -DCMAKE_CXX_FLAGS=-fdiagnostics-color=always -DCMAKE_C_FLAGS=-fdiagnostics-color=always ' +
  '-DCMAKE_BUILD_TYPE=Release ' +
  '-DCMAKE_TOOLCHAIN_FILE=/usr/lib/android-sdk/ndk-bundle/build/cmake/android.toolchain.cmake ' +
  '-DANDROID_PLATFORM=' + android_platform + ' -DANDROID_ABI=' + android_abi + ' ' +
  cmake_options({ MONERO_SLOW_HASH: true, WARNINGS_AS_ERRORS: false, BUILD_TESTS: false }) +
  '-DLOCAL_MIRROR=https://builds.lokinet.dev/deps ' +
  '-DBUILD_STATIC_DEPS=ON -DSTATIC=ON -G Ninja ' + cmake_extra,
  'ninja -j' + jobs + ' -v wallet_merged',
  'cd ..',
];

local gui_wallet_step(image, wine=false) = {
  name: 'GUI Wallet (dev)',
  platform: { arch: 'amd64' },
  image: image,
  pull: 'always',
  environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
  commands: (if wine then ['dpkg --add-architecture i386'] else []) + [
    apt_get_quiet + ' update',
    apt_get_quiet + ' install -y eatmydata',
    'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
    'eatmydata ' + apt_get_quiet + ' install -y --no-install-recommends git ssh curl ca-certificates binutils make' + (if wine then ' wine32 wine sed' else ''),
    'curl -sSL https://deb.nodesource.com/setup_14.x | bash -',
    'eatmydata ' + apt_get_quiet + ' update',
    'eatmydata ' + apt_get_quiet + ' install -y nodejs',
    'git clone https://github.com/loki-project/loki-electron-gui-wallet.git',
    'cp -v build/bin/oxend' + (if wine then '.exe' else '') + ' loki-electron-gui-wallet/bin',
    'cp -v build/bin/oxen-wallet-rpc' + (if wine then '.exe' else '') + ' loki-electron-gui-wallet/bin',
    'cd loki-electron-gui-wallet',
    'eatmydata npm install',
    'sed -i -e \'s/^\\\\( *"version": ".*\\\\)",/\\\\\\\\1-${DRONE_COMMIT_SHA:0:8}",/\' package.json',
  ] + (if wine then ['sed -i -e \'s/^\\\\( *"build": "quasar.*\\\\)",/\\\\\\\\1 --target=win",/\' package.json'] else []) + [
    'eatmydata npm run build',
    '../utils/build_scripts/drone-wallet-upload.sh',
  ],
};
local gui_wallet_step_darwin = {
  name: 'GUI Wallet (dev)',
  platform: { os: 'darwin', arch: 'amd64' },
  environment: { SSH_KEY: { from_secret: 'SSH_KEY' }, CSC_IDENTITY_AUTO_DISCOVERY: 'false' },
  commands: [
    'git clone https://github.com/loki-project/loki-electron-gui-wallet.git',
    'cp -v build/bin/{oxend,oxen-wallet-rpc} loki-electron-gui-wallet/bin',
    'cd loki-electron-gui-wallet',
    'sed -i -e \'s/^\\\\( *"version": ".*\\\\)",/\\\\1-${DRONE_COMMIT_SHA:0:8}",/\' package.json',
    'npm install',
    'npm run build',
    '../utils/build_scripts/drone-wallet-upload.sh',
  ],
};


[
  // Static build to make wallet3:
  {
    name: 'Static (wallet3)',
    kind: 'pipeline',
    type: 'docker',
    platform: { arch: 'amd64' },
    steps: [{
      name: 'build',
      image: docker_base + 'ubuntu-lts',
      pull: 'always',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
      commands: submodules_commands + [
        'apt update',
        'eatmydata ' + apt_get_quiet + ' install -y --no-install-recommends cmake git ninja-build ccache '
        + std.join(' ', static_build_deps),
        'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y lsb-release',
        'cp contrib/deb.oxen.io.gpg /etc/apt/trusted.gpg.d',
        'echo deb http://deb.oxen.io $$(lsb_release -sc) main >/etc/apt/sources.list.d/oxen.list',
        'eatmydata ' + apt_get_quiet + ' update',
        'apt update',
        'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y python3-venv python3-oxenmq',
        'pip3 install --upgrade pip',
        'pip3 install --upgrade build',
        'pip3 install --upgrade setuptools',
        'mkdir build',
        'cd build',
        'cmake .. -G Ninja ' +
        '-DSTATIC=ON -DBUILD_STATIC_DEPS=ON -DUSE_LTO=OFF -DCMAKE_BUILD_TYPE=Release -DWARNINGS_AS_ERRORS=OFF',
        'ninja -j6 -v wallet3_merged',
        'pip3 install ./pybind/',
        'cd ..',
        'cd src/wallet3/cli-wallet/',
        'python3.10 -m build',
      ],
    }],
  },

  // Various debian builds
  debian_pipeline('Debian sid (w/ tests) (amd64)', docker_base + 'debian-sid', lto=true, run_tests=true),
  debian_pipeline('Debian sid Debug (amd64)', docker_base + 'debian-sid', build_type='Debug', cmake_extra='-DBUILD_DEBUG_UTILS=ON'),
  clang(13),
  debian_pipeline('Debian stable (i386)', docker_base + 'debian-stable/i386', cmake_extra='-DDOWNLOAD_SODIUM=ON -DARCH_ID=i386 -DARCH=i686'),
  debian_pipeline('Debian buster (amd64)', docker_base + 'debian-buster', cmake_extra='-DDOWNLOAD_SODIUM=ON'),
  debian_pipeline('Ubuntu LTS (amd64)', docker_base + 'ubuntu-lts'),
  debian_pipeline('Ubuntu latest (amd64)', docker_base + 'ubuntu-rolling'),

  // ARM builds (ARM64 and armhf)
  debian_pipeline('Debian sid (ARM64)', docker_base + 'debian-sid', arch='arm64', build_tests=false),
  debian_pipeline('Debian stable (armhf)',
                  docker_base + 'debian-stable/arm32v7',
                  arch='arm64',
                  build_tests=false,
                  cmake_extra='-DARCH_ID=armhf'),

  // Static build (on bionic) which gets uploaded to builds.lokinet.dev:
  debian_pipeline(
    'Static (bionic amd64)',
    docker_base + 'ubuntu-bionic',
    deps=['g++-8'] + static_build_deps,
    cmake_extra='-DBUILD_STATIC_DEPS=ON -DCMAKE_C_COMPILER=gcc-8 -DCMAKE_CXX_COMPILER=g++-8 -DARCH=x86-64',
    build_tests=false,
    lto=true,
    extra_cmds=static_check_and_upload,
    kitware_cmake_distro='bionic',
    /*extra_steps=[gui_wallet_step('ubuntu:bionic')]*/
  ),

  // Static mingw build (on focal) which gets uploaded to builds.lokinet.dev:
  debian_pipeline(
    'Static (win64)',
    docker_base + 'debian-win32-cross',
    deps=['g++', 'g++-mingw-w64-x86-64'] + static_build_deps,
    cmake_extra='-DCMAKE_TOOLCHAIN_FILE=../cmake/64-bit-toolchain.cmake -DBUILD_STATIC_DEPS=ON -DARCH=x86-64',
    build_tests=false,
    lto=false,
    test_oxend=false,
    extra_cmds=[
      'ninja strip_binaries',
      'ninja create_zip',
      '../utils/build_scripts/drone-static-upload.sh',
    ],
    /*extra_steps=[gui_wallet_step('debian:stable', wine=true)]*/
  ),

  // Macos builds:
  mac_builder('macOS (Static)',
              cmake_extra='-DBUILD_STATIC_DEPS=ON -DARCH=core2 -DARCH_ID=amd64',
              build_tests=false,
              lto=true,
              extra_cmds=static_check_and_upload,/*extra_steps=[gui_wallet_step_darwin]*/),
  mac_builder('macOS (Release)', run_tests=true),
  mac_builder('macOS (Debug)', build_type='Debug', cmake_extra='-DBUILD_DEBUG_UTILS=ON'),


  // Android builds; we do them all in one image because the android NDK is huge
  {
    name: 'Android wallet_api',
    kind: 'pipeline',
    type: 'docker',
    platform: { arch: 'amd64' },
    steps: [
      submodules,
      {
        name: 'build',
        image: docker_base + 'android',
        environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
        commands: [
                    'echo deb http://deb.debian.org/debian sid contrib >/etc/apt/sources.list.d/sid-contrib.list',
                    apt_get_quiet + ' update',
                    apt_get_quiet + ' install -y eatmydata',
                    'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
                    'eatmydata ' + apt_get_quiet + ' install -y --no-install-recommends '
                    + 'cmake g++ git ninja-build ccache tar xz-utils google-android-ndk-installer '
                    + std.join(' ', static_build_deps),
                  ]
                  + android_build_steps('armeabi-v7a', cmake_extra='-DARCH=armv7-a -DARCH_ID=arm32')
                  + android_build_steps('arm64-v8a', cmake_extra='-DARCH=armv8-a -DARCH_ID=arm64')
                  + android_build_steps('x86_64', cmake_extra='-DARCH="x86-64 -msse4.2 -mpopcnt" -DARCH_ID=x86-64')
                  + [
                    './utils/build_scripts/drone-android-static-upload.sh armeabi-v7a arm64-v8a x86_64',
                  ],
      },
    ],
  },

  // iOS build
  {
    name: 'iOS wallet_api',
    kind: 'pipeline',
    type: 'exec',
    platform: { os: 'darwin', arch: 'amd64' },
    steps: [{
      name: 'build',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
      commands: submodules_commands + [
        'mkdir -p build/{arm64,sim64}',
        'cd build/arm64',
        'cmake ../.. -G Ninja ' +
        '-DCMAKE_TOOLCHAIN_FILE=../../cmake/ios.toolchain.cmake -DPLATFORM=OS -DDEPLOYMENT_TARGET=13 -DENABLE_VISIBILITY=ON -DENABLE_BITCODE=OFF ' +
        '-DSTATIC=ON -DBUILD_STATIC_DEPS=ON -DUSE_LTO=OFF -DCMAKE_BUILD_TYPE=Release ' +
        '-DRANDOMX_ENABLE_JIT=OFF -DCMAKE_CXX_FLAGS=-fcolor-diagnostics',
        'ninja -j6 -v wallet_merged',
        'cd ../sim64',
        'cmake ../.. -G Ninja ' +
        '-DCMAKE_TOOLCHAIN_FILE=../../cmake/ios.toolchain.cmake -DPLATFORM=SIMULATOR64 -DDEPLOYMENT_TARGET=13 -DENABLE_VISIBILITY=ON -DENABLE_BITCODE=OFF ' +
        '-DSTATIC=ON -DBUILD_STATIC_DEPS=ON -DUSE_LTO=OFF -DCMAKE_BUILD_TYPE=Release ' +
        '-DRANDOMX_ENABLE_JIT=OFF -DCMAKE_CXX_FLAGS=-fcolor-diagnostics',
        'ninja -j6 -v wallet_merged',
        'cd ../..',
        './utils/build_scripts/drone-ios-static-upload.sh',
      ],
    }],
  },

]
