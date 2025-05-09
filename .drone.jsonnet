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
  'libzstd-dev',
  'nettle-dev',
  'pkg-config',
  'python3',
  'qttools5-dev',
];
local default_deps = ['g++'] + default_deps_nocxx;  // g++ sometimes needs replacement

local gtest_filter = '-AddressFromURL.Failure:DNSResolver.DNSSEC*';

local docker_base = 'registry.oxen.rocks/';

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
                      build_everything=false,
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
        '-DLOCAL_MIRROR=https://oxen.rocks/deps '
        + cmake_options({ USE_LTO: lto, WARNINGS_AS_ERRORS: werror, BUILD_TESTS: build_tests || run_tests, BUILD_EVERYTHING: build_everything })
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

local clang(version, lto=true) = debian_pipeline(
  'Debian sid/clang-' + version + ' (amd64)',
  docker_base + 'debian-sid-clang',
  deps=['clang-' + version, 'llvm-' + version] + default_deps_nocxx,
  cmake_extra='-DCMAKE_C_COMPILER=clang-' + version + ' -DCMAKE_CXX_COMPILER=clang++-' + version + ' ',
  lto=lto,
  build_everything=true
);

local distro_deb_suffix = {
  unstable: '',
  sid: '',
  forky: '~deb14',
  trixie: '~deb13',
  bookworm: '~deb12',
  bullseye: '~deb11',
  oracular: '~ubuntu2410',
  noble: '~ubuntu2404',
  jammy: '~ubuntu2204',
  focal: '~ubuntu2004',
};
local distro_fmtspdsecp(distro) = !(distro == 'bullseye' || distro == 'jammy' || distro == 'focal');
local distro_build_env(distro, deb_suffix_base) = {
  DEBIAN_CODENAME: distro,
  DEBIAN_SUFFIX: deb_suffix_base + distro_deb_suffix[distro],
} + (if distro_fmtspdsecp(distro) then { WITH_FMT: 1, WITH_SPD: 1, WITH_SECP: 1 } else {}) + (
  if distro == 'focal' then { OXEN_APPEND_DEPS: ', g++-10', OXEN_DEB_CMAKE_EXTRA: '-DCMAKE_C_COMPILER=gcc-10 -DCMAKE_CXX_COMPILER=g++-10' } else {}
);

local snapshot_deb(distro, deb_suffix_base='-1', buildarch='amd64', debarch='amd64', jobs=6, repo_suffix='/staging') = {
  kind: 'pipeline',
  type: 'docker',
  name: distro + ' snapshot deb (' + debarch + ')',
  platform: { arch: buildarch },
  steps: [
    submodules,
    {
      name: 'build',
      image: 'registry.oxen.rocks/' +
             (if std.startsWith(distro_deb_suffix[distro], '~ubuntu') then 'ubuntu' else 'debian') +
             '-' + distro + '-builder',
      environment: {
        SSH_KEY: { from_secret: 'SSH_KEY' },
      } + distro_build_env(distro, deb_suffix_base),
      commands: [
        'echo "Building on ${DRONE_STAGE_MACHINE}"',
        'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
        'cp contrib/deb.oxen.io.gpg /etc/apt/trusted.gpg.d/deb.oxen.io.gpg',
        'echo deb http://deb.oxen.io' + repo_suffix + ' ' + distro + ' main >/etc/apt/sources.list.d/loki.list',
        apt_get_quiet + ' update',
        apt_get_quiet + ' install -y eatmydata',
        'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
        'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y git-buildpackage devscripts equivs g++ ccache openssh-client',
        'eatmydata dpkg-reconfigure ccache',
        './debian/setup-build.sh',
        'cd debian',
        'eatmydata mk-build-deps -i -r --tool="' + apt_get_quiet + ' -o Debug::pkgProblemResolver=yes --no-install-recommends -y" control',
        'cd ..',
        'eatmydata debuild --preserve-envvar=CCACHE_* --preserve-envvar=OXEN_DEB_CMAKE_EXTRA -us -uc -b -j' + jobs,
        './debian/ci-upload.sh ' + distro + ' ' + debarch,
      ],
    },
  ],
};


// Macos build
local mac_builder(name,
                  build_type='Release',
                  arch='amd64',
                  lto=false,
                  werror=false,  // FIXME
                  build_tests=true,
                  test_oxend=true,
                  run_tests=false,
                  cmake_extra='',
                  extra_cmds=[],
                  extra_steps=[],
                  jobs=6,
                  allow_fail=false) = {
  kind: 'pipeline',
  type: 'exec',
  name: name,
  platform: { os: 'darwin', arch: arch },
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
        '-DLOCAL_MIRROR=https://oxen.rocks/deps -DUSE_LTO=' + (if lto then 'ON ' else 'OFF ') +
        '-DWARNINGS_AS_ERRORS=' + (if werror then 'ON ' else 'OFF ') +
        (if build_tests || run_tests then '-DBUILD_TESTS=ON ' else '') +
        cmake_extra,
        'ninja -j' + jobs + ' -v',
      ] + (
        if test_oxend then [
          '(sleep 3; echo "status\ndiff\nexit") | TERM=xterm ./bin/oxend --offline --data-dir=startuptest',
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
  '-DCMAKE_TOOLCHAIN_FILE=/usr/lib/android-ndk/build/cmake/android.toolchain.cmake ' +
  '-DANDROID_PLATFORM=' + android_platform + ' -DANDROID_ABI=' + android_abi + ' ' +
  cmake_options({ MONERO_SLOW_HASH: true, WARNINGS_AS_ERRORS: false, BUILD_TESTS: false, RANDOMX_ENABLE_JIT: false }) +
  '-DLOCAL_MIRROR=https://oxen.rocks/deps ' +
  '-DBUILD_STATIC_DEPS=ON -DSTATIC=ON -DANDROID_STL=c++_shared -G Ninja ' + cmake_extra,
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
  // Android builds; we do all architecture builds within in one single step because the android NDK is huge
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
                    apt_get_quiet + ' update',
                    apt_get_quiet + ' install -y eatmydata',
                    'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
                    'eatmydata ' + apt_get_quiet + ' install -y --no-install-recommends '
                    + 'cmake g++ git ninja-build ccache tar xz-utils google-android-ndk-r28-installer '
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
    platform: { os: 'darwin', arch: 'arm64' },
    steps: [
      { name: 'submodules', commands: submodules_commands },
      {
        name: 'build',
        environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
        commands: [
          'mkdir -p build',
          'cd build',
          'cmake .. -G Ninja ' +
          '-DCMAKE_TOOLCHAIN_FILE=../cmake/ios.toolchain.cmake -DPLATFORM=OS64 -DDEPLOYMENT_TARGET=13 -DENABLE_VISIBILITY=ON -DENABLE_BITCODE=OFF ' +
          '-DRANDOMX_ENABLE_JIT=OFF ' +
          '-DSTATIC=ON -DBUILD_STATIC_DEPS=ON -DUSE_LTO=OFF -DCMAKE_BUILD_TYPE=Release ' +
          '-DLOCAL_MIRROR=https://oxen.rocks/deps ' +
          '-DCMAKE_CXX_FLAGS=-fcolor-diagnostics',
          'ninja -j6 -v wallet_merged',
          'cd ..',
          './utils/build_scripts/drone-ios-static-upload.sh ios',
        ],
      },
    ],
  },
  // iOS simulator build
  {
    name: 'iOS (sim) wallet_api',
    kind: 'pipeline',
    type: 'exec',
    platform: { os: 'darwin', arch: 'arm64' },
    steps: [
      { name: 'submodules', commands: submodules_commands },
      {
        name: 'build',
        environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
        commands: [
          'mkdir -p build',
          'cd build',
          'cmake .. -G Ninja ' +
          '-DCMAKE_TOOLCHAIN_FILE=../cmake/ios.toolchain.cmake -DPLATFORM=SIMULATORARM64 -DDEPLOYMENT_TARGET=13 -DENABLE_VISIBILITY=ON -DENABLE_BITCODE=OFF ' +
          '-DRANDOMX_ENABLE_JIT=OFF ' +
          '-DSTATIC=ON -DBUILD_STATIC_DEPS=ON -DUSE_LTO=OFF -DCMAKE_BUILD_TYPE=Release ' +
          '-DLOCAL_MIRROR=https://oxen.rocks/deps ' +
          '-DCMAKE_CXX_FLAGS=-fcolor-diagnostics',
          'ninja -j6 -v wallet_merged',
          'cd ..',
          './utils/build_scripts/drone-ios-static-upload.sh ios-sim',
        ],
      },
    ],
  },

]
